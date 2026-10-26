from __future__ import annotations

import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from enforcer import (
    ActionRequest,
    DecisionStatus,
    Enforcer,
    GatePolicy,
    GrantClaims,
    ProofVerificationError,
    SQLiteReplayStore,
)


NOW = datetime(2026, 10, 26, 20, 0, tzinfo=timezone.utc)


class FakeVerifier:
    """Test-only proof adapter. It is not cryptographic and is not production code."""

    verifier_id = "tests/fake-verifier"

    def __init__(self, mapping=None, fail=None):
        self.mapping = mapping or {}
        self.fail = fail

    def verify_and_decode(self, proof: bytes) -> GrantClaims:
        if self.fail == "invalid":
            raise ProofVerificationError("bad proof")
        if self.fail == "crash":
            raise RuntimeError("test adapter crash")
        if proof not in self.mapping:
            raise ProofVerificationError("unknown proof")
        return self.mapping[proof]


def request(**changes) -> ActionRequest:
    values = {
        "subject_id": "human:operator-17",
        "action": "deploy:release",
        "target_id": "service:payments-api",
        "request_id": "req-2026-10-26-0001",
    }
    values.update(changes)
    return ActionRequest(**values)


def claims(**changes) -> GrantClaims:
    values = {
        "issuer_id": "authority:release-approver",
        "subject_id": "human:operator-17",
        "action": "deploy:release",
        "target_id": "service:payments-api",
        "request_id": "req-2026-10-26-0001",
        "issued_at": NOW - timedelta(seconds=10),
        "expires_at": NOW + timedelta(seconds=60),
        "nonce": "nonce-001",
    }
    values.update(changes)
    return GrantClaims(**values)


class GateTests(unittest.TestCase):
    def setUp(self):
        self.store = SQLiteReplayStore(":memory:")
        self.proof = b"test-proof-001"
        self.verifier = FakeVerifier({self.proof: claims()})
        self.gate = Enforcer(verifier=self.verifier, replay_store=self.store, clock=lambda: NOW)

    def tearDown(self):
        self.gate.close()

    def test_default_verifier_denies(self):
        gate = Enforcer(replay_store=SQLiteReplayStore(":memory:"), clock=lambda: NOW)
        try:
            result = gate.authorize(request(), self.proof)
            self.assertEqual(result.status, DecisionStatus.DENY)
            self.assertEqual(result.reason_code, "PROOF_INVALID")
        finally:
            gate.close()

    def test_missing_proof_denies(self):
        result = self.gate.authorize(request(), None)
        self.assertEqual(result.status, DecisionStatus.DENY)
        self.assertEqual(result.reason_code, "PROOF_MISSING")

    def test_valid_exact_scope_grant_allows(self):
        result = self.gate.authorize(request(), self.proof)
        self.assertEqual(result.status, DecisionStatus.ALLOW)
        self.assertEqual(result.reason_code, "VERIFIED_ACTION_BOUND_GRANT")
        self.assertEqual(result.proof_sha256, __import__("hashlib").sha256(self.proof).hexdigest())

    def test_subject_mismatch_denies(self):
        self.verifier.mapping[self.proof] = claims(subject_id="human:other")
        result = self.gate.authorize(request(), self.proof)
        self.assertEqual(result.reason_code, "SCOPE_MISMATCH")

    def test_action_mismatch_denies(self):
        self.verifier.mapping[self.proof] = claims(action="delete:production-database")
        result = self.gate.authorize(request(), self.proof)
        self.assertEqual(result.reason_code, "SCOPE_MISMATCH")

    def test_target_mismatch_denies(self):
        self.verifier.mapping[self.proof] = claims(target_id="service:other")
        result = self.gate.authorize(request(), self.proof)
        self.assertEqual(result.reason_code, "SCOPE_MISMATCH")

    def test_request_id_mismatch_denies(self):
        self.verifier.mapping[self.proof] = claims(request_id="req:other")
        result = self.gate.authorize(request(), self.proof)
        self.assertEqual(result.reason_code, "SCOPE_MISMATCH")

    def test_expired_grant_denies(self):
        self.verifier.mapping[self.proof] = claims(expires_at=NOW)
        result = self.gate.authorize(request(), self.proof)
        self.assertEqual(result.reason_code, "GRANT_EXPIRED")

    def test_future_issued_grant_denies(self):
        self.verifier.mapping[self.proof] = claims(issued_at=NOW + timedelta(minutes=1), expires_at=NOW + timedelta(minutes=2))
        result = self.gate.authorize(request(), self.proof)
        self.assertEqual(result.reason_code, "GRANT_NOT_YET_VALID")

    def test_lifetime_above_policy_denies(self):
        self.verifier.mapping[self.proof] = claims(
            issued_at=NOW - timedelta(minutes=10), expires_at=NOW + timedelta(minutes=1)
        )
        result = self.gate.authorize(request(), self.proof)
        self.assertEqual(result.reason_code, "GRANT_LIFETIME_TOO_LONG")

    def test_invalid_proof_denies(self):
        self.gate = Enforcer(
            verifier=FakeVerifier(fail="invalid"), replay_store=self.store, clock=lambda: NOW
        )
        result = self.gate.authorize(request(), b"invalid")
        self.assertEqual(result.reason_code, "PROOF_INVALID")

    def test_verifier_crash_denies(self):
        self.gate = Enforcer(
            verifier=FakeVerifier(fail="crash"), replay_store=self.store, clock=lambda: NOW
        )
        result = self.gate.authorize(request(), b"anything")
        self.assertEqual(result.reason_code, "VERIFIER_ERROR")

    def test_replay_denies_second_use(self):
        first = self.gate.authorize(request(), self.proof)
        second = self.gate.authorize(request(), self.proof)
        self.assertEqual(first.status, DecisionStatus.ALLOW)
        self.assertEqual(second.status, DecisionStatus.DENY)
        self.assertEqual(second.reason_code, "GRANT_REPLAYED")

    def test_denied_execute_never_calls_action(self):
        called = []
        outcome = self.gate.execute(request(), None, lambda: called.append("ran"))
        self.assertFalse(outcome.action_invoked)
        self.assertEqual(called, [])

    def test_allowed_execute_calls_action_once(self):
        called = []
        outcome = self.gate.execute(request(), self.proof, lambda: called.append("ran") or "done")
        self.assertTrue(outcome.action_invoked)
        self.assertEqual(outcome.value, "done")
        self.assertEqual(called, ["ran"])

    def test_action_exception_propagates_and_grant_stays_consumed(self):
        def broken_action():
            raise RuntimeError("action failure")

        with self.assertRaisesRegex(RuntimeError, "action failure"):
            self.gate.execute(request(), self.proof, broken_action)
        retry = self.gate.authorize(request(), self.proof)
        self.assertEqual(retry.reason_code, "GRANT_REPLAYED")

    def test_naive_datetime_claims_rejected(self):
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            claims(issued_at=datetime(2026, 10, 26, 19, 0))

    def test_invalid_policy_rejected(self):
        with self.assertRaises(ValueError):
            GatePolicy(max_grant_lifetime=timedelta(0))
        with self.assertRaises(ValueError):
            GatePolicy(max_grant_lifetime="five minutes")

    def test_replay_store_allows_only_one_consumer_across_connections(self):
        with TemporaryDirectory() as folder:
            db_path = Path(folder) / "replay.sqlite3"
            stores = [SQLiteReplayStore(db_path) for _ in range(8)]
            try:
                def consume(store):
                    return store.consume("issuer-A", "one-nonce", "one-request")

                with ThreadPoolExecutor(max_workers=8) as pool:
                    results = list(pool.map(consume, stores))
                self.assertEqual(sum(results), 1)
            finally:
                for store in stores:
                    store.close()

    def test_replay_store_failure_denies(self):
        class BrokenStore:
            def consume(self, issuer_id, nonce, request_id):
                raise OSError("database offline")

        self.gate = Enforcer(verifier=self.verifier, replay_store=BrokenStore(), clock=lambda: NOW)
        result = self.gate.authorize(request(), self.proof)
        self.assertEqual(result.reason_code, "REPLAY_STORE_ERROR")


if __name__ == "__main__":
    unittest.main()
