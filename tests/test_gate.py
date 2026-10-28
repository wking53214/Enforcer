from __future__ import annotations

import hashlib
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import fields
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from enforcer import (
    ActionEnvelope,
    ActionRequest,
    AuthorizationStatus,
    AuthorizationStatusValue,
    DecisionStatus,
    Enforcer,
    GatePolicy,
    GrantClaims,
    ProofVerificationError,
    SQLiteReplayStore,
)


NOW = datetime(2026, 10, 26, 20, 0, tzinfo=timezone.utc)
FRESH_UNTIL = NOW + timedelta(seconds=20)


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


class FakeRevalidator:
    """Test-only authority adapter; it does not validate real policy or revocation."""

    revalidator_id = "tests/fake-revalidator"

    def __init__(self, status=None, fail=False):
        self.status = status
        self.fail = fail

    def revalidate(self, envelope, claims):
        if self.fail:
            raise OSError("status source unavailable")
        if self.status is not None:
            return self.status
        return AuthorizationStatus(
            status=AuthorizationStatusValue.CURRENT,
            envelope_sha256=envelope.envelope_sha256,
            policy_version=envelope.policy_version,
            checked_at=NOW,
            valid_until=FRESH_UNTIL,
        )


def request(**changes) -> ActionRequest:
    values = {
        "subject_id": "human:operator-17",
        "action": "deploy:release",
        "target_type": "service",
        "target_id": "service:payments-api",
        "request_id": "req-2026-10-26-0001",
        "parameters_sha256": hashlib.sha256(b"{\"region\":\"us-east-1\"}").hexdigest(),
        "policy_version": "release-policy-v3",
        "evidence_sha256": None,
        "schema_version": 1,
    }
    values.update(changes)
    return ActionRequest(**values)


def claims(**changes) -> GrantClaims:
    values = {
        "issuer_id": "authority:release-approver",
        "subject_id": "human:operator-17",
        "action": "deploy:release",
        "target_type": "service",
        "target_id": "service:payments-api",
        "evidence_sha256": None,
        "request_id": "req-2026-10-26-0001",
        "parameters_sha256": hashlib.sha256(b"{\"region\":\"us-east-1\"}").hexdigest(),
        "policy_version": "release-policy-v3",
        "schema_version": 1,
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
        self.gate = Enforcer(
            verifier=self.verifier, revalidator=FakeRevalidator(), replay_store=self.store, clock=lambda: NOW
        )

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

    def test_configured_verifier_requires_explicit_replay_store(self):
        # Silently falling back to an in-memory store would lose replay state on
        # restart while a real verifier is allowing grants. Fail closed instead.
        with self.assertRaisesRegex(ValueError, "explicit replay_store"):
            Enforcer(verifier=self.verifier, revalidator=FakeRevalidator(), clock=lambda: NOW)
        with self.assertRaisesRegex(ValueError, "explicit replay_store"):
            Enforcer(verifier=self.verifier, clock=lambda: NOW)
        # The reject-all default still constructs without a store and still denies.
        gate = Enforcer(clock=lambda: NOW)
        try:
            self.assertEqual(gate.authorize(request(), self.proof).reason_code, "PROOF_INVALID")
        finally:
            gate.close()

    def test_default_revalidator_denies(self):
        gate = Enforcer(
            verifier=self.verifier, replay_store=SQLiteReplayStore(":memory:"), clock=lambda: NOW
        )
        called = []
        try:
            outcome = gate.execute(request(), self.proof, lambda: called.append("ran"))
            self.assertEqual(outcome.decision.reason_code, "AUTHORITY_REVALIDATION_ERROR")
            self.assertFalse(outcome.action_invoked)
            self.assertEqual(called, [])
        finally:
            gate.close()

    def test_revoked_or_unknown_status_denies(self):
        for status_value, reason in (
            (AuthorizationStatusValue.REVOKED, "GRANT_REVOKED"),
            (AuthorizationStatusValue.UNKNOWN, "AUTHORITY_STATUS_UNKNOWN"),
        ):
            with self.subTest(status=status_value):
                status = AuthorizationStatus(
                    status=status_value,
                    envelope_sha256=request().envelope_sha256,
                    policy_version=request().policy_version,
                    checked_at=NOW,
                    valid_until=FRESH_UNTIL,
                )
                self.gate = Enforcer(
                    verifier=self.verifier,
                    revalidator=FakeRevalidator(status=status),
                    replay_store=SQLiteReplayStore(":memory:"),
                    clock=lambda: NOW,
                )
                result = self.gate.authorize(request(), self.proof)
                self.assertEqual(result.reason_code, reason)

    def test_status_context_mismatch_denies(self):
        status = AuthorizationStatus(
            status=AuthorizationStatusValue.CURRENT,
            envelope_sha256="0" * 64,
            policy_version=request().policy_version,
            checked_at=NOW,
            valid_until=FRESH_UNTIL,
        )
        self.gate = Enforcer(
            verifier=self.verifier,
            revalidator=FakeRevalidator(status=status),
            replay_store=SQLiteReplayStore(":memory:"),
            clock=lambda: NOW,
        )
        self.assertEqual(self.gate.authorize(request(), self.proof).reason_code, "AUTHORITY_CONTEXT_MISMATCH")

    def test_status_policy_version_mismatch_denies(self):
        status = AuthorizationStatus(
            status=AuthorizationStatusValue.CURRENT,
            envelope_sha256=request().envelope_sha256,
            policy_version="release-policy-v2",
            checked_at=NOW,
            valid_until=FRESH_UNTIL,
        )
        self.gate = Enforcer(
            verifier=self.verifier,
            revalidator=FakeRevalidator(status=status),
            replay_store=SQLiteReplayStore(":memory:"),
            clock=lambda: NOW,
        )
        self.assertEqual(self.gate.authorize(request(), self.proof).reason_code, "AUTHORITY_CONTEXT_MISMATCH")

    def test_revalidation_failure_never_calls_action(self):
        self.gate = Enforcer(
            verifier=self.verifier,
            revalidator=FakeRevalidator(fail=True),
            replay_store=SQLiteReplayStore(":memory:"),
            clock=lambda: NOW,
        )
        called = []
        outcome = self.gate.execute(request(), self.proof, lambda: called.append("ran"))
        self.assertEqual(outcome.decision.reason_code, "AUTHORITY_REVALIDATION_ERROR")
        self.assertFalse(outcome.action_invoked)
        self.assertEqual(called, [])

    def test_stale_expired_or_future_status_denies(self):
        statuses = (
            AuthorizationStatus(
                AuthorizationStatusValue.CURRENT, request().envelope_sha256, request().policy_version,
                NOW - timedelta(seconds=31), NOW + timedelta(seconds=10),
            ),
            AuthorizationStatus(
                AuthorizationStatusValue.CURRENT, request().envelope_sha256, request().policy_version,
                NOW, NOW,
            ),
            AuthorizationStatus(
                AuthorizationStatusValue.CURRENT, request().envelope_sha256, request().policy_version,
                NOW + timedelta(seconds=6), FRESH_UNTIL,
            ),
        )
        for status in statuses:
            with self.subTest(status=status):
                self.gate = Enforcer(
                    verifier=self.verifier,
                    revalidator=FakeRevalidator(status=status),
                    replay_store=SQLiteReplayStore(":memory:"),
                    clock=lambda: NOW,
                )
                self.assertEqual(self.gate.authorize(request(), self.proof).reason_code, "AUTHORITY_STATUS_STALE")

    def test_revalidation_exception_denies(self):
        self.gate = Enforcer(
            verifier=self.verifier,
            revalidator=FakeRevalidator(fail=True),
            replay_store=SQLiteReplayStore(":memory:"),
            clock=lambda: NOW,
        )
        self.assertEqual(self.gate.authorize(request(), self.proof).reason_code, "AUTHORITY_REVALIDATION_ERROR")

    def test_missing_proof_denies(self):
        result = self.gate.authorize(request(), None)
        self.assertEqual(result.status, DecisionStatus.DENY)
        self.assertEqual(result.reason_code, "PROOF_MISSING")

    def test_valid_exact_scope_grant_allows(self):
        result = self.gate.authorize(request(), self.proof)
        self.assertEqual(result.status, DecisionStatus.ALLOW)
        self.assertEqual(result.reason_code, "VERIFIED_ACTION_BOUND_GRANT")
        self.assertEqual(result.proof_sha256, hashlib.sha256(self.proof).hexdigest())

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

    def test_target_type_mismatch_denies(self):
        self.verifier.mapping[self.proof] = claims(target_type="database")
        result = self.gate.authorize(request(), self.proof)
        self.assertEqual(result.reason_code, "SCOPE_MISMATCH")

    def test_evidence_mismatch_or_removal_denies(self):
        digest = hashlib.sha256(b"evidence").hexdigest()
        self.verifier.mapping[self.proof] = claims(evidence_sha256=digest)
        self.assertEqual(self.gate.authorize(request(), self.proof).reason_code, "SCOPE_MISMATCH")
        self.verifier.mapping[self.proof] = claims()
        self.assertEqual(
            self.gate.authorize(request(evidence_sha256=digest), self.proof).reason_code, "SCOPE_MISMATCH"
        )

    def test_parameter_digest_mismatch_denies(self):
        self.verifier.mapping[self.proof] = claims(parameters_sha256=hashlib.sha256(b"other").hexdigest())
        self.assertEqual(self.gate.authorize(request(), self.proof).reason_code, "SCOPE_MISMATCH")

    def test_policy_version_mismatch_denies(self):
        self.verifier.mapping[self.proof] = claims(policy_version="release-policy-v2")
        self.assertEqual(self.gate.authorize(request(), self.proof).reason_code, "SCOPE_MISMATCH")

    def test_schema_version_mismatch_denies(self):
        # A verifier that returns an object bypassing dataclass validation is still denied.
        invalid = object.__new__(GrantClaims)
        for field in fields(GrantClaims):
            name = field.name
            value = getattr(claims(), name)
            object.__setattr__(invalid, name, 2 if name == "schema_version" else value)
        self.verifier.mapping[self.proof] = invalid
        self.assertEqual(self.gate.authorize(request(), self.proof).reason_code, "SCOPE_MISMATCH")

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
            verifier=FakeVerifier(fail="invalid"), revalidator=FakeRevalidator(),
            replay_store=self.store, clock=lambda: NOW
        )
        result = self.gate.authorize(request(), b"invalid")
        self.assertEqual(result.reason_code, "PROOF_INVALID")

    def test_verifier_crash_denies(self):
        self.gate = Enforcer(
            verifier=FakeVerifier(fail="crash"), revalidator=FakeRevalidator(),
            replay_store=self.store, clock=lambda: NOW
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

    def test_non_callable_action_is_rejected_before_consuming_proof(self):
        with self.assertRaisesRegex(TypeError, "^action must be callable$"):
            self.gate.execute(request(), self.proof, object())

        called = []
        outcome = self.gate.execute(request(), self.proof, lambda: called.append("ran") or "done")
        self.assertEqual(outcome.decision.status, DecisionStatus.ALLOW)
        self.assertTrue(outcome.action_invoked)
        self.assertEqual(outcome.value, "done")
        self.assertEqual(called, ["ran"])

    def test_envelope_mismatch_never_calls_action(self):
        self.verifier.mapping[self.proof] = claims(policy_version="other-policy")
        called = []
        outcome = self.gate.execute(request(), self.proof, lambda: called.append("ran"))
        self.assertFalse(outcome.action_invoked)
        self.assertEqual(called, [])

    def test_envelope_canonical_round_trip_and_digest(self):
        envelope = request()
        encoded = envelope.canonical_bytes()
        self.assertEqual(ActionEnvelope.from_canonical_bytes(encoded), envelope)
        self.assertEqual(envelope.envelope_sha256, hashlib.sha256(encoded).hexdigest())

    def test_envelope_parser_rejects_duplicate_unknown_and_noncanonical_fields(self):
        encoded = request().canonical_bytes()
        with self.assertRaises(ValueError):
            ActionEnvelope.from_canonical_bytes(encoded[:-1] + b',"action":"other"}')
        with self.assertRaises(ValueError):
            ActionEnvelope.from_canonical_bytes(encoded[:-1] + b',"extra":"value"}')
        with self.assertRaises(ValueError):
            ActionEnvelope.from_canonical_bytes(encoded.replace(b",", b", ", 1))
        with self.assertRaises(ValueError):
            ActionEnvelope.from_canonical_bytes(encoded.replace(b',"policy_version":"release-policy-v3"', b""))

    def test_envelope_rejects_unsupported_version_and_malformed_digests(self):
        with self.assertRaises(ValueError):
            request(schema_version=2)
        with self.assertRaises(ValueError):
            request(parameters_sha256="not-a-digest")
        with self.assertRaises(ValueError):
            request(evidence_sha256="A" * 64)

    def test_canonicalization_preserves_security_distinctions(self):
        self.assertNotEqual(request().canonical_bytes(), request(target_type="cluster").canonical_bytes())
        self.assertNotEqual(request().canonical_bytes(), request(evidence_sha256="a" * 64).canonical_bytes())
        self.assertNotEqual(request().canonical_bytes(), request(policy_version="other").canonical_bytes())
        self.assertNotEqual(request().canonical_bytes(), request(parameters_sha256="b" * 64).canonical_bytes())

    def test_sensitive_parameters_are_not_in_envelope_or_decision(self):
        secret = "credential=do-not-log"
        digest = hashlib.sha256(secret.encode()).hexdigest()
        envelope = request(parameters_sha256=digest)
        self.assertNotIn(secret.encode(), envelope.canonical_bytes())
        self.verifier.mapping[self.proof] = claims(parameters_sha256=digest)
        result = self.gate.authorize(envelope, self.proof)
        self.assertNotIn(secret, result.message)

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
            GatePolicy(max_revalidation_age=timedelta(0))
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

    def test_replay_store_persists_consumption_across_restart(self):
        with TemporaryDirectory() as folder:
            db_path = Path(folder) / "persistent-replay.sqlite3"
            first = SQLiteReplayStore(db_path)
            try:
                self.assertTrue(first.consume("issuer-A", "nonce-1", "request-1"))
            finally:
                first.close()

            reopened = SQLiteReplayStore(db_path)
            try:
                self.assertFalse(reopened.consume("issuer-A", "nonce-1", "request-1"))
                self.assertTrue(reopened.consume("issuer-A", "nonce-2", "request-2"))
            finally:
                reopened.close()

    def test_replay_store_failure_denies(self):
        class BrokenStore:
            def consume(self, issuer_id, nonce, request_id):
                raise OSError("database offline")

        self.gate = Enforcer(
            verifier=self.verifier, revalidator=FakeRevalidator(), replay_store=BrokenStore(), clock=lambda: NOW
        )
        result = self.gate.authorize(request(), self.proof)
        self.assertEqual(result.reason_code, "REPLAY_STORE_ERROR")

    def test_verifier_returning_non_claims_object_denies_without_calling_action(self):
        self.verifier.mapping[self.proof] = {"subject_id": "human:operator-17", "action": "deploy:release"}
        called = []
        outcome = self.gate.execute(request(), self.proof, lambda: called.append("ran"))
        self.assertEqual(outcome.decision.status, DecisionStatus.DENY)
        self.assertEqual(outcome.decision.reason_code, "CLAIMS_INVALID")
        self.assertFalse(outcome.action_invoked)
        self.assertEqual(called, [])

    def test_verifier_without_stable_identifier_denies_without_calling_action(self):
        class UnidentifiedVerifier(FakeVerifier):
            verifier_id = ""

        self.gate = Enforcer(
            verifier=UnidentifiedVerifier({self.proof: claims()}),
            revalidator=FakeRevalidator(),
            replay_store=SQLiteReplayStore(":memory:"),
            clock=lambda: NOW,
        )
        called = []
        outcome = self.gate.execute(request(), self.proof, lambda: called.append("ran"))
        self.assertEqual(outcome.decision.status, DecisionStatus.DENY)
        self.assertEqual(outcome.decision.reason_code, "CLAIMS_INVALID")
        self.assertFalse(outcome.action_invoked)
        self.assertEqual(called, [])

    def test_empty_proof_bytes_denies_as_missing(self):
        result = self.gate.authorize(request(), b"")
        self.assertEqual(result.status, DecisionStatus.DENY)
        self.assertEqual(result.reason_code, "PROOF_MISSING")

    def test_malformed_status_or_unidentified_revalidator_denies(self):
        class BlankIdRevalidator(FakeRevalidator):
            revalidator_id = "   "

        naive_status = AuthorizationStatus(
            status=AuthorizationStatusValue.CURRENT,
            envelope_sha256=request().envelope_sha256,
            policy_version=request().policy_version,
            checked_at=NOW.replace(tzinfo=None),
            valid_until=FRESH_UNTIL.replace(tzinfo=None),
        )
        revalidators = (
            ("plain string status", FakeRevalidator(status="CURRENT")),
            ("blank revalidator_id", BlankIdRevalidator()),
            ("naive status timestamps", FakeRevalidator(status=naive_status)),
        )
        for label, revalidator in revalidators:
            with self.subTest(case=label):
                self.gate = Enforcer(
                    verifier=self.verifier,
                    revalidator=revalidator,
                    replay_store=SQLiteReplayStore(":memory:"),
                    clock=lambda: NOW,
                )
                called = []
                outcome = self.gate.execute(request(), self.proof, lambda: called.append("ran"))
                self.assertEqual(outcome.decision.reason_code, "AUTHORITY_STATUS_INVALID")
                self.assertFalse(outcome.action_invoked)
                self.assertEqual(called, [])


if __name__ == "__main__":
    unittest.main()
