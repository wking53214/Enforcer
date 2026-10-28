from __future__ import annotations

import hashlib
import unittest
from datetime import datetime, timedelta, timezone

try:
    from cns.gate import GateOutcome, GatePosition, GateResult, resolve, subject_digest
    from enforcer.cns_integration import _envelope_content, execute_with_cns
except ImportError as exc:  # CNS is an optional integration dependency.
    _CNS_IMPORT_ERROR = exc
    GateOutcome = GatePosition = GateResult = None
    resolve = None
    subject_digest = None
    _envelope_content = None
else:
    _CNS_IMPORT_ERROR = None

from enforcer import (
    ActionEnvelope,
    AuthorizationStatus,
    AuthorizationStatusValue,
    Enforcer,
    GrantClaims,
    ProofVerificationError,
)


NOW = datetime(2026, 10, 27, 12, 0, tzinfo=timezone.utc)
PROOF = b"test-only-cns-proof"


class TestOnlyVerifier:
    verifier_id = "tests/cns-fake-verifier"

    def verify_and_decode(self, proof: bytes) -> GrantClaims:
        if proof != PROOF:
            raise ProofVerificationError("unknown test proof")
        return GrantClaims(
            issuer_id="test-issuer",
            subject_id="human:operator-1",
            action="deploy:release",
            target_type="service",
            target_id="service:payments",
            evidence_sha256=None,
            request_id="req-1",
            parameters_sha256=hashlib.sha256(b"{}").hexdigest(),
            policy_version="policy-v1",
            schema_version=1,
            issued_at=NOW - timedelta(seconds=1),
            expires_at=NOW + timedelta(minutes=1),
            nonce="nonce-1",
        )


class TestOnlyRevalidator:
    revalidator_id = "tests/cns-fake-revalidator"

    def revalidate(self, envelope, claims):
        return AuthorizationStatus(
            status=AuthorizationStatusValue.CURRENT,
            envelope_sha256=envelope.envelope_sha256,
            policy_version=envelope.policy_version,
            checked_at=NOW,
            valid_until=NOW + timedelta(seconds=10),
        )


class OMEGAGate:
    name = "test-outcome-check"
    position = GatePosition.OMEGA if GatePosition is not None else None

    def __init__(self):
        self.candidate = None

    def check(self, candidate):
        self.candidate = candidate
        return GateResult(
            gate=self.name,
            position=self.position,
            outcome=GateOutcome.PASS,
            reason="observed outcome accepted",
            subject="enforcer.observed-outcome.v1",
            subject_digest=subject_digest(candidate),
        )


class MisboundOMEGAGate(OMEGAGate):
    def check(self, candidate):
        self.candidate = candidate
        return GateResult(
            gate=self.name,
            position=self.position,
            outcome=GateOutcome.PASS,
            subject="enforcer.observed-outcome.v1",
            subject_digest="0" * 64,
        )


@unittest.skipIf(_CNS_IMPORT_ERROR is not None, "optional CNS checkout is not on PYTHONPATH")
class CNSIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.envelope = ActionEnvelope(
            subject_id="human:operator-1",
            action="deploy:release",
            target_type="service",
            target_id="service:payments",
            request_id="req-1",
            parameters_sha256=hashlib.sha256(b"{}").hexdigest(),
            policy_version="policy-v1",
            evidence_sha256=None,
            schema_version=1,
        )
        self.enforcer = Enforcer(
            verifier=TestOnlyVerifier(),
            revalidator=TestOnlyRevalidator(),
            clock=lambda: NOW,
        )

    def tearDown(self):
        self.enforcer.close()

    def test_alpha_and_omega_bind_the_envelope_and_observed_outcome(self):
        called = []
        omega = OMEGAGate()
        report = execute_with_cns(
            self.enforcer,
            self.envelope,
            PROOF,
            lambda: called.append("ran") or "callback-return-value",
            outcome_observer=lambda execution: {
                "state": "completed",
                "operation_id": "external-op-1",
            },
            outcome_gate=omega,
        )

        self.assertEqual(called, ["ran"])
        self.assertTrue(report.execution.action_invoked)
        self.assertEqual(report.alpha_result.position, GatePosition.ALPHA)
        self.assertEqual(report.alpha_result.outcome, GateOutcome.PASS)
        self.assertTrue(
            report.alpha_result.binds(
                "enforcer.action-envelope.v1",
                subject_digest(
                    {
                        "schema_version": self.envelope.schema_version,
                        "subject_id": self.envelope.subject_id,
                        "action": self.envelope.action,
                        "target_type": self.envelope.target_type,
                        "target_id": self.envelope.target_id,
                        "evidence_sha256": self.envelope.evidence_sha256,
                        "request_id": self.envelope.request_id,
                        "parameters_sha256": self.envelope.parameters_sha256,
                        "policy_version": self.envelope.policy_version,
                    }
                ),
            )
        )
        self.assertIsInstance(report.omega_result, GateResult)
        self.assertEqual(report.omega_result.position, GatePosition.OMEGA)
        self.assertTrue(
            report.omega_result.binds(
                "enforcer.observed-outcome.v1", subject_digest(omega.candidate)
            )
        )
        self.assertEqual(resolve((report.alpha_result, report.omega_result)), GateOutcome.PASS)
        self.assertEqual(omega.candidate["envelope_sha256"], self.envelope.envelope_sha256)
        self.assertEqual(
            omega.candidate["observed_outcome_sha256"],
            subject_digest({"state": "completed", "operation_id": "external-op-1"}),
        )
        self.assertNotIn("callback-return-value", repr(omega.candidate))

    def test_denial_is_alpha_terminal_breach_and_skips_omega(self):
        called = []
        omega = OMEGAGate()
        report = execute_with_cns(
            self.enforcer,
            self.envelope,
            None,
            lambda: called.append("ran"),
            outcome_observer=lambda execution: {"state": "impossible"},
            outcome_gate=omega,
        )

        self.assertEqual(called, [])
        self.assertFalse(report.execution.action_invoked)
        self.assertEqual(report.alpha_result.outcome, GateOutcome.TERMINAL_BREACH)
        self.assertIsNone(report.omega_result)
        self.assertIsNone(omega.candidate)

    def test_omega_configuration_must_be_complete_before_execution(self):
        called = []
        with self.assertRaises(ValueError):
            execute_with_cns(
                self.enforcer,
                self.envelope,
                PROOF,
                lambda: called.append("ran"),
                outcome_gate=OMEGAGate(),
            )
        self.assertEqual(called, [])

    def test_misbound_omega_is_rejected_after_callback(self):
        called = []
        with self.assertRaisesRegex(ValueError, "bind the exact observed outcome"):
            execute_with_cns(
                self.enforcer,
                self.envelope,
                PROOF,
                lambda: called.append("ran") or "returned",
                outcome_observer=lambda execution: {"state": "completed"},
                outcome_gate=MisboundOMEGAGate(),
            )
        # OMEGA runs after the effect; rejecting its malformed result cannot undo it.
        self.assertEqual(called, ["ran"])

    def test_cns_subject_digest_is_not_the_native_envelope_digest(self):
        # The two digests cover the same fields under different canonical forms.
        # A consumer must not substitute one for the other when binding results.
        cns_digest = subject_digest(_envelope_content(self.envelope))
        self.assertEqual(len(cns_digest), 64)
        self.assertNotEqual(self.envelope.envelope_sha256, cns_digest)


if __name__ == "__main__":
    unittest.main()
