"""Fail-closed action-bound authorization gate prototype."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, TypeVar

from .models import (
    ActionRequest,
    Decision,
    DecisionStatus,
    ExecutionOutcome,
    GrantClaims,
    utc_now,
)
from .proofs import ProofVerificationError, ProofVerifier, RejectAllProofVerifier
from .revalidation import (
    AuthorizationRevalidator,
    AuthorizationStatus,
    AuthorizationStatusValue,
    RejectingAuthorizationRevalidator,
)
from .replay import ReplayStore, SQLiteReplayStore

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class GatePolicy:
    """Bounded validation policy. This is not a complete constitutional policy."""

    max_grant_lifetime: timedelta = timedelta(minutes=5)
    allowed_clock_skew: timedelta = timedelta(seconds=5)
    max_revalidation_age: timedelta = timedelta(seconds=30)

    def __post_init__(self) -> None:
        if not isinstance(self.max_grant_lifetime, timedelta):
            raise ValueError("max_grant_lifetime must be a timedelta")
        if not isinstance(self.allowed_clock_skew, timedelta):
            raise ValueError("allowed_clock_skew must be a timedelta")
        if not isinstance(self.max_revalidation_age, timedelta):
            raise ValueError("max_revalidation_age must be a timedelta")
        if self.max_grant_lifetime <= timedelta(0):
            raise ValueError("max_grant_lifetime must be positive")
        if self.allowed_clock_skew < timedelta(0):
            raise ValueError("allowed_clock_skew cannot be negative")
        if self.max_revalidation_age <= timedelta(0):
            raise ValueError("max_revalidation_age must be positive")


class Enforcer:
    """Check an authenticated grant before a specific action callback is invoked.

    This class guarantees only the checks implemented here and only for callers
    that actually use `execute`. It cannot stop code from bypassing this object,
    secure the process against malicious code running in-process, establish the
    truth of evidence, or prove that every real action consumer is gated.
    """

    def __init__(
        self,
        *,
        verifier: ProofVerifier | None = None,
        revalidator: AuthorizationRevalidator | None = None,
        replay_store: ReplayStore | None = None,
        policy: GatePolicy | None = None,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._verifier = verifier if verifier is not None else RejectAllProofVerifier()
        self._revalidator = (
            revalidator if revalidator is not None else RejectingAuthorizationRevalidator()
        )
        self._replay_store = replay_store if replay_store is not None else SQLiteReplayStore()
        self._policy = policy if policy is not None else GatePolicy()
        self._clock = clock

    def authorize(self, request: ActionRequest, proof: bytes | None) -> Decision:
        """Return ALLOW only for a verified, exact-scope, current, unused proof."""
        now = self._current_time()
        digest = hashlib.sha256(proof).hexdigest() if isinstance(proof, bytes) else None

        if not isinstance(proof, bytes) or not proof:
            return self._deny(request, now, "PROOF_MISSING", "An authorization proof is required.", digest)

        try:
            claims = self._verifier.verify_and_decode(proof)
            verifier_id = self._verifier.verifier_id
        except ProofVerificationError:
            return self._deny(
                request, now, "PROOF_INVALID", "The proof was not authenticated by the configured verifier.", digest
            )
        except Exception:
            # Unexpected adapter failure is not permission to continue.
            return self._deny(
                request, now, "VERIFIER_ERROR", "The proof verifier failed; the action is denied.", digest
            )

        if not isinstance(claims, GrantClaims):
            return self._deny(
                request, now, "CLAIMS_INVALID", "The verifier returned an invalid claims object.", digest,
                verifier_id,
            )

        expected = {
            "schema_version": request.schema_version,
            "subject_id": request.subject_id,
            "action": request.action,
            "target_type": request.target_type,
            "target_id": request.target_id,
            "evidence_sha256": request.evidence_sha256,
            "request_id": request.request_id,
            "parameters_sha256": request.parameters_sha256,
            "policy_version": request.policy_version,
        }
        for field, expected_value in expected.items():
            if getattr(claims, field) != expected_value:
                return self._deny(
                    request,
                    now,
                    "SCOPE_MISMATCH",
                    f"The grant is not bound to the requested {field}.",
                    digest,
                    verifier_id,
                )

        if claims.issued_at > now + self._policy.allowed_clock_skew:
            return self._deny(
                request, now, "GRANT_NOT_YET_VALID", "The grant's issue time is in the future.", digest, verifier_id
            )
        if claims.expires_at <= now:
            return self._deny(
                request, now, "GRANT_EXPIRED", "The grant has expired.", digest, verifier_id
            )
        if claims.expires_at - claims.issued_at > self._policy.max_grant_lifetime:
            return self._deny(
                request,
                now,
                "GRANT_LIFETIME_TOO_LONG",
                "The grant exceeds the configured maximum lifetime.",
                digest,
                verifier_id,
            )

        try:
            status = self._revalidator.revalidate(request, claims)
            revalidator_id = self._revalidator.revalidator_id
        except Exception:
            return self._deny(
                request,
                now,
                "AUTHORITY_REVALIDATION_ERROR",
                "Current authorization status could not be verified; the action is denied.",
                digest,
                verifier_id,
            )
        if not isinstance(status, AuthorizationStatus):
            return self._deny(
                request, now, "AUTHORITY_STATUS_INVALID", "The status adapter returned an invalid result.",
                digest, verifier_id, revalidator_id,
            )
        if not isinstance(revalidator_id, str) or not revalidator_id.strip():
            return self._deny(
                request, now, "AUTHORITY_STATUS_INVALID", "The status adapter has no stable identifier.",
                digest, verifier_id,
            )
        if status.status is AuthorizationStatusValue.REVOKED:
            return self._deny(
                request, now, "GRANT_REVOKED", "The current authority reports this grant as revoked.",
                digest, verifier_id, revalidator_id,
            )
        if status.status is not AuthorizationStatusValue.CURRENT:
            return self._deny(
                request, now, "AUTHORITY_STATUS_UNKNOWN", "Current authorization status is unknown.",
                digest, verifier_id, revalidator_id,
            )
        if (
            status.envelope_sha256 != request.envelope_sha256
            or status.policy_version != request.policy_version
        ):
            return self._deny(
                request, now, "AUTHORITY_CONTEXT_MISMATCH", "Status is not bound to this envelope and policy.",
                digest, verifier_id, revalidator_id,
            )
        if (
            not isinstance(status.checked_at, datetime)
            or status.checked_at.tzinfo is None
            or status.checked_at.utcoffset() is None
            or not isinstance(status.valid_until, datetime)
            or status.valid_until.tzinfo is None
            or status.valid_until.utcoffset() is None
        ):
            return self._deny(
                request, now, "AUTHORITY_STATUS_INVALID", "Status timestamps are invalid.",
                digest, verifier_id, revalidator_id,
            )
        checked_at = status.checked_at.astimezone(timezone.utc)
        valid_until = status.valid_until.astimezone(timezone.utc)
        if (
            checked_at > now + self._policy.allowed_clock_skew
            or checked_at > valid_until
            or valid_until <= now
            or now - checked_at > self._policy.max_revalidation_age
            or valid_until - checked_at > self._policy.max_revalidation_age
        ):
            return self._deny(
                request, now, "AUTHORITY_STATUS_STALE", "Authorization status is stale or outside its validity bound.",
                digest, verifier_id, revalidator_id,
            )

        try:
            consumed = self._replay_store.consume(claims.issuer_id, claims.nonce, claims.request_id)
        except Exception:
            return self._deny(
                request,
                now,
                "REPLAY_STORE_ERROR",
                "Replay protection is unavailable; the action is denied.",
                digest,
                verifier_id,
                revalidator_id,
            )
        if not consumed:
            return self._deny(
                request, now, "GRANT_REPLAYED", "The grant nonce or request ID has already been consumed.", digest,
                verifier_id, revalidator_id,
            )

        return Decision(
            status=DecisionStatus.ALLOW,
            reason_code="VERIFIED_ACTION_BOUND_GRANT",
            message="The verifier authenticated an exact-envelope, current, unused grant.",
            request_id=request.request_id,
            evaluated_at=now,
            proof_sha256=digest,
            verifier_id=verifier_id,
            revalidator_id=revalidator_id,
        )

    def execute(
        self,
        request: ActionRequest,
        proof: bytes | None,
        action: Callable[[], T],
    ) -> ExecutionOutcome[T]:
        """Invoke this callback only after `authorize` returns ALLOW.

        Any exception raised by `action` propagates. The grant remains consumed:
        retry requires a new independently issued grant. Callers must not treat
        this helper as proof that alternate paths to the same action are gated.
        """
        decision = self.authorize(request, proof)
        if decision.status is not DecisionStatus.ALLOW:
            return ExecutionOutcome(decision=decision, action_invoked=False)
        value = action()
        return ExecutionOutcome(decision=decision, action_invoked=True, value=value)

    def close(self) -> None:
        """Close the replay store if it exposes a close method."""
        close = getattr(self._replay_store, "close", None)
        if callable(close):
            close()

    def __enter__(self) -> "Enforcer":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def _current_time(self) -> datetime:
        current = self._clock()
        if not isinstance(current, datetime) or current.tzinfo is None or current.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware datetime")
        return current.astimezone(timezone.utc)

    @staticmethod
    def _deny(
        request: ActionRequest,
        now: datetime,
        reason_code: str,
        message: str,
        digest: str | None = None,
        verifier_id: str | None = None,
        revalidator_id: str | None = None,
    ) -> Decision:
        return Decision(
            status=DecisionStatus.DENY,
            reason_code=reason_code,
            message=message,
            request_id=request.request_id,
            evaluated_at=now,
            proof_sha256=digest,
            verifier_id=verifier_id,
            revalidator_id=revalidator_id,
        )
