"""Immutable data structures used at the authorization boundary."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Generic, TypeVar

T = TypeVar("T")


def utc_now() -> datetime:
    """Return an aware UTC timestamp."""
    return datetime.now(timezone.utc)


def _require_nonblank(name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    if value != value.strip():
        raise ValueError(f"{name} must not have leading or trailing whitespace")


def _require_aware(name: str, value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be a timezone-aware datetime")


@dataclass(frozen=True, slots=True)
class ActionRequest:
    """The exact subject/action/target/request that seeks authorization.

    `request_id` must be unique for the caller's intended operation. The gate
    does not prove that a caller supplied the true subject or target; those
    values must come from trusted, action-path-specific code.
    """

    subject_id: str
    action: str
    target_id: str
    request_id: str

    def __post_init__(self) -> None:
        for name in ("subject_id", "action", "target_id", "request_id"):
            _require_nonblank(name, getattr(self, name))


@dataclass(frozen=True, slots=True)
class GrantClaims:
    """Claims extracted only after an external verifier authenticates a proof.

    This dataclass is not a credential and does not authenticate itself. A
    production `ProofVerifier` must verify the proof's issuer, integrity, and
    issuer authority before returning these claims.
    """

    issuer_id: str
    subject_id: str
    action: str
    target_id: str
    request_id: str
    issued_at: datetime
    expires_at: datetime
    nonce: str

    def __post_init__(self) -> None:
        for name in (
            "issuer_id",
            "subject_id",
            "action",
            "target_id",
            "request_id",
            "nonce",
        ):
            _require_nonblank(name, getattr(self, name))
        _require_aware("issued_at", self.issued_at)
        _require_aware("expires_at", self.expires_at)
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be later than issued_at")


class DecisionStatus(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


@dataclass(frozen=True, slots=True)
class Decision:
    """A local gate result, not a universal authorization certificate.

    An ALLOW decision means the grant was consumed by replay protection. Do not
    call `authorize` as a dry run and then expect `execute` to accept the same
    single-use grant; invoke `execute` once for the intended action path.
    """

    status: DecisionStatus
    reason_code: str
    message: str
    request_id: str
    evaluated_at: datetime
    proof_sha256: str | None = None
    verifier_id: str | None = None

    def __post_init__(self) -> None:
        _require_nonblank("reason_code", self.reason_code)
        _require_nonblank("message", self.message)
        _require_nonblank("request_id", self.request_id)
        _require_aware("evaluated_at", self.evaluated_at)


@dataclass(frozen=True, slots=True)
class ExecutionOutcome(Generic[T]):
    """Reports whether this particular guarded call invoked its action."""

    decision: Decision
    action_invoked: bool
    value: T | None = None

    def __post_init__(self) -> None:
        if self.action_invoked and self.decision.status is not DecisionStatus.ALLOW:
            raise ValueError("action_invoked cannot be true when the gate denied")
        if not self.action_invoked and self.value is not None:
            raise ValueError("a denied or non-invoked action cannot return a value")
