"""Immutable data structures used at the authorization boundary."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Generic, TypeVar

T = TypeVar("T")
_ENVELOPE_SCHEMA_VERSION = 1
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def utc_now() -> datetime:
    """Return an aware UTC timestamp."""
    return datetime.now(timezone.utc)


def _require_nonblank(name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    if value != value.strip():
        raise ValueError(f"{name} must not have leading or trailing whitespace")
    if unicodedata.normalize("NFC", value) != value:
        raise ValueError(f"{name} must use Unicode NFC normalization")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{name} must be valid Unicode text") from exc


def _require_sha256(name: str, value: str) -> None:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 hex digest")


def _require_aware(name: str, value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be a timezone-aware datetime")


@dataclass(frozen=True, slots=True)
class ActionEnvelope:
    """Versioned canonical description of the exact action seeking authority.

    `request_id` must be unique for the caller's intended operation. The gate
    does not prove that a caller supplied the true subject or target; those
    values must come from trusted, action-path-specific code. Parameter values
    are represented only by their SHA-256 digest, computed from action-specific
    canonical parameter bytes by the caller.
    """

    subject_id: str
    action: str
    target_type: str
    target_id: str
    request_id: str
    parameters_sha256: str
    policy_version: str
    evidence_sha256: str | None
    schema_version: int

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != _ENVELOPE_SCHEMA_VERSION:
            raise ValueError("unsupported action envelope schema_version")
        for name in (
            "subject_id", "action", "target_type", "target_id", "request_id", "policy_version"
        ):
            _require_nonblank(name, getattr(self, name))
        _require_sha256("parameters_sha256", self.parameters_sha256)
        if self.evidence_sha256 is not None:
            _require_sha256("evidence_sha256", self.evidence_sha256)

    def canonical_bytes(self) -> bytes:
        """Serialize using fixed field order, UTF-8, compact JSON, and explicit nulls."""
        values = {
            "schema_version": self.schema_version,
            "subject_id": self.subject_id,
            "action": self.action,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "evidence_sha256": self.evidence_sha256,
            "request_id": self.request_id,
            "parameters_sha256": self.parameters_sha256,
            "policy_version": self.policy_version,
        }
        return json.dumps(values, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")

    @property
    def envelope_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    @classmethod
    def from_canonical_bytes(cls, encoded: bytes) -> "ActionEnvelope":
        """Parse only this schema's canonical encoding; reject duplicates/extensions."""
        if not isinstance(encoded, bytes):
            raise ValueError("canonical envelope must be bytes")

        def pairs_no_duplicates(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate action envelope field")
                result[key] = value
            return result

        try:
            values = json.loads(
                encoded.decode("utf-8", errors="strict"),
                object_pairs_hook=pairs_no_duplicates,
                parse_constant=lambda value: (_ for _ in ()).throw(ValueError("invalid JSON constant")),
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("malformed canonical action envelope") from exc
        expected = {
            "schema_version", "subject_id", "action", "target_type", "target_id",
            "evidence_sha256", "request_id", "parameters_sha256", "policy_version",
        }
        if not isinstance(values, dict) or set(values) != expected:
            raise ValueError("action envelope fields are missing or unknown")
        try:
            envelope = cls(**values)
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid action envelope") from exc
        if envelope.canonical_bytes() != encoded:
            raise ValueError("action envelope is not canonically serialized")
        return envelope


# Source compatibility name only; old four-field requests cannot be constructed.
ActionRequest = ActionEnvelope


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
    target_type: str
    target_id: str
    evidence_sha256: str | None
    request_id: str
    parameters_sha256: str
    policy_version: str
    schema_version: int
    issued_at: datetime
    expires_at: datetime
    nonce: str

    def __post_init__(self) -> None:
        for name in (
            "issuer_id",
            "subject_id",
            "action",
            "target_type",
            "target_id",
            "request_id",
            "policy_version",
            "nonce",
        ):
            _require_nonblank(name, getattr(self, name))
        _require_aware("issued_at", self.issued_at)
        _require_aware("expires_at", self.expires_at)
        if type(self.schema_version) is not int or self.schema_version != _ENVELOPE_SCHEMA_VERSION:
            raise ValueError("unsupported grant schema_version")
        _require_sha256("parameters_sha256", self.parameters_sha256)
        if self.evidence_sha256 is not None:
            _require_sha256("evidence_sha256", self.evidence_sha256)
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
    revalidator_id: str | None = None

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
