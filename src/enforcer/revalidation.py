"""Trusted authorization freshness and revocation revalidation seam.

No production authority adapter is bundled. The default implementation denies
because this repository has no selected policy or revocation authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Protocol, runtime_checkable

from .models import ActionEnvelope, GrantClaims


class AuthorizationStatusValue(str, Enum):
    CURRENT = "CURRENT"
    REVOKED = "REVOKED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class AuthorizationStatus:
    """Status returned by a trusted adapter for one exact envelope and policy version."""

    status: AuthorizationStatusValue
    envelope_sha256: str
    policy_version: str
    checked_at: datetime
    valid_until: datetime


@runtime_checkable
class AuthorizationRevalidator(Protocol):
    """Trusted adapter that checks current policy/revocation immediately before use.

    Implementations must authenticate their status source and bind the response
    to the supplied envelope digest and policy version. CURRENT means the grant
    has not been revoked and that this exact policy version remains current for
    the action. A changed policy version must yield UNKNOWN or REVOKED until the
    caller obtains a newly authorized grant. Caller-provided booleans and
    unauthenticated local state are not authoritative.
    """

    @property
    def revalidator_id(self) -> str:
        """Stable identifier for the adapter and its protected configuration."""
        ...

    def revalidate(self, envelope: ActionEnvelope, claims: GrantClaims) -> AuthorizationStatus:
        """Return current, revoked, or unknown; raise if the required check fails."""
        ...


class RejectingAuthorizationRevalidator:
    """Safe default until a trusted current-policy/revocation source is selected."""

    @property
    def revalidator_id(self) -> str:
        return "reject-all/unconfigured"

    def revalidate(self, envelope: ActionEnvelope, claims: GrantClaims) -> AuthorizationStatus:
        raise RuntimeError("no trusted authorization revalidation source is configured")
