"""Integration seam for authenticating authorization proofs.

No production cryptographic verifier is bundled in v0.1. That omission is
intentional: issuer identity, key custody, revocation, and trust roots must be
selected and audited rather than guessed by this repository.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .models import GrantClaims


class ProofVerificationError(Exception):
    """Raised when a supplied proof is absent, malformed, untrusted, or invalid."""


@runtime_checkable
class ProofVerifier(Protocol):
    """Trusted adapter that verifies a proof and returns its authenticated claims.

    Implementations MUST verify, at minimum:
    - the proof's cryptographic integrity and issuer identity;
    - that the issuer is trusted for the requested class of authorization;
    - canonical decoding without accepting ambiguous or duplicate fields.

    For schema v1, returned claims MUST include the complete action-envelope
    scope (schema version, subject, canonical action ID, target type and stable
    target ID, evidence digest, request ID, parameter digest, and policy
    version). The gate checks each field against the caller's envelope, then
    checks time limits, revalidation freshness, and replay. Current grant and
    policy status is checked separately by `AuthorizationRevalidator`;
    this verifier alone does not establish current status. Implementations
    must reject missing,
    duplicate, unknown, or ambiguously decoded proof fields.
    The protocol itself provides no security; a permissive or forged adapter
    defeats the gate. Keep verifier implementation and trust material outside
    untrusted plugin/model-controlled paths.
    """

    @property
    def verifier_id(self) -> str:
        """Stable identifier for the verifier implementation/configuration."""
        ...

    def verify_and_decode(self, proof: bytes) -> GrantClaims:
        """Authenticate `proof`; raise `ProofVerificationError` on any failure."""
        ...


class RejectAllProofVerifier:
    """Safe default adapter: every proof is rejected until configured explicitly."""

    @property
    def verifier_id(self) -> str:
        return "reject-all/unconfigured"

    def verify_and_decode(self, proof: bytes) -> GrantClaims:
        raise ProofVerificationError("no production proof verifier is configured")
