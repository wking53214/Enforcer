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
    - revocation/status policy, if the chosen credential system supports it;
    - canonical decoding without accepting ambiguous or duplicate fields.

    The gate subsequently checks exact request binding, time limits, and replay.
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
