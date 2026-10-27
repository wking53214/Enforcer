"""≡TACK Enforcer: a fail-closed authorization-gate prototype.

This package is not a complete One Ring architecture and does not confer
authority. A deployment must provide a separately audited proof verifier and
must route each consequential action through the gate.
"""

from .gate import Enforcer, GatePolicy
from .models import (
    ActionEnvelope,
    ActionRequest,
    Decision,
    DecisionStatus,
    ExecutionOutcome,
    GrantClaims,
)
from .proofs import ProofVerificationError, ProofVerifier, RejectAllProofVerifier
from .revalidation import (
    AuthorizationRevalidator,
    AuthorizationStatus,
    AuthorizationStatusValue,
    RejectingAuthorizationRevalidator,
)
from .replay import ReplayStore, SQLiteReplayStore

__all__ = [
    "ActionEnvelope",
    "ActionRequest",
    "AuthorizationRevalidator",
    "AuthorizationStatus",
    "AuthorizationStatusValue",
    "Decision",
    "DecisionStatus",
    "Enforcer",
    "ExecutionOutcome",
    "GatePolicy",
    "GrantClaims",
    "ProofVerificationError",
    "ProofVerifier",
    "RejectAllProofVerifier",
    "RejectingAuthorizationRevalidator",
    "ReplayStore",
    "SQLiteReplayStore",
]

__version__ = "0.1.0"
