"""Optional translation seams between Enforcer and CNS gate contracts.

This module is deliberately not imported by :mod:`enforcer` itself. Install or
expose a pinned CNS checkout when an application opts into these adapters.
CNS gate results describe gate decisions; they do not issue authorization.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Generic, TypeVar

try:
    from cns.gate import Gate, GateOutcome, GatePosition, GateResult, subject_digest
except ImportError as exc:  # pragma: no cover - exercised only without optional CNS
    raise ImportError(
        "Enforcer CNS integration requires the cns package; install a reviewed CNS pin"
    ) from exc

from .gate import Enforcer
from .models import (
    ActionEnvelope,
    Decision,
    DecisionStatus,
    ExecutionOutcome,
)

T = TypeVar("T")

_ALPHA_SUBJECT = "enforcer.action-envelope.v1"
_OMEGA_SUBJECT = "enforcer.observed-outcome.v1"


@dataclass(frozen=True, slots=True)
class CNSExecutionReport(Generic[T]):
    """Enforcer execution plus its CNS ALPHA and optional OMEGA records.

    `omega_result` is absent when authorization denied or when no observed
    outcome gate was configured. The Enforcer decision and execution outcome
    remain available intact; the CNS records are interoperable summaries.
    """

    execution: ExecutionOutcome[T]
    alpha_result: GateResult
    omega_result: GateResult | None


def _envelope_content(envelope: ActionEnvelope) -> dict[str, object]:
    """Return the complete, secret-free v1 envelope content for CNS binding."""
    return {
        "schema_version": envelope.schema_version,
        "subject_id": envelope.subject_id,
        "action": envelope.action,
        "target_type": envelope.target_type,
        "target_id": envelope.target_id,
        "evidence_sha256": envelope.evidence_sha256,
        "request_id": envelope.request_id,
        "parameters_sha256": envelope.parameters_sha256,
        "policy_version": envelope.policy_version,
    }


def _alpha_result(envelope: ActionEnvelope, decision: Decision) -> GateResult:
    if decision.request_id != envelope.request_id:
        raise ValueError("Enforcer decision does not match the action envelope request_id")
    outcome = (
        GateOutcome.PASS
        if decision.status is DecisionStatus.ALLOW
        else GateOutcome.TERMINAL_BREACH
    )
    content = _envelope_content(envelope)
    return GateResult(
        gate="Enforcer",
        position=GatePosition.ALPHA,
        outcome=outcome,
        reason=decision.reason_code,
        subject=_ALPHA_SUBJECT,
        subject_digest=subject_digest(content),
    )


def execute_with_cns(
    enforcer: Enforcer,
    envelope: ActionEnvelope,
    proof: bytes | None,
    action: Callable[[], T],
    *,
    outcome_observer: Callable[[ExecutionOutcome[T]], Mapping[str, object]] | None = None,
    outcome_gate: Gate | None = None,
) -> CNSExecutionReport[T]:
    """Execute through Enforcer and translate its decision to CNS ALPHA.

    If both `outcome_observer` and an OMEGA `outcome_gate` are supplied, the
    observer runs after the guarded callback and returns a redacted,
    independently observed outcome record. Only its CNS digest, envelope
    digest, and request ID are passed to the OMEGA gate. A CNS OMEGA result
    describes that result check; it cannot undo an already performed effect.

    This function is an optional composition seam, not a real consumer or a
    claim of complete action-path coverage. Callback exceptions propagate as
    they do from `Enforcer.execute`; a downstream effect may then be unknown.
    """
    if (outcome_observer is None) != (outcome_gate is None):
        raise ValueError("outcome_observer and outcome_gate must be supplied together")
    if outcome_gate is not None:
        if outcome_gate.position is not GatePosition.OMEGA:
            raise ValueError("outcome_gate must declare CNS GatePosition.OMEGA")
        if not isinstance(outcome_gate.name, str) or not outcome_gate.name.strip():
            raise ValueError("outcome_gate must declare a non-empty CNS gate name")

    execution = enforcer.execute(envelope, proof, action)
    alpha_result = _alpha_result(envelope, execution.decision)
    omega_result = None

    if execution.action_invoked and outcome_observer is not None and outcome_gate is not None:
        observed = outcome_observer(execution)
        if not isinstance(observed, Mapping) or any(not isinstance(key, str) for key in observed):
            raise ValueError("outcome_observer must return a mapping with string keys")
        candidate = {
            "schema": "enforcer.observed-outcome.v1",
            "envelope_sha256": envelope.envelope_sha256,
            "request_id": envelope.request_id,
            "observed_outcome_sha256": subject_digest(observed),
        }
        omega_result = outcome_gate.check(candidate)
        if (
            not isinstance(omega_result, GateResult)
            or omega_result.gate != outcome_gate.name
            or omega_result.position is not GatePosition.OMEGA
            or not omega_result.binds(_OMEGA_SUBJECT, subject_digest(candidate))
        ):
            raise ValueError("CNS OMEGA result must bind the exact observed outcome candidate")

    return CNSExecutionReport(
        execution=execution,
        alpha_result=alpha_result,
        omega_result=omega_result,
    )
