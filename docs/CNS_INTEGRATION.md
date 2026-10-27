# Optional CNS integration

## Source inspected

The CNS repository was cloned read-only to `/tmp/enforcer-cns-inspection` at
commit `1b86c8280ca426c164f7768e4ef527d794ff7992` (`cns` 1.9.0). Its README
defines CNS as dependency-free row shapes and interfaces. `cns.gate` provides
`GatePosition`, `GateOutcome`, `GateResult`, the `Gate` protocol, and
`subject_digest`. It does not define authorization grants, policy authority,
revocation, or an `AuthorizationTarget` shape. Enforcer does not add any of
those to CNS and does not modify the CNS repository.

## Enforcer-side adapter

`enforcer.cns_integration` is an optional module. It imports the public
`cns.gate` contract only when an application imports this module; the core
Enforcer package has no CNS runtime dependency. The application must install
or expose a reviewed, pinned CNS checkout. This integration was exercised
against the commit above. No dependency was added to `pyproject.toml`.

`execute_with_cns(...)` always calls `Enforcer.execute(...)` for the action.
It returns a `CNSExecutionReport` that keeps the original `ExecutionOutcome`
and `Decision` intact and adds:

- An ALPHA `GateResult` bound with CNS `subject_digest` to all v1 action
  envelope fields. Enforcer `ALLOW` maps to CNS `PASS`; any Enforcer denial
  maps to `TERMINAL_BREACH`. The CNS digest is a separate representation from
  `ActionEnvelope.envelope_sha256`; they must not be compared as if identical.
- An optional OMEGA result. To enable it, callers provide both an
  `outcome_observer` and an OMEGA `Gate`. The observer runs only after the
  guarded callback and must provide a redacted mapping based on the
  application's actual outcome evidence. The adapter hashes that mapping
  with CNS `subject_digest` and passes only the envelope digest, request ID,
  and outcome digest to the OMEGA gate. The returned `GateResult` must declare
  OMEGA and bind the exact candidate.

If authorization denies, the callback is not invoked and no OMEGA result is
produced. The adapter does not issue grants, authenticate identities, select
policy versions, or infer how `target_type`, target IDs, or evidence map to
another repository. A callback exception propagates; if an external effect may
have happened before the exception, its outcome remains unknown. An OMEGA
failure happens after the action and cannot roll the effect back.

These functions are integration seams, not evidence that an Enforcer action
consumer or a complete CNS gate chain exists in this repository. The OMEGA
observer and gate must be connected to a real consumer and independently
observed outcome before making path-coverage or outcome-integrity claims.
