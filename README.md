# ≡TACK Enforcer

**Status: 0.1.0 prototype — not production-ready and not the final One Ring architecture.**

Enforcer is a small, fail-closed authorization-gate prototype. It tests one narrow property needed by Project One Ring: a consequential action callback should not be invoked unless an external verifier authenticates a grant bound to the exact versioned action envelope, a trusted revalidator confirms current status, and the grant is current and unused.

This repository does **not** decide the final One Ring architecture. The constitutional and repository investigation must establish whether this capability belongs here, in an existing repository, or behind an adapter. Treat this code as an inspectable prototype whose value must be proven against real action paths.

## What is implemented

- Immutable, versioned action envelopes and grant-claim records.
- Fail-closed proof-verifier integration seam. The default verifier rejects every proof.
- Fail-closed authorization revalidation seam. The default revalidator rejects because no trusted current-policy/revocation source is selected.
- Exact binding checks for subject, action, target type and ID, optional evidence digest, request ID, parameter digest, policy version, and schema version.
- Current authorization status, policy-version context, and bounded freshness checks immediately before replay consumption and callback invocation.
- Expiry, future-issued, and maximum-lifetime checks.
- Atomic local replay prevention using SQLite uniqueness constraints.
- `execute(...)`, which does not invoke the supplied callback when the gate denies.
- Atomic replay behavior tested across multiple SQLite connections.
- Standard-library unit tests for positive and adversarial cases.

## What is deliberately not implemented

- A production cryptographic proof verifier or identity provider.
- A way to issue authorization grants. The issuer and trust roots must be selected and independently controlled; the gate must not mint its own authority.
- Policy discovery, constitutional interpretation, amendment approval, appeal adjudication, memory/continuity authority, or multi-repository governance.
- A repository-wide mechanism that makes every possible action path call this gate.
- Distributed replay protection across hosts.
- A claim that evidence is true merely because a digest matches.

Those gaps are not quietly filled by mocks. Tests use an explicitly test-only fake verifier; it is not safe for production.

## Quick start

Requires Python 3.11 or newer. No runtime third-party dependencies.

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

Example integration shape:

```python
from enforcer import ActionRequest, Enforcer

# Supply independently reviewed adapters for both trust boundaries. Both
# defaults reject all until configured against real authority sources.
with Enforcer(
    verifier=trusted_verifier,
    revalidator=trusted_revalidator,
    replay_store=shared_replay_store,
) as gate:
    request = ActionRequest(
        subject_id=authenticated_subject.id,
        action="deploy:release",
        target_type=resolved_deployment.target_type,
        target_id=resolved_deployment.target_id,
        request_id=operation.request_id,
        parameters_sha256=operation.canonical_parameters_sha256,
        policy_version=policy.version,
        evidence_sha256=operation.evidence_sha256,
        schema_version=1,
    )
    outcome = gate.execute(request, signed_grant_bytes, perform_deployment)
    if not outcome.action_invoked:
        raise PermissionError(outcome.decision.reason_code)
```

The example describes an integration shape; it is not a working deployment adapter. Both trusted adapters must be independently selected, implemented, configured, and reviewed. The identifiers must come from trusted action-path inputs, not from model-generated claims. The context manager closes the replay store; it does not roll back an already consumed grant.

## Security boundary

Enforcer can gate only the callback routed through `execute`. It cannot prove that another code path, alternate repository, shell command, queue consumer, worker, or administrator cannot perform the same action without it. That requires tracing the actual consequential action consumer and testing bypass paths.

The `ProofVerifier` is a high-trust integration point. It must authenticate the issuer and verify that the issuer is authorized to grant the relevant action. The gate trusts the adapter's result; a permissive verifier defeats this prototype. The replay database must be protected from unauthorized writes. The default SQLite store is in-memory and loses replay state when the process ends; production integration must pass an access-controlled persistent store. A shared deployment needs a shared atomic replay store. The current replay table has no pruning/retention policy and will grow over time; retention must be designed so no still-valid grant can become reusable. A Python library inside a process is not a boundary against malicious code that can modify that process. An `ALLOW` consumes the grant, so call `execute` directly for the protected operation rather than running `authorize` as a preflight and then trying to reuse the proof.

The proof digest in a decision is a correlation/integrity reference, **not** proof that the content is true or that the issuer had authority. An `ALLOW` means only that these local checks passed for this callback path. It is not a constitutional verdict, a global permit, or a security certification.

## Action envelope v1

`ActionRequest` remains as a source compatibility alias for `ActionEnvelope`, but the old four-field constructor is no longer accepted. Callers must provide `target_type`, `parameters_sha256`, and `policy_version`; `evidence_sha256` is explicitly `None` when the applicable contract has no evidence digest. `target_id` is the stable target identifier only when the caller's trusted resolver defines it that way. No Sentinel OS mapping is implied.

The envelope serializes as compact UTF-8 JSON in the field order implemented by `ActionEnvelope.canonical_bytes()`, with Unicode NFC text, no leading/trailing whitespace in identifiers, explicit JSON `null` for absent evidence, and lowercase 64-character SHA-256 hex digests. Parsing accepts only that exact byte representation, exact v1 field set, and no duplicate keys. Callers must supply an already canonical action ID; Enforcer compares it exactly and does not alias or normalize action names. The parameter digest must be computed over action-specific canonical parameter bytes by the caller; Enforcer does not define parameter semantics or include parameter values in the envelope. The schema version, subject, action, target, evidence value, request ID, parameter digest, and policy version are all grant-bound. Grant timestamps, issuer, and nonce remain separately verified/checked and replay-bound.

This API change can break external callers. Update them to construct the complete envelope and ensure the verifier authenticates the same v1 fields before returning `GrantClaims`. No real consumer or production verifier was found in this repository.

## Authorization status revalidation

Every allow also requires a configured `AuthorizationRevalidator` to return an authority-authenticated `CURRENT` status bound to the exact envelope digest and policy version. `REVOKED`, `UNKNOWN`, malformed or mismatched status, exceptions, expired status, future status beyond allowed clock skew, or a status older than the configured 30-second maximum all deny. The status validity interval may not exceed that same bound. The default revalidator rejects all checks; the bundled test fake is not an authority adapter. This seam does not establish a trust source, policy distribution, revocation protocol, or operational cache behavior.

`execute()` performs revalidation within its gate call immediately before replay consumption and callback invocation. A status may change after the check and before or during the external effect; this residual TOCTOU window is not eliminated by the local library. `authorize()` remains a permission decision that consumes the grant, not evidence that an action was attempted or completed.

## Optional CNS integration

The [CNS integration contract](docs/CNS_INTEGRATION.md) documents the optional ALPHA and OMEGA result adapters. The CNS package remains a caller-supplied optional dependency; Enforcer does not add a hard dependency or treat CNS gate results as authorization grants.

## Project One Ring relationship

The RACE investigation prompt is preserved at [`docs/PROJECT_ONE_RING_RACE_PROMPT.md`](docs/PROJECT_ONE_RING_RACE_PROMPT.md). The intended order remains: inspect the Constitution and real repositories, map the actual action paths, identify existing enforcement, and only then determine whether this prototype should be integrated, adapted, separated, or rejected.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md), and [`docs/IMPLEMENTATION_BACKLOG.md`](docs/IMPLEMENTATION_BACKLOG.md) for the current boundaries and known gaps.

## Human approval boundary

Local source and test commands operate on this checkout. Repository publication does not authorize a production deployment, select a trusted issuer, establish protected-policy authority, or make constitutional changes.
