# Threat model — Enforcer 0.1.0

## Assets to protect

- A consequential action callback from being invoked without a grant accepted by the configured verifier.
- Binding between grant and exact subject, action, target, and request.
- Single-use behavior within the replay store's coordination domain.
- Explicit denial when proof verification, time validation, or replay storage fails.

## In-scope attacks tested by the current unit tests

- Missing or invalid proof.
- Unexpected verifier exception.
- Subject, action, target, or request substitution.
- Expired or future-issued grant.
- Grant lifetime exceeding local policy.
- Reuse of a consumed nonce or request ID.
- Replay database failure.
- Attempted action callback after denial.

These are unit-level tests against the prototype, not evidence that real-world consumers are protected.

## Out of scope / unresolved

- Compromised issuer, identity provider, signing key, verifier, Python process, host, or database administrator.
- Unsafe or misconfigured `ProofVerifier` that returns untrusted claims.
- Unsafe, compromised, or misconfigured authorization revalidator; this is a high-trust seam and the test fake proves no authority.
- A direct alternate action path that bypasses `execute`.
- Replay across restarts when the in-memory default store is used, multi-host race/replay behavior unless a persistent shared store is supplied, and replay-store growth/retention operations.
- Truth, completeness, freshness, or relevance of evidence referenced by the proof.
- Authority disputes between humans, laws, organizational policy, and constitutional articles.
- Malicious changes to source code, tests, CI, workflow permissions, deployment configuration, or trust-root configuration.
- Availability attacks and operational recovery beyond fail-closed denial at the local gate.

The default authorization revalidator denies because no trusted current-policy or revocation source has been selected. Configured status is accepted only when bound to the exact envelope digest and policy version, checked within the configured maximum age, and still within its declared validity interval. Status-source failure is fail-closed. This bounds stale responses but does not eliminate a status change after checking and before an external effect.

## Security semantics

- Integrity is not truth.
- Authentication is not authorization.
- A syntactically valid grant is not necessarily a grant from a trusted or sufficiently authorized issuer; the verifier must check that distinction.
- An `ALLOW` result does not prove that an independent policy decision was correct.
- A test pass does not prove this gate sits on the real action path.
- Replay consumption is the last check before `ALLOW` and runs before the action callback. A denied request never touches the replay store, so a transient denial does not burn the grant; a callback that fails after `ALLOW` leaves the grant consumed, and a retry needs a fresh grant.
- Denial caused by missing verifier or replay-store failure is intentional fail-closed behavior, not a successful authorization.

## Required follow-up before any production claim

1. Select and independently review the proof format and cryptographic verifier.
2. Define issuer authority, trust-root governance, revocation, key rollover, and emergency invalidation.
3. Use authenticated subject and resolved-target identities from the actual action path.
4. Trace every consequential consumer and show a bypass test for each alternate route.
5. Choose an atomic shared replay store for distributed deployment, if needed.
6. Protect code, workflow, policy, verifier, and trust-root changes through controls outside the authority of the component being constrained.
7. Record actual action outcomes separately from authorization decisions.
8. Review this prototype against the Constitution and existing repositories; do not assume the prototype must be retained.
