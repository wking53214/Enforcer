# Decision records

## ADR-0001 — Build a bounded gate prototype before claiming a target architecture

**Status:** Accepted for prototype only; subject to the Project One Ring investigation.

### Context

The repository is newly created and the full source-grounded One Ring audit has not yet established which existing component should own authorization enforcement. The project needs a concrete, testable starting point without pretending that the Constitution is already operational.

### Decision

Implement a narrow library boundary that checks a supplied, externally authenticated grant against the exact subject, action, target, request ID, time window, and replay state before invoking one callback. The default verifier rejects all proofs. Grant issuance and production cryptographic verification are not implemented here.

### Why

This provides a falsifiable prototype for one critical invariant—authorization must be action-bound and denial must prevent the guarded callback—without choosing an issuer, identity provider, cryptographic format, trust-root policy, central governor, or final repository architecture before evidence is gathered.

### Consequences

- The prototype is not production-ready.
- A configured `ProofVerifier` is trusted and must be independently designed and reviewed.
- This library cannot enforce that all consumers use the gate.
- A local SQLite store does not supply multi-host replay protection.
- The full audit may recommend integrating this code elsewhere, adapting it, retaining it as a concept, deferring it, or rejecting it.
- No repository mutation outside this local build, no push, and no production deployment is authorized by this ADR.

### Falsification conditions

Reject or redesign this prototype if source investigation shows an existing component already provides a better-supported capability; if the real action path cannot be made to call this gate safely; if its trust assumptions cannot be kept independent from the constrained authority; or if targeted adversarial tests reveal a bypass or incorrect grant binding.
