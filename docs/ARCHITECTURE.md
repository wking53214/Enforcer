# Architecture and status

## Current status

**Prototype only.** This code provides one narrow mechanism for experimenting with action-bound authorization. It does not implement the complete One Ring design and is not evidence that the Constitution is operational.

## Trust boundaries

```mermaid
flowchart LR
    R[Trusted action-path inputs] --> Q[Versioned ActionEnvelope]
    P[Externally issued proof] --> V[ProofVerifier adapter]
    T[Trusted current status source] --> X[AuthorizationRevalidator]
    Q --> G[Enforcer gate]
    V -->|authenticated claims or denial| G
    X -->|bound status or denial| G
    S[(Replay store)] <--> G
    G -->|DENY: callback not invoked| D[Caller handles denial]
    G -->|ALLOW for exact callback path only| A[Consequential action callback]
    A --> O[Caller-observed result]

    classDef existing fill:#e7e7e7,stroke:#666,color:#111;
    classDef proposed fill:#fff2cc,stroke:#a67c00,color:#111;
    class R,P,Q,V,T,X,S,G,D,A,O proposed;
```

All diagram elements above are intended interfaces in this prototype. The diagram is **not** a source-verified connection to any existing ≡TACK repository or production action consumer.

## Call flow

1. The caller resolves the subject, operation, target, and unique request ID from its trusted context.
2. An external authority issues a grant; issuance is outside this package.
3. The configured `ProofVerifier` authenticates the grant and trusted issuer, then returns `GrantClaims`.
4. Enforcer checks exact v1 envelope binding, including subject/action/target type and ID/evidence digest/request ID/parameter digest/policy version, and grant time bounds.
5. A trusted revalidator checks current policy/revocation status for the exact envelope and policy version. Unknown, revoked, stale, mismatched, or unavailable status denies.
6. The replay store atomically consumes `(issuer_id, nonce)` and the unique `request_id`.
7. Only then does `execute` invoke the supplied callback.
8. The caller remains responsible for recording the actual action result and connecting it to independent review.

## Design limits / unresolved choices

- No production verifier, key format, identity provider, issuer registry, revocation mechanism, or trust-anchor governance is selected.
- The default SQLite store is in-memory and loses replay history on process exit; a file-backed instance persists locally. Neither local mode coordinates replay protection across hosts.
- Replay records are not currently pruned. Retention and cleanup require a policy that does not allow any valid grant to become reusable.
- This library cannot prevent callers from invoking the same action through an unguarded alternate path.
- The current `Decision` is a local function result, not an independently signed, tamper-evident event ledger.
- No constitutional amendment workflow or protected-change mechanism exists here.
- The One Ring investigation must compare this capability with existing repositories before deciding to retain it.

## Action envelope v1

The public request type is `ActionEnvelope`; `ActionRequest` is retained as an alias, but the previous four-field constructor is intentionally incompatible. Canonical bytes are compact UTF-8 JSON with a fixed field order, NFC strings, explicit `null` for absent evidence, exact field-set validation, duplicate-key rejection, and no accepted noncanonical alternate encodings. Digests are lowercase SHA-256 hex. Callers define action-specific parameter canonicalization and provide only its digest. This format binds a supplied policy version; it does not discover or validate policy authority. Target type/ID resolution, authenticated subject provenance, and whether evidence is required remain adapter responsibilities.

An `AuthorizationRevalidator` response must bind the envelope digest and policy version, be checked no more than 30 seconds ago, and remain valid at the current check time. Revoked, unknown, mismatched, stale, future-dated beyond clock skew, malformed, or unavailable status denies. The default adapter rejects all requests. No production status source is implemented. A status change after revalidation remains a TOCTOU risk between the local check and external effect.
