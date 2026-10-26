# Codex / agent instructions for Enforcer

## Project status

Enforcer 0.1.0 is a prototype, not a production security boundary and not the completed One Ring architecture. Read `README.md`, `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, and `docs/DECISIONS.md` before changing behavior.

## Non-negotiable behavior

- Fail closed: missing, invalid, mismatched, expired, replayed, or unverifiable grants must not invoke the guarded callback.
- The default proof verifier must continue to reject all proofs.
- Do not implement grant issuance or embed signing keys in this project.
- Do not add a production verifier until issuer authority, trust roots, identity binding, revocation, key rotation, and protected configuration changes have been specified and independently reviewed.
- Keep identity, integrity, authorization, enforcement, execution, and review as separate concepts.
- Do not treat a digest as proof of truth or authority.
- Do not claim that this package gates all action paths. It only gates calls routed through `Enforcer.execute`.
- Do not treat test fakes as production adapters.

## Development rules

- Use the standard library unless a human-reviewed decision authorizes a dependency.
- Add targeted adversarial tests for behavior changes. Avoid repeatedly running unrelated broad tests without a specific question.
- Keep tests reproducible and deterministic.
- Do not modify any other ≡TACK repository, alter GitHub settings, or change constitutional text from this project.
- Do not claim tests were executed unless they were run and the actual result was observed.
- Preserve unknowns and failed checks in reports; do not infer success from missing output.

## Test command

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```
