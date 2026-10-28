# Contributing

- Keep the project fail-closed by default.
- Do not add a production allow path until issuer identity, authorization scope, cryptographic verification, trust-root governance, and revocation behavior have been specified and reviewed.
- Do not use a test fake in examples that could be mistaken for production code.
- Add one targeted test for every failure mode changed or introduced.
- Keep claims bounded: state exactly which code path was inspected and which tests were executed.
- Do not describe a passing unit test as proof that a real consequential consumer is governed.
- Do not make repository, policy, trust-root, or deployment changes without explicit authorization from the repository owner.

Run tests with:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

CI runs the CNS integration tests in a separate `cns` job with `ENFORCER_REQUIRE_CNS=1`, so a missing `cns` fails the run and those tests cannot skip. Local runs without CNS on the path and without the variable still skip them, so a standard-library-only contributor can run the suite.
