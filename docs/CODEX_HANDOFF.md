# Codex handoff — import Enforcer into its GitHub repository

The repository `wking53214/Enforcer` was confirmed empty when this scaffold was created. This package was built locally; it has not been pushed.

## Task for Codex

1. Inspect the current working directory, Git status, branch, remotes, and repository root before changing anything.
2. Confirm that this is the `wking53214/Enforcer` checkout. Do not proceed in another repository.
3. Copy the supplied project files into the repository root without nesting an extra `enforcer/` folder inside the repository. Preserve the documented file layout.
4. Do not overwrite any pre-existing untracked or user-authored file without reporting the collision first. The remote was empty at scaffold time, but verify current state rather than assuming it remains empty.
5. Run the documented standard-library tests and a compile check. Report the actual commands, test count, and results.
6. Inspect the complete diff for accidental secrets, generated files, incorrect paths, and unsupported security claims.
7. Do not add a production cryptographic verifier, grant issuer, signing key, new architecture, or dependency without a separate explicit design decision.
8. If all checks pass, commit and push this scaffold to `wking53214/Enforcer`, as the repository owner requested. Do not modify any other repository. If the remote state differs, authentication fails, or a conflict appears, stop and report rather than force-pushing or rewriting history.
9. Report the resulting commit SHA and the exact verification results. Do not describe the prototype as production-ready or as a complete One Ring implementation.

## Commands

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
python -m compileall -q src tests
```

Before any push, the diff must show only this project's intended files. Never use `git push --force` for this handoff.
