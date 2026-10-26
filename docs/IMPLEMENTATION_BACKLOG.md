# Implementation backlog

This backlog is intentionally a set of review gates, not authorization to deploy.

| ID | Work | Why it matters | Acceptance evidence | Status |
|---|---|---|---|---|
| ENF-001 | Inspect actual consumer path(s) before integrating this gate | A local guard is bypassable if action consumers do not call it | Source map from request through the real consumer; positive and bypass tests | NOT STARTED |
| ENF-002 | Select external proof/issuer model | The current verifier seam is intentionally abstract | Independent review of issuer scope, identity, integrity, revocation and key custody | NOT STARTED |
| ENF-003 | Select trust-root and protected-change controls | A verifier can be undermined if its own trust policy can be changed unilaterally | Demonstrated protected change path plus adversarial test | NOT STARTED |
| ENF-004 | Decide replay-store deployment model | SQLite implementation is local, not multi-host | Concurrency tests against chosen deployment store | NOT STARTED |
| ENF-005 | Specify action-result evidence and independent review | Authorization decision is not proof of execution or outcome | End-to-end trace linking decision to action result and independent review | NOT STARTED |
| ENF-006 | Compare capability with existing ≡TACK repositories | Avoid redundant component and premature architecture commitment | Source-grounded disposition: INTEGRATE / PARTIAL / ADAPT / CONCEPT ONLY / SEPARATE / DEFER / REJECT / NO ACTION | NOT STARTED |
| ENF-007 | Threat-model and adversarially test real adapter | Unit fake cannot validate production cryptography | Targeted tests with test keys, negative cases, tampering and revocation | NOT STARTED |
| ENF-008 | Determine whether and how this repo participates in One Ring | Avoid mistaking a prototype for the target architecture | Human-reviewed architecture decision supported by evidence | NOT STARTED |

## Human decisions required

- What legal/organizational authority may issue each action grant?
- How is human identity authenticated and linked to service accounts, sessions, and agents?
- Which operations are consequential, and how is each target resolved?
- Which controls must be independent, and which failure domains are acceptable?
- Who may alter trusted issuers, verifier behavior, policies, and protected-path rules?
- What is the appeal/override path, and how is reviewer authority verified?

Do not mark backlog items complete based on this document's existence.
