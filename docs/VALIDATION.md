# Release validation

This release incorporates the user's updated `main` through 11b81fa, preserving PostgreSQL, `/appscan/`, CLI, and VS Code work.

Completed checks and their results are recorded here before publishing. No Docker, PostgreSQL deployment, or GitHub check-decoration success is inferred from unit tests.

- Automated Python tests: 42 tests passed.
- Real PMD 7.17.0: Apex CRUD and SOQL injection found in demonstration source; current/baseline scanning completed.
- Rule catalog: 72 entries loaded from local PMD plus built-in metadata rules.
- PMD CPD: duplicate-report XML namespace handling verified using deliberate duplicate Apex code: one group, 175 tokens, 100% duplicated lines.
- Python and JavaScript syntax checks: passed.
- VS Code TypeScript compilation and bundle sync: passed.
- Browser workflow: passed in headless Chromium at desktop and mobile widths: login/error handling, project/user/policy setup, real scan with baseline and coverage, source browsing, hotspot review, rule detail, token creation/revocation, report download, and viewer restrictions. No browser page errors or mobile horizontal overflow.
- Docker image build / live PostgreSQL migration: not run in this environment; no Docker/PostgreSQL daemon available. Test with a backup on a staging Ubuntu deployment before merging/deploying.
- Optional GitHub check-run publication: helper supplied, no live GitHub write performed by that helper.

The SQLite migration is tested for idempotence and legacy scan preservation. PostgreSQL SQL uses the same schema and transactions but needs runtime validation against the target server. Configured DB failures no longer fall back to SQLite.
