# Release validation: 0.3

This release incorporates the user's updated main through **31e269d**, including the dashboard redesign, selective Salesforce tests, CLI packaging fixes, and VS Code reporting changes. Existing PostgreSQL configuration, `/appscan/` routing, and direct-persistence mode are retained.

- **73 Python tests passed** on SQLite, including existing scanner/test-runner tests and new shared-profile inheritance/cycle rollback, immutable snapshots, group revocation/token scope, atomic bulk rollback, filtered/keyset pagination, notification/portfolio visibility, retention pinning/stale-plan protection, SARIF import/lifecycle, legacy fingerprint compatibility, and changed-line coverage tests. HTTP tests exercise new routes and admin restrictions.
- **Real ESLint 9.39.1:** LWC decorators parse; dynamic eval is detected despite inline disable directives; uploaded executable ESLint configuration is not executed; malformed JavaScript reports an error. Missing requested engine makes the gate INCOMPLETE.
- **Real PMD 7.17.0 and CPD:** current/baseline demonstration scans completed without engine errors; Apex CRUD/SOQL injection and privileged permissions found. CPD completed. Gate was FAIL as expected for the deliberate vulnerabilities.
- **Browser workflow passed:** headless Chromium, routed dashboard and `/appscan/` redirect; login, project/user/policy setup, named profile binding, group editing, portfolio creation, retention preview, real PMD/CPD upload, source browsing, bulk issue review, notifications/read state, and viewer restrictions. Desktop/mobile screenshots inspected; no page errors or horizontal overflow at 390px. No live data was purged; retention apply is tested in temporary databases.
- **VS Code TypeScript compilation and Python bundle synchronization:** passed. New Python modules are included; JavaScript dependencies remain server/operator installed.
- **Python/JavaScript syntax and git whitespace checks:** passed.
- **Docker image build / live PostgreSQL:** not run. No Docker daemon is available, and installation of PostgreSQL was blocked by environment package-install permissions. SQL portability and tests do not establish runtime PostgreSQL migration success. Use a backed-up staging Ubuntu deployment to validate image construction, database migration, volume ownership, and restart behavior.
- **Salesforce org test execution:** existing test-runner unit tests use mocks; no Salesforce org was contacted in this release verification.
- **GitHub check decoration / outbound notifications:** no live helper check run or outbound notification was published. In-app notifications are implemented.

Schema changes are additive and SQLite migration is idempotent. Scan cleanup is opt-in, requires an unchanged preview hash, and is designed for one server process. Do not run multiple instances or operator direct-persistence writes concurrently with maintenance.

See [FEATURES.md](FEATURES.md) for remaining product gaps. This is not full SonarQube parity.
