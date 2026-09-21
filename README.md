# AppScan 0.4 — on-premises Salesforce quality platform

AppScan scans Salesforce source and metadata on Ubuntu Server/Docker, with a web dashboard, CLI, and VS Code extension. It uses PMD for Apex analysis and duplication detection. This is an independent implementation, not SonarQube or a claim of complete SonarQube parity.

See [the feature matrix](docs/FEATURES.md) for implemented features, limited implementations, and pending work.

See [the 0.3 team and analysis guide](docs/TEAM_ANALYSIS.md) for setup, API contracts, retention semantics, and import limitations.

See [the 0.4 analysis and audit guide](docs/ANALYSIS_OPERATIONS.md) for Visualforce, baseline SARIF, trends, and audit export.

## Features in this release

- Opt-in PMD Visualforce security checks for pages/components, with baseline comparison.
- Current/baseline SARIF comparison for imported findings, with matching-tool validation.
- Filtered, paginated audit history and bounded JSON/CSV export.
- Project/branch/PR quality charts with exact data tables and missing-value gaps.

- Named shared profiles with inheritance and project overrides; group access.
- Atomic bulk reviews, paginated issues/history, in-app notifications, and flat portfolios.
- Opt-in JavaScript/LWC ESLint analysis, external SARIF import, and changed-line coverage gates.
- Retention preview/apply with protected issue references and separate source cleanup.

- Projects, branch history, isolated PR analysis namespaces, commit traceability.
- PMD Apex security, performance, design, error-prone, best-practice, and code-style categories; PMD and metadata rule catalog, plus 13 opt-in ESLint rules.
- Per-project quality profiles: categories, disabled rules, severity overrides, and path exclusions.
- Configurable overall/new-finding gates, blocker thresholds, imported coverage thresholds, duplication thresholds, and hotspot-review requirements.
- Stable issue fingerprints; open/confirmed/accepted/false-positive/safe review; assignees, required comments, automatic fixed/reopened lifecycle.
- Security hotspots for selected metadata permissions, system-context flows, and possible secrets.
- File/line measures, imported coverage, PMD CPD duplicate blocks, history with gate/coverage/duplication values.
- Optional authenticated source browsing. Source retention is disabled by default.
- Admin/analyst/viewer roles, explicit project membership, expiring project-scoped API tokens, token revocation, audit events.
- Salesforce metadata comparison and generated deployment/deletion manifests.
- JSON, Markdown, and SARIF reports; CI exit status; optional GitHub check-run decoration helper.
- PostgreSQL when explicitly configured, otherwise SQLite. A configured PostgreSQL failure never switches to SQLite.
- Existing `/appscan/` reverse-proxy route and VS Code integration retained.

## Install on Ubuntu

Install [Docker Engine and Docker Compose](https://docs.docker.com/engine/install/ubuntu/), then:

```bash
git clone https://github.com/SRKT10950/AppScan.git
cd AppScan
# Until this release is merged, use its review branch:
git switch feature/analysis-operations
./setup.sh
```

The script generates a random admin password in `.env`, builds the image, and starts AppScan. Read `.env` locally for credentials. Default server URL is **http://127.0.0.1:8089**. Enable the Docker service to start containers at boot:

```bash
sudo systemctl enable docker
docker compose ps
docker compose logs --tail=100 appscan
```

From Windows PowerShell or another machine, use an SSH tunnel:

```powershell
ssh -N -L 8089:127.0.0.1:8089 ubuntu@YOUR_SERVER_IP
```

Then browse to **http://localhost:8089**. Replace `ubuntu` with your Ubuntu login. Keep the tunnel open. For shared access, use an HTTPS reverse proxy; credentials and source must not traverse unencrypted public HTTP. The server supports both `/` and `/appscan/`, redirecting `/appscan` to the trailing-slash URL. Apply authentication rate limits at the proxy.

Docker allocations: 2 cores, 2 GiB RAM, Java heap 768 MiB. Start here and measure actual workloads. The first image build requires internet access; local scanning thereafter does not. PMD 7.17.0 and its downloaded ZIP checksum are pinned. Base image and OS packages still require normal patching.

## Upgrade an existing installation

1. Back up the database and `.env` on a separate physical machine/disk.
2. **If you currently use central PostgreSQL, set its real connection explicitly in `.env` before upgrading.** Earlier Compose files embedded a default database URL/password; this release removes that default. Leaving all database settings blank now deliberately selects SQLite. AppScan does not migrate data between database engines.
3. If the old committed example database password was used for a real database, rotate it and update `.env`.
4. Pull/switch to this release and run `docker compose up -d --build`.
5. Check logs and `/readyz`, sign in as the environment-configured admin, and assign project members.

Existing scan records are preserved. Startup adds platform tables and idempotently links legacy scans to projects on branch `main`. Legacy issue history is not fabricated; new scans start persistent tracking. Queued/running scans interrupted by a restart become failed and must be resubmitted. Schema changes are additive; restore a database backup for rollback. Run one application instance against each database.

### PostgreSQL

Set one of these in `.env` (prefer a dedicated least-privilege DB role/database):

```dotenv
DATABASE_URL=postgresql://appscan:YOUR_URL_ENCODED_PASSWORD@host.docker.internal:5432/appscan_db
```

Or set `CENTRAL_PG_HOST`, `CENTRAL_PG_PORT`, `CENTRAL_PG_USER`, `CENTRAL_PG_PASSWORD`, and `CENTRAL_PG_DATABASE`. `DATABASE_URL` takes precedence. The image installs psycopg2; Compose defines Linux `host.docker.internal` through `host-gateway`. Configure PostgreSQL network access/TLS appropriately. Connection failure stops readiness/operations rather than writing to a different database.

### SQLite backup

With no PostgreSQL configuration:

```bash
docker compose exec -T appscan python -c 'import sqlite3; s=sqlite3.connect("/data/appscan.db"); d=sqlite3.connect("/data/backup.db"); s.backup(d); d.close(); s.close()'
docker compose cp appscan:/data/backup.db ./appscan-backup.db
```

Copy the backup off the server. Use `pg_dump`/your established backup process for PostgreSQL. Scan results, audit entries, and optionally retained source grow over time; automatic retention is not implemented. Monitor disk use.

## First analysis

1. Sign in, create/select a project, and configure its policy.
2. Upload `examples/current.zip` and `examples/baseline.zip`. These contain deliberately insecure demonstration code; never deploy them.
3. Set the target org's Metadata API version, branch, and optional PR/commit identifiers.
4. Run analysis. Expect Apex CRUD/SOQL injection findings and a privileged-permission hotspot.
5. Review findings and metadata changes, inspect gate conditions, and download the report.

For your own repository:

```bash
git archive --format=zip --output=/tmp/baseline.zip BASE_COMMIT
git archive --format=zip --output=/tmp/current.zip HEAD
```

The scanner never deploys to Salesforce. Manifests contain component names only: include required source, resolve dependencies, review destructive changes, and validate in a sandbox before deployment. Unsupported metadata is listed and omitted. No baseline means a full inventory of supported components, with no inferred deletions.

## Projects, reviews, and gates

An administrator creates projects and user accounts. Non-admins see only projects where their username is explicitly listed in project members. Analysts can submit scans/review issues; viewers can read. Admins can manage all projects. Global administrator access is intentional. The `.env` admin account remains available as a bootstrap account and is not editable in the UI.

A scan snapshots its policy. Later policy edits and issue reviews do not rewrite historical results; rescan to apply them. Accepted, false-positive, and safe issues do not block the next scan's gate. `safe` is available only for hotspots. Every review requires a comment and records an audit event. An assignee must be an enabled project member. Fixed/reopened states are determined by subsequent scans. Engine failures do not close absent findings; changing analysis scope does not mark excluded rules/files as fixed.

| Gate | Meaning |
| --- | --- |
| PASS | Implemented checks and required measures meet the selected policy. Not a security certification. |
| FAIL | One or more configured conditions failed. |
| INCOMPLETE | An engine/parser failed, or a required coverage/duplication measure is missing. |

“New” uses finding fingerprints compared with an uploaded baseline, or earlier findings in the same branch/PR namespace. It is not a line-level Sonar new-code-period implementation. First scans without a reference treat all findings as new. Fingerprints use rule, canonical path, normalized source anchor, message, and occurrence; substantial line/message/path changes can create a new issue.

PMD priorities map to Critical/High/Medium/Low; security rules are at least High unless an admin overrides them. Metadata rules are limited checks, and secret detection is heuristic. Coverage and duplication conditions always apply to overall supplied/analyzed code even when the blocker scope is “new.” Policy exclusions affect analysis but not metadata manifests. PMD categories execute locally; disabled findings are filtered from results. A PMD parse error still makes analysis incomplete.

Enable source retention only if you want code stored in the database for authenticated browsing. It can retain secrets present in source; protect and back up that database accordingly. When disabled, source is held transiently and is not available in the code browser. Scan reports still contain file paths, identifiers, and engine messages.

## CLI and CI

Python 3.12 is recommended. Run the CLI from your Salesforce checkout:

```bash
export APPSCAN_URL=https://your-server/appscan
# Set APPSCAN_TOKEN securely in the shell/CI secret store.
python3 /opt/appscan/cli.py --project OMSI --branch uat --baseline main --use-head
```

Create a project-scoped **scan** token in Administration. Tokens expire after 1–365 days and are stored only as hashes. Copy the displayed token once. Read tokens cannot submit scans or mutate reviews/settings. Scan tokens can submit/read only their project; they cannot administer users, review issues, or mint tokens. Password changes/disabled accounts revoke their stored tokens.

Optional arguments: `--pull-request 123`, `--revision FULL_SHA`, `--coverage path/to/lcov.info`, `--output-dir .appscan`. Coverage accepts LCOV, normalized JSON (`files[]`), or Salesforce CLI aggregate JSON (`result.coverage[]` containing name/numLinesCovered/numLinesUncovered). The browser currently accepts normalized JSON only:

```json
{"files":[{"path":"classes/AccountService.cls","covered_lines":80,"uncovered_lines":20}]}
```

Coverage is caller-provided, not generated or verified against a test run by AppScan. Zero coverable lines produces no percentage. Keep the imported report scoped to the analyzed project. New-code coverage and branch coverage are not implemented.

The CLI writes JSON/SARIF/manifests and exits 1 for FAIL/INCOMPLETE. Runtime errors are nonzero. A requested baseline failure is fatal. Server failure never silently falls back to local defaults; use `--offline` explicitly for direct local scanning (requires Java/PMD for Apex). If database settings or `DATA_DIR` are explicitly configured, direct scans also persist using the project policy, issue lifecycle, and branch context. This operator-only path requires database credentials, runs serially, and does not apply HTTP user permissions; use the server API for normal users. With no explicit database configuration, offline results remain local files. The server polls may take up to 11 minutes for current+baseline+duplication analysis. CI should fail when the command fails or a report is absent.

[GitHub Actions example](docs/github-actions.example.yml) uses a protected self-hosted runner that can reach AppScan. Install this app at `/opt/appscan`; configure `APPSCAN_TOKEN` as a secret and `APPSCAN_URL` / `APPSCAN_PROJECT` as variables in the Salesforce repository. The optional `scripts/github_check.py` publishes a check for the exact analyzed commit with up to 50 annotations and requires `checks:write`. This example is not active in this repository and no GitHub decoration has been sent during implementation. Do not use an untrusted fork on a runner with private-network access. Pin/review Action versions under your organization's policy.

## VS Code

Your existing extension remains supported. Version 0.2 adds **AppScan: Set Server API Token**, storing the token in VS Code SecretStorage for the configured server URL. Legacy password configuration still works, but a token avoids putting a password in settings. The extension sends branch/revision context, requires a trusted workspace, and reads each scan's unique output directory. Missing/failed scans cannot display an old or fabricated passing result.

```bash
cd vscode-extension
npm ci
npm run compile
```

Compilation synchronizes the authoritative root `app/` and `cli.py` into the extension bundle before TypeScript compilation. Manual scans and local diagnostics are supported; this is not Sonar's connected IDE protocol or continuous scan-on-save.

## API

Basic auth or `Authorization: Bearer aps_...` is required except for assets and liveness/readiness. HTTP JSON API accepts both root and `/appscan` prefixes.

| Endpoint | Purpose |
| --- | --- |
| `GET /api/me` | Current user/role/token scope |
| `GET, POST /api/projects` | Visible projects / admin creation |
| `POST /api/projects/{id}` | Save full `settings` and `members` (admin login) |
| `POST /api/scans` | Queue source ZIPs (`current`, optional `baseline` are base64), project name, branch/PR/revision/version, optional coverage |
| `GET /api/scans?project_id=...&branch=...` | Latest 100 visible analyses and measures |
| `GET /api/scans/{id}` | Status, immutable scan result and context |
| `GET /api/scans/{id}/report.zip` | Reports and manifests |
| `GET /api/scans/{id}/report.sarif` | SARIF export |
| `GET /api/scans/{id}/source?path=...` | Retained code if enabled; project access enforced |
| `GET /api/issues?project_id=...` | Up to 2,000 issues; optional branch/status/assignee/kind/search filters |
| `POST /api/issues/{id}` | Review with status, optional assignee, mandatory comment |
| `GET /api/issues/{id}/comments` | Review conversation |
| `GET /api/rules` | Locally installed rule catalog |
| `GET, POST /api/users` | Admin list/create/update users |
| `GET, POST /api/tokens` | Own token metadata / create token using password login |
| `POST /api/tokens/{id}/revoke` | Revoke own token |
| `GET /api/audit` | Latest 200 admin-visible audit events |
| `/healthz`, `/readyz` | Process liveness / database readiness |

## Limits and validation

One worker; maximum three queued/running scans. ZIP limits: 20 MiB compressed, 100 MiB expanded, 2 MiB/file, 100,000 entries. The server never executes uploaded source. Optional CLI selective tests run in the authenticated Salesforce org. Traversal paths, symlinks, encrypted archives, and duplicate component paths are rejected. PMD and CPD each have a 180-second timeout; current/baseline scans can both run. No SSO, clustering, server-side Git fetching, automated org retrieval, or complete multi-language analysis yet.

```bash
python -m unittest discover -s tests -v
node --check app/static/app.js
node --check app/static/platform.js
```

See [validation notes](docs/VALIDATION.md) for results and remaining environment-dependent checks.

## References

- [SonarQube Server feature concepts](https://docs.sonarsource.com/sonarqube-server)
- [PMD](https://pmd.github.io/)
- [Pinned PMD release](https://github.com/pmd/pmd/releases/tag/pmd_releases%2F7.17.0)

AppScan is MIT licensed. PMD and other dependencies retain their own licenses.
