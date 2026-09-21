# AppScan 0.4: analysis and audit operations

This release builds on main `4f0466e`, retaining the latest CLI server-upload metadata and VS Code server/local status feedback. It adds four features from the remaining functionality list. It is not full SonarQube parity; see [FEATURES.md](FEATURES.md).

## Visualforce security analysis

Enable **Analyze Visualforce security with PMD** in project quality settings or set `visualforce: true` in a shared profile. It is off by default to preserve existing policy behavior. The pinned PMD 7.17.0 distribution already contains the Visualforce engine; no extra runtime download is needed in the Docker image.

The server runs the fixed `category/visualforce/security.xml` ruleset against `.page` and `.component` files. The local rule catalog exposes `VfCsrf`, `VfHtmlStyleTagXss`, and `VfUnescapeEl` with PMD's descriptions/examples. Findings support normal project severity overrides, disabled rules, fingerprints, review, baseline comparison, and gates. Requested engine failure or syntax errors make analysis INCOMPLETE; no Visualforce files yields `not_applicable`.

Included Apex controller and object metadata siblings are available to PMD's local type resolution. No org query, uploaded configuration, or source execution occurs. Completeness still depends on included source, type resolution, supported syntax and these three rules. This is not a general taint-analysis engine or a complete Salesforce security assessment.

## Current and baseline SARIF

In **New analysis**, supply current SARIF, baseline source, and baseline SARIF. CLI users can pass:

```bash
python cli.py --server https://appscan.example.internal/appscan \
  --baseline origin/main --sarif current.sarif --baseline-sarif baseline.sarif
```

`POST /api/scans` accepts the baseline SARIF JSON object as `baseline_external`, alongside `external` and the existing base64 `baseline` source ZIP. The CLI's direct-persistence mode supports the same comparison. Scans still use the stored project policy.

Baseline SARIF requires both current SARIF and baseline source. Each result must resolve to a file/line in its respective source snapshot. Normalized tool names must be unique in each report and the two reports must contain the same tool set; include a successful empty run for tools with no findings. Invalid report structures fail the scan; failed tool invocations, invalid locations/results or mismatched current/baseline tool sets make the gate INCOMPLETE and do not update persistent issue history.

Findings are matched using AppScan's existing source-anchor fingerprints, so a line shift alone does not make a finding new. Changed rule/message/source anchors or additional occurrences may be new. Report-native suppression and fingerprint claims are not trusted. Reports must correspond to the supplied revisions; the server does not independently re-run an external scanner. Without baseline SARIF, imported findings are all new against an uploaded source baseline, as before.

The bounded SARIF 2.1.0 subset remains 50 runs / 10,000 findings per report within the HTTP request limit. No URI-base resolution, remote artifact fetching, or unrestricted SARIF ingestion is provided.

## Audit history and export

Administrators can filter audit history by exact actor, action and target, plus inclusive UTC calendar dates. Cursor pagination keeps an upper timestamp/ID boundary, so later audit writes do not shift subsequent pages. Changing filters requires a fresh first page. This is a read boundary, not a cryptographic audit ledger or a database-wide transaction snapshot across requests.

- `GET /api/audit?page_size=100&actor=…&action=…&target=…&since=YYYY-MM-DD&until=YYYY-MM-DD&cursor=…` returns `{items,total,next_cursor,snapshot}`.
- `GET /api/audit/export?format=json|csv` accepts the same filters and exports all matching events, up to **10,000 events and 8 MiB**. Exceeding either bound returns an error; narrow the filters. Export starts its own snapshot and ignores page cursors, so it is not restricted to the visible page.
- JSON includes event IDs, timestamps, actor/action/target, original JSON details strings, count and snapshot boundary. CSV includes the same event columns with a UTF-8 BOM and quotes formula-like cells as text to avoid spreadsheet formula execution.
- Export itself creates an `audit.export` event after building the output; that event is not included in its own export.
- Audit views/exports require administrator password authentication. Project tokens and analyst/viewer accounts cannot access them.
- `/api/audit` without `page_size` retains the legacy latest-200 array response.

## Quality trends

**Quality trends** displays historical total/new findings, imported coverage, changed-line coverage, and Apex duplication. Select one project, exact branch, and optionally a PR number. Branch and PR histories are isolated. Date filters use inclusive UTC calendar dates; display timestamps use the browser locale.

`GET /api/projects/{id}/trends?branch=main&pull_request=&page_size=100&since=…&until=…` returns chronologically ordered values for the latest 1–200 terminal scans, total matching count and a `truncated` flag. The UI offers 50/100/200. Narrow dates to explore an older period. The endpoint checks current project/group/token access.

Historical gates remain immutable. Charts show gate-colored points and exact measures in an accessible table with scan links. Missing metrics and failed scans are gaps, never fabricated zeros. Policy-change markers identify differences between adjacent displayed policy snapshots. Retention can remove old scans; charts reflect retained data, not permanent aggregates. No trend extrapolation, Sonar rating/debt calculation, automatic polling or unbounded chart retrieval is provided.

## Authentication and deployment

The latest main added an embedded default password for CLI/extension use. This release removes that password from current source, defaults and rebuilt bundles while retaining server URLs, User-Agent handling, report synchronization and status messages. Configure `APPSCAN_TOKEN`, explicit environment credentials, or **AppScan: Set Server API Token**. If the embedded password was used on a running server, rotate it there; removing it from code does not revoke it or remove historical Git commits. No live credential or deployment was changed by this release.

Back up the database, check out this release, and run `docker compose up -d --build`. The only schema addition is an idempotent audit timestamp/ID index. Existing records and schemas remain compatible. Run one server instance. No background schedule or outbound integration was enabled.

See [VALIDATION.md](VALIDATION.md) for actual tests and Docker/PostgreSQL validation limits.
