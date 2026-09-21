# AppScan 0.3: teams and broader Salesforce analysis

This release builds on main `31e269d`, preserving the routed dashboard, CLI selective Salesforce tests, resilient VS Code reporting, and Salesforce-aware ZIP packaging.

## Shared policies and project access

Open **Teams & portfolios** as an administrator. Create a named quality profile with a JSON object containing only its overrides, for example `{"javascript":true,"min_coverage":75}`. Profiles can inherit from one parent, up to eight levels. Cycles and invalid settings roll back the update. Bind a profile to the selected project; project overrides take precedence. Detaching preserves the effective policy as a standalone policy. Queued and historical scans keep their original policy snapshots. Shared profile changes affect future scans.

Groups contain enabled local users and grant access to selected projects. A user's global role still controls whether they may submit scans or review issues. Project-scoped tokens cannot escape their project, including through groups. Group changes take effect on the next request. Nested groups and custom permission templates are not implemented.

Use the checkboxes in **Issues & hotspots** to review up to 100 issues atomically. Every review requires a comment and validates project access. One invalid/inaccessible issue rolls back the whole batch. The issue list filters before applying its 50-row page boundary. The API supports up to 200 rows/page and includes a total count. Historical scan gates do not change after reviews; rescan to evaluate the updated gate.

Assignment/review and gate-transition notifications appear in the recipient's dashboard. The inbox shows up to 100 recent notifications and rechecks project visibility. There are no outbound emails or webhooks in this release.

Portfolios summarize the latest completed non-PR scan per project, across branches. The UI states this selection rule. A portfolio is hidden unless the viewer can access every member project. These are flat summaries, not application dependency graphs or hierarchical enterprise ratings.

## JavaScript and LWC

Enable **Analyze JavaScript / LWC with ESLint** in project quality settings. The Docker image includes Node 22, pinned ESLint 9.39.1, and a Babel parser supporting LWC decorator syntax. Thirteen fixed core rules cover dynamic code evaluation and selected reliability checks. Rule IDs begin with `ESLint/`, appear in the catalog, and support project disable/severity overrides. Uploaded configuration, Babel configuration, inline disable directives, and uploaded JavaScript modules are never executed by the analyzer. It parses source via ESLint `lintText` with a server-owned configuration.

For a source installation:

```bash
npm --prefix analyzers/javascript ci --omit=dev --ignore-scripts
```

Node must be on PATH. `APPSCAN_JS_RUNNER` may point to an administrator-installed `scan.mjs`; never point it to scanned repository content. Missing dependencies, parse errors, and timeouts produce INCOMPLETE when analysis is requested. The VS Code Python bundle does not bundle Node dependencies; use server scanning, or explicitly install/configure this analyzer for operator-managed direct scans. Generic TypeScript, Visualforce security rules, cross-file taint analysis, and all SonarJavaScript rules are not provided.

## External SARIF

Upload SARIF 2.1.0 in **New analysis**, pass `--sarif report.sarif` to the CLI, or include the JSON object in `POST /api/scans` as `external`. The supported subset requires a message, a repository-relative location resolving to one included file, and a valid source line. File/HTTP URLs, traversal, URI base references, ambiguous/unresolved paths, and malformed results are rejected or make analysis incomplete. At most 50 runs and 10,000 findings are accepted within the existing HTTP body limit. No artifacts are downloaded and report suppressions do not bypass project review.

Imported findings are explicitly caller-supplied evidence, identified as `SARIF:<tool>` and `External/<tool>/<rule>`. They are not re-verified by AppScan. `error` maps to High, `warning` to Medium, and `note`/`none` to Low. Imports do not claim security taxonomy based on untrusted custom properties. When comparing an uploaded source baseline, imported findings count as new because baseline SARIF is not supplied. Without an uploaded baseline, persisted branch fingerprints are used. Omitting a tool's report never marks that tool's previous findings fixed; include a successful empty run to establish no findings for that tool.

## Changed-line coverage

The CLI preserves LCOV `DA` hits. The API/UI also accept normalized records with explicit `line_hits`:

```json
{"files":[{"path":"classes/AccountService.cls","covered_lines":1,"uncovered_lines":1,"line_hits":{"10":3,"11":0}}]}
```

Set `min_new_coverage` or the changed-line coverage field in quality settings. An uploaded source baseline is required. The metric intersects inserted/replaced source lines with explicit executable-line entries; it does not infer executable lines from aggregate percentages. Aggregate-only Salesforce coverage does not establish new-line coverage. Changed files without line data, ambiguous mappings, or out-of-range lines produce an unavailable metric, and a required gate becomes INCOMPLETE. If no executable lines changed, the condition is NOT_APPLICABLE. Reports remain caller-supplied and must correspond to the uploaded revision. Branch coverage and date/version-based new-code periods are not implemented.

Selective Salesforce tests added on main remain available through CLI `--run-tests`; they execute through the authenticated Salesforce CLI in the caller's environment. The server only imports coverage and never executes uploaded source or calls Salesforce orgs.

## Retention

Retention is disabled by default. Select a project, save a retention policy, then **Preview selected project**. The exact plan lists scan IDs and source IDs. **Apply previewed cleanup** sends that plan's hash; if the eligible set or policy changed, it is rejected and requires a fresh preview.

- Age cleanup retains at least `keep_count` completed/failed scans per branch and PR namespace.
- Queued/running scans and issue first-seen/last-seen scan references are protected.
- `source_days` independently removes retained source, including source in otherwise pinned scans. The report and issue history remain.
- A zero age disables that cleanup category. Cleanup does not run automatically.
- Retention application and scan-result persistence share a process lock and database transactions. Deploy one server instance; do not run operator direct database scans concurrently with server maintenance. This is not a distributed lock or clustering implementation.
- Profiles, users, notifications, issue comments, and audit rows are not deleted by scan retention. Back up the database and maintain capacity for these records.

## Added APIs

All routes also work beneath `/appscan`. Password authentication is required for mutations other than scan submission; administrator functions additionally require admin role.

| Method / path | Purpose |
| --- | --- |
| GET/POST `/api/profiles` | List/create/update shared profiles (admin) |
| POST `/api/projects/{id}/profile` | Bind/detach shared profile; optional overrides (admin) |
| GET/POST `/api/groups` | List/create/update group memberships (admin) |
| POST `/api/projects/{id}/groups` | Replace group grants (admin) |
| POST `/api/issues/bulk` | Atomic review with `ids`, `status`, `comment`, optional `assignee` |
| GET `/api/issues?project_id=…&page_size=50&cursor=…` | Filtered `{items,total,next_cursor}` page; kind/severity/status/branch/assignee/search |
| GET `/api/scans?page_size=100&cursor=…` | Project/branch-filtered history page with opaque cursor |
| GET `/api/notifications` | Current user's visible inbox |
| POST `/api/notifications/{id}/read` | Mark own notification read |
| GET/POST `/api/portfolios` | Visible summaries / administrator create-update |
| POST `/api/projects/{id}/retention-policy` | Set `days`, `keep_count`, `source_days` (admin) |
| POST `/api/projects/{id}/retention` | Preview `{}` or apply `{apply:true,plan_hash:…}` (admin) |

Legacy list endpoints without `page_size` retain their old array response shapes. The updated dashboard uses pagination.

## Deployment

Back up SQLite or PostgreSQL before upgrading. Build with `docker compose up -d --build` after checking out this release. New tables and indexes are created idempotently; the existing scan table is preserved. Runtime scans require no internet. Image construction downloads PMD and npm dependencies. Use the existing HTTPS reverse proxy; [nginx.example.conf](nginx.example.conf) includes a rate-limit reference for an Ubuntu host proxy. Adjust limits and certificates locally; it is not installed automatically.

See [VALIDATION.md](VALIDATION.md) for actual verification and environment limitations, and [FEATURES.md](FEATURES.md) for remaining work.
