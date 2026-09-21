# SonarQube feature coverage and remaining work

The request is to include SonarQube's features. This release implements a sizeable Salesforce-focused foundation; it does **not** finish full parity. SonarQube is a multi-language product with proprietary engines, integrations, and enterprise features that cannot truthfully be replaced with placeholder UI. The reference is [SonarQube Server documentation](https://docs.sonarsource.com/sonarqube-server), not a claim that every listed feature is available in every Sonar edition.

| Area | AppScan 0.3 | Limits / pending work |
| --- | --- | --- |
| Projects | Implemented | Name-based project identity; no project rename/deletion UI |
| Project access | Implemented | Explicit members, groups, global admin/analyst/viewer roles; no nested groups/custom permission templates |
| Branch analysis | Implemented | Branch supplied by CLI/UI; no automatic remote branch discovery |
| Pull request analysis | Partial | Isolated PR namespace and baseline comparison; no automatic GitHub App/webhook ingestion |
| Quality gates | Implemented | Blocker count, overall imported coverage, Apex duplication, hotspot review |
| New-code evaluation | Partial | Finding fingerprints vs uploaded baseline/prior branch; changed-line coverage from explicit line hits + uploaded baseline; no date/version period |
| Quality profiles | Implemented | Per-project PMD categories, exclusions, disabled rules, severity overrides; named shared profile inheritance with project overrides |
| Rule catalog | Implemented | Reads pinned PMD rule descriptions/examples plus metadata rules |
| Bugs / reliability | Partial | PMD error-prone rules; currently reported as quality findings, not semantic Sonar bug taxonomy |
| Vulnerability analysis | Partial | PMD Apex security and selected XML checks; no Sonar proprietary dataflow engine |
| Code smells | Implemented | Selected PMD categories; not equal rules/scoring to Sonar |
| Security hotspots | Implemented | Selected heuristic/metadata findings with mandatory review comments |
| Issue persistence | Implemented | Fingerprint matching; fixed/reopened and reviewed states |
| Assignees/comments | Implemented | Enabled project users; in-app assignment/review notifications; no email |
| Issue search/filter | Implemented | Project, branch, status, assignee, kind, severity, text; filters before cursor pagination |
| Bulk issue changes | Implemented | Atomic batches up to 100 issues with mandatory comments |
| Source browser | Implemented, opt-in | Code files retained only when policy permits; plain text/line numbers, no blame or rich navigation |
| Line/file measures | Partial | Lines/nonblank and labelled lexical decision/comment estimates; no semantic complexity/debt/rating model |
| Coverage import | Implemented | LCOV line hits, Salesforce aggregate JSON, normalized JSON; changed-line coverage; caller-side selective Apex tests preserved; no branch coverage |
| Duplication | Implemented | PMD CPD Apex, 100-token threshold; no all-language duplication |
| History/trends | Partial | Paginated scan history with gate/count/coverage/duplication; no time-series charting/long-term aggregates |
| Report export | Implemented | JSON, Markdown, SARIF and metadata manifests; no PDF executive report |
| CI gate enforcement | Implemented | CLI nonzero exit status, no silent fallback |
| GitHub decoration | Optional helper | Check run + first 50 annotations; requires runner token/config; not live-tested against GitHub |
| GitLab/Bitbucket/Azure DevOps | Pending | CLI can run there; no native decoration adapters |
| API tokens | Implemented | Hashed, expiring, project-scoped read/scan; no enterprise token policy management |
| Users / roles | Implemented | Local PBKDF2 passwords and bootstrap admin; no MFA/password recovery/SSO |
| Audit history | Implemented | Policy/user/token/scan/issue events; capped UI list, not immutable external audit storage |
| VS Code | Partial | Existing manual scanning/diagnostics/report; secure token storage added; no Sonar connected-mode protocol |
| Webhooks / notifications | Partial | In-app gate/assignment notifications; no outbound webhooks, Slack/email, or scheduled scans |
| Multi-language analysis | Partial | Apex + opt-in fixed ESLint JavaScript/LWC rules; external SARIF import; no native TypeScript/Visualforce security engine |
| Taint/cross-file security | Pending | No new taint-analysis engine or proprietary Sonar rules |
| Dependency vulnerabilities / SBOM / licenses | Pending | Requires a maintained advisory source and dependency scanner |
| Architecture rules | Pending | No dependency-graph/architecture policy engine |
| Portfolios / applications | Partial | Flat cross-project gate/findings summaries; no hierarchy or application dependency graph |
| Enterprise identity | Pending | SAML/OIDC/LDAP/SCIM; local groups implemented |
| High availability / clustering | Pending | Single app worker/instance; PostgreSQL storage supported |
| Retention / lifecycle automation | Partial | Preview/hash-confirmed scan and source cleanup; disabled by default, no scheduler; issue/audit retention pending |
| AI fix suggestions | Pending | No generated patches or external AI source upload |
| Salesforce metadata delta manifests | Implemented | Supported mapping types only, no dependency resolver or automatic deployment |

## Suggested next implementation stages

1. Production hardening: live PostgreSQL/Docker deployment testing, audit export, notification/issue retention, retention scheduling.
2. Broader Salesforce analysis: Visualforce security rules, richer Flow/permissions analysis, TypeScript, cross-file analysis, baseline SARIF comparison.
3. DevOps automation: GitHub App setup/webhooks, check lifecycle/cancellation, GitLab/Azure adapters, outbound notifications.
4. Enterprise scope: SSO, distributed workers, hierarchical portfolios and dependency/SBOM analysis.

These stages are a backlog, not features silently represented as complete. Implementations need their own tests and operational validation before claiming parity.

Version 0.3 behavior and operational constraints are documented in [TEAM_ANALYSIS.md](TEAM_ANALYSIS.md).
