# Release validation: 0.4

This release incorporates the user's latest main through **4f0466e**, including CLI server-upload metadata and VS Code server/local report feedback. It preserves the prior dashboard, selective Salesforce tests, PostgreSQL configuration, `/appscan/` routing, and direct-persistence mode.

- **88 Python tests passed**, with `APPSCAN_TEST_PMD` pointing to the installed PMD 7.17.0 binary. New coverage includes current/baseline SARIF source-anchor matching, tool-set mismatch/ambiguity and failed baseline handling; Visualforce opt-in and missing-engine failure; audit snapshot pagination with tied timestamps and concurrent new events; filter/date/cursor validation; complete multi-page export, byte/row bounds and CSV formula protection; trend branch/PR/date/token isolation, missing metrics, failed scans, policy changes and truncation; HTTP audit/export permissions. Existing tests also cover issue lifecycle, profiles/groups, retention and mocked Salesforce test execution.
- **Real PMD Visualforce integration passed:** `.page` and `.component` XSS detection, `VfCsrf`, identical-source baseline comparison, and malformed-page INCOMPLETE behavior. The Visualforce module uses the fixed PMD ruleset, with no uploaded configuration execution.
- **Browser workflow passed in Chromium:** real Visualforce scan plus matching baseline SARIF yielded the expected new-code PASS; omitting baseline SARIF yielded FAIL; trend chart/table values and missing-coverage gaps matched reports; filtered JSON and CSV exports downloaded with matching contents; viewer project-trend access worked and audit access was denied. Desktop/mobile screenshots inspected; no browser page errors or horizontal overflow at 390px.
- **VS Code TypeScript build and Python bundle synchronization passed.** Latest main's upload status behavior is preserved. The embedded default password is absent from current tracked source, settings defaults, Python bundle and rebuilt JavaScript/maps; no live password was changed or Git history rewritten.
- **Python/JavaScript syntax and git whitespace checks passed.**
- **Docker image build and live PostgreSQL migration:** not run in this environment. No deployment success is inferred from SQLite tests. Validate the image, additive audit index migration, volume permissions and restart behavior on backed-up staging Ubuntu/PostgreSQL before deployment.
- **Salesforce org execution / GitHub check publication:** no live Salesforce org was contacted and no optional check-decoration helper was executed. Salesforce test-runner tests use mocks. No outbound notifications, live retention cleanup or scheduling was enabled.

To reproduce the test suite with the real PMD integration:

```bash
npm --prefix analyzers/javascript ci --omit=dev --ignore-scripts
APPSCAN_TEST_PMD=/absolute/path/to/pmd/bin/pmd python -m unittest discover -s tests -q
npm --prefix vscode-extension ci
npm --prefix vscode-extension run compile
```

Without `APPSCAN_TEST_PMD`, the real Visualforce integration test is explicitly skipped. The real ESLint test is skipped when its node dependencies are absent. Other deterministic tests remain runnable without those engines.

This is an independent Salesforce-focused implementation, not full SonarQube parity. [FEATURES.md](FEATURES.md) and [ANALYSIS_OPERATIONS.md](ANALYSIS_OPERATIONS.md) describe remaining gaps and operational limits.
