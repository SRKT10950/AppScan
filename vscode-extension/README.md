# AppScan - Salesforce Security & Code Analysis for VS Code

On-premises Salesforce code analysis, security linting, quality gates, and git baseline comparison directly inside Visual Studio Code.

## Features

- **Baseline Scanning**: Compare your current uncommitted changes or branch against any Git baseline (e.g. main, uat, origin/main).
- **Real-time Diagnostics & Problems Panel**: Highlights Apex security vulnerabilities, SOQL injection risks, CRUD/FLS violations, and XML metadata issues directly in the editor and Problems tab.
- **Interactive Report Dashboard**: View Quality Gates (PASS / FAIL / INCOMPLETE), metrics, metadata additions/modifications/deletions, and PMD findings in a dedicated webview dashboard.
- **Automatic Manifest Generation**: Produces package.xml and destructiveChanges.xml diffs for deployment.
- **Central PostgreSQL Backend**: Scan records and history persist to your server's PostgreSQL database.

## Commands

- AppScan: Run Scan vs Baseline (main): Instant scan against the default main branch.
- AppScan: Run Scan with Prompted Baseline...: Choose any Git branch, tag, or commit hash as baseline.
- AppScan: Scan Selected Folder...: Run scan focused on a specific directory (e.g. orce-app).
- AppScan: Show Latest Scan Dashboard: Open the interactive results webview.
- AppScan: Clear Diagnostic Findings: Clear diagnostic squigglies and problem markers.

## Requirements

Requires Python 3.10+ installed on the host. AppScan backend runs on http://localhost:8089 or via Docker Compose.

## Version 0.2

Use **AppScan: Set Server API Token** to save a project-scoped server token in VS Code SecretStorage. Tokens are associated with the configured server URL. Branch and commit context is submitted to the central project. Server failures no longer silently run a different local policy; absent reports cannot appear as PASS. Local CLI scanning remains available explicitly through `--offline`.

`npm run compile` synchronizes the root scanner/CLI into the extension before building. A trusted workspace is required to run the CLI. Each run writes to its own `.appscan/run-*` directory, avoiding stale report reuse. These directories can be removed when no longer needed.
