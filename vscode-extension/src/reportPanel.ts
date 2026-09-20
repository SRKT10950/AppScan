import * as vscode from "vscode";

export class ReportPanel {
  public static currentPanel: ReportPanel | undefined;
  private readonly _panel: vscode.WebviewPanel;
  private _disposables: vscode.Disposable[] = [];

  public static createOrShow(extensionUri: vscode.Uri, scanResult: any, project: string) {
    const column = vscode.window.activeTextEditor ? vscode.window.activeTextEditor.viewColumn : undefined;

    if (ReportPanel.currentPanel) {
      ReportPanel.currentPanel._panel.reveal(column);
      ReportPanel.currentPanel.update(scanResult, project);
      return;
    }

    const panel = vscode.window.createWebviewPanel(
      "appscanReport",
      `AppScan Report: ${project}`,
      column || vscode.ViewColumn.One,
      {
        enableScripts: true,
        retainContextWhenHidden: true
      }
    );

    ReportPanel.currentPanel = new ReportPanel(panel, extensionUri, scanResult, project);
  }

  private constructor(
    panel: vscode.WebviewPanel,
    private readonly _extensionUri: vscode.Uri,
    scanResult: any,
    project: string
  ) {
    this._panel = panel;
    this.update(scanResult, project);

    this._panel.onDidDispose(() => this.dispose(), null, this._disposables);
  }

  public update(scanResult: any, project: string) {
    this._panel.title = `AppScan: ${project}`;
    this._panel.webview.html = this._getHtmlForWebview(scanResult, project);
  }

  public dispose() {
    ReportPanel.currentPanel = undefined;
    this._panel.dispose();
    while (this._disposables.length) {
      const x = this._disposables.pop();
      if (x) {
        x.dispose();
      }
    }
  }

  private _getHtmlForWebview(scan: any, project: string): string {
    const gate = (scan.gate || "UNKNOWN").toUpperCase();
    const gateClass = gate === "PASS" ? "pass" : gate === "FAIL" ? "fail" : "incomplete";
    const findings = scan.findings || [];
    const changes = scan.changes || [];
    const warnings = scan.warnings || [];
    const errors = scan.errors || [];
    const qg = scan.quality_gate || {};
    const conditions: any[] = qg.conditions || [];
    const coverage = scan.coverage || null;
    const coveragePercent = coverage && typeof coverage.percent === "number" ? coverage.percent : null;
    const missingCoverage = conditions.some((c: any) => c.metric === "min_coverage" && c.status === "MISSING");

    const criticalCount = findings.filter((f: any) => f.severity === "Critical").length;
    const highCount = findings.filter((f: any) => f.severity === "High").length;
    const medCount = findings.filter((f: any) => f.severity === "Medium").length;
    const lowCount = findings.filter((f: any) => f.severity === "Low").length;

    const metricNameMap: Record<string, string> = {
      min_coverage: "Minimum Code Coverage",
      overall_blockers: "Overall Blocker Findings (Critical/High)",
      new_blockers: "New Blocker Findings (Critical/High)",
      max_duplication: "Maximum Code Duplication",
      unreviewed_hotspots: "Unreviewed Security Hotspots"
    };

    const formatLimit = (c: any): string => {
      if (c.metric === "min_coverage") return `>= ${c.limit}%`;
      if (c.metric === "max_duplication") return `<= ${c.limit}%`;
      if (c.metric && c.metric.endsWith("_blockers")) return `<= ${c.limit}`;
      if (c.metric === "unreviewed_hotspots") return "0";
      return String(c.limit ?? "N/A");
    };

    const formatActual = (c: any): string => {
      if (c.actual === null || c.actual === undefined) return "N/A (Missing)";
      if (c.metric === "min_coverage" || c.metric === "max_duplication") return `${c.actual}%`;
      return String(c.actual);
    };

    const conditionRows = conditions
      .map(
        (c: any) => `
        <tr>
          <td><strong>${metricNameMap[c.metric] || c.metric}</strong></td>
          <td><code>${formatActual(c)}</code></td>
          <td><code>${formatLimit(c)}</code></td>
          <td><span class="badge ${c.status.toLowerCase()}">${c.status}</span></td>
        </tr>`
      )
      .join("");

    const findingsRows = findings
      .map(
        (f: any) => `
        <tr class="finding-row ${f.severity}">
          <td><span class="badge ${f.severity}">${f.severity}</span></td>
          <td><code>${f.rule}</code></td>
          <td><strong>${f.path}</strong>:${f.line}</td>
          <td>${f.message}</td>
          <td><span class="category-tag">${f.engine || "Metadata"}</span></td>
        </tr>`
      )
      .join("");

    const changesRows = changes
      .map(
        (c: any) => `
        <tr>
          <td><span class="status-tag ${c.status}">${c.status.toUpperCase()}</span></td>
          <td><strong>${c.type}</strong></td>
          <td><code>${c.member}</code></td>
        </tr>`
      )
      .join("");

    return `<!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>AppScan Salesforce Analysis</title>
      <style>
        body {
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
          padding: 24px;
          color: var(--vscode-foreground);
          background-color: var(--vscode-editor-background);
          line-height: 1.5;
        }
        h1, h2, h3 { margin-top: 0; font-weight: 600; }
        .header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          border-bottom: 1px solid var(--vscode-widget-border);
          padding-bottom: 16px;
          margin-bottom: 24px;
        }
        .gate-banner {
          padding: 8px 18px;
          border-radius: 6px;
          font-weight: 700;
          font-size: 1.1rem;
          letter-spacing: 0.5px;
        }
        .gate-banner.pass { background-color: rgba(34, 197, 94, 0.2); color: #4ade80; border: 1px solid #22c55e; }
        .gate-banner.fail { background-color: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }
        .gate-banner.incomplete { background-color: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid #eab308; }

        .metrics-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
          gap: 16px;
          margin-bottom: 24px;
        }
        .metric-card {
          background-color: var(--vscode-editorWidget-background);
          border: 1px solid var(--vscode-widget-border);
          border-radius: 8px;
          padding: 16px;
          text-align: center;
        }
        .metric-num { font-size: 2rem; font-weight: 700; margin-top: 4px; }
        .metric-label { font-size: 0.75rem; color: var(--vscode-descriptionForeground); text-transform: uppercase; }

        .alert-box {
          padding: 14px 18px;
          border-radius: 6px;
          margin-bottom: 24px;
          font-size: 0.9rem;
          line-height: 1.5;
        }
        .alert-warning {
          background-color: rgba(234, 179, 8, 0.12);
          border: 1px solid rgba(234, 179, 8, 0.45);
          color: var(--vscode-foreground);
        }
        .alert-error {
          background-color: rgba(239, 68, 68, 0.12);
          border: 1px solid rgba(239, 68, 68, 0.45);
          color: var(--vscode-foreground);
        }
        .alert-box strong {
          display: block;
          margin-bottom: 4px;
        }

        table {
          width: 100%;
          border-collapse: collapse;
          margin-top: 12px;
          margin-bottom: 28px;
          font-size: 0.85rem;
        }
        th, td {
          text-align: left;
          padding: 10px 12px;
          border-bottom: 1px solid var(--vscode-widget-border);
        }
        th {
          background-color: var(--vscode-sideBar-background);
          color: var(--vscode-descriptionForeground);
          font-size: 0.75rem;
          text-transform: uppercase;
        }
        .badge {
          display: inline-block;
          padding: 2px 8px;
          border-radius: 4px;
          font-size: 0.75rem;
          font-weight: 600;
        }
        .badge.Critical, .badge.High, .badge.fail { background: #ef444433; color: #f87171; }
        .badge.Medium, .badge.missing { background: #eab30833; color: #facc15; }
        .badge.Low { background: #3b82f633; color: #60a5fa; }
        .badge.pass { background: #22c55e33; color: #4ade80; }

        .status-tag {
          display: inline-block;
          padding: 2px 6px;
          border-radius: 4px;
          font-size: 0.72rem;
          font-weight: 600;
        }
        .status-tag.added { background: #22c55e26; color: #4ade80; }
        .status-tag.modified { background: #3b82f626; color: #60a5fa; }
        .status-tag.deleted { background: #ef444426; color: #f87171; }

        .category-tag {
          font-size: 0.72rem;
          padding: 2px 6px;
          border-radius: 4px;
          background: var(--vscode-badge-background);
          color: var(--vscode-badge-foreground);
        }
      </style>
    </head>
    <body>
      <div class="header">
        <div>
          <h1>AppScan Salesforce Code Analysis</h1>
          <div style="color: var(--vscode-descriptionForeground);">Project: <strong>${project}</strong> | Engine: PMD 7.17.0 & Metadata Checks</div>
        </div>
        <div class="gate-banner ${gateClass}">Gate: ${gate}</div>
      </div>

      ${
        missingCoverage
          ? `<div class="alert-box alert-warning">
              <strong>⚠️ Quality Gate Incomplete: Missing Code Coverage</strong>
              This project requires code coverage to pass the Quality Gate, but coverage was not provided in this scan.
              <br>
              To run selective Apex test classes for modified code:
              use command <code>AppScan: Run Selective Tests & Scan Workspace</code> or pass <code>--run-tests</code> to the CLI.
            </div>`
          : ""
      }

      ${
        errors.length > 0
          ? `<div class="alert-box alert-error">
              <strong>Errors:</strong>
              <ul style="margin: 4px 0 0 16px; padding: 0;">
                ${errors.map((e: string) => `<li>${e}</li>`).join("")}
              </ul>
            </div>`
          : ""
      }

      ${
        warnings.length > 0
          ? `<div class="alert-box alert-warning">
              <strong>Warnings:</strong>
              <ul style="margin: 4px 0 0 16px; padding: 0;">
                ${warnings.map((w: string) => `<li>${w}</li>`).join("")}
              </ul>
            </div>`
          : ""
      }

      <div class="metrics-grid">
        <div class="metric-card">
          <div class="metric-label">Critical</div>
          <div class="metric-num" style="color: #f87171;">${criticalCount}</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">High</div>
          <div class="metric-num" style="color: #f87171;">${highCount}</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Medium</div>
          <div class="metric-num" style="color: #facc15;">${medCount}</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Low</div>
          <div class="metric-num" style="color: #60a5fa;">${lowCount}</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Coverage</div>
          <div class="metric-num" style="color: ${coveragePercent === null ? '#facc15' : coveragePercent >= 75 ? '#4ade80' : '#f87171'}; ${coveragePercent === null ? 'font-size: 1.15rem; padding-top: 6px;' : ''}">
            ${coveragePercent === null ? 'MISSING' : `${coveragePercent}%`}
          </div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Metadata Changes</div>
          <div class="metric-num" style="color: #a78bfa;">${changes.length}</div>
        </div>
      </div>

      ${
        conditions.length > 0
          ? `<h2>Quality Gate Conditions (${conditions.length})</h2>
             <table>
               <thead>
                 <tr>
                   <th>Policy Condition</th>
                   <th>Actual Value</th>
                   <th>Required Limit</th>
                   <th>Status</th>
                 </tr>
               </thead>
               <tbody>
                 ${conditionRows}
               </tbody>
             </table>`
          : ""
      }

      <h2>Findings (${findings.length})</h2>
      ${
        findings.length === 0
          ? "<p>No security or quality violations detected in current source!</p>"
          : `<table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Rule</th>
                  <th>Location</th>
                  <th>Description</th>
                  <th>Category</th>
                </tr>
              </thead>
              <tbody>
                ${findingsRows}
              </tbody>
            </table>`
      }

      <h2>Metadata Changes vs Baseline (${changes.length})</h2>
      ${
        changes.length === 0
          ? "<p>No metadata additions, modifications, or deletions compared to baseline.</p>"
          : `<table>
              <thead>
                <tr>
                  <th>Action</th>
                  <th>Component Type</th>
                  <th>Member Name</th>
                </tr>
              </thead>
              <tbody>
                ${changesRows}
              </tbody>
            </table>`
      }
    </body>
    </html>`;
  }
}
