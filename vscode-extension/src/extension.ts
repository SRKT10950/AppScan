import * as vscode from "vscode";
import * as path from "path";
import * as fs from "fs";
import { spawn, execFileSync } from "child_process";
import { ReportPanel } from "./reportPanel";

let diagnosticCollection: vscode.DiagnosticCollection;
let statusBarItem: vscode.StatusBarItem;
let latestScanResult: any = null;
let latestProjectName: string = "Salesforce App";

export function activate(context: vscode.ExtensionContext) {
  context.subscriptions.push(vscode.commands.registerCommand("appscan.setToken", async () => {
    const serverUrl = vscode.workspace.getConfiguration("appscan").get<string>("serverUrl", "http://localhost:8089");
    const token = await vscode.window.showInputBox({prompt: "AppScan project API token (blank clears it)", password: true, ignoreFocusOut: true});
    if (token !== undefined) {
      if (token) await context.secrets.store("appscan.token:" + serverUrl, token);
      else await context.secrets.delete("appscan.token:" + serverUrl);
    }
  }));
  diagnosticCollection = vscode.languages.createDiagnosticCollection("appscan");
  context.subscriptions.push(diagnosticCollection);

  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 90);
  statusBarItem.command = "appscan.showReport";
  statusBarItem.text = "$(shield) AppScan";
  statusBarItem.tooltip = "Click to open latest AppScan report";
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  context.subscriptions.push(
    vscode.commands.registerCommand("appscan.scanWorkspace", async () => {
      const config = vscode.workspace.getConfiguration("appscan");
      const defaultBaseline = config.get<string>("defaultBaseline", "main");
      await runScan(context, defaultBaseline);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("appscan.scanWithCustomBaseline", async () => {
      const config = vscode.workspace.getConfiguration("appscan");
      const defaultBaseline = config.get<string>("defaultBaseline", "main");

      const baseline = await vscode.window.showInputBox({
        prompt: "Enter Git baseline branch, tag, or commit hash",
        value: defaultBaseline,
        placeHolder: "e.g. main, uat, origin/main, HEAD~1"
      });

      if (baseline !== undefined) {
        await runScan(context, baseline.trim() || undefined);
      }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("appscan.scanFolder", async (uri?: vscode.Uri) => {
      const config = vscode.workspace.getConfiguration("appscan");
      const defaultBaseline = config.get<string>("defaultBaseline", "main");

      let folderPath = "";
      if (uri && uri.fsPath) {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (workspaceFolders && workspaceFolders.length > 0) {
          folderPath = path.relative(workspaceFolders[0].uri.fsPath, uri.fsPath);
        }
      }

      if (!folderPath) {
        folderPath = (await vscode.window.showInputBox({
          prompt: "Enter relative folder path to scan (e.g. force-app)",
          value: "force-app"
        })) || "";
      }

      await runScan(context, defaultBaseline, folderPath);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("appscan.showReport", () => {
      if (!latestScanResult) {
        vscode.window.showInformationMessage("No AppScan report available yet. Run a scan first.");
        return;
      }
      ReportPanel.createOrShow(context.extensionUri, latestScanResult, latestProjectName);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("appscan.clearFindings", () => {
      diagnosticCollection.clear();
      statusBarItem.text = "$(shield) AppScan";
      vscode.window.showInformationMessage("AppScan findings cleared.");
    })
  );
}

async function runScan(context: vscode.ExtensionContext, baseline?: string, subpath?: string) {
  if (!vscode.workspace.isTrusted) {
    vscode.window.showErrorMessage("Trust this workspace before running AppScan.");
    return;
  }
  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders || workspaceFolders.length === 0) {
    vscode.window.showErrorMessage("AppScan requires an open workspace folder.");
    return;
  }

  const workspaceRoot = workspaceFolders[0].uri.fsPath;
  const config = vscode.workspace.getConfiguration("appscan");
  const serverUrl = config.get<string>("serverUrl", "http://localhost:8089");
  const apiVersion = config.get<string>("apiVersion", "64.0");

  let cliPath = path.join(context.extensionPath, "python", "cli.py");
  if (!fs.existsSync(cliPath)) {
    cliPath = path.join(workspaceRoot, "AppScan", "cli.py");
  }
  if (!fs.existsSync(cliPath)) {
    cliPath = path.join(workspaceRoot, "cli.py");
  }
  if (!fs.existsSync(cliPath)) {
    statusBarItem.text = "$(error) AppScan: Error";
    vscode.window.showErrorMessage(`AppScan CLI runner not found. Checked: ${cliPath}`);
    return;
  }

  statusBarItem.text = "$(sync~spin) AppScan: Scanning...";

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "Running AppScan Salesforce Analysis...",
      cancellable: false
    },
    async (progress) => {
      progress.report({ message: `Comparing against baseline '${baseline || "none"}'...` });

      const outputDir = path.join(".appscan", "run-" + Date.now() + "-" + Math.random().toString(16).slice(2));
      const args: string[] = [cliPath, "--api-version", apiVersion, "--server", serverUrl, "--output-dir", outputDir];
      try {
        const branch = execFileSync("git", ["branch", "--show-current"], {cwd: workspaceRoot, encoding: "utf8"}).trim();
        const revision = execFileSync("git", ["rev-parse", "HEAD"], {cwd: workspaceRoot, encoding: "utf8"}).trim();
        args.push("--branch", branch || "detached", "--revision", revision);
      } catch { /* Non-git workspaces still receive server analysis. */ }
      if (baseline) {
        args.push("--baseline", baseline);
      }
      if (subpath) {
        args.push("--path", subpath);
      }

      try {
        const credentials: NodeJS.ProcessEnv = {};
        const token = await context.secrets.get("appscan.token:" + serverUrl);
        if (token) credentials.APPSCAN_TOKEN = token;
        else {
          credentials.APPSCAN_USER = config.get<string>("username", "admin");
          const password = config.get<string>("password", "");
          if (password) credentials.APPSCAN_PASSWORD = password;
        }
        await executePythonCli(args, workspaceRoot, credentials);
        const reportFile = path.join(workspaceRoot, outputDir, "report.json");

        if (fs.existsSync(reportFile)) {
          const raw = fs.readFileSync(reportFile, "utf-8");
          latestScanResult = JSON.parse(raw);
        } else {
          throw new Error("The scanner did not produce a report. No quality gate can be inferred.");
        }

        latestProjectName = path.basename(workspaceRoot);
        updateDiagnostics(workspaceRoot, latestScanResult.findings || []);

        const gate = (latestScanResult.gate || "INCOMPLETE").toUpperCase();
        const findingsCount = (latestScanResult.findings || []).length;

        if (gate === "PASS") {
          statusBarItem.text = `$(pass) AppScan: PASSED (${findingsCount})`;
          vscode.window
            .showInformationMessage(`AppScan Passed! Quality gate is clean. (${findingsCount} findings)`, "View Report")
            .then((selection) => {
              if (selection === "View Report") {
                ReportPanel.createOrShow(context.extensionUri, latestScanResult, latestProjectName);
              }
            });
        } else {
          statusBarItem.text = `$(error) AppScan: ${gate} (${findingsCount})`;
          vscode.window
            .showWarningMessage(
              `AppScan Quality Gate: ${gate}. Detected ${findingsCount} finding(s).`,
              "View Report"
            )
            .then((selection) => {
              if (selection === "View Report") {
                ReportPanel.createOrShow(context.extensionUri, latestScanResult, latestProjectName);
              }
            });
        }
      } catch (err: any) {
        statusBarItem.text = "$(error) AppScan: Error";
        vscode.window.showErrorMessage(`AppScan failed: ${err.message || err}`);
      }
    }
  );
}

function executePythonCli(args: string[], cwd: string, credentials: NodeJS.ProcessEnv): Promise<string> {
  return new Promise((resolve, reject) => {
    const pythonCmd = process.platform === "win32" ? "python" : "python3";
    const env = { ...process.env, ...credentials };
    if (!env.PMD_BIN && process.platform === "win32") {
      env.PMD_BIN = "D:\\Linux Server\\AppScan\\pmd\\bin\\pmd.bat";
    }
    const proc = spawn(pythonCmd, args, { cwd, shell: false, env });
    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (data) => {
      stdout += data.toString();
    });

    proc.stderr.on("data", (data) => {
      stderr += data.toString();
    });

    proc.on("close", (code) => {
      // Exit code 0 is PASS, code 1 is FAIL/violations detected
      if (code === 0 || code === 1) {
        resolve(stdout);
      } else {
        reject(new Error(stderr || stdout || `Process exited with code ${code}`));
      }
    });

    proc.on("error", (err) => {
      reject(err);
    });
  });
}

function updateDiagnostics(workspaceRoot: string, findings: any[]) {
  diagnosticCollection.clear();
  const fileMap = new Map<string, vscode.Diagnostic[]>();

  for (const f of findings) {
    const filePath = path.isAbsolute(f.path) ? f.path : path.join(workspaceRoot, f.path);
    const line = Math.max(0, (parseInt(f.line, 10) || 1) - 1);
    const range = new vscode.Range(line, 0, line, 200);

    let severity = vscode.DiagnosticSeverity.Warning;
    if (f.severity === "Critical" || f.severity === "High") {
      severity = vscode.DiagnosticSeverity.Error;
    } else if (f.severity === "Low") {
      severity = vscode.DiagnosticSeverity.Information;
    }

    const diagnostic = new vscode.Diagnostic(
      range,
      `[${f.rule}] ${f.message} (${f.category || "Security"})`,
      severity
    );
    diagnostic.source = "AppScan";
    diagnostic.code = f.rule;

    const uriString = vscode.Uri.file(filePath).toString();
    const existing = fileMap.get(uriString) || [];
    existing.push(diagnostic);
    fileMap.set(uriString, existing);
  }

  for (const [uriString, diags] of fileMap.entries()) {
    diagnosticCollection.set(vscode.Uri.parse(uriString), diags);
  }
}

export function deactivate() {
  if (diagnosticCollection) {
    diagnosticCollection.clear();
    diagnosticCollection.dispose();
  }
}
