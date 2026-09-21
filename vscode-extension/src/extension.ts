import * as vscode from "vscode";
import * as path from "path";
import * as fs from "fs";
import { spawn, execFileSync } from "child_process";
import { ReportPanel } from "./reportPanel";

let diagnosticCollection: vscode.DiagnosticCollection;
let statusBarItem: vscode.StatusBarItem;
let outputChannel: vscode.OutputChannel;
let latestScanResult: any = null;
let latestProjectName: string = "Salesforce App";

export function activate(context: vscode.ExtensionContext) {
  outputChannel = vscode.window.createOutputChannel("AppScan");
  context.subscriptions.push(outputChannel);

  context.subscriptions.push(vscode.commands.registerCommand("appscan.setToken", async () => {
    const serverUrl = vscode.workspace.getConfiguration("appscan").get<string>("serverUrl", "https://mhservice.co.in/appscan");
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
    vscode.commands.registerCommand("appscan.scanWithTests", async () => {
      const config = vscode.workspace.getConfiguration("appscan");
      const defaultBaseline = config.get<string>("defaultBaseline", "main");
      await runScan(context, defaultBaseline, undefined, true);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("appscan.mapTestClasses", async () => {
      await mapTestClasses(context);
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

async function runScan(
  context: vscode.ExtensionContext,
  baseline?: string,
  subpath?: string,
  forceRunTests: boolean = false
) {
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
  const serverUrl = config.get<string>("serverUrl", "https://mhservice.co.in/appscan");
  const isOffline = config.get<boolean>("offline", false);
  const fallbackToOffline = config.get<boolean>("fallbackToOffline", true);
  const apiVersion = config.get<string>("apiVersion", "64.0");
  const pmdBinPath = config.get<string>("pmdBinPath", "");

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
      progress.report({ message: `Preparing analysis...` });

      const outputDir = path.join(workspaceRoot, ".appscan", "run-" + Date.now() + "-" + Math.random().toString(16).slice(2));
      const args: string[] = [cliPath, "--api-version", apiVersion, "--output-dir", outputDir];

      if (isOffline) {
        args.push("--offline");
      } else {
        args.push("--server", serverUrl);
        if (fallbackToOffline) {
          args.push("--fallback-offline");
        }
      }

      try {
        const branch = execFileSync("git", ["branch", "--show-current"], {cwd: workspaceRoot, encoding: "utf8"}).trim();
        const revision = execFileSync("git", ["rev-parse", "HEAD"], {cwd: workspaceRoot, encoding: "utf8"}).trim();
        args.push("--branch", branch || "detached", "--revision", revision);
      } catch { /* Non-git workspaces still receive scan analysis. */ }

      let effectiveBaseline = baseline;
      if (effectiveBaseline) {
        try {
          execFileSync("git", ["rev-parse", "--verify", effectiveBaseline + "^{commit}"], { cwd: workspaceRoot, stdio: "ignore" });
        } catch {
          try {
            execFileSync("git", ["rev-parse", "--verify", `origin/${effectiveBaseline}^{commit}`], { cwd: workspaceRoot, stdio: "ignore" });
            effectiveBaseline = `origin/${effectiveBaseline}`;
          } catch {
            effectiveBaseline = undefined;
          }
        }
      }
      if (effectiveBaseline) {
        args.push("--baseline", effectiveBaseline);
      }

      if (subpath) {
        args.push("--path", subpath);
      }

      const shouldRunTests = forceRunTests || config.get<boolean>("runSelectiveTests", false);
      if (shouldRunTests) {
        args.push("--run-tests");
      }
      const testMapping = config.get<string>("testMappingPath", "");
      if (testMapping) {
        args.push("--test-mapping", testMapping);
      }
      const targetOrg = config.get<string>("targetOrg", "");
      if (targetOrg) {
        args.push("--target-org", targetOrg);
      }

      try {
        const credentials: NodeJS.ProcessEnv = {};
        const token = await context.secrets.get("appscan.token:" + serverUrl);
        if (token) credentials.APPSCAN_TOKEN = token;
        else {
          credentials.APPSCAN_USER = config.get<string>("username", "admin");
          const password = config.get<string>("password", "AppScanSecretPass2026!");
          if (password) credentials.APPSCAN_PASSWORD = password;
        }

        outputChannel.appendLine(`\n=== AppScan Execution: ${new Date().toISOString()} ===`);
        const cliResult = await executePythonCli(args, workspaceRoot, credentials, pmdBinPath);
        const reportFile = path.join(outputDir, "report.json");

        if (fs.existsSync(reportFile)) {
          const raw = fs.readFileSync(reportFile, "utf-8");
          latestScanResult = JSON.parse(raw);
        } else {
          outputChannel.show(true);
          const errDetail = cliResult.stderr.trim() || cliResult.stdout.trim() || `Process exited with code ${cliResult.code}`;
          throw new Error(`The scanner did not produce a report.\n\nError details:\n${errDetail}`);
        }

        latestProjectName = path.basename(workspaceRoot);
        updateDiagnostics(workspaceRoot, latestScanResult.findings || []);

        const gate = (latestScanResult.gate || "INCOMPLETE").toUpperCase();
        const findingsCount = (latestScanResult.findings || []).length;
        const conditions = latestScanResult.quality_gate?.conditions || [];
        const missingCoverage = conditions.some((c: any) => c.metric === "min_coverage" && c.status === "MISSING");
        const serverUploaded = latestScanResult.server_uploaded !== false && !!latestScanResult.server_scan_id;

        if (!isOffline && latestScanResult.server_uploaded === false) {
          const errMsg = latestScanResult.server_error ? `: ${latestScanResult.server_error}` : "";
          vscode.window
            .showWarningMessage(
              `AppScan: Analysis ran locally, but failed to update report to server (${serverUrl})${errMsg}`,
              "Set API Token",
              "Show Output"
            )
            .then((sel) => {
              if (sel === "Set API Token") {
                vscode.commands.executeCommand("appscan.setToken");
              } else if (sel === "Show Output") {
                outputChannel.show(true);
              }
            });
        }

        const reportActions: string[] = ["View Report"];
        if (serverUploaded) {
          reportActions.push("Open Web App");
        }

        const handleActions = (selection?: string) => {
          if (selection === "View Report") {
            ReportPanel.createOrShow(context.extensionUri, latestScanResult, latestProjectName);
          } else if (selection === "Open Web App") {
            vscode.env.openExternal(vscode.Uri.parse(serverUrl));
          }
        };

        const serverTag = serverUploaded ? " (Updated to App)" : " (Local)";

        if (gate === "PASS") {
          statusBarItem.text = `$(pass) AppScan: PASSED (${findingsCount})${serverUploaded ? " $(cloud-upload)" : ""}`;
          vscode.window
            .showInformationMessage(`AppScan Passed! Quality gate is clean. (${findingsCount} findings)${serverTag}`, ...reportActions)
            .then(handleActions);
        } else if (gate === "INCOMPLETE" && missingCoverage) {
          statusBarItem.text = `$(warning) AppScan: INCOMPLETE (Missing Coverage)`;
          vscode.window
            .showWarningMessage(
              `AppScan Quality Gate: INCOMPLETE due to missing Code Coverage. Run selective Apex tests to satisfy quality gate.${serverTag}`,
              "Run Selective Tests & Scan",
              ...reportActions
            )
            .then(async (selection) => {
              if (selection === "Run Selective Tests & Scan") {
                await runScan(context, baseline, subpath, true);
              } else {
                handleActions(selection);
              }
            });
        } else {
          statusBarItem.text = `$(error) AppScan: ${gate} (${findingsCount})${serverUploaded ? " $(cloud-upload)" : ""}`;
          vscode.window
            .showWarningMessage(
              `AppScan Quality Gate: ${gate}. Detected ${findingsCount} finding(s).${serverTag}`,
              ...reportActions
            )
            .then(handleActions);
        }
      } catch (err: any) {
        statusBarItem.text = "$(error) AppScan: Error";
        vscode.window.showErrorMessage(`AppScan failed: ${err.message || err}`, "Show Output").then((sel) => {
          if (sel === "Show Output") {
            outputChannel.show(true);
          }
        });
      }
    }
  );
}

async function mapTestClasses(context: vscode.ExtensionContext) {
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
  const pmdBinPath = config.get<string>("pmdBinPath", "");

  let cliPath = path.join(context.extensionPath, "python", "cli.py");
  if (!fs.existsSync(cliPath)) {
    cliPath = path.join(workspaceRoot, "AppScan", "cli.py");
  }
  if (!fs.existsSync(cliPath)) {
    cliPath = path.join(workspaceRoot, "cli.py");
  }
  if (!fs.existsSync(cliPath)) {
    vscode.window.showErrorMessage(`AppScan CLI runner not found. Checked: ${cliPath}`);
    return;
  }

  const args: string[] = [cliPath, "--map-tests"];
  const testMapping = config.get<string>("testMappingPath", "");
  if (testMapping) {
    args.push("--test-mapping", testMapping);
  }

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "AppScan: Detecting and mapping Apex test classes...",
      cancellable: false
    },
    async () => {
      try {
        await executePythonCli(args, workspaceRoot, {}, pmdBinPath);
        const mapFile = path.join(workspaceRoot, testMapping || ".appscan/test-mapping.json");
        vscode.window
          .showInformationMessage(
            "AppScan: Apex test class mappings successfully updated.",
            "Open Mapping File"
          )
          .then(async (selection) => {
            if (selection === "Open Mapping File" && fs.existsSync(mapFile)) {
              const doc = await vscode.workspace.openTextDocument(mapFile);
              await vscode.window.showTextDocument(doc);
            }
          });
      } catch (err: any) {
        vscode.window.showErrorMessage(`Failed to map test classes: ${err.message || err}`, "Show Output").then((sel) => {
          if (sel === "Show Output") {
            outputChannel.show(true);
          }
        });
      }
    }
  );
}

function executePythonCli(
  args: string[],
  cwd: string,
  credentials: NodeJS.ProcessEnv,
  pmdBinPath?: string
): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve, reject) => {
    const pythonCmd = process.platform === "win32" ? "python" : "python3";
    const env = { ...process.env, ...credentials };

    if (pmdBinPath && fs.existsSync(pmdBinPath)) {
      env.PMD_BIN = pmdBinPath;
    } else if (!env.PMD_BIN && process.platform === "win32") {
      const candidates = [
        path.join(cwd, "pmd", "bin", "pmd.bat"),
        "C:\\pmd\\bin\\pmd.bat",
        "D:\\Linux Server\\AppScan\\pmd\\bin\\pmd.bat"
      ];
      for (const c of candidates) {
        if (fs.existsSync(c)) {
          env.PMD_BIN = c;
          break;
        }
      }
    }

    outputChannel.appendLine(`[SPAWN] ${pythonCmd} ${args.join(" ")}`);
    const proc = spawn(pythonCmd, args, { cwd, shell: false, env });
    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (data) => {
      const str = data.toString();
      stdout += str;
      outputChannel.append(str);
    });

    proc.stderr.on("data", (data) => {
      const str = data.toString();
      stderr += str;
      outputChannel.append(str);
    });

    proc.on("close", (code) => {
      resolve({ stdout, stderr, code: code ?? 0 });
    });

    proc.on("error", (err) => {
      outputChannel.appendLine(`[ERROR] ${err.message || err}`);
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
