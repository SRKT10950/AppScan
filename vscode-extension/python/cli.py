#!/usr/bin/env python3
"""
AppScan CLI - VS Code & Terminal runner for Salesforce Code Analysis.
Compares current workspace code against a baseline git branch/commit.
Outputs in standard compiler/linter format for VS Code Problem Matchers.
"""
import argparse
import base64
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

SALESFORCE_EXTENSIONS = {
    ".cls", ".trigger", ".page", ".component", ".flow",
    ".permissionset", ".profile", ".layout", ".tab", ".app",
    ".md", ".permissionsetgroup", ".flexipage", ".remoteSite",
    ".namedCredential", ".externalCredential", ".globalValueSet",
    ".standardValueSet", ".resource", ".field", ".validationRule",
    ".recordType", ".listView", ".fieldSet", ".compactLayout",
    ".webLink", ".businessProcess", ".sharingReason", ".xml",
    ".js", ".html", ".css", ".object"
}

IGNORE_DIRS = {
    "node_modules", ".git", "dist", "build", "vendor",
    "__pycache__", ".pytest_cache", ".vscode", ".appscan",
    "data", "venv", ".venv", "env", ".env"
}

MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MiB limit per file in AppScan
MAX_TOTAL_SIZE = 80 * 1024 * 1024  # 80 MiB total expanded limit

def load_env_file(env_path: Path):
    if not env_path.is_file():
        return {}
    env = {}
    for line in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    return env

def get_git_root(cwd: Path) -> Path:
    proc = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=cwd, capture_output=True, text=True, check=False)
    if proc.returncode == 0 and proc.stdout.strip():
        return Path(proc.stdout.strip())
    return cwd

def is_ignored(path_str: str) -> bool:
    parts = path_str.replace("\\", "/").split("/")
    return any(p in IGNORE_DIRS or p.startswith(".") for p in parts[:-1])

def filter_zip_entries(zip_bytes: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as src, zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as dst:
        total_size = 0
        for info in src.infolist():
            if info.is_dir() or is_ignored(info.filename):
                continue
            if not any(info.filename.endswith(ext) for ext in SALESFORCE_EXTENSIONS):
                continue
            if info.file_size > MAX_FILE_SIZE:
                raise ValueError("Archive contains a file larger than 2 MiB; refusing a partial scan.")
            if total_size + info.file_size > MAX_TOTAL_SIZE:
                raise ValueError("Archive is too large; refusing a partial scan.")
            total_size += info.file_size
            dst.writestr(info, src.read(info.filename))
    return buf.getvalue()

def create_archive_from_git_ref(ref: str, cwd: Path, subpath: str | None = None) -> bytes:
    resolved = subprocess.run(["git", "rev-parse", "--verify", "--end-of-options", ref + "^{commit}"], cwd=cwd, capture_output=True, text=True, check=False)
    if resolved.returncode:
        raise ValueError("Baseline or HEAD is not a valid commit.")
    cmd = ["git", "archive", "--format=zip", resolved.stdout.strip(), "--"]
    if subpath:
        cmd.append(subpath)
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, check=False)
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace")
        raise RuntimeError(f"Failed to create git archive from ref '{ref}': {err.strip()}")
    return filter_zip_entries(proc.stdout)

def create_archive_from_working_dir(cwd: Path, subpath: str | None = None) -> bytes:
    target_dir = (cwd / subpath).resolve() if subpath else cwd.resolve()
    if not target_dir.is_relative_to(cwd.resolve()):
        raise ValueError("Scan path must remain inside the repository.")
    buf = io.BytesIO()
    total_size = 0
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for p in target_dir.rglob("*"):
            if p.is_file() and not p.is_symlink():
                rel = p.relative_to(cwd).as_posix()
                if is_ignored(rel):
                    continue
                if not any(p.name.endswith(ext) for ext in SALESFORCE_EXTENSIONS):
                    continue
                size = p.stat().st_size
                if size > MAX_FILE_SIZE:
                    raise ValueError("Source file exceeds 2 MiB; refusing a partial scan.")
                if total_size + size > MAX_TOTAL_SIZE:
                    raise ValueError("Source is too large; refusing a partial scan.")
                total_size += size
                z.write(p, rel)
    return buf.getvalue()

def run_scan_via_api(server_url: str, user: str, password: str, project: str, current_zip: bytes, baseline_zip: bytes | None, api_version: str, context=None):
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
    }
    payload = {
        "project": project,
        "current": base64.b64encode(current_zip).decode(),
        "api_version": api_version
    }
    payload.update(context or {})
    if os.environ.get("APPSCAN_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["APPSCAN_TOKEN"]
    if baseline_zip:
        payload["baseline"] = base64.b64encode(baseline_zip).decode()

    req = urllib.request.Request(f"{server_url.rstrip('/')}/api/scans", data=json.dumps(payload).encode(), headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        started = json.loads(resp.read().decode())
    scan_id = started["id"]

    for _ in range(660):
        time.sleep(1)
        req = urllib.request.Request(f"{server_url.rstrip('/')}/api/scans/{scan_id}", headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        status = data.get("status")
        if status in ("complete", "failed"):
            if status == "failed":
                err = data.get("result", {}).get("error", "Scan failed on server.")
                raise RuntimeError(err)
            return data.get("result", {})
    raise TimeoutError("Scan timed out waiting for server completion.")

def run_scan_direct(current_zip: bytes, baseline_zip: bytes | None, api_version: str, coverage=None, context=None):
    from app import scanner
    current = scanner.read_zip(base64.b64encode(current_zip).decode())
    baseline = scanner.read_zip(base64.b64encode(baseline_zip).decode()) if baseline_zip else None
    from app.db import get_pg_config
    if context and (get_pg_config() or os.environ.get("DATA_DIR")):
        from app.persistence import direct_scan
        return direct_scan(current, baseline, api_version, coverage, context)
    return scanner.scan(current, baseline, api_version, coverage=coverage)

def main():
    parser = argparse.ArgumentParser(description="AppScan Salesforce static code analyzer for VS Code")
    parser.add_argument("--baseline", "-b", help="Git branch, tag, or commit hash to use as baseline (e.g. main, uat, HEAD~1)")
    parser.add_argument("--path", help="Relative subpath to scan (e.g. force-app)")
    parser.add_argument("--use-head", action="store_true", help="Use git HEAD instead of uncommitted working tree for current code")
    parser.add_argument("--server", "-s", help="AppScan server URL (e.g. http://localhost:8089)")
    parser.add_argument("--project", "-p", help="Project name (defaults to repository name)")
    parser.add_argument("--api-version", default="64.0", help="Salesforce Metadata API version (default: 64.0)")
    parser.add_argument("--output-dir", "-o", default=".appscan", help="Directory to save scan report and manifests")
    parser.add_argument("--offline", action="store_true", help="Run scan directly without connecting to server")
    parser.add_argument("--branch", default="main", help="Branch namespace for server history")
    parser.add_argument("--pull-request", default="", help="Numeric PR identifier; isolated issue namespace")
    parser.add_argument("--revision", default="", help="Commit SHA for traceability")
    parser.add_argument("--coverage", help="LCOV or Salesforce/normalized JSON coverage report")
    args = parser.parse_args()
    from app.coverage import parse_coverage
    coverage = parse_coverage(Path(args.coverage).read_text()) if args.coverage else None

    git_root = get_git_root(Path.cwd())
    appscan_dir = Path(__file__).resolve().parent
    env_vars = load_env_file(appscan_dir / ".env")
    if not env_vars:
        env_vars = load_env_file(git_root / ".env")

    # Operator-supplied DB settings also apply to explicit offline/direct persistence.
    for key in ("DATABASE_URL", "POSTGRES_URL", "CENTRAL_PG_HOST", "CENTRAL_PG_PORT", "CENTRAL_PG_USER", "CENTRAL_PG_PASSWORD", "CENTRAL_PG_DATABASE", "DATA_DIR"):
        if key in env_vars and key not in os.environ:
            os.environ[key] = env_vars[key]

    server_url = args.server or os.environ.get("APPSCAN_URL") or env_vars.get("APPSCAN_URL") or "http://192.168.50.109:8089"
    user = os.environ.get("APPSCAN_USER") or env_vars.get("APPSCAN_USER", "admin")
    password = os.environ.get("APPSCAN_PASSWORD") or env_vars.get("APPSCAN_PASSWORD", "")
    project = args.project or git_root.name

    print(f"[*] AppScan Salesforce Code Analysis")
    print(f"[*] Project: {project} | API Version: {args.api_version}")

    # Build current archive
    if args.use_head:
        print("[*] Packaging current code from git HEAD...")
        current_zip = create_archive_from_git_ref("HEAD", git_root, args.path)
    else:
        print("[*] Packaging current working workspace files...")
        current_zip = create_archive_from_working_dir(git_root, args.path)

    # Build baseline archive if requested
    baseline_zip = None
    if args.baseline:
        print(f"[*] Packaging baseline code from '{args.baseline}'...")
        try:
            baseline_zip = create_archive_from_git_ref(args.baseline, git_root, args.path)
        except Exception as e:
            raise RuntimeError(f"Requested baseline could not be read: {e}") from e

    # Execute scan
    scan_result = None
    if not args.offline:
        try:
            print(f"[*] Connecting to AppScan server at {server_url}...")
            scan_result = run_scan_via_api(server_url, user, password, project, current_zip, baseline_zip, args.api_version, {"branch":args.branch, "pull_request":args.pull_request, "revision":args.revision, "coverage":coverage})
        except Exception as exc:
            raise RuntimeError("Server scan failed. No local fallback was performed; use --offline explicitly for a local scan.") from exc

    if scan_result is None:
        sys.path.insert(0, str(appscan_dir.parent))
        sys.path.insert(0, str(appscan_dir))
        print("[*] Running scan via in-process engine...")
        scan_result = run_scan_direct(current_zip, baseline_zip, args.api_version, coverage,
                                      {'project': project, 'branch': args.branch, 'pull_request': args.pull_request, 'revision': args.revision})

    # Save output artifacts
    out_dir = git_root / args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "report.json").write_text(json.dumps(scan_result, indent=2), encoding="utf-8")
    if "package_xml" in scan_result:
        (out_dir / "package.xml").write_text(scan_result["package_xml"], encoding="utf-8")
    if "destructive_xml" in scan_result:
        (out_dir / "destructiveChanges.xml").write_text(scan_result["destructive_xml"], encoding="utf-8")

    from app.quality import sarif
    (out_dir / "report.sarif").write_text(json.dumps(sarif(scan_result), indent=2), encoding="utf-8")

    # Display findings in standard VS Code Problem Matcher format
    # Format: {path}:{line}:{col}: {severity}: [{rule}] {message}
    findings = scan_result.get("findings", [])
    changes = scan_result.get("changes", [])
    gate = scan_result.get("gate", "PASS")

    print("\n" + "="*70)
    print(" SCAN FINDINGS (VS CODE COMPATIBLE)")
    print("="*70)

    severity_map = {
        "Critical": "error",
        "High": "error",
        "Medium": "warning",
        "Low": "info"
    }

    if not findings:
        print("No violations or security findings detected.")
    else:
        for f in findings:
            sev_label = severity_map.get(f.get("severity"), "warning")
            path = f.get("path", "unknown")
            line = f.get("line", 1)
            rule = f.get("rule", "CodeFinding")
            msg = f.get("message", "").replace("\n", " ")
            category = f.get("category", "General")
            print(f"{path}:{line}:1: {sev_label}: [{rule}] {msg} ({category})")

    if changes:
        print("\n" + "="*70)
        print(f" METADATA CHANGES COMPARED TO BASELINE ({len(changes)} items)")
        print("="*70)
        for c in changes:
            print(f"  [{c['status'].upper():8}] {c['type']} -> {c['member']}")

    print("\n" + "="*70)
    print(f" QUALITY GATE: {gate.upper()} (PMD: {scan_result.get('pmd', 'ok')})")
    print(f" Reports saved to: {out_dir.relative_to(git_root)}")
    print("="*70 + "\n")

    if gate.upper() in ("FAIL", "INCOMPLETE"):
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
