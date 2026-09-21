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
from pathlib import Path, PurePosixPath
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
    "data", "venv", ".venv", "env", ".env", ".sf", ".sfdx",
    "coverage", "target", "bin", "out", "tmp", "temp", "test-results"
}

MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MiB limit per file in AppScan
MAX_TOTAL_SIZE = 80 * 1024 * 1024  # 80 MiB total expanded limit
MAX_ENTRIES = 100000

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
    try:
        proc = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=cwd, capture_output=True, text=True, check=False)
        if proc.returncode == 0 and proc.stdout.strip():
            return Path(proc.stdout.strip())
    except Exception:
        pass
    return cwd

def is_ignored(path_str: str) -> bool:
    parts = path_str.replace("\\", "/").split("/")
    return any(p in IGNORE_DIRS or p.startswith(".") for p in parts[:-1])

def is_salesforce_file(rel: str) -> bool:
    parts = PurePosixPath(rel).parts
    if any(p in IGNORE_DIRS or p.startswith(".") for p in parts[:-1]):
        return False
    ext = Path(rel).suffix
    if ext not in SALESFORCE_EXTENSIONS:
        return False
    # If the file is generic web code (.js, .html, .css), only include if inside recognized Salesforce metadata/components
    if ext in {".js", ".html", ".css"}:
        return any(f in parts for f in {"lwc", "aura", "staticresources", "pages", "components"})
    # If .xml, only include if standard Salesforce manifest or -meta.xml or inside recognized metadata folders
    if ext == ".xml":
        name = Path(rel).name
        if name in {"package.xml", "destructiveChanges.xml", "destructiveChangesPre.xml", "destructiveChangesPost.xml"}:
            return True
        if name.endswith("-meta.xml"):
            return True
        return any(f in parts for f in {
            'classes', 'triggers', 'pages', 'components', 'flows',
            'permissionsets', 'profiles', 'layouts', 'tabs', 'applications',
            'customMetadata', 'permissionsetgroups', 'flexipages', 'remoteSiteSettings',
            'namedCredentials', 'externalCredentials', 'globalValueSets', 'standardValueSets',
            'objects', 'labels', 'customPermissions', 'sharingRules'
        })
    return True

def filter_zip_entries(zip_bytes: bytes) -> tuple[bytes, list[tuple[str, int]]]:
    buf = io.BytesIO()
    skipped: list[tuple[str, int]] = []
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as src, zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as dst:
        total_size = 0
        entry_count = 0
        for info in src.infolist():
            if info.is_dir() or not is_salesforce_file(info.filename):
                continue
            if info.file_size > MAX_FILE_SIZE:
                print(f"[!] Warning: Skipping '{info.filename}' ({info.file_size / (1024 * 1024):.1f} MiB): exceeds 2 MiB per-file limit.")
                skipped.append((info.filename, info.file_size))
                continue
            if total_size + info.file_size > MAX_TOTAL_SIZE or entry_count >= MAX_ENTRIES:
                print(f"[!] Warning: Total archive limit reached ({MAX_ENTRIES} entries / {MAX_TOTAL_SIZE // (1024 * 1024)} MiB). Skipping remaining files.")
                break
            total_size += info.file_size
            entry_count += 1
            dst.writestr(info, src.read(info.filename))
    return buf.getvalue(), skipped

def create_archive_from_git_ref(ref: str, cwd: Path, subpath: str | None = None) -> tuple[bytes, list[tuple[str, int]]]:
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

def create_archive_from_working_dir(cwd: Path, subpath: str | None = None) -> tuple[bytes, list[tuple[str, int]]]:
    target_dir = (cwd / subpath).resolve() if subpath else cwd.resolve()
    if not target_dir.is_relative_to(cwd.resolve()):
        raise ValueError("Scan path must remain inside the repository.")
    buf = io.BytesIO()
    total_size = 0
    entry_count = 0
    skipped: list[tuple[str, int]] = []

    candidate_files: list[Path] = []
    try:
        cmd = ["git", "ls-files", "-c", "-o", "--exclude-standard"]
        if subpath:
            cmd.extend(["--", subpath])
        proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
        if proc.returncode == 0 and proc.stdout.strip():
            for line in proc.stdout.splitlines():
                line = line.strip()
                if line:
                    p = cwd / line
                    if p.is_file() and not p.is_symlink():
                        candidate_files.append(p)
    except Exception:
        pass

    if not candidate_files:
        candidate_files = [p for p in target_dir.rglob("*") if p.is_file() and not p.is_symlink()]

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for p in candidate_files:
            try:
                rel = p.relative_to(cwd).as_posix()
            except ValueError:
                continue
            if not is_salesforce_file(rel):
                continue
            try:
                size = p.stat().st_size
            except OSError:
                continue
            if size > MAX_FILE_SIZE:
                print(f"[!] Warning: Skipping '{rel}' ({size / (1024 * 1024):.1f} MiB): exceeds 2 MiB per-file limit.")
                skipped.append((rel, size))
                continue
            if total_size + size > MAX_TOTAL_SIZE or entry_count >= MAX_ENTRIES:
                print(f"[!] Warning: Total archive limit reached ({MAX_ENTRIES} entries / {MAX_TOTAL_SIZE // (1024 * 1024)} MiB). Skipping remaining files.")
                break
            total_size += size
            entry_count += 1
            z.write(p, rel)
    return buf.getvalue(), skipped

def run_scan_via_api(server_url: str, user: str, password: str, project: str, current_zip: bytes, baseline_zip: bytes | None, api_version: str, context=None):
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode(),
        "User-Agent": "AppScan/0.4 (Salesforce VSCode)"
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
            res = data.get("result", {})
            res["server_scan_id"] = scan_id
            res["server_uploaded"] = True
            res["server_url"] = server_url
            return res
    raise TimeoutError("Scan timed out waiting for server completion.")

def run_scan_direct(current_zip: bytes, baseline_zip: bytes | None, api_version: str, coverage=None, context=None, external=None, baseline_external=None):
    from app import scanner
    current = scanner.read_zip(base64.b64encode(current_zip).decode())
    baseline = scanner.read_zip(base64.b64encode(baseline_zip).decode()) if baseline_zip else None
    from app.db import get_pg_config
    if context and (get_pg_config() or os.environ.get("DATA_DIR")):
        from app.persistence import direct_scan
        return direct_scan(current, baseline, api_version, coverage, context, external, baseline_external)
    return scanner.scan(current, baseline, api_version, coverage=coverage, external=external, baseline_external=baseline_external)

def get_modified_classes(git_root: Path, baseline: str | None, subpath: str | None = None) -> list[str]:
    """Find Apex classes modified or added relative to baseline or uncommitted changes."""
    modified = set()
    try:
        if baseline:
            cmd = ["git", "diff", "--name-only", baseline]
            if subpath:
                cmd.extend(["--", subpath])
            proc = subprocess.run(cmd, cwd=git_root, capture_output=True, text=True, check=False)
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    if line.endswith(".cls"):
                        modified.add(Path(line).stem)
        # Also check uncommitted working directory changes
        proc = subprocess.run(["git", "status", "--porcelain"], cwd=git_root, capture_output=True, text=True, check=False)
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                filepath = line[3:].strip()
                if filepath.endswith(".cls"):
                    modified.add(Path(filepath).stem)
    except Exception:
        pass
    return sorted(list(modified))

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
    parser.add_argument("--fallback-offline", action="store_true", help="Automatically fall back to local direct scan if server is unreachable")
    parser.add_argument("--branch", default="main", help="Branch namespace for server history")
    parser.add_argument("--pull-request", default="", help="Numeric PR identifier; isolated issue namespace")
    parser.add_argument("--revision", default="", help="Commit SHA for traceability")
    parser.add_argument("--baseline-sarif", help="SARIF for baseline source; requires --sarif and a source baseline")
    parser.add_argument("--sarif", help="External SARIF 2.1.0 report to import")
    parser.add_argument("--coverage", help="LCOV or Salesforce/normalized JSON coverage report")
    parser.add_argument("--run-tests", "-t", action="store_true", help="Run selective test classes for modified Apex classes via Salesforce CLI")
    parser.add_argument("--test-mapping", help="Path to class-to-test mapping JSON file (default: .appscan/test-mapping.json)")
    parser.add_argument("--map-tests", action="store_true", help="Discover and map test classes across workspace into test-mapping.json without scanning")
    parser.add_argument("--target-org", help="Target Salesforce org username/alias for test execution")
    args = parser.parse_args()

    git_root = get_git_root(Path.cwd())
    appscan_dir = Path(__file__).resolve().parent

    if args.map_tests:
        from app.test_runner import scan_workspace_classes, detect_test_classes_for, load_mapping, save_mapping
        mapping_file = Path(args.test_mapping) if args.test_mapping else (git_root / ".appscan" / "test-mapping.json")
        mapping = load_mapping(mapping_file)
        source_cls, test_cls = scan_workspace_classes(git_root)
        print(f"[*] Found {len(source_cls)} source classes and {len(test_cls)} test classes in workspace.")
        for name, p in source_cls.items():
            if name not in mapping:
                detected = detect_test_classes_for(name, p, test_cls)
                if detected:
                    mapping[name] = detected
                    print(f"  Mapped {name} -> {', '.join(detected)}")
        save_mapping(mapping_file, mapping)
        print(f"[*] Test mappings saved to {mapping_file}")
        sys.exit(0)

    from app.coverage import parse_coverage
    baseline_external = json.loads(Path(args.baseline_sarif).read_text()) if args.baseline_sarif else None
    external = json.loads(Path(args.sarif).read_text()) if args.sarif else None
    coverage = parse_coverage(Path(args.coverage).read_text()) if args.coverage else None

    if args.run_tests and not coverage:
        from app.test_runner import resolve_tests_for_classes, run_selective_tests
        modified_classes = get_modified_classes(git_root, args.baseline, args.path)
        if not modified_classes:
            target_dir = (git_root / args.path).resolve() if args.path else git_root
            modified_classes = [p.stem for p in target_dir.rglob("*.cls") if not p.stem.endswith("Test") and not p.stem.endswith("Tests")]
        print(f"[*] Target modified Apex classes for selective testing: {', '.join(modified_classes) if modified_classes else 'None detected'}")
        mapping_file = Path(args.test_mapping) if args.test_mapping else (git_root / ".appscan" / "test-mapping.json")
        test_classes, _ = resolve_tests_for_classes(modified_classes, git_root, mapping_file)
        if test_classes:
            out_target = Path(args.output_dir) if Path(args.output_dir).is_absolute() else (git_root / args.output_dir)
            coverage = run_selective_tests(test_classes, git_root, args.target_org, out_target)
        else:
            print("[!] No matching test classes found to run.")
    env_vars = load_env_file(appscan_dir / ".env")
    if not env_vars:
        env_vars = load_env_file(git_root / ".env")

    # Operator-supplied DB settings also apply to explicit offline/direct persistence.
    for key in ("DATABASE_URL", "POSTGRES_URL", "CENTRAL_PG_HOST", "CENTRAL_PG_PORT", "CENTRAL_PG_USER", "CENTRAL_PG_PASSWORD", "CENTRAL_PG_DATABASE", "DATA_DIR"):
        if key in env_vars and key not in os.environ:
            os.environ[key] = env_vars[key]

    server_url = args.server or os.environ.get("APPSCAN_URL") or env_vars.get("APPSCAN_URL") or "https://mhservice.co.in/appscan"
    user = os.environ.get("APPSCAN_USER") or env_vars.get("APPSCAN_USER", "admin")
    password = os.environ.get("APPSCAN_PASSWORD") or env_vars.get("APPSCAN_PASSWORD", "")
    project = args.project or git_root.name

    print(f"[*] AppScan Salesforce Code Analysis")
    print(f"[*] Project: {project} | API Version: {args.api_version}")

    # Build current archive
    all_skipped: list[tuple[str, int]] = []
    if args.use_head:
        print("[*] Packaging current code from git HEAD...")
        current_zip, skipped = create_archive_from_git_ref("HEAD", git_root, args.path)
        all_skipped.extend(skipped)
    else:
        print("[*] Packaging current working workspace files...")
        current_zip, skipped = create_archive_from_working_dir(git_root, args.path)
        all_skipped.extend(skipped)

    if not current_zip:
        raise RuntimeError("No Salesforce source files (.cls, .trigger, .xml, .js, .html, etc.) found in the target directory to scan.")

    # Build baseline archive if requested
    baseline_zip = None
    if args.baseline:
        print(f"[*] Packaging baseline code from '{args.baseline}'...")
        try:
            baseline_zip, base_skipped = create_archive_from_git_ref(args.baseline, git_root, args.path)
            all_skipped.extend(base_skipped)
        except Exception as e:
            if args.baseline in ("main", "master", "origin/main", "origin/master", "uat", "origin/uat"):
                print(f"[!] Notice: Baseline '{args.baseline}' could not be read ({e}). Proceeding without baseline comparison.")
                baseline_zip = None
            else:
                raise RuntimeError(f"Requested baseline could not be read: {e}") from e

    # Execute scan
    scan_result = None
    server_exc = None
    if not args.offline:
        try:
            print(f"[*] Connecting to AppScan server at {server_url}...")
            scan_result = run_scan_via_api(server_url, user, password, project, current_zip, baseline_zip, args.api_version, {"branch":args.branch, "pull_request":args.pull_request, "revision":args.revision, "coverage":coverage, "external":external, "baseline_external":baseline_external})
            print(f"[*] Scan report successfully uploaded to server ({server_url}). Scan ID: {scan_result.get('server_scan_id')}")
        except Exception as exc:
            server_exc = exc
            if args.fallback_offline:
                print(f"[!] Warning: Server scan failed at {server_url} ({exc}).")
                print(f"[*] Falling back to local offline scan engine (results will NOT be uploaded to {server_url})...")
                scan_result = None
            else:
                raise RuntimeError(f"Server scan failed ({server_url}): {exc}. Use --offline or --fallback-offline for local analysis.") from exc

    if scan_result is None:
        sys.path.insert(0, str(appscan_dir.parent))
        sys.path.insert(0, str(appscan_dir))
        print("[*] Running scan via in-process engine...")
        scan_result = run_scan_direct(current_zip, baseline_zip, args.api_version, coverage,
                                      {'project': project, 'branch': args.branch, 'pull_request': args.pull_request, 'revision': args.revision}, external=external, baseline_external=baseline_external)
        scan_result["server_uploaded"] = False
        scan_result["server_url"] = server_url
        if server_exc is not None:
            scan_result["server_error"] = str(server_exc)

    for item, sz in all_skipped:
        scan_result.setdefault("warnings", []).append(f"Skipped file '{item}' ({sz / (1024 * 1024):.1f} MiB): exceeds 2 MiB per-file limit.")

    # Save output artifacts
    out_dir = Path(args.output_dir)
    if not out_dir.is_absolute():
        out_dir = git_root / out_dir
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
    print("="*70)

    # Print Gate conditions if present
    conditions = scan_result.get("quality_gate", {}).get("conditions", [])
    if conditions:
        print("\nQuality Gate Conditions:")
        for c in conditions:
            status_icon = "✓" if c.get("status") == "PASS" else "✗"
            print(f"  [{status_icon}] {c.get('metric')}: {c.get('actual') if c.get('actual') is not None else 'MISSING'} (limit: {c.get('limit')}) -> {c.get('status')}")

    if gate.upper() == "INCOMPLETE":
        missing_cov = any(c.get("metric") == "min_coverage" and c.get("status") == "MISSING" for c in conditions)
        if missing_cov:
            limit = next((c.get("limit") for c in conditions if c.get("metric") == "min_coverage"), 75)
            print("\n" + "!"*70)
            print(f" [!] GATE INCOMPLETE: Project policy requires minimum {limit}% code coverage,")
            print("     but no coverage report was supplied.")
            print("     Run selective tests for modified classes with:")
            print("       python cli.py --run-tests")
            print("     Or provide a coverage JSON file with:")
            print("       python cli.py --coverage <file>")
            print("!"*70 + "\n")

    print()
    if gate.upper() in ("FAIL", "INCOMPLETE"):
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
