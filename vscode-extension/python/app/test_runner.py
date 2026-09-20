"""
AppScan Selective Apex Test Resolver and Runner.
Detects, maps, and executes selective test classes for modified Apex classes via Salesforce CLI (sf/sfdx),
persisting associations in .appscan/test-mapping.json so detection is only performed once.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

DEFAULT_MAPPING_FILE = ".appscan/test-mapping.json"


def load_mapping(mapping_file: Path) -> dict[str, list[str]]:
    """Load existing class-to-test mappings from JSON."""
    if not mapping_file.is_file():
        return {}
    try:
        data = json.loads(mapping_file.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return {k: list(v) if isinstance(v, list) else [str(v)] for k, v in data.items()}
    except Exception as exc:
        print(f"[!] Warning: Could not parse {mapping_file}: {exc}")
    return {}


def save_mapping(mapping_file: Path, mapping: dict[str, list[str]]) -> None:
    """Save class-to-test mappings into JSON file with indentation."""
    mapping_file.parent.mkdir(parents=True, exist_ok=True)
    sorted_mapping = {k: sorted(list(set(v))) for k, v in sorted(mapping.items())}
    mapping_file.write_text(json.dumps(sorted_mapping, indent=2) + "\n", encoding="utf-8")


def scan_workspace_classes(workspace_root: Path) -> tuple[dict[str, Path], dict[str, Path]]:
    """
    Scan workspace for Apex classes (.cls), categorizing them into:
    (source_classes, test_classes).
    """
    source_classes: dict[str, Path] = {}
    test_classes: dict[str, Path] = {}

    for p in workspace_root.rglob("*.cls"):
        if any(part in {".git", "node_modules", ".sf", ".sfdx", ".appscan", "dist", "build"} for part in p.parts):
            continue
        name = p.stem
        try:
            content = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        # Check if it is a test class: @isTest or testMethod
        is_test = bool(re.search(r"(?i)@isTest\b", content) or re.search(r"(?i)\btestMethod\b", content))
        if is_test:
            test_classes[name] = p
        else:
            source_classes[name] = p

    return source_classes, test_classes


def detect_test_classes_for(
    class_name: str,
    class_file: Path | None,
    test_classes: dict[str, Path]
) -> list[str]:
    """
    Intelligently discover matching test classes for class_name using:
    1. Standard naming conventions ({Name}Test, {Name}_Test, Test{Name}, {Name}Tests)
    2. Reference check inside test files (searching for instantiation or call of class_name)
    """
    found: list[str] = []

    # 1. Naming heuristics
    candidates = [
        f"{class_name}Test",
        f"{class_name}_Test",
        f"Test{class_name}",
        f"{class_name}Tests",
        f"Test_{class_name}",
        f"{class_name}TestCase",
    ]

    for candidate in candidates:
        if candidate in test_classes:
            found.append(candidate)

    if found:
        return found

    # 2. Reference heuristics: search test files that reference class_name
    pattern = re.compile(rf"\b{re.escape(class_name)}\b")
    for test_name, test_path in test_classes.items():
        try:
            content = test_path.read_text(encoding="utf-8", errors="replace")
            if pattern.search(content):
                found.append(test_name)
        except Exception:
            continue

    return found


def resolve_tests_for_classes(
    modified_classes: list[str],
    workspace_root: Path,
    mapping_file: Path | None = None,
    auto_detect: bool = True
) -> tuple[list[str], dict[str, list[str]]]:
    """
    Given a list of modified Apex class names, resolve the distinct list of test classes
    to execute, utilizing and updating .appscan/test-mapping.json.
    """
    mapping_path = mapping_file or (workspace_root / DEFAULT_MAPPING_FILE)
    mapping = load_mapping(mapping_path)
    updated = False

    source_classes: dict[str, Path] | None = None
    test_classes: dict[str, Path] | None = None

    resolved_tests: set[str] = set()

    for cls in modified_classes:
        # Strip .cls extension if present
        cls_clean = cls[:-4] if cls.endswith(".cls") else cls
        cls_clean = Path(cls_clean).name

        # Check if already mapped
        if cls_clean in mapping and mapping[cls_clean]:
            resolved_tests.update(mapping[cls_clean])
            continue

        if auto_detect:
            if source_classes is None or test_classes is None:
                source_classes, test_classes = scan_workspace_classes(workspace_root)

            # Check if this class is itself a test class
            if cls_clean in test_classes:
                resolved_tests.add(cls_clean)
                mapping[cls_clean] = [cls_clean]
                updated = True
                continue

            detected = detect_test_classes_for(
                cls_clean,
                source_classes.get(cls_clean),
                test_classes
            )
            if detected:
                resolved_tests.update(detected)
                mapping[cls_clean] = detected
                updated = True
                print(f"[*] Detected and mapped test class for {cls_clean}: {', '.join(detected)}")
            else:
                print(f"[!] No related test class found for modified class: {cls_clean}")

    if updated:
        save_mapping(mapping_path, mapping)
        print(f"[*] Updated test mapping in {mapping_path.relative_to(workspace_root) if mapping_path.is_relative_to(workspace_root) else mapping_path}")

    return sorted(list(resolved_tests)), mapping


def run_selective_tests(
    test_classes: list[str],
    workspace_root: Path,
    target_org: str | None = None,
    output_dir: Path | None = None
) -> dict | None:
    """
    Execute selective Apex tests via Salesforce CLI (sf or sfdx),
    and extract code coverage in standard AppScan format.
    """
    if not test_classes:
        print("[!] No test classes to execute.")
        return None

    out_dir = output_dir or (workspace_root / ".appscan")
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_output_file = out_dir / "sf-test-result.json"

    # Check for 'sf' or 'sfdx'
    sf_bin = shutil.which("sf") or shutil.which("sf.cmd")
    sfdx_bin = shutil.which("sfdx") or shutil.which("sfdx.cmd")

    tests_arg = ",".join(test_classes)
    print(f"[*] Running selective Apex tests: {tests_arg}")

    cmd: list[str] = []
    if sf_bin:
        cmd = [sf_bin, "apex", "run", "test", "--tests", tests_arg, "--code-coverage", "--result-format", "json"]
        if target_org:
            cmd.extend(["--target-org", target_org])
    elif sfdx_bin:
        cmd = [sfdx_bin, "force:apex:test:run", "-t", tests_arg, "-c", "-r", "json"]
        if target_org:
            cmd.extend(["-u", target_org])
    else:
        print("[!] Neither 'sf' nor 'sfdx' Salesforce CLI was found in PATH. Skipping test execution.")
        return None

    try:
        proc = subprocess.run(cmd, cwd=workspace_root, capture_output=True, text=True, check=False)
        stdout = proc.stdout.strip()
        if not stdout and proc.stderr:
            stdout = proc.stderr.strip()
        if stdout:
            raw_output_file.write_text(stdout, encoding="utf-8")

        # Parse output JSON
        data = None
        # Locate JSON block in output if CLI emitted warnings beforehand
        match = re.search(r"(\{.*\})", stdout, re.DOTALL)
        if match:
            data = json.loads(match.group(1))
        elif stdout.startswith("{"):
            data = json.loads(stdout)

        if not data:
            print("[!] Could not parse Salesforce CLI test output.")
            return None

        # Extract code coverage records
        result = data.get("result", data)
        records = result.get("coverage", [])
        if isinstance(records, dict):
            records = records.get("coverage", [])
        if not records and "codecoverage" in result:
            records = result.get("codecoverage", [])

        from .coverage import parse_coverage
        coverage_payload = {"result": {"coverage": records}}
        normalized = parse_coverage(json.dumps(coverage_payload))

        coverage_file = out_dir / "coverage.json"
        coverage_file.write_text(json.dumps(normalized, indent=2), encoding="utf-8")
        print(f"[*] Code coverage extracted for {len(normalized.get('files', []))} classes -> {coverage_file.name}")
        return normalized

    except Exception as exc:
        print(f"[!] Test execution error: {exc}")
        return None
