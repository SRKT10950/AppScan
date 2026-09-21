"""PMD Visualforce security rules using administrator-owned rule selection."""
import json
from pathlib import Path
import subprocess
import tempfile
import os


def analyze(files, enabled):
    if not enabled:
        return [], [], 'disabled'
    if not any(p.endswith(('.page', '.component')) for p in files):
        return [], [], 'not_applicable'
    from .scanner import find_pmd_binary, parse_pmd
    binary = find_pmd_binary()
    if not binary:
        return [], [{'message': 'Visualforce analysis requested but PMD is unavailable.'}], 'unavailable'
    with tempfile.TemporaryDirectory(prefix='appscan-vf-') as td:
        root = Path(td)
        source = root / 'source'
        source.mkdir()
        # Preserve controller/object siblings for PMD's local type resolution.
        # Only the fixed Visualforce ruleset runs; uploaded configuration is ignored.
        for path, content in files.items():
            if not (path.endswith(('.page', '.component', '.cls', '.object', '.object-meta.xml', '.field-meta.xml'))):
                continue
            target = source / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        report = root / 'report.json'
        try:
            result = subprocess.run([binary, 'check', '-d', str(source), '-R', 'category/visualforce/security.xml',
                '-f', 'json', '-r', str(report), '--no-cache', '--threads', '2'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=180,
                check=False, shell=(os.name == 'nt'))
            if result.returncode not in {0, 4}:
                raise ValueError('PMD did not complete')
            findings, errors = parse_pmd(json.loads(report.read_text()), source)
            for f in findings:
                f['engine'] = 'PMD Visualforce'
            errors = [{'message': 'Visualforce processing/configuration error. Check source syntax and installed PMD rules.'} for _ in errors]
            return findings, errors, 'error' if errors else 'complete'
        except (OSError, ValueError, subprocess.TimeoutExpired):
            return [], [{'message': 'Visualforce analysis failed or timed out.'}], 'error'
