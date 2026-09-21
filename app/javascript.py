"""Isolated fixed-configuration JavaScript/LWC lint subprocess."""
import json
import os
from pathlib import Path
import shutil
import subprocess


def analyze(files, enabled):
    source={p:b.decode('utf-8',errors='replace') for p,b in files.items() if p.endswith('.js')}
    if not enabled or not source:return [],[]
    runner=Path(os.environ.get('APPSCAN_JS_RUNNER',str(Path(__file__).resolve().parent.parent/'analyzers/javascript/scan.mjs')))
    node=shutil.which('node')
    if not node or not runner.is_file():
        return [],[{'message':'JavaScript analysis requested but the administrator-owned Node/ESLint analyzer is unavailable.'}]
    try:
        result=subprocess.run([node,str(runner)],input=json.dumps(source),text=True,capture_output=True,timeout=180,cwd=runner.parent)
        if result.returncode:raise ValueError('engine failed')
        report=json.loads(result.stdout)
        return report['findings'],report['errors']
    except (OSError,ValueError,KeyError,subprocess.TimeoutExpired):
        return [],[{'message':'JavaScript analyzer failed or timed out. Check its installed dependencies and server logs.'}]
