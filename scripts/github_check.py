#!/usr/bin/env python3
"""Optional CI check decoration; invoke explicitly with a fresh report and commit SHA."""
import argparse
import json
import os
from pathlib import Path
import re
import urllib.request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', required=True)
    parser.add_argument('--repository', default=os.environ.get('GITHUB_REPOSITORY'))
    parser.add_argument('--sha', required=True, help='Exact analyzed commit SHA')
    args = parser.parse_args()
    if not args.repository or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', args.repository):
        parser.error('Invalid repository.')
    if not re.fullmatch(r'[a-fA-F0-9]{40}', args.sha):
        parser.error('Supply the analyzed full 40-character commit SHA.')
    result = json.loads(Path(args.report).read_text())
    gate = result.get('gate', 'INCOMPLETE')
    lines = [f'Quality gate: **{gate}**', f'Findings: {len(result.get("findings", []))}', '', 'AppScan Salesforce analysis; review full report artifacts.']
    for c in result.get('quality_gate', {}).get('conditions', []):
        lines.append(f'- {c["metric"]}: {c["status"]} ({c["actual"]}, limit {c["limit"]})')
    annotations = []
    for f in result.get('findings', [])[:50]:
        annotations.append({'path': f['path'], 'start_line': max(1, f['line']), 'end_line': max(1, f['line']),
                            'annotation_level': 'failure' if f['severity'] in {'Critical','High'} else 'warning',
                            'title': f['rule'], 'message': f['message'][:60000]})
    payload = {'name': 'AppScan quality gate', 'head_sha': args.sha, 'status': 'completed',
               'conclusion': 'success' if gate == 'PASS' else 'failure',
               'output': {'title': 'AppScan: ' + gate, 'summary': '\n'.join(lines), 'annotations': annotations}}
    token = os.environ.get('GITHUB_TOKEN')
    if not token:
        parser.error('GITHUB_TOKEN with checks:write is required.')
    req = urllib.request.Request('https://api.github.com/repos/' + args.repository + '/check-runs',
        data=json.dumps(payload).encode(), headers={'Authorization':'Bearer ' + token, 'Accept':'application/vnd.github+json',
        'Content-Type':'application/json', 'X-GitHub-Api-Version':'2022-11-28'}, method='POST')
    with urllib.request.urlopen(req,timeout=30) as response:
        created=json.load(response)
    print('Created check run:',created['html_url'])


if __name__ == '__main__':
    main()
