"""Explicit, portable quality policy and metrics. No Sonar proprietary scoring."""
from collections import Counter
import fnmatch
import hashlib
import json
import math
from pathlib import PurePosixPath
import re

CATEGORIES = ['security', 'errorprone', 'performance', 'design', 'bestpractices', 'codestyle']
SEVERITIES = ['Critical', 'High', 'Medium', 'Low']
DEFAULT_POLICY = {
    'visualforce': False, 'javascript': False, 'min_new_coverage': None, 'scope': 'overall', 'max_blockers': 0, 'min_coverage': None,
    'max_duplication': None, 'require_hotspot_review': False,
    'categories': ['security', 'errorprone', 'performance', 'design'],
    'disabled_rules': [], 'severity_overrides': {}, 'exclusions': [], 'cpd': False, 'store_source': False,
}
HOTSPOTS = {'BroadDataAccess', 'PrivilegedPermission', 'FlowSystemContext', 'PossibleHardcodedSecret'}


def validate_policy(value):
    if not isinstance(value, dict) or set(value) - set(DEFAULT_POLICY):
        raise ValueError('Unknown policy settings.')
    policy = dict(DEFAULT_POLICY, **value)
    if policy['scope'] not in {'overall', 'new'}:
        raise ValueError('Gate scope must be overall or new.')
    if type(policy['max_blockers']) is not int or not 0 <= policy['max_blockers'] <= 100000:
        raise ValueError('max_blockers must be a nonnegative integer.')
    for key in ('min_coverage', 'min_new_coverage', 'max_duplication'):
        v = policy[key]
        if v is not None and (type(v) not in (int, float) or not math.isfinite(v) or not 0 <= v <= 100):
            raise ValueError(key + ' must be null or a percentage from 0 to 100.')
    for key in ('cpd', 'require_hotspot_review', 'store_source', 'javascript', 'visualforce'):
        if type(policy[key]) is not bool:
            raise ValueError(key + ' must be boolean.')
    for key in ('categories', 'disabled_rules', 'exclusions'):
        if not isinstance(policy[key], list) or len(policy[key]) > 100 or any(not isinstance(v, str) or len(v) > 200 for v in policy[key]):
            raise ValueError(key + ' must be a bounded list of strings.')
    if not policy['categories'] or set(policy['categories']) - set(CATEGORIES):
        raise ValueError('Select at least one supported Apex rule category.')
    if any(not re.fullmatch(r'[A-Za-z][A-Za-z0-9_./:-]{0,199}', v) for v in policy['disabled_rules']):
        raise ValueError('Invalid rule name.')
    overrides = policy['severity_overrides']
    if not isinstance(overrides, dict) or len(overrides) > 100 or any(not re.fullmatch(r'[A-Za-z][A-Za-z0-9_./:-]{0,199}', k) or v not in SEVERITIES for k, v in overrides.items()):
        raise ValueError('Invalid severity override.')
    return policy


def canonical(path):
    parts = PurePosixPath(path).parts
    folders = {'classes', 'triggers', 'objects', 'lwc', 'aura', 'pages', 'components', 'flows', 'permissionsets', 'profiles', 'layouts', 'staticresources', 'remoteSiteSettings'}
    for i, p in enumerate(parts):
        if p in folders:
            return '/'.join(parts[i:])
    return path


def filter_files(files, policy):
    return {p: data for p, data in files.items() if not any(fnmatch.fnmatchcase(p, pattern) or fnmatch.fnmatchcase(canonical(p), pattern) for pattern in policy['exclusions'])}


def analysis_signature(policy):
    values={k:policy.get(k,DEFAULT_POLICY[k]) for k in ('categories','exclusions','disabled_rules')}
    # Preserve v0.2 scope fingerprints when the new engine is disabled.
    if policy.get('javascript'):values['javascript']=True
    if policy.get('visualforce'):values['visualforce']=True
    return hashlib.sha256(json.dumps(values,sort_keys=True).encode()).hexdigest()


def enrich(findings, files, policy):
    seen = Counter()
    output = []
    for original in findings:
        if original['rule'] in policy['disabled_rules']:
            continue
        f = dict(original)
        f['severity'] = policy['severity_overrides'].get(f['rule'], f['severity'])
        f['kind'] = 'hotspot' if f['rule'] in HOTSPOTS else 'vulnerability' if f['category'] == 'Security' else 'code_smell'
        lines = files.get(f['path'], b'').decode('utf-8', errors='replace').splitlines()
        index = max(0, int(f.get('line') or 1) - 1)
        anchor = re.sub(r'\s+', ' ', lines[index].strip()) if index < len(lines) else f['message']
        # Repeated findings on identical source lines get deterministic occurrence IDs.
        seed = json.dumps([f['engine'], f['rule'], canonical(f['path']), anchor, f['message']], ensure_ascii=True)
        seen[seed] += 1
        f['fingerprint'] = hashlib.sha256((seed + ':' + str(seen[seed])).encode()).hexdigest()
        f['analysis_signature'] = analysis_signature(policy)
        f['status'] = 'open'
        f['assignee'] = ''
        f['is_new'] = True
        output.append(f)
    return output


def code_metrics(files):
    per_file = []
    for path, data in files.items():
        if not path.endswith(('.cls', '.trigger', '.js', '.ts', '.page', '.component')):
            continue
        text = data.decode('utf-8', errors='replace')
        lines = text.splitlines()
        # Lexical estimates, deliberately labelled; not PMD/Sonar semantic metrics.
        nonblank = sum(bool(line.strip()) for line in lines)
        comments = sum(line.lstrip().startswith(('//', '*', '/*', '<!--')) for line in lines)
        decisions = len(re.findall(r'\b(?:if|for|while|catch|when)\b|&&|\|\|', text))
        per_file.append({'path': path, 'lines': len(lines), 'nonblank_lines': nonblank,
                         'comment_lines_estimate': comments, 'decision_points_estimate': decisions})
    return {'lines': sum(x['lines'] for x in per_file), 'nonblank_lines': sum(x['nonblank_lines'] for x in per_file),
            'code_files': len(per_file), 'file_metrics': per_file}


def coverage_metrics(report):
    if report is None:
        return None
    if not isinstance(report, dict) or not isinstance(report.get('files'), list) or len(report['files']) > 10000:
        raise ValueError('Coverage must be {files: [{path, covered_lines, uncovered_lines}]}.')
    covered = uncovered = 0
    paths = set()
    for item in report['files']:
        if not isinstance(item, dict) or not isinstance(item.get('path'), str) or item['path'] in paths:
            raise ValueError('Coverage file paths must be unique strings.')
        paths.add(item['path'])
        for key in ('covered_lines', 'uncovered_lines'):
            if type(item.get(key)) is not int or not 0 <= item[key] <= 10000000:
                raise ValueError('Coverage counts must be nonnegative integers.')
        if 'line_hits' in item:
            hits=item['line_hits']
            if not isinstance(hits,dict) or len(hits)>100000 or any(not re.fullmatch(r'[1-9][0-9]{0,6}',k) or type(v) is not int or not 0<=v<=10000000 for k,v in hits.items()):
                raise ValueError('line_hits must map positive line numbers to nonnegative hit counts.')
            if sum(v>0 for v in hits.values())!=item['covered_lines'] or sum(v==0 for v in hits.values())!=item['uncovered_lines']:
                raise ValueError('Line hit counts disagree with coverage totals.')
        covered += item['covered_lines']
        uncovered += item['uncovered_lines']
    total = covered + uncovered
    return {'covered_lines': covered, 'uncovered_lines': uncovered, 'percent': round(100 * covered / total, 2) if total else None,
            'files': report['files'], 'source': 'imported; tests are not executed by AppScan'}


def evaluate(result, policy):
    conditions = []
    eligible = [f for f in result['findings'] if f.get('status') not in {'accepted', 'false_positive', 'safe', 'fixed'}]
    if policy['scope'] == 'new':
        eligible = [f for f in eligible if f.get('is_new', True)]
    blockers = sum(f['severity'] in {'Critical', 'High'} for f in eligible)
    conditions.append({'metric': policy['scope'] + '_blockers', 'actual': blockers, 'limit': policy['max_blockers'], 'status': 'PASS' if blockers <= policy['max_blockers'] else 'FAIL'})
    for key, actual, operator in [('min_coverage', (result.get('coverage') or {}).get('percent'), 'min'),
                                  ('min_new_coverage', (result.get('new_coverage') or {}).get('percent'), 'min'),
                                  ('max_duplication', (result.get('duplication') or {}).get('percent'), 'max')]:
        limit = policy.get(key)
        if limit is not None:
            status = 'MISSING' if actual is None else 'PASS' if (actual >= limit if operator == 'min' else actual <= limit) else 'FAIL'
            if key == 'min_new_coverage' and (result.get('new_coverage') or {}).get('status') == 'no_changed_executable_lines':
                status = 'NOT_APPLICABLE'
            conditions.append({'metric': key, 'actual': actual, 'limit': limit, 'status': status})
    if policy['require_hotspot_review']:
        pending = sum(f.get('kind') == 'hotspot' and f.get('status') in {'open', 'confirmed'} for f in eligible)
        conditions.append({'metric': 'unreviewed_hotspots', 'actual': pending, 'limit': 0, 'status': 'PASS' if pending == 0 else 'FAIL'})
    incomplete = bool(result['errors']) or any(c['status'] == 'MISSING' for c in conditions)
    return {'gate': 'INCOMPLETE' if incomplete else 'FAIL' if any(c['status'] == 'FAIL' for c in conditions) else 'PASS', 'conditions': conditions}


def sarif(result):
    rules = sorted({f['rule'] for f in result['findings']})
    return {'version': '2.1.0', '$schema': 'https://json.schemastore.org/sarif-2.1.0.json', 'runs': [{
        'tool': {'driver': {'name': 'AppScan', 'version': '0.4.0', 'rules': [{'id': r} for r in rules]}},
        'results': [{'ruleId': f['rule'], 'level': 'error' if f['severity'] in {'High', 'Critical'} else 'warning' if f['severity'] == 'Medium' else 'note',
                     'message': {'text': f['message']}, 'locations': [{'physicalLocation': {'artifactLocation': {'uri': __import__('urllib.parse', fromlist=['quote']).quote(f['path'], safe='/')},
                     'region': {'startLine': max(1, int(f.get('line') or 1))}}}],
                     'partialFingerprints': {'appscan/v1': f.get('fingerprint', '')}} for f in result['findings']]}]}
