"""Normalize imported coverage; never infer coverage when no report exists."""
import json
from .quality import coverage_metrics


def parse_coverage(text):
    if text.lstrip().startswith('{'):
        value = json.loads(text)
        if 'files' in value:
            coverage_metrics(value)
            return value
        # Salesforce CLI JSON aggregate code coverage records.
        result = value.get('result', value)
        records = result.get('coverage', []) if isinstance(result, dict) else []
        if isinstance(records, dict):
            records = records.get('coverage', [])
        if not isinstance(records, list) or not records:
            raise ValueError('Unsupported Salesforce coverage JSON. Use files[] or result.coverage[].')
        files = []
        for r in records:
            name = r.get('name') or r.get('ApexClassOrTrigger', {}).get('Name')
            covered = r.get('numLinesCovered', r.get('NumLinesCovered'))
            uncovered = r.get('numLinesUncovered', r.get('NumLinesUncovered'))
            if not name or covered is None or uncovered is None:
                raise ValueError('Coverage record needs name, numLinesCovered, and numLinesUncovered.')
            files.append({'path': name, 'covered_lines': covered, 'uncovered_lines': uncovered})
        value = {'files': files}
    else:
        records, current = {}, None
        for line in text.splitlines():
            if line.startswith('SF:'):
                current = line[3:]
                records.setdefault(current, {})
            elif line.startswith('DA:') and current:
                parts = line[3:].split(',')
                number, hits = int(parts[0]), int(parts[1])
                if number < 1 or hits < 0:
                    raise ValueError('Invalid LCOV line/hit count.')
                records[current][number] = max(hits, records[current].get(number, 0))
            elif line == 'end_of_record':
                current = None
        if not records:
            raise ValueError('Coverage is neither supported JSON nor LCOV.')
        value = {'files': [{'path': p, 'covered_lines': sum(n > 0 for n in lines.values()), 'uncovered_lines': sum(n == 0 for n in lines.values())} for p, lines in records.items()]}
    coverage_metrics(value)
    return value
