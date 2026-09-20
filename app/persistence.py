"""Operator-only direct scan persistence with explicit database configuration.
Database credentials confer administrative access. Run serially; server API is preferred.
"""
import json
import re
import secrets
from .db import get_db
from . import platform, quality
from .scanner import scan


def direct_scan(current, baseline, version, coverage, context):
    name=context.get('project','')
    branch=context.get('branch','main')
    pr=context.get('pull_request','')
    revision=context.get('revision','')
    if not isinstance(name,str) or not 1 <= len(name) <= 100 or any(ord(c)<32 for c in name):
        raise ValueError('Invalid direct-scan project.')
    if not isinstance(branch,str) or not re.fullmatch(r'[A-Za-z0-9_./-]{1,200}',branch):
        raise ValueError('Invalid branch.')
    if not isinstance(pr,str) or (pr and not re.fullmatch(r'\d{1,32}',pr)):
        raise ValueError('Invalid PR identifier.')
    if not isinstance(revision,str) or len(revision)>100 or any(ord(c)<32 for c in revision):
        raise ValueError('Invalid revision.')
    # Never call startup recovery here; it would mark the server's active scans failed.
    with get_db() as db:
        db.execute('CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, project TEXT, created TEXT, status TEXT, result TEXT)')
    platform.initialize()
    project=platform.ensure_project({'username':'local-cli','role':'admin'},name)
    policy=quality.validate_policy(json.loads(project['settings']))
    result=scan(current,baseline,version,policy,coverage)
    sid=secrets.token_hex(16)
    with get_db() as db:
        db.execute('INSERT INTO scans VALUES (?,?,?,?,?)',(sid,name,platform.now(),'running','{}'))
        db.execute('INSERT INTO scan_context VALUES (?,?,?,?,?,?,?)',(sid,project['id'],branch,pr,revision,'local-cli',json.dumps(policy)))
        if policy['store_source']:
            for path, content in quality.filter_files(current,policy).items():
                if path.endswith(('.cls','.trigger','.js','.ts','.page','.component')):
                    db.execute('INSERT INTO scan_sources VALUES (?,?,?)',(sid,path,content.decode('utf-8',errors='replace').replace('\x00','\ufffd')))
        platform.apply_result(db,sid,result)
        db.execute("UPDATE scans SET status='complete',result=? WHERE id=?",(json.dumps(result),sid))
    print(f'[*] Direct scan saved to configured database (ID: {sid})')
    return result
