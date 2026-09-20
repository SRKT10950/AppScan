"""Projects, identity, persistent issue workflow and auditable policy storage."""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import re
import secrets
from .db import get_db
from .quality import DEFAULT_POLICY, validate_policy, evaluate, analysis_signature


def now():
    return datetime.now(timezone.utc).isoformat()


def initialize():
    with get_db() as db:
        for sql in [
            'CREATE TABLE IF NOT EXISTS projects (id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, settings TEXT NOT NULL, members TEXT NOT NULL, created TEXT NOT NULL)',
            'CREATE TABLE IF NOT EXISTS scan_sources (scan_id TEXT NOT NULL, path TEXT NOT NULL, content TEXT NOT NULL, PRIMARY KEY(scan_id,path))',
            'CREATE TABLE IF NOT EXISTS scan_context (scan_id TEXT PRIMARY KEY, project_id TEXT NOT NULL, branch TEXT NOT NULL, pull_request TEXT NOT NULL, revision TEXT NOT NULL, actor TEXT NOT NULL, policy TEXT NOT NULL)',
            'CREATE TABLE IF NOT EXISTS issues (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, branch TEXT NOT NULL, fingerprint TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, status TEXT NOT NULL, assignee TEXT NOT NULL, finding TEXT NOT NULL, UNIQUE(project_id,branch,fingerprint))',
            'CREATE TABLE IF NOT EXISTS issue_comments (id TEXT PRIMARY KEY, issue_id TEXT NOT NULL, actor TEXT NOT NULL, created TEXT NOT NULL, body TEXT NOT NULL)',
            'CREATE TABLE IF NOT EXISTS app_users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL, enabled INTEGER NOT NULL)',
            'CREATE TABLE IF NOT EXISTS api_tokens (id TEXT PRIMARY KEY, username TEXT NOT NULL, name TEXT NOT NULL, digest TEXT UNIQUE NOT NULL, expires TEXT NOT NULL, project_id TEXT NOT NULL, scope TEXT NOT NULL)',
            'CREATE TABLE IF NOT EXISTS audit_events (id TEXT PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, created TEXT NOT NULL, details TEXT NOT NULL)',
            'CREATE INDEX IF NOT EXISTS issues_project ON issues(project_id,branch)',
            'CREATE INDEX IF NOT EXISTS context_project ON scan_context(project_id)',
        ]:
            db.execute(sql)
        # Idempotent legacy backfill preserves old scans and the existing schema.
        rows = db.execute('SELECT DISTINCT project FROM scans').fetchall()
        for row in rows:
            name = row['project'] or 'Imported project'
            pid = project_id(name)
            db.execute('INSERT INTO projects VALUES (?,?,?,?,?) ON CONFLICT (id) DO NOTHING', (pid, name, json.dumps(DEFAULT_POLICY), '[]', now()))
        for row in db.execute('SELECT s.id,s.project FROM scans s LEFT JOIN scan_context c ON s.id=c.scan_id WHERE c.scan_id IS NULL').fetchall():
            db.execute('INSERT INTO scan_context VALUES (?,?,?,?,?,?,?)', (row['id'], project_id(row['project'] or 'Imported project'), 'main', '', '', 'legacy', json.dumps(DEFAULT_POLICY)))


def project_id(name):
    return hashlib.sha256(name.encode()).hexdigest()[:32]


def audit(db, actor, action, target, details=None):
    db.execute('INSERT INTO audit_events VALUES (?,?,?,?,?,?)', (secrets.token_hex(16), actor, action, target, now(), json.dumps(details or {})))


def password_hash(password):
    if not isinstance(password, str) or not 16 <= len(password) <= 256:
        raise ValueError('Passwords must have 16–256 characters.')
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 310000).hex()
    return salt + '$' + digest


def password_matches(password, encoded):
    try:
        salt, digest = encoded.split('$')
        return hmac.compare_digest(hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 310000).hex(), digest)
    except (ValueError, AttributeError):
        return False


def authenticate(header, admin_user, admin_password):
    with get_db() as db:
        if header.startswith('Bearer '):
            digest = hashlib.sha256(header[7:].encode()).hexdigest()
            token = db.execute('SELECT * FROM api_tokens WHERE digest=?', (digest,)).fetchone()
            if not token or token['expires'] <= now():
                return None
            if token['username'] == admin_user:
                user = {'username': admin_user, 'role': 'admin', 'enabled': 1}
            else:
                user = db.execute('SELECT username,role,enabled FROM app_users WHERE username=?', (token['username'],)).fetchone()
            if not user or not user['enabled']:
                return None
            return dict(user, token_project=token['project_id'], token_scope=token['scope'])
        if not header.startswith('Basic '):
            return None
        try:
            username, password = base64.b64decode(header[6:], validate=True).decode().split(':', 1)
        except (ValueError, UnicodeDecodeError):
            return None
        if len(password) > 256:
            return None
        if username == admin_user and admin_password and hmac.compare_digest(password.encode(), admin_password.encode()):
            return {'username': username, 'role': 'admin'}
        row = db.execute('SELECT * FROM app_users WHERE username=?', (username,)).fetchone()
        if row and row['enabled'] and password_matches(password, row['password_hash']):
            return {'username': username, 'role': row['role']}
    return None


def can_access(user, project, write=False):
    if user.get('token_project') and user['token_project'] != project['id']:
        return False
    if write and (user['role'] == 'viewer' or user.get('token_scope') == 'read'):
        return False
    return user['role'] == 'admin' or user['username'] in json.loads(project['members'])


def project_for(user, pid, write=False):
    with get_db() as db:
        row = db.execute('SELECT * FROM projects WHERE id=?', (pid,)).fetchone()
    if not row or not can_access(user, row, write):
        raise PermissionError('Project is not accessible.')
    return row


def ensure_project(user, name):
    pid = project_id(name)
    with get_db() as db:
        row = db.execute('SELECT * FROM projects WHERE id=?', (pid,)).fetchone()
        if row is None:
            if user['role'] != 'admin' or 'token_scope' in user:
                raise PermissionError('An administrator must create the project and grant access first.')
            db.execute('INSERT INTO projects VALUES (?,?,?,?,?)', (pid, name, json.dumps(DEFAULT_POLICY), '[]', now()))
            audit(db, user['username'], 'project.create', pid, {'name': name})
    return project_for(user, pid, write=True)


def list_projects(user):
    with get_db() as db:
        rows = db.execute('SELECT * FROM projects ORDER BY name').fetchall()
    return [dict(r, settings=json.loads(r['settings']), members=json.loads(r['members'])) for r in rows if can_access(user, r)]


def save_project(user, pid, payload):
    if user['role'] != 'admin' or 'token_scope' in user:
        raise PermissionError('Administrator login required.')
    project_for(user, pid)
    settings = validate_policy(payload.get('settings', {}))
    members = payload.get('members', [])
    if not isinstance(members, list) or len(members) > 100 or any(not isinstance(x, str) for x in members):
        raise ValueError('Members must be a list of usernames.')
    with get_db() as db:
        users = {r['username'] for r in db.execute('SELECT username FROM app_users WHERE enabled=1').fetchall()}
        if set(members) - users:
            raise ValueError('All project members must be enabled users.')
        db.execute('UPDATE projects SET settings=?,members=? WHERE id=?', (json.dumps(settings), json.dumps(members), pid))
        audit(db, user['username'], 'project.settings', pid, {'settings': settings, 'members': members})


def apply_result(db, scan_id, result):
    context = db.execute('SELECT * FROM scan_context WHERE scan_id=?', (scan_id,)).fetchone()
    policy = json.loads(context['policy'])
    if result['errors']:
        # A failed analysis cannot establish the new-code reference or change lifecycle.
        result['quality_gate'] = evaluate(result, policy)
        result['gate'] = result['quality_gate']['gate']
        result['policy'] = policy
        result['metrics']['new_findings'] = sum(f.get('is_new', True) for f in result['findings'])
        platform_note = 'Issue history was not updated because analysis was incomplete.'
        result['warnings'].append(platform_note)
        audit(db, context['actor'], 'scan.incomplete', scan_id)
        return
    branch = context['branch'] if not context['pull_request'] else 'pr:' + context['pull_request'] + ':' + context['branch']
    prior = db.execute('SELECT * FROM issues WHERE project_id=? AND branch=?', (context['project_id'], branch)).fetchall()
    old = {r['fingerprint']: r for r in prior}
    current = set()
    for f in result['findings']:
        key = f['fingerprint']
        current.add(key)
        row = old.get(key)
        if row:
            status = 'open' if row['status'] == 'fixed' else row['status']
            f.update(issue_id=row['id'], status=status, assignee=row['assignee'])
            if result.get('new_code_reference') != 'uploaded_baseline':
                f['is_new'] = row['status'] == 'fixed'
            db.execute('UPDATE issues SET last_seen=?,status=?,finding=? WHERE id=?', (scan_id, status, json.dumps(f), row['id']))
        else:
            issue_id = secrets.token_hex(16)
            f['issue_id'] = issue_id
            db.execute('INSERT INTO issues VALUES (?,?,?,?,?,?,?,?,?)', (issue_id, context['project_id'], branch, key, scan_id, scan_id, 'open', '', json.dumps(f)))
    # Do not close issues on broken or changed-scope scans.
    prev = db.execute("SELECT c.policy FROM scan_context c JOIN scans s ON s.id=c.scan_id WHERE c.project_id=? AND c.branch=? AND c.pull_request=? AND s.status='complete' AND s.id<>? ORDER BY s.created DESC LIMIT 1", (context['project_id'], context['branch'], context['pull_request'], scan_id)).fetchone()
    same_scope = not prev or json.loads(prev['policy']) == policy
    if not result['errors'] and same_scope:
        for key, row in old.items():
            if key not in current and row['status'] != 'fixed' and json.loads(row['finding']).get('analysis_signature') == analysis_signature(policy):
                db.execute("UPDATE issues SET status='fixed' WHERE id=?", (row['id'],))
                audit(db, 'scanner', 'issue.fixed', row['id'], {'scan_id': scan_id})
    if result.get('new_code_reference') != 'uploaded_baseline':
        result['new_code_reference'] = 'previous_branch_findings' if old else 'first_scan_all_new'
    result['quality_gate'] = evaluate(result, policy)
    result['gate'] = result['quality_gate']['gate']
    result['policy'] = policy
    result['metrics']['new_findings'] = sum(f['is_new'] for f in result['findings'])
    audit(db, context['actor'], 'scan.complete', scan_id, {'gate': result['gate']})


def change_issue(user, iid, payload):
    with get_db() as db:
        row = db.execute('SELECT * FROM issues WHERE id=?', (iid,)).fetchone()
    if not row:
        raise ValueError('Issue not found.')
    project_for(user, row['project_id'], write=True)
    f = json.loads(row['finding'])
    allowed = {'open', 'confirmed', 'accepted', 'false_positive'} | ({'safe'} if f.get('kind') == 'hotspot' else set())
    status = payload.get('status', row['status'])
    if status not in allowed:
        raise ValueError('Invalid status; fixed is assigned by a successful rescan.')
    comment = payload.get('comment', '').strip()
    if not comment or len(comment) > 4000:
        raise ValueError('A review comment of 1–4000 characters is required.')
    assignee = payload.get('assignee', row['assignee'])
    if not isinstance(assignee, str):
        raise ValueError('Invalid assignee.')
    with get_db() as db:
        if assignee:
            target = db.execute('SELECT username,role,enabled FROM app_users WHERE username=?', (assignee,)).fetchone()
            project = db.execute('SELECT * FROM projects WHERE id=?', (row['project_id'],)).fetchone()
            if not target or not target['enabled'] or not can_access(target, project):
                raise ValueError('Assignee must be an enabled project member.')
        db.execute('UPDATE issues SET status=?,assignee=? WHERE id=?', (status, assignee, iid))
        db.execute('INSERT INTO issue_comments VALUES (?,?,?,?,?)', (secrets.token_hex(16), iid, user['username'], now(), comment))
        audit(db, user['username'], 'issue.review', iid, {'from': row['status'], 'to': status, 'assignee': assignee})


def manage_user(actor, payload, admin_user):
    username = payload.get('username', '')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', username) or username == admin_user:
        raise ValueError('Invalid or reserved username.')
    role = payload.get('role', 'viewer')
    if role not in {'admin', 'analyst', 'viewer'} or type(payload.get('enabled', True)) is not bool:
        raise ValueError('Invalid role or enabled value.')
    with get_db() as db:
        row = db.execute('SELECT * FROM app_users WHERE username=?', (username,)).fetchone()
        encoded = password_hash(payload['password']) if payload.get('password') else row['password_hash'] if row else None
        if not encoded:
            raise ValueError('Password required for a new user.')
        db.execute('INSERT INTO app_users VALUES (?,?,?,?) ON CONFLICT (username) DO UPDATE SET password_hash=excluded.password_hash,role=excluded.role,enabled=excluded.enabled', (username, encoded, role, int(payload.get('enabled', True))))
        if payload.get('password') or not payload.get('enabled', True):
            db.execute('DELETE FROM api_tokens WHERE username=?', (username,))
        audit(db, actor, 'user.update', username, {'role': role, 'enabled': payload.get('enabled', True)})


def create_token(user, payload):
    if 'token_scope' in user:
        raise PermissionError('Use a password login to create tokens.')
    pid = payload.get('project_id', '')
    scope = payload.get('scope', 'read')
    if scope not in {'read', 'scan'}:
        raise ValueError('Token scope must be read or scan.')
    project_for(user, pid, write=scope == 'scan')
    days = payload.get('days', 30)
    if type(days) is not int or not 1 <= days <= 365:
        raise ValueError('Token expiry must be 1–365 days.')
    name = payload.get('name', 'API token')
    if not isinstance(name, str) or not 1 <= len(name) <= 100:
        raise ValueError('Token name must be 1–100 characters.')
    token = 'aps_' + secrets.token_urlsafe(32)
    tid = secrets.token_hex(16)
    expiry = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()
    with get_db() as db:
        db.execute('INSERT INTO api_tokens VALUES (?,?,?,?,?,?,?)', (tid, user['username'], name, hashlib.sha256(token.encode()).hexdigest(), expiry, pid, scope))
        audit(db, user['username'], 'token.create', tid, {'project_id': pid, 'scope': scope})
    return {'id': tid, 'token': token, 'expires': expiry}
