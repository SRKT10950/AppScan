"""Authenticated on-premises scan service; one worker, SQLite or PostgreSQL."""
import base64
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import re
import secrets
import threading
import urllib.parse
import zipfile
from .scanner import read_zip, scan
from .db import get_db, initialize_db
from . import platform, quality

STATIC = Path(__file__).with_name('static')
USER = os.environ.get('APPSCAN_USER', 'admin')
PASSWORD = os.environ.get('APPSCAN_PASSWORD', '')
EXECUTOR = ThreadPoolExecutor(max_workers=1)
CAPACITY = threading.BoundedSemaphore(3)
BODY_LIMIT = 58 * 1024 * 1024


def initialize():
    initialize_db()
    platform.initialize()


def worker(scan_id, payload):
    try:
        with get_db() as con:
            con.execute("UPDATE scans SET status='running' WHERE id=?", (scan_id,))
        current = read_zip(payload['current'])
        baseline = read_zip(payload['baseline']) if payload.get('baseline') else None
        result = scan(current, baseline, payload['api_version'], payload['policy'], payload.get('coverage'))
        with get_db() as con:
            if payload['policy'].get('store_source'):
                for path, content in quality.filter_files(current, payload['policy']).items():
                    if path.endswith(('.cls', '.trigger', '.js', '.ts', '.page', '.component')):
                        con.execute('INSERT INTO scan_sources VALUES (?,?,?)', (scan_id, path, content.decode('utf-8', errors='replace').replace('\x00', '\ufffd')))
            platform.apply_result(con, scan_id, result)
            con.execute("UPDATE scans SET status='complete',result=? WHERE id=?", (json.dumps(result), scan_id))
    except Exception as exc:
        error = str(exc) if isinstance(exc, ValueError) else 'Scan failed. Check source and server/database availability.'
        try:
            with get_db() as con:
                con.execute("UPDATE scans SET status='failed',result=? WHERE id=?", (json.dumps({'error': error}), scan_id))
                platform.audit(con, 'scanner', 'scan.failed', scan_id)
        except Exception:
            print('Could not persist failed scan status; check database availability.', flush=True)
    finally:
        payload.clear()
        CAPACITY.release()


def report_zip(record):
    result = record['result']
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('report.json', json.dumps(record, indent=2))
        z.writestr('report.sarif', json.dumps(quality.sarif(result), indent=2))
        z.writestr('package.xml', result['package_xml'])
        z.writestr('destructiveChanges.xml', result['destructive_xml'])
        lines = ['# AppScan report', '', 'Project: ' + record['project'], 'Created: ' + record['created'],
                 'Quality gate: ' + result['gate'], 'PMD: ' + result['pmd'], '', '## Review notes']
        lines += ['- ' + w for w in result['warnings']]
        lines += ['', '## Metadata changes']
        lines += [f"- {r['status']}: {r['type']} / {r['member']}" for r in result['changes']]
        lines += ['', '## Findings']
        lines += [f"- {f['severity']} | {f['rule']} | {f['path']}:{f['line']} — {f['message']}" for f in result['findings']]
        lines += ['', '## Gate conditions', json.dumps(result.get('quality_gate', {}), indent=2)]
        lines += ['', '## Analysis errors'] + [str(e) for e in result['errors']]
        lines += ['', '## Unsupported files'] + result['unsupported']
        z.writestr('report.md', '\n'.join(lines))
    return out.getvalue()


def valid_text(value, label, maximum=100, required=True):
    if not isinstance(value, str) or len(value) > maximum or (required and not value.strip()) or any(ord(c) < 32 for c in value):
        raise ValueError(label + ' is invalid.')
    return value.strip()


class Handler(BaseHTTPRequestHandler):
    server_version = 'AppScan/0.2'

    def setup(self):
        super().setup()
        self.connection.settimeout(30)

    def log_message(self, fmt, *args):
        # Only method/status; URLs may contain project names or query data.
        print(self.command + ' request', flush=True)

    def send(self, code, body, kind='application/json', attachment=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header('Content-Type', kind)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if attachment:
            self.send_header('Content-Disposition', 'attachment; filename="' + attachment + '"')
        self.end_headers()
        self.wfile.write(body)

    def authorized(self):
        self.user = platform.authenticate(self.headers.get('Authorization', ''), USER, PASSWORD)
        if not self.user:
            self.send(401, {'error': 'Invalid or expired credentials.'})
            return False
        return True

    def admin(self):
        if self.user['role'] != 'admin' or 'token_scope' in self.user:
            raise PermissionError('Administrator password login required.')

    def _normalize_path(self):
        raw = urllib.parse.urlsplit(self.path).path
        return raw[len('/appscan'):] or '/' if raw == '/appscan' or raw.startswith('/appscan/') else raw

    def query(self):
        return {k: v[-1] for k, v in urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).items()}

    def read_json(self, limit=BODY_LIMIT):
        if self.headers.get('Content-Type', '').split(';')[0] != 'application/json' or self.headers.get('Transfer-Encoding'):
            raise ValueError('Use application/json with Content-Length.')
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            length = 0
        if not 0 < length <= limit:
            raise ValueError('Request exceeds size limit or has no valid Content-Length.')
        result = json.loads(self.rfile.read(length))
        if not isinstance(result, dict):
            raise ValueError('Request must be a JSON object.')
        return result

    def route(self, method):
        try:
            getattr(self, 'handle_' + method)()
        except PermissionError as exc:
            self.send(403, {'error': str(exc)})
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            self.send(400, {'error': str(exc) if isinstance(exc, ValueError) else 'Invalid request fields.'})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            self.send(503, {'error': 'Service unavailable; check database and server configuration.'})

    def do_GET(self):
        self.route('get')

    def do_POST(self):
        self.route('post')

    def handle_get(self):
        path = self._normalize_path()
        if path == '/healthz':
            return self.send(200, {'status': 'ok'})
        if path == '/readyz':
            with get_db() as db:
                db.execute('SELECT id FROM projects LIMIT 1').fetchall()
            return self.send(200, {'status': 'ready'})
        # Canonical trailing slash is needed for relative assets behind a proxy.
        if urllib.parse.urlsplit(self.path).path == '/appscan':
            query = urllib.parse.urlsplit(self.path).query
            self.send_response(308)
            self.send_header('Location', '/appscan/' + ('?' + query if query else ''))
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        assets = {'/': ('index.html', 'text/html; charset=utf-8'), '/app.js': ('app.js', 'text/javascript; charset=utf-8'), '/platform.js': ('platform.js', 'text/javascript; charset=utf-8'), '/style.css': ('style.css', 'text/css; charset=utf-8')}
        if path in assets:
            filename, kind = assets[path]
            return self.send(200, (STATIC / filename).read_bytes(), kind)
        if not self.authorized():
            return
        q = self.query()
        if path == '/api/me':
            return self.send(200, self.user)
        if path == '/api/projects':
            return self.send(200, platform.list_projects(self.user))
        if path == '/api/rules':
            from .rules import catalog
            return self.send(200, catalog())
        if path == '/api/tokens':
            if 'token_scope' in self.user:
                raise PermissionError('Password login required to list account tokens.')
            with get_db() as db:
                rows = db.execute('SELECT id,name,expires,project_id,scope FROM api_tokens WHERE username=?', (self.user['username'],)).fetchall()
            return self.send(200, rows)
        if path in {'/api/users', '/api/audit'}:
            self.admin()
            with get_db() as db:
                rows = db.execute('SELECT username,role,enabled FROM app_users ORDER BY username' if path == '/api/users' else 'SELECT * FROM audit_events ORDER BY created DESC LIMIT 200').fetchall()
            return self.send(200, rows)
        if path == '/api/scans':
            projects = platform.list_projects(self.user)
            ids = [p['id'] for p in projects if not q.get('project_id') or p['id'] == q['project_id']]
            if not ids:
                return self.send(200, [])
            sql = 'SELECT s.*,c.project_id,c.branch,c.pull_request,c.revision FROM scans s JOIN scan_context c ON s.id=c.scan_id WHERE c.project_id IN (' + ','.join('?' for _ in ids) + ')'
            params = list(ids)
            if q.get('branch'):
                sql += ' AND c.branch=?'
                params.append(q['branch'])
            sql += ' ORDER BY s.created DESC LIMIT 100'
            with get_db() as db:
                rows = db.execute(sql, params).fetchall()
            for r in rows:
                report = json.loads(r.pop('result') or '{}')
                r.update(gate=report.get('gate'), count=len(report.get('findings', [])), metrics=report.get('metrics') or {}, coverage=report.get('coverage'), duplication=report.get('duplication'))
                # Keep summaries small; per-file metrics remain in the scan report.
                if isinstance(r.get('metrics'), dict):
                    r['metrics'].pop('file_metrics', None)
            return self.send(200, rows)
        if path == '/api/issues':
            if not q.get('project_id'):
                raise ValueError('project_id query parameter is required.')
            platform.project_for(self.user, q['project_id'])
            sql = 'SELECT * FROM issues WHERE project_id=?'
            params = [q['project_id']]
            for key in ('branch', 'status', 'assignee'):
                if q.get(key):
                    sql += ' AND ' + key + '=?'
                    params.append(q[key])
            with get_db() as db:
                rows = db.execute(sql + ' ORDER BY id LIMIT 2000', params).fetchall()
            for r in rows:
                r['finding'] = json.loads(r['finding'])
            if q.get('kind'):
                rows = [r for r in rows if r['finding'].get('kind') == q['kind']]
            if q.get('search'):
                rows = [r for r in rows if q['search'].lower() in json.dumps(r['finding']).lower()]
            return self.send(200, rows)
        match = re.fullmatch(r'/api/issues/([a-f0-9]{32})/comments', path)
        if match:
            with get_db() as db:
                issue = db.execute('SELECT project_id FROM issues WHERE id=?', (match[1],)).fetchone()
                if not issue:
                    return self.send(404, {'error': 'Issue not found.'})
                platform.project_for(self.user, issue['project_id'])
                rows = db.execute('SELECT * FROM issue_comments WHERE issue_id=? ORDER BY created', (match[1],)).fetchall()
            return self.send(200, rows)
        match = re.fullmatch(r'/api/scans/([a-f0-9]{32})(/report.zip|/report.sarif|/source)?', path)
        if match:
            with get_db() as db:
                record = db.execute('SELECT s.*,c.project_id,c.branch,c.pull_request,c.revision FROM scans s JOIN scan_context c ON s.id=c.scan_id WHERE s.id=?', (match[1],)).fetchone()
            if not record:
                return self.send(404, {'error': 'Scan not found.'})
            platform.project_for(self.user, record['project_id'])
            record['result'] = json.loads(record['result'] or '{}')
            if match[2] == '/source':
                with get_db() as db:
                    source = db.execute('SELECT content FROM scan_sources WHERE scan_id=? AND path=?', (match[1], q.get('path', ''))).fetchone()
                return self.send(200, source) if source else self.send(404, {'error': 'Source not retained. Enable source browsing in the project policy before scanning.'})
            if match[2]:
                if record['status'] != 'complete':
                    return self.send(409, {'error': 'Report is not ready.'})
                if match[2] == '/report.sarif':
                    return self.send(200, quality.sarif(record['result']))
                return self.send(200, report_zip(record), 'application/zip', 'appscan-report.zip')
            return self.send(200, record)
        self.send(404, {'error': 'Not found.'})

    def handle_post(self):
        if not self.authorized():
            return
        path = self._normalize_path()
        if 'token_scope' in self.user and (path != '/api/scans' or self.user['token_scope'] != 'scan'):
            raise PermissionError('This token cannot perform that action.')
        if path == '/api/scans':
            return self.submit_scan()
        payload = self.read_json(128 * 1024)
        if path == '/api/projects':
            self.admin()
            row = platform.ensure_project(self.user, valid_text(payload.get('name'), 'Project name'))
            return self.send(201, {'id': row['id']})
        match = re.fullmatch(r'/api/projects/([a-f0-9]{32})', path)
        if match:
            platform.save_project(self.user, match[1], payload)
            return self.send(200, {'saved': True})
        match = re.fullmatch(r'/api/issues/([a-f0-9]{32})', path)
        if match:
            platform.change_issue(self.user, match[1], payload)
            return self.send(200, {'saved': True, 'note': 'Historical gates are immutable. Rescan to evaluate reviews.'})
        if path == '/api/users':
            self.admin()
            platform.manage_user(self.user['username'], payload, USER)
            return self.send(200, {'saved': True})
        if path == '/api/tokens':
            return self.send(201, platform.create_token(self.user, payload))
        match = re.fullmatch(r'/api/tokens/([a-f0-9]{32})/revoke', path)
        if match:
            with get_db() as db:
                db.execute('DELETE FROM api_tokens WHERE id=? AND username=?', (match[1], self.user['username']))
                platform.audit(db, self.user['username'], 'token.revoke', match[1])
            return self.send(200, {'revoked': True})
        self.send(404, {'error': 'Not found.'})

    def submit_scan(self):
        if self.user['role'] == 'viewer':
            raise PermissionError('Viewer accounts cannot submit scans.')
        if not CAPACITY.acquire(blocking=False):
            return self.send(429, {'error': 'Three scans are already queued/running. Try again later.'})
        submitted = False
        try:
            payload = self.read_json()
            project = platform.ensure_project(self.user, valid_text(payload.get('project'), 'Project name'))
            version = payload.get('api_version', '64.0')
            if not isinstance(version, str) or not re.fullmatch(r'\d{2,3}\.0', version):
                raise ValueError('Invalid API version.')
            branch = valid_text(payload.get('branch', 'main'), 'Branch', 200)
            if not re.fullmatch(r'[A-Za-z0-9_./-]{1,200}', branch):
                raise ValueError('Branch names must use letters, digits, underscores, dots, slashes, or hyphens.')
            pr = valid_text(payload.get('pull_request', ''), 'Pull request', 32, False)
            if pr and not pr.isdigit():
                raise ValueError('Pull request must be a numeric identifier.')
            revision = valid_text(payload.get('revision', ''), 'Revision', 100, False)
            if not isinstance(payload.get('current'), str) or not payload['current']:
                raise ValueError('Current source ZIP is required.')
            if payload.get('baseline') is not None and not isinstance(payload['baseline'], str):
                raise ValueError('Baseline must be a base64 ZIP string.')
            quality.coverage_metrics(payload.get('coverage'))
            policy = json.loads(project['settings'])
            payload = {k: payload.get(k) for k in ('current', 'baseline', 'coverage')}
            payload.update(api_version=version, policy=policy)
            scan_id = secrets.token_hex(16)
            with get_db() as con:
                con.execute('INSERT INTO scans (id,project,created,status,result) VALUES (?,?,?,?,?)', (scan_id, project['name'], platform.now(), 'queued', '{}'))
                con.execute('INSERT INTO scan_context VALUES (?,?,?,?,?,?,?)', (scan_id, project['id'], branch, pr, revision, self.user['username'], json.dumps(policy)))
                platform.audit(con, self.user['username'], 'scan.queued', scan_id, {'project_id': project['id'], 'branch': branch, 'pull_request': pr})
            EXECUTOR.submit(worker, scan_id, payload)
            submitted = True
            self.send(202, {'id': scan_id})
        finally:
            if not submitted:
                CAPACITY.release()


class Server(ThreadingHTTPServer):
    daemon_threads = True
    slots = threading.BoundedSemaphore(16)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


def main():
    if len(PASSWORD) < 16 or PASSWORD.startswith('CHANGE_'):
        raise SystemExit('Set APPSCAN_PASSWORD to a unique password of at least 16 characters.')
    initialize()
    port = int(os.environ.get('PORT', os.environ.get('APPSCAN_PORT', 8080)))
    bind = os.environ.get('APPSCAN_BIND', '0.0.0.0')
    server = Server((bind, port), Handler)
    print(f'AppScan listening on {bind}:{port}', flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        EXECUTOR.shutdown(wait=True)


if __name__ == '__main__':
    main()
