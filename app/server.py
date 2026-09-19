"""Single-instance authenticated on-premises scan service."""
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import threading
import urllib.parse
import zipfile
from .scanner import read_zip, scan

DATA = Path(os.environ.get('DATA_DIR', '/data'))
STATIC = Path(__file__).with_name('static')
USER = os.environ.get('APPSCAN_USER', 'admin')
PASSWORD = os.environ.get('APPSCAN_PASSWORD', '')
EXECUTOR = ThreadPoolExecutor(max_workers=1)
CAPACITY = threading.BoundedSemaphore(3)
BODY_LIMIT = 58 * 1024 * 1024


def connection():
    con = sqlite3.connect(DATA / 'appscan.db', timeout=15)
    con.row_factory = sqlite3.Row
    return con


def initialize():
    DATA.mkdir(parents=True, exist_ok=True)
    with connection() as con:
        con.execute('PRAGMA journal_mode=WAL')
        con.execute('CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, project TEXT, created TEXT, status TEXT, result TEXT)')
        con.execute("UPDATE scans SET status='failed', result=? WHERE status IN ('queued','running')", (json.dumps({'error': 'Server restarted before completion. Submit the scan again.'}),))


def worker(scan_id, payload):
    try:
        with connection() as con:
            con.execute("UPDATE scans SET status='running' WHERE id=?", (scan_id,))
        current = read_zip(payload['current'])
        baseline = read_zip(payload['baseline']) if payload.get('baseline') else None
        result = scan(current, baseline, payload['api_version'])
        status = 'complete'
    except ValueError as exc:
        result, status = {'error': str(exc)}, 'failed'
    except Exception:
        result, status = {'error': 'Scan failed unexpectedly. Verify source archive and server configuration.'}, 'failed'
    finally:
        payload.clear()
    try:
        with connection() as con:
            con.execute('UPDATE scans SET status=?, result=? WHERE id=?', (status, json.dumps(result), scan_id))
    finally:
        CAPACITY.release()


def report_zip(record):
    result = record['result']
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('report.json', json.dumps(record, indent=2))
        z.writestr('package.xml', result['package_xml'])
        z.writestr('destructiveChanges.xml', result['destructive_xml'])
        lines = ['# AppScan report', '', 'Project: ' + record['project'], 'Created: ' + record['created'],
                 'Quality gate: ' + result['gate'], 'PMD: ' + result['pmd'], '', '## Review notes']
        lines += ['- ' + w for w in result['warnings']]
        lines += ['', '## Metadata changes']
        lines += [f"- {r['status']}: {r['type']} / {r['member']}" for r in result['changes']]
        lines += ['', '## Findings']
        lines += [f"- {f['severity']} | {f['rule']} | {f['path']}:{f['line']} — {f['message']}" for f in result['findings']]
        lines += ['', '## Analysis errors'] + [str(e) for e in result['errors']]
        lines += ['', '## Unsupported files'] + result['unsupported']
        z.writestr('report.md', '\n'.join(lines))
    return out.getvalue()


class Handler(BaseHTTPRequestHandler):
    server_version = 'AppScan'

    def setup(self):
        super().setup()
        self.connection.settimeout(30)

    def log_message(self, fmt, *args):
        # Never log request headers, credentials, source, or body.
        print('%s %s' % (self.log_date_time_string(), fmt % args), flush=True)

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
        expected = 'Basic ' + base64.b64encode((USER + ':' + PASSWORD).encode()).decode()
        if not PASSWORD or not hmac.compare_digest(self.headers.get('Authorization', ''), expected):
            self.send(401, {'error': 'Invalid username or password.'})
            return False
        return True

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == '/healthz':
            return self.send(200, {'status': 'ok'})
        assets = {'/': ('index.html', 'text/html; charset=utf-8'), '/app.js': ('app.js', 'text/javascript; charset=utf-8'), '/style.css': ('style.css', 'text/css; charset=utf-8')}
        if path in assets:
            filename, kind = assets[path]
            return self.send(200, (STATIC / filename).read_bytes(), kind)
        if not self.authorized():
            return
        if path == '/api/scans':
            with connection() as con:
                rows = con.execute('SELECT * FROM scans ORDER BY created DESC LIMIT 100').fetchall()
            result = []
            for row in rows:
                r = dict(row)
                report = json.loads(r.pop('result') or '{}')
                r.update(gate=report.get('gate'), count=len(report.get('findings', [])))
                result.append(r)
            return self.send(200, result)
        match = re.fullmatch(r'/api/scans/([a-f0-9]{32})(/report.zip)?', path)
        if match:
            with connection() as con:
                row = con.execute('SELECT * FROM scans WHERE id=?', (match[1],)).fetchone()
            if not row:
                return self.send(404, {'error': 'Scan not found.'})
            record = dict(row)
            record['result'] = json.loads(record['result'] or '{}')
            if match[2]:
                if record['status'] != 'complete':
                    return self.send(409, {'error': 'Report is not ready.'})
                return self.send(200, report_zip(record), 'application/zip', 'appscan-report.zip')
            return self.send(200, record)
        self.send(404, {'error': 'Not found.'})

    def do_POST(self):
        if not self.authorized():
            return
        if self.path != '/api/scans':
            return self.send(404, {'error': 'Not found.'})
        if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
            return self.send(415, {'error': 'Use application/json.'})
        if self.headers.get('Transfer-Encoding'):
            return self.send(400, {'error': 'Chunked requests are not supported.'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            length = 0
        if length <= 0 or length > BODY_LIMIT:
            return self.send(413, {'error': 'Request exceeds upload limits or has no valid Content-Length.'})
        if not CAPACITY.acquire(blocking=False):
            return self.send(429, {'error': 'Three scans are already queued or running. Try again later.'})
        submitted = False
        try:
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict):
                raise ValueError('Request must be an object.')
            project = payload.get('project', '').strip()
            if not project or len(project) > 100 or any(ord(c) < 32 for c in project):
                raise ValueError('Project name must be 1–100 printable characters.')
            version = payload.get('api_version', '64.0')
            if not isinstance(version, str) or not re.fullmatch(r'\d{2,3}\.0', version):
                raise ValueError('API version must be a value such as 64.0.')
            if not isinstance(payload.get('current'), str) or not payload['current']:
                raise ValueError('Current source ZIP is required.')
            if payload.get('baseline') is not None and not isinstance(payload['baseline'], str):
                raise ValueError('Baseline must be a base64 ZIP string.')
            payload = {k: payload.get(k) for k in ('current', 'baseline')}
            payload['api_version'] = version
            scan_id = secrets.token_hex(16)
            with connection() as con:
                con.execute('INSERT INTO scans VALUES (?,?,?,?,?)', (scan_id, project, datetime.now(timezone.utc).isoformat(), 'queued', '{}'))
            EXECUTOR.submit(worker, scan_id, payload)
            submitted = True
            self.send(202, {'id': scan_id})
        except (ValueError, TypeError, AttributeError):
            self.send(400, {'error': 'Invalid request. Check project name, API version, and base64 ZIP inputs.'})
        finally:
            if not submitted:
                CAPACITY.release()


class Server(ThreadingHTTPServer):
    daemon_threads = True
    # Bound request threads, including slow clients.
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
    server = Server(('0.0.0.0', 8080), Handler)
    print('AppScan listening on :8080', flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        EXECUTOR.shutdown(wait=True)


if __name__ == '__main__':
    main()
