import base64
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import urllib.request
import urllib.error
import zipfile
from app import scanner, server, db


def archive(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        for name, content in files.items():
            z.writestr(name, content)
    return base64.b64encode(buf.getvalue()).decode()


class ScannerTests(unittest.TestCase):
    def test_archive_traversal(self):
        for path in ('../evil.cls', '/evil.cls', 'a\\evil.cls', 'C:/evil.cls'):
            with self.assertRaises(ValueError):
                scanner.read_zip(archive({path: 'x'}))

    def test_symlink(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as z:
            info = zipfile.ZipInfo('classes/Bad.cls')
            info.create_system = 3
            info.external_attr = 0o120777 << 16
            z.writestr(info, '/etc/passwd')
        with self.assertRaises(ValueError):
            scanner.read_zip(base64.b64encode(buf.getvalue()).decode())

    def test_large_file(self):
        with self.assertRaises(ValueError):
            scanner.read_zip(archive({'large': 'a' * (scanner.MAX_FILE + 1)}))

    def test_mapping_and_diff(self):
        old = {'old/force-app/main/default/classes/A.cls': b'a', 'old/force-app/main/default/classes/A.cls-meta.xml': b'm',
               'old/force-app/main/default/objects/Account/fields/Old__c.field-meta.xml': b'x'}
        new = {'new/force-app/main/default/classes/A.cls': b'b', 'new/force-app/main/default/classes/A.cls-meta.xml': b'm',
               'new/force-app/main/default/lwc/card/card.js': b'js', 'new/force-app/main/default/lwc/card/card.html': b'html'}
        rows, unsupported = scanner.changes(new, old)
        self.assertEqual({(r['type'], r['member'], r['status']) for r in rows}, {('ApexClass','A','modified'), ('CustomField','Account.Old__c','deleted'), ('LightningComponentBundle','card','added')})
        package = scanner.manifest(rows, False, '64.0')
        destructive = scanner.manifest(rows, True, '64.0')
        self.assertIn('<members>A</members>', package)
        self.assertNotIn('Old__c', package)
        self.assertIn('Account.Old__c', destructive)
        self.assertFalse(unsupported)

    def test_snapshot_prefix_does_not_change_component(self):
        rows, _ = scanner.changes({'repo-new/classes/A.cls':b'a'}, {'repo-old/classes/A.cls':b'a'})
        self.assertEqual(rows, [])

    def test_duplicate_packages_rejected(self):
        with self.assertRaises(ValueError):
            scanner.inventory({'one/classes/A.cls':b'a', 'two/classes/A.cls':b'b'})

    def test_xml_security_and_malformed(self):
        files = {'permissionsets/Test.permissionset-meta.xml': b'<PermissionSet><userPermissions><enabled>true</enabled><name>ModifyAllData</name></userPermissions></PermissionSet>',
                 'flows/Bad.flow-meta.xml': b'<Flow>'}
        findings, errors = scanner.metadata_checks(files)
        self.assertEqual(findings[0]['severity'], 'High')
        self.assertEqual(len(errors), 1)

    def test_entity_rejected(self):
        findings, errors = scanner.metadata_checks({'flows/Bad.flow-meta.xml': b'<!DOCTYPE x [<!ENTITY x "boom">]><Flow>&x;</Flow>'})
        self.assertTrue(errors)

    def test_secret_redacted(self):
        findings, _ = scanner.metadata_checks({'classes/Bad.cls': b'password = "secret-value-12345";'})
        self.assertEqual(findings[0]['rule'], 'PossibleHardcodedSecret')
        self.assertNotIn('secret-value', json.dumps(findings))

    def test_missing_pmd_not_pass(self):
        with patch.dict(os.environ, {'PMD_BIN': '/nonexistent'}):
            result = scanner.scan({'classes/A.cls': b'public class A {}'}, None, '64.0')
        self.assertEqual(result['gate'], 'INCOMPLETE')
        self.assertEqual(result['pmd'], 'unavailable')

    def test_metadata_only_pass(self):
        result = scanner.scan({'objects/Account/fields/X__c.field-meta.xml': b'<CustomField><fullName>X__c</fullName></CustomField>'}, None, '64.0')
        self.assertEqual(result['gate'], 'PASS')
        self.assertEqual(result['pmd'], 'not_applicable')

    def test_pmd_parser(self):
        findings, errors = scanner.parse_pmd({'files':[{'filename':'/tmp/src/classes/A.cls','violations':[{'rule':'ApexCRUDViolation','ruleset':'Security','priority':3,'beginline':2,'description':'Check CRUD'}]}]}, Path('/tmp/src'))
        self.assertEqual(findings[0]['severity'], 'High')
        self.assertEqual(findings[0]['path'], 'classes/A.cls')


class APITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.old_data = db.DATA_DIR
        db.DATA_DIR = Path(cls.tmp.name)
        server.PASSWORD = 'integration-password-1234'
        server.initialize()
        cls.http = server.Server(('127.0.0.1', 0), server.Handler)
        threading.Thread(target=cls.http.serve_forever, daemon=True).start()
        cls.url = 'http://127.0.0.1:' + str(cls.http.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.http.shutdown()
        cls.http.server_close()
        cls.tmp.cleanup()
        db.DATA_DIR = cls.old_data

    def request(self, path, data=None, auth=True):
        headers = {'Content-Type': 'application/json'}
        if auth:
            headers['Authorization'] = 'Basic ' + base64.b64encode(b'admin:integration-password-1234').decode()
        return urllib.request.urlopen(urllib.request.Request(self.url + path, data=json.dumps(data).encode() if data else None, headers=headers), timeout=10)

    def test_auth_required(self):
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.request('/api/scans', auth=False)
        self.assertEqual(error.exception.code, 401)

    def test_end_to_end(self):
        payload = {'project':'Test project', 'current':archive({'permissionsets/Admin.permissionset-meta.xml':'<PermissionSet><userPermissions><enabled>true</enabled><name>ModifyAllData</name></userPermissions></PermissionSet>'}), 'api_version':'64.0'}
        started = json.load(self.request('/api/scans', payload))
        for _ in range(100):
            record = json.load(self.request('/api/scans/' + started['id']))
            if record['status'] in {'complete', 'failed'}:
                break
            time.sleep(.02)
        self.assertEqual(record['status'], 'complete')
        self.assertEqual(record['result']['gate'], 'FAIL')
        report = self.request('/api/scans/' + started['id'] + '/report.zip').read()
        with zipfile.ZipFile(io.BytesIO(report)) as z:
            self.assertEqual(set(z.namelist()), {'report.json','report.md','report.sarif','package.xml','destructiveChanges.xml'})
        self.assertTrue(json.load(self.request('/api/scans')))

    def test_invalid_payload(self):
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.request('/api/scans', {'project':'', 'current':'wrong'})
        self.assertEqual(error.exception.code, 400)


if __name__ == '__main__':
    unittest.main()
