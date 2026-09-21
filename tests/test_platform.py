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
import urllib.error
import urllib.request
import zipfile
from app import db, platform, quality, scanner, server
from app.coverage import parse_coverage

ADMIN = {'username':'admin', 'role':'admin'}
RISK_PATH = 'permissionsets/Broad.permissionset-meta.xml'
RISK_XML = '<PermissionSet><userPermissions><enabled>true</enabled><name>ModifyAllData</name></userPermissions></PermissionSet>'
SAFE_XML = '<PermissionSet><label>Safe</label></PermissionSet>'


def archive(text=RISK_XML):
    out=io.BytesIO()
    with zipfile.ZipFile(out,'w') as z:
        z.writestr(RISK_PATH,text)
    return base64.b64encode(out.getvalue()).decode()


class PolicyTests(unittest.TestCase):
    def test_unknown_policy_rejected(self):
        for v in [{'arbitrary':1}, {'categories':['../../other']}, {'min_coverage':float('nan')}, {'max_blockers':True}, {'cpd':'yes'}, {'severity_overrides':{'bad name':'High'}}]:
            with self.assertRaises(ValueError): quality.validate_policy(v)

    def test_missing_required_metrics_incomplete(self):
        result=scanner.scan({RISK_PATH:SAFE_XML.encode()},None,'64.0',{'min_coverage':80})
        self.assertEqual(result['gate'],'INCOMPLETE')
        self.assertEqual(result['quality_gate']['conditions'][-1]['status'],'MISSING')

    def test_coverage_gate(self):
        report={'files':[{'path':'A.cls','covered_lines':80,'uncovered_lines':20}]}
        r=scanner.scan({RISK_PATH:SAFE_XML.encode()},None,'64.0',{'min_coverage':80},report)
        self.assertEqual(r['gate'],'PASS')
        r=scanner.scan({RISK_PATH:SAFE_XML.encode()},None,'64.0',{'min_coverage':90},report)
        self.assertEqual(r['gate'],'FAIL')

    def test_invalid_coverage_rejected(self):
        for value in [{'files':[{'path':'A','covered_lines':-1,'uncovered_lines':0}]}, {'files':[{'path':'A','covered_lines':True,'uncovered_lines':0}]}, {'files':'bad'}]:
            with self.assertRaises(ValueError): quality.coverage_metrics(value)

    def test_lcov_conversion(self):
        r=parse_coverage('SF:classes/A.cls\nDA:1,2\nDA:2,0\nend_of_record\nSF:classes/A.cls\nDA:2,1\nend_of_record')
        self.assertEqual(r['files'][0]['covered_lines'],2)
        self.assertEqual(quality.coverage_metrics(r)['percent'],100)

    def test_salesforce_conversion(self):
        r=parse_coverage(json.dumps({'result':{'coverage':[{'name':'AccountService','numLinesCovered':8,'numLinesUncovered':2}]}}))
        self.assertEqual(quality.coverage_metrics(r)['percent'],80)

    def test_salesforce_duplicate_class_aggregation(self):
        r=parse_coverage(json.dumps({'result':{'coverage':[
            {'name':'AccountService','numLinesCovered':5,'numLinesUncovered':2},
            {'name':'AccountService','numLinesCovered':3,'numLinesUncovered':0},
        ]}}))
        self.assertEqual(len(r['files']),1)
        self.assertEqual(r['files'][0]['covered_lines'],8)
        self.assertEqual(r['files'][0]['uncovered_lines'],2)
        self.assertEqual(quality.coverage_metrics(r)['percent'],80)

    def test_none_line_number_safe(self):
        f={'rule':'BroadDataAccess','severity':'High','path':'classes/A.cls','line':None,'message':'Msg','engine':'Metadata','category':'Security'}
        p=quality.validate_policy({})
        enriched=quality.enrich([f],{'classes/A.cls':b'public class A {}'},p)
        self.assertEqual(len(enriched),1)
        s=quality.sarif({'findings':enriched})
        self.assertEqual(s['runs'][0]['results'][0]['locations'][0]['physicalLocation']['region']['startLine'],1)

    def test_new_scope_uploaded_baseline(self):
        r=scanner.scan({RISK_PATH:RISK_XML.encode()},{RISK_PATH:RISK_XML.encode()},'64.0',{'scope':'new'})
        self.assertEqual(r['gate'],'PASS')
        self.assertFalse(r['findings'][0]['is_new'])
        self.assertEqual(r['new_code_reference'],'uploaded_baseline')

    def test_fingerprint_survives_line_shift(self):
        a={'classes/A.cls':b'public class A {\nString password="long-secret-value";\n}'}
        b={'classes/A.cls':b'\n\npublic class A {\nString password="long-secret-value";\n}'}
        p=quality.validate_policy({})
        af=quality.enrich(scanner.metadata_checks(a)[0],a,p)
        bf=quality.enrich(scanner.metadata_checks(b)[0],b,p)
        self.assertEqual(af[0]['fingerprint'],bf[0]['fingerprint'])
        self.assertNotIn('long-secret-value',json.dumps(af))

    def test_profile_disabled_and_severity_override(self):
        r=scanner.scan({RISK_PATH:RISK_XML.encode()},None,'64.0',{'disabled_rules':['PrivilegedPermission']})
        self.assertEqual(r['findings'],[])
        r=scanner.scan({RISK_PATH:RISK_XML.encode()},None,'64.0',{'severity_overrides':{'PrivilegedPermission':'Low'}})
        self.assertEqual(r['findings'][0]['severity'],'Low')
        self.assertEqual(r['gate'],'PASS')

    def test_exclusion_does_not_remove_manifest(self):
        r=scanner.scan({RISK_PATH:RISK_XML.encode()},None,'64.0',{'exclusions':['permissionsets/*']})
        self.assertEqual(r['findings'],[])
        self.assertIn('Broad',r['package_xml'])

    def test_cpd_namespaced_xml(self):
        from types import SimpleNamespace
        def fake_run(args, **kwargs):
            source=Path(args[args.index('--dir')+1])
            xml=f'<pmd-cpd xmlns="https://pmd-code.org/schema/cpd-report"><duplication lines="2" tokens="120"><file path="{source}/classes/A.cls" line="1"/><file path="{source}/classes/B.cls" line="1"/></duplication></pmd-cpd>'
            kwargs['stdout'].write(xml.encode());kwargs['stdout'].flush()
            return SimpleNamespace(returncode=4)
        with patch.object(scanner,'find_pmd_binary',return_value='/mock/pmd'),patch.object(scanner.subprocess,'run',side_effect=fake_run):
            result=scanner.run_cpd({'classes/A.cls':b'a\nb','classes/B.cls':b'a\nb'})
        self.assertEqual(result['percent'],100)
        self.assertEqual(len(result['groups']),1)

    def test_sarif_valid_locations(self):
        r=scanner.scan({RISK_PATH:RISK_XML.encode()},None,'64.0')
        sarif=quality.sarif(r)
        self.assertEqual(sarif['version'],'2.1.0')
        self.assertEqual(sarif['runs'][0]['results'][0]['locations'][0]['physicalLocation']['region']['startLine'],1)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.old_data=db.DATA_DIR;db.DATA_DIR=Path(self.tmp.name)
        self.env=patch.dict(os.environ,{'DATABASE_URL':'','POSTGRES_URL':'','CENTRAL_PG_HOST':''});self.env.start()
        server.initialize();self.project=platform.ensure_project(ADMIN,'Test')

    def tearDown(self):
        self.env.stop();db.DATA_DIR=self.old_data;self.tmp.cleanup()

    def record_scan(self, text=RISK_XML, policy=None, branch='main', errors=False):
        p=quality.validate_policy(policy or {})
        result=scanner.scan({RISK_PATH:text.encode()},None,'64.0',p)
        if errors:result['errors'].append({'message':'fake parser error'})
        import secrets
        sid=secrets.token_hex(16)
        with db.get_db() as con:
            con.execute('INSERT INTO scans VALUES (?,?,?,?,?)',(sid,'Test',platform.now(),'running','{}'))
            con.execute('INSERT INTO scan_context VALUES (?,?,?,?,?,?,?)',(sid,self.project['id'],branch,'','','admin',json.dumps(p)))
            platform.apply_result(con,sid,result)
            con.execute("UPDATE scans SET status='complete',result=? WHERE id=?",(json.dumps(result),sid))
        return result

    def test_issue_lifecycle_and_review(self):
        first=self.record_scan();f=first['findings'][0]
        platform.change_issue(ADMIN,f['issue_id'],{'status':'safe','comment':'Reviewed intended administrative access.'})
        second=self.record_scan();self.assertEqual(second['gate'],'PASS');self.assertEqual(second['findings'][0]['issue_id'],f['issue_id']);self.assertFalse(second['findings'][0]['is_new'])
        self.record_scan(SAFE_XML)
        with db.get_db() as con:row=con.execute('SELECT status FROM issues WHERE id=?',(f['issue_id'],)).fetchone()
        self.assertEqual(row['status'],'fixed')
        again=self.record_scan();self.assertEqual(again['findings'][0]['status'],'open');self.assertTrue(again['findings'][0]['is_new'])

    def test_incomplete_does_not_close(self):
        f=self.record_scan()['findings'][0];self.record_scan(SAFE_XML,errors=True)
        with db.get_db() as con:row=con.execute('SELECT status FROM issues WHERE id=?',(f['issue_id'],)).fetchone()
        self.assertEqual(row['status'],'open')

    def test_incomplete_scan_does_not_establish_new_reference(self):
        self.record_scan(errors=True)
        successful=self.record_scan()
        self.assertTrue(successful['findings'][0]['is_new'])

    def test_excluded_issue_not_marked_fixed(self):
        f=self.record_scan()['findings'][0]
        for _ in range(2):self.record_scan(policy={'disabled_rules':['PrivilegedPermission']})
        with db.get_db() as con:row=con.execute('SELECT status FROM issues WHERE id=?',(f['issue_id'],)).fetchone()
        self.assertEqual(row['status'],'open')

    def test_branch_isolation(self):
        a=self.record_scan();b=self.record_scan(branch='uat')
        self.assertNotEqual(a['findings'][0]['issue_id'],b['findings'][0]['issue_id']);self.assertTrue(b['findings'][0]['is_new'])

    def test_review_requires_comment(self):
        iid=self.record_scan()['findings'][0]['issue_id']
        with self.assertRaises(ValueError):platform.change_issue(ADMIN,iid,{'status':'accepted'})

    def test_legacy_migration_idempotent(self):
        with db.get_db() as con:con.execute('INSERT INTO scans VALUES (?,?,?,?,?)',('legacy1','Old Project',platform.now(),'complete','{}'))
        platform.initialize();platform.initialize()
        with db.get_db() as con:r=con.execute('SELECT * FROM scan_context WHERE scan_id=?',('legacy1',)).fetchall()
        self.assertEqual(len(r),1)

    def test_user_hash_and_tokens(self):
        platform.manage_user('admin',{'username':'reader','password':'strong-reader-password','role':'viewer'},'admin')
        platform.save_project(ADMIN,self.project['id'],{'members':['reader'],'settings':{}})
        header='Basic '+base64.b64encode(b'reader:strong-reader-password').decode()
        user=platform.authenticate(header,'admin','admin-password')
        self.assertEqual(user['role'],'viewer')
        token=platform.create_token(user,{'project_id':self.project['id']})
        self.assertEqual(platform.authenticate('Bearer '+token['token'],'admin','admin-password')['token_scope'],'read')
        with self.assertRaises(PermissionError):platform.create_token(user,{'project_id':self.project['id'],'scope':'scan'})
        platform.manage_user('admin',{'username':'reader','role':'viewer','enabled':False},'admin')
        self.assertIsNone(platform.authenticate('Bearer '+token['token'],'admin','admin-password'))

    def test_direct_persistence_preserves_active_scan_and_context(self):
        from app.persistence import direct_scan
        with db.get_db() as con:con.execute('INSERT INTO scans VALUES (?,?,?,?,?)',('inflight','Test',platform.now(),'running','{}'))
        result=direct_scan({RISK_PATH:RISK_XML.encode()},None,'64.0',None,{'project':'Test','branch':'uat','revision':'abc'})
        self.assertEqual(result['gate'],'FAIL')
        with db.get_db() as con:
            active=con.execute('SELECT status FROM scans WHERE id=?',('inflight',)).fetchone()
            saved=con.execute("SELECT * FROM scan_context WHERE actor='local-cli'").fetchone()
        self.assertEqual(active['status'],'running')
        self.assertEqual(saved['branch'],'uat')

    def test_configured_postgres_never_silently_falls_back(self):
        with patch.dict(os.environ,{'DATABASE_URL':'postgresql://unavailable/db'}),patch.object(db,'HAVE_PSYCOPG2',False):
            with self.assertRaises(RuntimeError):
                with db.get_db():pass


class AccessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.old_data=db.DATA_DIR;db.DATA_DIR=Path(cls.tmp.name)
        cls.old_password=server.PASSWORD;server.PASSWORD='integration-password-1234'
        server.initialize()
        platform.manage_user('admin',{'username':'viewer','role':'viewer','password':'viewer-password-123456'},'admin')
        platform.manage_user('admin',{'username':'analyst','role':'analyst','password':'analyst-password-123456'},'admin')
        cls.project=platform.ensure_project(ADMIN,'Private')
        cls.other=platform.ensure_project(ADMIN,'Other')
        platform.save_project(ADMIN,cls.project['id'],{'settings':{},'members':['analyst']})
        cls.http=server.Server(('127.0.0.1',0),server.Handler)
        threading.Thread(target=cls.http.serve_forever,daemon=True).start()
        cls.url='http://127.0.0.1:'+str(cls.http.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.http.shutdown();cls.http.server_close();db.DATA_DIR=cls.old_data;server.PASSWORD=cls.old_password;cls.tmp.cleanup()

    def req(self,path,body=None,user='admin',token=None):
        pwd={'admin':'integration-password-1234','analyst':'analyst-password-123456','viewer':'viewer-password-123456'}[user]
        auth='Bearer '+token if token else 'Basic '+base64.b64encode((user+':'+pwd).encode()).decode()
        return urllib.request.urlopen(urllib.request.Request(self.url+path,data=json.dumps(body).encode() if body is not None else None,headers={'Authorization':auth,'Content-Type':'application/json'}),timeout=5)

    def test_project_visibility(self):
        self.assertEqual(json.load(self.req('/api/projects',user='viewer')),[])
        self.assertEqual(len(json.load(self.req('/api/projects',user='analyst'))),1)
        with self.assertRaises(urllib.error.HTTPError) as e:self.req('/api/issues?project_id='+self.project['id'],user='viewer')
        self.assertEqual(e.exception.code,403)

    def test_viewer_cannot_scan_or_admin(self):
        for path,body in [('/api/scans',{'project':'Private','current':archive()}),('/api/users',{'username':'hack'})]:
            with self.assertRaises(urllib.error.HTTPError) as e:self.req(path,body,user='viewer')
            self.assertEqual(e.exception.code,403)

    def test_token_scope_enforced(self):
        token=json.load(self.req('/api/tokens',{'project_id':self.project['id'],'scope':'read'}))['token']
        with self.assertRaises(urllib.error.HTTPError) as e:self.req('/api/scans',{'project':'Private','current':archive()},token=token)
        self.assertEqual(e.exception.code,403)
        with self.assertRaises(urllib.error.HTTPError) as e:self.req('/api/issues?project_id='+self.other['id'],token=token)
        self.assertEqual(e.exception.code,403)
        with self.assertRaises(urllib.error.HTTPError) as e:self.req('/api/users',token=token)
        self.assertEqual(e.exception.code,403)

    def test_source_storage_opt_in_and_access(self):
        platform.save_project(ADMIN,self.project['id'],{'settings':{'store_source':True},'members':['analyst']})
        out=io.BytesIO()
        with zipfile.ZipFile(out,'w') as z:z.writestr('lwc/demo/demo.js','export const greeting = "hello";')
        submitted=json.load(self.req('/api/scans',{'project':'Private','current':base64.b64encode(out.getvalue()).decode()}))
        for _ in range(100):
            scan=json.load(self.req('/api/scans/'+submitted['id']))
            if scan['status'] in {'complete','failed'}:break
            time.sleep(.02)
        self.assertEqual(scan['status'],'complete')
        endpoint='/api/scans/'+submitted['id']+'/source?path=lwc/demo/demo.js'
        self.assertIn('hello',json.load(self.req(endpoint,user='analyst'))['content'])
        with self.assertRaises(urllib.error.HTTPError) as e:self.req(endpoint,user='viewer')
        self.assertEqual(e.exception.code,403)

    def test_subpath_and_admin_audit(self):
        self.assertEqual(json.load(self.req('/appscan/api/me'))['username'],'admin')
        events=json.load(self.req('/api/audit'))
        self.assertTrue(any(e['action']=='project.create' for e in events))
        with self.req('/appscan/') as r:self.assertEqual(r.status,200)

    def test_team_routes_and_admin_restrictions(self):
        profile=json.load(self.req('/api/profiles',{'name':'HTTP shared','overrides':{'javascript':True}}))
        self.req('/api/projects/'+self.project['id']+'/profile',{'profile_id':profile['id']})
        self.assertTrue(next(p for p in json.load(self.req('/api/projects')) if p['id']==self.project['id'])['settings']['javascript'])
        self.req('/api/projects/'+self.project['id']+'/profile',{})
        platform.save_project(ADMIN,self.project['id'],{'settings':{},'members':['analyst']})
        self.assertTrue(json.load(self.req('/api/profiles')))
        group=json.load(self.req('/api/groups',{'name':'HTTP group','members':['analyst']}))
        self.req('/api/projects/'+self.project['id']+'/groups',{'groups':[group['id']]})
        self.assertTrue(json.load(self.req('/api/groups')))
        self.req('/api/portfolios',{'name':'HTTP portfolio','projects':[self.project['id']]})
        self.assertTrue(json.load(self.req('/api/portfolios',user='analyst')))
        self.assertIsInstance(json.load(self.req('/api/notifications')),list)
        page=json.load(self.req('/api/scans?page_size=1'))
        self.assertIn('next_cursor',page)
        self.assertIn('total',json.load(self.req('/api/issues?project_id='+self.project['id']+'&page_size=1')))
        plan=json.load(self.req('/api/projects/'+self.project['id']+'/retention',{}))
        self.assertEqual(plan['delete_scans'],[])
        for path in ['/api/profiles','/api/groups']:
            with self.assertRaises(urllib.error.HTTPError) as e:self.req(path,user='analyst')
            self.assertEqual(e.exception.code,403)
        with self.assertRaises(urllib.error.HTTPError) as e:self.req('/api/projects/'+self.project['id']+'/retention',{'apply':True,'plan_hash':'stale'})
        self.assertEqual(e.exception.code,400)

    def test_missing_project_id_returns_400(self):
        with self.assertRaises(urllib.error.HTTPError) as e:
            self.req('/api/issues')
        self.assertEqual(e.exception.code, 400)

    def test_redirect_preserves_query(self):
        class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
            def http_error_308(self, req, fp, code, msg, headers):
                return fp
        opener = urllib.request.build_opener(NoRedirectHandler)
        resp = opener.open(urllib.request.Request(self.url + '/appscan?branch=dev'))
        self.assertEqual(resp.headers.get('Location'), '/appscan/?branch=dev')


if __name__=='__main__':unittest.main()
