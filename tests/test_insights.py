import csv
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import tempfile
import unittest
from unittest.mock import patch
from app import db, insights, platform, quality, scanner, server, visualforce
from app.external import engines

ADMIN={'username':'admin','role':'admin'}
SOURCE={'lwc/x/x.js':b'const x = 1;'}


def sarif(path='lwc/x/x.js',tool='Sample'):
    return {'version':'2.1.0','runs':[{'tool':{'driver':{'name':tool}},'results':[{'ruleId':'Rule','level':'error','message':{'text':'Review input'},'locations':[{'physicalLocation':{'artifactLocation':{'uri':path},'region':{'startLine':1}}}]}]}]}


class InsightsTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.old=db.DATA_DIR;db.DATA_DIR=Path(self.tmp.name)
        self.env=patch.dict(os.environ,{'DATABASE_URL':'','POSTGRES_URL':'','CENTRAL_PG_HOST':''});self.env.start()
        server.initialize();self.project=platform.ensure_project(ADMIN,'Insights')
    def tearDown(self):
        self.env.stop();db.DATA_DIR=self.old;self.tmp.cleanup()
    def event(self,created='2026-01-02T12:00:00+00:00',actor='reviewer',action='test.event',target='test'):
        iid=secrets.token_hex(16)
        with db.get_db() as con:con.execute('INSERT INTO audit_events VALUES (?,?,?,?,?,?)',(iid,actor,action,target,created,json.dumps({'message':'<script>not executable</script>'})))
        return iid
    def test_audit_snapshot_tied_timestamps_and_new_writes(self):
        ids={self.event() for _ in range(3)};q={'action':'test.event','page_size':1}
        first=insights.audit_page(ADMIN,q);seen={r['id'] for r in first['items']}
        newer=self.event('2026-02-01T00:00:00+00:00')
        while first['next_cursor']:
            first=insights.audit_page(ADMIN,dict(q,cursor=first['next_cursor']));seen.update(r['id'] for r in first['items'])
            self.assertEqual(first['total'],3)
        self.assertEqual(seen,ids);self.assertNotIn(newer,seen)
    def test_audit_filters_and_date_boundaries(self):
        keep=self.event('2026-01-02T23:59:59+00:00')
        self.event('2026-01-03T00:00:00+00:00');self.event(actor='other')
        page=insights.audit_page(ADMIN,{'actor':'reviewer','action':'test.event','since':'2026-01-02','until':'2026-01-02'})
        self.assertEqual([r['id'] for r in page['items']],[keep])
        for q in [{'since':'bad'}, {'until':'9999-12-31'}, {'since':'2026-02-01','until':'2026-01-01'}]:
            with self.assertRaises(ValueError):insights.audit_page(ADMIN,q)
    def test_bad_cursor_and_changed_filters(self):
        self.event();self.event();page=insights.audit_page(ADMIN,{'action':'test.event','page_size':1})
        for q in [{'cursor':'bad=='},{'cursor':insights.encode([])},{'cursor':page['next_cursor'],'action':'other'}]:
            with self.assertRaises(ValueError):insights.audit_page(ADMIN,q)
    def test_audit_requires_admin_password(self):
        for user in [{'username':'viewer','role':'viewer'},dict(ADMIN,token_scope='read')]:
            with self.assertRaises(PermissionError):insights.audit_page(user,{})
            with self.assertRaises(PermissionError):insights.audit_export(user,{})
    def test_audit_export_all_pages_and_event(self):
        for _ in range(205):self.event()
        body,kind,name=insights.audit_export(ADMIN,{'action':'test.event','format':'json'})
        value=json.loads(body);self.assertEqual(value['count'],205);self.assertEqual(len({r['id'] for r in value['events']}),205)
        self.assertEqual(name,'appscan-audit.json');self.assertEqual(kind,'application/json')
        self.assertEqual(insights.audit_page(ADMIN,{'action':'audit.export'})['total'],1)
    def test_csv_formula_safety_and_export_limits(self):
        self.event(actor='=1+1',target='  @SUM(1,2)')
        body,_,_=insights.audit_export(ADMIN,{'action':'test.event','format':'csv'})
        row=list(csv.DictReader(io.StringIO(body.decode('utf-8-sig'))))[0]
        self.assertEqual(row['actor'],"'=1+1");self.assertEqual(row['target'],"'  @SUM(1,2)")
        with patch.object(insights,'EXPORT_ROWS',0):
            with self.assertRaises(ValueError):insights.audit_export(ADMIN,{'action':'test.event'})
        with patch.object(insights,'EXPORT_BYTES',20):
            with self.assertRaises(ValueError):insights.audit_export(ADMIN,{'action':'test.event'})
        with self.assertRaises(ValueError):insights.audit_export(ADMIN,{'format':'html'})
    def saved_scan(self,created,branch='main',pr='',status='complete',policy=None):
        sid=secrets.token_hex(16)
        report={'gate':'PASS','findings':[],'metrics':{'new_findings':0},'coverage':{'percent':80},'new_coverage':None,'duplication':{'percent':0}}
        with db.get_db() as con:
            con.execute('INSERT INTO scans VALUES (?,?,?,?,?)',(sid,'Insights',created,status,json.dumps(report)))
            con.execute('INSERT INTO scan_context VALUES (?,?,?,?,?,?,?)',(sid,self.project['id'],branch,pr,'rev','admin',json.dumps(policy or quality.DEFAULT_POLICY)))
        return sid
    def test_trends_scope_order_missing_and_policy_change(self):
        a=self.saved_scan('2026-01-01T00:00:00+00:00')
        b=self.saved_scan('2026-01-02T00:00:00+00:00',status='failed',policy={'max_blockers':3})
        self.saved_scan('2026-01-03T00:00:00+00:00',branch='other');self.saved_scan('2026-01-03T00:00:00+00:00',pr='9');self.saved_scan('2026-01-03T00:00:00+00:00',status='running')
        r=insights.trends(ADMIN,self.project['id'],{})
        self.assertEqual([x['id'] for x in r['items']],[a,b]);self.assertEqual(r['total'],2)
        self.assertIsNone(r['items'][1]['coverage']);self.assertIsNone(r['items'][1]['gate']);self.assertTrue(r['items'][1]['policy_changed'])
        self.assertIsNone(r['items'][0]['new_coverage'])
        page=insights.trends(ADMIN,self.project['id'],{'page_size':1});self.assertTrue(page['truncated']);self.assertEqual(page['items'][0]['id'],b)
        self.assertEqual(insights.trends(ADMIN,self.project['id'],{'pull_request':'9'})['total'],1)
        self.assertEqual(insights.trends(ADMIN,self.project['id'],{'until':'2026-01-01'})['total'],1)
    def test_legacy_report_without_measures_is_not_zero(self):
        sid=self.saved_scan('2026-01-01T00:00:00+00:00')
        with db.get_db() as con:con.execute('UPDATE scans SET result=? WHERE id=?',('{}',sid))
        point=insights.trends(ADMIN,self.project['id'],{})['items'][0]
        self.assertIsNone(point['findings']);self.assertIsNone(point['coverage'])

    def test_trends_access_and_scoped_token(self):
        with self.assertRaises(PermissionError):insights.trends({'username':'viewer','role':'viewer'},self.project['id'],{})
        with self.assertRaises(PermissionError):insights.trends(dict(ADMIN,token_scope='read',token_project='other'),self.project['id'],{})
        self.assertEqual(insights.trends(dict(ADMIN,token_scope='read',token_project=self.project['id']),self.project['id'],{})['items'],[])


class AnalysisOperationsTests(unittest.TestCase):
    def test_baseline_sarif_changes_and_line_shift(self):
        before=sarif();current=sarif();current['runs'][0]['results'][0]['locations'][0]['physicalLocation']['region']['startLine']=2
        result=scanner.scan({'lwc/x/x.js':b'\nconst x = 1;'},SOURCE,'64.0',{'scope':'new'},external=current,baseline_external=before)
        self.assertEqual(result['gate'],'PASS');self.assertFalse(result['findings'][0]['is_new'])
        current['runs'][0]['results'][0]['message']['text']='A new issue'
        self.assertEqual(scanner.scan(SOURCE,SOURCE,'64.0',{'scope':'new'},external=current,baseline_external=before)['gate'],'INCOMPLETE')  # line 2 is out of range
        current['runs'][0]['results'][0]['locations'][0]['physicalLocation']['region']['startLine']=1
        result=scanner.scan(SOURCE,SOURCE,'64.0',{'scope':'new'},external=current,baseline_external=before)
        self.assertEqual(result['gate'],'FAIL');self.assertTrue(result['findings'][0]['is_new'])
    def test_missing_or_broken_baseline_never_suppresses(self):
        with self.assertRaises(ValueError):scanner.scan(SOURCE,None,'64.0',external=sarif(),baseline_external=sarif())
        with self.assertRaises(ValueError):scanner.scan(SOURCE,SOURCE,'64.0',baseline_external=sarif())
        r=scanner.scan(SOURCE,SOURCE,'64.0',{'scope':'new'},external=sarif());self.assertEqual(r['gate'],'FAIL')
        broken=sarif();broken['runs'][0]['invocations']=[{'executionSuccessful':False}]
        self.assertEqual(scanner.scan(SOURCE,SOURCE,'64.0',{'scope':'new'},external=sarif(),baseline_external=broken)['gate'],'INCOMPLETE')
        self.assertEqual(scanner.scan(SOURCE,SOURCE,'64.0',{'scope':'new'},external=sarif(),baseline_external=sarif(tool='Different'))['gate'],'INCOMPLETE')
    def test_ambiguous_sarif_tools_rejected(self):
        report=sarif(tool='A B');report['runs']+=sarif(tool='A_B')['runs']
        with self.assertRaises(ValueError):engines(report)
        with self.assertRaises(ValueError):engines({'version':'2.1.0','runs':[{}]})
    def test_visualforce_policy_and_failure(self):
        p=quality.validate_policy({})
        self.assertFalse(p['visualforce'])
        with self.assertRaises(ValueError):quality.validate_policy({'visualforce':'yes'})
        self.assertNotEqual(quality.analysis_signature(p),quality.analysis_signature(dict(p,visualforce=True)))
        with patch('app.scanner.find_pmd_binary',return_value=None):
            self.assertEqual(scanner.scan({'pages/A.page':b'<apex:page/>'},None,'64.0',{'visualforce':True})['gate'],'INCOMPLETE')
        self.assertEqual(visualforce.analyze(SOURCE,True)[2],'not_applicable')
    @unittest.skipUnless(os.environ.get('APPSCAN_TEST_PMD'),'Set APPSCAN_TEST_PMD for actual Visualforce integration')
    def test_real_visualforce_security_and_baseline(self):
        files={'pages/Risk.page':b'<apex:page controller="Ctrl" action="{!save}"><apex:outputText value="{!$CurrentPage.parameters.x}" escape="false" /></apex:page>',
               'components/Risk.component':b'<apex:component><apex:outputText value="{!$CurrentPage.parameters.x}" escape="false" /></apex:component>'}
        with patch.dict(os.environ,{'PMD_BIN':os.environ['APPSCAN_TEST_PMD']}):
            result=scanner.scan(files,files,'64.0',{'visualforce':True,'scope':'new'})
            self.assertFalse(result['errors']);self.assertEqual(result['visualforce'],'complete');self.assertEqual(result['gate'],'PASS')
            self.assertIn('VfCsrf',{f['rule'] for f in result['findings']})
            self.assertEqual({f['path'] for f in result['findings']},set(files))
            bad=scanner.scan({'pages/Risk.page':b'<apex:page><'},None,'64.0',{'visualforce':True})
            self.assertEqual(bad['gate'],'INCOMPLETE')
