import json
import os
from pathlib import Path
import secrets
import tempfile
import unittest
from unittest.mock import patch
from app import db, server, platform, governance as g, quality, scanner, javascript
from app.coverage import parse_coverage
from app.new_coverage import measure
from app.external import parse

ADMIN={'username':'admin','role':'admin'}
ANALYST={'username':'analyst','role':'analyst'}
PATH='permissionsets/Broad.permissionset-meta.xml'
XML=b'<PermissionSet><userPermissions><enabled>true</enabled><name>ModifyAllData</name></userPermissions></PermissionSet>'

class GovernanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.old=db.DATA_DIR;db.DATA_DIR=Path(self.tmp.name)
        self.env=patch.dict(os.environ,{'DATABASE_URL':'','POSTGRES_URL':'','CENTRAL_PG_HOST':''});self.env.start()
        server.initialize();self.p=platform.ensure_project(ADMIN,'One');self.other=platform.ensure_project(ADMIN,'Two')
        with db.get_db() as con:con.execute('INSERT INTO app_users VALUES (?,?,?,?)',('analyst','unused','analyst',1))
    def tearDown(self):
        self.env.stop();db.DATA_DIR=self.old;self.tmp.cleanup()
    def record(self,source=None,external=None,created=None,status='complete'):
        sid=secrets.token_hex(16);policy=quality.validate_policy({})
        result=scanner.scan(source or {PATH:XML},None,'64.0',policy,external=external)
        with db.get_db() as con:
            con.execute('INSERT INTO scans VALUES (?,?,?,?,?)',(sid,'One',created or platform.now(),'running','{}'))
            con.execute('INSERT INTO scan_context VALUES (?,?,?,?,?,?,?)',(sid,self.p['id'],'main','','','admin',json.dumps(policy)))
            if status=='complete':platform.apply_result(con,sid,result)
            con.execute('UPDATE scans SET status=?,result=? WHERE id=?',(status,json.dumps(result),sid))
        return sid,result
    def test_profile_inheritance_overrides_and_cycle_rollback(self):
        parent=g.save_profile(ADMIN,{'name':'Base','overrides':{'max_blockers':5}})['id']
        child=g.save_profile(ADMIN,{'name':'Child','parent_id':parent,'overrides':{'cpd':True}})['id']
        g.bind_profile(ADMIN,self.p['id'],{'profile_id':child,'overrides':{'max_blockers':2}})
        self.assertEqual(g.effective_policy(self.p)['max_blockers'],2)
        self.assertTrue(g.effective_policy(self.p)['cpd'])
        with self.assertRaises(ValueError):g.save_profile(ADMIN,{'id':parent,'name':'Base','parent_id':child})
        self.assertEqual(g.profile_policy(parent)['max_blockers'],5)
        g.bind_profile(ADMIN,self.p['id'],{})
        self.assertEqual(g.effective_policy(platform.project_for(ADMIN,self.p['id']))['max_blockers'],2)
    def test_profile_edits_do_not_modify_scan_snapshot(self):
        profile=g.save_profile(ADMIN,{'name':'Shared'})['id'];g.bind_profile(ADMIN,self.p['id'],{'profile_id':profile})
        sid,_=self.record();g.save_profile(ADMIN,{'id':profile,'name':'Shared','overrides':{'max_blockers':100}})
        with db.get_db() as con:row=con.execute('SELECT policy FROM scan_context WHERE scan_id=?',(sid,)).fetchone()
        self.assertEqual(json.loads(row['policy'])['max_blockers'],0)
    def test_group_grant_revoke_and_token_scope(self):
        gid=g.save_group(ADMIN,{'name':'Developers','members':['analyst']})['id']
        self.assertFalse(platform.can_access(ANALYST,self.p))
        g.bind_groups(ADMIN,self.p['id'],{'groups':[gid]});self.assertTrue(platform.can_access(ANALYST,self.p,True))
        self.assertFalse(platform.can_access(dict(ANALYST,token_project=self.other['id'],token_scope='scan'),self.p))
        g.save_group(ADMIN,{'id':gid,'name':'Developers','members':[]});self.assertFalse(platform.can_access(ANALYST,self.p))
    def test_bulk_atomic_rollback(self):
        _,r=self.record();iid=r['findings'][0]['issue_id']
        with self.assertRaises(ValueError):g.bulk_review(ADMIN,{'ids':[iid,'missing'],'status':'accepted','comment':'reviewed'})
        with db.get_db() as con:
            self.assertEqual(con.execute('SELECT status FROM issues WHERE id=?',(iid,)).fetchone()['status'],'open')
            self.assertEqual(con.execute('SELECT COUNT(*) AS n FROM issue_comments').fetchone()['n'],0)
        self.assertEqual(g.bulk_review(ADMIN,{'ids':[iid],'status':'safe','comment':'reviewed'})['updated'],1)
    def test_viewer_and_token_review_denied(self):
        _,r=self.record();payload={'ids':[r['findings'][0]['issue_id']],'status':'accepted','comment':'reviewed'}
        for user in [dict(ADMIN,role='viewer'),dict(ADMIN,token_scope='scan')]:
            with self.assertRaises(PermissionError):g.bulk_review(user,payload)
    def test_issue_filter_before_pagination(self):
        self.record();pid=self.p['id']
        first=g.issue_page(ADMIN,{'project_id':pid,'page_size':1})
        self.assertGreater(first['total'],0)
        self.assertEqual(g.issue_page(ADMIN,{'project_id':pid,'search':'not_present'})['total'],0)
        self.assertEqual(g.issue_page(ADMIN,{'project_id':pid,'search':'%'})['total'],0)
        self.assertEqual(g.issue_page(ADMIN,{'project_id':pid,'severity':'High'})['items'][0]['finding']['severity'],'High')
    def test_scan_keyset_ties_no_duplicates(self):
        ids={self.record(created='2026-01-01T00:00:00+00:00')[0] for _ in range(3)}
        seen=set();cursor=''
        while True:
            page=g.scan_page(ADMIN,{'project_id':self.p['id'],'page_size':1,'cursor':cursor})
            seen.update(r['id'] for r in page['items']);cursor=page['next_cursor']
            if not cursor:break
        self.assertEqual(ids,seen)
        with self.assertRaises(ValueError):g.scan_page(ADMIN,{'cursor':'not-a-cursor'})
    def test_notification_and_portfolio_access_revocation(self):
        gid=g.save_group(ADMIN,{'name':'Developers','members':['analyst']})['id'];g.bind_groups(ADMIN,self.p['id'],{'groups':[gid]})
        self.record();self.assertTrue(g.notifications(ANALYST))
        g.save_portfolio(ADMIN,{'name':'Private','projects':[self.p['id'],self.other['id']]})
        self.assertEqual(g.portfolios(ANALYST),[])
        g.save_group(ADMIN,{'id':gid,'name':'Developers','members':[]});self.assertEqual(g.notifications(ANALYST),[])
    def test_retention_preview_pins_and_apply(self):
        pinned,_=self.record(created='2020-01-01T00:00:00+00:00')
        disposable,_=self.record(created='2020-01-02T00:00:00+00:00',status='failed')
        active,_=self.record(created='2020-01-03T00:00:00+00:00',status='running')
        recent,_=self.record(created='2020-01-04T00:00:00+00:00',status='failed')
        self.assertEqual(g.retention(ADMIN,self.p['id'],{})['delete_scans'],[])
        g.retention_policy(ADMIN,self.p['id'],{'days':30,'keep_count':1})
        plan=g.retention(ADMIN,self.p['id'],{});self.assertEqual(plan['delete_scans'],[disposable])
        with self.assertRaises(ValueError):g.retention(ADMIN,self.p['id'],{'apply':True,'plan_hash':'stale'})
        self.assertEqual(g.retention(ADMIN,self.p['id'],{'apply':True,'plan_hash':plan['plan_hash']})['deleted'],1)
        with db.get_db() as con:self.assertEqual({r['id'] for r in con.execute('SELECT id FROM scans').fetchall()},{pinned,active,recent})
    def test_missing_external_report_does_not_close_imported_issue(self):
        source={'lwc/x/x.js':b'const x = 1;'}
        report=sarif('lwc/x/x.js');_,r=self.record(source,report)
        iid=next(f['issue_id'] for f in r['findings'] if f['engine'].startswith('SARIF:'))
        self.record(source)
        with db.get_db() as con:self.assertEqual(con.execute('SELECT status FROM issues WHERE id=?',(iid,)).fetchone()['status'],'open')
        report['runs'][0]['results']=[];self.record(source,report)
        with db.get_db() as con:self.assertEqual(con.execute('SELECT status FROM issues WHERE id=?',(iid,)).fetchone()['status'],'fixed')


def sarif(path):
    return {'version':'2.1.0','runs':[{'tool':{'driver':{'name':'Sample'}},'results':[{'ruleId':'Rule','level':'error','message':{'text':'Review input'},'locations':[{'physicalLocation':{'artifactLocation':{'uri':path},'region':{'startLine':1}}}],'suppressions':[{'kind':'external'}]}]}]}

class AnalysisTests(unittest.TestCase):
    def test_legacy_analysis_signature_survives_upgrade(self):
        import hashlib
        p=quality.validate_policy({})
        legacy=hashlib.sha256(json.dumps({k:p[k] for k in ('categories','exclusions','disabled_rules')},sort_keys=True).encode()).hexdigest()
        self.assertEqual(quality.analysis_signature(p),legacy)
        self.assertNotEqual(quality.analysis_signature(dict(p,javascript=True)),legacy)

    def test_sarif_paths_and_suppressions(self):
        files={'lwc/x/x.js':b'eval(input);'}
        findings,errors=parse(sarif('lwc/x/x.js'),files);self.assertEqual(len(findings),1);self.assertFalse(errors)
        for path in ['../lwc/x/x.js','file:///lwc/x/x.js','%2e%2e/lwc/x/x.js','missing.js']:
            findings,errors=parse(sarif(path),files);self.assertFalse(findings);self.assertTrue(errors)
    def test_sarif_failure_and_invalid_line(self):
        r=sarif('lwc/x/x.js');r['runs'][0]['invocations']=[{'executionSuccessful':False}]
        self.assertTrue(parse(r,{'lwc/x/x.js':b'x'})[1])
        r['runs'][0]['results'][0]['locations'][0]['physicalLocation']['region']['startLine']=99
        self.assertFalse(parse(r,{'lwc/x/x.js':b'x'})[0])
    def test_changed_lines_coverage(self):
        before={'lwc/x/x.js':b'const a=1;\nconst b=2;'};current={'lwc/x/x.js':b'const a=1;\nconst b=3;\nconst c=4;'}
        report=parse_coverage('SF:lwc/x/x.js\nDA:1,3\nDA:2,1\nDA:3,0\nend_of_record')
        self.assertEqual(measure(current,before,report)['percent'],50)
        self.assertIsNone(measure(current,None,report)['percent'])
        self.assertEqual(measure(before,before,report)['status'],'no_changed_executable_lines')
    def test_changed_coverage_missing_or_ambiguous_never_passes(self):
        current={'lwc/x/x.js':b'x'};report={'files':[{'path':'lwc/x/x.js','covered_lines':1,'uncovered_lines':0}]}
        self.assertEqual(measure(current,{},report)['status'],'unavailable')
        self.assertEqual(measure(dict(current,**{'other/lwc/x/x.js':b'y'}),{},report)['status'],'unavailable')
        result=scanner.scan(current,{},'64.0',{'min_new_coverage':80},report)
        self.assertEqual(result['gate'],'INCOMPLETE')
    def test_invalid_line_hits_rejected(self):
        for hits in [{'0':1},{'1':True},{'1':0}]:
            with self.assertRaises(ValueError):quality.coverage_metrics({'files':[{'path':'x','covered_lines':1,'uncovered_lines':0,'line_hits':hits}]})
    def test_requested_missing_js_engine_incomplete(self):
        with patch.dict(os.environ,{'APPSCAN_JS_RUNNER':'/nonexistent/runner.mjs'}):
            r=scanner.scan({'lwc/x/x.js':b'eval(input);'},None,'64.0',{'javascript':True})
        self.assertEqual(r['gate'],'INCOMPLETE')
    @unittest.skipUnless(Path('analyzers/javascript/node_modules/eslint').exists(),'Install analyzer dependencies for real engine test')
    def test_real_eslint_lwc_and_inline_suppression(self):
        findings,errors=javascript.analyze({'lwc/x/x.js':b"import {LightningElement,api} from 'lwc';\nexport default class X extends LightningElement { @api value; run() { /* eslint-disable */ eval(this.value); } }",'eslint.config.js':b"throw new Error('repository config must never execute');"},True)
        self.assertFalse(errors);self.assertIn('ESLint/no-eval',[f['rule'] for f in findings])
        self.assertTrue(javascript.analyze({'lwc/x/x.js':b'export default class {'},True)[1])
