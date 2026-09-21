"""Team administration, reusable policies, bounded queries and retention plans."""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
import secrets
from .db import get_db
from . import platform, quality


def admin(user):
    if user['role'] != 'admin' or 'token_scope' in user:
        raise PermissionError('Administrator password login required.')


def initialize():
    with get_db() as db:
        for sql in [
            'CREATE TABLE IF NOT EXISTS quality_profiles (id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, parent_id TEXT NOT NULL, overrides TEXT NOT NULL, updated TEXT NOT NULL)',
            'CREATE TABLE IF NOT EXISTS project_profiles (project_id TEXT PRIMARY KEY, profile_id TEXT NOT NULL, overrides TEXT NOT NULL)',
            'CREATE TABLE IF NOT EXISTS user_groups (id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL)',
            'CREATE TABLE IF NOT EXISTS group_members (group_id TEXT NOT NULL, username TEXT NOT NULL, PRIMARY KEY(group_id,username))',
            'CREATE TABLE IF NOT EXISTS project_groups (project_id TEXT NOT NULL, group_id TEXT NOT NULL, PRIMARY KEY(project_id,group_id))',
            'CREATE TABLE IF NOT EXISTS notifications (id TEXT PRIMARY KEY, username TEXT NOT NULL, project_id TEXT NOT NULL, created TEXT NOT NULL, message TEXT NOT NULL, target TEXT NOT NULL, seen INTEGER NOT NULL)',
            'CREATE TABLE IF NOT EXISTS portfolios (id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, projects TEXT NOT NULL)',
            'CREATE TABLE IF NOT EXISTS retention_policies (project_id TEXT PRIMARY KEY, days INTEGER NOT NULL, keep_count INTEGER NOT NULL, source_days INTEGER NOT NULL)',
            'CREATE TABLE IF NOT EXISTS issue_index (id TEXT PRIMARY KEY, kind TEXT NOT NULL, severity TEXT NOT NULL, search_text TEXT NOT NULL)',
            'CREATE INDEX IF NOT EXISTS notifications_user ON notifications(username,created)',
            'CREATE INDEX IF NOT EXISTS scans_created ON scans(created,id)',
        ]:
            db.execute(sql)
        for row in db.execute('SELECT i.id,i.finding FROM issues i LEFT JOIN issue_index x ON x.id=i.id WHERE x.id IS NULL').fetchall():
            index_issue(db,row['id'],json.loads(row['finding']))


def index_issue(db,iid,f):
    text=' '.join(str(f.get(k,'')) for k in ('rule','path','message','engine')).lower()
    db.execute('INSERT INTO issue_index VALUES (?,?,?,?) ON CONFLICT (id) DO UPDATE SET kind=excluded.kind,severity=excluded.severity,search_text=excluded.search_text', (iid,f.get('kind','code_smell'),f['severity'],text))


def group_access(user,pid):
    with get_db() as db:
        return bool(db.execute('SELECT g.group_id FROM group_members g JOIN project_groups p ON g.group_id=p.group_id WHERE p.project_id=? AND g.username=?', (pid,user['username'])).fetchone())


def profile_policy(pid, seen=None, db=None):
    if db is None:
        with get_db() as conn:return profile_policy(pid,seen,conn)
    seen=set(seen or ())
    if pid in seen or len(seen)>=8:
        raise ValueError('Profile inheritance cycle or depth greater than eight.')
    seen.add(pid)
    row=db.execute('SELECT * FROM quality_profiles WHERE id=?',(pid,)).fetchone()
    if not row:raise ValueError('Profile not found.')
    parent=profile_policy(row['parent_id'],seen,db) if row['parent_id'] else dict(quality.DEFAULT_POLICY)
    return quality.validate_policy(dict(parent,**json.loads(row['overrides'])))


def effective_policy(project, db=None):
    if db is None:
        with get_db() as conn:return effective_policy(project,conn)
    link=db.execute('SELECT * FROM project_profiles WHERE project_id=?',(project['id'],)).fetchone()
    if not link:return quality.validate_policy(json.loads(project['settings']))
    return quality.validate_policy(dict(profile_policy(link['profile_id'],db=db),**json.loads(link['overrides'])))


def save_profile(user,payload):
    admin(user)
    name=label(payload.get('name'))
    pid=identifier(payload.get('id') or secrets.token_hex(16))
    parent=payload.get('parent_id','')
    if parent:identifier(parent)
    overrides=payload.get('overrides',{})
    quality.validate_policy(overrides)
    with get_db() as db:
        unique_name(db,'quality_profiles',pid,name)
        db.execute('INSERT INTO quality_profiles VALUES (?,?,?,?,?) ON CONFLICT (id) DO UPDATE SET name=excluded.name,parent_id=excluded.parent_id,overrides=excluded.overrides,updated=excluded.updated', (pid,name,parent,json.dumps(overrides),platform.now()))
        # Validate every descendant as well as this node before committing a changed parent.
        for r in db.execute('SELECT id FROM quality_profiles').fetchall():profile_policy(r['id'],db=db)
        platform.audit(db,user['username'],'profile.save',pid,{'name':name,'parent_id':parent})
    return {'id':pid}


def list_profiles(user):
    admin(user)
    with get_db() as db:
        return [dict(r,overrides=json.loads(r['overrides']),effective=profile_policy(r['id'],db=db)) for r in db.execute('SELECT * FROM quality_profiles ORDER BY name').fetchall()]


def bind_profile(user,pid,payload):
    admin(user);project=platform.project_for(user,pid)
    profile=payload.get('profile_id','')
    overrides=payload.get('overrides',{})
    quality.validate_policy(overrides)
    with get_db() as db:
        if profile:
            quality.validate_policy(dict(profile_policy(profile,db=db),**overrides))
            db.execute('INSERT INTO project_profiles VALUES (?,?,?) ON CONFLICT (project_id) DO UPDATE SET profile_id=excluded.profile_id,overrides=excluded.overrides', (pid,profile,json.dumps(overrides)))
        else:
            current=effective_policy(project,db)
            db.execute('UPDATE projects SET settings=? WHERE id=?',(json.dumps(current),pid))
            db.execute('DELETE FROM project_profiles WHERE project_id=?',(pid,))
        platform.audit(db,user['username'],'project.profile',pid,{'profile_id':profile,'overrides':overrides})


def unique_name(db,table,record_id,name):
    # Table names are constants supplied only by the functions in this module.
    if db.execute('SELECT id FROM '+table+' WHERE name=? AND id<>?',(name,record_id)).fetchone():
        raise ValueError('Name already exists. Select the existing record to edit it.')


def identifier(value):
    if not isinstance(value,str) or not re.fullmatch(r'[a-f0-9]{32}',value):raise ValueError('Invalid record identifier.')
    return value


def label(value):
    if not isinstance(value,str) or not 1<=len(value.strip())<=100 or any(ord(c)<32 for c in value):
        raise ValueError('Name must contain 1–100 printable characters.')
    return value.strip()


def save_group(user,payload):
    admin(user);name=label(payload.get('name'));gid=identifier(payload.get('id') or secrets.token_hex(16))
    members=payload.get('members',[])
    if not isinstance(members,list) or len(members)>500 or any(not isinstance(x,str) for x in members):raise ValueError('Invalid group members.')
    with get_db() as db:
        known={r['username'] for r in db.execute('SELECT username FROM app_users WHERE enabled=1').fetchall()}
        if set(members)-known:raise ValueError('Members must be enabled local users.')
        unique_name(db,'user_groups',gid,name)
        db.execute('INSERT INTO user_groups VALUES (?,?) ON CONFLICT (id) DO UPDATE SET name=excluded.name',(gid,name))
        db.execute('DELETE FROM group_members WHERE group_id=?',(gid,))
        for member in sorted(set(members)):db.execute('INSERT INTO group_members VALUES (?,?)',(gid,member))
        platform.audit(db,user['username'],'group.save',gid,{'name':name,'members':members})
    return {'id':gid}


def bind_groups(user,pid,payload):
    admin(user);platform.project_for(user,pid)
    groups=payload.get('groups',[])
    if not isinstance(groups,list) or len(groups)>100 or any(not isinstance(x,str) for x in groups):raise ValueError('Invalid groups.')
    with get_db() as db:
        known={r['id'] for r in db.execute('SELECT id FROM user_groups').fetchall()}
        if set(groups)-known:raise ValueError('Unknown group.')
        db.execute('DELETE FROM project_groups WHERE project_id=?',(pid,))
        for gid in sorted(set(groups)):db.execute('INSERT INTO project_groups VALUES (?,?)',(pid,gid))
        platform.audit(db,user['username'],'project.groups',pid,{'groups':groups})


def notify(db,username,pid,message,target):
    db.execute('INSERT INTO notifications VALUES (?,?,?,?,?,?,?)',(secrets.token_hex(16),username,pid,platform.now(),message,target,0))


def notifications(user):
    with get_db() as db:rows=db.execute('SELECT * FROM notifications WHERE username=? ORDER BY created DESC LIMIT 100',(user['username'],)).fetchall()
    allowed={p['id'] for p in platform.list_projects(user)}
    return [r for r in rows if r['project_id'] in allowed]


def bulk_review(user,payload):
    ids=payload.get('ids',[])
    if not isinstance(ids,list) or not 1<=len(ids)<=100 or any(not isinstance(x,str) for x in ids) or len(ids)!=len(set(ids)):
        raise ValueError('Select 1–100 unique issues.')
    # One transaction. A failed permission/status check rolls back the entire batch.
    with platform.STATE_LOCK, get_db() as db:
        for iid in ids:platform.review_in_transaction(db,user,iid,payload)
        platform.audit(db,user['username'],'issues.bulk_review','batch',{'ids':ids})
    return {'updated':len(ids)}


def page_size(q,default=50):
    size=int(q.get('page_size',default))
    if not 1<=size<=200:raise ValueError('Page size must be 1–200.')
    return size


def issue_page(user,q):
    platform.project_for(user,q.get('project_id',''))
    limit=page_size(q)
    sql=' FROM issues i JOIN issue_index x ON i.id=x.id WHERE i.project_id=?'
    params=[q['project_id']]
    for key in ('branch','status','assignee'):
        if q.get(key):sql+=' AND i.'+key+'=?';params.append(q[key])
    for key in ('kind','severity'):
        if q.get(key):sql+=' AND x.'+key+'=?';params.append(q[key])
    if q.get('search'):
        text=q['search'].lower().replace('\\','\\\\').replace('%','\\%').replace('_','\\_')
        sql+=" AND x.search_text LIKE ? ESCAPE '\\'";params.append('%'+text+'%')
    with get_db() as db:
        total=db.execute('SELECT COUNT(*) AS n'+sql,params).fetchone()['n']
        if q.get('cursor'):sql+=' AND i.id>?';params.append(q['cursor'])
        rows=db.execute('SELECT i.*'+sql+' ORDER BY i.id LIMIT ?',params+[limit+1]).fetchall()
    more=len(rows)>limit;rows=rows[:limit]
    for row in rows:row['finding']=json.loads(row['finding'])
    return {'items':rows,'total':total,'next_cursor':rows[-1]['id'] if more else None}


def scan_page(user,q):
    ids=[p['id'] for p in platform.list_projects(user) if not q.get('project_id') or p['id']==q['project_id']]
    limit=page_size(q,100)
    if not ids:return {'items':[],'next_cursor':None}
    sql='SELECT s.*,c.project_id,c.branch,c.pull_request,c.revision FROM scans s JOIN scan_context c ON s.id=c.scan_id WHERE c.project_id IN ('+','.join('?' for _ in ids)+')'
    params=list(ids)
    if q.get('branch'):sql+=' AND c.branch=?';params.append(q['branch'])
    if q.get('cursor'):
        try:
            cursor=json.loads(base64.urlsafe_b64decode(q['cursor']).decode())
            if not isinstance(cursor,list) or len(cursor)!=2 or any(not isinstance(x,str) for x in cursor):raise ValueError()
        except Exception as exc:raise ValueError('Invalid scan cursor.') from exc
        sql+=' AND (s.created<? OR (s.created=? AND s.id<?))';params.extend([cursor[0],cursor[0],cursor[1]])
    with get_db() as db:rows=db.execute(sql+' ORDER BY s.created DESC,s.id DESC LIMIT ?',params+[limit+1]).fetchall()
    more=len(rows)>limit;rows=rows[:limit]
    cursor=base64.urlsafe_b64encode(json.dumps([rows[-1]['created'],rows[-1]['id']]).encode()).decode() if more else None
    for r in rows:
        report=json.loads(r.pop('result') or '{}')
        r.update(gate=report.get('gate'),count=len(report.get('findings',[])),metrics={k:v for k,v in (report.get('metrics') or {}).items() if k!='file_metrics'},coverage={'percent':(report.get('coverage') or {}).get('percent')},duplication={'percent':(report.get('duplication') or {}).get('percent')})
    return {'items':rows,'next_cursor':cursor}


def save_portfolio(user,payload):
    admin(user);name=label(payload.get('name'));pid=identifier(payload.get('id') or secrets.token_hex(16))
    projects=payload.get('projects',[])
    if not isinstance(projects,list) or len(projects)>100 or any(not isinstance(p,str) for p in projects):raise ValueError('Invalid project list.')
    for project in projects:platform.project_for(user,project)
    with get_db() as db:
        unique_name(db,'portfolios',pid,name)
        db.execute('INSERT INTO portfolios VALUES (?,?,?) ON CONFLICT (id) DO UPDATE SET name=excluded.name,projects=excluded.projects',(pid,name,json.dumps(sorted(set(projects)))))
        platform.audit(db,user['username'],'portfolio.save',pid,{'name':name,'projects':projects})
    return {'id':pid}


def portfolios(user):
    visible={p['id']:p for p in platform.list_projects(user)}
    with get_db() as db:
        rows=db.execute('SELECT * FROM portfolios ORDER BY name').fetchall()
        result=[]
        for row in rows:
            ids=json.loads(row['projects'])
            # Hide a portfolio entirely when membership would disclose hidden projects.
            if any(pid not in visible for pid in ids):continue
            projects=[]
            for pid in ids:
                scan=db.execute("SELECT s.id,s.result,s.created FROM scans s JOIN scan_context c ON c.scan_id=s.id WHERE c.project_id=? AND c.pull_request='' AND s.status='complete' ORDER BY s.created DESC LIMIT 1",(pid,)).fetchone()
                report=json.loads(scan['result']) if scan else {}
                projects.append({'id':pid,'name':visible[pid]['name'],'gate':report.get('gate','NO_SCAN'),'findings':len(report.get('findings',[])),'created':scan['created'] if scan else None})
            result.append(dict(row,projects=projects,failures=sum(p['gate']=='FAIL' for p in projects),incomplete=sum(p['gate'] in {'INCOMPLETE','NO_SCAN'} for p in projects)))
    return result


def retention_policy(user,pid,payload):
    admin(user);platform.project_for(user,pid)
    days=payload.get('days',0);keep=payload.get('keep_count',10);source=payload.get('source_days',0)
    if any(type(x) is not int for x in (days,keep,source)) or not 0<=days<=3650 or not 1<=keep<=1000 or not 0<=source<=3650:
        raise ValueError('Retention days must be 0–3650, keep count 1–1000. Zero disables age cleanup.')
    with get_db() as db:
        db.execute('INSERT INTO retention_policies VALUES (?,?,?,?) ON CONFLICT (project_id) DO UPDATE SET days=excluded.days,keep_count=excluded.keep_count,source_days=excluded.source_days',(pid,days,keep,source))
        platform.audit(db,user['username'],'retention.policy',pid,payload)


def retention_plan(db,pid):
    policy=db.execute('SELECT * FROM retention_policies WHERE project_id=?',(pid,)).fetchone()
    if not policy:policy={'days':0,'keep_count':10,'source_days':0}
    rows=db.execute("SELECT s.id,s.created,s.status,c.branch,c.pull_request FROM scans s JOIN scan_context c ON c.scan_id=s.id WHERE c.project_id=? ORDER BY s.created DESC,s.id DESC",(pid,)).fetchall()
    refs=db.execute('SELECT first_seen,last_seen FROM issues WHERE project_id=?',(pid,)).fetchall()
    pinned={x for r in refs for x in (r['first_seen'],r['last_seen'])}
    counts={};delete=[];sources=[]
    cutoff=(datetime.now(timezone.utc)-timedelta(days=policy['days'])).isoformat()
    source_cutoff=(datetime.now(timezone.utc)-timedelta(days=policy['source_days'])).isoformat()
    for r in rows:
        if r['status'] not in {'complete','failed'}:continue
        key=(r['branch'],r['pull_request']);counts[key]=counts.get(key,0)+1
        if policy['days'] and r['created']<cutoff and counts[key]>policy['keep_count'] and r['id'] not in pinned:delete.append(r['id'])
        if policy['source_days'] and r['created']<source_cutoff:sources.append(r['id'])
    source_ids=[r['scan_id'] for r in db.execute('SELECT DISTINCT ss.scan_id FROM scan_sources ss JOIN scan_context c ON c.scan_id=ss.scan_id WHERE c.project_id=?',(pid,)).fetchall()]
    sources=sorted(set(sources)&set(source_ids))
    result={'project_id':pid,'delete_scans':sorted(delete),'purge_sources':sources,'policy':policy,'pinned_issue_scans':len(pinned)}
    result['plan_hash']=hashlib.sha256(json.dumps(result,sort_keys=True).encode()).hexdigest()
    return result


def retention(user,pid,payload):
    admin(user);platform.project_for(user,pid)
    with platform.STATE_LOCK, get_db() as db:
        plan=retention_plan(db,pid)
        if payload.get('apply'):
            if payload.get('plan_hash')!=plan['plan_hash']:raise ValueError('Retention plan changed. Preview again before applying.')
            for sid in plan['delete_scans']:
                db.execute('DELETE FROM scan_sources WHERE scan_id=?',(sid,))
                db.execute('DELETE FROM scan_context WHERE scan_id=?',(sid,))
                db.execute('DELETE FROM scans WHERE id=?',(sid,))
            for sid in plan['purge_sources']:db.execute('DELETE FROM scan_sources WHERE scan_id=?',(sid,))
            platform.audit(db,user['username'],'retention.apply',pid,{'deleted':len(plan['delete_scans']),'purged_sources':len(plan['purge_sources'])})
            return {'deleted':len(plan['delete_scans']),'purged_sources':len(plan['purge_sources'])}
        return plan


def scan_notifications(db,context,result):
    previous=db.execute("SELECT s.result FROM scans s JOIN scan_context c ON c.scan_id=s.id WHERE c.project_id=? AND c.branch=? AND c.pull_request=? AND s.status='complete' AND s.id<>? ORDER BY s.created DESC LIMIT 1",(context['project_id'],context['branch'],context['pull_request'],context['scan_id'])).fetchone()
    old_gate=json.loads(previous['result']).get('gate') if previous else None
    if old_gate==result['gate']:return
    project=db.execute('SELECT * FROM projects WHERE id=?',(context['project_id'],)).fetchone()
    recipients=set(json.loads(project['members'])) | {context['actor']}
    recipients.update(r['username'] for r in db.execute('SELECT gm.username FROM group_members gm JOIN project_groups pg ON gm.group_id=pg.group_id WHERE pg.project_id=?',(project['id'],)).fetchall())
    for username in recipients:
        notify(db,username,project['id'],f"{project['name']} / {context['branch']}: gate {old_gate or 'NO_SCAN'} → {result['gate']}",context['scan_id'])
