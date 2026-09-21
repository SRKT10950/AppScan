"""Bounded audit navigation/export and authorized historical scan measures."""
import base64
import csv
from datetime import date, timedelta
import hashlib
import io
import json
import math
from .db import get_db
from . import governance, platform

EXPORT_ROWS = 10000
EXPORT_BYTES = 8 * 1024 * 1024


def text_filter(value):
    if not isinstance(value,str) or len(value)>200 or any(ord(c)<32 for c in value):
        raise ValueError('Invalid filter value.')
    return value.strip()


def date_filters(q):
    values={}
    for key in ('since','until'):
        value=q.get(key,'')
        if not value:continue
        try:
            parsed=date.fromisoformat(value)
            if parsed.isoformat()!=value:raise ValueError()
            values[key]=(parsed + timedelta(days=1) if key=='until' else parsed).isoformat()
        except (TypeError,ValueError,OverflowError):
            raise ValueError('Dates must use YYYY-MM-DD.') from None
    if values.get('since','')>=values.get('until','9999-12-31'):
        raise ValueError('Start date must not follow end date.')
    return values


def encode(value):
    return base64.urlsafe_b64encode(json.dumps(value,separators=(',',':')).encode()).decode()


def decode(value):
    try:
        if not isinstance(value,str) or len(value)>2000:raise ValueError()
        return json.loads(base64.b64decode(value,altchars=b'-_',validate=True))
    except (ValueError,TypeError,UnicodeDecodeError):
        raise ValueError('Invalid audit cursor.') from None


def pair(value):
    return isinstance(value,list) and len(value)==2 and all(isinstance(x,str) and 0<len(x)<=100 for x in value)


def audit_page(user,q):
    governance.admin(user)
    limit=governance.page_size(q,100)
    filters={k:text_filter(q.get(k,'')) for k in ('actor','action','target')}
    dates=date_filters(q)
    signature=hashlib.sha256(json.dumps([filters,dates],sort_keys=True).encode()).hexdigest()
    sql=' FROM audit_events WHERE 1=1';args=[]
    for key,value in filters.items():
        if value:sql+=' AND '+key+'=?';args.append(value)
    if 'since' in dates:sql+=' AND created>=?';args.append(dates['since'])
    if 'until' in dates:sql+=' AND created<?';args.append(dates['until'])
    cursor=decode(q['cursor']) if q.get('cursor') else None
    if cursor is not None and (not isinstance(cursor,dict) or cursor.get('filter')!=signature or not pair(cursor.get('upper')) or not pair(cursor.get('last'))):
        raise ValueError('Audit cursor does not match filters. Start a new page.')
    with get_db() as db:
        first=db.execute('SELECT created,id'+sql+' ORDER BY created DESC,id DESC LIMIT 1',args).fetchone() if cursor is None else None
        upper=cursor['upper'] if cursor else [first['created'],first['id']] if first else None
        if upper is None:return {'items':[],'total':0,'next_cursor':None,'snapshot':None}
        sql+=' AND (created<? OR (created=? AND id<=?))';args.extend([upper[0],upper[0],upper[1]])
        total=db.execute('SELECT COUNT(*) AS n'+sql,args).fetchone()['n']
        if cursor:
            last=cursor['last'];sql+=' AND (created<? OR (created=? AND id<?))';args.extend([last[0],last[0],last[1]])
        rows=db.execute('SELECT *'+sql+' ORDER BY created DESC,id DESC LIMIT ?',args+[limit+1]).fetchall()
    more=len(rows)>limit;rows=rows[:limit]
    next_cursor=encode({'filter':signature,'upper':upper,'last':[rows[-1]['created'],rows[-1]['id']]}) if more else None
    return {'items':rows,'total':total,'next_cursor':next_cursor,'snapshot':encode(upper)}


def csv_cell(value):
    value=str(value)
    # Spreadsheet exports must not interpret user-controlled values as formulas.
    return "'"+value if value.lstrip().startswith(('=','+','-','@')) or value.startswith(('\t','\r','\n')) else value


def audit_export(user,q):
    governance.admin(user)
    fmt=q.get('format','json')
    if fmt not in {'json','csv'}:raise ValueError('Export format must be json or csv.')
    query={k:v for k,v in q.items() if k not in {'cursor','page_size','format'}}
    query['page_size']=200
    rows=[];size=0;snapshot=None
    while True:
        page=audit_page(user,query)
        snapshot=snapshot or page['snapshot']
        if page['total']>EXPORT_ROWS:raise ValueError('Export exceeds 10,000 events. Narrow the date range or filters.')
        for row in page['items']:
            size+=len(json.dumps(row,ensure_ascii=True).encode())
            if size>EXPORT_BYTES:raise ValueError('Export exceeds 8 MiB. Narrow the date range or filters.')
            rows.append(row)
        if not page['next_cursor']:break
        query['cursor']=page['next_cursor']
    if fmt=='json':
        body=json.dumps({'snapshot':snapshot,'count':len(rows),'events':rows},ensure_ascii=True).encode()
        kind='application/json'
    else:
        stream=io.StringIO(newline='');writer=csv.writer(stream)
        fields=['id','created','actor','action','target','details'];writer.writerow(fields)
        for row in rows:writer.writerow([csv_cell(row[k]) for k in fields])
        body=stream.getvalue().encode('utf-8-sig');kind='text/csv; charset=utf-8'
    if len(body)>EXPORT_BYTES:raise ValueError('Export exceeds 8 MiB. Narrow the date range or filters.')
    with get_db() as db:platform.audit(db,user['username'],'audit.export',fmt,{'count':len(rows),'filters':{k:v for k,v in query.items() if k not in {'cursor','page_size'}}})
    return body,kind,'appscan-audit.'+fmt


def number(value,percent=False):
    if type(value) not in (int,float) or not math.isfinite(value) or value<0:return None
    if percent and value>100:return None
    return value


def trends(user,pid,q):
    platform.project_for(user,pid)
    branch=text_filter(q.get('branch') or 'main');pr=text_filter(q.get('pull_request',''))
    if pr and (not pr.isdigit() or len(pr)>32):raise ValueError('Invalid pull request identifier.')
    limit=governance.page_size(q,100);dates=date_filters(q)
    sql=" FROM scans s JOIN scan_context c ON c.scan_id=s.id WHERE c.project_id=? AND c.branch=? AND c.pull_request=? AND s.status IN ('complete','failed')"
    args=[pid,branch,pr]
    if 'since' in dates:sql+=' AND s.created>=?';args.append(dates['since'])
    if 'until' in dates:sql+=' AND s.created<?';args.append(dates['until'])
    items=[]
    with get_db() as db:
        total=db.execute('SELECT COUNT(*) AS n'+sql,args).fetchone()['n']
        refs=db.execute('SELECT s.id,s.created,s.status,c.revision,c.policy'+sql+' ORDER BY s.created DESC,s.id DESC LIMIT ?',args+[limit]).fetchall()
        previous_policy=None
        for row in reversed(refs):
            # Read one report at a time rather than loading all full reports at once.
            data=db.execute('SELECT result FROM scans WHERE id=?',(row['id'],)).fetchone()
            if not data:continue  # A concurrent authorized retention action removed it.
            report=json.loads(data['result'] or '{}')
            failed=row['status']=='failed'
            policy=json.loads(row.pop('policy'))
            row.update(gate=report.get('gate') if not failed else None,
                findings=len(report['findings']) if not failed and isinstance(report.get('findings'),list) else None,
                new_findings=number((report.get('metrics') or {}).get('new_findings')) if not failed else None,
                coverage=number((report.get('coverage') or {}).get('percent'),True) if not failed else None,
                new_coverage=number((report.get('new_coverage') or {}).get('percent'),True) if not failed else None,
                duplication=number((report.get('duplication') or {}).get('percent'),True) if not failed else None,
                policy_changed=previous_policy is not None and previous_policy!=policy)
            previous_policy=policy;items.append(row)
    return {'project_id':pid,'branch':branch,'pull_request':pr,'items':items,'total':total,'truncated':total>len(items)}
