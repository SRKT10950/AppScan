"""Changed executable-line coverage from an uploaded baseline and explicit line hits."""
import difflib
from .quality import canonical


def measure(current,baseline,report):
    missing={'percent':None,'status':'unavailable','covered_lines':0,'uncovered_lines':0}
    if baseline is None or report is None:return dict(missing,reason='Upload a baseline and line-level coverage.')
    before={};coverage={}
    for path,data in baseline.items():before.setdefault(canonical(path),[]).append(data)
    for row in report['files']:coverage.setdefault(canonical(row['path']),[]).append(row)
    keys=[canonical(p) for p in current if p.endswith(('.cls','.trigger','.js','.ts'))]
    if len(keys)!=len(set(keys)):return dict(missing,reason='Ambiguous current source paths.')
    covered=uncovered=0;unreported=[]
    for path,data in current.items():
        if not path.endswith(('.cls','.trigger','.js','.ts')):continue
        key=canonical(path);old=before.get(key,[])
        if len(old)>1:return dict(missing,reason='Ambiguous baseline paths.')
        if old and old[0]==data:continue
        rows=coverage.get(key,[])
        if len(rows)!=1 or 'line_hits' not in rows[0]:unreported.append(path);continue
        lines=data.decode('utf-8',errors='replace').splitlines()
        changed=set()
        for tag,_,__,a,b in difflib.SequenceMatcher(None,old[0].decode('utf-8',errors='replace').splitlines() if old else [],lines,autojunk=False).get_opcodes():
            if tag in {'replace','insert'}:changed.update(range(a+1,b+1))
        for number,hits in rows[0]['line_hits'].items():
            number=int(number)
            if number>len(lines):return dict(missing,reason='Coverage line is outside uploaded source.')
            if number in changed:
                covered+=hits>0;uncovered+=hits==0
    if unreported:return dict(missing,reason='Changed files lack unambiguous line-level coverage.',missing_files=unreported)
    total=covered+uncovered
    return {'percent':round(covered*100/total,2) if total else None,'status':'measured' if total else 'no_changed_executable_lines','covered_lines':covered,'uncovered_lines':uncovered}
