"""Import bounded, caller-supplied SARIF without fetching artifacts or honoring suppressions."""
from pathlib import PurePosixPath
import re
from urllib.parse import unquote, urlsplit
from .quality import canonical


def engines(report):
    if report is None:return []
    if not isinstance(report,dict) or report.get('version')!='2.1.0' or not isinstance(report.get('runs'),list) or len(report['runs'])>50:
        raise ValueError('External report must be SARIF 2.1.0 with at most 50 runs.')
    names=[]
    for run in report['runs']:
        if not isinstance(run,dict) or not isinstance(run.get('tool'),dict) or not isinstance(run['tool'].get('driver'),dict):
            raise ValueError('SARIF runs must identify a tool driver.')
        name=run['tool']['driver'].get('name')
        if not isinstance(name,str) or not 1<=len(name)<=200:raise ValueError('Invalid SARIF tool name.')
        normalized='SARIF:'+(re.sub(r'[^A-Za-z0-9_.-]','_',name)[:60] or 'external')
        if normalized in names:raise ValueError('Duplicate or ambiguous normalized SARIF tool names.')
        names.append(normalized)
    return names


def parse(report,files):
    if report is None:return [],[]
    if not isinstance(report,dict) or report.get('version')!='2.1.0' or not isinstance(report.get('runs'),list) or len(report['runs'])>50:
        raise ValueError('External report must be SARIF 2.1.0 with at most 50 runs.')
    engines(report)
    findings=[];errors=[];count=0
    paths={}
    for path in files:paths.setdefault(canonical(path),[]).append(path)
    for run in report['runs']:
        name=run.get('tool',{}).get('driver',{}).get('name','external')
        tool=re.sub(r'[^A-Za-z0-9_.-]','_',str(name))[:60] or 'external'
        if any(i.get('executionSuccessful') is False for i in run.get('invocations',[])):
            errors.append({'message':f'Imported SARIF tool {tool} reported unsuccessful execution.'})
        results=run.get('results',[])
        if not isinstance(results,list):raise ValueError('SARIF results must be a list.')
        count+=len(results)
        if count>10000:raise ValueError('SARIF import exceeds 10,000 findings.')
        for item in results:
            try:
                location=item['locations'][0]['physicalLocation']
                artifact=location['artifactLocation'];uri=unquote(artifact['uri'])
                if artifact.get('uriBaseId') or urlsplit(uri).scheme or uri.startswith(('/', '\\')) or '\\' in uri or '..' in PurePosixPath(uri).parts:
                    raise ValueError('Location must be repository-relative without a URI base.')
                path=uri[2:] if uri.startswith('./') else uri
                matches=[path] if path in files else paths.get(canonical(path),[])
                if len(matches)!=1:raise ValueError('Location does not identify one included source file.')
                path=matches[0];line=location.get('region',{}).get('startLine',1)
                if type(line) is not int or not 1<=line<=max(1,len(files[path].splitlines())):raise ValueError('Location line is outside the source file.')
                rule=str(item.get('ruleId','external'))
                if not re.fullmatch(r'[A-Za-z0-9_./:-]{1,100}',rule):raise ValueError('Invalid external rule identifier.')
                message=item['message'].get('text') or item['message'].get('markdown')
                if not isinstance(message,str) or not 1<=len(message)<=8000:raise ValueError('Invalid finding message.')
                severity={'error':'High','warning':'Medium','note':'Low','none':'Low'}.get(item.get('level','warning'))
                if severity is None:raise ValueError('Invalid finding level.')
                findings.append({'path':path,'line':line,'rule':f'External/{tool}/{rule}','engine':'SARIF:'+tool,'category':'External','severity':severity,'message':message})
            except (KeyError,IndexError,TypeError,AttributeError,ValueError) as exc:
                errors.append({'message':f'Invalid SARIF location/result from {tool}: {exc}'})
    return findings,errors
