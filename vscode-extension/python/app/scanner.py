"""Local-only Salesforce source analysis. No uploaded code is ever executed."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile
import zipfile
import xml.etree.ElementTree as ET

MAX_ZIP = 20 * 1024 * 1024
MAX_EXPANDED = 100 * 1024 * 1024
MAX_FILE = 2 * 1024 * 1024
NS = 'http://soap.sforce.com/2006/04/metadata'
ET.register_namespace('', NS)
SIMPLE = {
 'classes': ('ApexClass', '.cls'), 'triggers': ('ApexTrigger', '.trigger'),
 'pages': ('ApexPage', '.page'), 'components': ('ApexComponent', '.component'),
 'flows': ('Flow', '.flow'), 'permissionsets': ('PermissionSet', '.permissionset'),
 'profiles': ('Profile', '.profile'), 'layouts': ('Layout', '.layout'),
 'tabs': ('CustomTab', '.tab'), 'applications': ('CustomApplication', '.app'),
 'customMetadata': ('CustomMetadata', '.md'), 'permissionsetgroups': ('PermissionSetGroup', '.permissionsetgroup'),
 'flexipages': ('FlexiPage', '.flexipage'), 'remoteSiteSettings': ('RemoteSiteSetting', '.remoteSite'),
 'namedCredentials': ('NamedCredential', '.namedCredential'),
 'externalCredentials': ('ExternalCredential', '.externalCredential'),
 'globalValueSets': ('GlobalValueSet', '.globalValueSet'),
 'standardValueSets': ('StandardValueSet', '.standardValueSet'),
 'staticresources': ('StaticResource', '.resource'),
}
CHILD = {'fields': ('CustomField', '.field'), 'validationRules': ('ValidationRule', '.validationRule'),
 'recordTypes': ('RecordType', '.recordType'), 'listViews': ('ListView', '.listView'),
 'fieldSets': ('FieldSet', '.fieldSet'), 'compactLayouts': ('CompactLayout', '.compactLayout'),
 'webLinks': ('WebLink', '.webLink'), 'businessProcesses': ('BusinessProcess', '.businessProcess'),
 'sharingReasons': ('SharingReason', '.sharingReason')}


def read_zip(encoded):
    try:
        raw = base64.b64decode(encoded, validate=True)
    except Exception as exc:
        raise ValueError('Invalid base64 ZIP data.') from exc
    if len(raw) > MAX_ZIP:
        raise ValueError('Each ZIP must be at most 20 MiB.')
    result, size = {}, 0
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            entries = z.infolist()
            if len(entries) > 10000:
                raise ValueError('Archive exceeds 10,000 entries.')
            for info in entries:
                p = PurePosixPath(info.filename)
                if p.is_absolute() or '..' in p.parts or '\\' in info.filename or ':' in info.filename:
                    raise ValueError('Unsafe archive path.')
                if stat.S_ISLNK(info.external_attr >> 16):
                    raise ValueError('Archive symlinks are not allowed.')
                if info.is_dir():
                    continue
                if not p.parts or any(x in {'.git', 'node_modules', '.sf', '.sfdx'} for x in p.parts):
                    continue
                size += info.file_size
                if info.file_size > MAX_FILE or size > MAX_EXPANDED:
                    raise ValueError('Archive exceeds expanded size limits (2 MiB/file, 100 MiB total).')
                name = p.as_posix()
                if name in result:
                    raise ValueError('Duplicate archive paths are not allowed.')
                result[name] = z.read(info)
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError) as exc:
        raise ValueError('Invalid, encrypted, or unsupported ZIP archive.') from exc
    if not result:
        raise ValueError('Archive is empty.')
    return result


def component(path):
    parts = PurePosixPath(path).parts
    for i, folder in enumerate(parts[:-1]):
        tail = parts[i+1:]
        if folder in {'lwc', 'aura'} and len(tail) >= 2:
            return ('LightningComponentBundle' if folder == 'lwc' else 'AuraDefinitionBundle', tail[0])
        if folder == 'objects':
            if len(tail) == 1 and tail[0].endswith('.object'):
                return ('CustomObject', tail[0][:-7])
            if len(tail) == 2 and tail[1] == tail[0] + '.object-meta.xml':
                return ('CustomObject', tail[0])
            if len(tail) == 3 and tail[1] in CHILD:
                typ, suffix = CHILD[tail[1]]
                if tail[2].endswith(suffix + '-meta.xml'):
                    return typ, tail[0] + '.' + tail[2][:-len(suffix + '-meta.xml')]
        if folder in SIMPLE:
            typ, suffix = SIMPLE[folder]
            filename = tail[0]
            if folder == 'staticresources' and len(tail) > 1:
                return typ, filename
            if len(tail) == 1:
                for ext in (suffix + '-meta.xml', suffix):
                    if filename.endswith(ext):
                        return typ, filename[:-len(ext)]
    return None


def inventory(files):
    groups, unsupported = {}, []
    for path, data in files.items():
        key = component(path)
        if key:
            # Root folders differ between git archive snapshots; member-relative names stay stable.
            parts = PurePosixPath(path).parts
            index = next(i for i, x in enumerate(parts) if x in SIMPLE or x in {'objects', 'lwc', 'aura'})
            relative = '/'.join(parts[index:])
            bucket = groups.setdefault(key, {})
            if relative in bucket:
                raise ValueError('Duplicate metadata component across package directories: ' + key[1])
            bucket[relative] = hashlib.sha256(data).hexdigest()
        elif path.endswith(('.xml', '.cls', '.trigger', '.js', '.html', '.css')) and not path.endswith('package.xml'):
            unsupported.append(path)
    return groups, unsupported


def changes(current, baseline):
    new, unsupported = inventory(current)
    old, old_unsupported = inventory(baseline or {})
    rows = []
    for key in sorted(new.keys() | old.keys()):
        status = 'added' if key not in old else 'deleted' if key not in new else 'modified' if new[key] != old[key] else 'unchanged'
        if status != 'unchanged':
            rows.append({'type': key[0], 'member': key[1], 'status': status})
    return rows, sorted(set(unsupported + old_unsupported))


def manifest(rows, deleted, version):
    root = ET.Element('{%s}Package' % NS)
    grouped = {}
    for row in rows:
        if (row['status'] == 'deleted') == deleted:
            grouped.setdefault(row['type'], set()).add(row['member'])
    for typ, members in sorted(grouped.items()):
        node = ET.SubElement(root, '{%s}types' % NS)
        for member in sorted(members):
            ET.SubElement(node, '{%s}members' % NS).text = member
        ET.SubElement(node, '{%s}name' % NS).text = typ
    ET.SubElement(root, '{%s}version' % NS).text = version
    ET.indent(root)
    return ET.tostring(root, encoding='unicode', xml_declaration=True)


def finding(rule, severity, path, line, message, engine='Metadata', category='Security'):
    return dict(rule=rule, severity=severity, path=path, line=line, message=message, engine=engine, category=category)


def metadata_checks(files):
    findings, errors = [], []
    for path, raw in files.items():
        if not component(path):
            continue
        text = raw.decode('utf-8', errors='replace')
        if path.endswith(('.xml', '.profile', '.permissionset', '.remoteSite', '.flow')):
            try:
                if '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():
                    raise ValueError('DTD and entity declarations are not permitted.')
                root = ET.fromstring(text)
                for elem in root.iter():
                    tag = elem.tag.split('}')[-1]
                    val = (elem.text or '').strip()
                    if tag in {'modifyAllData', 'viewAllData', 'modifyAllRecords', 'viewAllRecords'} and val.lower() == 'true':
                        findings.append(finding('BroadDataAccess', 'High', path, 1, f'{tag} is enabled; confirm least-privilege access.'))
                    if tag == 'userPermissions':
                        fields = {c.tag.split('}')[-1]: (c.text or '').strip() for c in elem}
                        if fields.get('enabled', '').lower() == 'true' and fields.get('name') in {'ModifyAllData', 'ViewAllData', 'AuthorApex', 'ManageUsers', 'CustomizeApplication'}:
                            findings.append(finding('PrivilegedPermission', 'High', path, 1, fields['name'] + ' is enabled; review the assigned users.'))
                    if tag == 'disableProtocolSecurity' and val.lower() == 'true':
                        findings.append(finding('ProtocolSecurityDisabled', 'High', path, 1, 'Remote site protocol security is disabled.'))
                    if tag in {'url', 'endpoint'} and val.lower().startswith('http://'):
                        findings.append(finding('UnencryptedEndpoint', 'High', path, 1, 'Endpoint uses HTTP; configure HTTPS.'))
                    if tag == 'runInMode' and 'systemmode' in val.lower():
                        findings.append(finding('FlowSystemContext', 'Medium', path, 1, 'Flow runs in system context; review sharing and data access.'))
            except (ET.ParseError, ValueError) as exc:
                errors.append({'path': path, 'message': 'XML could not be checked: ' + str(exc)[:200]})
        if path.endswith(('.cls', '.trigger', '.js', '.xml')):
            for n, line in enumerate(text.splitlines(), 1):
                if re.search(r'(?i)\b(password|secret|api[_-]?key|access[_-]?token)\b\s*[:=]\s*[\'\"][^\'\"]{8,}[\'\"]', line):
                    findings.append(finding('PossibleHardcodedSecret', 'High', path, n, 'Possible hardcoded credential. Verify and rotate if genuine. Value withheld.', 'Heuristic'))
    return findings, errors


def parse_pmd(report, source):
    findings = []
    for f in report.get('files', []):
        try:
            path = Path(f['filename']).relative_to(source).as_posix()
        except ValueError:
            path = Path(f['filename']).name
        for v in f.get('violations', []):
            security = v.get('ruleset', '').lower() == 'security'
            priority = int(v.get('priority', 3))
            severity = 'Critical' if priority == 1 else 'High' if security or priority == 2 else 'Medium' if priority == 3 else 'Low'
            findings.append(finding(v['rule'], severity, path, v.get('beginline', 1), v.get('description', 'Review this finding.'), 'PMD', 'Security' if security else 'Quality'))
    errors = report.get('processingErrors', []) + report.get('configurationErrors', [])
    return findings, errors


def find_pmd_binary():
    env_bin = os.environ.get('PMD_BIN')
    if env_bin and Path(env_bin).is_file():
        return env_bin
    candidates = [
        Path(__file__).resolve().parent.parent / 'pmd' / 'bin' / 'pmd.bat',
        Path(__file__).resolve().parent.parent / 'pmd' / 'bin' / 'pmd',
        Path(__file__).resolve().parent.parent.parent / 'pmd' / 'bin' / 'pmd.bat',
        Path('D:/Linux Server/AppScan/pmd/bin/pmd.bat'),
        Path('C:/pmd/bin/pmd.bat'),
        Path('/opt/pmd/bin/pmd')
    ]
    for c in candidates:
        if c.is_file():
            return str(c)
    import shutil
    return shutil.which('pmd') or shutil.which('pmd.bat')


def run_pmd(files):
    apex = {p: b for p, b in files.items() if p.endswith(('.cls', '.trigger'))}
    if not apex:
        return [], [], 'not_applicable'
    binary = find_pmd_binary()
    if not binary:
        return [], [{'message': 'PMD is unavailable. Apex analysis was not performed.'}], 'unavailable'
    with tempfile.TemporaryDirectory(prefix='appscan-') as td:
        root = Path(td)
        source = root / 'source'
        source.mkdir()
        for path, raw in apex.items():
            target = source / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        output = root / 'report.json'
        try:
            proc = subprocess.run([binary, 'check', '-d', str(source), '-R', str(Path(__file__).with_name('ruleset.xml')),
                '-f', 'json', '-r', str(output), '--no-cache', '--threads', '2'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=180, check=False, shell=(os.name == 'nt'))
            if proc.returncode not in {0, 4}:
                return [], [{'message': f'PMD exited with code {proc.returncode}; scan is incomplete.'}], 'error'
            report = json.loads(output.read_text())
            results, errors = parse_pmd(report, source)
            # PMD errors can quote source text: keep persisted errors generic.
            safe_errors = [{'message': 'PMD processing/configuration error. Check Apex syntax and the ruleset.'} for _ in errors]
            return results, safe_errors, 'complete' if not errors else 'error'
        except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
            return [], [{'message': 'PMD did not complete: ' + type(exc).__name__}], 'error'


def scan(current, baseline, version):
    rows, unsupported = changes(current, baseline)
    if not inventory(current)[0]:
        raise ValueError('No supported Salesforce components found in current ZIP.')
    findings, errors = metadata_checks(current)
    apex_findings, apex_errors, engine = run_pmd(current)
    findings += apex_findings
    errors += apex_errors
    rank = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
    findings.sort(key=lambda x: (rank[x['severity']], x['path'], x['line']))
    incomplete = bool(errors)
    gate = 'INCOMPLETE' if incomplete else 'FAIL' if any(f['severity'] in {'Critical', 'High'} for f in findings) else 'PASS'
    warnings = []
    if baseline is None:
        warnings.append('No baseline supplied: all supported components are listed as added; deletions cannot be detected.')
    if unsupported:
        warnings.append('Some files have no supported metadata mapping. Manifests are partial; review unsupported files.')
    warnings.append('Manifests require deployment review and org validation. They do not contain source payloads or resolve dependencies.')
    return dict(gate=gate, pmd=engine, findings=findings, errors=errors, changes=rows, unsupported=unsupported,
        warnings=warnings, files=len(current), components=len(inventory(current)[0]),
        comparison='baseline' if baseline is not None else 'inventory', api_version=version,
        package_xml=manifest(rows, False, version), destructive_xml=manifest(rows, True, version))
