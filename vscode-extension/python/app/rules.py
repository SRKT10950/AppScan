"""Read the locally installed PMD rule definitions, with no network dependency."""
from functools import lru_cache
from pathlib import Path
import zipfile
import xml.etree.ElementTree as ET
from .scanner import find_pmd_binary
from .quality import CATEGORIES, HOTSPOTS


@lru_cache(maxsize=1)
def catalog():
    rules = []
    binary = find_pmd_binary()
    if binary:
        lib = Path(binary).resolve().parent.parent / 'lib'
        for jar in lib.glob('pmd-apex-*.jar'):
            with zipfile.ZipFile(jar) as z:
                for category in CATEGORIES:
                    name = 'category/apex/' + category + '.xml'
                    if name not in z.namelist():
                        continue
                    root = ET.fromstring(z.read(name))
                    for r in root:
                        if r.tag.split('}')[-1] != 'rule' or not r.get('name'):
                            continue
                        fields = {x.tag.split('}')[-1]: ''.join(x.itertext()).strip() for x in r}
                        rules.append({'name': r.get('name'), 'engine': 'PMD', 'category': category, 'description': fields.get('description', ''), 'priority': fields.get('priority', ''), 'example': fields.get('example', '')})
    pmd_available=bool(rules)
    visualforce_available=False
    if binary:
        for jar in (Path(binary).resolve().parent.parent/'lib').glob('pmd-visualforce-*.jar'):
            with zipfile.ZipFile(jar) as z:
                root=ET.fromstring(z.read('category/visualforce/security.xml'))
                for r in root:
                    if r.tag.split('}')[-1]!='rule' or not r.get('name'):continue
                    fields={x.tag.split('}')[-1]:''.join(x.itertext()).strip() for x in r}
                    rules.append({'name':r.get('name'),'engine':'PMD Visualforce (opt-in)','category':'security','description':fields.get('description',''),'priority':fields.get('priority',''),'example':fields.get('example','')})
                    visualforce_available=True
    descriptions = {
        'BroadDataAccess': 'Review view-all and modify-all permissions against least privilege.',
        'PrivilegedPermission': 'Review elevated user permissions and assignment scope.',
        'ProtocolSecurityDisabled': 'Enable remote site protocol security.',
        'UnencryptedEndpoint': 'Use HTTPS for the configured endpoint.',
        'FlowSystemContext': 'Review flow sharing and CRUD/FLS behavior in system context.',
        'PossibleHardcodedSecret': 'Verify the finding, revoke exposed credentials, and move secrets to protected configuration.',
    }
    rules += [{'name': key, 'engine': 'Metadata' if key != 'PossibleHardcodedSecret' else 'Heuristic', 'category': 'hotspot' if key in HOTSPOTS else 'security', 'description': value, 'priority': '', 'example': ''} for key, value in descriptions.items()]
    js_rules={'no-eval':'Disallow eval execution of strings.', 'no-implied-eval':'Disallow string arguments that imply eval.', 'no-new-func':'Disallow dynamically constructed functions.', 'no-script-url':'Disallow javascript: URLs.', 'no-unreachable':'Detect unreachable statements.', 'no-dupe-keys':'Detect duplicate object keys.', 'no-unsafe-finally':'Detect unsafe control flow in finally.', 'no-constant-condition':'Detect constant conditional expressions.', 'constructor-super':'Check superclass constructor calls.', 'valid-typeof':'Check typeof comparison values.', 'no-async-promise-executor':'Disallow async promise executors.', 'no-promise-executor-return':'Detect returned promise-executor values.', 'eqeqeq':'Require strict equality.'}
    rules += [{'name':'ESLint/'+key,'engine':'ESLint (opt-in)','category':'security' if key in {'no-eval','no-implied-eval','no-new-func','no-script-url'} else 'errorprone','description':value,'priority':'','example':''} for key,value in js_rules.items()]
    return {'rules': rules, 'pmd_catalog_available': pmd_available, 'visualforce_catalog_available':visualforce_available, 'categories': CATEGORIES}
