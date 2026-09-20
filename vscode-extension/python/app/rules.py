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
    descriptions = {
        'BroadDataAccess': 'Review view-all and modify-all permissions against least privilege.',
        'PrivilegedPermission': 'Review elevated user permissions and assignment scope.',
        'ProtocolSecurityDisabled': 'Enable remote site protocol security.',
        'UnencryptedEndpoint': 'Use HTTPS for the configured endpoint.',
        'FlowSystemContext': 'Review flow sharing and CRUD/FLS behavior in system context.',
        'PossibleHardcodedSecret': 'Verify the finding, revoke exposed credentials, and move secrets to protected configuration.',
    }
    rules += [{'name': key, 'engine': 'Metadata' if key != 'PossibleHardcodedSecret' else 'Heuristic', 'category': 'hotspot' if key in HOTSPOTS else 'security', 'description': value, 'priority': '', 'example': ''} for key, value in descriptions.items()]
    return {'rules': rules, 'pmd_catalog_available': bool(binary and len(rules) > len(descriptions)), 'categories': CATEGORIES}
