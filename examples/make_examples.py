"""Generate deliberately vulnerable test data, never deploy to Salesforce."""
from pathlib import Path
import zipfile
ROOT = Path(__file__).parent
meta = '<?xml version="1.0"?><ApexClass xmlns="http://soap.sforce.com/2006/04/metadata"><apiVersion>64.0</apiVersion><status>Active</status></ApexClass>'
baseline = {'force-app/main/default/classes/AccountService.cls': 'public with sharing class AccountService { public static String label() { return \'Example\'; } }',
            'force-app/main/default/classes/AccountService.cls-meta.xml':meta,
            'force-app/main/default/objects/Account/fields/Legacy_Code__c.field-meta.xml':'<CustomField xmlns="http://soap.sforce.com/2006/04/metadata"><fullName>Legacy_Code__c</fullName><label>Legacy Code</label><length>20</length><type>Text</type></CustomField>'}
current = {'force-app/main/default/classes/AccountService.cls': '''public without sharing class AccountService {
    public static List<Account> search(String searchTerm) {
        return Database.query('SELECT Id, Name FROM Account WHERE Name = \\' ' + searchTerm + ' \\'');
    }
    public static void createAccount(String name) {
        insert new Account(Name = name);
    }
}''',
           'force-app/main/default/classes/AccountService.cls-meta.xml':meta,
           'force-app/main/default/permissionsets/BroadAccess.permissionset-meta.xml':'<PermissionSet xmlns="http://soap.sforce.com/2006/04/metadata"><label>Demo Broad Access</label><userPermissions><enabled>true</enabled><name>ModifyAllData</name></userPermissions></PermissionSet>'}
for name, files in [('baseline.zip', baseline), ('current.zip', current)]:
    with zipfile.ZipFile(ROOT / name, 'w', zipfile.ZIP_DEFLATED) as z:
        for path, content in files.items(): z.writestr(path, content)
    print(ROOT / name)
