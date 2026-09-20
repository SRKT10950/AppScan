// One authoritative Python implementation, copied before extension packaging.
const fs = require('fs');
const path = require('path');
const root = path.resolve(__dirname, '../..');
const target = path.join(root, 'vscode-extension/python');
fs.rmSync(target, {recursive: true, force: true});
fs.mkdirSync(target, {recursive: true});
fs.cpSync(path.join(root, 'app'), path.join(target, 'app'), {
  recursive: true, filter: source => !source.includes('__pycache__') && !source.endsWith('.pyc')
});
fs.copyFileSync(path.join(root, 'cli.py'), path.join(target, 'cli.py'));
console.log('Synchronized bundled scanner and CLI.');
