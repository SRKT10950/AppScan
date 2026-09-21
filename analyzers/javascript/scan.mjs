// Only this administrator-owned configuration executes. Repository files are lintText input.
import { ESLint } from 'eslint';
import parser from '@babel/eslint-parser';
import decorators from '@babel/plugin-syntax-decorators';
let input = '';
for await (const chunk of process.stdin) input += chunk;
const files = JSON.parse(input);
const rules = {
  'no-eval':'error', 'no-implied-eval':'error', 'no-new-func':'error', 'no-script-url':'error',
  'no-unreachable':'error', 'no-dupe-keys':'error', 'no-unsafe-finally':'error',
  'no-constant-condition':'warn', 'constructor-super':'error', 'valid-typeof':'error',
  'no-async-promise-executor':'error', 'no-promise-executor-return':'warn', 'eqeqeq':'warn'
};
const lint = new ESLint({overrideConfigFile:true, ignore:false, overrideConfig:[{
  files:['**/*.js'], linterOptions:{noInlineConfig:true},
  languageOptions:{parser, ecmaVersion:'latest', sourceType:'module', parserOptions:{
    requireConfigFile:false, babelOptions:{babelrc:false,configFile:false,plugins:[[decorators,{legacy:true}]]}
  }}, rules
}]});
const findings=[], errors=[];
for (const [path, content] of Object.entries(files)) {
  const [result] = await lint.lintText(content, {filePath:'input.js'});
  for (const m of result.messages) {
    if (m.fatal) { errors.push({path,message:m.message}); continue; }
    // ESLint's ignored-inline-directive notices have no rule and are not findings.
    if (!m.ruleId) continue;
    const security=['no-eval','no-implied-eval','no-new-func','no-script-url'].includes(m.ruleId);
    findings.push({path,line:m.line||1,rule:'ESLint/'+m.ruleId,engine:'ESLint',
      category:security?'Security':'Error Prone',severity:m.severity===2?'High':'Medium',message:m.message});
  }
}
process.stdout.write(JSON.stringify({findings,errors}));
