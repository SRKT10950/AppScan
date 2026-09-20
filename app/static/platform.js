'use strict';
let currentUser = null, projectList = [], ruleList = [], reviewIssue = null;
const selectedProject = () => projectList.find(p => p.id === $('project-select').value);
const splitNames = value => value.split(',').map(x => x.trim()).filter(Boolean);
const runUI = fn => async event => { if(event?.preventDefault) event.preventDefault(); try { await fn(event); } catch(e) { notice(e.message); } };
async function jsonAPI(path, body) { return (await api(path, body === undefined ? {} : {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})).json(); }
function projectQuery() {
  const params = new URLSearchParams();
  if($('project-select').value) params.set('project_id', $('project-select').value);
  if($('branch-filter').value.trim()) params.set('branch', $('branch-filter').value.trim());
  return '?' + params;
}
async function loadPlatform() {
  currentUser = await jsonAPI('/api/me');
  $('identity').textContent = currentUser.username + ' · ' + currentUser.role;
  for(const n of document.querySelectorAll('.admin-only')) n.hidden = currentUser.role !== 'admin';
  $('start').disabled = currentUser.role === 'viewer';
  await loadProjects();
  const catalog = await jsonAPI('/api/rules'); ruleList = catalog.rules;
  $('rule-availability').textContent = catalog.pmd_catalog_available ? `${ruleList.length} local rule definitions. Review descriptions before changing profiles.` : 'PMD catalog unavailable; showing built-in metadata checks.';
  $('policy-categories').replaceChildren();
  for(const category of catalog.categories) { const label = el('label', undefined, 'check'); const box = document.createElement('input'); box.type='checkbox'; box.value=category; box.className='category'; label.append(box, document.createTextNode(category)); $('policy-categories').append(label); }
  renderPolicy(); renderRules(); await loadTokens();
  if(currentUser.role === 'admin') await loadAdmin();
  await loadIssues();
}
async function loadProjects() {
  const old = $('project-select').value;
  projectList = await jsonAPI('/api/projects');
  $('project-select').replaceChildren(new Option('All projects', ''));
  for(const p of projectList) $('project-select').append(new Option(p.name, p.id));
  if(projectList.some(p=>p.id===old)) $('project-select').value=old;
  else if(projectList.length===1) $('project-select').value=projectList[0].id;
  renderPolicy();
}
async function projectChanged() {
  const p=selectedProject(); if(p) $('project').value=p.name;
  renderPolicy(); await refresh(); await loadIssues();
}
$('project-select').onchange=runUI(projectChanged);
$('branch-filter').onchange=runUI(async()=>{await refresh();await loadIssues();});
$('create-project').onsubmit=runUI(async()=>{const r=await jsonAPI('/api/projects',{name:$('new-project-name').value});await loadProjects();$('project-select').value=r.id;await projectChanged();$('new-project-name').value='';});
function renderPolicy() {
  const p=selectedProject(); $('policy-fields').disabled=!p || currentUser?.role!=='admin';
  if(!p) return;
  const s=p.settings;
  $('policy-scope').value=s.scope; $('policy-blockers').value=s.max_blockers;
  $('policy-coverage').value=s.min_coverage??''; $('policy-duplication').value=s.max_duplication??'';
  $('policy-source').checked=!!s.store_source; $('policy-cpd').checked=s.cpd; $('policy-hotspots').checked=s.require_hotspot_review;
  $('policy-disabled').value=s.disabled_rules.join(', '); $('policy-overrides').value=JSON.stringify(s.severity_overrides);
  $('policy-exclusions').value=s.exclusions.join('\n'); $('policy-members').value=p.members.join(', ');
  for(const box of document.querySelectorAll('.category')) box.checked=s.categories.includes(box.value);
}
$('policy-form').onsubmit=runUI(async()=>{
  const p=selectedProject();if(!p)throw new Error('Select a project first.');
  const settings={scope:$('policy-scope').value,max_blockers:Number($('policy-blockers').value),min_coverage:$('policy-coverage').value===''?null:Number($('policy-coverage').value),max_duplication:$('policy-duplication').value===''?null:Number($('policy-duplication').value),cpd:$('policy-cpd').checked,store_source:$('policy-source').checked,require_hotspot_review:$('policy-hotspots').checked,categories:Array.from(document.querySelectorAll('.category:checked'),n=>n.value),disabled_rules:splitNames($('policy-disabled').value),severity_overrides:JSON.parse($('policy-overrides').value),exclusions:$('policy-exclusions').value.split('\n').map(x=>x.trim()).filter(Boolean)};
  await jsonAPI('/api/projects/'+p.id,{settings,members:splitNames($('policy-members').value)});await loadProjects();notice('Policy saved. New scans use this policy; earlier results remain unchanged.');
});
function renderQualitySummary(r) {
  const box=$('quality-summary');box.replaceChildren();
  const values=[['New findings',r.metrics?.new_findings??'—'],['Code lines',r.metrics?.lines??'—'],['Imported coverage',r.coverage?.percent==null?'Not supplied':r.coverage.percent+'%'],['Apex duplication',r.duplication?.percent==null?r.duplication?.status||'Not measured':r.duplication.percent+'%']];
  for(const [name,value] of values){const card=el('article');card.append(el('small',name),el('strong',value));box.append(card);}
  const details=el('details');details.append(el('summary','Gate conditions & file measures'));details.append(el('p','New-code reference: '+(r.new_code_reference||'legacy scan')));
  for(const c of r.quality_gate?.conditions||[])details.append(el('p',`${c.metric}: ${c.actual??'missing'} / limit ${c.limit} — ${c.status}`));
  const table=el('table');const head=el('tr');for(const t of ['File','Lines','Nonblank','Decision points (estimate)',...(r.policy?.store_source?['']:[])])head.append(el('th',t));table.append(head);
  for(const m of r.metrics?.file_metrics||[]){const row=el('tr');for(const value of [m.path,m.lines,m.nonblank_lines,m.decision_points_estimate])row.append(el('td',value));if(r.policy?.store_source){const cell=el('td'),button=el('button','Source','quiet');button.onclick=runUI(async()=>{const source=await jsonAPI('/api/scans/'+selected.id+'/source?path='+encodeURIComponent(m.path));$('source-title').textContent=m.path;$('source-content').textContent=source.content.split('\n').map((line,i)=>String(i+1).padStart(4,' ')+'  '+line).join('\n');$('source-dialog').showModal();});cell.append(button);row.append(cell);}table.append(row);}details.append(table);box.append(details);
  if(r.duplication?.groups?.length){const dup=el('details');dup.append(el('summary','Duplicated blocks'));for(const group of r.duplication.groups)dup.append(el('p',group.locations.map(l=>`${l.path}:${l.line} (${l.lines} lines)`).join(' ↔ ')));box.append(dup);}
}
async function loadIssues() {
  const p=selectedProject(), body=$('issue-rows');body.replaceChildren();
  if(!p){const row=el('tr'),cell=el('td','Select a project to view its issues.');cell.colSpan=5;row.append(cell);body.append(row);return;}
  const query=new URLSearchParams({project_id:p.id,branch:$('branch-filter').value.trim(),status:$('issue-status').value,kind:$('issue-kind').value,search:$('issue-search').value});
  const rows=await jsonAPI('/api/issues?'+query);
  if(!rows.length){const row=el('tr'),cell=el('td','No matching issues. Run a scan or change filters.');cell.colSpan=5;row.append(cell);body.append(row);}
  for(const issue of rows){const f=issue.finding,row=el('tr'),severity=el('td'),detail=el('td'),state=el('td'),action=el('td');severity.append(el('span',f.severity,'badge '+f.severity),el('small',f.kind));detail.append(el('strong',f.rule),el('small',f.path+':'+f.line),el('small',f.message));state.append(el('span',issue.status,'badge'),el('small',issue.branch));const button=el('button','Review','quiet');button.disabled=currentUser.role==='viewer';button.onclick=runUI(()=>openReview(issue));action.append(button);row.append(severity,detail,state,el('td',issue.assignee||'Unassigned'),action);body.append(row);}
}
$('reload-issues').onclick=runUI(loadIssues);$('issue-status').onchange=runUI(loadIssues);$('issue-kind').onchange=runUI(loadIssues);$('issue-search').onchange=runUI(loadIssues);
async function openReview(issue) {
  reviewIssue=issue;$('review-title').textContent=issue.finding.rule+' · '+issue.finding.path;
  const states=['open','confirmed','accepted','false_positive'];if(issue.finding.kind==='hotspot')states.push('safe');
  $('review-status').replaceChildren(...states.map(s=>new Option(s.replaceAll('_',' '),s)));$('review-status').value=states.includes(issue.status)?issue.status:'open';$('review-assignee').value=issue.assignee;$('review-comment').value='';
  const comments=await jsonAPI('/api/issues/'+issue.id+'/comments');$('review-comments').replaceChildren(...comments.map(c=>el('p',`${c.actor} · ${new Date(c.created).toLocaleString()}: ${c.body}`)));$('review-dialog').showModal();
}
$('close-review').onclick=()=>$('review-dialog').close();
$('review-form').onsubmit=runUI(async()=>{await jsonAPI('/api/issues/'+reviewIssue.id,{status:$('review-status').value,assignee:$('review-assignee').value,comment:$('review-comment').value});$('review-dialog').close();await loadIssues();notice('Review saved. Rescan to evaluate the updated gate.');});
function renderRules(){const query=$('rule-search').value.toLowerCase();$('rule-rows').replaceChildren();for(const r of ruleList.filter(r=>(r.name+' '+r.description).toLowerCase().includes(query))){const row=el('tr'),cell=el('td'),button=el('button','Details','quiet');button.onclick=()=>{$('rule-title').textContent=r.name;$('rule-description').textContent=r.description;$('rule-example').textContent=r.example||'No example provided.';$('rule-dialog').showModal();};cell.append(button);row.append(el('td',r.name),el('td',r.category),el('td',r.engine),cell);$('rule-rows').append(row);}}
$('rule-search').oninput=renderRules;$('close-rule').onclick=()=>$('rule-dialog').close();
$('token-form').onsubmit=runUI(async()=>{const p=selectedProject();if(!p)throw new Error('Select a project first.');const r=await jsonAPI('/api/tokens',{project_id:p.id,name:$('token-name').value,scope:$('token-scope').value,days:Number($('token-days').value)});$('new-token').textContent='Copy now; this token cannot be retrieved again:\n'+r.token;$('new-token').hidden=false;await loadTokens();});
async function loadTokens(){const rows=await jsonAPI('/api/tokens');$('token-list').replaceChildren();for(const r of rows){const item=el('p',`${r.name} · ${r.scope} · expires ${new Date(r.expires).toLocaleDateString()} `),button=el('button','Revoke','quiet');button.onclick=runUI(async()=>{await jsonAPI('/api/tokens/'+r.id+'/revoke',{});await loadTokens();$('new-token').hidden=true;$('new-token').textContent='';});item.append(button);$('token-list').append(item);}}
async function loadAdmin(){const users=await jsonAPI('/api/users');$('user-list').replaceChildren(...users.map(u=>el('p',`${u.username} · ${u.role} · ${u.enabled?'enabled':'disabled'}`)));const events=await jsonAPI('/api/audit');$('audit-rows').replaceChildren();for(const e of events){const row=el('tr');for(const v of [new Date(e.created).toLocaleString(),e.actor,e.action,e.target])row.append(el('td',v));$('audit-rows').append(row);}}
$('user-form').onsubmit=runUI(async()=>{await jsonAPI('/api/users',{username:$('new-username').value,password:$('new-password').value,role:$('new-role').value,enabled:$('user-enabled').checked});$('new-password').value='';await loadAdmin();notice('User saved. Assign project membership in Quality settings.');});

$('close-source').onclick=()=>$('source-dialog').close();
