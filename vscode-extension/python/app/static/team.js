'use strict';
let profiles=[],groups=[],portfolioList=[],retentionPreview=null;
const requireProject=()=>{const p=selectedProject();if(!p)throw new Error('Select a project first.');return p;};
function teamForm(id,title,fields,submit) {
  const section=el('details'),form=el('form');form.id=id;form.className='form-grid';section.append(el('summary',title));
  for(const [key,label,type,value] of fields){const l=el('label',label),input=el(type==='textarea'?'textarea':'input');input.id=key;if(type!=='textarea')input.type=type;input.value=value||'';l.append(input);form.append(l);}
  form.append(el('button','Save'));form.onsubmit=runUI(submit);section.append(form);$('team-admin').append(section);return section;
}
teamForm('shared-profile','Shared quality profiles',[
 ['shared-id','Profile (New creates a profile)','text'],['shared-name','Profile name','text'],['shared-parent','Parent profile (optional)','text'],['shared-overrides','Policy overrides (JSON)','textarea','{}']
],async()=>{await jsonAPI('/api/profiles',{id:$('shared-id').value,name:$('shared-name').value,parent_id:$('shared-parent').value,overrides:JSON.parse($('shared-overrides').value)});await loadTeam();await loadProjects();notice('Shared profile saved. New scans use the updated effective policy.');});
teamForm('bind-profile','Attach profile to selected project',[
 ['bind-profile-id','Shared profile (Standalone detaches)','text'],['bind-overrides','Project overrides (JSON)','textarea','{}']
],async()=>{await jsonAPI('/api/projects/'+requireProject().id+'/profile',{profile_id:$('bind-profile-id').value,overrides:JSON.parse($('bind-overrides').value)});await loadProjects();notice('Project profile saved.');});
teamForm('group-form','User groups',[
 ['group-id','Group (New creates a group)','text'],['group-name','Group name','text'],['group-members','Members (comma-separated usernames)','textarea']
],async()=>{await jsonAPI('/api/groups',{id:$('group-id').value,name:$('group-name').value,members:splitNames($('group-members').value)});await loadTeam();});
teamForm('bind-groups','Grant group access to selected project',[
 ['bind-group-ids','Groups with project access (replaces group grants)','textarea']
],async()=>{await jsonAPI('/api/projects/'+requireProject().id+'/groups',{groups:Array.from($('bind-group-ids').selectedOptions,o=>o.value)});await loadProjects();notice('Group access saved. Global user roles still control write permission.');});
teamForm('portfolio-form','Portfolio membership',[
 ['portfolio-id','Portfolio (New creates a portfolio)','text'],['portfolio-name','Portfolio name','text'],['portfolio-projects','Projects in portfolio','textarea']
],async()=>{await jsonAPI('/api/portfolios',{id:$('portfolio-id').value,name:$('portfolio-name').value,projects:Array.from($('portfolio-projects').selectedOptions,o=>o.value)});await loadTeam();});
teamForm('retention-form','Retention policy for selected project',[
 ['retention-days','Delete unpinned scans older than days (0 disables)','number','0'],['retention-keep','Minimum scans kept per branch / PR','number','10'],['retention-source','Purge source older than days (0 disables)','number','0']
],async()=>{await jsonAPI('/api/projects/'+requireProject().id+'/retention-policy',{days:Number($('retention-days').value),keep_count:Number($('retention-keep').value),source_days:Number($('retention-source').value)});retentionPreview=null;$('retention-apply').disabled=true;notice('Retention policy saved. Preview before applying cleanup.');});
$('retention-preview').onclick=runUI(async()=>{const p=requireProject();retentionPreview=await jsonAPI('/api/projects/'+p.id+'/retention',{});$('retention-result').textContent=JSON.stringify(retentionPreview,null,2);$('retention-apply').disabled=false;});
$('retention-apply').onclick=runUI(async()=>{const p=requireProject();if(!retentionPreview||retentionPreview.project_id!==p.id)throw new Error('Preview this project first.');const result=await jsonAPI('/api/projects/'+p.id+'/retention',{apply:true,plan_hash:retentionPreview.plan_hash});$('retention-result').textContent=JSON.stringify(result,null,2);retentionPreview=null;$('retention-apply').disabled=true;await refresh();});
$('team-refresh').onclick=runUI(loadTeam);
async function loadTeam() {
  const notes=await jsonAPI('/api/notifications');$('notifications-list').replaceChildren();
  for(const n of notes){const p=el('p',`${n.seen?'Read':'New'} · ${n.message} `);if(!n.seen){const b=el('button','Mark read','quiet');b.onclick=runUI(async()=>{await jsonAPI('/api/notifications/'+n.id+'/read',{});await loadTeam();});p.append(b);}$('notifications-list').append(p);}
  if(!notes.length)$('notifications-list').append(el('p','No notifications.'));
  const portfolios=await jsonAPI('/api/portfolios');portfolioList=portfolios;$('portfolio-list').replaceChildren();
  for(const p of portfolios){const card=el('article');card.append(el('h3',p.name),el('p',`${p.failures} failing · ${p.incomplete} incomplete or unscanned`));for(const project of p.projects)card.append(el('p',`${project.name}: ${project.gate} · ${project.findings} findings`));if(currentUser.role==='admin'){const edit=el('button','Edit portfolio','quiet');edit.onclick=()=>{$('portfolio-id').value=p.id;$('portfolio-name').value=p.name;for(const o of $('portfolio-projects').options)o.selected=p.projects.some(x=>x.id===o.value);$('portfolio-form').parentElement.open=true;};card.append(edit);}$('portfolio-list').append(card);}
  if(!portfolios.length)$('portfolio-list').append(el('p','No portfolios visible. An administrator can create one below.'));
  if(currentUser.role!=='admin')return;
  const select=(id,rows,empty,multiple=false)=>{let node=$(id);if(node.tagName!=='SELECT'){const replacement=el('select');replacement.id=id;node.replaceWith(replacement);node=replacement;}const values=Array.from(node.selectedOptions,o=>o.value);node.multiple=multiple;node.replaceChildren(...(multiple?[]:[new Option(empty,'')]),...rows.map(r=>new Option(r.name,r.id)));for(const o of node.options)o.selected=values.includes(o.value);};
  select('portfolio-id',portfolios,'New portfolio');select('portfolio-projects',projectList,'',true);
  profiles=await jsonAPI('/api/profiles');groups=await jsonAPI('/api/groups');
  select('shared-id',profiles,'New profile');select('shared-parent',profiles,'No parent');select('bind-profile-id',profiles,'Standalone');select('group-id',groups,'New group');select('bind-group-ids',groups,'',true);
  $('team-catalog').replaceChildren();
  for(const p of profiles){const row=el('p',`Profile ${p.name} `),edit=el('button','Edit','quiet'),bind=el('button','Use for project','quiet');edit.onclick=()=>{$('shared-id').value=p.id;$('shared-name').value=p.name;$('shared-parent').value=p.parent_id;$('shared-overrides').value=JSON.stringify(p.overrides,null,2);$('shared-profile').parentElement.open=true;};bind.onclick=()=>{$('bind-profile-id').value=p.id;$('bind-profile').parentElement.open=true;};row.append(edit,bind);$('team-catalog').append(row);}
  for(const g of groups){const row=el('p',`Group ${g.name} · ${g.members.join(', ')} `),edit=el('button','Edit','quiet');edit.onclick=()=>{$('group-id').value=g.id;$('group-name').value=g.name;$('group-members').value=g.members.join(', ');$('group-form').parentElement.open=true;};row.append(edit);$('team-catalog').append(row);}
  for(const p of projectList)$('team-catalog').append(el('p',`Project ${p.name} · profile ${profiles.find(x=>x.id===p.profile_id)?.name||'standalone'} · groups ${groups.filter(x=>p.groups.includes(x.id)).map(x=>x.name).join(', ')||'none'}`));
}
$('bulk-review').onsubmit=runUI(async()=>{const ids=Array.from(document.querySelectorAll('.issue-select:checked'),b=>b.value);await jsonAPI('/api/issues/bulk',{ids,status:$('bulk-status').value,comment:$('bulk-comment').value});await loadIssues();notice('Bulk review saved. Historical gates are unchanged; rescan to apply decisions.');});

// Keep existing-record selection paired with its saved values.
$('team-admin').addEventListener('change',event=>{const id=event.target.id,value=event.target.value;if(id==='shared-id'){const p=profiles.find(x=>x.id===value);$('shared-name').value=p?.name||'';$('shared-parent').value=p?.parent_id||'';$('shared-overrides').value=JSON.stringify(p?.overrides||{},null,2);}if(id==='portfolio-id'){const p=portfolioList.find(x=>x.id===value);$('portfolio-name').value=p?.name||'';for(const o of $('portfolio-projects').options)o.selected=(p?.projects||[]).some(x=>x.id===o.value);}if(id==='group-id'){const g=groups.find(x=>x.id===value);$('group-name').value=g?.name||'';$('group-members').value=(g?.members||[]).join(', ');}});
