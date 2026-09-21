'use strict';
let auditNext=null, trendData=null;
function syncInsightProjects(){
  const node=$('trend-project'),old=node.value||$('project-select').value;
  node.replaceChildren(new Option('Choose a project',''),...projectList.map(p=>new Option(p.name,p.id)));
  if(projectList.some(p=>p.id===old))node.value=old;
}
function auditQuery(){
  const q=new URLSearchParams({page_size:'100'});
  for(const k of ['actor','action','target','since','until'])if($('audit-'+k).value)q.set(k,$('audit-'+k).value);
  return q;
}
async function loadAudit(cursor=''){
  const q=auditQuery();if(cursor)q.set('cursor',cursor);
  const result=await jsonAPI('/api/audit?'+q);auditNext=result.next_cursor;$('audit-next').disabled=!auditNext;
  $('audit-count').textContent=`${result.total} events in this snapshot · ${result.items.length} on this page`;
  $('audit-rows').replaceChildren();
  for(const e of result.items){const row=el('tr');for(const v of [new Date(e.created).toLocaleString(),e.actor,e.action,e.target])row.append(el('td',v));const cell=el('td'),details=el('details');details.append(el('summary','Details'),el('pre',e.details));cell.append(details);row.append(cell);$('audit-rows').append(row);}
}
$('audit-filters').onsubmit=runUI(()=>loadAudit());
$('audit-first').onclick=runUI(()=>loadAudit());
$('audit-next').onclick=runUI(()=>loadAudit(auditNext||''));
for(const format of ['json','csv'])$('audit-export-'+format).onclick=runUI(async()=>{
  const q=auditQuery();q.set('format',format);
  const response=await api('/api/audit/export?'+q),url=URL.createObjectURL(await response.blob()),link=el('a');
  link.href=url;link.download='appscan-audit.'+format;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
  notice('Audit export downloaded. The export includes all matching events within the documented export limits.');
});
$('trend-form').onsubmit=runUI(async()=>{
  const pid=$('trend-project').value;if(!pid)throw new Error('Choose a project.');
  const q=new URLSearchParams({branch:$('trend-branch').value||'main',pull_request:$('trend-pr').value,page_size:$('trend-limit').value});
  for(const k of ['since','until'])if($('trend-'+k).value)q.set(k,$('trend-'+k).value);
  trendData=await jsonAPI('/api/projects/'+pid+'/trends?'+q);renderTrend();
});
$('trend-metric').onchange=()=>renderTrend();
function renderTrend(){
  const box=$('trend-chart');box.replaceChildren();$('trend-rows').replaceChildren();
  if(!trendData)return;
  const key=$('trend-metric').value,label=$('trend-metric').selectedOptions[0].textContent;
  const points=trendData.items,percent=['coverage','new_coverage','duplication'].includes(key);
  $('trend-summary').textContent=`${points.length} of ${trendData.total} finished analyses · ${trendData.branch}${trendData.pull_request?' / PR '+trendData.pull_request:' / branch analyses only'}${trendData.truncated?' · latest results shown; narrow dates for older history':''}. Gate values are historical snapshots. Missing measures are gaps, not zero.`;
  for(const p of points){const row=el('tr');for(const v of [new Date(p.created).toLocaleString(),p.status,p.gate||'—',p[key]==null?'Not measured':String(p[key])+(percent?'%':''),p.policy_changed?'Changed':'—',p.revision||'—'])row.append(el('td',v));const cell=el('td'),button=el('button','Open scan','quiet');button.onclick=runUI(()=>openScan(p.id));cell.append(button);row.append(cell);$('trend-rows').append(row);}
  const usable=points.filter(p=>Number.isFinite(p[key])&&Number.isFinite(Date.parse(p.created)));
  if(!usable.length){box.append(el('p','No measured values for this selection. The table retains failed scans and missing measures.'));return;}
  const ns='http://www.w3.org/2000/svg',svg=document.createElementNS(ns,'svg');
  const add=(tag,attrs,text)=>{const n=document.createElementNS(ns,tag);for(const [k,v]of Object.entries(attrs))n.setAttribute(k,String(v));if(text!==undefined)n.textContent=text;svg.append(n);return n;};
  svg.setAttribute('viewBox','0 0 900 320');svg.setAttribute('role','img');svg.setAttribute('aria-label',label+' over time; exact values in the table below.');
  add('title',{},label+' over time');
  const times=points.map(p=>Date.parse(p.created)).filter(Number.isFinite),start=Math.min(...times),end=Math.max(...times),peak=Math.max(1,...usable.map(p=>p[key])),ticks=percent?4:Math.min(4,Math.ceil(peak)),max=percent?100:Math.ceil(peak/ticks)*ticks;
  const x=t=>65+(end===start?390:(t-start)/(end-start)*780),y=v=>260-v/max*210;
  for(let i=0;i<=ticks;i++){const v=max*i/ticks;add('line',{x1:65,y1:y(v),x2:845,y2:y(v),class:'trend-grid'});add('text',{x:55,y:y(v)+4,'text-anchor':'end',class:'trend-label'},String(Math.round(v*10)/10)+(percent?'%':''));}
  add('text',{x:65,y:292,class:'trend-label'},new Date(start).toLocaleString());add('text',{x:845,y:292,'text-anchor':'end',class:'trend-label'},new Date(end).toLocaleString());
  let segment=[];const flush=()=>{if(segment.length>1)add('polyline',{points:segment.join(' '),class:'trend-line'});segment=[];};
  for(const p of points){if(!Number.isFinite(p[key])||!Number.isFinite(Date.parse(p.created))){flush();continue;}segment.push(x(Date.parse(p.created))+','+y(p[key]));}flush();
  for(const p of usable){const c=add('circle',{cx:x(Date.parse(p.created)),cy:y(p[key]),r:5,class:'trend-point '+(p.gate==='PASS'?'pass':p.gate==='FAIL'?'fail':'incomplete')});const title=document.createElementNS(ns,'title');title.textContent=`${new Date(p.created).toLocaleString()}: ${p[key]}${percent?'%':''} · ${p.gate||p.status}${p.policy_changed?' · policy changed':''}`;c.append(title);}
  box.append(svg);
}
