'use strict';

const $ = id => document.getElementById(id);
let auth = '', selected = null, historyTimer = null;

const el = (tag, text, cls) => {
  const n = document.createElement(tag);
  if (text !== undefined) n.textContent = text;
  if (cls) n.className = cls;
  return n;
};

const apiPrefix = window.location.pathname.replace(/\/+$/, '');

async function api(path, options = {}) {
  const target = apiPrefix + path;
  const response = await fetch(target, {
    ...options,
    headers: {
      'Authorization': auth,
      ...(options.headers || {})
    }
  });
  if (!response.ok) {
    let body;
    try { body = await response.json(); } catch { body = {}; }
    throw new Error(body.error || `Request failed (${response.status})`);
  }
  return response;
}

function notice(message = '') {
  const n = $('notice');
  if (n) {
    n.textContent = message;
    n.hidden = !message;
  }
}

function setRoute(hash) {
  const target = (hash || window.location.hash || '#overview').replace(/^#/, '');
  const views = ['overview', 'projects', 'issues-panel', 'quality-settings', 'rules-panel', 'administration', 'new-scan', 'history'];
  const active = views.includes(target) ? target : 'overview';

  for (const a of document.querySelectorAll('nav a')) {
    const href = a.getAttribute('href') || '';
    a.classList.toggle('active', href === '#' + active);
  }

  for (const v of views) {
    const section = $(v);
    if (section) {
      section.classList.toggle('active-view', v === active);
    }
  }

  const titles = {
    'overview': 'Scan overview',
    'projects': 'Projects & Branch Filters',
    'issues-panel': 'Issues & security hotspots',
    'quality-settings': 'Quality gates & profiles',
    'rules-panel': 'Rule catalog',
    'administration': 'Administration & access',
    'new-scan': 'New analysis',
    'history': 'Scan history'
  };
  const titleEl = $('header-view-title');
  if (titleEl) {
    titleEl.textContent = titles[active] || 'Scan overview';
  }

  document.body.classList.remove('mobile-nav-open');
}

window.addEventListener('hashchange', () => setRoute());

const menuToggle = $('menu-toggle');
if (menuToggle) {
  menuToggle.onclick = () => document.body.classList.toggle('mobile-nav-open');
}

$('login-form').onsubmit = async event => {
  event.preventDefault();
  const bytes = new TextEncoder().encode($('username').value + ':' + $('password').value);
  auth = 'Basic ' + btoa(Array.from(bytes, b => String.fromCharCode(b)).join(''));
  try {
    await loadPlatform();
    await refresh();
    $('password').value = '';
    $('login').hidden = true;
    $('app').hidden = false;
    $('logout').hidden = false;
    setRoute(window.location.hash || '#overview');
    historyTimer = setInterval(() => refresh().catch(e => notice(e.message)), 4000);
  } catch (e) {
    auth = '';
    $('login-error').textContent = e.message;
  }
};

$('logout').onclick = () => {
  location.reload();
};

$('refresh').onclick = () => refresh().catch(e => notice(e.message));

async function refresh() {
  const rows = await (await api('/api/scans' + projectQuery())).json();
  $('history-rows').replaceChildren();
  if (!rows.length) {
    const row = el('tr');
    const cell = el('td', 'No analyses yet. Upload your source in New analysis to start.');
    cell.colSpan = 8;
    row.append(cell);
    $('history-rows').append(row);
  }
  for (const r of rows) {
    const row = el('tr');
    row.append(
      el('td', r.project),
      el('td', (r.branch || 'main') + (r.pull_request ? ' / PR ' + r.pull_request : '')),
      el('td', new Date(r.created).toLocaleString()),
      el('td', r.status)
    );
    const gate = el('td');
    gate.append(el('span', r.gate || '—', 'badge ' + (r.gate || '')));
    row.append(
      gate,
      el('td', String(r.count)),
      el('td', (r.coverage?.percent ?? '—') + '% / ' + (r.duplication?.percent ?? '—') + '%')
    );
    const action = el('td');
    const button = el('button', 'View', 'quiet');
    button.onclick = () => openScan(r.id).catch(e => notice(e.message));
    action.append(button);
    row.append(action);
    $('history-rows').append(row);
  }
  if (selected && ['queued', 'running'].includes(selected.status)) {
    await openScan(selected.id);
  }
}

function fileData(file) {
  if (!file) return Promise.resolve(null);
  if (file.size > 20 * 1024 * 1024) return Promise.reject(new Error('Each ZIP must be at most 20 MiB.'));
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result.split(',')[1]);
    reader.onerror = () => reject(new Error('Could not read file.'));
    reader.readAsDataURL(file);
  });
}

$('scan-form').onsubmit = async event => {
  event.preventDefault();
  $('start').disabled = true;
  notice('Uploading source and queuing analysis…');
  try {
    const payload = {
      project: $('project').value,
      api_version: $('version').value,
      branch: $('scan-branch').value,
      pull_request: $('scan-pr').value,
      revision: $('scan-revision').value,
      coverage: $('coverage-file').files[0] ? JSON.parse(await $('coverage-file').files[0].text()) : null,
      current: await fileData($('current').files[0]),
      baseline: await fileData($('baseline').files[0])
    };
    const response = await (await api('/api/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    })).json();
    await loadProjects();
    await openScan(response.id);
    await refresh();
  } catch (e) {
    notice(e.message);
  } finally {
    $('start').disabled = false;
  }
};

async function openScan(id) {
  selected = await (await api('/api/scans/' + id)).json();
  const isComplete = selected.status === 'complete';
  $('report').hidden = !isComplete;
  const empty = $('overview-empty');
  if (empty) empty.hidden = isComplete;

  if (!isComplete) {
    for (const id of ['gate', 'security-count', 'change-count', 'component-count']) {
      $(id).textContent = '—';
    }
    $('gate-note').textContent = selected.status;
    const pill = $('gate-pill');
    if (pill) {
      pill.textContent = selected.status;
      pill.className = 'badge';
    }
    notice(selected.status === 'failed' ? (selected.result?.error || 'Scan failed.') : 'Analysis ' + selected.status + ' · results refresh automatically.');
    window.location.hash = '#overview';
    setRoute('#overview');
    return;
  }

  notice();
  const r = selected.result;
  $('gate').textContent = r.gate;
  $('gate-note').textContent = 'PMD: ' + r.pmd;

  const pill = $('gate-pill');
  if (pill) {
    pill.textContent = r.gate;
    pill.className = 'badge ' + r.gate;
  }

  $('security-count').textContent = r.findings.filter(f => f.category === 'Security').length;
  $('change-count').textContent = r.changes.length;
  $('component-count').textContent = r.components;
  $('report-title').textContent = selected.project;
  $('report-meta').textContent = `${new Date(selected.created).toLocaleString()} · ${r.files} files · ${r.comparison === 'baseline' ? 'Baseline comparison' : 'Full inventory'}`;
  $('warnings').replaceChildren(...r.warnings.map(w => el('p', w)));
  renderQualitySummary(r);

  // Reset tab to findings view
  for (const button of document.querySelectorAll('[data-tab]')) {
    const isFindings = button.dataset.tab === 'findings';
    button.classList.toggle('selected', isFindings);
    const view = $(button.dataset.tab + '-view');
    if (view) view.hidden = !isFindings;
  }

  renderFindings();
  $('changes').replaceChildren();
  for (const c of r.changes) {
    const row = el('tr'), status = el('td');
    status.append(el('span', c.status, 'badge ' + c.status));
    row.append(status, el('td', c.type), el('td', c.member));
    $('changes').append(row);
  }
  if (!r.changes.length) {
    const row = el('tr');
    const cell = el('td', 'No supported metadata changes.');
    cell.colSpan = 3;
    row.append(cell);
    $('changes').append(row);
  }
  const coverage = $('coverage-view');
  coverage.replaceChildren(el('p', 'Apex: PMD security, design, performance, and error-prone rules. XML: selected permission, flow, and endpoint checks. Secrets: heuristic detection. LWC/Aura: change mapping only; no JavaScript security analysis.'));
  coverage.append(el('h2', 'Analysis errors'));
  if (!r.errors.length) coverage.append(el('p', 'No analysis errors reported.'));
  for (const error of r.errors) {
    coverage.append(el('p', (error.path ? error.path + ': ' : '') + error.message));
  }
  coverage.append(el('h2', 'Unsupported metadata files'));
  if (!r.unsupported.length) coverage.append(el('p', 'None identified among inspected source files.'));
  for (const path of r.unsupported) {
    coverage.append(el('p', path));
  }

  // Switch route to overview so the report is in front of the user
  window.location.hash = '#overview';
  setRoute('#overview');
}

function renderFindings() {
  if (!selected || selected.status !== 'complete') return;
  const query = $('search').value.toLowerCase(), severity = $('severity').value;
  const findings = selected.result.findings.filter(f =>
    (!severity || f.severity === severity) &&
    [f.rule, f.path, f.message].join(' ').toLowerCase().includes(query)
  );
  $('findings').replaceChildren();
  for (const f of findings.slice(0, 500)) {
    const row = el('tr'), sev = el('td'), detail = el('td'), location = el('td', `${f.path}:${f.line}`);
    sev.append(el('span', f.severity, 'badge ' + f.severity));
    detail.append(
      el('strong', f.rule),
      el('small', f.message),
      el('small', f.engine + ' · ' + f.category + ' · ' + (f.is_new ? 'New' : 'Existing') + ' · ' + (f.status || 'open'))
    );
    row.append(sev, detail, location);
    $('findings').append(row);
  }
  if (!findings.length) {
    const row = el('tr');
    const cell = el('td', 'No findings match this view. Check coverage and errors before accepting a scan.');
    cell.colSpan = 3;
    row.append(cell);
    $('findings').append(row);
  }
  $('finding-count').textContent = `${findings.length} findings match · showing up to 500 · complete results are in the download`;
}

$('search').oninput = renderFindings;
$('severity').onchange = renderFindings;

for (const tab of document.querySelectorAll('[data-tab]')) {
  tab.onclick = () => {
    for (const button of document.querySelectorAll('[data-tab]')) {
      const active = button === tab;
      button.classList.toggle('selected', active);
      $(button.dataset.tab + '-view').hidden = !active;
    }
  };
}

$('download').onclick = async () => {
  try {
    const response = await api('/api/scans/' + selected.id + '/report.zip');
    const url = URL.createObjectURL(await response.blob());
    const a = el('a');
    a.href = url;
    a.download = 'appscan-report.zip';
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (e) {
    notice(e.message);
  }
};
