const API = '/api';
let currentFilters = {};
let severityChart = null;
let serverChart = null;

// --- Navigation ---
function showSection(name) {
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => {
    n.classList.remove('active');
    if (n.getAttribute('data-section') === name) n.classList.add('active');
  });
  const sec = document.getElementById('sec-' + name);
  if (sec) sec.classList.add('active');
  
  localStorage.setItem('activeSection', name);
  
  if (name === 'overview') refreshAll();
  else if (name === 'logs') loadLogs();
  else if (name === 'threats') loadThreats();
  else if (name === 'servers') loadServers();
  
  // Close mobile sidebar if open
  const app = document.querySelector('.app');
  if (app) app.classList.remove('mobile-sidebar-open');
}

function toggleSidebar() {
  const app = document.querySelector('.app');
  if (app) {
    app.classList.toggle('sidebar-collapsed');
    localStorage.setItem('sidebarCollapsed', app.classList.contains('sidebar-collapsed'));
  }
}

function toggleMobileSidebar() {
  const app = document.querySelector('.app');
  if (app) app.classList.toggle('mobile-sidebar-open');
}

function toast(msg, type = 'success') {
  const t = document.getElementById('toast');
  t.className = 'toast toast-' + type + ' show';
  t.innerHTML = '<i class="fas fa-' + (type === 'success' ? 'check-circle' : 'times-circle') + '"></i>' + msg;
  setTimeout(() => t.classList.remove('show'), 3000);
}

function escapeHtml(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

function riskColor(score) {
  if (score >= 70) return 'var(--red)';
  if (score >= 40) return 'var(--amber)';
  return 'var(--green)';
}

function sevBadge(sev) {
  return '<span class="badge badge-' + (sev || 'low').toLowerCase() + '">' + (sev || 'LOW') + '</span>';
}

// --- Filters ---
function buildFilterParams() {
  const p = new URLSearchParams();
  const sid = document.getElementById('f-server');
  const sev = document.getElementById('f-severity');
  const kw = document.getElementById('f-keyword');
  const df = document.getElementById('f-date-from');
  const dt = document.getElementById('f-date-to');
  if (sid && sid.value) p.set('server_id', sid.value);
  if (sev && sev.value) p.set('severity', sev.value);
  if (kw && kw.value) p.set('keyword', kw.value);
  if (df && df.value) p.set('date_from', df.value);
  if (dt && dt.value) p.set('date_to', dt.value);
  return p.toString();
}

function applyFilters() {
  const active = document.querySelector('.section.active');
  if (active.id === 'sec-logs') loadLogs();
  else if (active.id === 'sec-threats') loadThreats();
}

function clearFilters() {
  ['f-server','f-severity','f-keyword','f-date-from','f-date-to'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  applyFilters();
}

async function populateServerFilter() {
  try {
    const r = await fetch(API + '/servers/');
    const d = await r.json();
    const sel = document.getElementById('f-server');
    if (!sel) return;
    sel.innerHTML = '<option value="">All Servers</option>';
    (d.servers || []).forEach(s => {
      sel.innerHTML += '<option value="' + s.server_id + '">' + escapeHtml(s.name) + '</option>';
    });
  } catch(e) { console.error(e); }
}

// --- Overview ---
async function refreshAll() {
  try {
    const [sr, tr] = await Promise.all([fetch(API + '/stats/'), fetch(API + '/threats/?limit=5')]);
    const sd = await sr.json();
    const td = await tr.json();
    const st = sd.stats || {};

    document.getElementById('st-logs').textContent = st.total_threats || 0;
    document.getElementById('st-attacks').textContent = st.pending_attacks || 0;
    document.getElementById('st-normal').textContent = st.normal_count || 0;
    document.getElementById('st-risk').textContent = st.avg_risk || 0;

    // Threat table
    const el = document.getElementById('overview-threats');
    if (td.threats && td.threats.length > 0) {
      el.innerHTML = buildThreatTable(td.threats);
    } else {
      el.innerHTML = '<div class="empty"><i class="fas fa-shield-check"></i>No threats detected yet</div>';
    }

    // Charts
    renderSeverityChart(st.severity_distribution || []);
    renderTopIPs(st.top_attacking_ips || []);
    renderServerStats(st.server_stats || []);
  } catch(e) { console.error(e); }
}

function renderSeverityChart(dist) {
  const ctx = document.getElementById('severity-chart');
  if (!ctx) return;
  const labels = dist.map(d => d.severity_level);
  const data = dist.map(d => d.count);
  const colors = {'LOW':'#06b6d4','MEDIUM':'#f59e0b','HIGH':'#ef4444','CRITICAL':'#ff4444'};
  if (severityChart) severityChart.destroy();
  severityChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: labels,
      datasets: [{data: data, backgroundColor: labels.map(l => colors[l] || '#6366f1'), borderWidth: 0}]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: {legend: {position: 'bottom', labels: {color: '#94a3b8', padding: 16, font: {size: 12}}}},
      cutout: '65%'
    }
  });
}

function renderServerStats(stats) {
  const ctx = document.getElementById('server-chart');
  if (!ctx) return;
  const labels = stats.map(s => s.server__name || s.server__server_id);
  const attacks = stats.map(s => s.attacks);
  const totals = stats.map(s => s.total - s.attacks);
  if (serverChart) serverChart.destroy();
  serverChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [
        {label: 'Attacks', data: attacks, backgroundColor: 'rgba(239,68,68,0.7)', borderRadius: 4},
        {label: 'Normal', data: totals, backgroundColor: 'rgba(16,185,129,0.7)', borderRadius: 4}
      ]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      scales: {x:{ticks:{color:'#64748b'},grid:{color:'rgba(42,52,80,0.3)'}},y:{ticks:{color:'#64748b'},grid:{color:'rgba(42,52,80,0.3)'}}},
      plugins: {legend: {labels: {color: '#94a3b8'}}}
    }
  });
}

function renderTopIPs(ips) {
  const el = document.getElementById('top-ips-list');
  if (!el) return;
  if (!ips.length) { el.innerHTML = '<div class="empty"><i class="fas fa-check-circle"></i>No attacking IPs detected</div>'; return; }
  el.innerHTML = '<ul class="ip-list">' + ips.map(ip =>
    '<li><span style="font-family:monospace;color:var(--text)">' + escapeHtml(ip.ip) + '</span><span class="ip-count">' + ip.count + ' hits</span></li>'
  ).join('') + '</ul>';
}

// --- Logs ---
async function loadLogs() {
  const body = document.getElementById('logs-body');
  body.innerHTML = '<div class="empty"><div class="spinner"></div></div>';
  try {
    const params = buildFilterParams();
    const r = await fetch(API + '/logs/?' + params);
    const d = await r.json();
    document.getElementById('log-count').textContent = d.count + ' entries';
    if (!d.logs || d.logs.length === 0) {
      body.innerHTML = '<div class="empty"><i class="fas fa-inbox"></i>No logs found</div>';
      return;
    }
    body.innerHTML = d.logs.map(l => {
      const msg = typeof l === 'string' ? l : l.message || '';
      const srv = typeof l === 'object' ? l.server_name || '' : '';
      const sev = typeof l === 'object' ? l.severity || '' : '';
      return '<div class="log-entry"><div class="log-meta">' +
        (srv ? '<span class="log-tag srv">' + escapeHtml(srv) + '</span>' : '') +
        (sev ? '<span class="log-tag sev-' + sev + '">' + sev + '</span>' : '') +
        '</div><span>' + escapeHtml(msg) + '</span></div>';
    }).join('');
  } catch(e) {
    body.innerHTML = '<div class="empty"><i class="fas fa-exclamation-circle"></i>Failed to load logs</div>';
  }
}

// --- Threats ---
async function loadThreats() {
  const body = document.getElementById('threats-body');
  body.innerHTML = '<div class="empty"><div class="spinner"></div></div>';
  try {
    const params = buildFilterParams();
    const r = await fetch(API + '/threats/?' + params);
    const d = await r.json();
    if (!d.threats || d.threats.length === 0) {
      body.innerHTML = '<div class="empty"><i class="fas fa-shield-check"></i>No threats detected yet</div>';
      return;
    }
    body.innerHTML = buildThreatTable(d.threats);
  } catch(e) {
    body.innerHTML = '<div class="empty"><i class="fas fa-exclamation-circle"></i>Failed to load threats</div>';
  }
}

function buildThreatTable(threats) {
  let html = '<table><thead><tr><th>Time</th><th>Server</th><th>Severity</th><th>Class</th><th>Status</th><th>Risk</th><th>Source IP</th><th>Attack Type</th><th>Explanation</th><th>Actions</th></tr></thead><tbody>';
  threats.forEach(t => {
    const isResolved = t.status === 'RESOLVED';
    const cls = t.classification === 'ATTACK' ? 'attack' : 'normal';
    const time = new Date(t.timestamp).toLocaleString();
    const rc = riskColor(t.risk_score);
    const statusBadge = isResolved ? '<span class="badge badge-resolved">RESOLVED</span>' : '<span class="badge badge-' + cls + '">' + (t.classification === 'ATTACK' ? 'PENDING' : 'NORMAL') + '</span>';
    html += '<tr style="' + (isResolved ? 'opacity:0.6' : '') + '">'
      + '<td style="white-space:nowrap;color:var(--muted)">' + time + '</td>'
      + '<td>' + escapeHtml(t.server_name || '—') + '</td>'
      + '<td>' + sevBadge(t.severity_level) + '</td>'
      + '<td><span class="badge badge-' + cls + '">' + t.classification + '</span></td>'
      + '<td>' + statusBadge + '</td>'
      + '<td><div class="risk-bar"><div class="risk-fill" style="width:' + t.risk_score + '%;background:' + rc + '"></div></div>' + t.risk_score + '</td>'
      + '<td style="font-family:monospace;font-size:12px">' + escapeHtml(t.source_ip || '—') + '</td>'
      + '<td>' + escapeHtml(t.attack_type || '—') + '</td>'
      + '<td style="max-width:250px;color:var(--muted)">' + escapeHtml(t.explanation || '—') + '</td>'
      + '<td>' + (t.classification === 'ATTACK' && !isResolved ? '<button class="btn btn-sm btn-patch" onclick="patchThreat(' + t.id + ')"><i class="fas fa-hammer"></i> Patch</button>' : '—') + '</td></tr>';
  });
  html += '</tbody></table>';
  return html;
}

async function patchThreat(id) {
  try {
    const r = await fetch(API + '/resolve/' + id + '/', {method: 'POST', headers: {'X-CSRFToken': getCsrf()}});
    if (r.ok) {
      toast('Threat patched successfully!');
      refreshAll();
      if (document.getElementById('sec-threats').classList.contains('active')) loadThreats();
    }
  } catch(e) { toast('Failed to patch threat', 'error'); }
}

function getCsrf() {
  const el = document.querySelector('[name=csrfmiddlewaretoken]');
  return el ? el.value : '';
}

// --- Servers ---
async function loadServers() {
  const grid = document.getElementById('server-grid');
  if (!grid) return;
  grid.innerHTML = '<div class="empty"><div class="spinner"></div></div>';
  try {
    const r = await fetch(API + '/servers/');
    const d = await r.json();
    if (!d.servers || d.servers.length === 0) {
      grid.innerHTML = '<div class="empty"><i class="fas fa-server"></i>No servers registered yet. Run the system and trigger an analysis first.</div>';
      return;
    }
    grid.innerHTML = d.servers.map(s => `
      <div class="server-card" onclick="selectServer('${s.server_id}')">
        <h4><i class="fas fa-server" style="color:var(--accent);font-size:14px"></i>${escapeHtml(s.name)}</h4>
        <div class="env">${escapeHtml(s.environment)} — ${escapeHtml(s.server_id)}</div>
        <div class="metrics">
          <div class="metric"><div class="val" style="color:var(--accent)">${s.total_threats}</div><div class="lbl">Total</div></div>
          <div class="metric"><div class="val" style="color:var(--red)">${s.attack_count}</div><div class="lbl">Attacks</div></div>
          <div class="metric"><div class="val" style="color:var(--amber)">${s.avg_risk}</div><div class="lbl">Avg Risk</div></div>
        </div>
      </div>
    `).join('');
  } catch(e) {
    grid.innerHTML = '<div class="empty"><i class="fas fa-exclamation-circle"></i>Failed to load servers</div>';
  }
}

function selectServer(serverId) {
  const sel = document.getElementById('f-server');
  if (sel) sel.value = serverId;
  
  // Switch to threats view for that server
  showSection('threats');
}

// --- AI Analysis ---
async function runAnalysis() {
  const btn = document.getElementById('analyze-btn');
  const res = document.getElementById('analyze-result');
  btn.disabled = true;
  btn.innerHTML = '<div class="spinner"></div>Analyzing with AI...';
  res.innerHTML = '';
  try {
    const r = await fetch(API + '/analyze/', {method: 'POST', headers: {'X-CSRFToken': getCsrf(), 'Content-Type': 'application/json'}});
    const d = await r.json();
    toast('Analysis completed!');
    res.innerHTML = '<div style="padding:16px;background:rgba(16,185,129,0.1);border:1px solid rgba(16,185,129,0.3);border-radius:12px;color:var(--green);font-size:13px"><i class="fas fa-check-circle"></i> ' + (d.message || 'Done') + '</div>';
  } catch(e) {
    toast('Analysis failed', 'error');
    res.innerHTML = '<div style="padding:16px;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:12px;color:var(--red);font-size:13px"><i class="fas fa-times-circle"></i> Error occurred</div>';
  }
  btn.disabled = false;
  btn.innerHTML = '<i class="fas fa-brain"></i>Run AI Analysis';
}

// --- System Status ---
async function checkSystemStatus() {
  const dot = document.getElementById('system-status-dot');
  const text = document.getElementById('system-status-text');
  if (!dot || !text) return;
  try {
    const r = await fetch(API + '/stats/');
    if (r.ok) {
      dot.style.background = 'var(--green)';
      text.textContent = 'System Online';
    } else {
      dot.style.background = 'var(--red)';
      text.textContent = 'System Error';
    }
  } catch(e) {
    dot.style.background = 'var(--red)';
    text.textContent = 'System Offline';
  }
}

// --- Init ---
document.addEventListener('DOMContentLoaded', () => {
  if (localStorage.getItem('sidebarCollapsed') === 'true') {
    const app = document.querySelector('.app');
    if (app) app.classList.add('sidebar-collapsed');
  }
  
  const activeSec = localStorage.getItem('activeSection') || 'overview';
  showSection(activeSec);
  
  populateServerFilter();
  checkSystemStatus();
  
  setInterval(() => {
    refreshAll();
    checkSystemStatus();
  }, 30000);
});
