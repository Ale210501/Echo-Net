const wsStatusEl = document.getElementById('wsStatus');
const queueSizeEl = document.getElementById('queueSize');
const sessionCountEl = document.getElementById('sessionCount');
const sessionsBox = document.getElementById('sessionsBox');
const predictionList = document.getElementById('predictionList');
const itList = document.getElementById('itList');
const otList = document.getElementById('otList');
const reportBox = document.getElementById('reportBox');
const queueEventsBox = document.getElementById('queueEventsBox');
const refreshReportBtn = document.getElementById('refreshReportBtn');
const techniqueFilterEl = document.getElementById('techniqueFilter');
const ipFilterEl = document.getElementById('ipFilter');
const behaviorFilterEl = document.getElementById('behaviorFilter');
const applyFiltersBtn = document.getElementById('applyFiltersBtn');
const clearFiltersBtn = document.getElementById('clearFiltersBtn');
const techniqueChart = document.getElementById('techniqueChart');
const behaviorChart = document.getElementById('behaviorChart');
const otChart = document.getElementById('otChart');
const lastRefreshLabel = document.getElementById('lastRefreshLabel');

let socket = null;
let reconnectTimer = null;
let latestDashboard = null;
let filterState = {
  technique: '',
  ip: '',
  behavior: 'all',
};

function escapeHtml(text) {
  return String(text)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
}

function statusTag(status) {
  const value = (status || '').toLowerCase();
  if (value.includes('routed') || value.includes('started') || value.includes('exported')) {
    return '<span class="tag ok">' + escapeHtml(status) + '</span>';
  }
  if (value.includes('failed') || value.includes('error') || value.includes('missing')) {
    return '<span class="tag err">' + escapeHtml(status) + '</span>';
  }
  return '<span class="tag warn">' + escapeHtml(status || 'unknown') + '</span>';
}

function renderItems(container, items, renderer) {
  if (!Array.isArray(items) || items.length === 0) {
    container.innerHTML = '<div class="stream-item"><small>No data yet.</small></div>';
    return;
  }
  container.innerHTML = items
    .slice()
    .reverse()
    .map(renderer)
    .join('');
}

function renderBarChart(container, entries, colorClass = '') {
  if (!Array.isArray(entries) || entries.length === 0) {
    container.innerHTML = '<div class="stream-item"><small>No data yet.</small></div>';
    return;
  }

  const max = Math.max(...entries.map((entry) => entry.value || 0), 1);
  container.innerHTML = entries
    .map((entry) => {
      const width = Math.max(4, Math.round(((entry.value || 0) / max) * 100));
      return `
        <div class="bar-row ${colorClass}">
          <div class="bar-label">${escapeHtml(entry.label)}</div>
          <div class="bar-value">${escapeHtml(entry.value)}</div>
          <div class="bar-track"><div class="bar-fill" style="width:${width}%"></div></div>
        </div>
      `;
    })
    .join('');
}

function aggregateCounts(items, keyFn) {
  const counts = new Map();
  for (const item of items || []) {
    const key = keyFn(item);
    if (!key) continue;
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return [...counts.entries()]
    .map(([label, value]) => ({ label, value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 6);
}

function parseTimestamp(value) {
  const parsed = Date.parse(value || '');
  return Number.isNaN(parsed) ? 0 : parsed;
}

function applyFiltersToItems(items, predicate) {
  return (items || []).filter(predicate);
}

function extractTechnique(entry) {
  return entry?.payload?.technique_id || entry?.technique_id || '';
}

function extractIp(entry) {
  return entry?.request?.client_ip || entry?.request?.x_forwarded_for || entry?.client_ip || '';
}

function extractBehavior(entry) {
  return entry?.behavior?.profile || entry?.behavior || '';
}

function activeFiltersPredicate(entry) {
  const technique = (filterState.technique || '').trim().toLowerCase();
  const ip = (filterState.ip || '').trim().toLowerCase();
  const behavior = (filterState.behavior || 'all').trim().toLowerCase();

  const entryTechnique = extractTechnique(entry).toLowerCase();
  const entryIp = extractIp(entry).toLowerCase();
  const entryBehavior = extractBehavior(entry).toLowerCase();

  if (technique && !entryTechnique.includes(technique)) {
    return false;
  }
  if (ip && !entryIp.includes(ip)) {
    return false;
  }
  if (behavior !== 'all' && entryBehavior !== behavior) {
    return false;
  }
  return true;
}

function renderDashboard(data) {
  latestDashboard = data;
  const sessions = data.sessions || {};
  const sessionKeys = Object.keys(sessions);
  const nowText = new Date().toLocaleTimeString();

  queueSizeEl.textContent = String(data.queue_size ?? 0);
  sessionCountEl.textContent = String(sessionKeys.length);
  sessionsBox.textContent = JSON.stringify(sessions, null, 2);
  queueEventsBox.textContent = JSON.stringify(data.recent_queue_events || [], null, 2);
  lastRefreshLabel.textContent = `Last refresh ${nowText}`;

  const filteredPredictions = applyFiltersToItems(data.prediction_tail, activeFiltersPredicate);
  const filteredIt = applyFiltersToItems(data.it_commands_tail, activeFiltersPredicate);
  const filteredOt = applyFiltersToItems(data.ot_events_tail, activeFiltersPredicate);

  const techniqueCounts = aggregateCounts(filteredPredictions, (entry) => extractTechnique(entry));
  const behaviorCounts = aggregateCounts(filteredIt, (entry) => extractBehavior(entry) || (entry.status || 'unknown'));
  const otCounts = aggregateCounts(filteredOt, (entry) => entry.status || entry.event || 'event');

  renderBarChart(techniqueChart, techniqueCounts);
  renderBarChart(behaviorChart, behaviorCounts);
  renderBarChart(otChart, otCounts);

  renderItems(predictionList, filteredPredictions, (entry) => {
    const payload = entry.payload || {};
    const reaction = entry.reaction || {};
    return `
      <article class="stream-item">
        <strong>${escapeHtml(entry.event || 'prediction')}</strong>
        ${statusTag(reaction.status || reaction.action)}
        <div><small>${escapeHtml(entry.timestamp || '-')}</small></div>
        <div>Technique: ${escapeHtml(payload.technique_id || '-')} | Domain: ${escapeHtml(payload.target_domain || '-')}</div>
      </article>
    `;
  });

  renderItems(itList, filteredIt, (entry) => {
    const behavior = entry.behavior || {};
    return `
      <article class="stream-item">
        <strong>${escapeHtml(entry.event || 'it_event')}</strong>
        ${statusTag(entry.status || behavior.profile)}
        <div><small>${escapeHtml(entry.timestamp || '-')}</small></div>
        <div>Command: ${escapeHtml(entry.command || '')}</div>
        <div>Profile: ${escapeHtml(behavior.profile || '-')} | Score: ${escapeHtml(behavior.automation_score ?? '-')}</div>
        <div>IP: ${escapeHtml(entry.request?.client_ip || '-')} | UA: ${escapeHtml(entry.request?.user_agent || '-')}</div>
      </article>
    `;
  });

  renderItems(otList, filteredOt, (entry) => {
    return `
      <article class="stream-item">
        <strong>${escapeHtml(entry.event || 'ot_event')}</strong>
        ${statusTag(entry.status || 'event')}
        <div><small>${escapeHtml(entry.timestamp || '-')}</small></div>
        <div>${escapeHtml(entry.detail || '')}</div>
        <div>Snapshot detail: ${escapeHtml(entry.export_file || entry.container_name || '-')}</div>
      </article>
    `;
  });
}

async function loadLatestReport() {
  try {
    const response = await fetch('/dashboard/report/latest');
    const data = await response.json();
    if (data.status !== 'ok') {
      reportBox.textContent = 'No report available yet.';
      return;
    }
    reportBox.textContent = data.content || '';
  } catch (error) {
    reportBox.textContent = 'Error loading report: ' + error;
  }
}

function connectSocket() {
  const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
  socket = new WebSocket(`${proto}://${window.location.host}/ws/dashboard`);

  socket.onopen = () => {
    wsStatusEl.textContent = 'Live';
    wsStatusEl.style.color = '#52d273';
  };

  socket.onmessage = (event) => {
    const data = JSON.parse(event.data);
    renderDashboard(data);
  };

  socket.onclose = () => {
    wsStatusEl.textContent = 'Disconnected';
    wsStatusEl.style.color = '#ff6b6b';
    reconnectTimer = setTimeout(connectSocket, 2500);
  };

  socket.onerror = () => {
    wsStatusEl.textContent = 'Error';
    wsStatusEl.style.color = '#ffd166';
  };
}

function bindFilters() {
  applyFiltersBtn.addEventListener('click', () => {
    filterState = {
      technique: techniqueFilterEl.value,
      ip: ipFilterEl.value,
      behavior: behaviorFilterEl.value,
    };
    if (latestDashboard) {
      renderDashboard(latestDashboard);
    }
  });

  clearFiltersBtn.addEventListener('click', () => {
    techniqueFilterEl.value = '';
    ipFilterEl.value = '';
    behaviorFilterEl.value = 'all';
    filterState = { technique: '', ip: '', behavior: 'all' };
    if (latestDashboard) {
      renderDashboard(latestDashboard);
    }
  });
}

refreshReportBtn.addEventListener('click', loadLatestReport);

bindFilters();
connectSocket();
loadLatestReport();
