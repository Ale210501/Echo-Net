const wsStatusEl = document.getElementById('wsStatus');
const queueSizeEl = document.getElementById('queueSize');
const sessionCountEl = document.getElementById('sessionCount');
const sessionsBox = document.getElementById('sessionsBox');
const terminalBox = document.getElementById('terminalBox');
const terminalStateLabel = document.getElementById('terminalStateLabel');
const terminalSessionKey = document.getElementById('terminalSessionKey');
const terminalProfile = document.getElementById('terminalProfile');
const terminalPrompt = document.getElementById('terminalPrompt');
const terminalCwd = document.getElementById('terminalCwd');
const terminalExitCode = document.getElementById('terminalExitCode');
const terminalSessionsList = document.getElementById('terminalSessionsList');
const terminalOverviewState = document.getElementById('terminalOverviewState');
const terminalOverviewSession = document.getElementById('terminalOverviewSession');
const honeynetOverviewState = document.getElementById('honeynetOverviewState');
const honeynetOverviewContainer = document.getElementById('honeynetOverviewContainer');
const scenarioOverview = document.getElementById('scenarioOverview');
const pivotAlertBox = document.getElementById('pivotAlertBox');
const pivotSeverityLabel = document.getElementById('pivotSeverityLabel');
const pendingList = document.getElementById('pendingList');
const pendingBadge = document.getElementById('pendingBadge');
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

function setPill(el, text, state) {
  if (!el) return;
  el.textContent = text;
  el.classList.remove('ok', 'warn', 'error', 'running', 'idle', 'live', 'critical');
  if (state) el.classList.add(state);
}

function deriveState(value) {
  const text = String(value || '').toLowerCase();
  if (text.includes('live') || text.includes('running') || text.includes('started') || text.includes('ok') || text.includes('completed')) return 'live';
  if (text.includes('failed') || text.includes('error') || text.includes('critical') || text.includes('missing') || text.includes('disconnected')) return 'error';
  return 'warn';
}

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
  if (!container) return;
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

function renderTranscript(container, transcript) {
  if (!container) return;
  if (!Array.isArray(transcript) || transcript.length === 0) {
    container.textContent = 'No terminal transcript yet.';
    return;
  }
  container.textContent = transcript.join('\n');
}

function applyPivotAlert(alert) {
  const active = Boolean(alert?.active);
  const severity = String(alert?.severity || 'info').toLowerCase();
  if (pivotSeverityLabel) {
    setPill(
      pivotSeverityLabel,
      active ? 'Severity: ' + severity.toUpperCase() : 'No active pivot alert',
      active ? (severity === 'critical' ? 'critical' : (severity === 'warn' ? 'warn' : 'ok')) : 'warn'
    );
  }
  if (pivotAlertBox) {
    pivotAlertBox.textContent = alert?.message || 'No pivot telemetry available.';
    pivotAlertBox.className = 'pivot-alert ' + severity;
  }
}

function renderBarChart(container, entries) {
  if (!container) return;
  if (!Array.isArray(entries) || entries.length === 0) {
    container.innerHTML = '<div class="stream-item"><small>No data yet.</small></div>';
    return;
  }

  const max = Math.max(...entries.map((entry) => entry.value || 0), 1);
  container.innerHTML = entries
    .map((entry) => {
      const width = Math.max(4, Math.round(((entry.value || 0) / max) * 100));
      return `
        <div class="bar-row">
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

  if (technique && !entryTechnique.includes(technique)) return false;
  if (ip && !entryIp.includes(ip)) return false;
  if (behavior !== 'all' && entryBehavior !== behavior) return false;
  return true;
}

function latestScenarioSummary(queueEvents) {
  const events = Array.isArray(queueEvents) ? queueEvents : [];
  const match = events
    .slice()
    .reverse()
    .find((entry) => String(entry.event || '').includes('scenario'));

  if (!match) return 'No recent run';
  const status = match.status || match.event || 'scenario';
  const ts = match.timestamp || '-';
  return `${status} @ ${ts}`;
}

async function handleApproval(eventId, action) {
  try {
    const res = await fetch(`/soc/${action}/${eventId}`, { method: 'POST' });
    const body = await res.json();
    const card = document.getElementById(`approval-${eventId}`);
    if (card) {
      card.classList.add(action === 'approve' ? 'resolved-ok' : 'resolved-reject');
      card.querySelector('.approval-actions').innerHTML =
        `<span class="state-pill ${action === 'approve' ? 'ok' : 'error'}">${action === 'approve' ? 'Deployed' : 'Rejected'}</span>`;
    }
    console.log(`[approval] ${action} → ${eventId}`, body);
  } catch (err) {
    console.error(`[approval] ${action} failed`, err);
  }
}

function renderPendingApprovals(items) {
  if (!pendingList) return;

  if (!Array.isArray(items) || items.length === 0) {
    pendingBadge.style.display = 'none';
    pendingList.innerHTML = '<div class="stream-item"><small>No pending approvals.</small></div>';
    return;
  }

  pendingBadge.textContent = String(items.length);
  pendingBadge.style.display = 'inline-flex';

  pendingList.innerHTML = items.map((item) => {
    const payload = item.payload || {};
    const reaction = item.reaction || {};
    const conf = typeof item.confidence === 'number' ? (item.confidence * 100).toFixed(0) + '%' : '-';
    return `
      <article class="stream-item approval-card" id="approval-${escapeHtml(item.event_id)}">
        <div class="approval-header">
          <span class="state-pill warn">PENDING APPROVAL</span>
          <strong>${escapeHtml(payload.technique_id || '-')}</strong>
          <span class="subtle">Domain: ${escapeHtml(payload.target_domain || '-')}</span>
          <span class="subtle">Confidence: <strong>${conf}</strong></span>
        </div>
        <div class="approval-meta">
          <span>Action: ${escapeHtml(reaction.action || '-')}</span>
          <span>Received: ${escapeHtml(item.received_at || '-')}</span>
          <span>Event ID: <code>${escapeHtml(item.event_id)}</code></span>
        </div>
        <div class="approval-detail subtle">${escapeHtml(reaction.detail || reaction.description || '')}</div>
        <div class="approval-actions">
          <button class="btn-approve" onclick="handleApproval('${escapeHtml(item.event_id)}', 'approve')">
            ✓ Approve &amp; Deploy
          </button>
          <button class="btn-reject" onclick="handleApproval('${escapeHtml(item.event_id)}', 'reject')">
            ✗ Reject
          </button>
        </div>
      </article>
    `;
  }).join('');
}

function renderDashboard(data) {
  latestDashboard = data;
  const sessions = data.sessions || {};
  const sessionKeys = Object.keys(sessions);
  const nowText = new Date().toLocaleTimeString();
  const liveTerminal = data.live_terminal || {};
  const honeynet = data.honeynet || {};

  queueSizeEl.textContent = String(data.queue_size ?? 0);
  sessionCountEl.textContent = String(sessionKeys.length);
  sessionsBox.textContent = JSON.stringify(sessions, null, 2);
  queueEventsBox.textContent = JSON.stringify(data.recent_queue_events || [], null, 2);
  lastRefreshLabel.textContent = `Last refresh ${nowText}`;

  applyPivotAlert(data.pivot_alert || {});
  renderPendingApprovals(data.pending_approvals || []);

  terminalStateLabel.textContent = liveTerminal.status === 'live'
    ? 'Live terminal session active'
    : 'No terminal session yet';
  terminalStateLabel.classList.remove('ok', 'warn', 'error', 'running', 'idle', 'live', 'critical');
  terminalStateLabel.classList.add(liveTerminal.status === 'live' ? 'live' : 'warn');
  terminalSessionKey.textContent = liveTerminal.latest_session?.session_key || '-';
  terminalProfile.textContent = liveTerminal.latest_session?.shell_family || '-';
  terminalPrompt.textContent = liveTerminal.latest_session?.prompt || '-';
  terminalCwd.textContent = liveTerminal.latest_session?.cwd || '-';
  terminalExitCode.textContent = liveTerminal.latest_session?.last_exit_code ?? '-';
  renderTranscript(terminalBox, liveTerminal.transcript || []);

  const terminalSessions = Array.isArray(liveTerminal.sessions) ? liveTerminal.sessions : [];
  if (terminalSessions.length === 0) {
    terminalSessionsList.textContent = 'No session data yet.';
  } else {
    terminalSessionsList.innerHTML = terminalSessions
      .map((entry) => {
        return `
          <div class="session-item static">
            <strong>${escapeHtml(entry.session_key || '-')}</strong>
            <div><small>IP: ${escapeHtml(entry.source_ip || '-')} | Last: ${escapeHtml(entry.last_activity || '-')}</small></div>
          </div>
        `;
      })
      .join('');
  }

  setPill(terminalOverviewState, liveTerminal.status || 'unknown', deriveState(liveTerminal.status));
  terminalOverviewSession.textContent = liveTerminal.latest_session?.session_key || '-';
  setPill(
    honeynetOverviewState,
    honeynet.runtime?.status || honeynet.status || 'unknown',
    deriveState(honeynet.runtime?.status || honeynet.status)
  );
  honeynetOverviewContainer.textContent = honeynet.runtime?.container_status || '-';
  scenarioOverview.textContent = latestScenarioSummary(data.recent_queue_events || []);

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
    setPill(wsStatusEl, 'Live', 'live');
  };

  socket.onmessage = (event) => {
    const data = JSON.parse(event.data);
    renderDashboard(data);
  };

  socket.onclose = () => {
    setPill(wsStatusEl, 'Disconnected', 'error');
    reconnectTimer = setTimeout(connectSocket, 2500);
  };

  socket.onerror = () => {
    setPill(wsStatusEl, 'Error', 'warn');
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
