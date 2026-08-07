const feedState = document.getElementById('feedState');
const runtimeStatus = document.getElementById('runtimeStatus');
const containerStatus = document.getElementById('containerStatus');
const runtimeBox = document.getElementById('runtimeBox');
const sessionsList = document.getElementById('sessionsList');
const eventsList = document.getElementById('eventsList');
const pivotBox = document.getElementById('pivotBox');

function setPill(el, text, state) {
  if (!el) return;
  el.textContent = text;
  el.classList.remove('ok', 'warn', 'error', 'running', 'idle', 'live', 'critical');
  if (state) el.classList.add(state);
}

function deriveState(value) {
  const text = String(value || '').toLowerCase();
  if (text.includes('running') || text.includes('started') || text.includes('ok') || text.includes('live')) return 'live';
  if (text.includes('failed') || text.includes('error') || text.includes('missing') || text.includes('stopped')) return 'error';
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
  if (value.includes('started') || value.includes('ok') || value.includes('running')) return '<span class="tag ok">' + escapeHtml(status) + '</span>';
  if (value.includes('failed') || value.includes('error') || value.includes('missing')) return '<span class="tag err">' + escapeHtml(status) + '</span>';
  return '<span class="tag warn">' + escapeHtml(status || 'unknown') + '</span>';
}

function renderItems(container, items, renderer) {
  if (!Array.isArray(items) || items.length === 0) {
    container.innerHTML = '<div class="stream-item"><small>No data yet.</small></div>';
    return;
  }
  container.innerHTML = items.slice().reverse().map(renderer).join('');
}

async function refreshView() {
  try {
    const response = await fetch('/dashboard/summary?log_tail=80&event_tail=80');
    if (!response.ok) throw new Error('summary status ' + response.status);
    const summary = await response.json();

    setPill(feedState, 'Live', 'live');
    const honeynet = summary.honeynet || {};
    const runtime = honeynet.runtime || {};

    setPill(runtimeStatus, runtime.status || '-', deriveState(runtime.status));
    setPill(containerStatus, runtime.container_status || '-', deriveState(runtime.container_status));
    runtimeBox.textContent = JSON.stringify(runtime, null, 2);

    renderItems(sessionsList, honeynet.active_ot_sessions || [], (entry) => {
      return `<article class="stream-item"><strong>${escapeHtml(entry.session_key || 'ot_session')}</strong>${statusTag(entry.trap || 'ot')}<div><small>${escapeHtml(entry.last_activity || '-')}</small></div><div>Domain: ${escapeHtml(entry.target_domain || '-')} | Started: ${escapeHtml(entry.started_at || '-')}</div></article>`;
    });

    renderItems(eventsList, honeynet.recent_ot_events || [], (entry) => {
      return `<article class="stream-item"><strong>${escapeHtml(entry.event || 'ot_event')}</strong>${statusTag(entry.status || 'event')}<div><small>${escapeHtml(entry.timestamp || '-')}</small></div><div>${escapeHtml(entry.detail || '')}</div></article>`;
    });

    pivotBox.textContent = JSON.stringify(summary.pivot_alert || {}, null, 2);
  } catch (error) {
    setPill(feedState, 'Error', 'error');
    runtimeBox.textContent = 'Refresh error: ' + error;
  }
}

refreshView();
setInterval(refreshView, 4000);
