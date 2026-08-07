const feedState = document.getElementById('feedState');
const activeSession = document.getElementById('activeSession');
const lastExitCode = document.getElementById('lastExitCode');
const sendStatus = document.getElementById('sendStatus');
const commandInput = document.getElementById('commandInput');
const sourceIpInput = document.getElementById('sourceIpInput');
const userAgentInput = document.getElementById('userAgentInput');
const sendBtn = document.getElementById('sendBtn');
const transcriptBox = document.getElementById('transcriptBox');
const promptValue = document.getElementById('promptValue');
const cwdValue = document.getElementById('cwdValue');
const profileValue = document.getElementById('profileValue');
const sessionList = document.getElementById('sessionList');
const itStream = document.getElementById('itStream');

let latestSummary = null;
let selectedSession = '';
let pollTimer = null;

function setPill(el, text, state) {
  if (!el) return;
  el.textContent = text;
  el.classList.remove('ok', 'warn', 'error', 'running', 'idle', 'live', 'critical');
  if (state) el.classList.add(state);
}

function escapeHtml(text) {
  return String(text)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
}

function statusTag(status) {
  const value = (status || '').toLowerCase();
  if (value.includes('routed') || value.includes('started')) return '<span class="tag ok">' + escapeHtml(status) + '</span>';
  if (value.includes('failed') || value.includes('error')) return '<span class="tag err">' + escapeHtml(status) + '</span>';
  return '<span class="tag warn">' + escapeHtml(status || 'unknown') + '</span>';
}

function renderItems(container, items, renderer) {
  if (!Array.isArray(items) || items.length === 0) {
    container.innerHTML = '<div class="stream-item"><small>No data yet.</small></div>';
    return;
  }
  container.innerHTML = items.slice().reverse().map(renderer).join('');
}

function parseSession(sessionKey) {
  if (!sessionKey) return { sourceIp: '', uaHash: '' };
  const parts = String(sessionKey).split('::');
  return { sourceIp: parts[1] || '', uaHash: parts[2] || '' };
}

function renderSummary(summary) {
  latestSummary = summary;
  setPill(feedState, 'Live', 'live');

  const liveTerminal = summary.live_terminal || {};
  const latest = liveTerminal.latest_session || {};
  const transcript = Array.isArray(liveTerminal.transcript) ? liveTerminal.transcript : [];

  activeSession.textContent = latest.session_key || '-';
  lastExitCode.textContent = typeof latest.last_exit_code === 'undefined' ? '-' : String(latest.last_exit_code);
  promptValue.textContent = latest.prompt || '-';
  cwdValue.textContent = latest.cwd || '-';
  profileValue.textContent = latest.shell_family || '-';
  transcriptBox.textContent = transcript.length ? transcript.join('\n') : 'No transcript yet.';

  const sessions = Array.isArray(liveTerminal.sessions) ? liveTerminal.sessions : [];
  if (!sessions.length) {
    sessionList.textContent = 'No sessions yet.';
  } else {
    sessionList.innerHTML = sessions
      .map((item) => {
        const parsed = parseSession(item.session_key);
        const selectedClass = item.session_key === selectedSession ? 'selected' : '';
        return `<button class="session-item ${selectedClass}" data-session="${escapeHtml(item.session_key || '')}" data-ip="${escapeHtml(item.source_ip || parsed.sourceIp || '')}" data-ua="${escapeHtml(item.user_agent || '')}"><strong>${escapeHtml(item.session_key || '-')}</strong><div><small>IP: ${escapeHtml(item.source_ip || parsed.sourceIp || '-')} | Last: ${escapeHtml(item.last_activity || '-')}</small></div></button>`;
      })
      .join('');

    sessionList.querySelectorAll('.session-item').forEach((node) => {
      node.addEventListener('click', () => {
        selectedSession = node.getAttribute('data-session') || '';
        const ip = node.getAttribute('data-ip') || '';
        const ua = node.getAttribute('data-ua') || '';
        if (ip) sourceIpInput.value = ip;
        if (ua) userAgentInput.value = ua;
        sendStatus.textContent = 'Session selected: ' + selectedSession;
        sendStatus.classList.remove('state-pill', 'ok', 'warn', 'error', 'running');
        sendStatus.classList.add('state-pill', 'ok');
        if (latestSummary) renderSummary(latestSummary);
      });
    });
  }

  renderItems(itStream, summary.it_commands_tail || [], (entry) => {
    const behavior = entry.behavior || {};
    return `<article class="stream-item"><strong>${escapeHtml(entry.event || 'it_event')}</strong>${statusTag(entry.status || behavior.profile)}<div><small>${escapeHtml(entry.timestamp || '-')}</small></div><div>Command: ${escapeHtml(entry.command || '')}</div><div>IP: ${escapeHtml(entry.request?.client_ip || '-')} | UA: ${escapeHtml(entry.request?.user_agent || '-')}</div></article>`;
  });
}

async function loadSummary() {
  try {
    const response = await fetch('/dashboard/summary?log_tail=50&event_tail=50');
    if (!response.ok) throw new Error('summary status ' + response.status);
    const summary = await response.json();
    renderSummary(summary);
  } catch (error) {
    setPill(feedState, 'Error', 'error');
    sendStatus.textContent = 'Summary fetch failed: ' + error;
    sendStatus.classList.remove('state-pill', 'ok', 'warn', 'error', 'running');
    sendStatus.classList.add('state-pill', 'error');
  }
}

async function sendCommand() {
  const command = (commandInput.value || '').trim();
  if (!command) {
    sendStatus.textContent = 'Insert a command before sending.';
    sendStatus.classList.remove('state-pill', 'ok', 'warn', 'error', 'running');
    sendStatus.classList.add('state-pill', 'warn');
    return;
  }

  const payload = { command };
  const sourceIp = (sourceIpInput.value || '').trim();
  const userAgent = (userAgentInput.value || '').trim();
  if (sourceIp) payload.source_ip = sourceIp;
  if (userAgent) payload.user_agent = userAgent;

  sendBtn.disabled = true;
  sendStatus.textContent = 'Sending...';
  sendStatus.classList.remove('state-pill', 'ok', 'warn', 'error', 'running');
  sendStatus.classList.add('state-pill', 'running');

  try {
    const response = await fetch('/attacker/command', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    if (!response.ok) {
      sendStatus.textContent = 'Send failed: ' + response.status;
      sendStatus.classList.remove('state-pill', 'ok', 'warn', 'error', 'running');
      sendStatus.classList.add('state-pill', 'error');
      return;
    }

    selectedSession = data.session_key || selectedSession;
    sendStatus.textContent = 'Command routed (' + (data.status || 'ok') + ').';
    sendStatus.classList.remove('state-pill', 'ok', 'warn', 'error', 'running');
    sendStatus.classList.add('state-pill', 'ok');
    if (Array.isArray(data.terminal_transcript)) {
      transcriptBox.textContent = data.terminal_transcript.join('\n');
    }
    await loadSummary();
  } catch (error) {
    sendStatus.textContent = 'Send error: ' + error;
    sendStatus.classList.remove('state-pill', 'ok', 'warn', 'error', 'running');
    sendStatus.classList.add('state-pill', 'error');
  } finally {
    sendBtn.disabled = false;
  }
}

sendBtn.addEventListener('click', sendCommand);
commandInput.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') sendCommand();
});

loadSummary();
pollTimer = setInterval(loadSummary, 3000);
