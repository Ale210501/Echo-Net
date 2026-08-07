const runnerState = document.getElementById('runnerState');
const pivotSeverity = document.getElementById('pivotSeverity');
const lastSuccessRate = document.getElementById('lastSuccessRate');
const pivotStateLabel = document.getElementById('pivotStateLabel');
const pivotAlertBox = document.getElementById('pivotAlertBox');
const runStatus = document.getElementById('runStatus');
const scenarioIpInput = document.getElementById('scenarioIpInput');
const scenarioUaInput = document.getElementById('scenarioUaInput');
const scenarioLabelInput = document.getElementById('scenarioLabelInput');
const runScenarioBtn = document.getElementById('runScenarioBtn');
const scenarioResultBox = document.getElementById('scenarioResultBox');
const kpiCmdTotal = document.getElementById('kpiCmdTotal');
const kpiRouteRate = document.getElementById('kpiRouteRate');
const kpiAvgMs = document.getElementById('kpiAvgMs');
const kpiOtStatus = document.getElementById('kpiOtStatus');

function setPill(el, text, state) {
  if (!el) return;
  el.textContent = text;
  el.classList.remove('ok', 'warn', 'error', 'running', 'idle', 'live', 'critical');
  if (state) el.classList.add(state);
}

function applyPivot(alert) {
  const active = Boolean(alert?.active);
  const severity = String(alert?.severity || 'info').toLowerCase();
  const severityLabel = severity.toUpperCase();
  const severityState = severity === 'critical' ? 'critical' : (severity === 'warn' ? 'warn' : 'ok');
  setPill(pivotSeverity, severityLabel, severityState);
  setPill(pivotStateLabel, active ? 'Active signal' : 'Monitoring', active ? severityState : 'warn');
  pivotAlertBox.className = `pivot-alert ${severity}`;
  pivotAlertBox.textContent = alert?.message || 'No pivot signal available.';
}

async function refreshPivot() {
  try {
    const response = await fetch('/dashboard/summary?log_tail=30&event_tail=30');
    if (!response.ok) throw new Error('summary status ' + response.status);
    const data = await response.json();
    applyPivot(data.pivot_alert || {});
  } catch (error) {
    setPill(pivotStateLabel, 'Unavailable', 'error');
    pivotAlertBox.className = 'pivot-alert warn';
    pivotAlertBox.textContent = 'Pivot summary error: ' + error;
  }
}

async function runScenario() {
  setPill(runnerState, 'Running', 'running');
  setPill(runStatus, 'Executing scenario...', 'running');
  runScenarioBtn.disabled = true;

  const payload = {
    source_ip: (scenarioIpInput.value || '').trim() || '10.20.30.40',
    user_agent: (scenarioUaInput.value || '').trim() || 'scenario-runner/1.0',
    attack_label: (scenarioLabelInput.value || '').trim() || 'Echo-Net automatic IT->OT scenario',
    trigger_ot: true,
    generate_report: true,
    commands: ['whoami', 'ip route', 'show me current network routes'],
  };

  try {
    const response = await fetch('/scenario/run/basic', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    if (!response.ok) {
      setPill(runnerState, 'Failed', 'error');
      setPill(runStatus, 'Scenario failed: ' + response.status, 'error');
      scenarioResultBox.textContent = JSON.stringify(data, null, 2);
      return;
    }

    const kpi = data.kpi || {};
    setPill(runnerState, 'Completed', 'ok');
    setPill(runStatus, 'Scenario completed successfully.', 'ok');
    lastSuccessRate.textContent = String(kpi.it_route_success_rate_pct ?? '-') + '%';
    kpiCmdTotal.textContent = String(kpi.it_commands_total ?? '-');
    kpiRouteRate.textContent = String(kpi.it_route_success_rate_pct ?? '-') + '%';
    kpiAvgMs.textContent = String(kpi.it_avg_response_ms ?? '-');
    kpiOtStatus.textContent = String(kpi.ot_status ?? '-');
    scenarioResultBox.textContent = JSON.stringify(data, null, 2);
    await refreshPivot();
  } catch (error) {
    setPill(runnerState, 'Error', 'error');
    setPill(runStatus, 'Scenario error: ' + error, 'error');
  } finally {
    runScenarioBtn.disabled = false;
  }
}

runScenarioBtn.addEventListener('click', runScenario);
refreshPivot();
setInterval(refreshPivot, 4000);
