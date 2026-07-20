const defaultApi = window.location.origin;
let API = sessionStorage.getItem('AI_SIEM_API') || defaultApi;
let connected = false;

function emptyHuntState() {
  return {
    has_run: false,
    total_matches: 0,
    events: [],
    facets: {},
    scope: { available_events: 0, scanned_events: 0, scan_truncated: false },
    query: {},
  };
}

let state = {
  session: { role: 'viewer', capabilities: [] },
  notifications: { enabled: false, channels: [] },
  readiness: { ready: false, status: 'restricted', checks: [] },
  report: { overview: {}, alerts_by_severity: {}, incidents_by_status: {} },
  hunt: emptyHuntState(),
  huntRequest: {},
  huntHistory: [],
  operations: {},
  metrics: {},
  events: [],
  alerts: [],
  incidents: [],
  anomalies: [],
  rules: [],
};

const fallback = {
  session: { role: 'viewer', capabilities: [] },
  notifications: { enabled: false, channels: [] },
  readiness: { ready: false, status: 'restricted', checks: [] },
  report: { overview: {}, alerts_by_severity: {}, incidents_by_status: {} },
  hunt: emptyHuntState(),
  huntRequest: {},
  huntHistory: [],
  operations: {},
  metrics: {
    total_events: 0,
    critical_alerts: 0,
    open_incidents: 0,
    risk_score: 0,
    source_distribution: {},
    event_type_distribution: {},
  },
  events: [],
  alerts: [],
  incidents: [],
  anomalies: [],
  rules: [],
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => document.querySelectorAll(selector);
const escapeHtml = (value, fallbackValue = '—') => {
  const normalized = value === null || value === undefined || value === ''
    ? fallbackValue
    : String(value);
  return normalized.replace(/[&<>'"]/g, (character) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    "'": '&#39;',
    '"': '&quot;',
  })[character]);
};

function getToken() {
  return sessionStorage.getItem('AI_SIEM_API_KEY') || '';
}

function authHeaders(extra = {}) {
  const token = getToken();
  return token ? { ...extra, Authorization: `Bearer ${token}` } : { ...extra };
}

function canOperate() {
  return (state.session.capabilities || []).includes('write:operations');
}

function canAdminister() {
  return (state.session.capabilities || []).includes('admin:configuration');
}

function canViewRawEvents() {
  return (state.session.capabilities || []).includes('read:raw-events');
}

function badge(value) {
  const normalized = String(value || '').toLowerCase();
  const cssClass = normalized.includes('critical') || normalized === 'p1'
    ? 'critical'
    : normalized.includes('high') || normalized === 'p2'
      ? 'high'
      : normalized.includes('medium')
        ? 'medium'
        : '';
  return `<mark class="${cssClass}">${escapeHtml(value)}</mark>`;
}

function normalizeApiUrl(value) {
  const parsed = new URL(value.trim());
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('API URL must use HTTP or HTTPS.');
  }
  if (
    parsed.username
    || parsed.password
    || parsed.pathname !== '/'
    || parsed.search
    || parsed.hash
  ) {
    throw new Error('API URL cannot contain credentials, path, query, or fragment.');
  }
  const localHosts = new Set(['localhost', '127.0.0.1', '::1']);
  if (parsed.protocol !== 'https:' && !localHosts.has(parsed.hostname)) {
    throw new Error('Remote API connections must use HTTPS.');
  }
  return parsed.origin;
}

async function requestJson(path, options = {}) {
  const response = await fetch(API + path, {
    cache: 'no-store',
    ...options,
    headers: authHeaders(options.headers || {}),
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(body.detail || `${path} returned ${response.status}`);
    error.status = response.status;
    error.retryAfter = response.headers.get('Retry-After');
    throw error;
  }
  return body;
}

async function api(path) {
  return requestJson(path);
}

function showConnectionDialog(message = '') {
  $('#api-url').value = API;
  $('#api-key').value = '';
  $('#connection-error').textContent = message;
  $('#auth-gate').hidden = false;
  $('#api-key').focus();
}

function hideConnectionDialog() {
  $('#connection-error').textContent = '';
  $('#auth-gate').hidden = true;
}

async function connect() {
  const error = $('#connection-error');
  const button = $('#connect-submit');
  error.textContent = '';
  button.disabled = true;
  try {
    const apiUrl = normalizeApiUrl($('#api-url').value);
    const key = $('#api-key').value.trim();
    if (!key) {
      throw new Error('Enter the API key.');
    }
    API = apiUrl;
    sessionStorage.setItem('AI_SIEM_API', API);
    sessionStorage.setItem('AI_SIEM_API_KEY', key);
    if (!(await load())) {
      throw new Error('Connection failed. Check the URL and API key.');
    }
    hideConnectionDialog();
  } catch (connectionError) {
    sessionStorage.removeItem('AI_SIEM_API_KEY');
    error.textContent = connectionError.message;
  } finally {
    button.disabled = false;
  }
}

function disconnect() {
  connected = false;
  sessionStorage.removeItem('AI_SIEM_API_KEY');
  state = fallback;
  render();
  showConnectionDialog('Session disconnected.');
}

async function load() {
  if (!getToken()) {
    connected = false;
    state = fallback;
    render();
    return false;
  }
  try {
    const currentHunt = state.hunt || emptyHuntState();
    const currentHuntRequest = { ...(state.huntRequest || {}) };
    const currentHuntHistory = [...(state.huntHistory || [])];
    const session = await api('/api/session');
    const [events, alerts, incidents, anomalies, metrics, rules, operations, report] = await Promise.all([
      api('/api/events'),
      api('/api/alerts'),
      api('/api/incidents'),
      api('/api/anomalies'),
      api('/api/metrics'),
      api('/api/rules'),
      api('/api/operations/summary'),
      api('/api/reports/summary'),
    ]);
    const [notifications, readiness] = session.role === 'admin'
      ? await Promise.all([
          api('/api/notifications/status').catch(() => ({ enabled: false, channels: [], unavailable: true })),
          api('/api/readiness').catch(() => ({ ready: false, status: 'unavailable', checks: [] })),
        ])
      : [
          { enabled: false, channels: [], restricted: true },
          { ready: false, status: 'restricted', checks: [] },
        ];
    state = {
      session,
      notifications,
      readiness,
      report,
      hunt: currentHunt,
      huntRequest: currentHuntRequest,
      huntHistory: currentHuntHistory,
      events,
      alerts,
      incidents,
      anomalies,
      metrics,
      rules,
      operations,
    };
    connected = true;
    $('#backend-status').textContent = 'Backend connected';
    $('#backend-status').classList.remove('offline');
    $('#soc-source').textContent = 'FastAPI backend';
    $('#soc-mode').textContent = 'Live data';
  } catch (error) {
    connected = false;
    state = fallback;
    $('#backend-status').textContent = 'Backend offline or unauthorized';
    $('#backend-status').classList.add('offline');
    $('#soc-source').textContent = 'Unavailable';
    $('#soc-mode').textContent = 'Connection required';
  }
  render();
  return connected;
}

function render() {
  const now = new Date().toLocaleTimeString();
  $('#clock').textContent = now;
  $('#last-refresh').textContent = now;
  $('#metric-events').textContent = Number(state.metrics.total_events || 0).toLocaleString();
  $('#metric-critical').textContent = state.metrics.critical_alerts || 0;
  $('#metric-incidents').textContent = state.metrics.open_incidents || 0;
  $('#metric-risk').textContent = `${state.metrics.risk_score || 0}/100`;
  $('#open-alerts').textContent = state.alerts.length;
  $('#session-role').textContent = String(state.session.role || 'viewer').toUpperCase();
  $('#metric-unassigned').textContent = state.operations.unassigned_alerts || 0;
  $('#metric-sla').textContent = (
    Number(state.operations.breached_alert_slas || 0)
    + Number(state.operations.breached_incident_slas || 0)
  );
  $('#run-analysis').disabled = !canOperate();

  renderAlerts();
  renderIncidents();
  renderNotifications();
  renderReadiness();
  renderReports();
  renderHunt();

  $('#anomalies-list').innerHTML = state.anomalies.map((anomaly) => {
    const features = Object.entries(anomaly.contributing_features || {})
      .map(([key, value]) => {
        const displayValue = Array.isArray(value) ? value.join('|') : value;
        return `${escapeHtml(key)}=${escapeHtml(displayValue)}`;
      })
      .join(' · ');
    return `
      <div class="incident">
        <strong>${escapeHtml(anomaly.anomaly_id)}</strong>
        <span>${escapeHtml(anomaly.reason)}</span>
        ${badge(`${Math.round((Number(anomaly.anomaly_score) || 0) * 100)} score`)}
        <small>${escapeHtml(anomaly.entity)} · ${features}</small>
      </div>
    `;
  }).join('');

  $('#detections-body').innerHTML = state.rules.map((rule) => `
    <tr>
      <td>${escapeHtml(rule.rule_id)}</td>
      <td>${escapeHtml(rule.name)}</td>
      <td>${badge(rule.severity)}</td>
      <td>${escapeHtml(rule.tactic)}</td>
      <td>${escapeHtml(rule.technique)}</td>
    </tr>
  `).join('');

  renderDistribution('#source-distribution', state.metrics.source_distribution || {});
  renderDistribution('#event-type-distribution', state.metrics.event_type_distribution || {});
  renderMitre();
  renderNarrative();
  renderActivity();
}

function renderNotifications() {
  const container = $('#notification-channels');
  const testButton = $('#notification-test');
  if (!canAdminister()) {
    container.innerHTML = '<div class="content-item"><span>Admin access is required to inspect notification configuration.</span></div>';
    testButton.disabled = true;
    return;
  }
  const channels = state.notifications.channels || [];
  container.innerHTML = channels.length
    ? channels.map((channel) => `
        <div class="content-item">
          <span>${escapeHtml(channel.kind)}</span>
          ${badge(channel.enabled ? 'Enabled' : 'Disabled')}
        </div>
      `).join('')
    : '<div class="content-item"><span>Notification status is unavailable.</span></div>';
  testButton.disabled = !state.notifications.enabled;
}

function readinessDetail(check) {
  const detail = check.detail || {};
  if (check.name === 'credentials') {
    return `Configured roles: ${(detail.configured_roles || []).join(', ') || 'none'}`;
  }
  if (check.name === 'storage') {
    return `${detail.backend || 'unknown'} · ${Number(detail.stored_events || 0).toLocaleString()} stored events`;
  }
  if (check.name === 'analysis') {
    return `${Number(detail.alerts || 0)} alerts · ${Number(detail.incidents || 0)} incidents · ${Number(detail.open_alerts || 0)} open`;
  }
  if (check.name === 'notifications') {
    const enabled = (detail.channels || []).filter((channel) => channel.enabled).length;
    return `${enabled} enabled channel${enabled === 1 ? '' : 's'} · optional`;
  }
  return 'No sensitive details exposed';
}

function renderReadiness() {
  const container = $('#readiness-checks');
  if (!canAdminister()) {
    container.innerHTML = '<div class="content-item"><span>Admin access is required to inspect deployment readiness.</span></div>';
    return;
  }
  const checks = state.readiness.checks || [];
  container.innerHTML = checks.length
    ? checks.map((check) => `
        <div class="readiness-item">
          <div><strong>${escapeHtml(check.name)}</strong><span>${escapeHtml(readinessDetail(check))}</span></div>
          ${badge(check.status)}
        </div>
      `).join('')
    : '<div class="content-item"><span>Readiness status is unavailable.</span></div>';
}

function renderReports() {
  const overview = state.report.overview || {};
  const cards = [
    ['Events', Number(overview.total_events || 0).toLocaleString()],
    ['Alerts', Number(overview.total_alerts || 0).toLocaleString()],
    ['Incidents', Number(overview.total_incidents || 0).toLocaleString()],
    ['Open alerts', Number(overview.open_alerts || 0).toLocaleString()],
    ['SLA breaches', (
      Number(overview.breached_alert_slas || 0)
      + Number(overview.breached_incident_slas || 0)
    ).toLocaleString()],
    ['Risk score', `${Number(overview.risk_score || 0)}/100`],
  ];
  $('#report-summary').innerHTML = cards.map(([label, value]) => `
    <div class="report-stat"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>
  `).join('');
  $('#export-json').disabled = !canOperate();
  $('#export-csv').disabled = !canOperate();
}

async function downloadReport(format) {
  if (!canOperate() || !['json', 'csv'].includes(format)) return;
  const result = $('#report-result');
  const buttons = [$('#export-json'), $('#export-csv')];
  buttons.forEach((button) => { button.disabled = true; });
  result.textContent = `Preparing de-identified ${format.toUpperCase()} evidence...`;
  try {
    const response = await fetch(`${API}/api/reports/export?format=${format}`, {
      cache: 'no-store',
      headers: authHeaders(),
    });
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.detail || `Export returned ${response.status}`);
    }
    const blob = await response.blob();
    const objectUrl = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = objectUrl;
    anchor.download = `ai-siem-evidence.${format}`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(objectUrl);
    result.textContent = `${format.toUpperCase()} evidence downloaded without raw targets.`;
  } catch (error) {
    if (error.status === 429) {
      const retryAfter = /^\d+$/.test(error.retryAfter || '')
        ? `${error.retryAfter} second${error.retryAfter === '1' ? '' : 's'}`
        : 'a short interval';
      result.textContent = `Hunt capacity is busy. Retry after ${retryAfter}; your filters were preserved.`;
    } else {
      result.textContent = error.message;
    }
  } finally {
    buttons.forEach((button) => { button.disabled = !canOperate(); });
  }
}

function formatHuntTime(value) {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? String(value || '—') : parsed.toLocaleString();
}

function huntPivotButton(field, value, label) {
  if (!value) return '';
  return `<button class="pivot-chip" type="button" data-hunt-field="${field}" data-hunt-value="${escapeHtml(value)}">${escapeHtml(label)}</button>`;
}

function renderHuntFacet(field, selector, label) {
  const facets = state.hunt.facets?.[field] || [];
  $(selector).innerHTML = `
    <strong>${escapeHtml(label)}</strong>
    <div>${facets.length
    ? facets.map((facet) => `
        <button class="facet-chip" type="button" data-hunt-field="${field}" data-hunt-value="${escapeHtml(facet.value)}">
          <span>${escapeHtml(facet.value)}</span><b>${Number(facet.count || 0)}</b>
        </button>
      `).join('')
    : '<span class="facet-empty">No values</span>'}</div>
  `;
}

function renderHunt() {
  const hunt = state.hunt || emptyHuntState();
  const rawToggle = $('#hunt-raw');
  rawToggle.disabled = !canViewRawEvents();
  if (!canViewRawEvents()) rawToggle.checked = false;

  $('#hunt-matched').textContent = Number(hunt.total_matches || 0).toLocaleString();
  $('#hunt-scanned').textContent = Number(hunt.scope?.scanned_events || 0).toLocaleString();
  $('#hunt-available').textContent = Number(hunt.scope?.available_events || 0).toLocaleString();
  $('#hunt-scope').textContent = hunt.scope?.scan_truncated ? 'Recent bounded scope' : 'Full active set';

  renderHuntFacet('source', '#hunt-facet-source', 'Sources');
  renderHuntFacet('event_type', '#hunt-facet-type', 'Event types');
  renderHuntFacet('status', '#hunt-facet-status', 'Statuses');
  renderHuntFacet('asset', '#hunt-facet-asset', 'Assets');
  renderHuntFacet('user', '#hunt-facet-user', 'Users');
  renderHuntFacet('src_ip', '#hunt-facet-ip', 'Source IPs');

  $('#hunt-body').innerHTML = hunt.has_run
    ? (hunt.events || []).map((event) => {
        const evidence = event.raw_log || event.message || event.command_line || 'No preview';
        return `
          <tr>
            <td>${escapeHtml(formatHuntTime(event.timestamp))}<br><small>${escapeHtml(event.id)}</small></td>
            <td>${escapeHtml(event.source)}<br><small>${escapeHtml(event.event_type)}</small></td>
            <td>${escapeHtml(event.asset)}</td>
            <td>${escapeHtml(event.user)}<br><small>${escapeHtml(event.src_ip)}</small></td>
            <td>${badge(event.status)}</td>
            <td class="hunt-evidence">${escapeHtml(evidence)}</td>
            <td><div class="pivot-actions">
              ${huntPivotButton('asset', event.asset, 'Asset')}
              ${huntPivotButton('user', event.user, 'User')}
              ${huntPivotButton('src_ip', event.src_ip, 'IP')}
            </div></td>
          </tr>
        `;
      }).join('') || '<tr><td colspan="7" class="empty-row">No telemetry matched this hunt.</td></tr>'
    : '<tr><td colspan="7" class="empty-row">Run a structured hunt to inspect telemetry.</td></tr>';

  const pageStart = hunt.total_matches ? Number(hunt.offset || 0) + 1 : 0;
  const pageEnd = Number(hunt.offset || 0) + (hunt.events || []).length;
  $('#hunt-page').textContent = hunt.has_run
    ? `${pageStart}–${pageEnd} of ${Number(hunt.total_matches || 0).toLocaleString()}`
    : 'No results';
  $('#hunt-prev').disabled = !hunt.has_run || Number(hunt.offset || 0) === 0;
  $('#hunt-next').disabled = !hunt.has_run || !hunt.has_more;

  $('#hunt-history').innerHTML = state.huntHistory.length
    ? state.huntHistory.map((item) => `
        <div class="hunt-history-item">
          <span>${escapeHtml(item.label)}</span>
          <small>${escapeHtml(item.time)} · ${Number(item.matches || 0)} matches</small>
        </div>
      `).join('')
    : '<div class="content-item"><span>No hunts in this browser session.</span></div>';
}

function huntTimeValue(selector, name) {
  const value = $(selector).value;
  if (!value) return null;
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    throw new Error(`${name} is invalid.`);
  }
  return parsed.toISOString();
}

function buildHuntPayload() {
  const payload = {
    q: $('#hunt-q').value.trim(),
    source: $('#hunt-source').value.trim(),
    event_type: $('#hunt-type').value.trim(),
    asset: $('#hunt-asset').value.trim(),
    user: $('#hunt-user').value.trim(),
    src_ip: $('#hunt-ip').value.trim(),
    status: $('#hunt-status').value.trim(),
    start_time: huntTimeValue('#hunt-start', 'Start time'),
    end_time: huntTimeValue('#hunt-end', 'End time'),
    sort: $('#hunt-sort').value,
    limit: Number($('#hunt-limit').value),
    include_raw: $('#hunt-raw').checked && canViewRawEvents(),
  };
  return Object.fromEntries(
    Object.entries(payload).filter(([, value]) => value !== '' && value !== null),
  );
}

function huntHistoryLabel(payload) {
  const labels = Object.entries(payload)
    .filter(([key, value]) => !['limit', 'sort', 'include_raw'].includes(key) && value)
    .map(([key, value]) => `${key.replace('_', ' ')}: ${value}`);
  return labels.join(' · ') || 'All recent telemetry';
}

async function runHunt(event, offset = 0, recordHistory = true) {
  if (event) event.preventDefault();
  const button = $('#hunt-submit');
  const result = $('#hunt-result');
  button.disabled = true;
  result.textContent = 'Running bounded hunt...';
  try {
    const payload = recordHistory
      ? buildHuntPayload()
      : { ...(state.huntRequest || {}) };
    delete payload.offset;
    if (offset > 0) payload.offset = offset;
    const response = await requestJson('/api/hunt', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    state.hunt = { ...response, has_run: true };
    state.huntRequest = { ...payload };
    delete state.huntRequest.offset;
    if (recordHistory) {
      state.huntHistory = [{
        label: huntHistoryLabel(payload),
        time: new Date().toLocaleTimeString(),
        matches: response.total_matches || 0,
      }, ...state.huntHistory].slice(0, 8);
    }
    result.textContent = `${response.total_matches || 0} matches in ${response.scope?.scanned_events || 0} inspected events.`;
    renderHunt();
  } catch (error) {
    result.textContent = error.message;
  } finally {
    button.disabled = false;
  }
}

function paginateHunt(direction) {
  const hunt = state.hunt || emptyHuntState();
  const limit = Number(hunt.limit || $('#hunt-limit').value || 100);
  const offset = Math.max(0, Number(hunt.offset || 0) + (direction * limit));
  runHunt(null, offset, false);
}

function resetHunt() {
  $('#hunt-form').reset();
  state.hunt = emptyHuntState();
  state.huntRequest = {};
  $('#hunt-result').textContent = '';
  renderHunt();
}

function applyHuntPivot(button) {
  const controls = {
    source: '#hunt-source',
    event_type: '#hunt-type',
    status: '#hunt-status',
    asset: '#hunt-asset',
    user: '#hunt-user',
    src_ip: '#hunt-ip',
  };
  const selector = controls[button.dataset.huntField];
  if (!selector || !button.dataset.huntValue) return;
  $(selector).value = button.dataset.huntValue;
  runHunt();
}

async function testNotificationChannels() {
  if (!canAdminister() || !state.notifications.enabled) return;
  const button = $('#notification-test');
  const result = $('#notification-result');
  button.disabled = true;
  result.textContent = 'Sending bounded test...';
  try {
    const response = await requestJson('/api/notifications/test', { method: 'POST' });
    result.textContent = `${response.delivered || 0} delivered · ${response.failed || 0} failed · ${response.skipped || 0} skipped`;
  } catch (error) {
    result.textContent = error.message;
  } finally {
    button.disabled = !state.notifications.enabled;
  }
}

function renderAlerts() {
  const severity = $('#alert-severity').value;
  const status = $('#alert-status').value;
  const search = $('#alert-search').value.trim().toLowerCase();
  const alerts = state.alerts.filter((alert) => {
    const searchable = [
      alert.alert_id,
      alert.title,
      alert.rule_id,
      alert.asset,
      alert.user,
      alert.src_ip,
      alert.assigned_to,
    ].join(' ').toLowerCase();
    return (severity === 'all' || alert.severity === severity)
      && (status === 'all' || alert.status === status)
      && (!search || searchable.includes(search));
  });

  $('#alerts-body').innerHTML = alerts.map((alert) => `
    <tr>
      <td>${escapeHtml(alert.alert_id)}</td>
      <td>${escapeHtml(alert.title)}<br><small>${escapeHtml(alert.rule_id)}</small></td>
      <td>${badge(alert.severity)}</td>
      <td>${Math.round((Number(alert.confidence) || 0) * 100)}%</td>
      <td>${escapeHtml(alert.tactic)}</td>
      <td>${escapeHtml(alert.technique)}</td>
      <td>${escapeHtml(alert.asset)}</td>
      <td>${escapeHtml(alert.user || alert.src_ip)}</td>
      <td>${badge(alert.status)}</td>
      <td>${escapeHtml(alert.assigned_to)}</td>
      <td class="${alert.sla_breached ? 'sla-breached' : ''}">${alert.sla_breached ? 'Breached' : 'On time'}</td>
      <td><button class="btn table-action" data-operation-type="alert" data-operation-id="${escapeHtml(alert.alert_id)}" data-operation-status="${escapeHtml(alert.status)}" data-operation-assignee="${escapeHtml(alert.assigned_to)}" ${canOperate() ? '' : 'disabled'}>Manage</button></td>
    </tr>
  `).join('');
  $('#alert-result-count').textContent = `${alerts.length} results`;
}

function renderIncidents() {
  const status = $('#incident-status').value;
  const incidents = state.incidents.filter(
    (incident) => status === 'all' || incident.status === status,
  );
  $('#incidents-list').innerHTML = incidents.map((incident) => `
    <div class="incident">
      <strong>${escapeHtml(incident.incident_id)}</strong>
      <span>${escapeHtml(incident.title)}</span>
      ${badge(incident.priority)}
      <em>${escapeHtml(incident.status)}</em>
      <small>${(incident.related_alert_ids || []).length} alerts · ${(incident.timeline || []).length} timeline events</small>
      <small>${(incident.related_alert_ids || []).map((id) => escapeHtml(id)).join(', ')}</small>
      <small>Owner: ${escapeHtml(incident.assigned_to || incident.owner)}</small>
      <small class="${incident.sla_breached ? 'sla-breached' : ''}">SLA: ${incident.sla_breached ? 'Breached' : 'On time'}</small>
      <button class="btn table-action" data-operation-type="incident" data-operation-id="${escapeHtml(incident.incident_id)}" data-operation-status="${escapeHtml(incident.status)}" data-operation-assignee="${escapeHtml(incident.assigned_to || incident.owner)}" ${canOperate() ? '' : 'disabled'}>Manage case</button>
    </div>
  `).join('');
}

function renderDistribution(selector, data) {
  const entries = Object.entries(data);
  $(selector).innerHTML = entries.length
    ? entries.map(([key, value]) => `
        <div class="content-item"><span>${escapeHtml(key)}</span>${badge(value)}</div>
      `).join('')
    : '<div class="content-item"><span>No data</span></div>';
}

function renderMitre() {
  const tactics = {};
  state.alerts.forEach((alert) => {
    const tactic = String(alert.tactic || 'Unmapped');
    tactics[tactic] = (tactics[tactic] || 0) + 1;
  });
  $('#mitre').innerHTML = Object.entries(tactics).map(([tactic, count]) => `
    <div><span>${escapeHtml(tactic)}</span><b>${count}</b></div>
  `).join('') || '<div><span>No active alerts</span><b>0</b></div>';
}

function renderNarrative() {
  const alert = [...state.alerts]
    .sort((first, second) => (second.confidence || 0) - (first.confidence || 0))[0];
  if (!alert) {
    $('#narrative').innerHTML = '<strong>No active detections</strong><span>Backend is reachable but no alerts are currently generated.</span>';
    return;
  }
  $('#narrative').innerHTML = `
    <strong>${escapeHtml(alert.severity)} activity on ${escapeHtml(alert.asset)}</strong>
    <span>${escapeHtml(alert.title)}. Rule <b>${escapeHtml(alert.rule_id)}</b> maps to
    <b>${escapeHtml(alert.tactic)}</b> / <b>${escapeHtml(alert.technique)}</b> with
    <b>${Math.round((Number(alert.confidence) || 0) * 100)}% confidence</b>.</span>
    <span><b>Action:</b> ${escapeHtml(alert.recommended_action)}</span>
  `;
}

function renderActivity() {
  const bars = [...$$('#bars span')];
  const timestamps = state.events
    .map((event) => Date.parse(event.timestamp))
    .filter((value) => Number.isFinite(value));
  const buckets = Array(bars.length).fill(0);
  if (timestamps.length) {
    const minimum = Math.min(...timestamps);
    const maximum = Math.max(...timestamps);
    const span = Math.max(maximum - minimum, 1);
    timestamps.forEach((timestamp) => {
      const index = Math.min(
        buckets.length - 1,
        Math.floor(((timestamp - minimum) / span) * buckets.length),
      );
      buckets[index] += 1;
    });
  }
  const peak = Math.max(...buckets, 1);
  bars.forEach((bar, index) => {
    const activityLevel = buckets[index]
      ? Math.max(1, Math.min(10, Math.ceil((buckets[index] / peak) * 10)))
      : 0;
    bar.className = `activity-level-${activityLevel}`;
    bar.title = `${buckets[index]} events`;
    bar.setAttribute('aria-label', `${buckets[index]} events`);
  });
}

async function runAnalysis() {
  if (!canOperate()) {
    return;
  }
  const top = [...state.alerts]
    .sort((first, second) => (second.confidence || 0) - (first.confidence || 0))[0];
  if (!top) {
    $('#analysis-box').innerHTML = '<strong>No alert selected</strong><span>No alert is available for triage.</span>';
    $('#response-list').innerHTML = '';
    switchView('analysis');
    return;
  }

  let analysis;
  try {
    const response = await fetch(`${API}/api/triage`, {
      method: 'POST',
      headers: authHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ alert_id: top.alert_id, action: 'frontend_review' }),
    });
    if (!response.ok) {
      throw new Error(`Triage returned ${response.status}`);
    }
    analysis = await response.json();
  } catch (error) {
    analysis = { alert_id: top.alert_id, status: 'offline_or_unauthorized' };
  }

  $('#analysis-box').innerHTML = `
    <strong>${escapeHtml(top.alert_id)} · ${escapeHtml(top.severity)}</strong>
    <span>${escapeHtml(top.title)} detected on ${escapeHtml(top.asset)}.</span>
    <span><b>MITRE:</b> ${escapeHtml(top.tactic)} · ${escapeHtml(top.technique)}</span>
    <span><b>Triage:</b> ${escapeHtml(analysis.status)}</span>
  `;
  $('#response-list').innerHTML = [
    top.recommended_action,
    'Validate affected asset',
    'Review related incidents',
    'Document analyst decision',
  ].map((item) => `<div class="response-item">${escapeHtml(item)}</div>`).join('');
  switchView('analysis');
}

let operationTarget = null;
const operationStatuses = {
  alert: ['open', 'acknowledged', 'investigating', 'resolved', 'false_positive'],
  incident: ['open', 'investigating', 'contained', 'resolved', 'closed'],
};

function openOperationEditor(button) {
  if (!canOperate()) {
    return;
  }
  const type = button.dataset.operationType;
  const id = button.dataset.operationId;
  if (!operationStatuses[type] || !id) {
    return;
  }
  operationTarget = { type, id };
  const source = type === 'alert'
    ? state.alerts.find((item) => item.alert_id === id)
    : state.incidents.find((item) => item.incident_id === id);
  $('#operation-title').textContent = `${type === 'alert' ? 'Manage alert' : 'Manage incident'} · ${id}`;
  $('#operation-status').innerHTML = operationStatuses[type]
    .map((status) => `<option value="${status}">${status.replace('_', ' ')}</option>`)
    .join('');
  $('#operation-status').value = source?.status || button.dataset.operationStatus;
  $('#operation-assignee').value = source?.assigned_to || button.dataset.operationAssignee || '';
  $('#operation-note').value = source?.resolution_note || '';
  $('#operation-error').textContent = '';
  $('#operation-dialog').hidden = false;
  $('#operation-assignee').focus();
}

function closeOperationEditor() {
  operationTarget = null;
  $('#operation-error').textContent = '';
  $('#operation-dialog').hidden = true;
}

async function saveOperation(event) {
  event.preventDefault();
  if (!operationTarget || !canOperate()) {
    return;
  }
  const button = $('#operation-save');
  const error = $('#operation-error');
  button.disabled = true;
  error.textContent = '';
  try {
    const path = operationTarget.type === 'alert'
      ? `/api/alerts/${encodeURIComponent(operationTarget.id)}`
      : `/api/incidents/${encodeURIComponent(operationTarget.id)}`;
    await requestJson(path, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        status: $('#operation-status').value,
        assigned_to: $('#operation-assignee').value.trim() || 'unassigned',
        resolution_note: $('#operation-note').value.trim(),
      }),
    });
    closeOperationEditor();
    await load();
  } catch (operationError) {
    error.textContent = operationError.message;
  } finally {
    button.disabled = false;
  }
}

function switchView(id) {
  const button = [...$$('nav button')].find((item) => item.dataset.view === id);
  const view = document.getElementById(id);
  if (!button || !view) {
    return;
  }
  $$('nav button').forEach((item) => item.classList.toggle('active', item === button));
  $$('.view').forEach((item) => item.classList.remove('active'));
  view.classList.add('active');
  $('#view-title').textContent = button.textContent;
}

$$('nav button').forEach((button) => {
  button.onclick = () => switchView(button.dataset.view);
});
$('#refresh').onclick = load;
$('#run-analysis').onclick = runAnalysis;
$('#connection-settings').onclick = () => showConnectionDialog();
$('#disconnect').onclick = disconnect;
$('#connect-submit').onclick = connect;
$('#connection-form').onsubmit = (event) => {
  event.preventDefault();
  connect();
};
$('#alert-severity').onchange = renderAlerts;
$('#alert-status').onchange = renderAlerts;
$('#alert-search').oninput = renderAlerts;
$('#incident-status').onchange = renderIncidents;
$('#operation-form').onsubmit = saveOperation;
$('#operation-cancel').onclick = closeOperationEditor;
$('#notification-test').onclick = testNotificationChannels;
$('#export-json').onclick = () => downloadReport('json');
$('#export-csv').onclick = () => downloadReport('csv');
$('#hunt-form').onsubmit = runHunt;
$('#hunt-reset').onclick = resetHunt;
$('#hunt-prev').onclick = () => paginateHunt(-1);
$('#hunt-next').onclick = () => paginateHunt(1);
document.addEventListener('click', (event) => {
  if (!(event.target instanceof Element)) return;
  const huntPivot = event.target.closest('[data-hunt-field]');
  if (huntPivot) {
    applyHuntPivot(huntPivot);
    return;
  }
  const button = event.target.closest('[data-operation-type]');
  if (button) {
    openOperationEditor(button);
  }
});

setInterval(() => {
  $('#clock').textContent = new Date().toLocaleTimeString();
}, 1000);
setInterval(() => {
  if (connected) {
    load();
  }
}, 15000);

if (getToken()) {
  load().then((isConnected) => {
    if (!isConnected) {
      showConnectionDialog('Stored tab session is no longer valid.');
    }
  });
} else {
  render();
  showConnectionDialog();
}
