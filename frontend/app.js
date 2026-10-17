const API = localStorage.getItem('AI_SIEM_API') || 'http://localhost:8000';
let state = { metrics: {}, events: [], alerts: [], incidents: [], anomalies: [], rules: [] };
const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);
const safe = (v, fallback = '—') => AISiemSecurity.escapeHtml(v === null || v === undefined || v === '' ? fallback : v);
const fallback = { metrics: { total_events: 0, critical_alerts: 0, open_incidents: 0, risk_score: 0, source_distribution: {}, event_type_distribution: {} }, events: [], alerts: [], incidents: [], anomalies: [], rules: [] };
let apiToken = ''; // Volatile: not persisted in browser storage.
function authHeaders(extra={}){return apiToken?{...extra,Authorization:`Bearer ${apiToken}`}:{...extra};}
function badge(v){const x=String(v||'').toLowerCase();const c=x.includes('critical')||x==='p1'?'critical':x.includes('high')||x==='p2'?'high':x.includes('medium')?'medium':'';return `<mark class="${c}">${safe(v)}</mark>`;}
async function api(path){const r=await fetch(API+path,{cache:'no-store',headers:authHeaders()}); if(!r.ok) throw new Error(`${path} returned ${r.status}`); return r.json();}
async function load(){
  try{
    const [events, alerts, incidents, anomalies, metrics, rules] = await Promise.all([api('/api/events'), api('/api/alerts'), api('/api/incidents'), api('/api/anomalies'), api('/api/metrics'), api('/api/rules')]);
    state={events,alerts,incidents,anomalies,metrics,rules};
    $('#backend-status').textContent='Backend connected'; $('#backend-status').classList.remove('offline'); $('#soc-source').textContent='FastAPI backend'; $('#soc-mode').textContent='Live data';
  }catch(e){
    state=fallback; $('#backend-status').textContent='Backend offline, unauthorized, or missing API key (use Connect)'; $('#backend-status').classList.add('offline'); $('#soc-source').textContent='Unavailable'; $('#soc-mode').textContent='Offline/auth warning';
  }
  render();
}
function render(){
  const now=new Date().toLocaleTimeString(); $('#clock').textContent=now; $('#last-refresh').textContent=now;
  $('#metric-events').textContent=Number(state.metrics.total_events||0).toLocaleString(); $('#metric-critical').textContent=state.metrics.critical_alerts||0; $('#metric-incidents').textContent=state.metrics.open_incidents||0; $('#metric-risk').textContent=(state.metrics.risk_score||0)+'/100'; $('#open-alerts').textContent=state.alerts.length;
  $('#alerts-body').innerHTML=state.alerts.map(a=>`<tr><td>${safe(a.alert_id)}</td><td>${safe(a.title)}<br><small>${safe(a.rule_id)}</small></td><td>${badge(a.severity)}</td><td>${Math.round((Number(a.confidence)||0)*100)}%</td><td>${safe(a.tactic)}</td><td>${safe(a.technique)}</td><td>${safe(a.asset)}</td><td>${safe(a.user || a.src_ip)}</td></tr>`).join('');
  $('#incidents-list').innerHTML=state.incidents.map(i=>`<div class="incident"><strong>${safe(i.incident_id)}</strong><span>${safe(i.title)}</span>${badge(i.priority)}<em>${safe(i.status)}</em><small>${(i.related_alert_ids||[]).length} alerts · ${(i.timeline||[]).length} timeline events</small><small>${safe((i.related_alert_ids||[]).join(', '))}</small></div>`).join('');
  $('#anomalies-list').innerHTML=state.anomalies.map(a=>`<div class="incident"><strong>${safe(a.anomaly_id)}</strong><span>${safe(a.reason)}</span>${badge(Math.round((Number(a.anomaly_score)||0)*100)+' score')}<small>${safe(a.entity)} · ${safe(Object.entries(a.contributing_features||{}).map(([k,v])=>`${k}=${Array.isArray(v)?v.join('|'):v}`).join(' · '))}</small></div>`).join('');
  $('#detections-body').innerHTML=state.rules.map(d=>`<tr><td>${safe(d.rule_id)}</td><td>${safe(d.name)}</td><td>${badge(d.severity)}</td><td>${safe(d.tactic)}</td><td>${safe(d.technique)}</td></tr>`).join('');
  renderDistribution('#source-distribution', state.metrics.source_distribution || {}); renderDistribution('#event-type-distribution', state.metrics.event_type_distribution || {}); renderMitre(); renderSeverityDonut(); renderNarrative(); animateBars();
}
function renderDistribution(selector, data){const entries=Object.entries(data);$(selector).innerHTML=entries.length ? entries.map(([k,v])=>`<div class="content-item"><span>${safe(k)}</span>${badge(v)}</div>`).join('') : '<div class="content-item"><span>No data</span></div>';}
function renderMitre(){const m={};state.alerts.forEach(a=>m[a.tactic]=(m[a.tactic]||0)+1);$('#mitre').innerHTML=Object.entries(m).map(([k,v])=>`<div><span>${safe(k)}</span><b>${Number(v)||0}</b></div>`).join('') || '<div><span>No active alerts</span><b>0</b></div>';}
function renderSeverityDonut(){
  const segments = [
    ['critical','var(--red)'],
    ['high','var(--orange)'],
    ['medium','var(--yellow)'],
    ['low','var(--green)'],
  ];
  const counts = Object.fromEntries(segments.map(([key])=>[key,0]));
  for (const alert of state.alerts) {
    const level = String(alert.severity || '').toLowerCase();
    if (Object.prototype.hasOwnProperty.call(counts, level)) counts[level]++;
  }
  const total = Object.values(counts).reduce((sum,n)=>sum+n,0);
  const donut = $('.donut');
  if (!total) {
    donut.style.background = 'var(--surface2)';
    donut.setAttribute('aria-label', 'No severity distribution to display');
    return;
  }
  let offset=0;
  const stops=[];
  for (const [level,color] of segments) {
    const next=offset + counts[level]/total*100;
    if (next>offset) stops.push(`${color} ${offset}% ${next}%`);
    offset=next;
  }
  donut.style.background = `conic-gradient(${stops.join(', ')})`;
  donut.setAttribute('aria-label', segments.map(([level])=>`${level}: ${counts[level]}`).join('; '));
}
function renderNarrative(){const a=[...state.alerts].sort((x,y)=>(y.confidence||0)-(x.confidence||0))[0]; if(!a){$('#narrative').innerHTML='<strong>No active detections</strong><span>Backend is reachable but no alerts are currently generated.</span>';return;} $('#narrative').innerHTML=`<strong>${safe(a.severity)} activity on ${safe(a.asset)}</strong><span>${safe(a.title)}. Rule <b>${safe(a.rule_id)}</b> maps to <b>${safe(a.tactic)}</b> / <b>${safe(a.technique)}</b> with <b>${Math.round((Number(a.confidence)||0)*100)}% confidence</b>.</span><span><b>Action:</b> ${safe(a.recommended_action)}</span>`;}
function animateBars(){
  // Events currently loaded from the paginated API response, not synthetic bars.
  const counts = Array(7).fill(0);
  const now = Date.now();
  for (const event of state.events) {
    const timestamp = Date.parse(event.timestamp);
    if (!Number.isFinite(timestamp)) continue;
    const ago = Math.floor((now - timestamp) / 3600000);
    if (ago >= 0 && ago < 7) counts[6 - ago]++;
  }
  const highest = Math.max(1, ...counts);
  $('#bars span').forEach((bar, i) => {
    bar.style.height = `${counts[i] / highest * 100}%`;
    bar.title = `${counts[i]} events in hourly bucket ${i+1} of last seven hours`;
    bar.setAttribute('aria-label', bar.title);
  });
}
async function runAnalysis(){
  const top = [...state.alerts].sort((x,y)=>(y.confidence||0)-(x.confidence||0))[0];
  if (!top) {
    $('#analysis-box').textContent = 'No alert is available for triage.';
    $('#response-list').replaceChildren();
    switchView('analysis');
    return;
  }
  try {
    const response = await fetch(API+'/api/triage', {
      method: 'POST',
      headers: authHeaders({'Content-Type':'application/json'}),
      body: JSON.stringify({alert_id:top.alert_id,action:'frontend_review'})
    });
    if (!response.ok) throw new Error('HTTP '+response.status);
    const analysis = await response.json();
    $('#analysis-box').innerHTML = `<strong>${safe(top.alert_id)} · ${safe(top.severity)}</strong><span>${safe(top.title)} detected on ${safe(top.asset)}.</span><span><b>MITRE:</b> ${safe(top.tactic)} · ${safe(top.technique)}</span><span><b>Triage:</b> ${safe(analysis.status)}</span>`;
    $('#response-list').innerHTML = [top.recommended_action,'Validate affected asset','Review related incidents','Document analyst decision'].map(action=>`<div class="response-item">${safe(action)}</div>`).join('');
  } catch (error) {
    $('#analysis-box').textContent = 'Triage was not recorded (' + error.message + '). Check credentials and analyst permissions.';
    $('#response-list').replaceChildren();
  }
  switchView('analysis');
}
function switchView(id){$$('nav button').forEach(b=>b.classList.toggle('active',b.dataset.view===id));$$('.view').forEach(v=>v.classList.remove('active'));$('#'+id).classList.add('active');$('#view-title').textContent=document.querySelector(`[data-view="${id}"]`).textContent;}
$$('nav button').forEach(b=>b.onclick=()=>switchView(b.dataset.view));$('#refresh').onclick=load;$('#run-analysis').onclick=runAnalysis;setInterval(()=>$('#clock').textContent=new Date().toLocaleTimeString(),1000);setInterval(load,15000);$('#connect-token').onclick=()=>{
  const field = $('#api-token');
  apiToken = field.value.trim();
  field.value = '';
  load();
};
$('#api-token').addEventListener('keydown', event=>{
  if(event.key==='Enter') $('#connect-token').click();
});
load();
