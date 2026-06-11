const API = localStorage.getItem('AI_SIEM_API') || 'http://localhost:8000';
let state = { metrics: {}, alerts: [], incidents: [], detections: [], dashboards: [], parsers: [], workflows: [], report: {} };

const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);

const fallback = {
  metrics: { total_events: 43200, critical_alerts: 1, open_incidents: 3, risk_score: 72 },
  alerts: [
    { id: 'ALT-1041', title: 'Multiple failed SSH attempts from external IP', severity: 'Critical', confidence: 94, source: 'Linux Auth', asset: 'srv-prod-01', tactic: 'Credential Access', technique: 'T1110', status: 'New', recommendation: 'Block source IP and review successful logins.' },
    { id: 'ALT-1042', title: 'Encoded PowerShell command execution', severity: 'High', confidence: 88, source: 'EDR', asset: 'win-fin-07', tactic: 'Execution', technique: 'T1059.001', status: 'Investigating', recommendation: 'Isolate endpoint and collect process tree.' }
  ],
  incidents: [
    { id: 'INC-219', title: 'Suspected brute-force campaign', priority: 'P1', status: 'Investigating', owner: 'SOC L1', related_alerts: 14 },
    { id: 'INC-218', title: 'PowerShell execution chain', priority: 'P2', status: 'Containment', owner: 'SOC L2', related_alerts: 6 }
  ],
  detections: [
    { id: 'DET-001', name: 'SSH Brute Force', severity: 'High', tactic: 'Credential Access', technique: 'T1110' },
    { id: 'DET-002', name: 'Suspicious PowerShell', severity: 'High', tactic: 'Execution', technique: 'T1059.001' }
  ],
  dashboards: ['soc_overview', 'mitre_coverage', 'incident_response'],
  parsers: ['linux_auth', 'windows_event', 'firewall_syslog', 'cloudtrail'],
  workflows: [
    { name: 'Block IP', action: 'Firewall containment', status: 'Ready' },
    { name: 'Isolate Host', action: 'Endpoint containment', status: 'Ready' },
    { name: 'Reset User Password', action: 'Identity response', status: 'Ready' }
  ],
  report: { title: 'Weekly SOC Summary', critical_findings: 3, open_incidents: 3, top_tactic: 'Credential Access' }
};

function badge(v){const x=String(v).toLowerCase();let c=x.includes('critical')||x==='p1'?'critical':x.includes('high')||x==='p2'?'high':x.includes('medium')?'medium':'';return `<mark class="${c}">${v}</mark>`}
async function api(path){const r=await fetch(API+path,{cache:'no-store'}); if(!r.ok) throw new Error(path); return r.json();}

async function load(){
  try{
    const [metrics, alerts, incidents, detections, dashboards, parsers, workflows, report] = await Promise.all([
      api('/api/metrics'), api('/api/alerts'), api('/api/incidents'), api('/api/detections'), api('/api/dashboards'), api('/api/parsers'), api('/api/workflows'), api('/api/reports/summary')
    ]);
    state={metrics,alerts,incidents,detections,dashboards,parsers,workflows,report};
    $('#backend-status').textContent='Backend connected';
    $('#soc-source').textContent='Backend API';
    $('#soc-mode').textContent='Live Monitor';
  }catch(e){
    state=fallback;
    $('#backend-status').textContent='Demo mode · backend offline';
    $('#soc-source').textContent='Fallback data';
    $('#soc-mode').textContent='Presentation Mode';
  }
  render();
}

function render(){
  const now=new Date().toLocaleTimeString();
  $('#clock').textContent=now; $('#last-refresh').textContent=now;
  $('#metric-events').textContent=Number(state.metrics.total_events||0).toLocaleString();
  $('#metric-critical').textContent=state.metrics.critical_alerts||0;
  $('#metric-incidents').textContent=state.metrics.open_incidents||0;
  $('#metric-risk').textContent=(state.metrics.risk_score||0)+'/100';
  $('#open-alerts').textContent=state.alerts.length;
  $('#alerts-body').innerHTML=state.alerts.map(a=>`<tr><td>${a.id}</td><td>${a.title}</td><td>${badge(a.severity)}</td><td>${a.confidence}%</td><td>${a.source}</td><td>${a.asset}</td><td>${a.tactic}</td><td>${badge(a.status)}</td></tr>`).join('');
  $('#incidents-list').innerHTML=state.incidents.map(i=>`<div class="incident"><strong>${i.id}</strong><span>${i.title}</span>${badge(i.priority)}<em>${i.status}</em><small>${i.related_alerts} alerts · ${i.owner}</small></div>`).join('');
  $('#detections-body').innerHTML=state.detections.map(d=>`<tr><td>${d.id}</td><td>${d.name}</td><td>${badge(d.severity)}</td><td>${d.tactic}</td><td>${d.technique}</td></tr>`).join('');
  $('#dashboards-list').innerHTML=state.dashboards.map(x=>`<div class="content-item"><span>${x}</span>${badge('Ready')}</div>`).join('');
  $('#parsers-list').innerHTML=state.parsers.map(x=>`<div class="content-item"><span>${x}</span>${badge('Enabled')}</div>`).join('');
  $('#workflows-list').innerHTML=state.workflows.map(x=>`<div class="content-item"><span>${x.name}</span>${badge(x.status)}</div>`).join('');
  $('#reports-list').innerHTML=`<div class="mini"><strong>${state.report.title}</strong><br><span>Executive summary</span></div><div class="mini"><strong>${state.report.critical_findings}</strong><br><span>Critical findings</span></div><div class="mini"><strong>${state.report.open_incidents}</strong><br><span>Open incidents</span></div>`;
  renderMitre(); renderNarrative(); animateBars();
}
function renderMitre(){const m={};state.alerts.forEach(a=>m[a.tactic]=(m[a.tactic]||0)+1);$('#mitre').innerHTML=Object.entries(m).map(([k,v])=>`<div><span>${k}</span><b>${v}</b></div>`).join('')}
function renderNarrative(){const a=[...state.alerts].sort((x,y)=>y.confidence-x.confidence)[0]; if(!a)return; $('#narrative').innerHTML=`<strong>${a.severity} activity on ${a.asset}</strong><span>${a.title}. Mapped to <b>${a.tactic}</b> with <b>${a.confidence}% confidence</b>.</span><span><b>Action:</b> ${a.recommendation}</span>`}
function animateBars(){$$('#bars span').forEach(b=>b.style.height=(35+Math.floor(Math.random()*60))+'%')}
async function runAnalysis(){let analysis; try{const r=await fetch(API+'/api/triage',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});analysis=await r.json()}catch(e){const a=state.alerts[0];analysis={alert_id:a.id,severity:a.severity,assessment:`${a.title} detected on ${a.asset}.`,mitre_tactic:a.tactic,mitre_technique:a.technique,recommended_actions:[a.recommendation,'Validate affected asset','Check related alerts','Document response actions']}} $('#analysis-box').innerHTML=`<strong>${analysis.alert_id} · ${analysis.severity}</strong><span>${analysis.assessment}</span><span><b>MITRE:</b> ${analysis.mitre_tactic} · ${analysis.mitre_technique}</span>`; $('#response-list').innerHTML=analysis.recommended_actions.map(x=>`<div class="response-item">${x}</div>`).join(''); switchView('analysis')}
function switchView(id){$$('nav button').forEach(b=>b.classList.toggle('active',b.dataset.view===id));$$('.view').forEach(v=>v.classList.remove('active'));$('#'+id).classList.add('active');$('#view-title').textContent=document.querySelector(`[data-view="${id}"]`).textContent}
$$('nav button').forEach(b=>b.onclick=()=>switchView(b.dataset.view));$('#refresh').onclick=load;$('#run-analysis').onclick=runAnalysis;setInterval(()=>$('#clock').textContent=new Date().toLocaleTimeString(),1000);setInterval(load,15000);setInterval(animateBars,3500);load();
