import React, {useEffect, useMemo, useState} from 'react';
import {createRoot} from 'react-dom/client';
import './style.css';

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000';

function useApi(path){
  const [data,setData]=useState(null);
  const [error,setError]=useState(null);
  useEffect(()=>{
    setError(null);
    fetch(`${API}${path}`)
      .then(r=>{if(!r.ok) throw new Error(`HTTP ${r.status}`); return r.json();})
      .then(setData)
      .catch(e=>setError(e.message));
  },[path]);
  return {data,error};
}

function matchesFilter(item, filters){
  return Object.entries(filters).every(([k,v]) => !v || String(item[k] || '').toLowerCase().includes(v.toLowerCase()));
}

function App(){
  const [view,setView]=useState('events');
  const [selectedIncident,setSelectedIncident]=useState(null);
  const [filters,setFilters]=useState({severity:'',source:'',asset:'',user:'',tactic:''});
  const health=useApi('/api/health');
  const metrics=useApi('/api/metrics');
  const {data,error}=useApi(`/api/${view}`);
  const offline = Boolean(health.error || error);
  const tabs=['events','alerts','incidents','anomalies','rules'];
  const rows = useMemo(() => Array.isArray(data) ? data.filter(x => matchesFilter(x, filters)) : [], [data, filters]);

  const selected = rows.find(x => x.incident_id === selectedIncident);

  return <div className="app">
    <aside>
      <h1>AI-SIEM</h1>
      <p>Live SOC Command Center</p>
      {tabs.map(t=><button key={t} className={view===t?'active':''} onClick={()=>{setView(t); setSelectedIncident(null)}}>{t}</button>)}
    </aside>

    <main>
      <header>
        <div>
          <h2>{view.toUpperCase()}</h2>
          <span>Backend: {offline ? 'OFFLINE / DATA NOT LIVE' : 'online'} · API {API}</span>
        </div>
      </header>

      {offline && <div className="offline">Backend is offline or unreachable. The dashboard does not silently replace live API data with fake data.</div>}

      {metrics.data && <section className="cards">
        <div>Events <b>{metrics.data.total_events}</b></div>
        <div>Alerts <b>{metrics.data.total_alerts}</b></div>
        <div>Open incidents <b>{metrics.data.open_incidents}</b></div>
        <div>Risk score <b>{metrics.data.risk_score}</b></div>
      </section>}

      <section className="filters">
        {Object.keys(filters).map(k => <input key={k} placeholder={`filter ${k}`} value={filters[k]} onChange={e=>setFilters({...filters,[k]:e.target.value})}/>)}
      </section>

      {view === 'incidents' && selected && <section className="detail">
        <h3>{selected.title}</h3>
        <p><b>Priority:</b> {selected.priority} · <b>Status:</b> {selected.status} · <b>Owner:</b> {selected.owner}</p>
        <p><b>Related alerts:</b> {(selected.related_alert_ids || []).join(', ')}</p>
        <h4>Timeline</h4>
        {(selected.timeline || []).map((t,i)=><div className="timeline" key={i}>{t.timestamp} — {t.title} — {t.asset || ''} {t.user || ''} {t.src_ip || ''}</div>)}
      </section>}

      <section className="panel">
        {rows.map((x,i)=><article className="row" key={i} onClick={()=>x.incident_id && setSelectedIncident(x.incident_id)}>
          <div className="rowhead">
            <b>{x.title || x.name || x.incident_id || x.reason || x.event_type}</b>
            {x.severity && <span className={`sev ${x.severity}`}>{x.severity}</span>}
            {x.anomaly_score && <span className="score">score {Number(x.anomaly_score).toFixed(2)}</span>}
          </div>
          {x.reason && <p>{x.reason}</p>}
          {x.related_alert_ids && <p>related_alert_ids: {x.related_alert_ids.join(', ')}</p>}
          <pre>{JSON.stringify(x,null,2)}</pre>
        </article>)}
      </section>
    </main>
  </div>
}

createRoot(document.getElementById('root')).render(<App/>);
