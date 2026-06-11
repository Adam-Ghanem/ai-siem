import React, {useEffect, useState} from 'react';
import {createRoot} from 'react-dom/client';
import './style.css';

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000';

function useApi(path){
  const [data,setData]=useState(null);
  const [error,setError]=useState(null);
  useEffect(()=>{fetch(`${API}${path}`).then(r=>{if(!r.ok) throw new Error(r.status); return r.json();}).then(setData).catch(e=>setError(e.message));},[path]);
  return {data,error};
}

function App(){
  const [view,setView]=useState('alerts');
  const health=useApi('/api/health');
  const metrics=useApi('/api/metrics');
  const {data,error}=useApi(`/api/${view}`);
  const offline = health.error || error;
  const tabs=['events','alerts','incidents','anomalies','rules'];
  return <div className="app">
    <aside><h1>AI-SIEM</h1><p>Live SOC Command Center</p>{tabs.map(t=><button key={t} className={view===t?'active':''} onClick={()=>setView(t)}>{t}</button>)}</aside>
    <main>
      <header><div><h2>{view.toUpperCase()}</h2><span>Backend: {offline ? 'OFFLINE / NOT TRUSTED' : 'online'}</span></div></header>
      {offline && <div className="offline">Backend is offline or unreachable. This UI does not silently show fake live SOC data.</div>}
      {metrics.data && <section className="cards"><div>Events <b>{metrics.data.total_events}</b></div><div>Alerts <b>{metrics.data.total_alerts}</b></div><div>Incidents <b>{metrics.data.total_incidents}</b></div><div>Anomalies <b>{metrics.data.total_anomalies}</b></div></section>}
      <section className="panel">{(data||[]).map((x,i)=><article className="row" key={i}><b>{x.title || x.name || x.incident_id || x.reason || x.event_type}</b><pre>{JSON.stringify(x,null,2)}</pre></article>)}</section>
    </main>
  </div>
}

createRoot(document.getElementById('root')).render(<App/>);
