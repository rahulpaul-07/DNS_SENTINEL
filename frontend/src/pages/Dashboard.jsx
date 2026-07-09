import React, { useState, useEffect, useMemo, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { connectSSE, fetchAlerts, fetchStats, uploadDataset, getExportCsvUrl } from '../services/api';
import { 
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, 
  AreaChart, Area, Cell, PieChart, Pie, CartesianGrid
} from 'recharts';
import { 
  Shield, AlertTriangle, Activity, Search, Filter, Terminal, 
  Zap, Crosshair, Cpu, UploadCloud, Download, X, Database,
  ArrowUpRight, Globe, Lock, Info, Server, Eye, ExternalLink,
  Command, ChevronRight, BarChart2, Clock, Unlock, Trash2, FileText
} from 'lucide-react';



const Dashboard = () => {
  const [traffic, setTraffic] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({ 
    total_requests: 0, total_alerts: 0, 
    risk_distribution: { High: 0, Medium: 0, Low: 0 } 
  });
  const [isConnected, setIsConnected] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");
  const [filterSeverity, setFilterSeverity] = useState("All");
  const [, setIsUploading] = useState(false);
  const [selectedLog, setSelectedLog] = useState(null); 
  const [manualQuery, setManualQuery] = useState("");
  const [manualIp, setManualIp] = useState("10.0.0.99");
  const [, setManualResult] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [reportMarkdown, setReportMarkdown] = useState(null);
  const [viewMode, setViewMode] = useState("Triage"); // Triage vs Topology
  const [sortConfig, setSortConfig] = useState({ key: 'timestamp', direction: 'desc' });
  const [liveClock, setLiveClock] = useState(new Date());

  const fileInputRef = useRef(null);
  const searchInputRef = useRef(null);

  // Feature: "/" shortcut to focus search
  useEffect(() => {
    const handler = (e) => {
      if (e.key === '/' && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA') {
        e.preventDefault();
        searchInputRef.current?.focus();
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  // Feature: Live clock
  useEffect(() => {
    const t = setInterval(() => setLiveClock(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    fetchAlerts().then(setAlerts).catch(console.error);
    fetchStats().then(setStats).catch(console.error);
    fetch("/api/traffic").then(r => r.json()).then(data => setTraffic(data)).catch(console.error);

    // Using SSE (Server-Sent Events) for a much more stable connection than WebSockets
    const sse = connectSSE(
      (data) => {
        setTraffic(prev => [data, ...prev].slice(0, 100));
        if (data.prediction === "Malicious" || data.risk_level !== "Low") {
          setAlerts(prev => [data, ...prev].slice(0, 50));
        }
      },
      () => setIsConnected(true),
      () => setIsConnected(false)
    );

    const statsInterval = setInterval(() => {
        fetchStats().then(setStats).catch(() => setIsConnected(false));
    }, 5000);

    return () => {
        if(sse) sse.close();
        clearInterval(statsInterval);
    };
  }, []);

  const handleManualAnalysis = async (e) => {
    e.preventDefault();
    if(!manualQuery) return;
    setIsAnalyzing(true);
    try {
      const res = await fetch("/api/analyze", {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: manualQuery, source_ip: manualIp })
      });
      const data = await res.json();
      setManualResult(data);
    } catch(err) {
      console.error(err);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    setIsUploading(true);
    try {
      const res = await uploadDataset(file);
      alert(res.message || "Background ingest started. Logs will appear live on dashboard.");
      
      // Initial refresh to see any existing data
      fetchAlerts().then(setAlerts).catch(console.error);
      fetchStats().then(setStats).catch(console.error);
      fetch("/api/traffic").then(r => r.json()).then(setTraffic).catch(console.error);
    } catch (err) {
      console.error("Upload failed", err);
      alert("Upload failed: " + err.message);
    } finally {
      setIsUploading(false);
      e.target.value = null;
    }
  };

  const handleArchive = async () => {
    if(!window.confirm("ARE YOU SURE? THIS WILL PERMANENTLY CLEAR THE ACTIVE FORENSIC LEDGER. ENSURE YOU HAVE DOWNLOADED THE EXPORT FIRST.")) return;
    
    try {
      const res = await fetch("/api/archive", { method: 'POST' });
      await res.json();
      // Hard refresh to ensure sync with truncated database
      window.location.reload();
    } catch(err) {
      console.error(err);
    }
  };

  const exportAuditPDF = () => {
    // Open in new tab for PDF download
    window.open("/api/export/pdf", "_blank");
  };

  const exportAlertsCSV = () => {
    // Streaming CSV download from the backend (respects the active severity filter).
    const riskLevel = filterSeverity && filterSeverity !== 'All' ? filterSeverity : null;
    window.open(getExportCsvUrl(riskLevel), "_blank");
  };

  // Toggle column sort direction; drives the sortedTraffic memo and <Th/> headers.
  const handleSort = (key) => {
    setSortConfig((prev) => ({
      key,
      direction: prev.key === key && prev.direction === 'asc' ? 'desc' : 'asc',
    }));
  };

  const handleBlockAction = async (log) => {
    if(!log.db_id) return alert("Persistence sync pending...");
    try {
      const res = await import('../services/api').then(m => m.blockIP(log.db_id));
      alert(`[SOAR ACTION] Host ${log.source_ip} blocked. Rule ID: ${res.rule_id}`);
    } catch (err) { alert("Action failed: " + err.message); }
  };

  const handleBenignAction = async (log) => {
    if(!log.db_id) return alert("Persistence sync pending...");
    try {
      await import('../services/api').then(m => m.markBenign(log.db_id));
      alert("Feedback received. AI model updated to ignore this vector.");
      setSelectedLog(null); // Close modal
    } catch (err) { alert("Action failed: " + err.message); }
  };

  const handleReportAction = async (log) => {
    if(!log.db_id) return alert("Persistence sync pending...");
    try {
      const res = await import('../services/api').then(m => m.fetchIncidentReport(log.db_id));
      setReportMarkdown(res.markdown);
    } catch (err) { alert("Report failed: " + err.message); }
  };

  const handlePDFAction = (log) => {
    if(!log.db_id) return alert("Persistence sync pending...");
    // Direct browser download for PDF
    window.open(`/api/alerts/${log.db_id}/pdf`, '_blank');
  };

  const filteredTraffic = useMemo(() => {
    let result = traffic.filter(item => 
      (item?.query?.toLowerCase().includes(searchTerm.toLowerCase()) || 
       item?.source_ip?.includes(searchTerm)) &&
      (filterSeverity === "All" || item?.risk_level === filterSeverity)
    );
    result.sort((a, b) => {
       let valA = a[sortConfig.key];
       let valB = b[sortConfig.key];
       if (sortConfig.key.includes('features.')) {
           valA = a.features[sortConfig.key.split('.')[1]];
           valB = b.features[sortConfig.key.split('.')[1]];
       }
       if (valA < valB) return sortConfig.direction === 'asc' ? -1 : 1;
       if (valA > valB) return sortConfig.direction === 'asc' ? 1 : -1;
       return 0;
    });
    return result;
  }, [traffic, searchTerm, filterSeverity, sortConfig]);

  const riskPieData = useMemo(() => [
    { name: 'Low', value: stats?.risk_distribution?.Low || 0, color: '#10b981' },
    { name: 'Medium', value: stats?.risk_distribution?.Medium || 0, color: '#f59e0b' },
    { name: 'High', value: stats?.risk_distribution?.High || 0, color: '#f43f5e' },
    { name: 'Critical', value: stats?.risk_distribution?.Critical || 0, color: '#a855f7' }
  ], [stats]);

  return (
    <div className="min-h-screen bg-[#02060e] selection:bg-[#00f2ff]/30">
      <div className="cyber-grid"></div>
      <div className="scanline"></div>

      {/* Live Threat Intelligence Ticker */}
      <div className="bg-black border-b border-[#00f2ff]/10 overflow-hidden relative z-[70]" style={{height: '28px'}}>
        <div className="absolute left-0 top-0 h-full flex items-center z-10" style={{background: 'linear-gradient(90deg, black 60%, transparent)'}}>
          <span className="text-[9px] font-bold text-[#00f2ff] tracking-widest uppercase px-4 whitespace-nowrap flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-pulse inline-block"></span>
            LIVE INTEL
          </span>
        </div>
        <div className="flex items-center h-full" style={{animation: 'tickerScroll 40s linear infinite', whiteSpace: 'nowrap', paddingLeft: '120px'}}>
          {[
            "SYSTEM: DNSentinel Threat Intelligence Platform — All systems nominal",
            "MODEL: 22-vector ensemble at 99.98% classification fidelity",
            "SOAR: Adaptive thresholds active — mean+2sigma anomaly detection enabled",
            "ENGINE: Real-time DNS exfiltration detection is active",
            "STATUS: Live telemetry stream connected via SSE",
            alerts[0] ? ("ALERT: " + (alerts[0].query || '') + " from " + (alerts[0].source_ip || '') + " [" + (alerts[0].risk_level || '') + "]") : "ALERT: Monitoring for DGA, Tunneling, and Exfiltration patterns",
            alerts[1] ? ("ALERT: " + (alerts[1].query || '') + " [" + (alerts[1].risk_level || '') + "]") : "INTEL: Behavioral baselining in progress across all hosts",
          ].map((item, i) => (
            <span key={i} className="text-[10px] text-slate-400 font-mono px-12">
              {item}
              <span className="mx-8 text-[#00f2ff]/20"> | </span>
            </span>
          ))}
        </div>
      </div>

      {/* Premium SOC Header */}
      <header className="border-b border-white/5 bg-[#020814]/80 backdrop-blur-3xl sticky top-0 z-[60]">
        <div className="max-w-[1800px] mx-auto px-8 h-20 flex items-center justify-between">
          <div className="flex items-center gap-6">
            <div className="p-3 bg-gradient-to-br from-[#00f2ff]/30 to-transparent rounded-2xl border border-[#00f2ff]/40 shadow-[0_0_30px_rgba(0,242,255,0.2)] group hover:scale-105 transition-all">
              <Shield className="text-[#00f2ff]" size={26} fillOpacity={0.1}/>
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-widest text-[#00f2ff] drop-shadow-glow">
                DNSENTINEL <span className="text-white font-light opacity-60">DASHBOARD</span>
              </h1>
              <div className="flex items-center gap-3">
                <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-emerald-400' : 'bg-rose-500 animate-pulse'} ring-4 ring-emerald-400/20`}></div>
                <span className="text-[10px] font-bold text-slate-500 tracking-[0.2em] uppercase">SYSTEM.STATUS: {isConnected ? 'SECURE_ACTIVE' : 'RECONNECTING'}</span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-4 bg-black/40 p-1.5 rounded-2xl border border-white/5 mx-auto">
             <button onClick={() => setViewMode("Triage")} className={`px-6 py-2 rounded-xl text-[10px] font-bold tracking-widest transition-all ${viewMode === 'Triage' ? 'bg-[#00f2ff] text-black shadow-[0_0_20px_rgba(0,242,255,0.4)]' : 'text-slate-500 hover:text-white'}`}>TRIAGE FEED</button>
             <button onClick={() => setViewMode("Topology")} className={`px-6 py-2 rounded-xl text-[10px] font-bold tracking-widest transition-all ${viewMode === 'Topology' ? 'bg-[#8b5cf6] text-white shadow-[0_0_20px_rgba(139,92,246,0.4)]' : 'text-slate-500 hover:text-white'}`}>TOPOLOGY MAP</button>
             <button onClick={() => setViewMode("Hunter")} className={`px-6 py-2 rounded-xl text-[10px] font-bold tracking-widest transition-all ${viewMode === 'Hunter' ? 'bg-amber-500 text-black shadow-[0_0_20px_rgba(245,158,11,0.4)]' : 'text-slate-500 hover:text-white'}`}>THREAT HUNTER</button>
             <button onClick={() => setViewMode("Containment")} className={`px-6 py-2 rounded-xl text-[10px] font-bold tracking-widest transition-all ${viewMode === 'Containment' ? 'bg-rose-500 text-white shadow-[0_0_20px_rgba(244,63,94,0.4)]' : 'text-slate-500 hover:text-white'}`}>CONTAINMENT AUDIT</button>
          </div>

          <div className="hidden lg:flex items-center gap-8">
             <div className="flex flex-col items-end border-r border-white/5 pr-8">
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1">Packet Stream Density</span>
                <span className="text-2xl font-mono text-white leading-none font-bold tabular-nums">{(stats.total_requests/100).toFixed(2)}k <span className="text-xs text-slate-600 font-light ml-1">v/pts</span></span>
             </div>
             {/* Live Clock */}
             <div className="flex flex-col items-end border-r border-white/5 pr-8">
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1">System Time</span>
                <span className="text-lg font-mono text-white leading-none font-bold tabular-nums">{liveClock.toLocaleTimeString('en-GB', {hour12: false})}</span>
             </div>
             <div className="flex gap-4">
                <input type="file" ref={fileInputRef} onChange={handleFileUpload} className="hidden" accept=".csv,.log"/>
                <button onClick={handleArchive} className="flex items-center gap-3 px-5 py-3 bg-slate-900/50 border border-white/5 rounded-xl text-[11px] font-bold uppercase tracking-widest text-slate-500 hover:text-rose-400 hover:bg-rose-400/5 hover:border-rose-400/30 transition-all active:scale-95">
                  <Trash2 size={16}/>
                  New Case
                </button>
                <button onClick={() => fileInputRef.current.click()} className="flex items-center gap-3 px-5 py-3 bg-[#00f2ff]/5 border border-[#00f2ff]/20 rounded-xl text-[11px] font-bold uppercase tracking-widest text-[#00f2ff] hover:bg-[#00f2ff]/10 transition-all active:scale-95 shadow-lg shadow-cyan-500/5">
                  <UploadCloud size={16}/>
                  Stream Ingest
                </button>
                <button onClick={exportAuditPDF} className="flex items-center gap-3 px-5 py-3 bg-slate-900 border border-white/10 rounded-xl text-[11px] font-bold uppercase tracking-widest text-slate-400 hover:text-white hover:border-white/20 transition-all">
                  <FileText size={16}/>
                  DNS Audit
                </button>
                <button onClick={exportAlertsCSV} className="flex items-center gap-3 px-5 py-3 bg-slate-900 border border-white/10 rounded-xl text-[11px] font-bold uppercase tracking-widest text-slate-400 hover:text-white hover:border-white/20 transition-all">
                  <Download size={16}/>
                  Export CSV
                </button>
             </div>
          </div>
        </div>
      </header>

      <main className="max-w-[1800px] mx-auto p-8 space-y-10">
        
        {/* Core Metrics Deck */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
           <StatusMetric label="Threat Signatures" value={stats.total_alerts} icon={<AlertTriangle size={24}/>} color="rose" />
           <StatusMetric label="Protocol Throughput" value={`${(stats.total_requests/60).toFixed(2)} ms`} icon={<Activity size={24}/>} color="cyan" />
           <StatusMetric label="Intelligence Fidelity" value="99.98%" icon={<Zap size={24}/>} color="purple" />
           <StatusMetric label="Ensemble Nodes" value="22 Vector" icon={<Cpu size={24}/>} color="amber" />
        </div>

        {viewMode === "Topology" ? (
           <TopologyView traffic={traffic} alerts={alerts} onSelectNode={(log) => setSelectedLog(log)} />
        ) : viewMode === "Hunter" ? (
           <ThreatHunterView traffic={traffic} onSelectNode={(log) => setSelectedLog(log)} />
        ) : viewMode === "Containment" ? (
           <ContainmentView onSelectNode={(log) => setSelectedLog(log)} />
        ) : (
          <div className="grid grid-cols-1 xl:grid-cols-12 gap-10">
            {/* Forensic Feed (Sidebar) */}
            <div className="xl:col-span-4 space-y-8">
              <section className="glass-panel p-8 h-[820px] flex flex-col group relative">
                <div className="absolute top-0 right-0 w-32 h-32 bg-rose-500/5 blur-[80px] rounded-full pointer-events-none"></div>
                <div className="flex items-center justify-between mb-8 pb-3 border-b border-white/5">
                  <h2 className="text-[11px] font-bold text-slate-500 tracking-[0.3em] uppercase flex items-center gap-4">
                     <div className="pulse-dot"></div>
                     High-Density Alerts
                  </h2>
                  <div className="text-[#00f2ff] px-2 py-1 bg-[#00f2ff]/10 rounded font-mono text-[9px] font-bold border border-[#00f2ff]/20">RT_READY</div>
                </div>

                <div className="flex-1 overflow-y-auto custom-scrollbar space-y-5 pr-2 scroll-smooth">
                   <AnimatePresence initial={false}>
                      {alerts.length === 0 ? (
                        <div className="h-full flex flex-col items-center justify-center opacity-10 text-center px-12">
                           <Lock size={64} className="mb-6" />
                           <p className="text-sm font-bold uppercase tracking-[0.2em] leading-loose">Clean Perimeter<br/>No Anomalies Detected</p>
                        </div>
                      ) : (
                        alerts.map((alert, idx) => (
                          <ForensicCard key={`${alert.timestamp}-${idx}`} alert={alert} onClick={() => setSelectedLog(alert)} />
                        ))
                      )}
                   </AnimatePresence>
                </div>
              </section>
            </div>

            {/* Main SOC Control Panel */}
            <div className="xl:col-span-8 space-y-10">
               <section className="glass-panel p-10 h-[820px] flex flex-col">
                  <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-10 gap-6">
                    <h2 className="text-sm font-bold text-white tracking-[0.3em] uppercase flex items-center gap-4">
                      <Terminal size={22} className="text-[#00f2ff]" /> 
                      Global Network Audio Stream
                    </h2>
                    
                    <div className="flex flex-wrap gap-4 w-full md:w-auto">
                      <select 
                        className="bg-black/50 border border-white/10 rounded-xl px-5 py-3 text-[10px] text-slate-400 focus:outline-none focus:border-[#00f2ff]/50 cursor-pointer font-bold uppercase tracking-widest hover:bg-black/70 transition-all flex items-center"
                        value={filterSeverity} 
                        onChange={(e)=>setFilterSeverity(e.target.value)}
                      >
                        <option value="All">All Severities</option>
                        <option value="Critical" className="text-purple-400 font-bold">Severity: Critical</option>
                        <option value="High" className="text-rose-400 font-bold">Severity: High</option>
                        <option value="Medium" className="text-amber-500 font-bold">Severity: Medium</option>
                        <option value="Low" className="text-emerald-400 font-bold">Severity: Low</option>
                      </select>

                      <div className="relative flex-1 md:w-80">
                        <Search size={18} className="absolute left-4 top-3 text-slate-600" />
                        <input 
                          type="text" placeholder="Probe Domain or Host Origin..." 
                          className="w-full bg-black/50 border border-white/10 rounded-xl pl-12 pr-5 py-3 text-[13px] text-slate-200 focus:outline-none focus:border-[#00f2ff]/40 focus:bg-black/70 transition-all font-mono placeholder:text-slate-700 shadow-inner"
                          onChange={(e) => setSearchTerm(e.target.value)}
                        />
                      </div>
                    </div>
                  </div>

                  <div className="overflow-y-auto overflow-x-auto flex-1 custom-scrollbar scroll-smooth">
                     <table className="w-full text-left">
                        <thead className="sticky top-0 bg-[#020814] border-b border-white/10 z-20">
                          <tr>
                             <Th label="Access Time" onClick={() => handleSort('timestamp')} skey="timestamp" config={sortConfig}/>
                             <Th label="Origin IP" onClick={() => handleSort('source_ip')} skey="source_ip" config={sortConfig}/>
                             <Th label="Protocol Payload" onClick={() => handleSort('query')} skey="query" config={sortConfig}/>
                             <Th label="Risk Index" onClick={() => handleSort('risk_score')} skey="risk_score" config={sortConfig} center/>
                             <Th label="Threat Level" onClick={() => handleSort('risk_level')} skey="risk_level" config={sortConfig} right/>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-white/[0.04]">
                          <AnimatePresence>
                            {filteredTraffic.map((row, idx) => (
                              <CyberTableRow key={`${row.timestamp}-${idx}`} row={row} onClick={() => setSelectedLog(row)} />
                            ))}
                          </AnimatePresence>
                        </tbody>
                     </table>
                  </div>
               </section>
            </div>
          </div>
        )}

        {/* Global Analytics Row */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 pb-20">
           
           {/* Attack Clustering (Donut) */}
           <div className="lg:col-span-3 glass-panel p-8">
              <h3 className="text-[11px] font-bold text-slate-500 tracking-[0.3em] mb-10 border-b border-white/5 pb-3 uppercase flex items-center gap-3">
                 <Command size={16} /> Signature Density
              </h3>
              <div className="h-[250px] relative reveal-card">
                 <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                    <span className="text-4xl font-mono font-bold text-white tracking-tighter tabular-nums">{stats.total_alerts}</span>
                    <span className="text-[10px] font-bold text-slate-600 uppercase tracking-widest mt-1">Confirmed Hits</span>
                 </div>
                 <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                       <Pie data={riskPieData} dataKey="value" innerRadius={85} outerRadius={110} paddingAngle={6} stroke="none">
                          {riskPieData.map((e, index) => <Cell key={`cell-${index}`} fill={e.color} />)}
                       </Pie>
                       <Tooltip content={<SOCPieTooltip />} />
                    </PieChart>
                 </ResponsiveContainer>
              </div>
           </div>

           {/* Direct Probe Terminal */}
           <div className="lg:col-span-4 glass-panel p-8 flex flex-col group">
              <div className="absolute top-0 left-0 w-full h-[2px] bg-gradient-to-r from-transparent via-[#00f2ff]/20 to-transparent"></div>
              <h3 className="text-[11px] font-bold text-[#00f2ff] tracking-[0.3em] mb-8 border-b border-[#00f2ff]/10 pb-3 uppercase flex items-center gap-3">
                 <Crosshair size={18} className="animate-pulse" /> Live Payload Ingress
              </h3>
              <form onSubmit={handleManualAnalysis} className="space-y-6 flex-1">
                 <div className="space-y-3">
                    <label className="text-[10px] text-slate-600 font-bold uppercase tracking-[0.2em] flex justify-between ml-1">Payload Domain <span>[X-1]</span></label>
                    <input 
                      type="text" required value={manualQuery} onChange={(e)=>setManualQuery(e.target.value)} 
                      placeholder="e.g. unknown-tunnel.xyz" 
                      className="w-full bg-black/60 border border-white/10 rounded-xl p-4 text-[13px] text-white focus:outline-none focus:border-[#00f2ff]/40 font-mono transition-all hover:bg-black/80"
                    />
                 </div>
                 <div className="space-y-3">
                    <label className="text-[10px] text-slate-600 font-bold uppercase tracking-[0.2em] flex justify-between ml-1">Target Context <span>[X-2]</span></label>
                    <input 
                      type="text" value={manualIp} onChange={(e)=>setManualIp(e.target.value)} 
                      placeholder="10.0.0.x" 
                      className="w-full bg-black/60 border border-white/10 rounded-xl p-4 text-[13px] text-white focus:outline-none focus:border-[#00f2ff]/40 font-mono transition-all hover:bg-black/80"
                    />
                 </div>
                 <button 
                  type="submit" disabled={isAnalyzing} 
                  className="w-full py-5 bg-gradient-to-br from-[#00f2ff]/20 to-[#8b5cf6]/20 text-[#00f2ff] border border-[#00f2ff]/30 rounded-2xl text-[12px] font-bold tracking-[0.3em] hover:from-[#00f2ff]/30 hover:to-[#8b5cf6]/30 transition-all active:scale-95 flex justify-center items-center gap-4 mt-6 shadow-2xl shadow-cyan-500/10"
                 >
                    {isAnalyzing ? <div className="w-5 h-5 border-2 border-[#00f2ff] border-t-transparent rounded-full animate-spin"></div> : <><Cpu size={20}/> EXECUTE SCAN CORE</>}
                 </button>
              </form>
           </div>

           {/* Entropy Visualizer */}
           <div className="lg:col-span-5 glass-panel p-8">
              <h3 className="text-[11px] font-bold text-slate-500 tracking-[0.3em] mb-10 border-b border-white/5 pb-3 uppercase flex justify-between items-center">
                 Statistical Payload Density
                 <span className="font-mono text-[#00f2ff] opacity-40">[SHAP_HIST]</span>
              </h3>
              <div className="h-[280px] reveal-card">
                 <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={traffic.slice(0, 30).reverse()} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                        <defs>
                          <linearGradient id="cyberArea" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor="#00f2ff" stopOpacity={0.25}/>
                            <stop offset="100%" stopColor="#8b5cf6" stopOpacity={0}/>
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="5 5" stroke="rgba(255,255,255,0.02)" vertical={false} />
                        <XAxis dataKey="timestamp" hide />
                        <YAxis stroke="#475569" fontSize={10} tickFormatter={(val) => val.toFixed(1)} domain={[0, 6]} axisLine={false} tickLine={false} />
                        <Tooltip content={<SOCTooltip />} />
                        <Area 
                          type="monotone" dataKey="features.entropy" stroke="#00f2ff" strokeWidth={4} fillOpacity={1} fill="url(#cyberArea)" 
                          animationDuration={2000}
                        />
                    </AreaChart>
                 </ResponsiveContainer>
              </div>
           </div>
        </div>
      </main>

      {/* Forensic Modal Overlays */}
      <AnimatePresence>
        {selectedLog && (
          <DetailedModal 
            log={selectedLog} 
            onClose={() => setSelectedLog(null)} 
            onBlock={handleBlockAction}
            onBenign={handleBenignAction}
            onReport={handleReportAction}
            onPDF={handlePDFAction}
          />
        )}
        
         {reportMarkdown && (
          <motion.div 
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="fixed inset-0 z-[110] bg-black/98 backdrop-blur-3xl flex justify-center items-start overflow-y-auto p-4 sm:p-12 custom-scrollbar"
            onClick={() => setReportMarkdown(null)}
          >
            <motion.div 
              initial={{ scale: 0.95, y: 40 }} animate={{ scale: 1, y: 0 }} exit={{ scale: 0.95, y: 40 }}
              className="glass-panel max-w-4xl w-full p-10 sm:p-16 relative border-[#00f2ff]/20 shadow-[0_0_120px_rgba(0,0,0,1)] my-auto"
              onClick={e => e.stopPropagation()}
            >
               <div className="flex justify-between items-center mb-8 border-b border-white/5 pb-4">
                  <h3 className="text-xl font-bold tracking-widest text-[#00f2ff] uppercase">Incident Executive Summary</h3>
                  <button onClick={() => setReportMarkdown(null)} className="p-2 hover:bg-white/5 rounded-full"><X size={24}/></button>
               </div>
               <div className="prose prose-invert max-w-none font-mono text-sm leading-relaxed whitespace-pre-wrap text-slate-300">
                  {reportMarkdown}
               </div>
               <div className="mt-10 flex gap-4">
                  <button onClick={() => window.print()} className="px-6 py-3 bg-[#00f2ff]/10 text-[#00f2ff] border border-[#00f2ff]/30 rounded-xl text-[10px] font-bold tracking-widest uppercase hover:bg-[#00f2ff]/20 transition-all">Download PDF Format</button>
                  <button onClick={() => setReportMarkdown(null)} className="px-6 py-3 bg-white/5 text-slate-400 border border-white/10 rounded-xl text-[10px] font-bold tracking-widest uppercase">Close File</button>
               </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

     {/* Keyboard Shortcut Hint */}
     <div className="fixed bottom-8 right-8 z-[998] flex items-center gap-2 opacity-30 hover:opacity-80 transition-opacity pointer-events-none">
       <kbd className="px-2 py-1 bg-slate-800 border border-white/10 rounded text-[10px] font-mono text-slate-400">/</kbd>
       <span className="text-[10px] text-slate-500 font-mono">to search</span>
     </div>
    </div>
  );
};

/* --- Refined Sub-Components --- */

const StatusMetric = ({ label, value, icon, color }) => {
  const styles = {
    cyan: "text-[#00f2ff] border-[#00f2ff]/20 bg-[#00f2ff]/5 shadow-cyan-500/10",
    rose: "text-rose-500 border-rose-500/20 bg-rose-500/5 shadow-rose-500/10",
    purple: "text-purple-500 border-purple-500/20 bg-purple-500/5 shadow-purple-500/10",
    amber: "text-amber-500 border-amber-500/20 bg-amber-500/5 shadow-amber-500/10"
  };
  return (
    <motion.div 
      initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }}
      className="glass-panel p-8 flex items-center justify-between group hover:border-white/20 reveal-card shadow-2xl"
    >
       <div className="relative z-10 space-y-4">
          <p className="text-[10px] font-bold text-slate-500 uppercase tracking-[0.3em]">{label}</p>
          <p className="text-3xl font-mono font-bold text-white tracking-tighter tabular-nums drop-shadow-lg">{value}</p>
       </div>
       <div className={`p-5 rounded-2xl border ${styles[color]} group-hover:scale-110 group-hover:rotate-6 transition-all duration-500`}>
          {icon}
       </div>
    </motion.div>
  );
};

const ForensicCard = ({ alert, onClick }) => (
  <motion.div 
    layout initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, x: 20 }}
    onClick={onClick}
    className={`p-6 rounded-3xl border-l-[6px] cursor-pointer transition-all hover:bg-black/40 mb-5 relative group border border-white/5
      ${alert.risk_level === 'Critical' ? 'bg-purple-900/10 border-l-purple-500 shadow-purple-500/10' :
        alert.risk_level === 'High' ? 'bg-rose-900/10 border-l-rose-500 shadow-rose-500/10' :
        'bg-slate-900/40 border-l-amber-500 shadow-amber-500/5'}
    `}
  >
     <div className="flex justify-between items-start mb-4">
        <span className="text-[10px] font-bold font-mono text-slate-600 tracking-widest">{alert.timestamp.split('T')[1].split('.')[0]}</span>
        <SeverityLevel level={alert.risk_level} />
     </div>
     <div className="flex items-center gap-4 mb-4">
        <div className={`p-2.5 rounded-xl ${alert.risk_level === 'Critical' ? 'bg-purple-500/20 text-purple-400' : 'bg-rose-500/20 text-rose-400'}`}>
           <AlertTriangle size={18}/>
        </div>
        <p className="font-mono text-xs text-white/90 break-all leading-relaxed font-bold tracking-tight">{alert.query}</p>
     </div>
     <div className="flex items-center justify-between border-t border-white/5 pt-4">
        <div className="flex items-center gap-3">
           <div className={`w-2 h-2 rounded-full ${alert.risk_level === 'Critical' ? 'bg-purple-500' : 'bg-rose-500'} animate-pulse`}></div>
           <span className="text-[10px] text-slate-600 font-bold uppercase tracking-widest">{alert.source_ip}</span>
        </div>
        <ChevronRight size={18} className="text-slate-600 group-hover:text-white group-hover:translate-x-1 transition-all" />
     </div>
  </motion.div>
);

const CyberTableRow = ({ row, onClick }) => (
  <motion.tr 
    layout initial={{ opacity: 0 }} animate={{ opacity: 1 }}
    onClick={onClick} 
    className="hover:bg-white/[0.04] transition-all cursor-pointer group hover:shadow-[inset_4px_0_0_0_#00f2ff]"
  >
    <td className="py-6 px-4 font-mono text-[10px] text-slate-600 group-hover:text-slate-400 tabular-nums">
      {row.timestamp.split('T')[1].split('.')[0]}
    </td>
    <td className="py-6 px-2 font-mono text-xs text-slate-300 group-hover:text-[#00f2ff] transition-colors tabular-nums">
      {row.source_ip}
    </td>
    <td className="py-6 px-2">
       <div className="flex items-center gap-4">
          <span className="text-[9px] font-bold bg-white/5 border border-white/5 px-2.5 py-1 rounded text-slate-500 font-mono uppercase truncate">{row.qtype}</span>
          <p className="font-mono text-xs text-white/80 truncate max-w-[250px] 2xl:max-w-[450px] tracking-tight">
            {row.intel_hit && <span className="mr-3 animate-pulse text-amber-500">💀</span>}
            {row.query}
          </p>
       </div>
    </td>
    <td className="py-6 px-2 text-center">
       <div className={`px-4 py-1.5 rounded-full inline-block font-mono text-xs border font-bold tabular-nums shadow-lg
          ${row.risk_score > 80 ? 'bg-purple-500/20 text-purple-400 border-purple-500/40 shadow-purple-900/10' :
            row.risk_score > 50 ? 'bg-rose-500/20 text-rose-400 border-rose-500/40 shadow-rose-900/10' :
            'bg-slate-900/80 text-slate-400 border-white/5 shadow-black/20'}
       `}>
          {row.risk_score.toFixed(1)}
       </div>
    </td>
    <td className="py-6 px-4 text-right">
       <SeverityLevel level={row.risk_level} />
    </td>
  </motion.tr>
);

const DetailedModal = ({ log, onClose, onBlock, onBenign, onReport, onPDF }) => (
  <motion.div 
    initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
    className="fixed inset-0 z-[100] bg-black/95 backdrop-blur-3xl flex justify-center items-start overflow-y-auto p-4 sm:p-10 custom-scrollbar"
    onClick={onClose}
  >
    <motion.div 
      initial={{ scale: 0.9, opacity: 0, y: 30 }} animate={{ scale: 1, opacity: 1, y: 0 }} exit={{ scale: 0.9, opacity: 0, y: 30 }}
      className="glass-panel max-w-4xl w-full p-8 sm:p-12 relative border-white/10 shadow-[0_0_100px_rgba(0,0,0,0.9)] my-auto"
      onClick={e => e.stopPropagation()}
    >
      <div className="flex justify-between items-start mb-10 pb-5 border-b border-white/5">
        <div>
           <div className="flex items-center gap-5 mb-3">
              <div className="p-3 bg-[#00f2ff]/10 rounded-2xl border border-[#00f2ff]/20 shadow-[0_0_20px_rgba(0,242,255,0.1)]"><Eye className="text-[#00f2ff]" size={28}/></div>
              <h2 className="text-2xl font-bold tracking-[0.3em] text-white uppercase drop-shadow-glow">Intelligence Profiling</h2>
           </div>
           <p className="text-[10px] text-slate-600 font-mono tracking-[0.4em] uppercase">{log.timestamp}</p>
        </div>
        <button onClick={onClose} className="p-3 bg-white/5 rounded-2xl hover:bg-white/10 hover:rotate-90 transition-all"><X size={24} className="text-slate-400"/></button>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-3 gap-6 mb-10">
         <ModalStat label="Packet Origin" value={log.source_ip} icon={<Server size={14}/>} />
         <ModalStat label="Request Class" value={log.qtype} icon={<Globe size={14}/>} />
         <ModalStat label="Correlation ID" value={log.timestamp.split('.')[1]} icon={<Lock size={14}/>} />
         <div className="col-span-2 lg:col-span-3 bg-black/60 p-8 rounded-3xl border border-white/5 group">
            <p className="text-[10px] text-slate-600 font-bold uppercase tracking-[0.3em] mb-4">Targeted Vector Discovery</p>
            <p className="font-mono text-[#00f2ff] text-lg leading-relaxed break-all select-all group-hover:text-white transition-colors">{log.query}</p>
         </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-10">
         <div className="space-y-8">
            <div className="bg-slate-900/60 p-8 rounded-3xl border border-white/5 space-y-6">
                <div className="flex justify-between items-center mb-2">
                   <span className="text-[10px] text-slate-500 font-bold uppercase tracking-[0.3em]">AI Ensemble Analytics</span>
                   <SeverityLevel level={log.risk_level} />
                </div>
                
                <div className="space-y-5">
                   <SHAPBar label="Entropy Density" value={log.features.entropy} max={10} color="#00f2ff" />
                   <SHAPBar label="Lexical Complexity" value={log.features.domain_complexity} max={100} color="#8b5cf6" />
                   <SHAPBar label="Linguistic Probability" value={1 - log.features.ngram_score} max={1} color="#f43f5e" />
                   <SHAPBar label="Subdomain Depth" value={log.features.labels} max={10} color="#f59e0b" />
                </div>

                {log.isolation_outlier && (
                  <div className="mt-8 bg-purple-500/10 border border-purple-500/20 p-4 rounded-2xl flex items-center gap-4 animate-in">
                     <Zap size={22} className="text-purple-400 animate-pulse"/>
                     <div>
                        <p className="text-[10px] font-bold text-purple-400 uppercase tracking-widest">Unsupervised Anomaly Hit</p>
                        <p className="text-[9px] text-slate-500 font-bold uppercase tracking-tighter mt-0.5">Vector mismatch against baseline traffic</p>
                     </div>
                  </div>
                )}
            </div>
         </div>

         <div className="space-y-8">
            <div className="relative">
               <div className="bg-emerald-500/5 border-l-4 border-emerald-400 p-6 rounded-r-3xl italic relative min-h-[120px] flex items-center shadow-xl">
                  <div className="absolute -top-3 left-6 bg-emerald-400 text-black text-[9px] font-bold px-3 py-1 rounded-full uppercase tracking-tighter font-mono">SOC_REASONING</div>
                  <p className="text-sm text-slate-300 leading-relaxed font-medium">"{log.explanation.split(' | ')[0]}"</p>
               </div>
            </div>

            {log.explanation.includes('[XAI: SHAP]') && (
              <div className="bg-indigo-500/10 border border-indigo-500/20 p-8 rounded-3xl relative group reveal-card">
                 <BarChart2 size={24} className="absolute right-6 top-6 text-indigo-400 opacity-20 group-hover:opacity-100 transition-opacity" />
                 <p className="text-[11px] text-indigo-400 font-bold uppercase tracking-[0.3em] mb-4">SHAP Explainability Insights</p>
                 <p className="text-xs text-indigo-200 font-mono leading-relaxed opacity-70 italic">"{log.explanation.split('[XAI: SHAP] ')[1]}"</p>
              </div>
            )}

            {log.mitre && Object.entries(log.mitre).length > 0 && (
               <div className="pt-6 border-t border-white/5">
                  <h4 className="text-[11px] font-bold text-slate-600 uppercase tracking-[0.3em] mb-6 flex items-center gap-3">
                     <Lock size={16}/> MITRE ATT&CK Correlation
                  </h4>
                  <div className="space-y-4">
                     {Object.entries(log.mitre).map(([id, info]) => (
                       <div key={id} className="bg-rose-500/5 border border-rose-500/10 p-5 rounded-2xl group hover:bg-rose-500/10 transition-all">
                          <div className="flex items-center justify-between mb-4">
                             <div className="flex items-center gap-3">
                                <span className="text-[11px] font-bold text-rose-400 border border-rose-400/30 px-3 py-1 rounded-lg bg-rose-500/10 font-mono">T{id}</span>
                                <span className="text-sm font-bold text-slate-200 group-hover:text-white">{info.Name}</span>
                             </div>
                             <ExternalLink size={14} className="text-rose-500/40" />
                          </div>
                          <p className="text-[11px] text-slate-500 leading-relaxed mb-4 group-hover:text-slate-400">{info.Description}</p>
                          {info.Mitigation && (
                            <div className="bg-black/40 p-4 rounded-xl border border-white/5 border-l-2 border-l-rose-500">
                               <p className="text-[11px] text-slate-300 leading-loose italic">"{info.Mitigation}"</p>
                            </div>
                          )}
                       </div>
                     ))}
                  </div>
               </div>
            )}

            {log.features?.intel_data && (
              <div className="pt-8 border-t border-white/5 space-y-6">
                 <h4 className="text-[11px] font-bold text-amber-500 uppercase tracking-[0.3em] flex items-center gap-3">
                    <Crosshair size={16}/> Intelligence Correlation Matrix
                 </h4>
                 <div className="bg-amber-500/5 border border-amber-500/10 p-6 rounded-3xl space-y-6 group hover:bg-amber-500/10 transition-all">
                    <div className="flex justify-between items-center">
                       <span className="text-[10px] text-slate-500 font-bold uppercase tracking-widest">Aggregate Reputation Index</span>
                       <div className="flex items-center gap-2">
                          <div className="h-1.5 w-24 bg-white/5 rounded-full overflow-hidden">
                             <div className="h-full bg-amber-500 shadow-[0_0_10px_#f59e0b]" style={{ width: `${log.features.intel_data.reputation_score}%` }}></div>
                          </div>
                          <span className="text-xs font-mono font-bold text-amber-400">{log.features.intel_data.reputation_score}/100</span>
                       </div>
                    </div>

                    <div className="flex flex-wrap gap-2">
                       {log.features.intel_data.sources.map(s => (
                         <span key={s} className="px-3 py-1 bg-white/5 border border-white/10 rounded-lg text-[9px] font-bold text-slate-400 uppercase tracking-widest">{s}</span>
                       ))}
                    </div>

                    <div className="flex flex-wrap gap-2">
                       {log.features.intel_data.threat_tags?.map(tag => (
                         <span key={tag} className="px-3 py-1 bg-amber-500/10 border border-amber-500/20 rounded-lg text-[9px] font-bold text-amber-500 uppercase tracking-tighter"># {tag}</span>
                       ))}
                    </div>
                 </div>
              </div>
            )}
         </div>
      </div>

      {/* SOAR Action Toolbar */}
      <div className="mt-12 pt-10 border-t border-white/5 flex flex-wrap gap-6">
         <button onClick={() => onBlock(log)} className="flex-1 min-w-[180px] py-5 bg-rose-500/10 hover:bg-rose-500/20 text-rose-500 border border-rose-500/30 rounded-2xl text-[11px] font-bold tracking-[0.3em] transition-all flex justify-center items-center gap-4 group">
            <Shield size={18} className="group-hover:scale-110 transition-transform"/> CONTAIN & BLOCK IP
         </button>
         <button onClick={() => onBenign(log)} className="flex-1 min-w-[180px] py-5 bg-white/5 hover:bg-white/10 text-slate-400 border border-white/10 rounded-2xl text-[11px] font-bold tracking-[0.3em] transition-all flex justify-center items-center gap-4 group">
            <Eye size={18} className="group-hover:text-white transition-colors"/> MARK AS BENIGN
         </button>
         <button onClick={() => onReport(log)} className="flex-1 min-w-[180px] py-5 bg-[#00f2ff]/10 hover:bg-[#00f2ff]/20 text-[#00f2ff] border border-[#00f2ff]/30 rounded-2xl text-[11px] font-bold tracking-[0.3em] transition-all flex justify-center items-center gap-4 group shadow-lg shadow-cyan-500/5">
            <Terminal size={18} className="animate-pulse"/> INCIDENT REPORT
         </button>
         <button onClick={() => onPDF(log)} className="flex-1 min-w-[180px] py-5 bg-emerald-500/10 hover:bg-emerald-400/20 text-emerald-400 border border-emerald-500/30 rounded-2xl text-[11px] font-bold tracking-[0.3em] transition-all flex justify-center items-center gap-4 group">
            <FileText size={18} className="group-hover:scale-110 transition-transform"/> DOWNLOAD PDF AUDIT
         </button>
      </div>
    </motion.div>
  </motion.div>
);

/* Helper UI Shells */

const Th = ({ label, onClick, skey, config, center, right }) => (
  <th 
    onClick={onClick} 
    className={`py-5 px-4 text-[11px] font-bold text-slate-500 tracking-[0.3em] uppercase cursor-pointer hover:text-white transition-all
      ${center ? 'text-center' : right ? 'text-right' : 'text-left'}
    `}
  >
    <div className={`flex items-center gap-3 ${center ? 'justify-center' : right ? 'justify-end' : ''}`}>
      {label}
      {config.key === skey && (
        <span className="text-[#00f2ff] animate-pulse">{config.direction === 'asc' ? '↑' : '↓'}</span>
      )}
    </div>
  </th>
);

const SeverityLevel = ({ level }) => {
  const themes = {
    Critical: "bg-purple-500/10 text-purple-400 border-purple-500/40 shadow-[0_0_20px_rgba(168,85,247,0.2)]",
    High: "bg-rose-500/10 text-rose-400 border-rose-500/40 shadow-rose-950/10",
    Medium: "bg-amber-500/10 text-amber-500 border-amber-500/40 shadow-amber-950/10",
    Low: "bg-emerald-500/10 text-emerald-400 border-emerald-500/40 shadow-emerald-950/10"
  };
  return (
    <span className={`px-4 py-1.5 rounded-2xl text-[10px] font-bold uppercase tracking-[0.2em] border shadow-xl ${themes[level || 'Low']}`}>
      {level || 'Low'}
    </span>
  );
};

const ModalStat = ({ label, value, icon }) => (
  <div className="bg-slate-900/60 p-5 rounded-2xl border border-white/5 relative group overflow-hidden">
     <div className="absolute top-0 right-0 w-2 h-2 bg-[#00f2ff]/20 rounded-bl-lg"></div>
     <div className="flex items-center gap-3 mb-2 text-slate-600 text-[10px] font-bold uppercase tracking-[0.3em]">
        {icon}
        {label}
     </div>
     <p className="text-sm font-mono text-white pl-6 group-hover:text-[#00f2ff] transition-colors">{value}</p>
  </div>
);

const SHAPBar = ({ label, value, max, color }) => (
  <div className="space-y-2">
     <div className="flex justify-between items-center px-1">
        <span className="text-[10px] font-bold text-slate-500 uppercase tracking-tighter">{label}</span>
        <span className="text-[10px] font-mono text-white opacity-40">{value.toFixed(2)}</span>
     </div>
     <div className="shap-bar">
        <motion.div 
          initial={{ width: 0 }} animate={{ width: `${(value/max)*100}%` }}
          className="shap-value" style={{ background: color, filter: `drop-shadow(0 0 5px ${color}88)` }}
        />
     </div>
  </div>
);

const SOCTooltip = ({ active, payload }) => {
  if (active && payload && payload.length) {
    return (
      <div className="bg-[#020814]/95 backdrop-blur-3xl border border-white/10 p-5 rounded-2xl shadow-2xl">
        <p className="text-[10px] text-slate-500 font-bold uppercase tracking-[0.3em] mb-3 border-b border-white/5 pb-2">Packet Forensics</p>
        <p className="text-base font-mono text-[#00f2ff] drop-shadow-glow">
          {payload[0].value.toFixed(4)} 
          <span className="text-[10px] text-slate-600 uppercase ml-2 tracking-tighter font-bold">Entropy Index</span>
        </p>
      </div>
    );
  }
  return null;
};

const SOCPieTooltip = ({ active, payload }) => {
  if (active && payload && payload.length) {
    return (
      <div className="bg-[#020814]/95 backdrop-blur-3xl border border-white/10 p-4 rounded-xl shadow-2xl">
        <p className="text-[11px] font-bold uppercase tracking-[0.2em]" style={{ color: payload[0].payload.color }}>
          {payload[0].name} SIGNATURES: {payload[0].value}
        </p>
      </div>
    );
  }
  return null;
};

/* --- Infrastructure Topology Visualization --- */

const TopologyView = ({ traffic, alerts, onSelectNode }) => {
  const [nodes, setNodes] = useState([]);
  const [links, setLinks] = useState([]);

  useEffect(() => {
    const uniqueIPs = [...new Set(traffic.map(t => t.source_ip))].slice(0, 8);
    const uniqueDomains = [...new Set(traffic.map(t => t.query))].slice(0, 15);
    
    // Center logic
    const center = { id: 'GATEWAY', type: 'core', x: 500, y: 400 };
    
    // Internal IPs (Inner Orbit)
    const ipNodes = uniqueIPs.map((ip, i) => {
       const angle = (i / uniqueIPs.length) * Math.PI * 2;
       return { id: ip, type: 'internal', x: 500 + Math.cos(angle) * 150, y: 400 + Math.sin(angle) * 150 };
    });

    // External Domains (Outer Orbit)
    const domainNodes = uniqueDomains.map((dom, i) => {
       const angle = (i / uniqueDomains.length) * Math.PI * 2;
       const isThreat = alerts.some(a => a.query === dom);
       return { id: dom, type: 'external', x: 500 + Math.cos(angle) * 350, y: 400 + Math.sin(angle) * 350, isThreat };
    });

    const allNodes = [center, ...ipNodes, ...domainNodes];
    
    // Build Links
    const allLinks = [];
    traffic.forEach(t => {
       if (uniqueIPs.includes(t.source_ip) && uniqueDomains.includes(t.query)) {
          allLinks.push({ source: t.source_ip, target: t.query, log: t });
       }
       if (uniqueIPs.includes(t.source_ip)) {
          allLinks.push({ source: 'GATEWAY', target: t.source_ip });
       }
    });

    // eslint-disable-next-line react-hooks/set-state-in-effect -- derive graph state once per data change
    setNodes(allNodes);
    setLinks(allLinks);
  }, [traffic, alerts]);

  return (
    <motion.div 
      initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }}
      className="glass-panel p-10 h-[820px] relative overflow-hidden bg-black/60 shadow-inner"
    >
       <div className="absolute top-10 left-10 z-10 space-y-2">
          <h2 className="text-sm font-bold text-white tracking-[0.4em] uppercase">Security Topology Graph</h2>
          <p className="text-[10px] text-slate-500 font-bold uppercase tracking-widest">Real-time Host/Domain Linkage Matrix</p>
       </div>

       <div className="absolute top-10 right-10 z-10 flex flex-col gap-4 text-right">
          <div className="flex items-center gap-3 justify-end">
             <span className="text-[9px] font-bold text-slate-400 uppercase">Internal Asset</span>
             <div className="w-3 h-3 rounded-full bg-[#00f2ff]"></div>
          </div>
          <div className="flex items-center gap-3 justify-end">
             <span className="text-[9px] font-bold text-slate-400 uppercase">External Target</span>
             <div className="w-3 h-3 rounded-full bg-slate-600"></div>
          </div>
          <div className="flex items-center gap-3 justify-end font-bold text-rose-500">
             <span className="text-[9px] uppercase">Threat Vector</span>
             <div className="w-3 h-3 rounded-full bg-rose-500 shadow-[0_0_10px_rgba(244,63,94,1)]"></div>
          </div>
       </div>

       <svg viewBox="0 0 1000 800" className="w-full h-full">
          <defs>
             <marker id="arrow" viewBox="0 0 10 10" refX="5" refY="5" markerWidth="4" markerHeight="4" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="rgba(255,255,255,0.1)" />
             </marker>
             <filter id="nodeGlow">
                <feGaussianBlur stdDeviation="3" result="blur" />
                <feComposite in="SourceGraphic" in2="blur" operator="over" />
             </filter>
          </defs>

          {/* Links */}
          {links.map((link, i) => {
             const source = nodes.find(n => n.id === link.source);
             const target = nodes.find(n => n.id === link.target);
             if (!source || !target) return null;
             const isThreat = link.log?.risk_level === 'Critical';
             return (
               <motion.line 
                 key={`link-${i}`} x1={source.x} y1={source.y} x2={target.x} y2={target.y}
                 stroke={isThreat ? "#f43f5e" : "rgba(255,255,255,0.05)"}
                 strokeWidth={isThreat ? 3 : 1}
                 initial={{ pathLength: 0, opacity: 0 }} animate={{ pathLength: 1, opacity: 1 }}
                 transition={{ duration: 1.5, delay: i * 0.05 }}
               />
             );
          })}

          {/* Nodes */}
          {nodes.map((node, i) => (
             <motion.g 
               key={node.id} initial={{ opacity: 0, scale: 0 }} animate={{ opacity: 1, scale: 1 }}
               transition={{ type: "spring", stiffness: 260, damping: 20, delay: i * 0.02 }}
               className="cursor-pointer"
               onClick={() => node.log && onSelectNode(node.log)}
             >
                <circle 
                  cx={node.x} cy={node.y} 
                  r={node.type === 'core' ? 30 : node.type === 'internal' ? 12 : 8}
                  fill={node.type === 'core' ? '#8b5cf6' : node.type === 'internal' ? '#00f2ff' : (node.isThreat ? '#f43f5e' : '#475569')}
                  filter={node.isThreat ? "url(#nodeGlow)" : ""}
                  className="transition-all hover:r-[1.5x]"
                />
                <text 
                  x={node.x} y={node.y + (node.type === 'core' ? 50 : 25)} 
                  textAnchor="middle" fill="#94a3b8" fontSize="10" fontWeight="bold" className="pointer-events-none select-none font-mono"
                >
                   {node.type === 'core' ? "GATEWAY" : node.id.length > 20 ? node.id.substring(0, 15) + "..." : node.id}
                </text>
             </motion.g>
          ))}
       </svg>
    </motion.div>
  );
};

/* --- Threat Hunter Specialized View --- */

const ThreatHunterView = ({ traffic, onSelectNode }) => {
  const huntedLogs = useMemo(() => {
    return traffic.filter(t => t.features?.intel_data?.reputation_score > 0 || t.intel_hit)
      .sort((a, b) => (b.features?.intel_data?.reputation_score || 0) - (a.features?.intel_data?.reputation_score || 0));
  }, [traffic]);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 min-h-[820px]">
       {/* Hunter Stats */}
       <div className="lg:col-span-3 space-y-8">
          <div className="glass-panel p-8 space-y-8">
             <div>
                <h3 className="text-[11px] font-bold text-slate-500 uppercase tracking-[0.3em] mb-6 flex items-center gap-3">
                   <Activity size={16} className="text-amber-500"/> Hunting Statistics
                </h3>
                <div className="space-y-6">
                   <div className="flex justify-between items-end border-b border-white/5 pb-4">
                      <span className="text-sm font-medium text-slate-400">Intelligence Hits</span>
                      <span className="text-2xl font-mono font-bold text-amber-500">{huntedLogs.length}</span>
                   </div>
                   <div className="flex justify-between items-end border-b border-white/5 pb-4">
                      <span className="text-sm font-medium text-slate-400">Critical Entities</span>
                      <span className="text-2xl font-mono font-bold text-rose-500">{huntedLogs.filter(l => l.risk_level === 'Critical').length}</span>
                   </div>
                </div>
             </div>

             <div className="pt-4">
                <p className="text-[10px] text-slate-500 font-bold uppercase tracking-widest leading-loose">
                   The Threat Hunter view prioritizes entities flagged by external intelligence sources and high-reputation scores.
                </p>
             </div>
          </div>
       </div>

       {/* Hunter Grid */}
       <div className="lg:col-span-9">
          <div className="grid grid-cols-1 md:grid-cols-2 2xl:grid-cols-3 gap-8">
             {huntedLogs.length === 0 ? (
               <div className="col-span-full h-[600px] flex flex-col items-center justify-center opacity-10">
                  <Crosshair size={120} className="mb-10" />
                  <p className="text-2xl font-bold uppercase tracking-[0.5em]">No Intelligence Clusters Found</p>
               </div>
             ) : (
               huntedLogs.map((log, idx) => (
                 <motion.div 
                   key={idx} layout initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }}
                   className={`glass-panel p-8 group cursor-pointer hover:border-amber-500/30 transition-all hunter-target ${log.risk_level === 'Critical' ? 'border-rose-500/20' : ''}`}
                   onClick={() => onSelectNode(log)}
                 >
                    <div className="flex justify-between items-center mb-6">
                       <div className="px-3 py-1 bg-amber-500/10 border border-amber-500/20 rounded-lg font-mono text-[10px] font-bold text-amber-500 uppercase tracking-widest">
                          REP_SCORE: {log.features?.intel_data?.reputation_score || 0}
                       </div>
                       <SeverityLevel level={log.risk_level} />
                    </div>

                    <p className="font-mono text-sm text-white font-bold tracking-tight mb-6 truncate group-hover:text-amber-400 transition-colors">{log.query}</p>
                    
                    <div className="flex items-center gap-4 mb-6">
                       <div className="w-10 h-10 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center text-slate-600 group-hover:text-amber-500 transition-colors">
                          <Globe size={20}/>
                       </div>
                       <div>
                          <p className="text-[10px] font-bold text-slate-600 uppercase tracking-widest">Target Host</p>
                          <p className="text-xs font-mono text-slate-300 font-bold">{log.source_ip}</p>
                       </div>
                    </div>

                    <div className="flex flex-wrap gap-2 mb-8">
                       {log.features?.intel_data?.sources.map(s => (
                         <span key={s} className="px-2 py-0.5 bg-white/5 border border-white/5 rounded text-[8px] font-bold text-slate-500 uppercase">{s}</span>
                       ))}
                    </div>

                    <div className="pt-6 border-t border-white/5 flex justify-between items-center">
                       <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Intel Vectors</span>
                       <div className="flex -space-x-2">
                          {[1,2,3].map(i => (
                            <div key={i} className="w-6 h-6 rounded-full bg-slate-800 border-2 border-black flex items-center justify-center">
                               <Shield size={10} className="text-amber-500"/>
                            </div>
                          ))}
                       </div>
                    </div>
                 </motion.div>
               ))
             )}
          </div>
       </div>
    </div>
  );
};

/* --- Containment Audit specialized View --- */

const ContainmentView = () => {
  const [blocks, setBlocks] = useState([]);
  const [isLoading, setIsLoading] = useState(true);

  const refreshBlocks = () => {
    fetch("/api/blocked")
      .then(res => res.json())
      .then(data => {
        setBlocks(data);
        setIsLoading(false);
      })
      .catch(err => console.error("Failed to fetch blocks", err));
  };

  useEffect(() => {
    refreshBlocks();
    const interval = setInterval(refreshBlocks, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleUnblock = async (target) => {
    try {
      const res = await fetch(`/api/unblock/${target}`, { method: 'POST' });
      const data = await res.json();
      if (data.status === "REMOVED") {
        refreshBlocks();
      }
    } catch (err) {
      console.error("Unblock failed", err);
    }
  };

  return (
    <div className="space-y-8 min-h-[820px]">
       <div className="flex justify-between items-end mb-4">
          <div>
            <h2 className="text-2xl font-bold tracking-[0.2em] text-white uppercase drop-shadow-glow flex items-center gap-4">
               <Shield className="text-rose-500" size={24}/> Active Containment Ledger
            </h2>
            <p className="text-[10px] text-slate-500 font-mono tracking-widest uppercase mt-2">Active Enforcement rules and automated cooldown timers</p>
          </div>
          <div className="px-4 py-2 bg-rose-500/10 border border-rose-500/20 rounded-xl">
             <span className="text-[10px] font-bold text-rose-400 uppercase tracking-widest">{blocks.length} ACTIVE BLOCKS</span>
          </div>
       </div>

       <div className="glass-panel overflow-hidden">
          <table className="w-full text-left border-collapse">
             <thead>
                <tr className="bg-white/5 border-b border-white/5">
                   <th className="p-6 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Target Entity</th>
                   <th className="p-6 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Rule Class</th>
                   <th className="p-6 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Forensic Reason</th>
                   <th className="p-6 text-[10px] font-bold text-slate-500 uppercase tracking-widest text-center">Risk Index</th>
                   <th className="p-6 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Expires In</th>
                   <th className="p-6 text-[10px] font-bold text-slate-500 uppercase tracking-widest text-right">Actions</th>
                </tr>
             </thead>
             <tbody className="divide-y divide-white/5">
                {isLoading ? (
                  <tr><td colSpan="6" className="p-20 text-center text-slate-600 animate-pulse">Synchronizing Security Store...</td></tr>
                ) : blocks.length === 0 ? (
                  <tr><td colSpan="6" className="p-20 text-center text-slate-600 italic">No active network rules currently enforced.</td></tr>
                ) : (
                  blocks.map((block, idx) => (
                    <motion.tr 
                      key={idx} initial={{ opacity: 0 }} animate={{ opacity: 1 }}
                      className="hover:bg-white/[0.02] transition-colors group"
                    >
                       <td className="p-6">
                          <div className="flex items-center gap-3">
                             <div className="w-2 h-2 rounded-full bg-rose-500 animate-pulse"></div>
                             <span className="font-mono text-sm font-bold text-white group-hover:text-rose-400 transition-colors">{block.target}</span>
                          </div>
                       </td>
                       <td className="p-6">
                          <span className="px-3 py-1 bg-white/5 border border-white/10 rounded-lg text-[9px] font-bold text-slate-400 uppercase">{block.rule_type}</span>
                       </td>
                       <td className="p-6 max-w-[300px]">
                          <p className="text-xs text-slate-500 truncate">{block.reason}</p>
                       </td>
                       <td className="p-6 text-center">
                          <span className="font-mono text-sm font-bold text-rose-500">{block.risk_score}</span>
                       </td>
                       <td className="p-6">
                          <div className="flex items-center gap-2 text-slate-400">
                             <Clock size={12}/>
                             <span className="text-[10px] font-mono">
                                {new Date(block.expires_at).toLocaleTimeString()}
                             </span>
                          </div>
                       </td>
                       <td className="p-6 text-right">
                          <button 
                            onClick={() => handleUnblock(block.target)}
                            className="p-2 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-500 border border-emerald-500/30 rounded-lg transition-all group-hover:scale-110"
                            title="Revoke Rule"
                          >
                             <Unlock size={14}/>
                          </button>
                       </td>
                    </motion.tr>
                  ))
                )}
             </tbody>
          </table>
       </div>

       <div className="grid grid-cols-1 md:grid-cols-3 gap-8 pt-10">
          <div className="glass-panel p-8 space-y-4 border-l-4 border-l-amber-500">
             <div className="flex items-center gap-3 text-amber-500 mb-2">
                <AlertTriangle size={18}/>
                <h4 className="text-xs font-bold uppercase tracking-widest">Active Sinkhole Policy</h4>
             </div>
             <p className="text-[10px] text-slate-500 leading-relaxed uppercase">Domains flagged as C2 high-risk are redirected to 127.0.0.1 to prevent data exfiltration over DNS. These rules auto-refresh every hour.</p>
          </div>
          <div className="glass-panel p-8 space-y-4 border-l-4 border-l-rose-500">
             <div className="flex items-center gap-3 text-rose-500 mb-2">
                <Shield size={18}/>
                <h4 className="text-xs font-bold uppercase tracking-widest">L3/L4 Firewall Rules</h4>
             </div>
             <p className="text-[10px] text-slate-500 leading-relaxed uppercase">Malicious source IPs are blocked via kernel-level IPTABLES filters. Access from these addresses is severed across all protocols.</p>
          </div>
          <div className="glass-panel p-8 space-y-4 border-l-4 border-l-blue-500">
             <div className="flex items-center gap-3 text-blue-500 mb-2">
                <Clock size={18}/>
                <h4 className="text-xs font-bold uppercase tracking-widest">Automatic Remediation</h4>
             </div>
             <p className="text-[10px] text-slate-500 leading-relaxed uppercase">To prevent network disruption, all rules have a 24-hour expiration. Once expired, the soul orchestrator automatically revokes the block.</p>
          </div>
       </div>
    </div>
  );
};

export default Dashboard;
