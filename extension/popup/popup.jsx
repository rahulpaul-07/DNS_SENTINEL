import React, { useState, useEffect } from 'react';
import { createRoot } from 'react-dom/client';
import { Shield, Settings, Activity, AlertTriangle, ShieldBan, MonitorPlay, Trash2 } from 'lucide-react';
import './popup.css';

const Popup = () => {
  const [events, setEvents] = useState([]);
  const [stats, setStats] = useState({ total: 0, blocked: 0, alerts: 0, maxScore: 0 });
  const [selectedEvent, setSelectedEvent] = useState(null);
  
  const clearData = () => {
    const request = indexedDB.open("DNSentinelDB", 1);
    request.onsuccess = (e) => {
        const db = e.target.result;
        if(db.objectStoreNames.contains("dns_events")) {
            const tx = db.transaction("dns_events", "readwrite");
            tx.objectStore("dns_events").clear();
            tx.oncomplete = () => {
                setEvents([]);
                setStats({ total: 0, blocked: 0, alerts: 0, maxScore: 0 });
                setSelectedEvent(null);
            };
        }
    };
  };
  
  useEffect(() => {
    // Load initial events from DB
    const request = indexedDB.open("DNSentinelDB", 1);
    request.onsuccess = (e) => {
      const db = e.target.result;
      if(db.objectStoreNames.contains("dns_events")) {
        const tx = db.transaction("dns_events", "readonly");
        const store = tx.objectStore("dns_events");
        const getReq = store.getAll();
        getReq.onsuccess = () => {
          const all = getReq.result || [];
          const recent = all.sort((a,b) => b.timestamp - a.timestamp).slice(0, 20);
          setEvents(recent);
          
          let blocked = 0; let alerts = 0; let max = 0;
          all.forEach(ev => {
              if (ev.tier === 'BLOCK' || ev.tier === 'CRITICAL') blocked++;
              if (ev.tier === 'ALERT') alerts++;
              if (ev.final_score > max) max = ev.final_score;
          });
          setStats({ total: all.length, blocked, alerts, maxScore: max });
        };
      }
    };

    const listener = (msg) => {
      if (msg.type === "DNS_EVENT") {
        setEvents(prev => [msg.payload, ...prev].slice(0, 20));
        setStats(prev => ({
            total: prev.total + 1,
            blocked: prev.blocked + (['BLOCK', 'CRITICAL'].includes(msg.payload.tier) ? 1 : 0),
            alerts: prev.alerts + (msg.payload.tier === 'ALERT' ? 1 : 0),
            maxScore: Math.max(prev.maxScore, msg.payload.final_score)
        }));
      }
    };
    chrome.runtime.onMessage.addListener(listener);
    return () => chrome.runtime.onMessage.removeListener(listener);
  }, []);

  const getTierColor = (tier) => {
      switch(tier) {
          case 'CRITICAL': return 'bg-red-500';
          case 'BLOCK': return 'bg-orange-500';
          case 'ALERT': return 'bg-yellow-500';
          default: return 'bg-blue-500';
      }
  };

  return (
    <div className="flex flex-col h-full bg-[#020617] text-white overflow-hidden relative">
        {/* Ambient Glow Effects */}
        <div className="absolute top-[-50px] left-[-50px] w-48 h-48 bg-cyan-500/20 rounded-full blur-3xl pointer-events-none"></div>
        <div className="absolute bottom-[-50px] right-[-50px] w-64 h-64 bg-indigo-500/10 rounded-full blur-3xl pointer-events-none"></div>

        <header className="flex justify-between items-center p-4 bg-slate-900/50 backdrop-blur-md border-b border-slate-800/60 z-10">
            <div className="flex items-center gap-2">
                <Shield className="w-6 h-6 text-cyan-400 drop-shadow-[0_0_8px_rgba(34,211,238,0.5)]" />
                <h1 className="font-bold text-lg tracking-wide bg-gradient-to-r from-cyan-400 to-indigo-400 bg-clip-text text-transparent">DNSentinel <span className="text-cyan-400 text-[10px] uppercase ml-1 font-black bg-cyan-950 px-1.5 py-0.5 rounded border border-cyan-800/50 shadow-[0_0_5px_rgba(34,211,238,0.3)]">Live</span></h1>
            </div>
            <div className="flex gap-3">
                <Trash2 onClick={clearData} className="w-5 h-5 text-slate-400 hover:text-red-400 transition-colors cursor-pointer" title="Clear All Telemetry" />
                <Settings className="w-5 h-5 text-slate-400 hover:text-cyan-400 transition-colors cursor-pointer" />
            </div>
        </header>
        
        <div className="grid grid-cols-2 gap-3 p-4 z-10">
            <div className="bg-slate-800/40 backdrop-blur-sm p-4 rounded-xl border border-slate-700/50 flex flex-col items-center shadow-lg transition-transform hover:scale-105">
                <Activity className="w-6 h-6 text-cyan-400 mb-2 drop-shadow-[0_0_8px_rgba(34,211,238,0.4)]" />
                <span className="text-3xl font-black bg-gradient-to-b from-white to-slate-400 bg-clip-text text-transparent">{stats.total}</span>
                <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mt-1">Total Analyzed</span>
            </div>
            <div className="bg-slate-800/40 backdrop-blur-sm p-4 rounded-xl border border-slate-700/50 flex flex-col items-center shadow-lg transition-transform hover:scale-105">
                <ShieldBan className="w-6 h-6 text-orange-400 mb-2 drop-shadow-[0_0_8px_rgba(249,115,22,0.4)]" />
                <span className="text-3xl font-black bg-gradient-to-b from-white to-slate-400 bg-clip-text text-transparent">{stats.blocked}</span>
                <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mt-1">Blocked</span>
            </div>
            <div className="bg-slate-800/40 backdrop-blur-sm p-4 rounded-xl border border-slate-700/50 flex flex-col items-center shadow-lg transition-transform hover:scale-105">
                <AlertTriangle className="w-6 h-6 text-yellow-400 mb-2 drop-shadow-[0_0_8px_rgba(234,179,8,0.4)]" />
                <span className="text-3xl font-black bg-gradient-to-b from-white to-slate-400 bg-clip-text text-transparent">{stats.alerts}</span>
                <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mt-1">Active Alerts</span>
            </div>
            <div className="bg-slate-800/40 backdrop-blur-sm p-4 rounded-xl border border-slate-700/50 flex flex-col items-center shadow-lg transition-transform hover:scale-105 relative overflow-hidden">
                <div className="absolute inset-0 bg-red-500/5 blur-xl"></div>
                <MonitorPlay className="w-6 h-6 text-red-400 mb-2 drop-shadow-[0_0_8px_rgba(248,113,113,0.4)] z-10" />
                <span className="text-3xl font-black bg-gradient-to-b from-red-400 to-red-600 bg-clip-text text-transparent z-10">{(stats.maxScore || 0).toFixed(2)}</span>
                <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mt-1 z-10">Max Risk</span>
            </div>
        </div>

        <div className="flex-1 overflow-y-auto px-4 pb-4 space-y-2 relative z-10">
            <h2 className="text-[11px] font-bold text-slate-500 uppercase tracking-widest ml-1 mb-3">Live Telemetry</h2>
            {events.length === 0 ? (
                <div className="text-center text-slate-500 mt-10 text-sm italic">Waiting for DNS traffic...</div>
            ) : events.map((ev, idx) => (
                <div key={idx} onClick={() => setSelectedEvent(ev)} className="bg-slate-800/30 hover:bg-slate-700/50 backdrop-blur-sm cursor-pointer p-3 rounded-lg border border-slate-700/50 flex items-center justify-between text-sm transition-all duration-200 hover:shadow-lg group">
                    <div className="flex items-center gap-3 overflow-hidden">
                        <div className={`w-2.5 h-2.5 rounded-full ${getTierColor(ev.tier)} shadow-[0_0_8px_currentColor] flex-shrink-0 transition-transform group-hover:scale-125`} />
                        <span className="truncate max-w-[200px] font-medium text-slate-200 group-hover:text-white transition-colors" title={ev.domain}>{ev.domain}</span>
                    </div>
                    <div className="flex flex-col items-end flex-shrink-0">
                        <span className={`font-mono font-bold text-base ${ev.final_score > 60 ? 'text-red-400 drop-shadow-[0_0_5px_rgba(248,113,113,0.5)]' : 'text-cyan-400 drop-shadow-[0_0_5px_rgba(34,211,238,0.5)]'}`}>{ev.final_score.toFixed(2)}</span>
                        <span className="text-[10px] text-slate-500 font-medium">{new Date(ev.timestamp).toLocaleTimeString()}</span>
                    </div>
                </div>
            ))}

            {selectedEvent && (
                <div className="absolute inset-0 bg-slate-950/95 backdrop-blur-xl z-20 flex flex-col h-full animate-in slide-in-from-bottom-full duration-300">
                    <div className="p-4 border-b border-slate-800/80 flex justify-between items-center bg-slate-900/80">
                        <h3 className="font-bold truncate pr-4 text-white text-lg">{selectedEvent.domain}</h3>
                        <button onClick={() => setSelectedEvent(null)} className="text-slate-400 hover:text-white hover:bg-slate-800 w-8 h-8 rounded-full flex items-center justify-center transition-colors">&times;</button>
                    </div>
                    <div className="p-5 flex-1 overflow-y-auto text-sm space-y-6">
                        <div className="flex justify-between items-center bg-slate-800/50 p-4 rounded-xl border border-slate-700/50">
                            <span className="text-slate-300 font-medium">Risk Score</span>
                            <span className="font-mono text-2xl font-black text-red-400 drop-shadow-[0_0_8px_rgba(248,113,113,0.5)]">{(selectedEvent.final_score || 0).toFixed(2)}</span>
                        </div>
                        <div className="space-y-4">
                            <div className="flex justify-between items-center px-1">
                                <span className="text-slate-400 font-medium">Risk Tier</span>
                                <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                                    selectedEvent.tier === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border-red-500/30' :
                                    selectedEvent.tier === 'BLOCK' ? 'bg-orange-500/20 text-orange-400 border-orange-500/30' :
                                    selectedEvent.tier === 'ALERT' ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' :
                                    'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                                }`}>{selectedEvent.tier}</span>
                            </div>

                            {/* AI Feature Breakdown (XAI) */}
                            <div className="bg-slate-900/50 p-4 rounded-xl border border-slate-800/50 space-y-3">
                                <div className="text-[11px] font-bold text-slate-500 uppercase tracking-widest mb-1">AI Risk Breakdown</div>
                                <div className="space-y-2">
                                    <div className="flex justify-between items-center text-[12px]">
                                        <span className="text-slate-400">Structural Entropy</span>
                                        <div className="flex items-center gap-2">
                                            <div className="w-20 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                                                <div className="h-full bg-cyan-500" style={{width: `${Math.min((selectedEvent.features?.entropy || 0) * 20, 100)}%`}}></div>
                                            </div>
                                            <span className="text-cyan-400 font-mono text-[10px]">{(selectedEvent.features?.entropy || 0).toFixed(2)}</span>
                                        </div>
                                    </div>
                                    <div className="flex justify-between items-center text-[12px]">
                                        <span className="text-slate-400">Digit Density</span>
                                        <div className="flex items-center gap-2">
                                            <div className="w-20 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                                                <div className="h-full bg-indigo-500" style={{width: `${(selectedEvent.features?.digit_ratio || 0) * 100}%`}}></div>
                                            </div>
                                            <span className="text-indigo-400 font-mono text-[10px]">{((selectedEvent.features?.digit_ratio || 0) * 100).toFixed(0)}%</span>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <div className="bg-slate-800/30 p-3 rounded-lg border border-slate-700/30">
                                <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1">AI Reasoning</div>
                                <p className="text-xs text-slate-300 leading-relaxed italic">"{selectedEvent.shap_reason || "No explanation available."}"</p>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
        
        {/* Live SOC Status Ticker */}
        <footer className="mt-auto bg-slate-900/80 border-t border-slate-800/80 px-4 py-2 flex items-center justify-between z-10 overflow-hidden">
            <div className="flex items-center gap-2 whitespace-nowrap animate-pulse">
                <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 shadow-[0_0_5px_rgba(16,185,129,0.5)]"></div>
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-tighter">System: Stable</span>
            </div>
            <div className="flex-1 px-4 overflow-hidden">
                <div className="text-[10px] font-mono text-cyan-400/60 animate-marquee whitespace-nowrap">
                    SEC_CORE: Active | HEURISTICS: Loaded | ML_PIE: Running | GROQ_AI: Online | TELEMETRY_STREAM: Connected
                </div>
            </div>
            <button 
                onClick={() => window.open('http://localhost:5173')}
                className="text-[10px] font-black text-cyan-400 hover:text-cyan-300 uppercase tracking-widest transition-colors flex items-center gap-1"
            >
                DNS Dashboard
                <Activity className="w-3 h-3" />
            </button>
        </footer>
    </div>
  );
};

const root = createRoot(document.getElementById('root'));
root.render(<Popup />);
