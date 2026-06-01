import React, { useState, useEffect } from 'react';
import { createRoot } from 'react-dom/client';
import { Shield, Settings, Activity, AlertTriangle, ShieldBan, MonitorPlay, Trash2 } from 'lucide-react';
import './popup.css';
import { calculateFallbackScore, extractFeatures } from '../background/heuristics.js';

const Popup = () => {
  const [events, setEvents] = useState([]);
  const [stats, setStats] = useState({ total: 0, blocked: 0, alerts: 0, maxScore: 0 });
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [activeTabDomain, setActiveTabDomain] = useState(null);
  const [activeTabEvent, setActiveTabEvent] = useState(null);
  const [isActiveTabSystem, setIsActiveTabSystem] = useState(false);
  const [activeTabUrl, setActiveTabUrl] = useState("");
  const [showSettings, setShowSettings] = useState(false);
  const [backendUrl, setBackendUrl] = useState("http://127.0.0.1:8001");
  const [groqKey, setGroqKey] = useState("");
  
  const determineTier = (score) => {
    if (score > 90) return "CRITICAL";
    if (score > 80) return "BLOCK";
    if (score > 60) return "ALERT";
    return "MONITOR";
  };

  const triggerLocalCalculation = (domain, url, tabId) => {
    const features = extractFeatures(domain);
    const scoreData = calculateFallbackScore(features, domain);
    
    setActiveTabEvent({
        id: "temp_" + Date.now(),
        domain,
        url,
        tabId,
        timestamp: Date.now(),
        features,
        ml_score: scoreData.ml_score || 0.5,
        isolation_score: 1,
        final_score: scoreData.final_score,
        shap_reason: "[Local Engine] Calculating initial scores...",
        tier: determineTier(scoreData.final_score),
        detailsType: "main_frame"
    });
  };

  const detectActiveTab = (currentEvents = []) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs && tabs[0] && tabs[0].url) {
            const urlStr = tabs[0].url;
            setActiveTabUrl(urlStr);
            try {
                const url = new URL(urlStr);
                if (url.protocol.startsWith('http')) {
                    const hostname = url.hostname;
                    setActiveTabDomain(hostname);
                    setIsActiveTabSystem(false);
                    
                    const existing = currentEvents.find(ev => 
                        ev.domain === hostname || 
                        hostname.endsWith('.' + ev.domain) || 
                        ev.domain.endsWith('.' + hostname)
                    );
                    
                    if (existing) {
                        setActiveTabEvent(existing);
                    } else {
                        chrome.runtime.sendMessage({
                            type: "ANALYZE_DOMAIN",
                            domain: hostname,
                            url: urlStr,
                            tabId: tabs[0].id
                        });
                        triggerLocalCalculation(hostname, urlStr, tabs[0].id);
                    }
                } else {
                    setActiveTabDomain(url.hostname || url.protocol);
                    setIsActiveTabSystem(true);
                    setActiveTabEvent(null);
                }
            } catch (e) {
                console.error("Error parsing tab URL:", e);
                setIsActiveTabSystem(true);
            }
        }
    });
  };

  const clearData = () => {
    const request = indexedDB.open("DNSentinelDB", 1);
    request.onsuccess = (e) => {
        const db = e.target.result;
        if(db.objectStoreNames.contains("dns_events")) {
            const tx = db.transaction("dns_events", "readwrite");
            const store = tx.objectStore("dns_events");
            const clearReq = store.clear();
            tx.oncomplete = () => {
                setEvents([]);
                setStats({ total: 0, blocked: 0, alerts: 0, maxScore: 0 });
                setSelectedEvent(null);
                setActiveTabEvent(null);
            };
        }
    };
  };
  
  useEffect(() => {
    chrome.storage.local.get(["BACKEND_API_URL", "GROQ_API_KEY"], (result) => {
      if (result.BACKEND_API_URL) setBackendUrl(result.BACKEND_API_URL);
      if (result.GROQ_API_KEY) setGroqKey(result.GROQ_API_KEY);
    });

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
              if (['BLOCK', 'CRITICAL', 'HIGH'].includes(ev.tier)) blocked++;
              if (['ALERT', 'BLOCK', 'CRITICAL', 'HIGH', 'MEDIUM'].includes(ev.tier)) alerts++;
              if (ev.final_score > max) max = ev.final_score;
          });
          setStats({ total: all.length, blocked, alerts, maxScore: max });
          
          detectActiveTab(recent);
        };
      }
    };

    const listener = (msg) => {
      if (msg.type === "DNS_EVENT") {
        setEvents(prev => {
          const index = prev.findIndex(ev => ev.id === msg.payload.id);
          let updatedEvents;
          if (index !== -1) {
            updatedEvents = [...prev];
            updatedEvents[index] = msg.payload;
          } else {
            updatedEvents = [msg.payload, ...prev].slice(0, 20);
          }

          setSelectedEvent(selected => {
            if (selected && selected.id === msg.payload.id) {
              return msg.payload;
            }
            return selected;
          });

          setActiveTabDomain(currentActiveDomain => {
             if (currentActiveDomain && (msg.payload.domain === currentActiveDomain || currentActiveDomain.endsWith('.' + msg.payload.domain) || msg.payload.domain.endsWith('.' + currentActiveDomain))) {
                 setActiveTabEvent(msg.payload);
             }
             return currentActiveDomain;
          });

          setStats(prevStats => {
            if (index !== -1) {
              const oldEvent = prev[index];
              let blockedDiff = 0;
              let alertsDiff = 0;
              
              if (['BLOCK', 'CRITICAL', 'HIGH'].includes(oldEvent.tier)) blockedDiff--;
              if (['ALERT', 'BLOCK', 'CRITICAL', 'HIGH', 'MEDIUM'].includes(oldEvent.tier)) alertsDiff--;
              
              if (['BLOCK', 'CRITICAL', 'HIGH'].includes(msg.payload.tier)) blockedDiff++;
              if (['ALERT', 'BLOCK', 'CRITICAL', 'HIGH', 'MEDIUM'].includes(msg.payload.tier)) alertsDiff++;
              
              return {
                total: prevStats.total,
                blocked: prevStats.blocked + blockedDiff,
                alerts: prevStats.alerts + alertsDiff,
                maxScore: Math.max(prevStats.maxScore, msg.payload.final_score)
              };
            } else {
              return {
                total: prevStats.total + 1,
                blocked: prevStats.blocked + (['BLOCK', 'CRITICAL', 'HIGH'].includes(msg.payload.tier) ? 1 : 0),
                alerts: prevStats.alerts + (['ALERT', 'BLOCK', 'CRITICAL', 'HIGH', 'MEDIUM'].includes(msg.payload.tier) ? 1 : 0),
                maxScore: Math.max(prevStats.maxScore, msg.payload.final_score)
              };
            }
          });

          return updatedEvents;
        });
      }
    };
    chrome.runtime.onMessage.addListener(listener);
    return () => chrome.runtime.onMessage.removeListener(listener);
  }, []);

  const getTierColor = (tier) => {
      switch(tier) {
          case 'CRITICAL':
          case 'HIGH':
              return 'bg-red-500';
          case 'BLOCK':
          case 'MEDIUM':
              return 'bg-orange-500';
          case 'ALERT':
              return 'bg-yellow-500';
          default:
              return 'bg-emerald-500';
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
                <Settings onClick={() => setShowSettings(true)} className="w-5 h-5 text-slate-400 hover:text-cyan-400 transition-colors cursor-pointer" />
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
                <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mt-1">Security Warnings</span>
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
                        <div className="bg-slate-800/50 p-4 rounded-xl border border-slate-700/50 space-y-1">
                             <div className="flex justify-between items-center">
                                 <span className="text-slate-300 font-semibold text-sm">Threat Level (Risk Score)</span>
                                 <span className="font-mono text-2xl font-black text-red-400 drop-shadow-[0_0_8px_rgba(248,113,113,0.5)]">{(selectedEvent.final_score || 0).toFixed(2)}</span>
                             </div>
                             <p className="text-[11px] text-slate-400 leading-normal">Measures how suspicious the website itself is based on machine learning structural analysis.</p>
                         </div>
                        <div className="space-y-4">
                            <div className="flex justify-between items-center px-1">
                                <span className="text-slate-400 font-medium">Risk Tier</span>
                                <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                                    (selectedEvent.tier === 'CRITICAL' || selectedEvent.tier === 'HIGH') ? 'bg-red-500/20 text-red-400 border-red-500/30' :
                                    (selectedEvent.tier === 'BLOCK' || selectedEvent.tier === 'MEDIUM') ? 'bg-orange-500/20 text-orange-400 border-orange-500/30' :
                                    selectedEvent.tier === 'ALERT' ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' :
                                    'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                                }`}>{selectedEvent.tier}</span>
                            </div>

                            {/* AI Feature Breakdown (XAI) */}
                            <div className="bg-slate-900/50 p-4 rounded-xl border border-slate-800/50 space-y-4">
                                <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">AI Risk Indicators</div>
                                <div className="space-y-3.5">
                                    <div className="space-y-1">
                                        <div className="flex justify-between items-center text-[12px]">
                                            <span className="text-slate-300 font-semibold">Name Randomness (Entropy)</span>
                                            <div className="flex items-center gap-2">
                                                <div className="w-20 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                                                    <div className="h-full bg-cyan-500" style={{width: `${Math.min((selectedEvent.features?.entropy || 0) * 20, 100)}%`}}></div>
                                                </div>
                                                <span className="text-cyan-400 font-mono text-[10px] font-bold">{(selectedEvent.features?.entropy || 0).toFixed(2)}</span>
                                            </div>
                                        </div>
                                        <p className="text-[10.5px] text-slate-500 leading-normal">Checks how chaotic the address letters are. High randomness is a major indicator of hacker-controlled networks.</p>
                                    </div>
                                    <div className="space-y-1">
                                        <div className="flex justify-between items-center text-[12px]">
                                            <span className="text-slate-300 font-semibold">Number Ratio (Digits)</span>
                                            <div className="flex items-center gap-2">
                                                <div className="w-20 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                                                    <div className="h-full bg-indigo-500" style={{width: `${(selectedEvent.features?.digit_ratio || 0) * 100}%`}}></div>
                                                </div>
                                                <span className="text-indigo-400 font-mono text-[10px] font-bold">{((selectedEvent.features?.digit_ratio || 0) * 100).toFixed(0)}%</span>
                                            </div>
                                        </div>
                                        <p className="text-[10.5px] text-slate-500 leading-normal">Checks what percentage of characters are numbers. Legitimate sites rarely use number-packed names.</p>
                                    </div>
                                </div>
                            </div>

                            {(() => {
                                const parsed = parseExplanation(selectedEvent.shap_reason, selectedEvent.final_score);
                                return (
                                    <div className="bg-slate-900/50 p-4 rounded-xl border border-slate-800/50 space-y-3">
                                        <div>
                                            <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1">AI Assessment</div>
                                            <p className="text-xs text-slate-200 leading-relaxed font-semibold">{parsed.friendly}</p>
                                        </div>
                                        
                                        {parsed.pie && (
                                            <div className="pt-2 border-t border-slate-805 space-y-1">
                                                <div className="flex justify-between items-center text-xs">
                                                    <span className="text-slate-400 font-medium">Response Urgency (PIE Score)</span>
                                                    <span className="font-mono text-cyan-400 font-bold">{parsed.pie}</span>
                                                </div>
                                                <p className="text-[10px] text-slate-500 leading-normal">Determines operational action priority by weighting the website's threat score against the security value of this computer.</p>
                                            </div>
                                        )}
                                        
                                        {parsed.technical && (
                                            <details className="pt-2 border-t border-slate-850 group">
                                                <summary className="text-[10px] font-bold text-slate-500 uppercase tracking-widest cursor-pointer select-none hover:text-slate-400 transition-colors flex justify-between items-center list-none">
                                                    Developer Logs (SHAP & ML)
                                                    <span className="text-[9px] text-slate-500 group-open:rotate-180 transition-transform">▼</span>
                                                </summary>
                                                <p className="mt-2 text-[11px] text-slate-400 font-mono leading-relaxed bg-slate-950/60 p-2.5 rounded border border-slate-800/60 break-words">{parsed.technical}</p>
                                            </details>
                                        )}
                                    </div>
                                );
                            })()}
                        </div>
                    </div>
                    <div className="border-t border-slate-800/80 bg-slate-900/80 p-4 flex gap-3">
                        <button onClick={() => {
                            chrome.runtime.sendMessage({ type: "ALLOW_DOMAIN", domain: selectedEvent.domain }, (response) => {
                                if (response && response.status === "allowed") {
                                    const toast = document.createElement('div');
                                    toast.style.cssText = 'position:fixed;bottom:20px;left:20px;background:#10b981;color:white;padding:1rem;border-radius:8px;font-size:14px;font-weight:bold;z-index:1000';
                                    toast.textContent = `✓ ${selectedEvent.domain} allowed`;
                                    document.body.appendChild(toast);
                                    setTimeout(() => toast.remove(), 2000);
                                }
                                setSelectedEvent(null);
                            });
                        }} className="flex-1 bg-emerald-600 hover:bg-emerald-700 text-white font-bold py-2 px-4 rounded-lg transition-colors duration-200 shadow-lg text-sm">
                            ✓ Allow
                        </button>
                        <button onClick={() => {
                            chrome.runtime.sendMessage({ type: "BLOCK_DOMAIN", domain: selectedEvent.domain }, (response) => {
                                if (response && response.status === "blocked") {
                                    const toast = document.createElement('div');
                                    toast.style.cssText = 'position:fixed;bottom:20px;left:20px;background:#dc2626;color:white;padding:1rem;border-radius:8px;font-size:14px;font-weight:bold;z-index:1000';
                                    toast.textContent = `✕ ${selectedEvent.domain} blocked`;
                                    document.body.appendChild(toast);
                                    setTimeout(() => toast.remove(), 2000);
                                }
                                setSelectedEvent(null);
                            });
                        }} className="flex-1 bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-4 rounded-lg transition-colors duration-200 shadow-lg text-sm">
                            ✕ Block
                        </button>
                    </div>
                </div>
            )}

            {showSettings && (
                <div className="absolute inset-0 bg-slate-950/95 backdrop-blur-xl z-20 flex flex-col h-full animate-in slide-in-from-bottom-full duration-300">
                    <div className="p-4 border-b border-slate-800/80 flex justify-between items-center bg-slate-900/80">
                        <div className="flex items-center gap-3">
                            <button onClick={() => setShowSettings(false)} className="text-slate-400 bg-slate-800/50 border border-slate-700/50 w-8 h-8 rounded-full flex items-center justify-center cursor-pointer hover:bg-slate-700 transition-all">
                                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>
                            </button>
                            <h3 className="font-bold text-white text-lg">Extension Settings</h3>
                        </div>
                    </div>
                    
                    <div className="p-5 flex-1 overflow-y-auto space-y-6 text-sm">
                        <div className="flex flex-col gap-2">
                            <label className="text-slate-300 font-semibold">Backend Server URL</label>
                            <input 
                                type="text" 
                                value={backendUrl} 
                                onChange={(e) => setBackendUrl(e.target.value)} 
                                className="bg-slate-800/50 border border-slate-700/50 rounded-lg px-3.5 py-2.5 text-white font-mono outline-none focus:border-cyan-400 transition-colors w-full box-border" 
                                placeholder="http://127.0.0.1:8001" 
                            />
                            <p className="text-[11px] text-slate-500 leading-normal">Specify the URL of the FastAPI machine learning inference engine. Can be hosted locally or on a cloud server.</p>
                        </div>

                        <div className="flex flex-col gap-2">
                            <label className="text-slate-300 font-semibold">Groq API Key</label>
                            <input 
                                type="password" 
                                value={groqKey} 
                                onChange={(e) => setGroqKey(e.target.value)} 
                                className="bg-slate-800/50 border border-slate-700/50 rounded-lg px-3.5 py-2.5 text-white font-mono outline-none focus:border-cyan-400 transition-colors w-full box-border" 
                                placeholder="gsk_..." 
                            />
                            <p className="text-[11px] text-slate-500 leading-normal">Your personal Groq API Key. Used as a direct LLM fallback for XAI (Explainable AI) analysis if the backend server is temporarily unreachable.</p>
                        </div>
                    </div>

                    <div className="border-t border-slate-800/80 bg-slate-900/90 p-4 flex gap-3 z-10">
                        <button 
                            onClick={() => {
                                chrome.storage.local.set({
                                    BACKEND_API_URL: backendUrl,
                                    GROQ_API_KEY: groqKey
                                }, () => {
                                    setShowSettings(false);
                                });
                            }} 
                            className="flex-1 bg-sky-600 hover:bg-sky-700 text-white font-bold py-2.5 px-4 rounded-lg cursor-pointer transition-all duration-200 shadow-md hover:scale-[1.02]"
                        >
                            Save Settings
                        </button>
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

function parseExplanation(rawText, score = 0) {
    if (!rawText || rawText === "[Local Engine] Analyzing structural features...") {
        return { friendly: "Analyzing structural and security patterns...", technical: "", pie: "" };
    }
    
    if (score < 50) {
        return {
            friendly: "This website behaves normally. Our machine learning models evaluated its name and found no malicious patterns.",
            technical: rawText,
            pie: ""
        };
    }
    
    const parts = rawText.split('|').map(p => p.trim());
    let threatText = "";
    let shapText = "";
    let pieText = "";
    
    parts.forEach(part => {
        if (part.includes("PIE Score")) {
            pieText = part;
        } else if (part.includes("[XAI: SHAP]")) {
            shapText = part;
        } else {
            threatText = threatText ? (threatText + " " + part) : part;
        }
    });
    
    let friendly = "";
    if (threatText.includes("Standard benign DNS") || threatText.includes("Normal traffic structures") || threatText.includes("benign DNS resolution")) {
        friendly = "This website behaves normally. Our machine learning models evaluated its name and found no malicious patterns.";
    } else {
        const bulletPoints = [];
        if (threatText.includes("Isolation Forest flagged")) {
            bulletPoints.push("Our AI detected unusual patterns that differ from standard, trusted web destinations.");
        }
        if (threatText.includes("human-readable n-grams") || threatText.includes("DGA generated")) {
            bulletPoints.push("The domain name looks randomized and doesn't match standard language patterns, which is typical for automated command systems.");
        }
        if (threatText.includes("entropy") || threatText.includes("tunneling")) {
            bulletPoints.push("The website name contains random, high-entropy character sequences resembling encoded data exfiltration.");
        }
        if (threatText.includes("long DNS label")) {
            bulletPoints.push("The web address contains excessively long parts, which is a known method for sneaking data out.");
        }
        
        if (bulletPoints.length > 0) {
            friendly = bulletPoints.join(" ");
        } else {
            friendly = "Our machine learning model detected suspicious structural deviations that may represent an active threat.";
        }
    }
    
    return {
        friendly,
        technical: threatText + (shapText ? " | " + shapText : ""),
        pie: pieText
    };
}

const root = createRoot(document.getElementById('root'));
root.render(<Popup />);
