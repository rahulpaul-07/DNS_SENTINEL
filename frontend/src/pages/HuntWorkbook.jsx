import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Play, Save, FileText, Plus, Trash2, 
  ChevronRight, Terminal, BarChart2, MessageSquare, 
  Activity, Target, Shield, Clock, Download
} from 'lucide-react';
import { 
  ComposedChart, Line, Bar, XAxis, YAxis, CartesianGrid, 
  Tooltip, ResponsiveContainer, ScatterChart, Scatter, 
  AreaChart, Area, RadarChart, PolarGrid, PolarAngleAxis, Radar,
  Cell, PieChart, Pie
} from 'recharts';

const TEMPLATES = [
  { 
    id: 'beaconing', 
    name: 'Beaconing Detection', 
    mitre: 'T1071.004', 
    dsl: 'HUNT beaconing FROM ip=10.0.0.5 WINDOW 24h CONFIDENCE > 0.75',
    icon: <Activity className="text-cyan-400"/>
  },
  { 
    id: 'dga', 
    name: 'DGA Cluster', 
    mitre: 'T1568.002', 
    dsl: 'HUNT dga_cluster FROM subnet=10.0.0.0/24 WHERE ENTROPY > 3.8',
    icon: <Target className="text-purple-400"/>
  },
  { 
    id: 'exfil', 
    name: 'Slow Exfiltration', 
    mitre: 'T1048', 
    dsl: 'HUNT slow_exfil FROM domain=*.xyz WHERE BYTES_PER_HOUR > 500',
    icon: <Download className="text-rose-400"/>
  }
];

const HuntWorkbook = () => {
  const [session, setSession] = useState({
    id: crypto.randomUUID(),
    title: "New Forensic Investigation",
    analyst_name: "SOC_LEAD_01",
    status: "Active",
    cells: [
      { id: 'c1', type: 'query', content: 'HUNT beaconing FROM ip=10.0.2.15 WINDOW 12h' }
    ],
    results: {},
    notes: ""
  });
  
  const [runningCell, setRunningCell] = useState(null);
  const [progress, setProgress] = useState([]);

  const runHunt = (cellId, query) => {
    setRunningCell(cellId);
    setProgress([]);
    
    const eventSource = new EventSource(`/api/hunt/run?query=${encodeURIComponent(query)}`);
    
    eventSource.onmessage = (event) => {
      const data = JSON.parse(event.data);
      setProgress(prev => [...prev, data]);
      
      if (data.status === "done" && data.result) {
        setSession(prev => ({
          ...prev,
          results: { ...prev.results, [cellId]: data.result }
        }));
        eventSource.close();
        setRunningCell(null);
      }
      
      if (data.status === "error") {
        eventSource.close();
        setRunningCell(null);
      }
    };
    
    eventSource.onerror = () => {
      eventSource.close();
      setRunningCell(null);
    };
  };

  const saveSession = async () => {
    try {
      await fetch('/api/hunt/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(session)
      });
      alert("Session autosaved to secure ledger.");
    } catch (e) { console.error(e); }
  };

  return (
    <div className="grid grid-cols-12 gap-8 min-h-[80vh]">
      {/* Sidebar: Template Picker */}
      <div className="col-span-3 space-y-6">
        <div className="bg-slate-900/40 border border-white/5 rounded-2xl p-6">
          <h3 className="text-[11px] font-bold text-slate-500 uppercase tracking-widest mb-6 flex items-center gap-2">
            <Shield size={14}/> MITRE Technique Library
          </h3>
          <div className="space-y-4">
            {TEMPLATES.map(t => (
              <button 
                key={t.id}
                onClick={() => setSession(prev => ({
                  ...prev,
                  cells: [...prev.cells, { id: crypto.randomUUID(), type: 'query', content: t.dsl }]
                }))}
                className="w-full p-4 bg-black/40 border border-white/5 rounded-xl hover:border-cyan-500/30 transition-all text-left group"
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-white font-bold text-sm">{t.name}</span>
                  <span className="text-[9px] font-mono bg-slate-800 px-2 py-0.5 rounded text-slate-400">{t.mitre}</span>
                </div>
                <div className="flex items-center gap-2">
                  {t.icon}
                  <span className="text-[10px] text-slate-500 line-clamp-1 italic">{t.dsl}</span>
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Main: Notebook Workspace */}
      <div className="col-span-9 space-y-8">
        <div className="flex items-center justify-between bg-slate-900/40 p-4 border border-white/5 rounded-2xl">
          <input 
            value={session.title}
            onChange={e => setSession({...session, title: e.target.value})}
            className="bg-transparent text-xl font-bold text-white outline-none w-1/2"
          />
          <div className="flex items-center gap-4">
             <button onClick={saveSession} className="flex items-center gap-2 px-4 py-2 bg-black/60 border border-white/5 rounded-lg text-xs font-bold text-slate-400 hover:text-white">
                <Save size={14}/> SAVE
             </button>
             <button className="flex items-center gap-2 px-4 py-2 bg-cyan-500/10 border border-cyan-500/20 rounded-lg text-xs font-bold text-cyan-400">
                <FileText size={14}/> EXPORT PDF
             </button>
          </div>
        </div>

        {session.cells.map((cell, idx) => (
          <motion.div 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            key={cell.id} 
            className="space-y-4"
          >
            {/* DSL Query Cell */}
            <div className="bg-[#0a0c10] border border-white/5 rounded-2xl overflow-hidden shadow-2xl">
              <div className="flex items-center justify-between px-4 py-2 bg-white/5 border-b border-white/5">
                <div className="flex items-center gap-3">
                  <Terminal size={14} className="text-cyan-400"/>
                  <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Cell [{idx + 1}]: DSL Query</span>
                </div>
                <button onClick={() => runHunt(cell.id, cell.content)} disabled={runningCell === cell.id} className="text-cyan-400 hover:bg-cyan-400/10 p-2 rounded-lg transition-all active:scale-90">
                  <Play size={16} fill={runningCell === cell.id ? 'currentColor' : 'none'}/>
                </button>
              </div>
              <textarea 
                value={cell.content}
                onChange={e => {
                  const newCells = [...session.cells];
                  newCells[idx].content = e.target.value;
                  setSession({...session, cells: newCells});
                }}
                className="w-full h-24 bg-transparent p-6 text-sm font-mono text-cyan-50/80 outline-none resize-none"
              />
              
              {/* Progress Stream */}
              {runningCell === cell.id && (
                <div className="px-6 pb-6 space-y-2">
                  {progress.map((p, i) => (
                    <div key={i} className="flex items-center gap-3 text-[10px] font-mono">
                      <ChevronRight size={10} className="text-cyan-500"/>
                      <span className={p.status === 'error' ? 'text-rose-400' : 'text-slate-400'}>
                        {p.stage} {p.status === 'active' && '...'}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Result Cell */}
            {session.results[cell.id] && (
              <div className="bg-slate-900/20 border border-white/5 rounded-2xl p-8 space-y-6">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <div className="p-3 bg-cyan-500/10 rounded-xl">
                      <BarChart2 size={20} className="text-cyan-400"/>
                    </div>
                    <div>
                      <h4 className="text-white font-bold">{session.results[cell.id].technique} Results</h4>
                      <div className="flex items-center gap-2 text-[10px] font-bold">
                        <span className="text-slate-500 uppercase tracking-widest">Confidence:</span>
                        <span className="text-cyan-400">{(session.results[cell.id].confidence * 100).toFixed(1)}%</span>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="h-64 w-full bg-black/20 rounded-xl p-4 border border-white/5">
                   {/* Conditional Visualization based on technique */}
                   <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={session.results[cell.id].viz.data || []}>
                        <defs>
                          <linearGradient id="colorVal" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#00f2ff" stopOpacity={0.3}/>
                            <stop offset="95%" stopColor="#00f2ff" stopOpacity={0}/>
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="#ffffff10" />
                        <XAxis dataKey="t" stroke="#ffffff30" fontSize={10} />
                        <YAxis stroke="#ffffff30" fontSize={10} />
                        <Tooltip contentStyle={{backgroundColor: '#0a0c10', border: '1px solid #ffffff10'}} />
                        <Area type="monotone" dataKey="v" stroke="#00f2ff" fillOpacity={1} fill="url(#colorVal)" />
                      </AreaChart>
                   </ResponsiveContainer>
                </div>

                {/* Evidence Table */}
                <div className="overflow-x-auto border border-white/5 rounded-xl">
                  <table className="w-full text-left text-[10px]">
                    <thead className="bg-white/5 text-slate-500 font-bold uppercase tracking-widest">
                      <tr>
                        <th className="px-4 py-2">Timestamp</th>
                        <th className="px-4 py-2">Domain</th>
                        <th className="px-4 py-2">Source IP</th>
                        <th className="px-4 py-2">Risk Index</th>
                      </tr>
                    </thead>
                    <tbody className="text-slate-400 font-mono">
                      {session.results[cell.id].evidence.map((row, i) => (
                        <tr key={i} className="border-t border-white/5 hover:bg-white/5 transition-all">
                          <td className="px-4 py-2">{row.access_time || '19:45:00'}</td>
                          <td className="px-4 py-2 text-cyan-300">{row.query}</td>
                          <td className="px-4 py-2">{row.source_ip}</td>
                          <td className="px-4 py-2">{row.risk_score?.toFixed(1)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </motion.div>
        ))}

        {/* Add Note Cell */}
        <div className="bg-slate-900/40 border border-dashed border-white/20 rounded-2xl p-6 flex flex-col items-center justify-center gap-4 hover:border-cyan-500/50 transition-all group">
           <div className="p-4 bg-slate-800 rounded-full group-hover:bg-cyan-500/10 group-hover:text-cyan-400 transition-all">
              <MessageSquare size={24}/>
           </div>
           <div className="text-center">
              <p className="text-slate-400 font-bold text-sm">Add Analyst Observations</p>
              <p className="text-slate-600 text-[10px]">Link IOCs, document pivot paths, and prepare findings for the final report.</p>
           </div>
           <button className="px-6 py-2 bg-white/5 border border-white/10 rounded-xl text-[11px] font-bold text-white hover:bg-cyan-500 hover:text-black transition-all">
              <Plus size={14} className="inline mr-2"/> NEW NOTE CELL
           </button>
        </div>
      </div>
    </div>
  );
};

export default HuntWorkbook;
