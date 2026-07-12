import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Shield, AlertTriangle, Clock, Unlock } from 'lucide-react';

export const ContainmentView = () => {
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
