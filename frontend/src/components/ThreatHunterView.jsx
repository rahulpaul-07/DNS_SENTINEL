import { useMemo } from 'react';
import { motion } from 'framer-motion';
import { Shield, Activity, Crosshair, Globe } from 'lucide-react';
import { SeverityLevel } from './primitives';

export const ThreatHunterView = ({ traffic, onSelectNode }) => {
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
