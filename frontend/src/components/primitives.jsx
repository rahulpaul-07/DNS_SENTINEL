import { motion } from 'framer-motion';

export const StatusMetric = ({ label, value, icon, color }) => {
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

export const Th = ({ label, onClick, skey, config, center, right }) => (
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

export const SeverityLevel = ({ level }) => {
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

export const ModalStat = ({ label, value, icon }) => (
  <div className="bg-slate-900/60 p-5 rounded-2xl border border-white/5 relative group overflow-hidden">
     <div className="absolute top-0 right-0 w-2 h-2 bg-[#00f2ff]/20 rounded-bl-lg"></div>
     <div className="flex items-center gap-3 mb-2 text-slate-600 text-[10px] font-bold uppercase tracking-[0.3em]">
        {icon}
        {label}
     </div>
     <p className="text-sm font-mono text-white pl-6 group-hover:text-[#00f2ff] transition-colors">{value}</p>
  </div>
);

export const SHAPBar = ({ label, value, max, color }) => (
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

export const SOCTooltip = ({ active, payload }) => {
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

export const SOCPieTooltip = ({ active, payload }) => {
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
