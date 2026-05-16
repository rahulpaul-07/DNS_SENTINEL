import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  ScatterChart, Scatter, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, ZAxis
} from 'recharts';
import { Database, Download, Activity, Cpu } from 'lucide-react';

const DatasetStudio = () => {
  const [params, setParams] = useState({
    attack_type: 'DGA',
    n_samples: 100,
    entropy_min: 3.5,
    entropy_max: 5.0,
    ttl_range: [60, 300],
    query_rate: 10
  });

  const [isGenerating, setIsGenerating] = useState(false);
  const [generatedSamples, setGeneratedSamples] = useState([]);
  const [datasetId, setDatasetId] = useState(null);
  
  const [qualityScore, setQualityScore] = useState(null);
  const [pcaData, setPcaData] = useState([]);
  const [isScoring, setIsScoring] = useState(false);

  const handleGenerate = async () => {
    setIsGenerating(true);
    try {
      const res = await fetch("http://localhost:8001/dataset/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(params)
      });
      const data = await res.json();
      setGeneratedSamples(data.samples);
      setDatasetId(data.id);
      
      // Auto-trigger fidelity score
      evaluateQuality(data.samples);
    } catch (err) {
      console.error(err);
      alert("Generation failed");
    } finally {
      setIsGenerating(false);
    }
  };

  const evaluateQuality = async (samples) => {
    setIsScoring(true);
    try {
      const res = await fetch("http://localhost:8001/dataset/quality", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ synthetic_samples: samples })
      });
      const data = await res.json();
      setQualityScore(data);
      if (data.pca_data) setPcaData(data.pca_data);
    } catch (err) {
      console.error(err);
    } finally {
      setIsScoring(false);
    }
  };

  const handleExport = () => {
    if (datasetId) {
      window.open(`http://localhost:8001/dataset/export/${datasetId}`, "_blank");
    }
  };

  return (
    <div className="grid grid-cols-1 xl:grid-cols-12 gap-8 h-[820px]">
      
      {/* Left Panel: Params */}
      <div className="xl:col-span-3 glass-panel p-8 flex flex-col">
        <h2 className="text-[11px] font-bold text-slate-500 tracking-[0.3em] uppercase mb-8 flex items-center gap-3">
          <Database size={16} className="text-[#00f2ff]" />
          CTGAN Parameters
        </h2>
        
        <div className="space-y-6 flex-1">
          <div>
             <label className="text-[10px] text-slate-400 font-bold uppercase tracking-widest block mb-2">Target Profile</label>
             <select 
               value={params.attack_type} 
               onChange={(e) => setParams({...params, attack_type: e.target.value})}
               className="w-full bg-black/50 border border-white/10 rounded-xl p-3 text-sm text-slate-200 outline-none"
             >
               <option value="DGA">DGA (High Entropy)</option>
               <option value="Tunneling">DNS Tunneling</option>
               <option value="Exfiltration">Data Exfiltration</option>
               <option value="Benign">Benign Baseline</option>
             </select>
          </div>
          
          <div>
             <label className="text-[10px] text-slate-400 font-bold uppercase tracking-widest block mb-2">Synthesis Volume</label>
             <input 
               type="range" min="10" max="5000" step="10" 
               value={params.n_samples} onChange={(e) => setParams({...params, n_samples: parseInt(e.target.value)})}
               className="w-full"
             />
             <div className="text-right text-xs font-mono text-[#00f2ff] mt-1">{params.n_samples} VECTORS</div>
          </div>
          
          <div>
             <label className="text-[10px] text-slate-400 font-bold uppercase tracking-widest block mb-2">Entropy Range</label>
             <div className="flex gap-4">
                <input type="number" step="0.1" value={params.entropy_min} onChange={(e) => setParams({...params, entropy_min: parseFloat(e.target.value)})} className="w-1/2 bg-black/50 border border-white/10 rounded-lg p-2 text-xs font-mono text-white text-center" />
                <input type="number" step="0.1" value={params.entropy_max} onChange={(e) => setParams({...params, entropy_max: parseFloat(e.target.value)})} className="w-1/2 bg-black/50 border border-white/10 rounded-lg p-2 text-xs font-mono text-white text-center" />
             </div>
          </div>
          
          <div>
             <label className="text-[10px] text-slate-400 font-bold uppercase tracking-widest block mb-2">TTL Noise (Min / Max)</label>
             <div className="flex gap-4">
                <input type="number" value={params.ttl_range[0]} onChange={(e) => setParams({...params, ttl_range: [parseInt(e.target.value), params.ttl_range[1]]})} className="w-1/2 bg-black/50 border border-white/10 rounded-lg p-2 text-xs font-mono text-white text-center" />
                <input type="number" value={params.ttl_range[1]} onChange={(e) => setParams({...params, ttl_range: [params.ttl_range[0], parseInt(e.target.value)]})} className="w-1/2 bg-black/50 border border-white/10 rounded-lg p-2 text-xs font-mono text-white text-center" />
             </div>
          </div>
        </div>
        
        <button 
          onClick={handleGenerate} disabled={isGenerating}
          className="w-full py-4 mt-6 bg-[#00f2ff]/10 hover:bg-[#00f2ff]/20 border border-[#00f2ff]/30 text-[#00f2ff] rounded-xl font-bold tracking-[0.2em] uppercase text-xs transition-all flex justify-center items-center gap-3"
        >
          {isGenerating ? <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin"></div> : <><Cpu size={16}/> Forge Dataset</>}
        </button>
      </div>

      {/* Center Panel: Preview */}
      <div className="xl:col-span-5 glass-panel p-8 flex flex-col">
         <div className="flex justify-between items-center mb-6 pb-4 border-b border-white/5">
            <h2 className="text-[11px] font-bold text-slate-500 tracking-[0.3em] uppercase flex items-center gap-3">
              <Activity size={16} /> Data Stream Preview
            </h2>
            <div className="text-[9px] font-bold px-2 py-1 bg-black/40 rounded border border-white/10 text-slate-400">
               {generatedSamples.length} GENERATED
            </div>
         </div>
         
         <div className="flex-1 overflow-auto custom-scrollbar">
            <table className="w-full text-left">
               <thead className="sticky top-0 bg-[#020814]/90 backdrop-blur z-10 text-[10px] text-slate-500 uppercase tracking-widest font-bold">
                  <tr>
                     <th className="py-3 px-2">Index</th>
                     <th className="py-3 px-2">Entropy</th>
                     <th className="py-3 px-2">Length</th>
                     <th className="py-3 px-2">Target Type</th>
                  </tr>
               </thead>
               <tbody className="divide-y divide-white/[0.04]">
                  {generatedSamples.slice(0, 100).map((s, i) => (
                     <tr key={i} className="hover:bg-white/5 text-xs font-mono text-slate-300">
                        <td className="py-3 px-2 opacity-50">#{i}</td>
                        <td className="py-3 px-2 text-[#00f2ff]">{s.entropy?.toFixed(3)}</td>
                        <td className="py-3 px-2">{Math.round(s.length)}</td>
                        <td className="py-3 px-2">
                           <span className="px-2 py-0.5 rounded bg-white/10 text-[10px]">{s.attack_type}</span>
                        </td>
                     </tr>
                  ))}
                  {generatedSamples.length === 0 && (
                     <tr><td colSpan="4" className="text-center py-20 text-slate-600 italic">No samples generated yet.</td></tr>
                  )}
               </tbody>
            </table>
         </div>
         
         <button 
          onClick={handleExport} disabled={!datasetId}
          className={`mt-6 w-full py-4 rounded-xl font-bold tracking-[0.2em] uppercase text-xs transition-all flex justify-center items-center gap-3
            ${datasetId ? 'bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-400 border border-indigo-500/30' : 'bg-slate-900 text-slate-600 border border-slate-800 cursor-not-allowed'}
          `}
         >
            <Download size={16}/> Export CSV Package
         </button>
      </div>

      {/* Right Panel: Fidelity PCA */}
      <div className="xl:col-span-4 glass-panel p-8 flex flex-col relative overflow-hidden">
         <h2 className="text-[11px] font-bold text-slate-500 tracking-[0.3em] uppercase mb-8 flex items-center gap-3">
           Synthesis Fidelity Assessment
         </h2>
         
         {isScoring ? (
            <div className="flex-1 flex flex-col items-center justify-center opacity-50">
               <div className="w-8 h-8 border-4 border-indigo-500 border-t-transparent rounded-full animate-spin mb-4"></div>
               <p className="text-xs font-mono uppercase tracking-widest text-indigo-400">Running Adversarial Validation...</p>
            </div>
         ) : qualityScore ? (
            <>
               {/* Fidelity Gauge */}
               <div className="flex items-center justify-center mb-8 bg-black/40 py-6 rounded-3xl border border-white/5">
                  <div className="text-center">
                     <p className="text-[10px] font-bold text-slate-500 uppercase tracking-[0.3em] mb-2">Global Fidelity Score</p>
                     <div className="text-4xl font-black text-emerald-400 drop-shadow-[0_0_15px_rgba(52,211,153,0.3)]">
                        {(qualityScore.fidelity_score * 100).toFixed(1)}%
                     </div>
                     <p className="text-[9px] text-slate-600 uppercase mt-2">Discrimination Acc: {(qualityScore.accuracy * 100).toFixed(1)}%</p>
                  </div>
               </div>

               {/* PCA Scatter Plot */}
               <div className="flex-1 min-h-[300px] relative">
                  <div className="absolute top-0 right-0 flex gap-4 text-[10px] font-bold uppercase z-10">
                     <div className="flex items-center gap-2 text-[#00f2ff]"><div className="w-2 h-2 rounded-full bg-[#00f2ff]"></div> Synthetic</div>
                     <div className="flex items-center gap-2 text-rose-500"><div className="w-2 h-2 rounded-full bg-rose-500"></div> Real</div>
                  </div>
                  <ResponsiveContainer width="100%" height="100%">
                     <ScatterChart margin={{ top: 20, right: 10, bottom: 10, left: -20 }}>
                       <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                       <XAxis type="number" dataKey="x" stroke="#475569" fontSize={10} />
                       <YAxis type="number" dataKey="y" stroke="#475569" fontSize={10} />
                       <ZAxis range={[20, 20]} />
                       <Tooltip cursor={{ strokeDasharray: '3 3' }} contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b' }} />
                       <Scatter name="Synthetic" data={pcaData.filter(d => d.type === 'Synthetic')} fill="#00f2ff" fillOpacity={0.6} />
                       <Scatter name="Real" data={pcaData.filter(d => d.type === 'Real')} fill="#f43f5e" fillOpacity={0.6} />
                     </ScatterChart>
                  </ResponsiveContainer>
               </div>
            </>
         ) : (
            <div className="flex-1 flex flex-col items-center justify-center opacity-20">
               <Database size={48} className="mb-4" />
               <p className="text-xs font-mono uppercase tracking-widest text-slate-400">Awaiting Dataset Generation</p>
            </div>
         )}
      </div>

    </div>
  );
};

export default DatasetStudio;
