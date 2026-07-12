import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';

export const TopologyView = ({ traffic, alerts, onSelectNode }) => {
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
