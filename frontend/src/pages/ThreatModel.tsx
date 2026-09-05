import React, { useEffect, useState } from 'react';
import {
  ShieldAlert, Layers, ShieldCheck, AlertCircle, ArrowDown,
  ArrowRight, Cpu, Lock, CheckCircle2, ChevronRight
} from 'lucide-react';
import { api } from '../services/api';
import type { Threat } from '../types';

export const ThreatModel: React.FC = () => {
  const [threats, setThreats] = useState<Threat[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedCategory, setSelectedCategory] = useState<string>('');
  const [selectedThreat, setSelectedThreat] = useState<Threat | null>(null);

  const categories = [
    'Spoofing', 'Tampering', 'Repudiation', 'Information Disclosure',
    'Denial of Service', 'Elevation of Privilege'
  ];

  useEffect(() => {
    loadThreats();
  }, [selectedCategory]);

  const loadThreats = async () => {
    setLoading(true);
    try {
      const data = await api.getThreats({
        category: selectedCategory || undefined
      });
      setThreats(data);
      if (data.length > 0 && !selectedThreat) {
        setSelectedThreat(data[0]);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">STRIDE Threat Modeling & Attack Paths</h1>
        <p className="text-xs text-slate-400 font-mono mt-1">
          Automated architectural threat analysis with Impact &times; Probability risk matrices and attack paths
        </p>
      </div>

      {/* Category Tabs */}
      <div className="flex flex-wrap gap-2">
        <button
          onClick={() => setSelectedCategory('')}
          className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all ${
            selectedCategory === ''
              ? 'bg-cyber-cyan text-black font-bold shadow-cyber-cyan'
              : 'bg-cyber-panel border border-cyber-border text-slate-300 hover:text-white'
          }`}
        >
          All STRIDE ({threats.length})
        </button>
        {categories.map((cat) => (
          <button
            key={cat}
            onClick={() => setSelectedCategory(cat)}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all ${
              selectedCategory === cat
                ? 'bg-cyber-cyan text-black font-bold shadow-cyber-cyan'
                : 'bg-cyber-panel border border-cyber-border text-slate-300 hover:text-white'
            }`}
          >
            {cat}
          </button>
        ))}
      </div>

      {/* Grid: Threat Cards & Attack Path Visualizer */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Threats List */}
        <div className="lg:col-span-5 rounded-xl glass-panel border border-cyber-border/80 overflow-hidden flex flex-col h-[700px]">
          <div className="p-3 bg-cyber-bg/60 border-b border-cyber-border text-xs font-mono text-slate-400">
            STRIDE THREAT INVENTORY
          </div>

          <div className="flex-1 overflow-y-auto divide-y divide-cyber-border/40">
            {threats.map((t) => {
              const isSelected = selectedThreat?.id === t.id;
              return (
                <div
                  key={t.id}
                  onClick={() => setSelectedThreat(t)}
                  className={`p-4 cursor-pointer transition-all ${
                    isSelected
                      ? 'bg-cyber-cyan/10 border-l-4 border-l-cyber-cyan'
                      : 'hover:bg-cyber-panel/40'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2 mb-1.5">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyber-panel border border-cyber-border text-cyber-cyan font-bold">
                      {t.category}
                    </span>
                    
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                      t.risk_level === 'Critical' ? 'bg-cyber-red/20 text-cyber-red border border-cyber-red/30' :
                      t.risk_level === 'High' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
                      t.risk_level === 'Medium' ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30' :
                      'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                    }`}>
                      {t.risk_level} (Risk: {t.risk_score})
                    </span>
                  </div>

                  <h3 className="text-xs font-bold text-white line-clamp-1 mb-1">{t.title}</h3>
                  <p className="text-[11px] text-slate-400 line-clamp-2">{t.description}</p>
                  
                  <div className="mt-2 text-[10px] font-mono text-cyber-muted flex items-center justify-between">
                    <span>Component: {t.affected_component}</span>
                    <span>{t.impact} &times; {t.probability}</span>
                  </div>
                </div>
              );
            })}

            {threats.length === 0 && !loading && (
              <div className="p-8 text-center text-xs text-slate-500 font-mono">
                No STRIDE threats found for this category.
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Interactive Attack Path Visualizer */}
        <div className="lg:col-span-7 rounded-xl glass-panel border border-cyber-border/80 p-6 overflow-y-auto h-[700px] space-y-6">
          {selectedThreat ? (
            <>
              {/* Threat Overview */}
              <div className="border-b border-cyber-border pb-5">
                <div className="flex items-center justify-between mb-2">
                  <span className="px-2.5 py-1 rounded text-xs font-mono font-bold bg-cyber-panel text-cyber-cyan border border-cyber-cyan/30">
                    {selectedThreat.category}
                  </span>
                  <div className="text-xs font-mono text-slate-300">
                    Impact: <b className="text-white">{selectedThreat.impact}/5</b> &bull; Probability: <b className="text-white">{selectedThreat.probability}/5</b> &bull; Risk Score: <b className="text-cyber-red">{selectedThreat.risk_score}/25</b>
                  </div>
                </div>

                <h2 className="text-base font-bold text-white mb-2">{selectedThreat.title}</h2>
                <p className="text-xs text-slate-300 leading-relaxed">{selectedThreat.description}</p>

                <div className="mt-3 grid grid-cols-2 gap-3 text-xs font-mono text-slate-400 bg-cyber-bg/50 p-3 rounded-lg border border-cyber-border">
                  <div>Affected Component: <span className="text-white block truncate">{selectedThreat.affected_component}</span></div>
                  <div>Attack Vector: <span className="text-white block truncate">{selectedThreat.attack_vector}</span></div>
                </div>
              </div>

              {/* Attack Path Visual Flow */}
              <div className="space-y-3">
                <h3 className="text-xs font-bold font-mono text-white flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-cyber-cyan" />
                  CONCRETE ATTACK PATH FLOW (SOURCE &rarr; SINK)
                </h3>

                <div className="space-y-2 relative">
                  {selectedThreat.attack_path?.map((step, idx) => (
                    <React.Fragment key={idx}>
                      <div className="p-3.5 rounded-lg bg-cyber-surface border border-cyber-border/80 flex items-start gap-3 relative">
                        <div className="w-6 h-6 rounded-full bg-cyber-cyan/10 border border-cyber-cyan/40 text-cyber-cyan text-xs font-mono font-bold flex items-center justify-center flex-shrink-0">
                          {step.step || idx + 1}
                        </div>
                        <div className="flex-1 space-y-1">
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-bold text-white">{step.name}</span>
                            <span className="text-[10px] font-mono uppercase text-cyber-muted px-1.5 py-0.5 rounded bg-cyber-panel">
                              {step.type}
                            </span>
                          </div>
                          <p className="text-xs text-slate-300 leading-relaxed">{step.description}</p>
                          {step.code_snippet && (
                            <div className="p-2 rounded bg-black/70 border border-cyber-border font-mono text-[11px] text-cyber-red mt-1">
                              <code>{step.code_snippet}</code>
                            </div>
                          )}
                        </div>
                      </div>
                      {idx < selectedThreat.attack_path.length - 1 && (
                        <div className="flex justify-center my-0.5">
                          <ArrowDown className="w-4 h-4 text-cyber-cyan animate-bounce" />
                        </div>
                      )}
                    </React.Fragment>
                  ))}
                </div>
              </div>

              {/* Controls & Mitigations */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="p-4 rounded-xl bg-cyber-panel/30 border border-cyber-border">
                  <h4 className="text-xs font-bold font-mono text-slate-300 mb-2 flex items-center gap-1.5">
                    <AlertCircle className="w-3.5 h-3.5 text-yellow-400" />
                    Existing Controls
                  </h4>
                  <ul className="text-xs text-slate-400 space-y-1 list-disc pl-4">
                    {selectedThreat.existing_controls?.map((c: string, i: number) => (
                      <li key={i}>{c}</li>
                    ))}
                  </ul>
                </div>

                <div className="p-4 rounded-xl bg-cyber-green/5 border border-cyber-green/30">
                  <h4 className="text-xs font-bold font-mono text-cyber-green mb-2 flex items-center gap-1.5">
                    <ShieldCheck className="w-3.5 h-3.5" />
                    Recommended Controls
                  </h4>
                  <ul className="text-xs text-slate-300 space-y-1 list-disc pl-4">
                    {selectedThreat.recommended_controls?.map((c: string, i: number) => (
                      <li key={i}>{c}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </>
          ) : (
            <div className="h-full flex items-center justify-center text-xs text-slate-500 font-mono">
              Select a STRIDE threat to visualize the attack path and recommended controls.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
