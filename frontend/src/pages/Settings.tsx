import React, { useEffect, useState } from 'react';
import { Settings as SettingsIcon, Cpu, ShieldCheck, CheckCircle2, XCircle, AlertCircle, HardDrive } from 'lucide-react';
import { api } from '../services/api';

export const Settings: React.FC = () => {
  const [systemStatus, setSystemStatus] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    setLoading(true);
    try {
      const data = await api.getSystemSettings();
      setSystemStatus(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">System Settings & Health Status</h1>
        <p className="text-xs text-slate-400 font-mono mt-1">
          Scanner engine availability, LLM provider integration, and runtime limits inspection
        </p>
      </div>

      {/* Scanners Status */}
      <div className="p-6 rounded-xl glass-panel border border-cyber-border/80 space-y-4">
        <h2 className="text-sm font-bold text-white font-mono flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-cyber-cyan" />
          DETERMINISTIC SECURITY SCANNER ENGINES
        </h2>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {systemStatus?.scanners && Object.entries(systemStatus.scanners).map(([name, info]: any) => (
            <div key={name} className="p-4 rounded-lg bg-cyber-bg/70 border border-cyber-border flex items-start justify-between gap-3">
              <div>
                <h3 className="text-xs font-bold font-mono text-white uppercase">{name}</h3>
                <span className="text-[11px] text-slate-400 block mt-0.5">{info.mode}</span>
              </div>
              <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                info.installed ? 'bg-cyber-green/20 text-cyber-green border border-cyber-green/30' : 'bg-cyber-cyan/10 text-cyber-cyan border border-cyber-cyan/30'
              }`}>
                {info.installed ? 'Native CLI Active' : 'Fallback Engine Active'}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* AI & LLM Provider Status */}
      <div className="p-6 rounded-xl glass-panel border border-cyber-border/80 space-y-4">
        <h2 className="text-sm font-bold text-white font-mono flex items-center gap-2">
          <Cpu className="w-4 h-4 text-cyber-purple" />
          AI REASONING PROVIDER CONFIGURATION
        </h2>

        <div className="p-4 rounded-lg bg-cyber-bg/70 border border-cyber-border space-y-3 font-mono text-xs">
          <div className="flex items-center justify-between">
            <span className="text-slate-400">ACTIVE PROVIDER:</span>
            <span className="text-white font-bold uppercase">{systemStatus?.llm_provider || 'offline'}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-slate-400">ACTIVE MODEL:</span>
            <span className="text-cyber-cyan">{systemStatus?.model_name || 'offline-rule-engine-v1'}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-slate-400">OFFLINE FALLBACK SUPPORT:</span>
            <span className="text-cyber-green font-bold flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" /> ENABLED
            </span>
          </div>
        </div>
      </div>

      {/* Upload Limits */}
      <div className="p-6 rounded-xl glass-panel border border-cyber-border/80 space-y-4">
        <h2 className="text-sm font-bold text-white font-mono flex items-center gap-2">
          <HardDrive className="w-4 h-4 text-slate-300" />
          UPLOAD SECURITY LIMITS & GUARDRAILS
        </h2>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 font-mono text-xs">
          <div className="p-3.5 rounded-lg bg-cyber-bg border border-cyber-border">
            <span className="text-[10px] text-slate-400 block uppercase">Max Archive Size</span>
            <b className="text-white text-sm">{systemStatus?.limits?.max_upload_size_mb || 50} MB</b>
          </div>
          <div className="p-3.5 rounded-lg bg-cyber-bg border border-cyber-border">
            <span className="text-[10px] text-slate-400 block uppercase">Max Files Count</span>
            <b className="text-white text-sm">{systemStatus?.limits?.max_files_count || 2000} Files</b>
          </div>
          <div className="p-3.5 rounded-lg bg-cyber-bg border border-cyber-border">
            <span className="text-[10px] text-slate-400 block uppercase">Max Uncompressed</span>
            <b className="text-white text-sm">{systemStatus?.limits?.max_uncompressed_size_mb || 200} MB</b>
          </div>
        </div>
      </div>
    </div>
  );
};
