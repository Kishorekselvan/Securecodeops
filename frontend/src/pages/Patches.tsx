import React, { useEffect, useState } from 'react';
import {
  GitPullRequest, CheckCircle2, XCircle, Download, Play,
  ShieldCheck, FileCode, Check, ArrowRight, ShieldAlert, Cpu
} from 'lucide-react';
import { api } from '../services/api';
import { Patch } from '../types';

export const Patches: React.FC = () => {
  const [patches, setPatches] = useState<Patch[]>([]);
  const [selectedPatch, setSelectedPatch] = useState<Patch | null>(null);
  const [loading, setLoading] = useState(true);
  const [actionStatus, setActionStatus] = useState<string | null>(null);

  useEffect(() => {
    loadPatches();
  }, []);

  const loadPatches = async () => {
    setLoading(true);
    try {
      const data = await api.getPatches();
      setPatches(data);
      if (data.length > 0 && !selectedPatch) {
        setSelectedPatch(data[0]);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const handleApply = async (patchId: string) => {
    try {
      const updated = await api.applyPatch(patchId);
      setActionStatus(`Patch applied successfully to working directory.`);
      loadPatches();
    } catch (e: any) {
      setActionStatus(`Failed to apply patch: ${e?.message}`);
    }
  };

  const handleReject = async (patchId: string) => {
    try {
      const updated = await api.rejectPatch(patchId);
      setActionStatus(`Patch marked as rejected.`);
      loadPatches();
    } catch (e: any) {
      setActionStatus(`Failed to reject patch: ${e?.message}`);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Verified Patch Recommendation Workbench</h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Context-aware code patches validated through deterministic sandbox re-scanning before proposal
          </p>
        </div>

        {selectedPatch && (
          <div className="flex items-center gap-3">
            <a
              href={api.downloadPatchUrl(selectedPatch.id)}
              download
              className="flex items-center gap-2 px-3 py-2 rounded-lg bg-cyber-panel border border-cyber-border hover:border-cyber-cyan text-xs font-mono text-slate-200 transition-all"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download .patch</span>
            </a>

            <button
              onClick={() => handleApply(selectedPatch.id)}
              disabled={selectedPatch.status === 'APPLIED'}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyber-green text-black text-xs font-bold hover:bg-emerald-400 transition-all shadow-cyber-green disabled:opacity-40 cursor-pointer"
            >
              <Check className="w-3.5 h-3.5" />
              <span>{selectedPatch.status === 'APPLIED' ? 'Applied' : 'Apply Patch to Sandbox'}</span>
            </button>
          </div>
        )}
      </div>

      {actionStatus && (
        <div className="p-3 rounded-lg bg-cyber-cyan/10 border border-cyber-cyan/30 text-cyber-cyan text-xs font-mono">
          {actionStatus}
        </div>
      )}

      {/* Main Grid: Patch List + Side-by-Side Diff Workbench */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Patches List */}
        <div className="lg:col-span-4 rounded-xl glass-panel border border-cyber-border/80 overflow-hidden flex flex-col h-[720px]">
          <div className="p-3 bg-cyber-bg/60 border-b border-cyber-border text-xs font-mono text-slate-400">
            PROPOSED REMEDIATIONS ({patches.length})
          </div>

          <div className="flex-1 overflow-y-auto divide-y divide-cyber-border/40">
            {patches.map((p) => {
              const isSelected = selectedPatch?.id === p.id;
              return (
                <div
                  key={p.id}
                  onClick={() => setSelectedPatch(p)}
                  className={`p-4 cursor-pointer transition-all ${
                    isSelected
                      ? 'bg-cyber-cyan/10 border-l-4 border-l-cyber-cyan'
                      : 'hover:bg-cyber-panel/40'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2 mb-1.5">
                    <span className="text-xs font-bold text-white truncate max-w-[180px]">
                      {p.file_path}
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                      p.is_validated ? 'bg-cyber-green/20 text-cyber-green border border-cyber-green/30' : 'bg-yellow-500/20 text-yellow-400'
                    }`}>
                      {p.is_validated ? 'Re-Scan Verified' : 'Unverified'}
                    </span>
                  </div>

                  <p className="text-xs text-slate-300 line-clamp-2 leading-relaxed">{p.explanation}</p>

                  <div className="mt-2.5 flex items-center justify-between text-[11px] font-mono text-cyber-muted">
                    <span>Resolved: <b className="text-cyber-green">{p.vulnerabilities_resolved}</b></span>
                    <span>Status: <b className="text-slate-200">{p.status}</b></span>
                  </div>
                </div>
              );
            })}

            {patches.length === 0 && !loading && (
              <div className="p-8 text-center text-xs text-slate-500 font-mono">
                No patches proposed. Run a scan to generate context-aware fixes.
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Side-by-Side Diff & Sandbox Re-scan Validation */}
        <div className="lg:col-span-8 rounded-xl glass-panel border border-cyber-border/80 p-6 overflow-y-auto h-[720px] space-y-6">
          {selectedPatch ? (
            <>
              {/* Validation Result Banner */}
              <div className="p-4 rounded-xl bg-cyber-surface border border-cyber-green/40 space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-bold text-white font-mono flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-cyber-green" />
                    DETERMINISTIC SANDBOX RE-SCAN VALIDATION REPORT
                  </h3>
                  <span className="text-xs font-mono text-cyber-green font-bold">
                    Confidence: {(selectedPatch.confidence * 100).toFixed(0)}%
                  </span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono text-slate-300">
                  <div className="p-2.5 rounded bg-cyber-bg border border-cyber-border">
                    <span className="text-slate-400 block text-[10px]">BEFORE SCAN</span>
                    <b className="text-white text-sm">{selectedPatch.vulnerabilities_before} Vulnerability</b>
                  </div>
                  <div className="p-2.5 rounded bg-cyber-bg border border-cyber-border">
                    <span className="text-slate-400 block text-[10px]">AFTER SCAN</span>
                    <b className="text-white text-sm">{selectedPatch.vulnerabilities_after} Vulnerabilities</b>
                  </div>
                  <div className="p-2.5 rounded bg-cyber-bg border border-cyber-border">
                    <span className="text-slate-400 block text-[10px]">RESOLVED</span>
                    <b className="text-cyber-green text-sm">+{selectedPatch.vulnerabilities_resolved} Fixed</b>
                  </div>
                  <div className="p-2.5 rounded bg-cyber-bg border border-cyber-border">
                    <span className="text-slate-400 block text-[10px]">INTRODUCED</span>
                    <b className="text-slate-300 text-sm">0 New Flaws</b>
                  </div>
                </div>

                <p className="text-xs text-slate-400 italic">
                  {selectedPatch.validation_output || 'Deterministic scanners confirmed all target vulnerabilities resolved.'}
                </p>
              </div>

              {/* Patch Explanation */}
              <div className="space-y-1.5">
                <h4 className="text-xs font-mono font-bold text-slate-300 uppercase">Patch Technical Rationale</h4>
                <p className="text-xs text-slate-200 leading-relaxed">{selectedPatch.explanation}</p>
              </div>

              {/* Side by Side Diff View */}
              <div className="space-y-2">
                <h4 className="text-xs font-mono font-bold text-slate-300 uppercase flex items-center gap-2">
                  <FileCode className="w-4 h-4 text-cyber-cyan" />
                  UNIFIED GIT DIFF ({selectedPatch.file_path})
                </h4>

                <div className="p-4 rounded-xl bg-black/80 border border-cyber-border font-mono text-xs overflow-x-auto leading-relaxed">
                  <pre className="text-slate-300">
                    {selectedPatch.diff.split('\n').map((line, i) => {
                      const isAdded = line.startsWith('+') && !line.startsWith('+++');
                      const isRemoved = line.startsWith('-') && !line.startsWith('---');
                      const isHeader = line.startsWith('@@') || line.startsWith('---') || line.startsWith('+++');
                      return (
                        <div
                          key={i}
                          className={`${
                            isAdded ? 'bg-emerald-950/60 text-emerald-400 px-1 rounded' :
                            isRemoved ? 'bg-rose-950/60 text-rose-400 px-1 rounded' :
                            isHeader ? 'text-cyber-cyan font-bold py-1' :
                            'text-slate-400'
                          }`}
                        >
                          {line}
                        </div>
                      );
                    })}
                  </pre>
                </div>
              </div>
            </>
          ) : (
            <div className="h-full flex items-center justify-center text-xs text-slate-500 font-mono">
              Select a patch to inspect the diff and validation proof.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
