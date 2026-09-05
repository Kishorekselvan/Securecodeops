import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  AlertTriangle, Search, Filter, Cpu, ShieldCheck, ShieldAlert,
  FileCode, ExternalLink, GitPullRequest, CheckCircle2, XCircle, Info
} from 'lucide-react';
import { api } from '../services/api';
import { Finding } from '../types';

export const Findings: React.FC = () => {
  const navigate = useNavigate();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [scannerFilter, setScannerFilter] = useState('');
  const [aiFilter, setAiFilter] = useState('');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  useEffect(() => {
    loadFindings();
  }, [severityFilter, categoryFilter, scannerFilter, aiFilter]);

  const loadFindings = async () => {
    setLoading(true);
    try {
      const data = await api.getFindings({
        severity: severityFilter || undefined,
        category: categoryFilter || undefined,
        scanner: scannerFilter || undefined,
        ai_status: aiFilter || undefined
      });
      setFindings(data);
      if (data.length > 0 && !selectedFinding) {
        setSelectedFinding(data[0]);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const filtered = findings.filter(f =>
    f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
    f.file_path.toLowerCase().includes(searchQuery.toLowerCase()) ||
    (f.cwe && f.cwe.toLowerCase().includes(searchQuery.toLowerCase()))
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Security Vulnerabilities & Findings</h1>
        <p className="text-xs text-slate-400 font-mono mt-1">
          Normalized findings from deterministic scanners coupled with AI exploitability validation
        </p>
      </div>

      {/* Filter Bar */}
      <div className="p-4 rounded-xl glass-panel border border-cyber-border/80 flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search by title, file, or CWE..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-cyber-bg border border-cyber-border rounded-lg pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyber-cyan font-mono"
          />
        </div>

        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="bg-cyber-bg border border-cyber-border rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyber-cyan font-mono"
        >
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>

        <select
          value={scannerFilter}
          onChange={(e) => setScannerFilter(e.target.value)}
          className="bg-cyber-bg border border-cyber-border rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyber-cyan font-mono"
        >
          <option value="">All Scanners</option>
          <option value="semgrep">Semgrep</option>
          <option value="bandit">Bandit</option>
          <option value="gitleaks">GitLeaks</option>
          <option value="trivy">Trivy</option>
        </select>

        <select
          value={aiFilter}
          onChange={(e) => setAiFilter(e.target.value)}
          className="bg-cyber-bg border border-cyber-border rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyber-cyan font-mono"
        >
          <option value="">All AI Statuses</option>
          <option value="VALIDATED">AI Validated</option>
          <option value="FALSE_POSITIVE">False Positive</option>
          <option value="UNCERTAIN">Uncertain</option>
        </select>
      </div>

      {/* Main Grid: Findings List + Detail Drawer */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: List */}
        <div className="lg:col-span-5 rounded-xl glass-panel border border-cyber-border/80 overflow-hidden flex flex-col h-[700px]">
          <div className="p-3 bg-cyber-bg/60 border-b border-cyber-border text-xs font-mono text-slate-400 flex items-center justify-between">
            <span>SHOWING {filtered.length} FINDINGS</span>
          </div>

          <div className="flex-1 overflow-y-auto divide-y divide-cyber-border/40">
            {filtered.map((f) => {
              const isSelected = selectedFinding?.id === f.id;
              return (
                <div
                  key={f.id}
                  onClick={() => setSelectedFinding(f)}
                  className={`p-4 cursor-pointer transition-all ${
                    isSelected
                      ? 'bg-cyber-cyan/10 border-l-4 border-l-cyber-cyan'
                      : 'hover:bg-cyber-panel/40'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2 mb-1.5">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                      f.severity === 'CRITICAL' ? 'bg-cyber-red/20 text-cyber-red border border-cyber-red/30' :
                      f.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
                      f.severity === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30' :
                      'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                    }`}>
                      {f.severity}
                    </span>

                    <span className="text-[10px] font-mono text-slate-400 uppercase">
                      {f.scanner}
                    </span>
                  </div>

                  <h3 className="text-xs font-bold text-white line-clamp-1 mb-1">{f.title}</h3>
                  
                  <div className="flex items-center justify-between text-[11px] text-cyber-muted font-mono">
                    <span className="truncate max-w-[200px]">{f.file_path}:{f.line_number}</span>
                    {f.ai_validation_status === 'VALIDATED' && (
                      <span className="text-cyber-green flex items-center gap-1 text-[10px]">
                        <CheckCircle2 className="w-3 h-3" /> Validated
                      </span>
                    )}
                    {f.ai_validation_status === 'FALSE_POSITIVE' && (
                      <span className="text-cyber-purple flex items-center gap-1 text-[10px]">
                        <XCircle className="w-3 h-3" /> False Positive
                      </span>
                    )}
                  </div>
                </div>
              );
            })}

            {filtered.length === 0 && !loading && (
              <div className="p-8 text-center text-xs text-slate-500 font-mono">
                No vulnerabilities matched your filters.
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Detailed View Drawer */}
        <div className="lg:col-span-7 rounded-xl glass-panel border border-cyber-border/80 p-6 overflow-y-auto h-[700px] space-y-6">
          {selectedFinding ? (
            <>
              {/* Header Details */}
              <div className="border-b border-cyber-border pb-5">
                <div className="flex flex-wrap items-center justify-between gap-3 mb-2">
                  <div className="flex items-center gap-2">
                    <span className={`px-2.5 py-1 rounded text-xs font-mono font-bold ${
                      selectedFinding.severity === 'CRITICAL' ? 'bg-cyber-red/20 text-cyber-red border border-cyber-red/30' :
                      selectedFinding.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
                      selectedFinding.severity === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30' :
                      'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                    }`}>
                      {selectedFinding.severity}
                    </span>
                    <span className="text-xs font-mono text-slate-400">
                      Scanner: <b className="text-slate-200">{selectedFinding.scanner}</b>
                    </span>
                  </div>

                  <button
                    onClick={() => navigate('/patches')}
                    className="flex items-center gap-1.5 px-3 py-1 rounded bg-cyber-cyan/10 hover:bg-cyber-cyan/20 border border-cyber-cyan/30 text-cyber-cyan text-xs font-mono font-medium transition-all"
                  >
                    <GitPullRequest className="w-3.5 h-3.5" />
                    <span>View Proposed Patch &rarr;</span>
                  </button>
                </div>

                <h2 className="text-lg font-bold text-white mb-2">{selectedFinding.title}</h2>
                <p className="text-xs text-slate-300 leading-relaxed">{selectedFinding.description}</p>
                
                <div className="flex flex-wrap items-center gap-4 mt-3 text-xs font-mono text-cyber-muted">
                  <span>CWE: <b className="text-slate-200">{selectedFinding.cwe || 'N/A'}</b></span>
                  <span>&bull;</span>
                  <span>OWASP: <b className="text-slate-200">{selectedFinding.owasp || 'N/A'}</b></span>
                  <span>&bull;</span>
                  <span>Location: <b className="text-slate-200">{selectedFinding.file_path}:{selectedFinding.line_number}</b></span>
                </div>
              </div>

              {/* Code Snippet */}
              {selectedFinding.code_snippet && (
                <div className="space-y-2">
                  <h3 className="text-xs font-bold font-mono text-slate-300 flex items-center gap-2">
                    <FileCode className="w-4 h-4 text-cyber-cyan" />
                    VULNERABLE CODE SNIPPET ({selectedFinding.file_path})
                  </h3>
                  <div className="p-4 rounded-lg bg-black/70 border border-cyber-border font-mono text-xs text-slate-200 overflow-x-auto leading-relaxed border-l-4 border-l-cyber-red">
                    <pre>{selectedFinding.code_snippet}</pre>
                  </div>
                </div>
              )}

              {/* AI Exploitability Validation Box */}
              <div className="p-4 rounded-xl bg-cyber-surface/90 border border-cyber-purple/40 space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-bold text-white font-mono flex items-center gap-2">
                    <Cpu className="w-4 h-4 text-cyber-purple" />
                    AI CONTEXTUAL REASONING & VALIDATION
                  </h3>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                    selectedFinding.ai_validation_status === 'VALIDATED' ? 'bg-cyber-green/20 text-cyber-green border border-cyber-green/30' :
                    selectedFinding.ai_validation_status === 'FALSE_POSITIVE' ? 'bg-cyber-purple/20 text-cyber-purple border border-cyber-purple/30' :
                    'bg-slate-700 text-slate-300'
                  }`}>
                    {selectedFinding.ai_validation_status}
                  </span>
                </div>

                <p className="text-xs text-slate-300 leading-relaxed">
                  {selectedFinding.ai_reasoning || 'Deterministic finding verified against application AST context.'}
                </p>

                {selectedFinding.ai_attack_scenario && (
                  <div className="mt-2 text-xs text-slate-400 bg-cyber-bg/60 p-3 rounded border border-cyber-border">
                    <span className="font-bold text-slate-200 block mb-1 font-mono">ATTACK SCENARIO:</span>
                    {selectedFinding.ai_attack_scenario}
                  </div>
                )}
              </div>

              {/* Remediation Guidance */}
              <div className="p-4 rounded-xl bg-cyber-panel/40 border border-cyber-border space-y-2">
                <h3 className="text-xs font-bold text-white font-mono flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-cyber-green" />
                  RECOMMENDED REMEDIATION
                </h3>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {selectedFinding.ai_remediation || 'Apply parameterized inputs, context-aware output encoding, or secret isolation.'}
                </p>
              </div>
            </>
          ) : (
            <div className="h-full flex items-center justify-center text-xs text-slate-500 font-mono">
              Select a vulnerability finding to inspect code evidence and AI reasoning.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
