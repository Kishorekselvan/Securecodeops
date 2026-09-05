import React, { useEffect, useState } from 'react';
import { FileCheck2, CheckCircle2, XCircle, AlertCircle, ShieldCheck, FileText, ArrowRight } from 'lucide-react';
import { api } from '../services/api';
import { ComplianceCheck } from '../types';

export const Compliance: React.FC = () => {
  const [checks, setChecks] = useState<ComplianceCheck[]>([]);
  const [selectedFramework, setSelectedFramework] = useState<string>('OWASP_TOP_10');
  const [loading, setLoading] = useState(true);

  const frameworks = [
    { id: 'OWASP_TOP_10', label: 'OWASP Top 10 2021' },
    { id: 'GDPR', label: 'GDPR Article 32' },
    { id: 'ISO_27001', label: 'ISO 27001 (A.8)' },
    { id: 'NIST_SP_800_53', label: 'NIST SP 800-53' },
    { id: 'PCI_DSS', label: 'PCI-DSS v4.0' }
  ];

  useEffect(() => {
    loadComplianceData();
  }, [selectedFramework]);

  const loadComplianceData = async () => {
    setLoading(true);
    try {
      const data = await api.getComplianceChecks({
        framework: selectedFramework || undefined
      });
      setChecks(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const passCount = checks.filter(c => c.status === 'PASS').length;
  const failCount = checks.filter(c => c.status === 'FAIL').length;
  const partialCount = checks.filter(c => c.status === 'PARTIAL').length;
  const frameworkScore = checks.length > 0 ? Math.round((passCount / checks.length) * 100) : 100;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Regulatory & Standard Compliance Matrix</h1>
        <p className="text-xs text-slate-400 font-mono mt-1">
          Automated control evaluation against global cybersecurity frameworks with deterministic evidence mapping
        </p>
      </div>

      {/* Framework Tabs */}
      <div className="flex flex-wrap gap-2">
        {frameworks.map((fw) => (
          <button
            key={fw.id}
            onClick={() => setSelectedFramework(fw.id)}
            className={`px-4 py-2 rounded-lg text-xs font-mono transition-all ${
              selectedFramework === fw.id
                ? 'bg-cyber-cyan text-black font-bold shadow-cyber-cyan'
                : 'bg-cyber-panel border border-cyber-border text-slate-300 hover:text-white'
            }`}
          >
            {fw.label}
          </button>
        ))}
      </div>

      {/* Score Summary Card */}
      <div className="p-6 rounded-xl glass-panel border border-cyber-border/80 flex flex-col sm:flex-row sm:items-center justify-between gap-6">
        <div className="space-y-1">
          <span className="text-xs font-mono text-cyber-muted uppercase">Framework Compliance Score</span>
          <div className="flex items-baseline gap-3">
            <span className="text-4xl font-extrabold text-white">{frameworkScore}%</span>
            <span className="text-xs text-slate-400 font-mono">
              ({passCount} Passing / {checks.length} Controls)
            </span>
          </div>
        </div>

        <div className="flex items-center gap-6 font-mono text-xs">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-cyber-green" />
            <span>{passCount} Pass</span>
          </div>
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-yellow-400" />
            <span>{partialCount} Partial</span>
          </div>
          <div className="flex items-center gap-2">
            <XCircle className="w-4 h-4 text-cyber-red" />
            <span>{failCount} Fail</span>
          </div>
        </div>
      </div>

      {/* Controls Breakdown List */}
      <div className="space-y-4">
        {checks.map((ctrl) => (
          <div key={ctrl.id} className="p-5 rounded-xl glass-panel border border-cyber-border/80 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2.5">
                <span className={`px-2.5 py-1 rounded text-xs font-mono font-bold ${
                  ctrl.status === 'PASS' ? 'bg-cyber-green/20 text-cyber-green border border-cyber-green/30' :
                  ctrl.status === 'FAIL' ? 'bg-cyber-red/20 text-cyber-red border border-cyber-red/30' :
                  'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30'
                }`}>
                  {ctrl.status}
                </span>

                <span className="font-mono text-xs font-bold text-cyber-cyan">
                  [{ctrl.control_id}]
                </span>

                <span className="font-bold text-sm text-white">{ctrl.control_name}</span>
              </div>

              <span className="text-xs font-mono text-slate-400">
                Control Score: <b className="text-white">{ctrl.score}%</b>
              </span>
            </div>

            {/* Evidence and findings */}
            <div className="text-xs text-slate-300 space-y-2">
              <div className="font-mono text-[11px] text-slate-400">
                EVIDENCE / AUDIT TRAIL:
              </div>
              <ul className="list-disc pl-5 space-y-1 text-slate-300">
                {ctrl.evidence?.map((ev, i) => (
                  <li key={i}>{ev}</li>
                ))}
              </ul>
            </div>

            {ctrl.recommendation && ctrl.status !== 'PASS' && (
              <div className="p-3 rounded-lg bg-cyber-panel/40 border border-cyber-border text-xs text-slate-200">
                <span className="font-bold text-yellow-400 block mb-1 font-mono">REMEDIATION RECOMMENDATION:</span>
                {ctrl.recommendation}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};
