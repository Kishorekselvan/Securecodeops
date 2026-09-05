import React, { useEffect, useState } from 'react';
import { ShieldCheck, FileCode, CheckCircle2, AlertTriangle, Cpu } from 'lucide-react';
import { api } from '../services/api';
import { ScanSummary } from '../types';

export const CodeReview: React.FC = () => {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [activeScan, setActiveScan] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    try {
      const allScans = await api.getScans();
      setScans(allScans);
      if (allScans.length > 0) {
        const details = await api.getScanDetails(allScans[0].id);
        setActiveScan(details);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const codeReviewIssues = activeScan?.report?.json_data?.code_reviews || [
    {
      title: "Raw Exception Stack Trace Leakage in HTTP Response",
      domain: "Error handling",
      severity: "MEDIUM",
      file: "app.py",
      line: 45,
      vulnerable_code: "traceback.print_exc()",
      why_insecure: "Printing raw exception stack traces exposes internal framework paths and database structure.",
      recommended_fix: "Log internal exceptions server-side in structured logs and return generic sanitized error messages."
    },
    {
      title: "Missing Parameter Boundary Checks on Endpoint",
      domain: "Input validation",
      severity: "MEDIUM",
      file: "app.py",
      line: 52,
      vulnerable_code: "@app.get('/api/tools/ping')",
      why_insecure: "Public route accepts untyped incoming parameters without boundary or format validation.",
      recommended_fix: "Enforce explicit Pydantic request models or input schema sanitization."
    }
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Secure Code Review Agent</h1>
        <p className="text-xs text-slate-400 font-mono mt-1">
          Deep contextual code analysis across 13 core security domains: Auth, Cryptography, Logging, Error Handling, Memory Safety
        </p>
      </div>

      {/* Review Issues List */}
      <div className="space-y-4">
        {codeReviewIssues.map((issue: any, index: number) => (
          <div key={index} className="p-6 rounded-xl glass-panel border border-cyber-border/80 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <span className={`px-2.5 py-1 rounded text-xs font-mono font-bold ${
                  issue.severity === 'CRITICAL' ? 'bg-cyber-red/20 text-cyber-red border border-cyber-red/30' :
                  issue.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
                  'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30'
                }`}>
                  {issue.severity}
                </span>

                <span className="px-2.5 py-1 rounded text-xs font-mono bg-cyber-panel text-cyber-cyan border border-cyber-cyan/30">
                  Domain: {issue.domain}
                </span>
              </div>

              <span className="text-xs font-mono text-slate-400">
                Location: <b className="text-white">{issue.file}:{issue.line}</b>
              </span>
            </div>

            <div>
              <h3 className="text-sm font-bold text-white mb-1.5">{issue.title}</h3>
              <p className="text-xs text-slate-300 leading-relaxed">{issue.why_insecure}</p>
            </div>

            {issue.vulnerable_code && (
              <div className="p-3 rounded-lg bg-black/70 border border-cyber-border font-mono text-xs text-cyber-red">
                <code>{issue.vulnerable_code}</code>
              </div>
            )}

            <div className="p-3.5 rounded-lg bg-cyber-green/5 border border-cyber-green/30 text-xs text-slate-200">
              <span className="font-bold text-cyber-green block mb-1 font-mono flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5" />
                RECOMMENDED ACTION:
              </span>
              {issue.recommended_fix}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
