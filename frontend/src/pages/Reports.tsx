import React, { useEffect, useState } from 'react';
import {
  FileText, Download, FileCode, CheckCircle2, ShieldCheck,
  AlertTriangle, Cpu, Layers, Network, ExternalLink
} from 'lucide-react';
import { api } from '../services/api';
import { ScanSummary, Report } from '../types';

export const Reports: React.FC = () => {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>('');
  const [report, setReport] = useState<Report | null>(null);
  const [benchmarkMetrics, setBenchmarkMetrics] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadScans();
    loadBenchmarkMetrics();
  }, []);

  const loadBenchmarkMetrics = async () => {
    try {
      const data = await api.getBenchmarkMetrics();
      setBenchmarkMetrics(data);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    if (selectedScanId) {
      loadReport(selectedScanId);
    }
  }, [selectedScanId]);

  const loadScans = async () => {
    try {
      const data = await api.getScans();
      setScans(data);
      if (data.length > 0) {
        setSelectedScanId(data[0].id);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const loadReport = async (scanId: string) => {
    setLoading(true);
    try {
      const data = await api.getReport(scanId);
      setReport(data);
    } catch (e) {
      console.error(e);
      setReport(null);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Executive Security Reports & Exports</h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Complete assessment report, transparent score breakdown, and downloadable PDF / JSON / CSV exports
          </p>
        </div>

        {selectedScanId && (
          <div className="flex flex-wrap items-center gap-3">
            <a
              href={api.getPdfReportUrl(selectedScanId)}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyber-cyan text-black font-bold text-xs hover:bg-cyan-300 transition-all shadow-cyber-cyan"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download PDF Report</span>
            </a>

            <a
              href={api.getJsonExportUrl(selectedScanId)}
              download
              className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-cyber-panel border border-cyber-border hover:border-cyber-cyan text-xs font-mono text-slate-200 transition-all"
            >
              <FileCode className="w-3.5 h-3.5" />
              <span>Export JSON</span>
            </a>

            <a
              href={api.getCsvExportUrl(selectedScanId)}
              download
              className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-cyber-panel border border-cyber-border hover:border-cyber-cyan text-xs font-mono text-slate-200 transition-all"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Export CSV</span>
            </a>
          </div>
        )}
      </div>

      {/* Scan Selector */}
      {scans.length > 0 && (
        <div className="flex items-center gap-3">
          <span className="text-xs text-cyber-muted font-mono">SELECT SCAN AUDIT:</span>
          <select
            value={selectedScanId}
            onChange={(e) => setSelectedScanId(e.target.value)}
            className="bg-cyber-panel border border-cyber-border rounded-lg px-3 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyber-cyan"
          >
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                {s.repository_name || 'Repository'} - Score: {s.security_score}/100 ({s.status})
              </option>
            ))}
          </select>
        </div>
      )}

      {/* Report Document Preview */}
      {report ? (
        <div className="p-8 rounded-xl glass-panel border border-cyber-border/80 space-y-8 max-w-5xl">
          {/* Report Document Title Header */}
          <div className="border-b border-cyber-border pb-6 flex items-start justify-between">
            <div>
              <span className="text-xs font-mono font-bold text-cyber-cyan uppercase tracking-widest block mb-1">
                SECURECODEOPS AI &bull; ASSESSMENT REPORT
              </span>
              <h2 className="text-xl font-bold text-white">{report.title}</h2>
              <p className="text-xs text-slate-400 font-mono mt-1">
                Scan ID: {report.scan_id} &bull; Generated: {report.created_at ? new Date(report.created_at).toUTCString() : 'N/A'}
              </p>
            </div>

            <div className="text-right">
              <span className="text-[10px] font-mono text-slate-400 block uppercase">Overall Score</span>
              <span className="text-3xl font-extrabold text-white font-mono">
                {report.score_breakdown?.security_score ?? 100}/100
              </span>
            </div>
          </div>

          {/* 1. Executive Summary */}
          <div className="space-y-2">
            <h3 className="text-sm font-bold font-mono text-white flex items-center gap-2">
              <FileText className="w-4 h-4 text-cyber-cyan" />
              1. EXECUTIVE SUMMARY
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed bg-cyber-bg/50 p-4 rounded-lg border border-cyber-border">
              {report.executive_summary}
            </p>
          </div>

          {/* 2. Score Breakdown Table */}
          <div className="space-y-3">
            <h3 className="text-sm font-bold font-mono text-white flex items-center gap-2">
              <Cpu className="w-4 h-4 text-cyber-cyan" />
              2. SECURITY SCORE PENALTY AUDIT
            </h3>
            <div className="p-4 rounded-lg bg-cyber-bg/60 border border-cyber-border font-mono text-xs space-y-2">
              <div className="text-cyber-cyan mb-2">
                Formula: {report.score_breakdown?.formula}
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                {Object.entries(report.score_breakdown?.penalties || {}).map(([k, v]) => (
                  <div key={k} className="p-2.5 rounded bg-cyber-surface border border-cyber-border">
                    <span className="text-[10px] text-slate-400 block uppercase">{k.replace('_', ' ')}</span>
                    <b className="text-cyber-red text-sm">-{v} pts</b>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* 3. Findings Summary Metrics */}
          <div className="space-y-3">
            <h3 className="text-sm font-bold font-mono text-white flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-cyber-red" />
              3. VULNERABILITIES & FINDINGS SUMMARY
            </h3>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 font-mono text-xs">
              <div className="p-4 rounded-xl bg-cyber-bg border border-cyber-border text-center">
                <span className="text-slate-400 block text-[10px]">TOTAL FINDINGS</span>
                <span className="text-2xl font-bold text-white mt-1 block">
                  {report.json_data?.summary_metrics?.total_vulnerabilities ?? 0}
                </span>
              </div>
              <div className="p-4 rounded-xl bg-cyber-bg border border-cyber-border text-center">
                <span className="text-slate-400 block text-[10px]">CRITICAL SEVERITY</span>
                <span className="text-2xl font-bold text-cyber-red mt-1 block">
                  {report.json_data?.summary_metrics?.critical ?? 0}
                </span>
              </div>
              <div className="p-4 rounded-xl bg-cyber-bg border border-cyber-border text-center">
                <span className="text-slate-400 block text-[10px]">STRIDE THREATS</span>
                <span className="text-2xl font-bold text-amber-400 mt-1 block">
                  {report.json_data?.summary_metrics?.stride_threats ?? 0}
                </span>
              </div>
              <div className="p-4 rounded-xl bg-cyber-bg border border-cyber-border text-center">
                <span className="text-slate-400 block text-[10px]">COMPLIANCE SCORE</span>
                <span className="text-2xl font-bold text-cyber-green mt-1 block">
                  {report.json_data?.summary_metrics?.compliance_score ?? 100}%
                </span>
              </div>
            </div>
          </div>

          {/* 4. Paper Evaluation & Benchmark Metrics (Table II) */}
          {benchmarkMetrics && (
            <div className="space-y-4 pt-4 border-t border-cyber-border">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold font-mono text-white flex items-center gap-2">
                  <Network className="w-4 h-4 text-cyber-cyan" />
                  4. RESEARCH EVALUATION & BENCHMARK SUITE (PAPER TABLE II)
                </h3>
                <span className="text-[10px] text-cyber-muted font-mono">
                  Ground Truth Dataset: {benchmarkMetrics.dataset_size} samples
                </span>
              </div>

              {/* Comparative Metrics Table */}
              <div className="overflow-x-auto rounded-lg border border-cyber-border">
                <table className="w-full text-left font-mono text-xs">
                  <thead className="bg-cyber-bg text-slate-400 border-b border-cyber-border">
                    <tr>
                      <th className="p-3">Tool / Architecture</th>
                      <th className="p-3">VDR (%)</th>
                      <th className="p-3">FPR (%)</th>
                      <th className="p-3">Precision</th>
                      <th className="p-3">Recall</th>
                      <th className="p-3">F1-Score</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-cyber-border/40 text-slate-200">
                    {benchmarkMetrics.table_ii_metrics && Object.values(benchmarkMetrics.table_ii_metrics).map((m: any) => (
                      <tr
                        key={m.tool_name}
                        className={m.tool_name.includes('SecureCodeOps') ? 'bg-cyber-cyan/10 font-bold text-white' : 'hover:bg-white/[0.02]'}
                      >
                        <td className="p-3 flex items-center gap-2">
                          {m.tool_name.includes('SecureCodeOps') && (
                            <span className="w-2 h-2 rounded-full bg-cyber-cyan animate-pulse" />
                          )}
                          {m.tool_name}
                        </td>
                        <td className="p-3 text-cyber-green">{m.vdr_percent}%</td>
                        <td className="p-3 text-cyber-purple">{m.fpr_percent}%</td>
                        <td className="p-3">{m.precision}</td>
                        <td className="p-3">{m.recall}</td>
                        <td className="p-3 text-cyber-cyan">{m.f1_score}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Target Achievement Matrix */}
              {benchmarkMetrics.target_comparison && (
                <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2 font-mono text-xs">
                  {Object.entries(benchmarkMetrics.target_comparison).map(([metric, data]: [string, any]) => (
                    <div key={metric} className="p-2.5 rounded-lg bg-cyber-bg/80 border border-cyber-border text-center">
                      <span className="text-[10px] text-slate-400 block font-bold">{metric}</span>
                      <span className="text-xs font-bold text-cyber-cyan block mt-0.5">{data.achieved}</span>
                      <span className="text-[9px] text-cyber-green block mt-0.5">Target {data.target}</span>
                      <span className={`inline-block px-1.5 py-0.2 rounded text-[9px] mt-1 font-bold ${
                        data.met ? 'bg-cyber-green/20 text-cyber-green' : 'bg-cyber-red/20 text-cyber-red'
                      }`}>
                        {data.met ? 'PASSED' : 'UNMET'}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      ) : (
        <div className="p-12 text-center text-xs text-slate-500 font-mono glass-panel rounded-xl">
          {loading ? 'Loading report details...' : 'Select a completed scan to inspect the full security report.'}
        </div>
      )}
    </div>
  );
};
