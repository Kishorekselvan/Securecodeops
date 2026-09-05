import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert, ShieldCheck, AlertTriangle, Network, FileCheck2,
  Clock, ArrowRight, Play, Cpu, TrendingUp, Layers, CheckCircle2,
  HelpCircle, Info
} from 'lucide-react';
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip,
  PieChart, Pie, Cell, Legend
} from 'recharts';
import { api } from '../services/api';
import { ScanSummary, Repository } from '../types';

export const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [repos, setRepos] = useState<Repository[]>([]);
  const [loading, setLoading] = useState(true);
  const [showFormula, setShowFormula] = useState(false);

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    setLoading(true);
    try {
      const [scansData, reposData] = await Promise.all([
        api.getScans(),
        api.getRepositories()
      ]);
      setScans(scansData);
      setRepos(reposData);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const latestScan = scans[0];

  const severityData = latestScan ? [
    { name: 'Critical', value: latestScan.critical_count, color: '#ef4444' },
    { name: 'High', value: latestScan.high_count, color: '#f97316' },
    { name: 'Medium', value: latestScan.medium_count, color: '#eab308' },
    { name: 'Low', value: latestScan.low_count, color: '#3b82f6' },
  ].filter(d => d.value > 0) : [];

  const categoryData = [
    { category: 'SQLi', count: 2 },
    { category: 'Secrets', count: 3 },
    { category: 'RCE / Cmd', count: 2 },
    { category: 'XSS', count: 1 },
    { category: 'Dependencies', count: 4 },
  ];

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Security Posture Dashboard</h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Global multi-agent security analytics and continuous vulnerability tracking
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowFormula(!showFormula)}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-cyber-panel border border-cyber-border hover:border-cyber-cyan/50 text-xs font-mono text-slate-300 transition-all cursor-pointer"
          >
            <Info className="w-3.5 h-3.5 text-cyber-cyan" />
            <span>Score Formula</span>
          </button>
          
          <button
            onClick={() => navigate('/repositories')}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyber-cyan text-black text-xs font-bold hover:bg-cyan-300 transition-all shadow-cyber-cyan cursor-pointer"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>New Scan</span>
          </button>
        </div>
      </div>

      {/* Transparent Score Formula Breakdown Banner */}
      {showFormula && (
        <div className="p-5 rounded-xl bg-cyber-surface border border-cyber-cyan/40 glass-panel animate-fadeIn">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-bold text-white flex items-center gap-2 font-mono">
              <Cpu className="w-4 h-4 text-cyber-cyan" />
              TRANSPARENT SECURITY SCORE MATHEMATICAL FORMULA
            </h3>
            <button onClick={() => setShowFormula(false)} className="text-slate-400 hover:text-white text-xs">&times;</button>
          </div>
          <div className="font-mono text-xs text-cyber-cyan bg-cyber-bg/80 p-3 rounded border border-cyber-border mb-3">
            Security Score = 100 &minus; (CritPen + HighPen + MedPen + LowPen + SecretPen + DepRiskPen + CompPen)
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-[11px] text-slate-300 font-mono">
            <div>&bull; Critical: 15 pts (max 45)</div>
            <div>&bull; High: 8 pts (max 30)</div>
            <div>&bull; Medium: 3 pts (max 15)</div>
            <div>&bull; Secrets: 10 pts (max 30)</div>
            <div>&bull; Dep Risk: 0.5 &times; Risk (max 20)</div>
            <div>&bull; Compliance: (100 - Score) &times; 0.25</div>
          </div>
        </div>
      )}

      {/* Top Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        {/* Security Score */}
        <div className="p-5 rounded-xl glass-panel border border-cyber-border/80 relative overflow-hidden">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2 font-mono">
            <span>SECURITY SCORE</span>
            <ShieldCheck className="w-4 h-4 text-cyber-cyan" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-white">
              {latestScan ? latestScan.security_score : 100}
            </span>
            <span className="text-xs text-cyber-muted font-mono">/ 100</span>
          </div>
          <div className="mt-3 flex items-center gap-2 text-[11px] text-slate-400">
            <span className={`w-2 h-2 rounded-full ${
              (latestScan?.security_score ?? 100) >= 80 ? 'bg-cyber-green' : (latestScan?.security_score ?? 100) >= 50 ? 'bg-cyber-yellow' : 'bg-cyber-red'
            }`}></span>
            <span>{latestScan ? `Status: ${latestScan.status}` : 'No scan history'}</span>
          </div>
        </div>

        {/* Total Vulnerabilities */}
        <div className="p-5 rounded-xl glass-panel border border-cyber-border/80">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2 font-mono">
            <span>TOTAL FINDINGS</span>
            <AlertTriangle className="w-4 h-4 text-cyber-red" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-white">
              {latestScan ? latestScan.total_vulnerabilities : 0}
            </span>
            <span className="text-xs text-cyber-red font-mono font-semibold">
              ({latestScan ? latestScan.critical_count : 0} Critical)
            </span>
          </div>
          <div className="mt-3 text-[11px] text-slate-400 flex items-center gap-3">
            <span className="text-orange-400">{latestScan ? latestScan.high_count : 0} High</span>
            <span className="text-yellow-400">{latestScan ? latestScan.medium_count : 0} Med</span>
            <span className="text-blue-400">{latestScan ? latestScan.low_count : 0} Low</span>
          </div>
        </div>

        {/* Compliance Score */}
        <div className="p-5 rounded-xl glass-panel border border-cyber-border/80">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2 font-mono">
            <span>COMPLIANCE POSTURE</span>
            <FileCheck2 className="w-4 h-4 text-cyber-green" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-cyber-green">
              {latestScan ? `${latestScan.compliance_score}%` : '100%'}
            </span>
          </div>
          <div className="mt-3 text-[11px] text-slate-400">
            OWASP, GDPR, ISO 27001, NIST, PCI
          </div>
        </div>

        {/* FP Reduction & Repos */}
        <div className="p-5 rounded-xl glass-panel border border-cyber-border/80">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2 font-mono">
            <span>FP REDUCTION RATE</span>
            <Cpu className="w-4 h-4 text-cyber-purple" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-cyber-purple">
              {latestScan ? `${latestScan.false_positive_reduction_rate}%` : '0%'}
            </span>
          </div>
          <div className="mt-3 text-[11px] text-slate-400 font-mono">
            {repos.length} Repositories tracked
          </div>
        </div>
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Breakdown Chart */}
        <div className="p-6 rounded-xl glass-panel border border-cyber-border/80">
          <h3 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-cyber-cyan" />
            Vulnerabilities by Severity
          </h3>
          {severityData.length > 0 ? (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    outerRadius={80}
                    innerRadius={45}
                    paddingAngle={4}
                    label
                  >
                    {severityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: '#11192e', borderColor: '#1f2e4d', fontSize: '12px' }} />
                  <Legend wrapperStyle={{ fontSize: '12px' }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center text-xs text-slate-500 font-mono">
              No active vulnerability data. Run a scan to populate.
            </div>
          )}
        </div>

        {/* Category Breakdown Chart */}
        <div className="p-6 rounded-xl glass-panel border border-cyber-border/80">
          <h3 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
            <Layers className="w-4 h-4 text-cyber-cyan" />
            Top Vulnerability Categories
          </h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={categoryData} layout="vertical">
                <XAxis type="number" stroke="#64748b" fontSize={11} />
                <YAxis dataKey="category" type="category" stroke="#64748b" fontSize={11} width={80} />
                <Tooltip contentStyle={{ backgroundColor: '#11192e', borderColor: '#1f2e4d', fontSize: '12px' }} />
                <Bar dataKey="count" fill="#00f0ff" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Recent Scans History */}
      <div className="rounded-xl glass-panel border border-cyber-border/80 overflow-hidden">
        <div className="p-5 border-b border-cyber-border flex items-center justify-between">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <Clock className="w-4 h-4 text-cyber-cyan" />
            Recent Multi-Agent Scans
          </h3>
          <button
            onClick={() => navigate('/repositories')}
            className="text-xs text-cyber-cyan hover:underline font-mono"
          >
            View Repositories &rarr;
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-cyber-bg/70 text-slate-400 font-mono uppercase text-[10px] border-b border-cyber-border">
              <tr>
                <th className="py-3 px-5">Repository</th>
                <th className="py-3 px-5">Status</th>
                <th className="py-3 px-5">Security Score</th>
                <th className="py-3 px-5">Total Findings</th>
                <th className="py-3 px-5">Duration</th>
                <th className="py-3 px-5 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-border/40">
              {scans.map((s) => (
                <tr key={s.id} className="hover:bg-cyber-panel/40 transition-colors">
                  <td className="py-3.5 px-5 font-medium text-white">
                    {s.repository_name || 'Repository'}
                  </td>
                  <td className="py-3.5 px-5">
                    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-mono ${
                      s.status === 'COMPLETED' ? 'bg-cyber-green/10 text-cyber-green border border-cyber-green/30' :
                      s.status === 'RUNNING' ? 'bg-cyber-cyan/10 text-cyber-cyan border border-cyber-cyan/30 animate-pulse' :
                      'bg-cyber-yellow/10 text-cyber-yellow border border-cyber-yellow/30'
                    }`}>
                      {s.status}
                    </span>
                  </td>
                  <td className="py-3.5 px-5 font-mono font-bold">
                    <span className={s.security_score >= 80 ? 'text-cyber-green' : s.security_score >= 50 ? 'text-cyber-yellow' : 'text-cyber-red'}>
                      {s.security_score}/100
                    </span>
                  </td>
                  <td className="py-3.5 px-5 font-mono">
                    {s.total_vulnerabilities} ({s.critical_count} Crit)
                  </td>
                  <td className="py-3.5 px-5 text-slate-400 font-mono">
                    {s.duration_seconds}s
                  </td>
                  <td className="py-3.5 px-5 text-right">
                    <button
                      onClick={() => navigate(`/scans/${s.id}`)}
                      className="px-3 py-1 rounded bg-cyber-panel hover:bg-cyber-cyan/20 border border-cyber-border hover:border-cyber-cyan/50 text-slate-200 text-xs font-mono transition-all"
                    >
                      View Report
                    </button>
                  </td>
                </tr>
              ))}
              {scans.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500 font-mono">
                    No scans conducted yet. Click "New Scan" or "Run Live Demo Scan" to begin.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
