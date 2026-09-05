import React, { useEffect, useState, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Activity, CheckCircle2, Clock, AlertTriangle, ShieldCheck,
  FileCode, Terminal, RefreshCw, Layers, ArrowRight, FileText,
  GitPullRequest, Network, AlertCircle, XCircle
} from 'lucide-react';
import { api } from '../services/api';
import { ScanDetails as ScanDetailsType, AgentLog } from '../types';

export const ScanDetails: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const [scan, setScan] = useState<ScanDetailsType | null>(null);
  const [logs, setLogs] = useState<AgentLog[]>([]);
  const [loading, setLoading] = useState(true);
  const logEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!scanId) return;
    loadScanDetails();

    // Setup SSE live stream
    const eventSource = new EventSource(`http://localhost:8000/api/scans/${scanId}/events`);
    
    eventSource.addEventListener('SCAN_PROGRESS', (e: any) => {
      try {
        const payload = JSON.parse(e.data);
        setScan((prev) => prev ? {
          ...prev,
          progress: payload.data.progress,
          current_stage: payload.data.current_stage,
          status: payload.data.status
        } : null);
      } catch (err) {}
    });

    eventSource.addEventListener('AGENT_LOG', (e: any) => {
      try {
        const payload = JSON.parse(e.data);
        setLogs((prev) => [...prev, {
          id: Math.random().toString(),
          scan_id: scanId,
          agent_name: payload.data.agent_name,
          level: payload.data.level,
          message: payload.data.message,
          details: {},
          timestamp: payload.data.timestamp
        }]);
      } catch (err) {}
    });

    eventSource.addEventListener('SCAN_COMPLETED', () => {
      loadScanDetails();
      eventSource.close();
    });

    eventSource.addEventListener('SCAN_FAILED', () => {
      loadScanDetails();
      eventSource.close();
    });

    // Polling fallback every 3s if SSE is not triggering
    const interval = setInterval(() => {
      loadScanDetails();
    }, 3000);

    return () => {
      eventSource.close();
      clearInterval(interval);
    };
  }, [scanId]);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  const loadScanDetails = async () => {
    if (!scanId) return;
    try {
      const data = await api.getScanDetails(scanId);
      setScan(data);
      const initialLogs = await api.getAgentLogs(scanId);
      setLogs(initialLogs);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const agentPipeline = [
    { name: 'Repository Analysis Agent', type: 'repository_analysis', desc: 'AST code parsing & Knowledge Graph' },
    { name: 'Vulnerability Detection Agent', type: 'vulnerability_detection', desc: 'Semgrep, Bandit, Trivy & AI Validation' },
    { name: 'Dependency Scanner Agent', type: 'dependency_scanner', desc: 'CVE vulnerability audit & Exposure factors' },
    { name: 'Threat Modeling Agent', type: 'threat_modeling', desc: 'STRIDE matrices & Attack paths' },
    { name: 'Secure Code Review Agent', type: 'code_review', desc: '13-domain security review' },
    { name: 'Compliance Agent', type: 'compliance', desc: 'OWASP, GDPR, ISO, NIST, PCI-DSS' },
    { name: 'Patch Recommendation Agent', type: 'patch_recommendation', desc: 'Diff synthesis & Sandbox re-scan validation' },
    { name: 'Report Generation Agent', type: 'report_generation', desc: 'Score formula & Downloadable PDF' },
  ];

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-white tracking-tight">
              Scan: {scan?.repository_name || 'Repository'}
            </h1>
            <span className={`px-2.5 py-1 rounded-full text-[10px] font-mono uppercase tracking-wider ${
              scan?.status === 'COMPLETED' ? 'bg-cyber-green/10 text-cyber-green border border-cyber-green/30' :
              scan?.status === 'RUNNING' ? 'bg-cyber-cyan/10 text-cyber-cyan border border-cyber-cyan/30 animate-pulse' :
              'bg-cyber-red/10 text-cyber-red border border-cyber-red/30'
            }`}>
              {scan?.status || 'INITIALIZING'}
            </span>
          </div>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Scan ID: {scanId} &bull; Stage: {scan?.current_stage || 'Initializing...'}
          </p>
        </div>

        {scan?.status === 'COMPLETED' && (
          <div className="flex items-center gap-3">
            <button
              onClick={() => navigate('/findings')}
              className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-cyber-panel hover:bg-cyber-cyan/20 border border-cyber-border hover:border-cyber-cyan/50 text-xs font-mono text-white transition-all cursor-pointer"
            >
              <AlertTriangle className="w-3.5 h-3.5 text-cyber-red" />
              <span>Findings ({scan.total_vulnerabilities})</span>
            </button>
            <button
              onClick={() => navigate('/reports')}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyber-cyan text-black text-xs font-bold hover:bg-cyan-300 transition-all shadow-cyber-cyan cursor-pointer"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Full Report & PDF</span>
            </button>
          </div>
        )}
      </div>

      {/* Progress Bar */}
      <div className="p-5 rounded-xl glass-panel border border-cyber-border/80 space-y-3">
        <div className="flex items-center justify-between text-xs font-mono">
          <span className="text-slate-300 flex items-center gap-2">
            <RefreshCw className={`w-3.5 h-3.5 text-cyber-cyan ${scan?.status === 'RUNNING' ? 'animate-spin' : ''}`} />
            {scan?.current_stage || 'Supervisor Agent Coordinating Tasks'}
          </span>
          <span className="text-cyber-cyan font-bold">{Math.round(scan?.progress || 0)}%</span>
        </div>
        <div className="w-full h-2.5 bg-cyber-bg rounded-full overflow-hidden border border-cyber-border">
          <div
            className="h-full bg-gradient-to-r from-cyber-cyan to-blue-500 transition-all duration-500 rounded-full shadow-cyber-cyan"
            style={{ width: `${scan?.progress || 0}%` }}
          />
        </div>
      </div>

      {/* Multi-Agent Supervisor Hierarchy & Execution Pipeline */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Agent Pipeline Visual Checklist */}
        <div className="lg:col-span-1 rounded-xl glass-panel border border-cyber-border/80 p-5 space-y-4">
          <h2 className="text-sm font-bold text-white flex items-center gap-2 font-mono">
            <Layers className="w-4 h-4 text-cyber-cyan" />
            SUPERVISOR AGENT PIPELINE
          </h2>

          <div className="space-y-3">
            {agentPipeline.map((agent, index) => {
              const matchedAgent = scan?.agents?.find(a => a.agent_type === agent.type);
              const isCompleted = matchedAgent?.status === 'COMPLETED' || (scan?.status === 'COMPLETED');
              const isRunning = scan?.status === 'RUNNING' && !isCompleted && scan?.progress >= (index * 12);

              return (
                <div
                  key={agent.type}
                  className={`p-3 rounded-lg border transition-all ${
                    isCompleted
                      ? 'bg-cyber-panel/40 border-cyber-green/30 text-slate-200'
                      : isRunning
                      ? 'bg-cyber-cyan/10 border-cyber-cyan/40 text-cyber-cyan shadow-cyber-cyan'
                      : 'bg-cyber-bg/40 border-cyber-border/40 text-slate-500'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 text-xs font-semibold">
                      {isCompleted ? (
                        <CheckCircle2 className="w-4 h-4 text-cyber-green flex-shrink-0" />
                      ) : isRunning ? (
                        <RefreshCw className="w-4 h-4 text-cyber-cyan animate-spin flex-shrink-0" />
                      ) : (
                        <Clock className="w-4 h-4 text-slate-500 flex-shrink-0" />
                      )}
                      <span>{agent.name}</span>
                    </div>
                    {matchedAgent && (
                      <span className="text-[10px] font-mono text-slate-400">
                        {matchedAgent.duration_seconds}s
                      </span>
                    )}
                  </div>
                  <p className="text-[11px] text-slate-400 mt-1 pl-6">
                    {agent.desc}
                  </p>
                </div>
              );
            })}
          </div>
        </div>

        {/* Live Agent Terminal Logs Stream */}
        <div className="lg:col-span-2 rounded-xl glass-panel border border-cyber-border/80 overflow-hidden flex flex-col h-[520px]">
          <div className="p-4 bg-cyber-bg/80 border-b border-cyber-border flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyber-cyan" />
              <span className="text-xs font-mono font-bold text-white">LIVE AGENT EXECUTION LOGS</span>
            </div>
            <span className="text-[10px] font-mono text-cyber-muted">
              {logs.length} Events Received
            </span>
          </div>

          <div className="flex-1 p-4 bg-black/60 font-mono text-xs overflow-y-auto space-y-2 select-text">
            {logs.map((l, i) => (
              <div key={i} className="flex items-start gap-2.5 leading-relaxed">
                <span className="text-slate-600 text-[10px] select-none pt-0.5">
                  {l.timestamp ? new Date(l.timestamp).toLocaleTimeString() : '00:00:00'}
                </span>
                <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                  l.level === 'SUCCESS' ? 'bg-cyber-green/20 text-cyber-green' :
                  l.level === 'ERROR' ? 'bg-cyber-red/20 text-cyber-red' :
                  l.level === 'WARNING' ? 'bg-cyber-yellow/20 text-cyber-yellow' :
                  'bg-cyber-blue/20 text-cyber-blue'
                }`}>
                  {l.agent_name}
                </span>
                <span className="text-slate-300">{l.message}</span>
              </div>
            ))}
            {logs.length === 0 && (
              <div className="text-slate-500 italic">Waiting for agent execution logs...</div>
            )}
            <div ref={logEndRef} />
          </div>
        </div>
      </div>
    </div>
  );
};
