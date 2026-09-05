import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Play, RefreshCw, Terminal, CheckCircle2, AlertCircle } from 'lucide-react';
import { api } from '../../services/api';
import { ScanSummary, Repository } from '../../types';

interface NavbarProps {
  currentScanId?: string;
  onScanSelect?: (scanId: string) => void;
}

export const Navbar: React.FC<NavbarProps> = ({ currentScanId, onScanSelect }) => {
  const navigate = useNavigate();
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [loadingDemo, setLoadingDemo] = useState(false);

  useEffect(() => {
    loadScans();
  }, []);

  const loadScans = async () => {
    try {
      const data = await api.getScans();
      setScans(data);
    } catch (e) {
      console.error(e);
    }
  };

  const handleLaunchDemo = async () => {
    setLoadingDemo(true);
    try {
      const repo = await api.createDemoRepository();
      const newScan = await api.createScan(repo.id);
      navigate(`/scans/${newScan.id}`);
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingDemo(false);
    }
  };

  return (
    <header className="h-16 bg-cyber-surface/90 backdrop-blur-md border-b border-cyber-border sticky top-0 z-20 flex items-center justify-between px-8 ml-64">
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
          <Terminal className="w-3.5 h-3.5 text-cyber-cyan" />
          <span>SUPERVISOR:</span>
          <span className="text-cyber-green font-semibold">ONLINE</span>
        </div>

        {/* Scan Selector */}
        {scans.length > 0 && (
          <div className="flex items-center gap-2 ml-4">
            <span className="text-xs text-cyber-muted font-mono">ACTIVE SCAN:</span>
            <select
              value={currentScanId || scans[0]?.id}
              onChange={(e) => {
                const id = e.target.value;
                if (onScanSelect) onScanSelect(id);
                navigate(`/scans/${id}`);
              }}
              className="bg-cyber-panel border border-cyber-border rounded px-3 py-1 text-xs text-slate-200 focus:outline-none focus:border-cyber-cyan font-mono"
            >
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.repository_name || 'Repository'} - Score: {s.security_score}/100 ({s.status})
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      <div className="flex items-center gap-3">
        <button
          onClick={handleLaunchDemo}
          disabled={loadingDemo}
          className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-cyber-cyan/10 hover:bg-cyber-cyan/20 border border-cyber-cyan/40 text-cyber-cyan text-xs font-semibold tracking-wide transition-all shadow-cyber-cyan cursor-pointer disabled:opacity-50"
        >
          {loadingDemo ? (
            <RefreshCw className="w-3.5 h-3.5 animate-spin" />
          ) : (
            <Play className="w-3.5 h-3.5 fill-current" />
          )}
          <span>RUN DEMO SCAN</span>
        </button>

        <button
          onClick={() => navigate('/repositories')}
          className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-cyber-panel hover:bg-cyber-panel/80 border border-cyber-border text-slate-200 text-xs font-medium transition-all"
        >
          <span>Upload ZIP</span>
        </button>
      </div>
    </header>
  );
};
