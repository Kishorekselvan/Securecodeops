import React, { useEffect, useState } from 'react';
import { Network, AlertTriangle, ShieldCheck, ArrowRight, Package, ExternalLink } from 'lucide-react';
import { api } from '../services/api';
import { Dependency } from '../types';

export const Dependencies: React.FC = () => {
  const [dependencies, setDependencies] = useState<Dependency[]>([]);
  const [loading, setLoading] = useState(true);
  const [vulnerableOnly, setVulnerableOnly] = useState(false);
  const [selectedEcosystem, setSelectedEcosystem] = useState('');

  useEffect(() => {
    loadDependencies();
  }, [vulnerableOnly, selectedEcosystem]);

  const loadDependencies = async () => {
    setLoading(true);
    try {
      const data = await api.getDependencies({
        vulnerable_only: vulnerableOnly || undefined,
        ecosystem: selectedEcosystem || undefined
      });
      setDependencies(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const totalRisk = dependencies.reduce((acc, d) => acc + (d.risk_contribution || 0), 0);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Software Bill of Materials (SBOM) & Dependencies</h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Audited package manifests, CVE vulnerability identification, and reachability exposure scoring
          </p>
        </div>

        <div className="p-3 rounded-lg bg-cyber-panel border border-cyber-border font-mono text-xs flex items-center gap-4">
          <div>Total Dependencies: <b className="text-white">{dependencies.length}</b></div>
          <div>&bull;</div>
          <div>Vulnerable: <b className="text-cyber-red">{dependencies.filter(d => d.is_vulnerable).length}</b></div>
          <div>&bull;</div>
          <div>Total Risk: <b className="text-cyber-cyan">{totalRisk.toFixed(1)}</b></div>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="p-4 rounded-xl glass-panel border border-cyber-border/80 flex flex-wrap items-center gap-4">
        <label className="flex items-center gap-2 text-xs font-mono text-slate-300 cursor-pointer">
          <input
            type="checkbox"
            checked={vulnerableOnly}
            onChange={(e) => setVulnerableOnly(e.target.checked)}
            className="rounded bg-cyber-bg border-cyber-border text-cyber-cyan focus:ring-0"
          />
          <span>Show Vulnerable Only</span>
        </label>

        <select
          value={selectedEcosystem}
          onChange={(e) => setSelectedEcosystem(e.target.value)}
          className="bg-cyber-bg border border-cyber-border rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyber-cyan font-mono"
        >
          <option value="">All Ecosystems</option>
          <option value="pypi">PyPI (Python)</option>
          <option value="npm">NPM (Node.js)</option>
          <option value="maven">Maven (Java)</option>
        </select>
      </div>

      {/* Dependencies Table */}
      <div className="rounded-xl glass-panel border border-cyber-border/80 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-cyber-bg/70 text-slate-400 font-mono uppercase text-[10px] border-b border-cyber-border">
              <tr>
                <th className="py-3 px-5">Package</th>
                <th className="py-3 px-5">Version</th>
                <th className="py-3 px-5">Ecosystem</th>
                <th className="py-3 px-5">Vulnerability / CVE</th>
                <th className="py-3 px-5">CVSS & Exposure</th>
                <th className="py-3 px-5">Recommended Secure Target</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-border/40 font-mono">
              {dependencies.map((dep) => (
                <tr key={dep.id} className="hover:bg-cyber-panel/30 transition-colors">
                  <td className="py-3.5 px-5 font-bold text-white flex items-center gap-2">
                    <Package className="w-3.5 h-3.5 text-cyber-cyan flex-shrink-0" />
                    <span>{dep.package_name}</span>
                  </td>
                  <td className="py-3.5 px-5 text-slate-300">
                    {dep.installed_version}
                  </td>
                  <td className="py-3.5 px-5 uppercase text-[10px] text-cyber-muted">
                    {dep.ecosystem}
                  </td>
                  <td className="py-3.5 px-5">
                    {dep.is_vulnerable ? (
                      <div className="space-y-0.5">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyber-red/20 text-cyber-red border border-cyber-red/30">
                          {dep.cve_id || 'CVE Advisory'}
                        </span>
                        <div className="text-[10px] text-slate-400 font-sans mt-0.5 max-w-xs truncate">
                          {dep.recommendation}
                        </div>
                      </div>
                    ) : (
                      <span className="text-cyber-green text-[11px] flex items-center gap-1">
                        <ShieldCheck className="w-3 h-3" /> Secure
                      </span>
                    )}
                  </td>
                  <td className="py-3.5 px-5">
                    {dep.is_vulnerable ? (
                      <div>
                        <span className="text-white font-bold">{dep.cvss_score || 'N/A'}</span>
                        <span className="text-slate-400 text-[10px]"> &times; {dep.exposure_factor} = <b className="text-cyber-cyan">{dep.risk_contribution}</b></span>
                      </div>
                    ) : (
                      <span className="text-slate-500">0.0</span>
                    )}
                  </td>
                  <td className="py-3.5 px-5">
                    {dep.fixed_version ? (
                      <span className="text-cyber-cyan font-bold flex items-center gap-1">
                        <span>&ge; {dep.fixed_version}</span>
                      </span>
                    ) : (
                      <span className="text-slate-500">Latest</span>
                    )}
                  </td>
                </tr>
              ))}

              {dependencies.length === 0 && !loading && (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500 font-mono">
                    No dependencies matched your criteria.
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
