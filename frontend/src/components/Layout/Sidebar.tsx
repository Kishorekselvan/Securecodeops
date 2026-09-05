import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  ShieldAlert, LayoutDashboard, FolderGit2, Activity, AlertTriangle,
  FileCheck2, Network, GitPullRequest, FileText, Settings, ShieldCheck,
  Cpu, Lock
} from 'lucide-react';

export const Sidebar: React.FC = () => {
  const navItems = [
    { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
    { to: "/repositories", label: "Repositories", icon: FolderGit2 },
    { to: "/findings", label: "Vulnerabilities", icon: AlertTriangle },
    { to: "/threat-model", label: "Threat Model (STRIDE)", icon: ShieldAlert },
    { to: "/dependencies", label: "Dependencies", icon: Network },
    { to: "/code-review", label: "Code Review", icon: ShieldCheck },
    { to: "/compliance", label: "Compliance", icon: FileCheck2 },
    { to: "/patches", label: "Verified Patches", icon: GitPullRequest },
    { to: "/knowledge-graph", label: "Knowledge Graph", icon: Cpu },
    { to: "/reports", label: "Security Reports", icon: FileText },
    { to: "/settings", label: "Settings & Health", icon: Settings },
  ];

  return (
    <aside className="w-64 bg-cyber-surface border-r border-cyber-border flex flex-col h-screen fixed left-0 top-0 z-30">
      {/* Brand Header */}
      <div className="h-16 flex items-center px-6 border-b border-cyber-border bg-cyber-bg/50">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-cyber-cyan/10 border border-cyber-cyan/30 flex items-center justify-center text-cyber-cyan shadow-cyber-cyan">
            <Lock className="w-4 h-4" />
          </div>
          <div>
            <span className="font-bold text-sm tracking-wider text-white">SECURE<span className="text-cyber-cyan">CODE</span>OPS</span>
            <span className="block text-[10px] text-cyber-muted font-mono tracking-widest uppercase">Multi-Agent AI</span>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        <div className="px-3 py-2 text-[10px] font-mono uppercase tracking-wider text-cyber-muted">
          Security Platform
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-medium transition-all duration-200 ${
                  isActive
                    ? 'bg-cyber-cyan/10 text-cyber-cyan border border-cyber-cyan/30 font-semibold shadow-cyber-cyan'
                    : 'text-slate-400 hover:text-slate-100 hover:bg-cyber-panel/60 border border-transparent'
                }`
              }
            >
              <Icon className="w-4 h-4" />
              <span>{item.label}</span>
            </NavLink>
          );
        })}
      </nav>

      {/* Footer Info */}
      <div className="p-4 border-t border-cyber-border bg-cyber-bg/40">
        <div className="flex items-center justify-between text-[11px] text-cyber-muted font-mono">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyber-green animate-pulse"></span>
            <span>SYSTEM READY</span>
          </div>
          <span className="text-slate-500">v1.0.0</span>
        </div>
      </div>
    </aside>
  );
};
