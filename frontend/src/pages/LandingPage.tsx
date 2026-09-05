import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert, Cpu, Lock, CheckCircle2, ArrowRight, Play, Terminal,
  Network, FileCheck2, GitPullRequest, Layers, Code, ShieldCheck, Zap
} from 'lucide-react';
import { api } from '../services/api';

export const LandingPage: React.FC = () => {
  const navigate = useNavigate();
  const [loadingDemo, setLoadingDemo] = useState(false);

  const handleLaunchDemo = async () => {
    setLoadingDemo(true);
    try {
      const repo = await api.createDemoRepository();
      const newScan = await api.createScan(repo.id);
      navigate(`/scans/${newScan.id}`);
    } catch (e) {
      console.error(e);
      navigate('/dashboard');
    } finally {
      setLoadingDemo(false);
    }
  };

  return (
    <div className="min-h-screen bg-cyber-bg text-slate-100 flex flex-col selection:bg-cyber-cyan selection:text-black">
      {/* Top Navigation */}
      <header className="h-20 border-b border-cyber-border/60 bg-cyber-surface/60 backdrop-blur-md sticky top-0 z-30 px-8 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-cyber-cyan/10 border border-cyber-cyan/40 flex items-center justify-center text-cyber-cyan shadow-cyber-cyan">
            <Lock className="w-5 h-5" />
          </div>
          <div>
            <span className="font-bold text-lg tracking-wider text-white">SECURE<span className="text-cyber-cyan">CODE</span>OPS AI</span>
            <span className="block text-[10px] text-cyber-muted font-mono tracking-widest uppercase">Multi-Agent DevSecOps Platform</span>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <button
            onClick={() => navigate('/dashboard')}
            className="text-xs text-slate-300 hover:text-white px-3 py-2 transition-colors font-medium"
          >
            Dashboard
          </button>
          <button
            onClick={() => navigate('/repositories')}
            className="text-xs text-slate-300 hover:text-white px-3 py-2 transition-colors font-medium"
          >
            Repositories
          </button>
          <button
            onClick={handleLaunchDemo}
            disabled={loadingDemo}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyber-cyan text-black font-semibold text-xs tracking-wide hover:bg-cyan-300 transition-all shadow-cyber-cyan cursor-pointer disabled:opacity-50"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>{loadingDemo ? 'Launching Pipeline...' : 'Run Live Demo Scan'}</span>
          </button>
        </div>
      </header>

      {/* Hero Section */}
      <section className="relative pt-20 pb-16 px-8 max-w-6xl mx-auto text-center overflow-hidden">
        {/* Glow backdrop */}
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[350px] bg-cyber-cyan/10 blur-[120px] pointer-events-none rounded-full" />

        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyber-cyan/10 border border-cyber-cyan/30 text-cyber-cyan text-xs font-mono mb-6">
          <Zap className="w-3.5 h-3.5" />
          <span>AUTONOMOUS MULTI-AGENT DEVSECOPS RESEARCH PROTOTYPE</span>
        </div>

        <h1 className="text-4xl sm:text-6xl font-extrabold tracking-tight text-white mb-6 leading-tight">
          Deterministic Security Scanners <br />
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyber-cyan via-blue-400 to-indigo-400">
            Powered by Multi-Agent AI Reasoning
          </span>
        </h1>

        <p className="text-base sm:text-lg text-slate-400 max-w-3xl mx-auto mb-10 leading-relaxed">
          SecureCodeOps AI coordinates a specialized supervisor hierarchy to perform AST repository analysis, 
          deterministic SAST scanning, STRIDE threat modeling, dependency CVE auditing, compliance verification, 
          and verified sandbox-tested patch synthesis.
        </p>

        <div className="flex flex-wrap items-center justify-center gap-4">
          <button
            onClick={handleLaunchDemo}
            disabled={loadingDemo}
            className="flex items-center gap-2 px-6 py-3.5 rounded-xl bg-cyber-cyan text-black font-bold text-sm hover:bg-cyan-300 transition-all shadow-cyber-cyan cursor-pointer"
          >
            <Play className="w-4 h-4 fill-current" />
            <span>{loadingDemo ? 'Initializing Analysis...' : 'Analyze Demo Repository'}</span>
            <ArrowRight className="w-4 h-4" />
          </button>

          <button
            onClick={() => navigate('/repositories')}
            className="flex items-center gap-2 px-6 py-3.5 rounded-xl bg-cyber-surface border border-cyber-border hover:border-cyber-cyan/50 text-white font-medium text-sm transition-all"
          >
            <span>Upload ZIP Repository</span>
          </button>
        </div>
      </section>

      {/* Multi-Agent Architecture Showcase */}
      <section className="py-16 px-8 max-w-6xl mx-auto w-full">
        <div className="text-center mb-12">
          <h2 className="text-2xl font-bold text-white mb-3">Supervisor-Coordinated Agent Pipeline</h2>
          <p className="text-sm text-slate-400 max-w-2xl mx-auto">
            Each specialized agent operates autonomously with clear input/output contracts and strict evidence provenance.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="p-6 rounded-xl glass-panel border border-cyber-border/80 hover:border-cyber-cyan/40 transition-all">
            <div className="w-10 h-10 rounded-lg bg-cyber-blue/10 border border-cyber-blue/30 flex items-center justify-center text-cyber-blue mb-4">
              <Cpu className="w-5 h-5" />
            </div>
            <h3 className="text-base font-bold text-white mb-2">1. Repository Analysis Agent</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Multi-language AST parsing (Python, JS/TS, Java) discovering endpoints, DB calls, auth checks, and constructing the Knowledge Graph.
            </p>
          </div>

          <div className="p-6 rounded-xl glass-panel border border-cyber-border/80 hover:border-cyber-cyan/40 transition-all">
            <div className="w-10 h-10 rounded-lg bg-cyber-red/10 border border-cyber-red/30 flex items-center justify-center text-cyber-red mb-4">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <h3 className="text-base font-bold text-white mb-2">2. Vulnerability Agent & AI Validator</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Orchestrates Semgrep, Bandit, Trivy, and GitLeaks with deterministic rule engines, validated by AI exploitability reasoning.
            </p>
          </div>

          <div className="p-6 rounded-xl glass-panel border border-cyber-border/80 hover:border-cyber-cyan/40 transition-all">
            <div className="w-10 h-10 rounded-lg bg-cyber-yellow/10 border border-cyber-yellow/30 flex items-center justify-center text-cyber-yellow mb-4">
              <Layers className="w-5 h-5" />
            </div>
            <h3 className="text-base font-bold text-white mb-2">3. STRIDE Threat Modeling Agent</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Automated STRIDE threat matrices with Impact (1–5) &times; Probability (1–5) risk scoring and step-by-step attack path generation.
            </p>
          </div>

          <div className="p-6 rounded-xl glass-panel border border-cyber-border/80 hover:border-cyber-cyan/40 transition-all">
            <div className="w-10 h-10 rounded-lg bg-cyber-purple/10 border border-cyber-purple/30 flex items-center justify-center text-cyber-purple mb-4">
              <Network className="w-5 h-5" />
            </div>
            <h3 className="text-base font-bold text-white mb-2">4. Dependency Scanner Agent</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Manifest audits for NPM, PyPI, and Maven with reachability exposure factor calculation and safe upgrade targets.
            </p>
          </div>

          <div className="p-6 rounded-xl glass-panel border border-cyber-border/80 hover:border-cyber-cyan/40 transition-all">
            <div className="w-10 h-10 rounded-lg bg-cyber-green/10 border border-cyber-green/30 flex items-center justify-center text-cyber-green mb-4">
              <FileCheck2 className="w-5 h-5" />
            </div>
            <h3 className="text-base font-bold text-white mb-2">5. Compliance Agent</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Multi-framework compliance verification covering OWASP Top 10, GDPR Article 32, ISO 27001, NIST SP 800-53, and PCI-DSS.
            </p>
          </div>

          <div className="p-6 rounded-xl glass-panel border border-cyber-border/80 hover:border-cyber-cyan/40 transition-all">
            <div className="w-10 h-10 rounded-lg bg-cyber-cyan/10 border border-cyber-cyan/30 flex items-center justify-center text-cyber-cyan mb-4">
              <GitPullRequest className="w-5 h-5" />
            </div>
            <h3 className="text-base font-bold text-white mb-2">6. Patch Agent & Re-Scan Verification</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Synthesizes context-aware diffs and executes isolated sandbox re-scans to verify vulnerability reduction before proposing.
            </p>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="mt-auto border-t border-cyber-border py-8 px-8 text-center text-xs text-cyber-muted font-mono">
        <p>SecureCodeOps AI &bull; Autonomous Multi-Agent DevSecOps Platform &bull; Academic & Research Prototype</p>
      </footer>
    </div>
  );
};
