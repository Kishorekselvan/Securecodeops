import React, { useEffect, useState } from 'react';
import { Cpu, Search, Filter, Info, Layers, Network, Database, Lock, AlertTriangle } from 'lucide-react';
import { api } from '../services/api';
import { KnowledgeGraph as KnowledgeGraphType, ScanSummary } from '../types';

export const KnowledgeGraph: React.FC = () => {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>('');
  const [graphData, setGraphData] = useState<KnowledgeGraphType | null>(null);
  const [selectedType, setSelectedType] = useState<string>('ALL');
  const [selectedNode, setSelectedNode] = useState<any>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadScans();
  }, []);

  useEffect(() => {
    if (selectedScanId) {
      loadGraph(selectedScanId);
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

  const loadGraph = async (scanId: string) => {
    setLoading(true);
    try {
      const data = await api.getKnowledgeGraph(scanId);
      setGraphData(data);
      if (data.nodes.length > 0) {
        setSelectedNode(data.nodes[0]);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const nodeTypes = ['ALL', 'File', 'Function', 'API_Endpoint', 'Database', 'Auth', 'Sensitive_Data', 'Dependency', 'Finding', 'Threat'];

  const filteredNodes = graphData?.nodes.filter(n => {
    const matchesType = selectedType === 'ALL' || n.type === selectedType;
    const matchesSearch = n.label.toLowerCase().includes(searchQuery.toLowerCase()) || n.type.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesType && matchesSearch;
  }) || [];

  const getNodeColor = (type: string) => {
    switch (type) {
      case 'File': return 'text-blue-400 bg-blue-950/40 border-blue-500/30';
      case 'Function': return 'text-cyan-400 bg-cyan-950/40 border-cyan-500/30';
      case 'API_Endpoint': return 'text-emerald-400 bg-emerald-950/40 border-emerald-500/30';
      case 'Database': return 'text-amber-400 bg-amber-950/40 border-amber-500/30';
      case 'Auth': return 'text-purple-400 bg-purple-950/40 border-purple-500/30';
      case 'Sensitive_Data': return 'text-rose-400 bg-rose-950/40 border-rose-500/30';
      case 'Finding': return 'text-red-400 bg-red-950/40 border-red-500/30';
      case 'Threat': return 'text-orange-400 bg-orange-950/40 border-orange-500/30';
      case 'Dependency': return 'text-indigo-400 bg-indigo-950/40 border-indigo-500/30';
      default: return 'text-slate-300 bg-slate-900 border-slate-700';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Repository Knowledge Graph</h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Structural relationship ontology mapping Files, Functions, Endpoints, Databases, Secrets, and Threats
          </p>
        </div>

        {/* Scan Selector */}
        {scans.length > 0 && (
          <select
            value={selectedScanId}
            onChange={(e) => setSelectedScanId(e.target.value)}
            className="bg-cyber-panel border border-cyber-border rounded-lg px-3 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyber-cyan"
          >
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                {s.repository_name || 'Repository'} ({s.status})
              </option>
            ))}
          </select>
        )}
      </div>

      {/* Type Filter Buttons */}
      <div className="flex flex-wrap gap-2">
        {nodeTypes.map((t) => (
          <button
            key={t}
            onClick={() => setSelectedType(t)}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all ${
              selectedType === t
                ? 'bg-cyber-cyan text-black font-bold shadow-cyber-cyan'
                : 'bg-cyber-panel border border-cyber-border text-slate-300 hover:text-white'
            }`}
          >
            {t} {graphData?.stats?.[t] ? `(${graphData.stats[t]})` : ''}
          </button>
        ))}
      </div>

      {/* Main Grid: Visual Graph Nodes & Inspector Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Nodes Canvas / Grid */}
        <div className="lg:col-span-8 rounded-xl glass-panel border border-cyber-border/80 p-5 h-[680px] flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <div className="relative flex-1 max-w-sm">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Filter graph nodes..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-cyber-bg border border-cyber-border rounded-lg pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-500 font-mono"
              />
            </div>
            <span className="text-xs font-mono text-cyber-muted">
              {filteredNodes.length} NODES &bull; {graphData?.edges?.length || 0} RELATIONSHIP EDGES
            </span>
          </div>

          <div className="flex-1 overflow-y-auto p-4 rounded-xl bg-black/40 border border-cyber-border/40 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 auto-rows-max">
            {filteredNodes.map((n) => {
              const isSelected = selectedNode?.id === n.id;
              return (
                <div
                  key={n.id}
                  onClick={() => setSelectedNode(n)}
                  className={`p-3 rounded-lg border cursor-pointer transition-all ${getNodeColor(n.type)} ${
                    isSelected ? 'ring-2 ring-cyber-cyan shadow-cyber-cyan' : 'hover:scale-[1.02]'
                  }`}
                >
                  <div className="flex items-center justify-between gap-1.5 mb-1">
                    <span className="text-[10px] font-mono font-bold uppercase tracking-wider opacity-80">
                      {n.type}
                    </span>
                  </div>
                  <h4 className="text-xs font-bold truncate text-white">{n.label}</h4>
                </div>
              );
            })}

            {filteredNodes.length === 0 && !loading && (
              <div className="col-span-full py-16 text-center text-xs text-slate-500 font-mono">
                No graph nodes match this type or query.
              </div>
            )}
          </div>
        </div>

        {/* Node Inspection Panel */}
        <div className="lg:col-span-4 rounded-xl glass-panel border border-cyber-border/80 p-5 h-[680px] overflow-y-auto space-y-4">
          <h3 className="text-xs font-bold font-mono text-slate-300 uppercase flex items-center gap-2">
            <Info className="w-4 h-4 text-cyber-cyan" />
            NODE PROPERTIES & RELATIONSHIPS
          </h3>

          {selectedNode ? (
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-cyber-bg border border-cyber-border">
                <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${getNodeColor(selectedNode.type)}`}>
                  {selectedNode.type}
                </span>
                <h2 className="text-sm font-bold text-white mt-2 break-all">{selectedNode.label}</h2>
              </div>

              {/* Properties */}
              <div className="space-y-2">
                <h4 className="text-[11px] font-mono text-slate-400 uppercase">Properties</h4>
                <div className="p-3 rounded-lg bg-cyber-bg/70 border border-cyber-border font-mono text-xs text-slate-300 space-y-1.5">
                  {Object.entries(selectedNode.properties || {}).map(([k, v]) => (
                    <div key={k} className="flex flex-col">
                      <span className="text-slate-500 text-[10px] uppercase">{k}:</span>
                      <span className="text-white break-all">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Connected Edges */}
              <div className="space-y-2">
                <h4 className="text-[11px] font-mono text-slate-400 uppercase">Connected Relationships</h4>
                <div className="space-y-1.5">
                  {graphData?.edges
                    ?.filter(e => e.source === selectedNode.id || e.target === selectedNode.id)
                    .map((edge) => (
                      <div key={edge.id} className="p-2.5 rounded bg-cyber-bg border border-cyber-border text-xs font-mono text-slate-300 flex items-center justify-between">
                        <span className="text-cyber-cyan font-bold">[{edge.label}]</span>
                        <span className="text-slate-400 truncate max-w-[150px]">
                          {edge.source === selectedNode.id ? edge.target : edge.source}
                        </span>
                      </div>
                    ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center text-xs text-slate-500 font-mono">
              Click any node in the graph to inspect properties and relationships.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
