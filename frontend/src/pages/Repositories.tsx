import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  FolderGit2, Upload, Play, RefreshCw, FileCode, Clock,
  Shield, CheckCircle2, AlertCircle, FileArchive
} from 'lucide-react';
import { api } from '../services/api';
import { Repository } from '../types';

export const Repositories: React.FC = () => {
  const navigate = useNavigate();
  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [repoName, setRepoName] = useState('');
  const [repoDesc, setRepoDesc] = useState('');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    loadRepositories();
  }, []);

  const loadRepositories = async () => {
    setLoading(true);
    try {
      const data = await api.getRepositories();
      setRepositories(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFile) {
      setErrorMsg('Please select a .zip repository file to upload.');
      return;
    }

    setUploading(true);
    setErrorMsg(null);

    const formData = new FormData();
    formData.append('file', selectedFile);
    if (repoName) formData.append('name', repoName);
    if (repoDesc) formData.append('description', repoDesc);

    try {
      const newRepo = await api.uploadRepositoryZip(formData);
      const scan = await api.createScan(newRepo.id);
      navigate(`/scans/${scan.id}`);
    } catch (err: any) {
      setErrorMsg(err?.response?.data?.detail || 'Failed to upload and extract repository archive.');
    } finally {
      setUploading(false);
    }
  };

  const handleCreateDemo = async () => {
    setUploading(true);
    setErrorMsg(null);
    try {
      const demoRepo = await api.createDemoRepository();
      const scan = await api.createScan(demoRepo.id);
      navigate(`/scans/${scan.id}`);
    } catch (err: any) {
      setErrorMsg(err?.response?.data?.detail || 'Failed to initialize demo repository.');
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Repository Management</h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Upload source archives (.zip) or inspect tracked repositories for security analysis
          </p>
        </div>

        <button
          onClick={handleCreateDemo}
          disabled={uploading}
          className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-cyber-cyan text-black text-xs font-bold hover:bg-cyan-300 transition-all shadow-cyber-cyan cursor-pointer disabled:opacity-50"
        >
          <Play className="w-3.5 h-3.5 fill-current" />
          <span>Launch Demo Repository Scan</span>
        </button>
      </div>

      {/* Upload Box */}
      <div className="p-6 rounded-xl glass-panel border border-cyber-border/80">
        <h2 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
          <Upload className="w-4 h-4 text-cyber-cyan" />
          Upload New Repository Archive
        </h2>

        {errorMsg && (
          <div className="mb-4 p-3 rounded-lg bg-cyber-red/10 border border-cyber-red/30 text-cyber-red text-xs flex items-center gap-2">
            <AlertCircle className="w-4 h-4 flex-shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}

        <form onSubmit={handleUpload} className="space-y-4">
          {/* Drag & Drop Target */}
          <div
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragOver(false);
              if (e.dataTransfer.files?.[0]) {
                setSelectedFile(e.dataTransfer.files[0]);
                if (!repoName) setRepoName(e.dataTransfer.files[0].name.replace('.zip', ''));
              }
            }}
            className={`border-2 border-dashed rounded-xl p-8 text-center transition-all cursor-pointer ${
              dragOver
                ? 'border-cyber-cyan bg-cyber-cyan/5'
                : 'border-cyber-border hover:border-cyber-border/80 bg-cyber-bg/40'
            }`}
            onClick={() => document.getElementById('repo-file-input')?.click()}
          >
            <input
              id="repo-file-input"
              type="file"
              accept=".zip"
              className="hidden"
              onChange={(e) => {
                if (e.target.files?.[0]) {
                  setSelectedFile(e.target.files[0]);
                  if (!repoName) setRepoName(e.target.files[0].name.replace('.zip', ''));
                }
              }}
            />

            <FileArchive className="w-10 h-10 text-cyber-cyan mx-auto mb-3" />
            <p className="text-xs text-slate-200 font-medium">
              {selectedFile ? selectedFile.name : 'Click to browse or drag & drop ZIP repository here'}
            </p>
            <p className="text-[11px] text-cyber-muted font-mono mt-1">
              Supports .zip archives up to 50MB (Zip Slip & Zip Bomb Protected)
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1">Repository Name (Optional)</label>
              <input
                type="text"
                placeholder="e.g. backend-api-service"
                value={repoName}
                onChange={(e) => setRepoName(e.target.value)}
                className="w-full bg-cyber-bg border border-cyber-border rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyber-cyan font-mono"
              />
            </div>
            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1">Description (Optional)</label>
              <input
                type="text"
                placeholder="e.g. Primary backend authentication and payments service"
                value={repoDesc}
                onChange={(e) => setRepoDesc(e.target.value)}
                className="w-full bg-cyber-bg border border-cyber-border rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyber-cyan"
              />
            </div>
          </div>

          <div className="flex justify-end">
            <button
              type="submit"
              disabled={uploading || !selectedFile}
              className="flex items-center gap-2 px-5 py-2 rounded-lg bg-cyber-panel hover:bg-cyber-cyan/20 border border-cyber-cyan/40 text-cyber-cyan text-xs font-bold transition-all disabled:opacity-40 cursor-pointer"
            >
              {uploading ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Extracting & Starting Scan...</span>
                </>
              ) : (
                <>
                  <Upload className="w-3.5 h-3.5" />
                  <span>Upload & Analyze</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Repositories List */}
      <div className="rounded-xl glass-panel border border-cyber-border/80 overflow-hidden">
        <div className="p-5 border-b border-cyber-border flex items-center justify-between">
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <FolderGit2 className="w-4 h-4 text-cyber-cyan" />
            Configured Repositories ({repositories.length})
          </h2>
        </div>

        <div className="divide-y divide-cyber-border/40">
          {repositories.map((r) => (
            <div key={r.id} className="p-5 hover:bg-cyber-panel/30 transition-colors flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div className="space-y-1.5">
                <div className="flex items-center gap-2">
                  <span className="font-bold text-sm text-white">{r.name}</span>
                  {r.is_demo && (
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyber-purple/20 text-cyber-purple border border-cyber-purple/30">
                      DEMO
                    </span>
                  )}
                </div>
                <p className="text-xs text-slate-400 max-w-xl">{r.description || 'No description provided.'}</p>
                <div className="flex flex-wrap items-center gap-3 text-[11px] text-cyber-muted font-mono">
                  <span>{r.file_count} files</span>
                  <span>&bull;</span>
                  <span>{r.lines_of_code} lines of code</span>
                  <span>&bull;</span>
                  <span>Languages: {r.languages?.join(', ') || 'Multi-language'}</span>
                </div>
              </div>

              <div className="flex items-center gap-3">
                <button
                  onClick={async () => {
                    const scan = await api.createScan(r.id);
                    navigate(`/scans/${scan.id}`);
                  }}
                  className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-cyber-cyan/10 hover:bg-cyber-cyan/20 border border-cyber-cyan/30 text-cyber-cyan text-xs font-mono font-medium transition-all"
                >
                  <Play className="w-3 h-3 fill-current" />
                  <span>Start Scan</span>
                </button>
              </div>
            </div>
          ))}

          {repositories.length === 0 && !loading && (
            <div className="p-8 text-center text-slate-500 font-mono text-xs">
              No repositories added yet. Upload a ZIP file or start with the Demo Repository.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
