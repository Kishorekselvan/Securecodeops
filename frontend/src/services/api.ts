import axios from 'axios';
import type {
  Repository, ScanSummary, ScanDetails, Finding, Threat,
  Dependency, ComplianceCheck, Patch, Report, AgentLog, KnowledgeGraph
} from '../types';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

const client = axios.create({
  baseURL: API_BASE,
  timeout: 45000,
});

export const api = {
  // Repositories
  getRepositories: async (): Promise<Repository[]> => {
    const res = await client.get('/repositories');
    return res.data;
  },
  getRepository: async (id: string): Promise<Repository> => {
    const res = await client.get(`/repositories/${id}`);
    return res.data;
  },
  uploadRepositoryZip: async (formData: FormData): Promise<Repository> => {
    const res = await client.post('/repositories/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    });
    return res.data;
  },
  createDemoRepository: async (): Promise<Repository> => {
    const res = await client.post('/repositories/demo');
    return res.data;
  },

  // Scans
  createScan: async (repositoryId: string): Promise<ScanSummary> => {
    const res = await client.post('/scans', { repository_id: repositoryId });
    return res.data;
  },
  getScans: async (): Promise<ScanSummary[]> => {
    const res = await client.get('/scans');
    return res.data;
  },
  getScanDetails: async (scanId: string): Promise<ScanDetails> => {
    const res = await client.get(`/scans/${scanId}`);
    return res.data;
  },
  getScanStatus: async (scanId: string): Promise<any> => {
    const res = await client.get(`/scans/${scanId}/status`);
    return res.data;
  },

  // Findings
  getFindings: async (params?: Record<string, any>): Promise<Finding[]> => {
    const res = await client.get('/findings', { params });
    return res.data;
  },
  getFinding: async (id: string): Promise<Finding> => {
    const res = await client.get(`/findings/${id}`);
    return res.data;
  },
  updateFindingStatus: async (id: string, status: string): Promise<Finding> => {
    const res = await client.patch(`/findings/${id}/status`, null, { params: { status } });
    return res.data;
  },
  submitFindingFeedback: async (id: string, feedbackType: string, notes?: string): Promise<any> => {
    const res = await client.post(`/findings/${id}/feedback`, {
      feedback_type: feedbackType,
      developer_notes: notes || ''
    });
    return res.data;
  },
  getLearningStats: async (): Promise<any> => {
    const res = await client.get('/findings/learning/stats');
    return res.data;
  },

  // Threats
  getThreats: async (params?: Record<string, any>): Promise<Threat[]> => {
    const res = await client.get('/threats', { params });
    return res.data;
  },

  // Dependencies
  getDependencies: async (params?: Record<string, any>): Promise<Dependency[]> => {
    const res = await client.get('/dependencies', { params });
    return res.data;
  },

  // Compliance
  getComplianceChecks: async (params?: Record<string, any>): Promise<ComplianceCheck[]> => {
    const res = await client.get('/compliance', { params });
    return res.data;
  },
  getComplianceSummary: async (scanId: string): Promise<Record<string, any>> => {
    const res = await client.get('/compliance/framework-summary', { params: { scan_id: scanId } });
    return res.data;
  },

  // Patches
  getPatches: async (params?: Record<string, any>): Promise<Patch[]> => {
    const res = await client.get('/patches', { params });
    return res.data;
  },
  applyPatch: async (patchId: string): Promise<Patch> => {
    const res = await client.post(`/patches/${patchId}/apply`);
    return res.data;
  },
  rejectPatch: async (patchId: string): Promise<Patch> => {
    const res = await client.post(`/patches/${patchId}/reject`);
    return res.data;
  },
  downloadPatchUrl: (patchId: string) => `${API_BASE}/patches/${patchId}/download`,

  // Reports
  getReport: async (scanId: string): Promise<Report> => {
    const res = await client.get(`/reports/${scanId}`);
    return res.data;
  },
  getBenchmarkMetrics: async (): Promise<any> => {
    const res = await client.get('/reports/benchmark/metrics');
    return res.data;
  },
  getPdfReportUrl: (scanId: string) => `${API_BASE}/reports/${scanId}/pdf`,
  getJsonExportUrl: (scanId: string) => `${API_BASE}/reports/${scanId}/export-json`,
  getCsvExportUrl: (scanId: string) => `${API_BASE}/reports/${scanId}/export-csv`,

  // Knowledge Graph
  getKnowledgeGraph: async (scanId: string): Promise<KnowledgeGraph> => {
    const res = await client.get(`/knowledge-graph/${scanId}`);
    return res.data;
  },

  // Agent Logs
  getAgentLogs: async (scanId: string): Promise<AgentLog[]> => {
    const res = await client.get('/agent-logs', { params: { scan_id: scanId } });
    return res.data;
  },

  // Settings
  getSystemSettings: async (): Promise<any> => {
    const res = await client.get('/settings/status');
    return res.data;
  }
};
