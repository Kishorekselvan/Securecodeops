import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from './components/Layout/Layout';
import { LandingPage } from './pages/LandingPage';
import { Dashboard } from './pages/Dashboard';
import { Repositories } from './pages/Repositories';
import { ScanDetails } from './pages/ScanDetails';
import { Findings } from './pages/Findings';
import { ThreatModel } from './pages/ThreatModel';
import { Dependencies } from './pages/Dependencies';
import { CodeReview } from './pages/CodeReview';
import { Compliance } from './pages/Compliance';
import { Patches } from './pages/Patches';
import { KnowledgeGraph } from './pages/KnowledgeGraph';
import { Reports } from './pages/Reports';
import { Settings } from './pages/Settings';

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<LandingPage />} />
        
        {/* App Layout Shell */}
        <Route element={<Layout />}>
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/repositories" element={<Repositories />} />
          <Route path="/scans/:scanId" element={<ScanDetails />} />
          <Route path="/findings" element={<Findings />} />
          <Route path="/threat-model" element={<ThreatModel />} />
          <Route path="/dependencies" element={<Dependencies />} />
          <Route path="/code-review" element={<CodeReview />} />
          <Route path="/compliance" element={<Compliance />} />
          <Route path="/patches" element={<Patches />} />
          <Route path="/knowledge-graph" element={<KnowledgeGraph />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/settings" element={<Settings />} />
        </Route>

        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
};

export default App;
