import { useState, useCallback } from "react";
import Dashboard from "./components/Dashboard";
import UploadPanel from "./components/UploadPanel";
import RulesPanel from "./components/RulesPanel";
import Header from "./components/Header";
import "./App.css";

const API_BASE = process.env.REACT_APP_API_URL || "http://localhost:5000";

export default function App() {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [rules, setRules] = useState({
    blockedApps: [],
    blockedIPs: [],
    blockedDomains: [],
  });
  const [activeTab, setActiveTab] = useState("upload");

  const runDemo = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = await fetch(`${API_BASE}/api/demo`);
      const data = await resp.json();
      if (!data.success) throw new Error(data.error);
      setReport(data.report);
      setActiveTab("dashboard");
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  const analyzePcap = useCallback(async (file) => {
    setLoading(true);
    setError(null);
    try {
      const form = new FormData();
      if (file) form.append("pcap", file);
      form.append("rules", JSON.stringify(rules));

      const resp = await fetch(`${API_BASE}/api/analyze`, {
        method: "POST",
        body: form,
      });
      const data = await resp.json();
      if (!data.success) throw new Error(data.error);
      setReport(data.report);
      setActiveTab("dashboard");
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [rules]);

  return (
    <div className="app">
      <Header activeTab={activeTab} setActiveTab={setActiveTab} />

      <main className="main-content">
        {error && (
          <div className="error-banner">
            <span className="error-icon">⚠</span>
            <span>{error}</span>
            <button onClick={() => setError(null)}>✕</button>
          </div>
        )}

        {activeTab === "upload" && (
          <UploadPanel
            onAnalyze={analyzePcap}
            onDemo={runDemo}
            loading={loading}
          />
        )}
        {activeTab === "rules" && (
          <RulesPanel rules={rules} setRules={setRules} />
        )}
        {activeTab === "dashboard" && (
          <Dashboard report={report} loading={loading} onDemo={runDemo} />
        )}
      </main>
    </div>
  );
}
