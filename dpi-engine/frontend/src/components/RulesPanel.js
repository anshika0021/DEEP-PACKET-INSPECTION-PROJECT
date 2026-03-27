import { useState } from "react";

const KNOWN_APPS = [
  "YouTube", "Netflix", "TikTok", "Twitch", "Disney+", "Spotify",
  "Facebook", "Twitter/X", "Instagram", "LinkedIn", "Reddit", "WhatsApp",
  "Telegram", "Google", "Gmail", "GitHub", "Zoom", "Slack", "Teams", "AWS"
];

export default function RulesPanel({ rules, setRules }) {
  const [ipInput, setIpInput] = useState("");
  const [domainInput, setDomainInput] = useState("");

  const toggleApp = (app) => {
    setRules((r) => ({
      ...r,
      blockedApps: r.blockedApps.includes(app)
        ? r.blockedApps.filter((a) => a !== app)
        : [...r.blockedApps, app],
    }));
  };

  const addIP = () => {
    const ip = ipInput.trim();
    if (ip && !rules.blockedIPs.includes(ip)) {
      setRules((r) => ({ ...r, blockedIPs: [...r.blockedIPs, ip] }));
      setIpInput("");
    }
  };

  const removeIP = (ip) => {
    setRules((r) => ({ ...r, blockedIPs: r.blockedIPs.filter((i) => i !== ip) }));
  };

  const addDomain = () => {
    const d = domainInput.trim().toLowerCase();
    if (d && !rules.blockedDomains.includes(d)) {
      setRules((r) => ({ ...r, blockedDomains: [...r.blockedDomains, d] }));
      setDomainInput("");
    }
  };

  const removeDomain = (d) => {
    setRules((r) => ({ ...r, blockedDomains: r.blockedDomains.filter((x) => x !== d) }));
  };

  const clearAll = () => {
    setRules({ blockedApps: [], blockedIPs: [], blockedDomains: [] });
  };

  const totalRules = rules.blockedApps.length + rules.blockedIPs.length + rules.blockedDomains.length;

  return (
    <div className="rules-panel">
      <div className="panel-header">
        <h2>🛡 Blocking Rules</h2>
        <p>Configure what traffic to block. Rules are applied when you analyze a PCAP.</p>
        {totalRules > 0 && (
          <div className="rules-badge">{totalRules} active rule{totalRules !== 1 ? "s" : ""}</div>
        )}
      </div>

      {/* App blocking */}
      <div className="rule-section">
        <h3>Block by Application</h3>
        <p className="rule-desc">Select apps to block. All traffic classified as these apps will be dropped.</p>
        <div className="app-grid">
          {KNOWN_APPS.map((app) => (
            <button
              key={app}
              className={`app-tag ${rules.blockedApps.includes(app) ? "blocked" : ""}`}
              onClick={() => toggleApp(app)}
            >
              {rules.blockedApps.includes(app) ? "🚫 " : ""}{app}
            </button>
          ))}
        </div>
      </div>

      {/* IP blocking */}
      <div className="rule-section">
        <h3>Block by Source IP</h3>
        <p className="rule-desc">All traffic from these IPs will be dropped regardless of application.</p>
        <div className="input-row">
          <input
            className="rule-input"
            placeholder="e.g. 192.168.1.50"
            value={ipInput}
            onChange={(e) => setIpInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && addIP()}
          />
          <button className="btn btn-sm" onClick={addIP}>Add IP</button>
        </div>
        <div className="tag-list">
          {rules.blockedIPs.map((ip) => (
            <span key={ip} className="tag tag-ip">
              {ip}
              <button onClick={() => removeIP(ip)}>✕</button>
            </span>
          ))}
        </div>
      </div>

      {/* Domain blocking */}
      <div className="rule-section">
        <h3>Block by Domain Pattern</h3>
        <p className="rule-desc">Substring match: "tiktok" will block tiktok.com, cdn.tiktok.com, etc.</p>
        <div className="input-row">
          <input
            className="rule-input"
            placeholder="e.g. tiktok"
            value={domainInput}
            onChange={(e) => setDomainInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && addDomain()}
          />
          <button className="btn btn-sm" onClick={addDomain}>Add Pattern</button>
        </div>
        <div className="tag-list">
          {rules.blockedDomains.map((d) => (
            <span key={d} className="tag tag-domain">
              {d}
              <button onClick={() => removeDomain(d)}>✕</button>
            </span>
          ))}
        </div>
      </div>

      {totalRules > 0 && (
        <button className="btn btn-danger" onClick={clearAll}>Clear All Rules</button>
      )}
    </div>
  );
}
