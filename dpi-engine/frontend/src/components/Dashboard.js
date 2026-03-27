const CATEGORY_COLORS = {
  streaming: "#ef4444",
  social: "#3b82f6",
  google: "#22c55e",
  microsoft: "#a855f7",
  developer: "#f59e0b",
  other: "#6b7280",
  unknown: "#374151",
};

const CATEGORY_ICONS = {
  streaming: "🎬",
  social: "💬",
  google: "🔵",
  microsoft: "🟦",
  developer: "⚙️",
  other: "🌐",
  unknown: "❓",
};

function StatCard({ label, value, sub, color }) {
  return (
    <div className="stat-card" style={{ borderTopColor: color }}>
      <div className="stat-value" style={{ color }}>{value.toLocaleString()}</div>
      <div className="stat-label">{label}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  );
}

function AppBar({ app, count, total, blocked }) {
  const pct = Math.round((count / total) * 100);
  return (
    <div className={`app-bar ${blocked ? "app-blocked" : ""}`}>
      <div className="app-bar-header">
        <span className="app-name">{app}</span>
        <span className="app-count">{count} pkts · {pct}%{blocked ? " 🚫 BLOCKED" : ""}</span>
      </div>
      <div className="app-bar-track">
        <div
          className="app-bar-fill"
          style={{
            width: `${pct}%`,
            background: blocked ? "#ef4444" : "#22c55e",
          }}
        />
      </div>
    </div>
  );
}

export default function Dashboard({ report, loading, onDemo }) {
  if (loading) {
    return (
      <div className="dashboard-empty">
        <div className="spinner" />
        <p>Analyzing packets...</p>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="dashboard-empty">
        <div className="empty-icon">📊</div>
        <p>No analysis yet. Upload a PCAP file or run the demo.</p>
        <button className="btn btn-primary" onClick={onDemo}>⚡ Run Demo</button>
      </div>
    );
  }

  const { summary, appBreakdown, snisFound, blockedFlows, flows } = report;
  const dropPct = summary.total > 0 ? ((summary.dropped / summary.total) * 100).toFixed(1) : 0;
  const fwdPct = summary.total > 0 ? ((summary.forwarded / summary.total) * 100).toFixed(1) : 0;

  return (
    <div className="dashboard">
      {/* Summary Stats */}
      <div className="stats-grid">
        <StatCard label="Total Packets" value={summary.total} sub={`${(summary.totalBytes / 1024).toFixed(1)} KB`} color="#6b7280" />
        <StatCard label="Forwarded" value={summary.forwarded} sub={`${fwdPct}%`} color="#22c55e" />
        <StatCard label="Dropped" value={summary.dropped} sub={`${dropPct}%`} color="#ef4444" />
        <StatCard label="Flows Tracked" value={summary.flows} color="#3b82f6" />
        <StatCard label="TCP Packets" value={summary.tcp} color="#8b5cf6" />
        <StatCard label="UDP Packets" value={summary.udp} color="#f59e0b" />
      </div>

      <div className="dashboard-grid">
        {/* App Breakdown */}
        <div className="panel">
          <h3 className="panel-title">Application Breakdown</h3>
          {appBreakdown.length === 0 ? (
            <p className="empty-msg">No applications classified</p>
          ) : (
            appBreakdown.slice(0, 12).map((a) => (
              <AppBar key={a.app} {...a} total={summary.total} />
            ))
          )}
        </div>

        {/* Detected Domains */}
        <div className="panel">
          <h3 className="panel-title">🔍 Detected SNIs / Domains ({snisFound.length})</h3>
          <div className="sni-list">
            {snisFound.length === 0 ? (
              <p className="empty-msg">No SNIs extracted</p>
            ) : (
              snisFound.map(({ sni, app }) => (
                <div key={sni} className="sni-row">
                  <span className="sni-domain">{sni}</span>
                  <span className="sni-app">{app}</span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Blocked Flows */}
        {blockedFlows.length > 0 && (
          <div className="panel panel-blocked">
            <h3 className="panel-title">🚫 Blocked Flows ({blockedFlows.length})</h3>
            <div className="flow-list">
              {blockedFlows.map((f, i) => (
                <div key={i} className="flow-row">
                  <div className="flow-src">{f.srcIp}</div>
                  <div className="flow-arrow">→</div>
                  <div className="flow-dst">{f.dstIp}:{f.dstPort}</div>
                  <div className="flow-sni">{f.sni || "—"}</div>
                  <div className="flow-reason">{f.reason}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* All Flows */}
        <div className="panel">
          <h3 className="panel-title">🔗 All Flows ({flows.length})</h3>
          <div className="flow-table-wrap">
            <table className="flow-table">
              <thead>
                <tr>
                  <th>Source IP</th>
                  <th>Destination</th>
                  <th>SNI / Domain</th>
                  <th>App</th>
                  <th>Pkts</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {flows.slice(0, 30).map((f, i) => (
                  <tr key={i} className={f.blocked ? "row-blocked" : ""}>
                    <td className="td-ip">{f.srcIp}</td>
                    <td className="td-ip">{f.dstIp}:{f.dstPort}</td>
                    <td className="td-sni">{f.sni || <span className="td-empty">—</span>}</td>
                    <td>
                      <span className="badge-app">{f.app}</span>
                    </td>
                    <td>{f.packetCount}</td>
                    <td>
                      {f.blocked ? (
                        <span className="badge-blocked">BLOCKED</span>
                      ) : (
                        <span className="badge-ok">OK</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
