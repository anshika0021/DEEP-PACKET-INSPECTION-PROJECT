export default function Header({ activeTab, setActiveTab }) {
  const tabs = [
    { id: "upload", label: "📁 Upload PCAP" },
    { id: "rules", label: "🛡 Blocking Rules" },
    { id: "dashboard", label: "📊 Dashboard" },
  ];

  return (
    <header className="header">
      <div className="header-brand">
        <div className="brand-icon">🔍</div>
        <div>
          <div className="brand-title">DPI Engine</div>
          <div className="brand-sub">Deep Packet Inspection · Node.js</div>
        </div>
      </div>
      <nav className="header-nav">
        {tabs.map((t) => (
          <button
            key={t.id}
            className={`nav-btn ${activeTab === t.id ? "active" : ""}`}
            onClick={() => setActiveTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </nav>
    </header>
  );
}
