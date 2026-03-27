import { useState, useRef } from "react";

export default function UploadPanel({ onAnalyze, onDemo, loading }) {
  const [dragOver, setDragOver] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const fileRef = useRef();

  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file) setSelectedFile(file);
  };

  const handleFile = (e) => {
    const file = e.target.files[0];
    if (file) setSelectedFile(file);
  };

  return (
    <div className="upload-panel">
      <div className="panel-header">
        <h2>Analyze PCAP File</h2>
        <p>Upload a Wireshark capture file to inspect traffic, identify applications, and apply blocking rules.</p>
      </div>

      <div
        className={`drop-zone ${dragOver ? "drag-over" : ""} ${selectedFile ? "has-file" : ""}`}
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        onClick={() => fileRef.current.click()}
      >
        <input
          ref={fileRef}
          type="file"
          accept=".pcap,.pcapng"
          style={{ display: "none" }}
          onChange={handleFile}
        />
        {selectedFile ? (
          <>
            <div className="drop-icon">📄</div>
            <div className="drop-filename">{selectedFile.name}</div>
            <div className="drop-size">{(selectedFile.size / 1024).toFixed(1)} KB</div>
          </>
        ) : (
          <>
            <div className="drop-icon">📁</div>
            <div className="drop-label">Drop your .pcap file here</div>
            <div className="drop-hint">or click to browse</div>
          </>
        )}
      </div>

      <div className="upload-actions">
        <button
          className="btn btn-primary"
          onClick={() => onAnalyze(selectedFile)}
          disabled={loading}
        >
          {loading ? "⏳ Analyzing..." : "🔍 Analyze PCAP"}
        </button>
        <div className="divider">or</div>
        <button
          className="btn btn-secondary"
          onClick={onDemo}
          disabled={loading}
        >
          {loading ? "⏳ Loading..." : "⚡ Run Demo (no file needed)"}
        </button>
      </div>

      <div className="info-cards">
        <div className="info-card">
          <div className="info-icon">🔎</div>
          <div className="info-title">TLS SNI Extraction</div>
          <div className="info-text">Identifies HTTPS destinations from Client Hello even without decryption</div>
        </div>
        <div className="info-card">
          <div className="info-icon">🏷</div>
          <div className="info-title">App Classification</div>
          <div className="info-text">Maps domains to apps: YouTube, Netflix, Facebook, GitHub and more</div>
        </div>
        <div className="info-card">
          <div className="info-icon">🚫</div>
          <div className="info-title">Flow Blocking</div>
          <div className="info-text">Block by app, IP, or domain. Once a flow is identified, all packets are filtered</div>
        </div>
        <div className="info-card">
          <div className="info-icon">📊</div>
          <div className="info-title">Traffic Reports</div>
          <div className="info-text">Full breakdown: packet counts, flows, app distribution, and blocked connections</div>
        </div>
      </div>
    </div>
  );
}
