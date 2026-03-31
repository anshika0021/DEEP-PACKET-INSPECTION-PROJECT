# 🔍 DPI Engine — Deep Packet Inspection in Node.js + React

A full JavaScript implementation of the DPI system — no C++, no compilation.  
Built for MERN stack developers. Runs entirely with Node.js and React.

---

## 📁 Project Structure

```
dpi-engine/
├── backend/
│   ├── src/
│   │   ├── pcapReader.js        # Reads .pcap binary files
│   │   ├── pcapWriter.js        # Writes filtered output .pcap
│   │   ├── packetParser.js      # Parses Ethernet → IP → TCP/UDP
│   │   ├── sniExtractor.js      # Extracts TLS SNI + HTTP Host + DNS
│   │   ├── appClassifier.js     # Maps domains → app names (YouTube, etc.)
│   │   ├── dpiEngine.js         # Core engine: flow tracking + rule engine
│   │   └── testPcapGenerator.js # Generates synthetic test traffic
│   ├── cli.js                   # Command-line interface
│   ├── server.js                # Express REST API
│   └── package.json
├── frontend/
│   ├── src/
│   │   ├── App.js               # Main React app
│   │   ├── App.css              # Dark terminal-style UI
│   │   └── components/
│   │       ├── Header.js
│   │       ├── UploadPanel.js   # Drag-and-drop PCAP upload
│   │       ├── RulesPanel.js    # Configure blocking rules
│   │       └── Dashboard.js     # Analysis results + charts
│   └── package.json
└── package.json                 # Root scripts
```

---

## 🚀 Quick Start (3 steps)

### Prerequisites
- Node.js v16+ installed → check with: `node --version`
- npm installed → check with: `npm --version`

---

### Step 1: Install dependencies

```bash
# Install backend dependencies
cd dpi-engine/backend
npm install

# Install frontend dependencies
cd ../frontend
npm install
```

---

### Step 2A: Run as Web App (React + Express)

Open **two terminals**:
## Second PR for Pull Shark Badge 🔥
**Terminal 1 — Backend API:**
```bash
cd dpi-engine/backend
node server.js
# → API running on http://localhost:5000
```

**Terminal 2 — React Frontend:**
```bash
cd dpi-engine/frontend
npm start
# → UI opens at http://localhost:3000
```
## Second update for Pull Shark Badge

Then open `http://localhost:3000` in your browser.

---

### Step 2B: Run as CLI (no frontend needed)

```bash
cd dpi-engine/backend

# Run demo with built-in test traffic:
node cli.js --demo

# Block YouTube and TikTok in demo:
node cli.js --demo --block-app YouTube --block-app TikTok

# Block a specific IP:
node cli.js --demo --block-ip 192.168.1.50

# Analyze your own .pcap file:
node cli.js path/to/capture.pcap output.pcap --block-app Netflix

# Multiple rules together:
node cli.js capture.pcap filtered.pcap \
  --block-app YouTube \
  --block-app TikTok \
  --block-ip 192.168.1.50 \
  --block-domain facebook
```

---

## 🌐 API Endpoints

Once the backend is running (`node server.js`):

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/demo` | Run analysis on built-in test traffic |
| POST | `/api/analyze` | Upload a .pcap file + rules, get report |

### Test the API directly:

```bash
# Health check
curl http://localhost:5000/api/health

# Run demo analysis
curl http://localhost:5000/api/demo

# Upload your own PCAP with rules
curl -X POST http://localhost:5000/api/analyze \
  -F "pcap=@capture.pcap" \
  -F 'rules={"blockedApps":["YouTube","TikTok"],"blockedIPs":[],"blockedDomains":[]}'
```

---

## 🧪 How the Demo Works (No PCAP file needed)

The engine includes a **built-in traffic generator** that creates synthetic packets:

| Source IP | Destination | SNI / Domain | App |
|-----------|-------------|--------------|-----|
| 192.168.1.100 | 142.250.x.x:443 | www.youtube.com | YouTube |
| 192.168.1.100 | 157.240.x.x:443 | www.facebook.com | Facebook |
| 192.168.1.101 | 140.82.x.x:443 | github.com | GitHub |
| 192.168.1.102 | 34.107.x.x:443 | www.netflix.com | Netflix |
| 192.168.1.103 | 104.244.x.x:443 | twitter.com | Twitter/X |
| 192.168.1.105 | 128.199.x.x:443 | www.tiktok.com | TikTok |
| 192.168.1.50  | various:443 | instagram, youtube | (blocked IP) |
| + DNS queries, HTTP traffic, Zoom, Slack, Teams, AWS... | | | |

---

## 📊 What You See in the Dashboard

1. **Summary stats** — total packets, forwarded, dropped, flows, TCP/UDP split
2. **Application breakdown** — bar chart of traffic by app with block status
3. **Detected SNIs** — every domain name extracted from TLS/HTTP/DNS
4. **Blocked flows** — which connections were dropped and why
5. **Flow table** — full list of all tracked network flows

---

## 🛡 Blocking Rules

Three types of rules (combinable):

```
By App:     Block all traffic classified as "YouTube", "TikTok", etc.
By IP:      Block all traffic from a source IP (e.g. 192.168.1.50)
By Domain:  Substring match — "tiktok" blocks tiktok.com, cdn.tiktok.com, etc.
```

**Flow-level blocking**: Once a flow is identified as blocked (after seeing the TLS Client Hello), ALL subsequent packets of that flow are dropped — same behavior as the C++ original.

---

## 🔬 How SNI Extraction Works (JavaScript)

```
PCAP file
  └── Raw bytes
        └── Ethernet header (14 bytes)  →  src/dst MAC
              └── IP header (20 bytes)  →  src/dst IP, protocol
                    └── TCP header (20 bytes)  →  src/dst port
                          └── Payload
                                ├── TLS Record (byte 0 = 0x16)
                                │     └── Client Hello (byte 5 = 0x01)
                                │           └── Extensions
                                │                 └── SNI (type 0x0000)
                                │                       └── "www.youtube.com" ✓
                                ├── HTTP Request
                                │     └── "Host: example.com" ✓
                                └── DNS Query
                                      └── "api.github.com" ✓
```

---

## 🔧 Add Your Own App Signatures

Edit `backend/src/appClassifier.js`:

```js
const APP_SIGNATURES = [
  // Add your custom app
  { app: 'MyApp', patterns: ['myapp.com', 'cdn.myapp.io'] },
  ...
];
```

---

## 📦 Getting a Real PCAP File

If you want to analyze real traffic (not the demo):

1. Install **Wireshark**: https://www.wireshark.org/download.html
2. Capture traffic on your network interface
3. Save as `.pcap` format
4. Upload via the web UI or pass to the CLI

Or download sample captures from:
- https://wiki.wireshark.org/SampleCaptures
- https://www.netresec.com/?page=PcapFiles

---

## ❓ Troubleshooting

| Problem | Fix |
|---------|-----|
| `EADDRINUSE: port 5000` | Another process uses 5000. Run: `PORT=5001 node server.js` and update `REACT_APP_API_URL=http://localhost:5001` |
| `npm start` fails in frontend | Make sure you're in the `frontend/` folder, not root |
| CORS error in browser | Backend must be running on port 5000 before starting frontend |
| "Invalid PCAP magic number" | File is not a valid .pcap (maybe .pcapng — convert in Wireshark: File → Save As → pcap) |

---

## 🗺 Architecture Summary
```
Browser (React)
    ↕  HTTP/JSON
Express API (Node.js :5000)
    │
    ├── PcapReader     → reads binary .pcap
    ├── PacketParser   → Ethernet/IP/TCP/UDP
    ├── SNIExtractor   → TLS Client Hello + HTTP Host + DNS
    ├── AppClassifier  → domain → app name
    ├── DPIEngine      → flow table + rule engine
    └── PcapWriter     → writes filtered output
```
