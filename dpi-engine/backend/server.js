/**
 * DPI Engine - Express API Server
 */

const express = require('express');
const multer = require('multer');
const cors = require('cors');
const path = require('path');

const PcapReader = require('./src/pcapReader');
const PcapWriter = require('./src/pcapWriter');
const DPIEngine = require('./src/dpiEngine');
const { generateTestPcap } = require('./src/testPcapGenerator');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// Multer: store in memory
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }, // 50 MB
  fileFilter: (req, file, cb) => {
    if (file.originalname.endsWith('.pcap') || file.originalname.endsWith('.pcapng')) {
      cb(null, true);
    } else {
      cb(new Error('Only .pcap files are allowed'));
    }
  },
});

/**
 * POST /api/analyze
 * Body: multipart/form-data
 *   - pcap: file (optional, will use generated test if missing)
 *   - rules: JSON string { blockedApps: [], blockedIPs: [], blockedDomains: [] }
 */
app.post('/api/analyze', upload.single('pcap'), (req, res) => {
  try {
    let pcapBuffer;
    if (req.file) {
      pcapBuffer = req.file.buffer;
    } else {
      // Use generated test PCAP
      pcapBuffer = generateTestPcap();
    }

    let rules = {};
    if (req.body.rules) {
      try {
        rules = JSON.parse(req.body.rules);
      } catch (e) {
        rules = {};
      }
    }

    // Process PCAP
    const reader = new PcapReader();
    reader.openBuffer(pcapBuffer);

    const engine = new DPIEngine(rules);
    const writer = new PcapWriter();

    for (const rawPacket of reader.packets()) {
      const result = engine.processPacket(rawPacket);
      if (result.action === 'forward') {
        writer.writePacket(rawPacket);
      }
    }

    const report = engine.getReport();
    const outputPcap = writer.toBuffer();

    res.json({
      success: true,
      report,
      outputPcapBase64: outputPcap.toString('base64'),
      outputPcapSize: outputPcap.length,
    });
  } catch (err) {
    console.error('Error processing PCAP:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/demo
 * Run analysis on generated test PCAP with default rules
 */
app.get('/api/demo', (req, res) => {
  try {
    const pcapBuffer = generateTestPcap();
    const rules = {
      blockedApps: ['YouTube', 'TikTok'],
      blockedIPs: ['192.168.1.50'],
      blockedDomains: [],
    };

    const reader = new PcapReader();
    reader.openBuffer(pcapBuffer);

    const engine = new DPIEngine(rules);
    const writer = new PcapWriter();

    for (const rawPacket of reader.packets()) {
      const result = engine.processPacket(rawPacket);
      if (result.action === 'forward') {
        writer.writePacket(rawPacket);
      }
    }

    const report = engine.getReport();
    res.json({ success: true, report });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/health
 */
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`\n🔍 DPI Engine API running on http://localhost:${PORT}`);
  console.log(`   Try: GET http://localhost:${PORT}/api/demo`);
});

module.exports = app;
