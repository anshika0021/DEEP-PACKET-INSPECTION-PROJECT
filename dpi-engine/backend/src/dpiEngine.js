/**
 * DPI Engine - Core
 * Orchestrates: packet parsing → SNI extraction → classification → rule matching
 */

const { parsePacket } = require('./packetParser');
const { extractTLSSNI, extractHTTPHost, extractDNSQuery } = require('./sniExtractor');
const { classifyHost } = require('./appClassifier');

class DPIEngine {
  constructor(rules = {}) {
    this.rules = {
      blockedApps: new Set((rules.blockedApps || []).map(a => a.toLowerCase())),
      blockedIPs: new Set(rules.blockedIPs || []),
      blockedDomains: (rules.blockedDomains || []).map(d => d.toLowerCase()),
    };

    // Flow table: flowKey → flow state
    this.flows = new Map();

    // Stats
    this.stats = {
      total: 0,
      forwarded: 0,
      dropped: 0,
      tcp: 0,
      udp: 0,
      other: 0,
      totalBytes: 0,
      appCounts: {},
      snisFound: [],
      blockedFlows: [],
    };
  }

  /**
   * Process a single raw packet
   * Returns: { packet, parsed, flow, action: 'forward'|'drop', reason }
   */
  processPacket(rawPacket) {
    this.stats.total++;
    this.stats.totalBytes += rawPacket.origLen || rawPacket.inclLen || 0;

    const parsed = parsePacket(rawPacket);

    if (!parsed) {
      this.stats.forwarded++;
      return { raw: rawPacket, parsed: null, flow: null, action: 'forward', reason: 'non-ip' };
    }

    if (parsed.isTcp) this.stats.tcp++;
    else if (parsed.isUdp) this.stats.udp++;
    else this.stats.other++;

    // Get or create flow
    const flow = this._getOrCreateFlow(parsed);

    // If flow already blocked, drop immediately
    if (flow.blocked) {
      this.stats.dropped++;
      return { raw: rawPacket, parsed, flow, action: 'drop', reason: flow.blockReason };
    }

    // Deep inspection: try to extract SNI/host
    this._inspectPayload(parsed, flow);

    // Apply rules
    const blockResult = this._applyRules(parsed, flow);
    if (blockResult) {
      flow.blocked = true;
      flow.blockReason = blockResult;
      this.stats.dropped++;
      this.stats.blockedFlows.push({
        flowKey: flow.key,
        srcIp: parsed.srcIp,
        dstIp: parsed.dstIp,
        dstPort: parsed.dstPort,
        sni: flow.sni,
        app: flow.app,
        reason: blockResult,
      });
      return { raw: rawPacket, parsed, flow, action: 'drop', reason: blockResult };
    }

    this.stats.forwarded++;
    flow.packetCount++;
    flow.byteCount += rawPacket.origLen || 0;
    return { raw: rawPacket, parsed, flow, action: 'forward', reason: null };
  }

  _getOrCreateFlow(parsed) {
    const key = parsed.flowKey;

    if (!this.flows.has(key)) {
      this.flows.set(key, {
        key,
        srcIp: parsed.srcIp,
        dstIp: parsed.dstIp,
        srcPort: parsed.srcPort,
        dstPort: parsed.dstPort,
        protocol: parsed.protocol,
        sni: null,
        app: 'Unknown',
        category: 'unknown',
        blocked: false,
        blockReason: null,
        firstSeen: parsed.timestamp,
        lastSeen: parsed.timestamp,
        packetCount: 0,
        byteCount: 0,
        tlsDetected: false,
        httpDetected: false,
        dnsQuery: null,
      });
    }

    const flow = this.flows.get(key);
    flow.lastSeen = parsed.timestamp;
    return flow;
  }

  _inspectPayload(parsed, flow) {
    const payload = parsed.payload;
    if (!payload || payload.length === 0) return;

    // TLS SNI extraction (HTTPS port 443)
    if (parsed.isTcp && !flow.sni) {
      const tlsResult = extractTLSSNI(payload);
      if (tlsResult) {
        flow.sni = tlsResult.sni;
        flow.tlsDetected = true;
        flow.alpn = tlsResult.alpn;
        this._classifyFlow(flow);
      }
    }

    // HTTP Host extraction (port 80)
    if (parsed.isTcp && !flow.sni) {
      const host = extractHTTPHost(payload);
      if (host) {
        flow.sni = host;
        flow.httpDetected = true;
        this._classifyFlow(flow);
      }
    }

    // DNS query extraction
    if (parsed.isUdp && parsed.isDns && !flow.dnsQuery) {
      const query = extractDNSQuery(payload);
      if (query) {
        flow.dnsQuery = query;
        flow.sni = query;
        this._classifyFlow(flow);
      }
    }
  }

  _classifyFlow(flow) {
    if (!flow.sni) return;

    const result = classifyHost(flow.sni);
    flow.app = result.app;
    flow.category = result.category;

    // Track SNI stats
    if (!this.stats.snisFound.find(s => s.sni === flow.sni)) {
      this.stats.snisFound.push({ sni: flow.sni, app: flow.app });
    }

    // Update app counts
    this.stats.appCounts[flow.app] = (this.stats.appCounts[flow.app] || 0) + 1;
  }

  _applyRules(parsed, flow) {
    // Rule 1: Blocked source IP
    if (this.rules.blockedIPs.has(parsed.srcIp)) {
      return `Blocked IP: ${parsed.srcIp}`;
    }

    // Rule 2: Blocked app (only once we know the app)
    if (flow.app && flow.app !== 'Unknown') {
      if (this.rules.blockedApps.has(flow.app.toLowerCase())) {
        return `Blocked app: ${flow.app}`;
      }
    }

    // Rule 3: Blocked domain pattern
    if (flow.sni) {
      for (const domain of this.rules.blockedDomains) {
        if (flow.sni.toLowerCase().includes(domain)) {
          return `Blocked domain: ${domain}`;
        }
      }
    }

    return null;
  }

  getReport() {
    const appList = Object.entries(this.stats.appCounts)
      .sort((a, b) => b[1] - a[1])
      .map(([app, count]) => ({
        app,
        count,
        percent: ((count / this.stats.total) * 100).toFixed(1),
        blocked: this.rules.blockedApps.has(app.toLowerCase()),
      }));

    return {
      summary: {
        total: this.stats.total,
        forwarded: this.stats.forwarded,
        dropped: this.stats.dropped,
        tcp: this.stats.tcp,
        udp: this.stats.udp,
        totalBytes: this.stats.totalBytes,
        flows: this.flows.size,
      },
      appBreakdown: appList,
      snisFound: this.stats.snisFound,
      blockedFlows: this.stats.blockedFlows,
      flows: Array.from(this.flows.values()).map(f => ({
        srcIp: f.srcIp,
        dstIp: f.dstIp,
        srcPort: f.srcPort,
        dstPort: f.dstPort,
        sni: f.sni,
        app: f.app,
        category: f.category,
        blocked: f.blocked,
        blockReason: f.blockReason,
        packetCount: f.packetCount,
        byteCount: f.byteCount,
      })),
    };
  }
}

module.exports = DPIEngine;
