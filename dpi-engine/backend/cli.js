#!/usr/bin/env node
/**
 * DPI Engine CLI
 * Usage: node cli.js <input.pcap> [output.pcap] [options]
 *
 * Options:
 *   --block-app YouTube      Block all YouTube traffic
 *   --block-ip 192.168.1.50  Block all traffic from this IP
 *   --block-domain tiktok    Block any SNI containing "tiktok"
 *   --demo                   Run with built-in test traffic
 */

const fs = require('fs');
const path = require('path');
const PcapReader = require('./src/pcapReader');
const PcapWriter = require('./src/pcapWriter');
const DPIEngine = require('./src/dpiEngine');
const { generateTestPcap } = require('./src/testPcapGenerator');

// Parse args
const args = process.argv.slice(2);
const flags = { blockedApps: [], blockedIPs: [], blockedDomains: [] };
let inputFile = null;
let outputFile = null;
let demo = false;

for (let i = 0; i < args.length; i++) {
  switch (args[i]) {
    case '--block-app':    flags.blockedApps.push(args[++i]); break;
    case '--block-ip':     flags.blockedIPs.push(args[++i]); break;
    case '--block-domain': flags.blockedDomains.push(args[++i]); break;
    case '--demo':         demo = true; break;
    default:
      if (!inputFile && !args[i].startsWith('--')) inputFile = args[i];
      else if (!outputFile && !args[i].startsWith('--')) outputFile = args[i];
  }
}

// Default output
if (!outputFile) outputFile = 'output.pcap';

// ─── Banner ───
console.log(`
╔══════════════════════════════════════════════════════════════╗
║          DPI ENGINE (Node.js)  -  Deep Packet Inspection     ║
╚══════════════════════════════════════════════════════════════╝`);

if (flags.blockedApps.length)    console.log(`[Rules] Blocked apps: ${flags.blockedApps.join(', ')}`);
if (flags.blockedIPs.length)     console.log(`[Rules] Blocked IPs: ${flags.blockedIPs.join(', ')}`);
if (flags.blockedDomains.length) console.log(`[Rules] Blocked domains: ${flags.blockedDomains.join(', ')}`);

// ─── Load PCAP ───
let pcapBuffer;
if (demo || !inputFile) {
  console.log('\n[Reader] Using generated demo traffic...');
  pcapBuffer = generateTestPcap();
} else {
  if (!fs.existsSync(inputFile)) {
    console.error(`[ERROR] File not found: ${inputFile}`);
    process.exit(1);
  }
  pcapBuffer = fs.readFileSync(inputFile);
  console.log(`\n[Reader] Loading ${inputFile} (${(pcapBuffer.length / 1024).toFixed(1)} KB)...`);
}

// ─── Process ───
const reader = new PcapReader();
reader.openBuffer(pcapBuffer);

const engine = new DPIEngine(flags);
const writer = new PcapWriter();

let count = 0;
for (const rawPacket of reader.packets()) {
  const result = engine.processPacket(rawPacket);
  if (result.action === 'forward') writer.writePacket(rawPacket);
  count++;
  if (count % 1000 === 0) process.stdout.write(`\r[Reader] Processed ${count} packets...`);
}

console.log(`\r[Reader] Done reading ${count} packets`);

// ─── Write output ───
fs.writeFileSync(outputFile, writer.toBuffer());
console.log(`[Output] Filtered PCAP written to: ${outputFile}`);

// ─── Report ───
const report = engine.getReport();
const { summary, appBreakdown, snisFound, blockedFlows } = report;

const bar = (n, total) => {
  const pct = total > 0 ? Math.round((n / total) * 20) : 0;
  return '█'.repeat(pct).padEnd(20);
};

console.log(`
╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                        ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:  ${String(summary.total).padStart(10)}                              ║
║ Total Bytes:    ${String(summary.totalBytes).padStart(10)} bytes                        ║
║ TCP Packets:    ${String(summary.tcp).padStart(10)}                              ║
║ UDP Packets:    ${String(summary.udp).padStart(10)}                              ║
║ Flows Tracked:  ${String(summary.flows).padStart(10)}                              ║
╠══════════════════════════════════════════════════════════════╣
║ Forwarded:      ${String(summary.forwarded).padStart(10)}                              ║
║ Dropped:        ${String(summary.dropped).padStart(10)}                              ║
╠══════════════════════════════════════════════════════════════╣
║                   APPLICATION BREAKDOWN                       ║
╠══════════════════════════════════════════════════════════════╣`);

for (const { app, count: c, percent, blocked } of appBreakdown.slice(0, 10)) {
  const label = (app + (blocked ? ' (BLOCKED)' : '')).padEnd(20);
  const cnt = String(c).padStart(5);
  const pct = `${percent}%`.padStart(6);
  const b = bar(c, summary.total);
  console.log(`║ ${label} ${cnt} ${pct} ${b} ║`);
}

console.log(`╠══════════════════════════════════════════════════════════════╣
║                    DETECTED SNIs / DOMAINS                    ║
╠══════════════════════════════════════════════════════════════╣`);

for (const { sni, app } of snisFound) {
  const s = sni.padEnd(35);
  const a = app.padEnd(20);
  console.log(`║  ${s} → ${a} ║`);
}

if (blockedFlows.length > 0) {
  console.log(`╠══════════════════════════════════════════════════════════════╣
║                        BLOCKED FLOWS                          ║
╠══════════════════════════════════════════════════════════════╣`);
  for (const f of blockedFlows) {
    const line = `${f.srcIp} → ${f.sni || f.dstIp} (${f.reason})`;
    console.log(`║  ${line.padEnd(60)} ║`);
  }
}

console.log(`╚══════════════════════════════════════════════════════════════╝\n`);
