/**
 * Test PCAP Generator
 * Creates synthetic PCAP files containing:
 * - HTTPS traffic with TLS Client Hello (SNI: youtube.com, facebook.com, github.com)
 * - HTTP traffic with Host headers
 * - DNS queries
 * - Generic TCP traffic
 */

const PcapWriter = require('./pcapWriter');

const PCAP_MAGIC = 0xa1b2c3d4;

function ipToBytes(ip) {
  return ip.split('.').map(Number);
}

function buildEthernetHeader(srcMac, dstMac, etherType) {
  const buf = Buffer.alloc(14);
  dstMac.forEach((b, i) => buf[i] = b);
  srcMac.forEach((b, i) => buf[6 + i] = b);
  buf.writeUInt16BE(etherType, 12);
  return buf;
}

function buildIPHeader(srcIp, dstIp, protocol, payloadLen) {
  const buf = Buffer.alloc(20);
  buf[0] = 0x45; // Version 4, IHL 5
  buf[1] = 0x00; // DSCP
  buf.writeUInt16BE(20 + payloadLen, 2); // Total length
  buf.writeUInt16BE(0x1234, 4); // ID
  buf.writeUInt16BE(0x4000, 6); // Flags (DF)
  buf[8] = 64; // TTL
  buf[9] = protocol;
  // Checksum = 0 (skip for test)
  buf.writeUInt16BE(0, 10);
  ipToBytes(srcIp).forEach((b, i) => buf[12 + i] = b);
  ipToBytes(dstIp).forEach((b, i) => buf[16 + i] = b);
  return buf;
}

function buildTCPHeader(srcPort, dstPort, seq, ack, flags) {
  const buf = Buffer.alloc(20);
  buf.writeUInt16BE(srcPort, 0);
  buf.writeUInt16BE(dstPort, 2);
  buf.writeUInt32BE(seq, 4);
  buf.writeUInt32BE(ack, 8);
  buf[12] = 0x50; // Data offset = 5 (20 bytes)
  buf[13] = flags;
  buf.writeUInt16BE(65535, 14); // Window
  return buf;
}

function buildUDPHeader(srcPort, dstPort, payloadLen) {
  const buf = Buffer.alloc(8);
  buf.writeUInt16BE(srcPort, 0);
  buf.writeUInt16BE(dstPort, 2);
  buf.writeUInt16BE(8 + payloadLen, 4);
  return buf;
}

function buildTLSClientHello(sni) {
  // Build SNI extension
  const sniBytes = Buffer.from(sni, 'ascii');
  const sniExt = Buffer.alloc(9 + sniBytes.length);
  sniExt.writeUInt16BE(0x0000, 0); // Type: SNI
  sniExt.writeUInt16BE(5 + sniBytes.length, 2); // Ext length
  sniExt.writeUInt16BE(3 + sniBytes.length, 4); // SNI list length
  sniExt[6] = 0x00; // Name type: hostname
  sniExt.writeUInt16BE(sniBytes.length, 7); // Name length
  sniBytes.copy(sniExt, 9);

  // Build extensions block
  const extsLen = sniExt.length;
  const extsBuf = Buffer.alloc(2 + extsLen);
  extsBuf.writeUInt16BE(extsLen, 0);
  sniExt.copy(extsBuf, 2);

  // Client Hello body
  const random = Buffer.alloc(32, 0xab); // fake random
  const sessionId = Buffer.alloc(0);
  const cipherSuites = Buffer.from([0x00, 0x04, 0x00, 0x2f, 0x00, 0x35]); // 2 len + 2 suites
  const compression = Buffer.from([0x01, 0x00]); // 1 method: null

  const helloBody = Buffer.concat([
    Buffer.from([0x03, 0x03]), // Version TLS 1.2
    random,
    Buffer.from([sessionId.length]),
    sessionId,
    cipherSuites,
    compression,
    extsBuf,
  ]);

  // Handshake header
  const handshakeHeader = Buffer.alloc(4);
  handshakeHeader[0] = 0x01; // Client Hello
  handshakeHeader[1] = 0;
  handshakeHeader.writeUInt16BE(helloBody.length, 2);

  // TLS record
  const recordLen = handshakeHeader.length + helloBody.length;
  const tlsRecord = Buffer.alloc(5);
  tlsRecord[0] = 0x16; // Handshake
  tlsRecord.writeUInt16BE(0x0303, 1); // TLS 1.2
  tlsRecord.writeUInt16BE(recordLen, 3);

  return Buffer.concat([tlsRecord, handshakeHeader, helloBody]);
}

function buildHTTPRequest(host, path = '/') {
  return Buffer.from(
    `GET ${path} HTTP/1.1\r\nHost: ${host}\r\nConnection: keep-alive\r\n\r\n`,
    'ascii'
  );
}

function buildDNSQuery(domain) {
  const buf = Buffer.alloc(12);
  buf.writeUInt16BE(0x1234, 0); // Transaction ID
  buf.writeUInt16BE(0x0100, 2); // Standard query
  buf.writeUInt16BE(1, 4); // QDCOUNT = 1
  buf.writeUInt16BE(0, 6);
  buf.writeUInt16BE(0, 8);
  buf.writeUInt16BE(0, 10);

  const labels = domain.split('.');
  const qname = Buffer.concat([
    ...labels.map(l => {
      const lb = Buffer.from(l, 'ascii');
      const len = Buffer.alloc(1);
      len[0] = lb.length;
      return Buffer.concat([len, lb]);
    }),
    Buffer.from([0x00]),
  ]);
  const qtype = Buffer.from([0x00, 0x01, 0x00, 0x01]); // A IN

  return Buffer.concat([buf, qname, qtype]);
}

function buildPacket(srcIp, dstIp, srcPort, dstPort, protocol, payload, timestamp) {
  const eth = buildEthernetHeader(
    [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
    [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
    0x0800
  );

  let transport;
  if (protocol === 6) {
    transport = buildTCPHeader(srcPort, dstPort, 1000, 0, 0x02); // SYN
  } else {
    transport = buildUDPHeader(srcPort, dstPort, payload.length);
  }

  const ip = buildIPHeader(srcIp, dstIp, protocol, transport.length + payload.length);
  const data = Buffer.concat([eth, ip, transport, payload]);

  return {
    timestamp,
    inclLen: data.length,
    origLen: data.length,
    data,
  };
}

/**
 * Generate a test PCAP buffer with various traffic types
 */
function generateTestPcap() {
  const writer = new PcapWriter();
  let t = 1700000000.0;

  const testCases = [
    // TLS/HTTPS traffic with SNI
    { src: '192.168.1.100', dst: '142.250.185.206', sp: 54321, dp: 443, proto: 6, payload: buildTLSClientHello('www.youtube.com') },
    { src: '192.168.1.100', dst: '157.240.214.35',  sp: 54322, dp: 443, proto: 6, payload: buildTLSClientHello('www.facebook.com') },
    { src: '192.168.1.101', dst: '140.82.121.4',    sp: 54323, dp: 443, proto: 6, payload: buildTLSClientHello('github.com') },
    { src: '192.168.1.102', dst: '34.107.221.82',   sp: 54324, dp: 443, proto: 6, payload: buildTLSClientHello('www.netflix.com') },
    { src: '192.168.1.103', dst: '104.244.42.193',  sp: 54325, dp: 443, proto: 6, payload: buildTLSClientHello('twitter.com') },
    { src: '192.168.1.104', dst: '172.64.155.209',  sp: 54326, dp: 443, proto: 6, payload: buildTLSClientHello('discord.com') },
    { src: '192.168.1.105', dst: '128.199.248.105', sp: 54327, dp: 443, proto: 6, payload: buildTLSClientHello('www.tiktok.com') },
    { src: '192.168.1.106', dst: '52.94.236.248',   sp: 54328, dp: 443, proto: 6, payload: buildTLSClientHello('api.spotify.com') },
    // HTTP traffic
    { src: '192.168.1.107', dst: '93.184.216.34',   sp: 54329, dp: 80,  proto: 6, payload: buildHTTPRequest('example.com') },
    { src: '192.168.1.108', dst: '104.16.149.103',  sp: 54330, dp: 80,  proto: 6, payload: buildHTTPRequest('www.reddit.com') },
    // DNS queries
    { src: '192.168.1.100', dst: '8.8.8.8',          sp: 12345, dp: 53,  proto: 17, payload: buildDNSQuery('www.google.com') },
    { src: '192.168.1.101', dst: '8.8.8.8',          sp: 12346, dp: 53,  proto: 17, payload: buildDNSQuery('api.github.com') },
    { src: '192.168.1.102', dst: '1.1.1.1',          sp: 12347, dp: 53,  proto: 17, payload: buildDNSQuery('s.youtube.com') },
    // More HTTPS flows
    { src: '192.168.1.50',  dst: '142.250.185.206', sp: 55000, dp: 443, proto: 6, payload: buildTLSClientHello('www.youtube.com') },
    { src: '192.168.1.50',  dst: '157.240.214.35',  sp: 55001, dp: 443, proto: 6, payload: buildTLSClientHello('www.instagram.com') },
    { src: '192.168.1.109', dst: '104.26.10.229',   sp: 54331, dp: 443, proto: 6, payload: buildTLSClientHello('slack.com') },
    { src: '192.168.1.110', dst: '170.114.52.2',    sp: 54332, dp: 443, proto: 6, payload: buildTLSClientHello('zoom.us') },
    { src: '192.168.1.111', dst: '13.107.42.14',    sp: 54333, dp: 443, proto: 6, payload: buildTLSClientHello('teams.microsoft.com') },
    { src: '192.168.1.112', dst: '216.58.210.174',  sp: 54334, dp: 443, proto: 6, payload: buildTLSClientHello('drive.google.com') },
    { src: '192.168.1.113', dst: '54.230.47.15',    sp: 54335, dp: 443, proto: 6, payload: buildTLSClientHello('s3.amazonaws.com') },
  ];

  for (const tc of testCases) {
    t += 0.05;
    const pkt = buildPacket(tc.src, tc.dst, tc.sp, tc.dp, tc.proto, tc.payload, t);
    writer.writePacket(pkt);
  }

  return writer.toBuffer();
}

module.exports = { generateTestPcap };
