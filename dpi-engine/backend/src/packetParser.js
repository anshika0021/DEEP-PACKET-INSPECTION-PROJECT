/**
 * Packet Parser
 * Parses: Ethernet → IP → TCP/UDP → Payload
 */

const ETHERTYPE_IPV4 = 0x0800;
const ETHERTYPE_IPV6 = 0x86dd;
const PROTO_TCP = 6;
const PROTO_UDP = 17;
const PROTO_ICMP = 1;

function macToString(buf, offset) {
  return Array.from({ length: 6 }, (_, i) =>
    buf[offset + i].toString(16).padStart(2, '0')
  ).join(':');
}

function ipToString(buf, offset) {
  return `${buf[offset]}.${buf[offset + 1]}.${buf[offset + 2]}.${buf[offset + 3]}`;
}

function ipToInt(buf, offset) {
  return ((buf[offset] << 24) | (buf[offset + 1] << 16) | (buf[offset + 2] << 8) | buf[offset + 3]) >>> 0;
}

function parsePacket(rawPacket) {
  const { data, timestamp, inclLen, origLen } = rawPacket;

  const result = {
    timestamp,
    origLen,
    // Ethernet
    srcMac: null,
    dstMac: null,
    etherType: null,
    // IP
    srcIp: null,
    dstIp: null,
    srcIpInt: 0,
    dstIpInt: 0,
    protocol: null,
    ttl: 0,
    ipHeaderLen: 0,
    // TCP/UDP
    srcPort: null,
    dstPort: null,
    tcpFlags: 0,
    tcpSeq: 0,
    tcpAck: 0,
    // Payload
    payload: null,
    payloadOffset: 0,
    // Meta
    isTcp: false,
    isUdp: false,
    isDns: false,
    isHttps: false,
    isHttp: false,
    // Five-tuple key
    flowKey: null,
  };

  let offset = 0;

  // --- Ethernet Header (14 bytes) ---
  if (data.length < 14) return null;
  result.dstMac = macToString(data, 0);
  result.srcMac = macToString(data, 6);
  result.etherType = data.readUInt16BE(12);
  offset = 14;

  // Handle 802.1Q VLAN tag (4 extra bytes)
  if (result.etherType === 0x8100) {
    offset += 4;
    result.etherType = data.readUInt16BE(offset - 2);
  }

  if (result.etherType !== ETHERTYPE_IPV4) return null; // Only IPv4 for now

  // --- IP Header (20+ bytes) ---
  if (data.length < offset + 20) return null;

  const ipVersionIHL = data[offset];
  const ipVersion = (ipVersionIHL >> 4) & 0xf;
  if (ipVersion !== 4) return null;

  const ihl = (ipVersionIHL & 0xf) * 4;
  result.ipHeaderLen = ihl;
  result.ttl = data[offset + 8];
  result.protocol = data[offset + 9];
  result.srcIp = ipToString(data, offset + 12);
  result.dstIp = ipToString(data, offset + 16);
  result.srcIpInt = ipToInt(data, offset + 12);
  result.dstIpInt = ipToInt(data, offset + 16);

  offset += ihl;

  // --- TCP Header ---
  if (result.protocol === PROTO_TCP) {
    if (data.length < offset + 20) return null;
    result.isTcp = true;
    result.srcPort = data.readUInt16BE(offset);
    result.dstPort = data.readUInt16BE(offset + 2);
    result.tcpSeq = data.readUInt32BE(offset + 4);
    result.tcpAck = data.readUInt32BE(offset + 8);
    const dataOffset = ((data[offset + 12] >> 4) & 0xf) * 4;
    result.tcpFlags = data[offset + 13];
    offset += dataOffset;
  }
  // --- UDP Header ---
  else if (result.protocol === PROTO_UDP) {
    if (data.length < offset + 8) return null;
    result.isUdp = true;
    result.srcPort = data.readUInt16BE(offset);
    result.dstPort = data.readUInt16BE(offset + 2);
    offset += 8;
  }
  else {
    return result; // ICMP or other
  }

  result.payload = data.slice(offset);
  result.payloadOffset = offset;

  // Flags
  result.isHttps = result.dstPort === 443 || result.srcPort === 443;
  result.isHttp = result.dstPort === 80 || result.srcPort === 80;
  result.isDns = result.dstPort === 53 || result.srcPort === 53;

  // Build canonical flow key (always smaller IP/port first for bidirectional tracking)
  const [a, b] = sortFlowTuple(
    result.srcIpInt, result.srcPort,
    result.dstIpInt, result.dstPort
  );
  result.flowKey = `${a[0]}:${a[1]}-${b[0]}:${b[1]}-${result.protocol}`;

  return result;
}

function sortFlowTuple(srcIp, srcPort, dstIp, dstPort) {
  if (srcIp < dstIp || (srcIp === dstIp && srcPort < dstPort)) {
    return [[srcIp, srcPort], [dstIp, dstPort]];
  }
  return [[dstIp, dstPort], [srcIp, srcPort]];
}

module.exports = { parsePacket };
