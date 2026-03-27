/**
 * SNI Extractor
 * Extracts Server Name Indication from:
 * 1. TLS Client Hello (HTTPS traffic)
 * 2. HTTP Host header (plain HTTP)
 * 3. DNS queries
 */

// TLS Constants
const TLS_CONTENT_HANDSHAKE = 0x16;
const TLS_HANDSHAKE_CLIENT_HELLO = 0x01;
const TLS_EXT_SNI = 0x0000;
const TLS_EXT_ALPN = 0x0010;

/**
 * Extract SNI from TLS Client Hello
 * Returns: { sni: string, alpn: string[] } or null
 */
function extractTLSSNI(payload) {
  if (!payload || payload.length < 6) return null;

  // Check TLS record header
  if (payload[0] !== TLS_CONTENT_HANDSHAKE) return null;

  // TLS version check (0x0301 = TLS 1.0, 0x0303 = TLS 1.3)
  const tlsVersion = payload.readUInt16BE(1);
  if (tlsVersion < 0x0300 || tlsVersion > 0x0304) return null;

  const recordLen = payload.readUInt16BE(3);
  if (payload.length < 5 + recordLen) return null;

  // Handshake layer
  if (payload[5] !== TLS_HANDSHAKE_CLIENT_HELLO) return null;

  // Client Hello body starts at byte 9
  // Bytes 5: handshake type
  // Bytes 6-8: handshake length (3 bytes)
  // Bytes 9-10: client version
  // Bytes 11-42: random (32 bytes)
  let offset = 43;

  if (offset >= payload.length) return null;

  // Skip Session ID
  const sessionIdLen = payload[offset];
  offset += 1 + sessionIdLen;
  if (offset + 2 > payload.length) return null;

  // Skip Cipher Suites
  const cipherSuitesLen = payload.readUInt16BE(offset);
  offset += 2 + cipherSuitesLen;
  if (offset + 1 > payload.length) return null;

  // Skip Compression Methods
  const compressionLen = payload[offset];
  offset += 1 + compressionLen;
  if (offset + 2 > payload.length) return null;

  // Extensions
  const extensionsLen = payload.readUInt16BE(offset);
  offset += 2;

  const extEnd = offset + extensionsLen;
  if (extEnd > payload.length) return null;

  let sni = null;
  const alpn = [];

  while (offset + 4 <= extEnd) {
    const extType = payload.readUInt16BE(offset);
    const extLen = payload.readUInt16BE(offset + 2);
    offset += 4;

    if (extType === TLS_EXT_SNI) {
      // SNI List
      if (offset + 2 <= extEnd) {
        const sniListLen = payload.readUInt16BE(offset);
        let sniOffset = offset + 2;
        const sniEnd = offset + 2 + sniListLen;

        while (sniOffset + 3 <= sniEnd) {
          const nameType = payload[sniOffset]; // 0x00 = hostname
          const nameLen = payload.readUInt16BE(sniOffset + 1);
          sniOffset += 3;
          if (nameType === 0x00 && sniOffset + nameLen <= sniEnd) {
            sni = payload.slice(sniOffset, sniOffset + nameLen).toString('ascii');
          }
          sniOffset += nameLen;
        }
      }
    } else if (extType === TLS_EXT_ALPN) {
      // ALPN (Application Layer Protocol Negotiation)
      if (offset + 2 <= extEnd) {
        const alpnListLen = payload.readUInt16BE(offset);
        let alpnOffset = offset + 2;
        const alpnEnd = offset + 2 + alpnListLen;
        while (alpnOffset + 1 <= alpnEnd) {
          const protoLen = payload[alpnOffset];
          alpnOffset += 1;
          if (alpnOffset + protoLen <= alpnEnd) {
            alpn.push(payload.slice(alpnOffset, alpnOffset + protoLen).toString('ascii'));
          }
          alpnOffset += protoLen;
        }
      }
    }

    offset += extLen;
  }

  if (!sni) return null;
  return { sni, alpn };
}

/**
 * Extract Host from HTTP request
 * Returns: string or null
 */
function extractHTTPHost(payload) {
  if (!payload || payload.length < 4) return null;

  const text = payload.toString('ascii', 0, Math.min(payload.length, 2048));

  // Must be an HTTP request
  if (!/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|CONNECT|PATCH) /i.test(text)) return null;

  const hostMatch = text.match(/\r\nHost:\s*([^\r\n]+)/i);
  if (hostMatch) {
    return hostMatch[1].trim().toLowerCase().replace(/:\d+$/, ''); // remove port
  }

  return null;
}

/**
 * Parse DNS query to extract queried domain
 * Returns: string or null
 */
function extractDNSQuery(payload) {
  if (!payload || payload.length < 12) return null;

  // DNS header: 12 bytes
  const flags = payload.readUInt16BE(2);
  const isQuery = (flags & 0x8000) === 0;
  if (!isQuery) return null;

  const qdCount = payload.readUInt16BE(4);
  if (qdCount === 0) return null;

  // Parse first question
  let offset = 12;
  const labels = [];

  while (offset < payload.length) {
    const len = payload[offset];
    if (len === 0) break;
    if ((len & 0xc0) === 0xc0) break; // pointer, skip
    offset++;
    if (offset + len > payload.length) return null;
    labels.push(payload.slice(offset, offset + len).toString('ascii'));
    offset += len;
  }

  if (labels.length === 0) return null;
  return labels.join('.').toLowerCase();
}

module.exports = { extractTLSSNI, extractHTTPHost, extractDNSQuery };
