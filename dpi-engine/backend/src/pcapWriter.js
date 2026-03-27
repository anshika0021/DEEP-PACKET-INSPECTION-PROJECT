/**
 * PCAP Writer
 * Writes filtered packets to a new PCAP file
 */

const PCAP_MAGIC = 0xa1b2c3d4;
const PCAP_VERSION_MAJOR = 2;
const PCAP_VERSION_MINOR = 4;
const PCAP_SNAPLEN = 65535;
const PCAP_LINKTYPE_ETHERNET = 1;

class PcapWriter {
  constructor() {
    this.chunks = [];
    this._writeGlobalHeader();
  }

  _writeGlobalHeader() {
    const header = Buffer.alloc(24);
    header.writeUInt32LE(PCAP_MAGIC, 0);
    header.writeUInt16LE(PCAP_VERSION_MAJOR, 4);
    header.writeUInt16LE(PCAP_VERSION_MINOR, 6);
    header.writeInt32LE(0, 8);  // thiszone
    header.writeUInt32LE(0, 12); // sigfigs
    header.writeUInt32LE(PCAP_SNAPLEN, 16);
    header.writeUInt32LE(PCAP_LINKTYPE_ETHERNET, 20);
    this.chunks.push(header);
  }

  writePacket(rawPacket) {
    const { timestamp, inclLen, origLen, data } = rawPacket;
    const tsSec = Math.floor(timestamp);
    const tsUsec = Math.round((timestamp - tsSec) * 1e6);

    const pktHeader = Buffer.alloc(16);
    pktHeader.writeUInt32LE(tsSec, 0);
    pktHeader.writeUInt32LE(tsUsec, 4);
    pktHeader.writeUInt32LE(inclLen, 8);
    pktHeader.writeUInt32LE(origLen, 12);

    this.chunks.push(pktHeader);
    this.chunks.push(data);
  }

  toBuffer() {
    return Buffer.concat(this.chunks);
  }
}

module.exports = PcapWriter;
