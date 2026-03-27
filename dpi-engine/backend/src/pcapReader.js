/**
 * PCAP Reader - Reads Wireshark capture files
 * PCAP Global Header: 24 bytes
 * Packet Header: 16 bytes per packet
 */

const fs = require('fs');

const PCAP_MAGIC = 0xa1b2c3d4;
const PCAP_MAGIC_SWAPPED = 0xd4c3b2a1;

class PcapReader {
  constructor() {
    this.buffer = null;
    this.offset = 0;
    this.swapped = false;
    this.linkType = 0;
  }

  open(filepath) {
    this.buffer = fs.readFileSync(filepath);
    this.offset = 0;
    this._readGlobalHeader();
  }

  openBuffer(buffer) {
    this.buffer = buffer;
    this.offset = 0;
    this._readGlobalHeader();
  }

  _readGlobalHeader() {
    const magic = this.buffer.readUInt32LE(0);
    if (magic === PCAP_MAGIC) {
      this.swapped = false;
    } else if (magic === PCAP_MAGIC_SWAPPED) {
      this.swapped = true;
    } else {
      throw new Error(`Invalid PCAP magic number: 0x${magic.toString(16)}`);
    }

    this.linkType = this._readU32(20);
    this.offset = 24; // Skip global header
  }

  _readU16(offset) {
    return this.swapped
      ? this.buffer.readUInt16BE(offset)
      : this.buffer.readUInt16LE(offset);
  }

  _readU32(offset) {
    return this.swapped
      ? this.buffer.readUInt32BE(offset)
      : this.buffer.readUInt32LE(offset);
  }

  readNextPacket() {
    if (this.offset + 16 > this.buffer.length) return null;

    const tsSec = this._readU32(this.offset);
    const tsUsec = this._readU32(this.offset + 4);
    const inclLen = this._readU32(this.offset + 8);
    const origLen = this._readU32(this.offset + 12);
    this.offset += 16;

    if (this.offset + inclLen > this.buffer.length) return null;

    const data = this.buffer.slice(this.offset, this.offset + inclLen);
    this.offset += inclLen;

    return {
      timestamp: tsSec + tsUsec / 1e6,
      inclLen,
      origLen,
      data,
    };
  }

  *packets() {
    let pkt;
    while ((pkt = this.readNextPacket()) !== null) {
      yield pkt;
    }
  }
}

module.exports = PcapReader;
