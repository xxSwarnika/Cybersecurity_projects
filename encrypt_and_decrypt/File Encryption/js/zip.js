/**
 * Minimal ZIP support, "stored" entries only (no compression).
 *
 * Why it exists: some hosts only let a page save certain file types
 * (.zip yes, .sbox no). Encrypted data does not compress anyway, so storing
 * it uncompressed costs nothing. Sealbox can open its own zips directly.
 *
 * Format reference: PKWARE APPNOTE.TXT, sections 4.3.7 (local header),
 * 4.3.12 (central directory) and 4.3.16 (end of central directory).
 */
const Zip = (() => {
  'use strict';

  const LOCAL_HEADER_SIG = 0x04034b50;
  const CENTRAL_DIR_SIG = 0x02014b50;
  const END_OF_DIR_SIG = 0x06054b50;
  const LOCAL_HEADER_BYTES = 30;
  const CENTRAL_DIR_BYTES = 46;
  const END_OF_DIR_BYTES = 22;
  const VERSION_NEEDED = 20;          // 2.0
  const FLAG_UTF8_NAME = 1 << 11;
  const FLAG_DATA_DESCRIPTOR = 1 << 3;
  const METHOD_STORED = 0;

  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  const CRC_TABLE = (() => {
    const table = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      table[n] = c >>> 0;
    }
    return table;
  })();

  function crc32(bytes) {
    let crc = 0xffffffff;
    for (let i = 0; i < bytes.length; i++) crc = CRC_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
    return (crc ^ 0xffffffff) >>> 0;
  }

  /** ZIP stores timestamps in the old MS-DOS format (2-second precision). */
  function dosDateTime(date) {
    const time = (date.getHours() << 11) | (date.getMinutes() << 5) | (date.getSeconds() >> 1);
    const day = ((date.getFullYear() - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate();
    return { time, day };
  }

  /**
   * @param {{name: string, bytes: Uint8Array}[]} files
   * @returns {Uint8Array}
   */
  function create(files, date = new Date()) {
    const { time, day } = dosDateTime(date);
    const locals = [];
    const centrals = [];
    let offset = 0;

    for (const file of files) {
      const name = encoder.encode(file.name);
      const crc = crc32(file.bytes);
      const size = file.bytes.length;

      const local = new Uint8Array(LOCAL_HEADER_BYTES + name.length);
      const lv = new DataView(local.buffer);
      lv.setUint32(0, LOCAL_HEADER_SIG, true);
      lv.setUint16(4, VERSION_NEEDED, true);
      lv.setUint16(6, FLAG_UTF8_NAME, true);
      lv.setUint16(8, METHOD_STORED, true);
      lv.setUint16(10, time, true);
      lv.setUint16(12, day, true);
      lv.setUint32(14, crc, true);
      lv.setUint32(18, size, true);       // compressed size
      lv.setUint32(22, size, true);       // uncompressed size
      lv.setUint16(26, name.length, true);
      lv.setUint16(28, 0, true);          // extra field length
      local.set(name, LOCAL_HEADER_BYTES);

      const central = new Uint8Array(CENTRAL_DIR_BYTES + name.length);
      const cv = new DataView(central.buffer);
      cv.setUint32(0, CENTRAL_DIR_SIG, true);
      cv.setUint16(4, VERSION_NEEDED, true);  // version made by
      cv.setUint16(6, VERSION_NEEDED, true);  // version needed
      cv.setUint16(8, FLAG_UTF8_NAME, true);
      cv.setUint16(10, METHOD_STORED, true);
      cv.setUint16(12, time, true);
      cv.setUint16(14, day, true);
      cv.setUint32(16, crc, true);
      cv.setUint32(20, size, true);
      cv.setUint32(24, size, true);
      cv.setUint16(28, name.length, true);
      // 30: extra length, 32: comment length, 34: disk, 36: internal attrs, 38: external attrs (all 0)
      cv.setUint32(42, offset, true);         // where the local header starts
      central.set(name, CENTRAL_DIR_BYTES);

      locals.push(local, file.bytes);
      centrals.push(central);
      offset += local.length + size;
    }

    const centralSize = centrals.reduce((sum, c) => sum + c.length, 0);
    const end = new Uint8Array(END_OF_DIR_BYTES);
    const ev = new DataView(end.buffer);
    ev.setUint32(0, END_OF_DIR_SIG, true);
    ev.setUint16(8, files.length, true);   // entries on this disk
    ev.setUint16(10, files.length, true);  // entries in total
    ev.setUint32(12, centralSize, true);
    ev.setUint32(16, offset, true);        // central directory offset

    const parts = [...locals, ...centrals, end];
    const out = new Uint8Array(parts.reduce((sum, p) => sum + p.length, 0));
    let at = 0;
    for (const part of parts) {
      out.set(part, at);
      at += part.length;
    }
    return out;
  }

  function isZip(bytes) {
    return bytes.length >= 4 && new DataView(bytes.buffer, bytes.byteOffset).getUint32(0, true) === LOCAL_HEADER_SIG;
  }

  /**
   * Reads the entries of a zip by walking its local headers.
   * Compressed entries are listed with `stored: false` and no bytes.
   * @returns {{name: string, stored: boolean, bytes: Uint8Array|null}[]}
   */
  function read(bytes) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const entries = [];
    let at = 0;

    while (at + LOCAL_HEADER_BYTES <= bytes.length && view.getUint32(at, true) === LOCAL_HEADER_SIG) {
      const flags = view.getUint16(at + 6, true);
      const method = view.getUint16(at + 8, true);
      const size = view.getUint32(at + 18, true);
      const nameLength = view.getUint16(at + 26, true);
      const extraLength = view.getUint16(at + 28, true);
      const nameStart = at + LOCAL_HEADER_BYTES;
      const dataStart = nameStart + nameLength + extraLength;
      const name = decoder.decode(bytes.subarray(nameStart, nameStart + nameLength));

      // Sizes written after the data (streamed zips) cannot be walked this way.
      if (flags & FLAG_DATA_DESCRIPTOR || dataStart + size > bytes.length) {
        entries.push({ name, stored: false, bytes: null });
        break;
      }
      const stored = method === METHOD_STORED;
      entries.push({ name, stored, bytes: stored ? bytes.slice(dataStart, dataStart + size) : null });
      at = dataStart + size;
    }
    return entries;
  }

  return { create, read, isZip, crc32 };
})();

if (typeof module !== 'undefined') module.exports = Zip;
