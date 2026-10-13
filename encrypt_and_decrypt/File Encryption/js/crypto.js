/**
 * Sealbox file format: password-based file encryption with the Web Crypto API.
 *
 *   Key derivation:  PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte random salt
 *   Encryption:      AES-256-GCM, 12-byte random IV, 16-byte authentication tag
 *
 * File layout (all integers big-endian):
 *
 *   offset  size  field
 *   0       4     magic "SBOX"
 *   4       1     format version (1)
 *   5       4     PBKDF2 iterations
 *   9       16    salt
 *   25      12    IV
 *   37      n     ciphertext of [metadata length (4) | metadata JSON | file bytes]
 *   end-16  16    GCM authentication tag (appended by Web Crypto)
 *
 * The 37-byte header is passed to AES-GCM as "additional authenticated data",
 * so changing any header byte (for example lowering the iteration count) makes
 * decryption fail. The original file name and type are inside the ciphertext,
 * so they stay private too.
 *
 * No DOM access: runs in the browser (global `Sealbox`) and in Node 19+.
 */
const Sealbox = (() => {
  'use strict';

  const subtle = globalThis.crypto.subtle;
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  // ---------------------------------------------------------------------------
  // Format constants
  // ---------------------------------------------------------------------------

  const MAGIC = Uint8Array.from([0x53, 0x42, 0x4f, 0x58]); // "SBOX"
  const VERSION = 1;
  const SALT_BYTES = 16;
  const IV_BYTES = 12;
  const TAG_BYTES = 16;
  const META_LENGTH_BYTES = 4;

  const OFFSET = { magic: 0, version: 4, iterations: 5, salt: 9, iv: 25, ciphertext: 37 };
  const HEADER_BYTES = OFFSET.ciphertext;

  /** OWASP's 2023 recommendation for PBKDF2-HMAC-SHA256. */
  const DEFAULT_ITERATIONS = 600_000;
  // Files outside this range are rejected before any work is done:
  // too few rounds is unsafe, too many could freeze the browser.
  const MIN_ITERATIONS = 100_000;
  const MAX_ITERATIONS = 10_000_000;

  const MAX_FILE_BYTES = 512 * 1024 * 1024; // whole file is held in memory
  const FILE_EXTENSION = '.sbox';

  class SealboxError extends Error {
    /** @param {'empty_password'|'too_large'|'not_sealbox'|'unsupported_version'|'bad_iterations'|'wrong_password_or_tampered'|'corrupt'} code */
    constructor(code, message) {
      super(message);
      this.name = 'SealboxError';
      this.code = code;
    }
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  function randomBytes(length) {
    return globalThis.crypto.getRandomValues(new Uint8Array(length));
  }

  function concatBytes(...parts) {
    const out = new Uint8Array(parts.reduce((sum, p) => sum + p.length, 0));
    let offset = 0;
    for (const part of parts) {
      out.set(part, offset);
      offset += part.length;
    }
    return out;
  }

  function toHex(bytes) {
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  }

  async function sha256Hex(bytes) {
    return toHex(new Uint8Array(await subtle.digest('SHA-256', bytes)));
  }

  /** Keeps only a plain file name: no folders, control characters or empty names. */
  function safeFileName(name) {
    const base = String(name || '').split(/[\\/]/).pop().replace(/[\u0000-\u001f\u007f]/g, '').trim();
    return base && base !== '.' && base !== '..' ? base : 'decrypted-file';
  }

  // ---------------------------------------------------------------------------
  // Header
  // ---------------------------------------------------------------------------

  /** True when the bytes start with the Sealbox signature and are long enough. */
  function isSealboxFile(bytes) {
    return bytes.length >= HEADER_BYTES + TAG_BYTES && MAGIC.every((b, i) => bytes[i] === b);
  }

  function writeHeader({ iterations, salt, iv }) {
    const header = new Uint8Array(HEADER_BYTES);
    header.set(MAGIC, OFFSET.magic);
    header[OFFSET.version] = VERSION;
    new DataView(header.buffer).setUint32(OFFSET.iterations, iterations);
    header.set(salt, OFFSET.salt);
    header.set(iv, OFFSET.iv);
    return header;
  }

  /** Reads and validates the header. Throws SealboxError if the file is not usable. */
  function readHeader(bytes) {
    if (!isSealboxFile(bytes)) {
      throw new SealboxError('not_sealbox', 'This is not a Sealbox-encrypted file.');
    }
    const version = bytes[OFFSET.version];
    if (version !== VERSION) {
      throw new SealboxError('unsupported_version', `Format version ${version} is not supported.`);
    }
    const iterations = new DataView(bytes.buffer, bytes.byteOffset).getUint32(OFFSET.iterations);
    if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
      throw new SealboxError('bad_iterations', `The file asks for ${iterations.toLocaleString('en')} key-derivation rounds, which is outside the safe range.`);
    }
    return {
      version,
      iterations,
      salt: bytes.slice(OFFSET.salt, OFFSET.salt + SALT_BYTES),
      iv: bytes.slice(OFFSET.iv, OFFSET.iv + IV_BYTES),
      header: bytes.slice(0, HEADER_BYTES),
    };
  }

  // ---------------------------------------------------------------------------
  // Key derivation
  // ---------------------------------------------------------------------------

  /**
   * Stretches the password into a 256-bit AES key. The many rounds make every
   * password guess expensive for an attacker. The key cannot be exported.
   */
  async function deriveKey(password, salt, iterations) {
    // NFC normalisation: "é" typed as one or two code points gives the same key.
    const passwordKey = await subtle.importKey('raw', encoder.encode(password.normalize('NFC')), 'PBKDF2', false, ['deriveKey']);
    return subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
      passwordKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
  }

  // ---------------------------------------------------------------------------
  // Plaintext packing: metadata travels encrypted together with the file
  // ---------------------------------------------------------------------------

  function packPlaintext(fileBytes, meta) {
    const metaBytes = encoder.encode(JSON.stringify(meta));
    const length = new Uint8Array(META_LENGTH_BYTES);
    new DataView(length.buffer).setUint32(0, metaBytes.length);
    return concatBytes(length, metaBytes, fileBytes);
  }

  function unpackPlaintext(plain) {
    const metaLength = new DataView(plain.buffer, plain.byteOffset).getUint32(0);
    const metaEnd = META_LENGTH_BYTES + metaLength;
    if (metaEnd > plain.length) throw new SealboxError('corrupt', 'The decrypted data is malformed.');

    let meta;
    try {
      meta = JSON.parse(decoder.decode(plain.subarray(META_LENGTH_BYTES, metaEnd)));
    } catch {
      throw new SealboxError('corrupt', 'The file information inside is unreadable.');
    }
    return {
      bytes: plain.slice(metaEnd),
      name: safeFileName(meta.name),
      type: typeof meta.type === 'string' ? meta.type : '',
      encryptedAt: typeof meta.encryptedAt === 'string' ? meta.encryptedAt : null,
    };
  }

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  /**
   * Encrypts a file.
   * @param {Uint8Array} fileBytes
   * @param {string} password
   * @param {{name?: string, type?: string, iterations?: number}} [options]
   * @returns {Promise<{bytes: Uint8Array, fileName: string, iterations: number, salt: Uint8Array, iv: Uint8Array}>}
   */
  async function encrypt(fileBytes, password, { name = 'file', type = '', iterations = DEFAULT_ITERATIONS } = {}) {
    if (!password) throw new SealboxError('empty_password', 'Enter a password.');
    if (fileBytes.length > MAX_FILE_BYTES) {
      throw new SealboxError('too_large', 'Files over 512 MB are not supported, because the whole file is processed in memory.');
    }

    const salt = randomBytes(SALT_BYTES);
    const iv = randomBytes(IV_BYTES);   // never reused: new for every encryption
    const header = writeHeader({ iterations, salt, iv });
    const key = await deriveKey(password, salt, iterations);

    const plain = packPlaintext(fileBytes, { name: safeFileName(name), type, encryptedAt: new Date().toISOString() });
    const ciphertext = new Uint8Array(await subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: header, tagLength: TAG_BYTES * 8 },
      key,
      plain,
    ));

    return {
      bytes: concatBytes(header, ciphertext),
      fileName: safeFileName(name) + FILE_EXTENSION,
      iterations,
      salt,
      iv,
    };
  }

  /**
   * Decrypts a Sealbox file and verifies it has not been changed.
   * @param {Uint8Array} encrypted
   * @param {string} password
   * @returns {Promise<{bytes: Uint8Array, name: string, type: string, encryptedAt: string|null, iterations: number, salt: Uint8Array, iv: Uint8Array}>}
   */
  async function decrypt(encrypted, password) {
    if (!password) throw new SealboxError('empty_password', 'Enter the password.');
    const { iterations, salt, iv, header } = readHeader(encrypted);
    const key = await deriveKey(password, salt, iterations);

    let plain;
    try {
      plain = new Uint8Array(await subtle.decrypt(
        { name: 'AES-GCM', iv, additionalData: header, tagLength: TAG_BYTES * 8 },
        key,
        encrypted.subarray(HEADER_BYTES),
      ));
    } catch {
      // GCM cannot tell a wrong password from a modified file: both fail the tag check.
      throw new SealboxError('wrong_password_or_tampered', 'Wrong password, or the file has been changed since it was encrypted.');
    }
    return { ...unpackPlaintext(plain), iterations, salt, iv };
  }

  return {
    encrypt,
    decrypt,
    isSealboxFile,
    readHeader,
    sha256Hex,
    toHex,
    safeFileName,
    SealboxError,
    FORMAT: Object.freeze({ HEADER_BYTES, TAG_BYTES, SALT_BYTES, IV_BYTES, OFFSET, DEFAULT_ITERATIONS, MAX_FILE_BYTES, FILE_EXTENSION }),
  };
})();

if (typeof module !== 'undefined') module.exports = Sealbox;
