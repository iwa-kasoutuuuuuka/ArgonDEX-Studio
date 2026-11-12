/**
 * ArgonDEX Studio - Binary ZIP / APK Archive, Deflate, Signing Block & X.509 Engine
 * Zero-dependency pure JavaScript binary parser and builder for Android APK files.
 */

(function (global) {
  'use strict';

  // ==================== CRC32 & HASH UTILITIES ====================
  const CRC32_TABLE = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    }
    CRC32_TABLE[i] = c >>> 0;
  }

  function crc32(bytes) {
    let crc = 0xFFFFFFFF;
    for (let i = 0; i < bytes.length; i++) {
      crc = CRC32_TABLE[(crc ^ bytes[i]) & 0xFF] ^ (crc >>> 8);
    }
    return (crc ^ 0xFFFFFFFF) >>> 0;
  }

  function adler32(bytes, start = 0, end = bytes.length) {
    const MOD_ADLER = 65521;
    let a = 1, b = 0;
    for (let i = start; i < end; i++) {
      a = (a + bytes[i]) % MOD_ADLER;
      b = (b + a) % MOD_ADLER;
    }
    return ((b << 16) | a) >>> 0;
  }

  async function sha256Hex(bytes) {
    if (global.crypto && global.crypto.subtle) {
      try {
        const hashBuffer = await global.crypto.subtle.digest('SHA-256', bytes);
        return Array.from(new Uint8Array(hashBuffer))
          .map(b => b.toString(16).padStart(2, '0'))
          .join('');
      } catch (e) {
        // Fallback to pure JS SHA-256 if subtle crypto is unavailable (e.g. file:// origin)
      }
    }
    return pureJsSha256Hex(bytes);
  }

  function pureJsSha256Hex(asciiBytes) {
    const K = new Uint32Array([
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]);
    const H = new Uint32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]);
    const l = asciiBytes.length;
    const bitLenHi = Math.floor((l * 8) / 0x100000000);
    const bitLenLo = (l * 8) >>> 0;
    const padLen = ((l + 9 + 63) & ~63);
    const buf = new Uint8Array(padLen);
    buf.set(asciiBytes);
    buf[l] = 0x80;
    const dv = new DataView(buf.buffer);
    dv.setUint32(padLen - 8, bitLenHi, false);
    dv.setUint32(padLen - 4, bitLenLo, false);

    const W = new Uint32Array(64);
    const rotr = (x, n) => (x >>> n) | (x << (32 - n));

    for (let offset = 0; offset < padLen; offset += 64) {
      for (let i = 0; i < 16; i++) {
        W[i] = dv.getUint32(offset + i * 4, false);
      }
      for (let i = 16; i < 64; i++) {
        const s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >>> 3);
        const s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >>> 10);
        W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
      }
      let [a, b, c, d, e, f, g, h] = H;
      for (let i = 0; i < 64; i++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ ((~e) & g);
        const temp1 = (h + S1 + ch + K[i] + W[i]) >>> 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e;
        e = (d + temp1) >>> 0;
        d = c; c = b; b = a;
        a = (temp1 + temp2) >>> 0;
      }
      H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0;
      H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
      H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0;
      H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
    }
    return Array.from(H).map(v => v.toString(16).padStart(8, '0')).join('');
  }

  function computeShannonEntropy(bytes) {
    if (!bytes || bytes.length === 0) return 0;
    const freq = new Uint32Array(256);
    const len = bytes.length;
    for (let i = 0; i < len; i++) {
      freq[bytes[i]]++;
    }
    let entropy = 0;
    for (let i = 0; i < 256; i++) {
      if (freq[i] > 0) {
        const p = freq[i] / len;
        entropy -= p * Math.log2(p);
      }
    }
    return Math.round(entropy * 1000) / 1000;
  }

  // ==================== PURE JS INFLATE (RFC 1951 FALLBACK) ====================
  function inflateRawSync(src, expectedSize) {
    let pos = 0;
    let bitBuf = 0;
    let bitCnt = 0;

    function bits(n) {
      while (bitCnt < n) {
        if (pos >= src.length) throw new Error('Unexpected EOF in deflate stream');
        bitBuf |= src[pos++] << bitCnt;
        bitCnt += 8;
      }
      const val = bitBuf & ((1 << n) - 1);
      bitBuf >>>= n;
      bitCnt -= n;
      return val;
    }

    function buildHuffman(lengths) {
      const maxBits = 15;
      const count = new Int32Array(maxBits + 1);
      for (let i = 0; i < lengths.length; i++) {
        if (lengths[i] > 0) count[lengths[i]]++;
      }
      const nextCode = new Int32Array(maxBits + 1);
      let code = 0;
      for (let b = 1; b <= maxBits; b++) {
        code = (code + count[b - 1]) << 1;
        nextCode[b] = code;
      }
      const map = new Map();
      for (let sym = 0; sym < lengths.length; sym++) {
        const len = lengths[sym];
        if (len > 0) {
          const c = nextCode[len]++;
          map.set((len << 16) | c, sym);
        }
      }
      return { map, maxBits };
    }

    function decodeSymbol(tree) {
      let code = 0;
      for (let len = 1; len <= tree.maxBits; len++) {
        code = (code << 1) | bits(1);
        const key = (len << 16) | code;
        if (tree.map.has(key)) return tree.map.get(key);
      }
      throw new Error('Invalid Huffman code in deflate stream');
    }

    const FIXED_LIT = new Uint8Array(288);
    for (let i = 0; i <= 143; i++) FIXED_LIT[i] = 8;
    for (let i = 144; i <= 255; i++) FIXED_LIT[i] = 9;
    for (let i = 256; i <= 279; i++) FIXED_LIT[i] = 7;
    for (let i = 280; i <= 287; i++) FIXED_LIT[i] = 8;
    const FIXED_DIST = new Uint8Array(32).fill(5);

    const fixedLitTree = buildHuffman(FIXED_LIT);
    const fixedDistTree = buildHuffman(FIXED_DIST);

    const LEN_BASE = [
      3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
      35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258
    ];
    const LEN_EXTRA = [
      0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
      3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0
    ];
    const DIST_BASE = [
      1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
      257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577
    ];
    const DIST_EXTRA = [
      0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
      7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13
    ];
    const CL_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

    const MAX_INFLATE_BYTES = 256 * 1024 * 1024; // 256 MB Zip-Bomb guard
    if (expectedSize && expectedSize > MAX_INFLATE_BYTES) {
      throw new Error(`Decompression aborted: declared size (${expectedSize} B) exceeds safety limit`);
    }
    let out = new Uint8Array(Math.min(expectedSize || Math.max(src.length * 3, 4096), 64 * 1024 * 1024));
    let outPos = 0;

    function ensureCapacity(extra) {
      if (outPos + extra > MAX_INFLATE_BYTES) {
        throw new Error('Decompression aborted: Zip-Bomb limit exceeded (256 MB)');
      }
      if (outPos + extra <= out.length) return;
      let newLen = out.length * 2;
      while (newLen < outPos + extra) newLen *= 2;
      const next = new Uint8Array(Math.min(newLen, MAX_INFLATE_BYTES));
      next.set(out.subarray(0, outPos));
      out = next;
    }

    let bfinal = 0;
    while (!bfinal) {
      bfinal = bits(1);
      const btype = bits(2);
      if (btype === 0) {
        bitBuf = 0;
        bitCnt = 0;
        if (pos + 4 > src.length) throw new Error('EOF in stored block');
        const len = src[pos] | (src[pos + 1] << 8);
        pos += 4;
        ensureCapacity(len);
        out.set(src.subarray(pos, pos + len), outPos);
        outPos += len;
        pos += len;
      } else if (btype === 1 || btype === 2) {
        let litTree = fixedLitTree;
        let distTree = fixedDistTree;
        if (btype === 2) {
          const hlit = bits(5) + 257;
          const hdist = bits(5) + 1;
          const hclen = bits(4) + 4;
          const clLengths = new Uint8Array(19);
          for (let i = 0; i < hclen; i++) {
            clLengths[CL_ORDER[i]] = bits(3);
          }
          const clTree = buildHuffman(clLengths);
          const allLengths = new Uint8Array(hlit + hdist);
          let idx = 0;
          while (idx < hlit + hdist) {
            const sym = decodeSymbol(clTree);
            if (sym < 16) {
              allLengths[idx++] = sym;
            } else if (sym === 16) {
              const rep = bits(2) + 3;
              const prev = allLengths[idx - 1];
              for (let r = 0; r < rep; r++) allLengths[idx++] = prev;
            } else if (sym === 17) {
              const rep = bits(3) + 3;
              for (let r = 0; r < rep; r++) allLengths[idx++] = 0;
            } else if (sym === 18) {
              const rep = bits(7) + 11;
              for (let r = 0; r < rep; r++) allLengths[idx++] = 0;
            }
          }
          litTree = buildHuffman(allLengths.subarray(0, hlit));
          distTree = buildHuffman(allLengths.subarray(hlit));
        }

        while (true) {
          const sym = decodeSymbol(litTree);
          if (sym === 256) break;
          if (sym < 256) {
            ensureCapacity(1);
            out[outPos++] = sym;
          } else {
            const lenIdx = sym - 257;
            const length = LEN_BASE[lenIdx] + (LEN_EXTRA[lenIdx] ? bits(LEN_EXTRA[lenIdx]) : 0);
            const distSym = decodeSymbol(distTree);
            const distance = DIST_BASE[distSym] + (DIST_EXTRA[distSym] ? bits(DIST_EXTRA[distSym]) : 0);
            ensureCapacity(length);
            for (let i = 0; i < length; i++) {
              out[outPos] = out[outPos - distance];
              outPos++;
            }
          }
        }
      } else {
        throw new Error('Invalid deflate block type 3');
      }
    }
    return out.subarray(0, outPos);
  }

  async function decompressDeflateRaw(compressedBytes, uncompressedSize) {
    if (typeof DecompressionStream !== 'undefined') {
      try {
        const ds = new DecompressionStream('deflate-raw');
        const writer = ds.writable.getWriter();
        writer.write(compressedBytes);
        writer.close();
        const response = new Response(ds.readable);
        const ab = await response.arrayBuffer();
        return new Uint8Array(ab);
      } catch (e) {
        // Fallback to pure JS inflate
      }
    }
    return inflateRawSync(compressedBytes, uncompressedSize);
  }

  // ==================== APK SIGNING BLOCK V2/V3 & X.509 PARSER ====================
  function parseApkSigningBlock(bytes, centralDirOffset) {
    // APK Signing Block ends right before Central Directory with 16-byte magic "APK Sig Block 42"
    if (centralDirOffset < 32) return null;
    const magicOffset = centralDirOffset - 16;
    const magic = new TextDecoder().decode(bytes.subarray(magicOffset, centralDirOffset));
    if (magic !== 'APK Sig Block 42') return null;

    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const sizeOfBlockLow = dv.getUint32(centralDirOffset - 24, true);
    const sizeOfBlockHigh = dv.getUint32(centralDirOffset - 20, true);
    if (sizeOfBlockHigh !== 0 || sizeOfBlockLow > centralDirOffset) return null;

    const blockStart = centralDirOffset - 8 - sizeOfBlockLow;
    if (blockStart < 0) return null;

    const pairsStart = blockStart + 8;
    const pairsEnd = centralDirOffset - 24;
    let pos = pairsStart;
    const schemes = [];

    const KNOWN_IDS = {
      0x7109871a: 'APK Signature Scheme v2',
      0xf05368c0: 'APK Signature Scheme v3',
      0x1b93ad61: 'APK Signature Scheme v3.1',
      0x42726577: 'Dependency MetadataBlock',
      0x504b4453: 'Source Stamp Block',
      0x2146444e: 'Android Gradle Frosting / Play Metadata'
    };

    while (pos + 12 <= pairsEnd) {
      const pairSizeLow = dv.getUint32(pos, true);
      const pairSizeHigh = dv.getUint32(pos + 4, true);
      if (pairSizeHigh !== 0 || pairSizeLow < 4 || pos + 8 + pairSizeLow > pairsEnd) break;
      const id = dv.getUint32(pos + 8, true);
      schemes.push({
        id: '0x' + id.toString(16).padStart(8, '0'),
        name: KNOWN_IDS[id] || `Custom Block (0x${id.toString(16)})`,
        size: pairSizeLow - 4,
        offset: pos + 12
      });
      pos += 8 + pairSizeLow;
    }

    return {
      present: true,
      blockStart,
      blockSize: sizeOfBlockLow + 8,
      schemes,
      v2Signed: schemes.some(s => s.id === '0x7109871a'),
      v3Signed: schemes.some(s => s.id === '0xf05368c0' || s.id === '0x1b93ad61')
    };
  }

  function parseX509CertificateSummary(bytes) {
    // Extracts readable DN attributes, OIDs, and validity strings from PKCS#7 / X.509 DER bytes
    const OID_MAP = {
      '2.5.4.3': 'CN',
      '2.5.4.6': 'C',
      '2.5.4.7': 'L',
      '2.5.4.8': 'ST',
      '2.5.4.10': 'O',
      '2.5.4.11': 'OU',
      '1.2.840.113549.1.1.1': 'RSA Encryption',
      '1.2.840.113549.1.1.5': 'SHA1withRSA',
      '1.2.840.113549.1.1.11': 'SHA256withRSA',
      '1.2.840.113549.1.1.12': 'SHA384withRSA',
      '1.2.840.113549.1.1.13': 'SHA512withRSA',
      '1.2.840.10045.2.1': 'EC Public Key',
      '1.2.840.10045.4.3.2': 'ECDSAwithSHA256',
      '1.2.840.10040.4.1': 'DSA'
    };

    const dnParts = [];
    const algorithms = new Set();
    const dates = [];
    const decoder = new TextDecoder('utf-8', { fatal: false });

    function decodeOid(oidBytes) {
      if (!oidBytes.length) return '';
      const parts = [Math.floor(oidBytes[0] / 40), oidBytes[0] % 40];
      let val = 0;
      for (let i = 1; i < oidBytes.length; i++) {
        val = (val << 7) | (oidBytes[i] & 0x7f);
        if ((oidBytes[i] & 0x80) === 0) {
          parts.push(val);
          val = 0;
        }
      }
      return parts.join('.');
    }

    // Lightweight TLV scanner for OID + String pairs and UTCTime / GeneralizedTime
    for (let i = 0; i < bytes.length - 4; i++) {
      if (bytes[i] === 0x06) { // OBJECT IDENTIFIER
        const len = bytes[i + 1];
        if (len > 0 && len < 20 && i + 2 + len < bytes.length) {
          const oid = decodeOid(bytes.subarray(i + 2, i + 2 + len));
          if (OID_MAP[oid]) {
            const label = OID_MAP[oid];
            if (label.length <= 2) {
              // Check next ASN.1 string (UTF8String 0x0C, PrintableString 0x13, IA5String 0x16, BMPString 0x1E)
              const nextPos = i + 2 + len;
              const strTag = bytes[nextPos];
              const strLen = bytes[nextPos + 1];
              if ([0x0c, 0x13, 0x14, 0x16].includes(strTag) && strLen > 0 && strLen < 128 && nextPos + 2 + strLen <= bytes.length) {
                const strVal = decoder.decode(bytes.subarray(nextPos + 2, nextPos + 2 + strLen));
                dnParts.push(`${label}=${strVal}`);
              }
            } else {
              algorithms.add(label);
            }
          }
        }
      } else if (bytes[i] === 0x17 && bytes[i + 1] === 13 && i + 15 <= bytes.length) {
        // UTCTime YYMMDDHHMMSSZ
        const raw = decoder.decode(bytes.subarray(i + 2, i + 15));
        if (/^\d{12}Z$/.test(raw)) {
          const yy = parseInt(raw.slice(0, 2), 10);
          const year = yy >= 50 ? 1900 + yy : 2000 + yy;
          dates.push(`${year}-${raw.slice(2, 4)}-${raw.slice(4, 6)} ${raw.slice(6, 8)}:${raw.slice(8, 10)}:${raw.slice(10, 12)} UTC`);
        }
      }
    }

    return {
      subjectOrIssuer: dnParts.length ? dnParts.join(', ') : 'CN=Android Debug, O=Android, C=US',
      algorithms: Array.from(algorithms),
      validFrom: dates[0] || 'N/A',
      validUntil: dates[1] || 'N/A',
      size: bytes.length
    };
  }

  // ==================== APK ARCHIVE PARSER ====================
  function categorizeEntry(filename) {
    if (filename === 'AndroidManifest.xml') return 'manifest';
    if (/^classes\d*\.dex$/.test(filename)) return 'dex';
    if (filename === 'resources.arsc') return 'arsc';
    if (filename.startsWith('lib/') && filename.endsWith('.so')) return 'native';
    if (filename.startsWith('res/')) return 'res';
    if (filename.startsWith('assets/')) return 'assets';
    if (filename.startsWith('META-INF/')) return 'Signature/META-INF';
    if (filename.startsWith('kotlin/')) return 'kotlin';
    return 'other';
  }

  async function parseApkArchive(arrayBuffer, fileName = 'application.apk') {
    const bytes = new Uint8Array(arrayBuffer);
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const sha256 = await sha256Hex(bytes);

    // Locate End of Central Directory (EOCD: 0x06054b50)
    let eocdOffset = -1;
    const minEocdSearch = Math.max(0, bytes.length - 65557);
    for (let i = bytes.length - 22; i >= minEocdSearch; i--) {
      if (dv.getUint32(i, true) === 0x06054b50) {
        eocdOffset = i;
        break;
      }
    }

    if (eocdOffset === -1) {
      throw new Error('Invalid APK/ZIP archive: End of Central Directory (EOCD) signature not found.');
    }

    const totalEntries = dv.getUint16(eocdOffset + 10, true);
    const cdSize = dv.getUint32(eocdOffset + 12, true);
    const cdOffset = dv.getUint32(eocdOffset + 16, true);

    const signingBlock = parseApkSigningBlock(bytes, cdOffset);

    const entries = [];
    const entryMap = new Map();
    const decoder = new TextDecoder('utf-8');
    let ptr = cdOffset;

    const categoryBreakdown = {
      dex: { count: 0, compressed: 0, uncompressed: 0 },
      native: { count: 0, compressed: 0, uncompressed: 0 },
      res: { count: 0, compressed: 0, uncompressed: 0 },
      arsc: { count: 0, compressed: 0, uncompressed: 0 },
      assets: { count: 0, compressed: 0, uncompressed: 0 },
      manifest: { count: 0, compressed: 0, uncompressed: 0 },
      'Signature/META-INF': { count: 0, compressed: 0, uncompressed: 0 },
      kotlin: { count: 0, compressed: 0, uncompressed: 0 },
      other: { count: 0, compressed: 0, uncompressed: 0 }
    };

    for (let i = 0; i < totalEntries && ptr + 46 <= bytes.length; i++) {
      const sig = dv.getUint32(ptr, true);
      if (sig !== 0x02014b50) break;

      const flags = dv.getUint16(ptr + 8, true);
      const compressionMethod = dv.getUint16(ptr + 10, true);
      const dosTime = dv.getUint16(ptr + 12, true);
      const dosDate = dv.getUint16(ptr + 14, true);
      const crc = dv.getUint32(ptr + 16, true);
      const compressedSize = dv.getUint32(ptr + 20, true);
      const uncompressedSize = dv.getUint32(ptr + 24, true);
      const nameLen = dv.getUint16(ptr + 28, true);
      const extraLen = dv.getUint16(ptr + 30, true);
      const commentLen = dv.getUint16(ptr + 32, true);
      const localHeaderOffset = dv.getUint32(ptr + 42, true);

      const name = decoder.decode(bytes.subarray(ptr + 46, ptr + 46 + nameLen));
      ptr += 46 + nameLen + extraLen + commentLen;

      if (name.endsWith('/')) continue; // Skip directory entries

      const category = categorizeEntry(name);
      if (categoryBreakdown[category]) {
        categoryBreakdown[category].count++;
        categoryBreakdown[category].compressed += compressedSize;
        categoryBreakdown[category].uncompressed += uncompressedSize;
      }

      const entry = {
        name,
        category,
        flags,
        compressionMethod,
        compressionName: compressionMethod === 0 ? 'STORE' : (compressionMethod === 8 ? 'DEFLATE' : `METHOD_${compressionMethod}`),
        crc32: '0x' + crc.toString(16).padStart(8, '0'),
        compressedSize,
        uncompressedSize,
        localHeaderOffset,
        _cachedData: null,
        async extract() {
          if (this._cachedData) return this._cachedData;
          if (localHeaderOffset + 30 > bytes.length) {
            throw new Error(`Invalid local header offset for ${name}`);
          }
          const lSig = dv.getUint32(localHeaderOffset, true);
          if (lSig !== 0x04034b50) {
            throw new Error(`Corrupt local file header for ${name}`);
          }
          const lNameLen = dv.getUint16(localHeaderOffset + 26, true);
          const lExtraLen = dv.getUint16(localHeaderOffset + 28, true);
          const dataStart = localHeaderOffset + 30 + lNameLen + lExtraLen;
          const rawSlice = bytes.subarray(dataStart, dataStart + compressedSize);

          if (compressionMethod === 0) {
            this._cachedData = rawSlice;
          } else if (compressionMethod === 8) {
            this._cachedData = await decompressDeflateRaw(rawSlice, uncompressedSize);
          } else {
            throw new Error(`Unsupported compression method ${compressionMethod} for ${name}`);
          }
          return this._cachedData;
        }
      };

      entries.push(entry);
      entryMap.set(name, entry);
    }

    // Extract certificate metadata if present
    const certificates = [];
    for (const entry of entries) {
      if (/^META-INF\/.*\.(RSA|DSA|EC)$/i.test(entry.name)) {
        try {
          const certBytes = await entry.extract();
          const certHash = await sha256Hex(certBytes);
          const certSummary = parseX509CertificateSummary(certBytes);
          certificates.push({
            file: entry.name,
            sha256: certHash,
            ...certSummary
          });
        } catch (e) {
          // Ignore malformed cert
        }
      }
    }

    return {
      fileName,
      fileSize: bytes.length,
      sha256,
      entropy: computeShannonEntropy(bytes),
      totalEntries: entries.length,
      cdOffset,
      cdSize,
      signingBlock: signingBlock || { present: false, schemes: [], v2Signed: false, v3Signed: false },
      certificates,
      categoryBreakdown,
      entries,
      entryMap,
      rawBytes: bytes
    };
  }

  // ==================== ZIP ARCHIVE BUILDER (FOR EXPORT & SAMPLE APK) ====================
  function buildZipArchive(files, signingBlockPayload = null) {
    // files: Array of { name: string, data: Uint8Array }
    // Uses STORE (method 0) for fast, deterministic archive creation, with optional APK Signing Block v2
    const encoder = new TextEncoder();
    const localHeaders = [];
    const centralHeaders = [];
    let offset = 0;

    for (const f of files) {
      const nameBytes = encoder.encode(f.name);
      const data = f.data instanceof Uint8Array ? f.data : new Uint8Array(f.data);
      const crc = crc32(data);

      // 4-byte alignment extra field for uncompressed resources.arsc / .so (zipalign)
      let extraLen = 0;
      const headerBaseLen = 30 + nameBytes.length;
      if (f.name === 'resources.arsc' || f.name.endsWith('.so')) {
        const rem = (offset + headerBaseLen) % 4;
        if (rem !== 0) extraLen = 4 - rem;
      }

      const localHeader = new Uint8Array(30 + nameBytes.length + extraLen + data.length);
      const ldv = new DataView(localHeader.buffer);
      ldv.setUint32(0, 0x04034b50, true); // Local file header signature
      ldv.setUint16(4, 20, true);         // Version needed
      ldv.setUint16(6, 0x0800, true);     // UTF-8 flag
      ldv.setUint16(8, 0, true);          // Method 0 (STORE)
      ldv.setUint16(10, 0x5421, true);    // Mod time
      ldv.setUint16(12, 0x576C, true);    // Mod date
      ldv.setUint32(14, crc, true);
      ldv.setUint32(18, data.length, true);
      ldv.setUint32(22, data.length, true);
      ldv.setUint16(26, nameBytes.length, true);
      ldv.setUint16(28, extraLen, true);
      localHeader.set(nameBytes, 30);
      localHeader.set(data, 30 + nameBytes.length + extraLen);

      const centralHeader = new Uint8Array(46 + nameBytes.length);
      const cdv = new DataView(centralHeader.buffer);
      cdv.setUint32(0, 0x02014b50, true); // Central directory signature
      cdv.setUint16(4, 20, true);         // Version made by
      cdv.setUint16(6, 20, true);         // Version needed
      cdv.setUint16(8, 0x0800, true);     // UTF-8 flag
      cdv.setUint16(10, 0, true);         // Method 0 (STORE)
      cdv.setUint16(12, 0x5421, true);
      cdv.setUint16(14, 0x576C, true);
      cdv.setUint32(16, crc, true);
      cdv.setUint32(20, data.length, true);
      cdv.setUint32(24, data.length, true);
      cdv.setUint16(28, nameBytes.length, true);
      cdv.setUint16(30, 0, true);
      cdv.setUint16(32, 0, true);
      cdv.setUint16(34, 0, true);
      cdv.setUint16(36, 0, true);
      cdv.setUint32(38, 0, true);
      cdv.setUint32(42, offset, true);
      centralHeader.set(nameBytes, 46);

      localHeaders.push(localHeader);
      centralHeaders.push(centralHeader);
      offset += localHeader.length;
    }

    let sigBlockBytes = new Uint8Array(0);
    if (signingBlockPayload) {
      sigBlockBytes = signingBlockPayload;
      offset += sigBlockBytes.length;
    }

    const cdOffset = offset;
    let cdSize = 0;
    for (const c of centralHeaders) cdSize += c.length;

    const eocd = new Uint8Array(22);
    const edv = new DataView(eocd.buffer);
    edv.setUint32(0, 0x06054b50, true);
    edv.setUint16(4, 0, true);
    edv.setUint16(6, 0, true);
    edv.setUint16(8, files.length, true);
    edv.setUint16(10, files.length, true);
    edv.setUint32(12, cdSize, true);
    edv.setUint32(16, cdOffset, true);
    edv.setUint16(20, 0, true);

    const totalLen = offset + cdSize + 22;
    const out = new Uint8Array(totalLen);
    let pos = 0;
    for (const l of localHeaders) {
      out.set(l, pos);
      pos += l.length;
    }
    if (sigBlockBytes.length) {
      out.set(sigBlockBytes, pos);
      pos += sigBlockBytes.length;
    }
    for (const c of centralHeaders) {
      out.set(c, pos);
      pos += c.length;
    }
    out.set(eocd, pos);
    return out;
  }

  global.ArgonZip = {
    crc32,
    adler32,
    sha256Hex,
    pureJsSha256Hex,
    computeShannonEntropy,
    parseApkArchive,
    buildZipArchive
  };
})(typeof window !== 'undefined' ? window : globalThis);
