/**
 * ArgonDEX Studio - Complete Dalvik Executable (DEX) Parser, Smali Disassembler,
 * Control Flow Graph (CFG) Builder, and Dalvik-to-Java Source Code Decompiler.
 */

(function (global) {
  'use strict';

  // ==================== LEB128 & MUTF-8 DECODERS ====================
  function readUleb128(bytes, offsetObj) {
    let result = 0;
    let shift = 0;
    let count = 0;
    while (offsetObj.pos < bytes.length && count < 5) {
      const b = bytes[offsetObj.pos++];
      result |= (b & 0x7f) << shift;
      count++;
      if ((b & 0x80) === 0) break;
      shift += 7;
    }
    return result >>> 0;
  }

  function readSleb128(bytes, offsetObj) {
    let result = 0;
    let shift = 0;
    let b = 0;
    let count = 0;
    while (offsetObj.pos < bytes.length && count < 5) {
      b = bytes[offsetObj.pos++];
      result |= (b & 0x7f) << shift;
      shift += 7;
      count++;
      if ((b & 0x80) === 0) break;
    }
    if (shift < 32 && (b & 0x40) !== 0) {
      result |= (~0 << shift);
    }
    return result;
  }

  function sanitizeClassPath(fullName) {
    // Prevents Zip-Slip / Path Traversal when mapping DEX class names to file paths
    return String(fullName || 'UnknownClass')
      .replace(/\\/g, '/')
      .split('.')
      .join('/')
      .split('/')
      .map(seg => seg.replace(/[^A-Za-z0-9_$]/g, '_'))
      .filter(seg => seg.length > 0 && seg !== '.' && seg !== '..')
      .join('/') || 'UnknownClass';
  }

  function decodeMutf8(bytes, startOffset) {
    const posObj = { pos: startOffset };
    const utf16Len = readUleb128(bytes, posObj);
    const chars = [];
    let pos = posObj.pos;
    while (pos < bytes.length && chars.length < utf16Len) {
      const a = bytes[pos++];
      if (a === 0) break;
      if ((a & 0x80) === 0) {
        chars.push(String.fromCharCode(a));
      } else if ((a & 0xe0) === 0xc0) {
        const b = bytes[pos++] & 0x3f;
        chars.push(String.fromCharCode(((a & 0x1f) << 6) | b));
      } else if ((a & 0xf0) === 0xe0) {
        const b = bytes[pos++] & 0x3f;
        const c = bytes[pos++] & 0x3f;
        chars.push(String.fromCharCode(((a & 0x0f) << 12) | (b << 6) | c));
      } else {
        chars.push('?');
      }
    }
    return chars.join('');
  }

  // ==================== JAVA TYPE & ACCESS FLAG FORMATTERS ====================
  const ACCESS_FLAGS = {
    ACC_PUBLIC:       0x0001,
    ACC_PRIVATE:      0x0002,
    ACC_PROTECTED:    0x0004,
    ACC_STATIC:       0x0008,
    ACC_FINAL:        0x0010,
    ACC_SYNCHRONIZED: 0x0020,
    ACC_VOLATILE:     0x0040,
    ACC_BRIDGE:       0x0040,
    ACC_TRANSIENT:    0x0080,
    ACC_VARARGS:      0x0080,
    ACC_NATIVE:       0x0100,
    ACC_INTERFACE:    0x0200,
    ACC_ABSTRACT:     0x0400,
    ACC_STRICT:       0x0800,
    ACC_SYNTHETIC:    0x1000,
    ACC_ANNOTATION:   0x2000,
    ACC_ENUM:         0x4000,
    ACC_CONSTRUCTOR:  0x10000,
    ACC_DECLARED_SYNCHRONIZED: 0x20000
  };

  function formatAccessFlags(flags, target = 'class') {
    const out = [];
    if (flags & ACCESS_FLAGS.ACC_PUBLIC) out.push('public');
    if (flags & ACCESS_FLAGS.ACC_PROTECTED) out.push('protected');
    if (flags & ACCESS_FLAGS.ACC_PRIVATE) out.push('private');
    if (flags & ACCESS_FLAGS.ACC_STATIC) out.push('static');
    if (target !== 'interface' && (flags & ACCESS_FLAGS.ACC_ABSTRACT) && !(flags & ACCESS_FLAGS.ACC_INTERFACE)) {
      out.push('abstract');
    }
    if (flags & ACCESS_FLAGS.ACC_FINAL) out.push('final');
    if (target === 'method') {
      if (flags & (ACCESS_FLAGS.ACC_SYNCHRONIZED | ACCESS_FLAGS.ACC_DECLARED_SYNCHRONIZED)) out.push('synchronized');
      if (flags & ACCESS_FLAGS.ACC_NATIVE) out.push('native');
    }
    if (target === 'field') {
      if (flags & ACCESS_FLAGS.ACC_VOLATILE) out.push('volatile');
      if (flags & ACCESS_FLAGS.ACC_TRANSIENT) out.push('transient');
    }
    return out;
  }

  function descriptorToJavaType(desc, importsSet = null) {
    if (!desc) return 'void';
    let arrayDim = 0;
    let i = 0;
    while (i < desc.length && desc[i] === '[') {
      arrayDim++;
      i++;
    }
    const core = desc.slice(i);
    let base;
    switch (core[0]) {
      case 'V': base = 'void'; break;
      case 'Z': base = 'boolean'; break;
      case 'B': base = 'byte'; break;
      case 'S': base = 'short'; break;
      case 'C': base = 'char'; break;
      case 'I': base = 'int'; break;
      case 'J': base = 'long'; break;
      case 'F': base = 'float'; break;
      case 'D': base = 'double'; break;
      case 'L': {
        const full = core.slice(1, core.endsWith(';') ? -1 : core.length).replace(/\//g, '.');
        if (importsSet && !full.startsWith('java.lang.')) {
          importsSet.add(full);
        }
        const lastDot = full.lastIndexOf('.');
        base = lastDot !== -1 ? full.slice(lastDot + 1) : full;
        break;
      }
      default:
        base = core;
    }
    return base + '[]'.repeat(arrayDim);
  }

  function descriptorToFullClassName(desc) {
    if (!desc) return '';
    if (desc.startsWith('L') && desc.endsWith(';')) {
      return desc.slice(1, -1).replace(/\//g, '.');
    }
    return desc.replace(/\//g, '.');
  }

  function escapeJavaString(str) {
    if (str == null) return 'null';
    return String(str)
      .replace(/\\/g, '\\\\')
      .replace(/"/g, '\\"')
      .replace(/\r/g, '\\r')
      .replace(/\n/g, '\\n')
      .replace(/\t/g, '\\t');
  }

  // ==================== DALVIK 256-OPCODE TABLE ====================
  // Format codes:
  // 10x, 12x, 11n, 11x, 10t, 20t, 22x, 21t, 21s, 21h, 21c, 23x, 22b, 22t, 22s, 22c, 30t, 32x, 31i, 31t, 31c, 35c, 3rc, 51l
  // Reference types (ref): 'none', 'string', 'type', 'field', 'method'
  const OPCODE_TABLE = new Array(256);
  function defOp(op, name, fmt, ref = 'none') {
    OPCODE_TABLE[op] = { op, name, fmt, ref };
  }

  defOp(0x00, 'nop', '10x');
  defOp(0x01, 'move', '12x');
  defOp(0x02, 'move/from16', '22x');
  defOp(0x03, 'move/16', '32x');
  defOp(0x04, 'move-wide', '12x');
  defOp(0x05, 'move-wide/from16', '22x');
  defOp(0x06, 'move-wide/16', '32x');
  defOp(0x07, 'move-object', '12x');
  defOp(0x08, 'move-object/from16', '22x');
  defOp(0x09, 'move-object/16', '32x');
  defOp(0x0a, 'move-result', '11x');
  defOp(0x0b, 'move-result-wide', '11x');
  defOp(0x0c, 'move-result-object', '11x');
  defOp(0x0d, 'move-exception', '11x');
  defOp(0x0e, 'return-void', '10x');
  defOp(0x0f, 'return', '11x');
  defOp(0x10, 'return-wide', '11x');
  defOp(0x11, 'return-object', '11x');
  defOp(0x12, 'const/4', '11n');
  defOp(0x13, 'const/16', '21s');
  defOp(0x14, 'const', '31i');
  defOp(0x15, 'const/high16', '21h');
  defOp(0x16, 'const-wide/16', '21s');
  defOp(0x17, 'const-wide/32', '31i');
  defOp(0x18, 'const-wide', '51l');
  defOp(0x19, 'const-wide/high16', '21h');
  defOp(0x1a, 'const-string', '21c', 'string');
  defOp(0x1b, 'const-string/jumbo', '31c', 'string');
  defOp(0x1c, 'const-class', '21c', 'type');
  defOp(0x1d, 'monitor-enter', '11x');
  defOp(0x1e, 'monitor-exit', '11x');
  defOp(0x1f, 'check-cast', '21c', 'type');
  defOp(0x20, 'instance-of', '22c', 'type');
  defOp(0x21, 'array-length', '12x');
  defOp(0x22, 'new-instance', '21c', 'type');
  defOp(0x23, 'new-array', '22c', 'type');
  defOp(0x24, 'filled-new-array', '35c', 'type');
  defOp(0x25, 'filled-new-array/range', '3rc', 'type');
  defOp(0x26, 'fill-array-data', '31t');
  defOp(0x27, 'throw', '11x');
  defOp(0x28, 'goto', '10t');
  defOp(0x29, 'goto/16', '20t');
  defOp(0x2a, 'goto/32', '30t');
  defOp(0x2b, 'packed-switch', '31t');
  defOp(0x2c, 'sparse-switch', '31t');
  defOp(0x2d, 'cmpl-float', '23x');
  defOp(0x2e, 'cmpg-float', '23x');
  defOp(0x2f, 'cmpl-double', '23x');
  defOp(0x30, 'cmpg-double', '23x');
  defOp(0x31, 'cmp-long', '23x');
  defOp(0x32, 'if-eq', '22t');
  defOp(0x33, 'if-ne', '22t');
  defOp(0x34, 'if-lt', '22t');
  defOp(0x35, 'if-ge', '22t');
  defOp(0x36, 'if-gt', '22t');
  defOp(0x37, 'if-le', '22t');
  defOp(0x38, 'if-eqz', '21t');
  defOp(0x39, 'if-nez', '21t');
  defOp(0x3a, 'if-ltz', '21t');
  defOp(0x3b, 'if-gez', '21t');
  defOp(0x3c, 'if-gtz', '21t');
  defOp(0x3d, 'if-lez', '21t');

  // Array ops 0x44..0x51
  const ARRAY_OPS = [
    'aget', 'aget-wide', 'aget-object', 'aget-boolean', 'aget-byte', 'aget-char', 'aget-short',
    'aput', 'aput-wide', 'aput-object', 'aput-boolean', 'aput-byte', 'aput-char', 'aput-short'
  ];
  ARRAY_OPS.forEach((name, idx) => defOp(0x44 + idx, name, '23x'));

  // Instance field ops 0x52..0x5f
  const IFIELD_OPS = [
    'iget', 'iget-wide', 'iget-object', 'iget-boolean', 'iget-byte', 'iget-char', 'iget-short',
    'iput', 'iput-wide', 'iput-object', 'iput-boolean', 'iput-byte', 'iput-char', 'iput-short'
  ];
  IFIELD_OPS.forEach((name, idx) => defOp(0x52 + idx, name, '22c', 'field'));

  // Static field ops 0x60..0x6d
  const SFIELD_OPS = [
    'sget', 'sget-wide', 'sget-object', 'sget-boolean', 'sget-byte', 'sget-char', 'sget-short',
    'sput', 'sput-wide', 'sput-object', 'sput-boolean', 'sput-byte', 'sput-char', 'sput-short'
  ];
  SFIELD_OPS.forEach((name, idx) => defOp(0x60 + idx, name, '21c', 'field'));

  // Invoke ops 0x6e..0x78
  defOp(0x6e, 'invoke-virtual', '35c', 'method');
  defOp(0x6f, 'invoke-super', '35c', 'method');
  defOp(0x70, 'invoke-direct', '35c', 'method');
  defOp(0x71, 'invoke-static', '35c', 'method');
  defOp(0x72, 'invoke-interface', '35c', 'method');
  defOp(0x74, 'invoke-virtual/range', '3rc', 'method');
  defOp(0x75, 'invoke-super/range', '3rc', 'method');
  defOp(0x76, 'invoke-direct/range', '3rc', 'method');
  defOp(0x77, 'invoke-static/range', '3rc', 'method');
  defOp(0x78, 'invoke-interface/range', '3rc', 'method');

  // Unary ops 0x7b..0x8f
  const UNARY_OPS = [
    'neg-int', 'not-int', 'neg-long', 'not-long', 'neg-float', 'neg-double',
    'int-to-long', 'int-to-float', 'int-to-double', 'long-to-int', 'long-to-float', 'long-to-double',
    'float-to-int', 'float-to-long', 'float-to-double', 'double-to-int', 'double-to-long', 'double-to-float',
    'int-to-byte', 'int-to-char', 'int-to-short'
  ];
  UNARY_OPS.forEach((name, idx) => defOp(0x7b + idx, name, '12x'));

  // Binary 23x ops 0x90..0xaf
  const BIN_OPS = [
    'add-int', 'sub-int', 'mul-int', 'div-int', 'rem-int', 'and-int', 'or-int', 'xor-int', 'shl-int', 'shr-int', 'ushr-int',
    'add-long', 'sub-long', 'mul-long', 'div-long', 'rem-long', 'and-long', 'or-long', 'xor-long', 'shl-long', 'shr-long', 'ushr-long',
    'add-float', 'sub-float', 'mul-float', 'div-float', 'rem-float',
    'add-double', 'sub-double', 'mul-double', 'div-double', 'rem-double'
  ];
  BIN_OPS.forEach((name, idx) => {
    defOp(0x90 + idx, name, '23x');
    defOp(0xb0 + idx, name + '/2addr', '12x');
  });

  // Binary lit16 0xd0..0xd7
  const LIT16_OPS = ['add-int/lit16', 'rsub-int', 'mul-int/lit16', 'div-int/lit16', 'rem-int/lit16', 'and-int/lit16', 'or-int/lit16', 'xor-int/lit16'];
  LIT16_OPS.forEach((name, idx) => defOp(0xd0 + idx, name, '22s'));

  // Binary lit8 0xd8..0xe2
  const LIT8_OPS = ['add-int/lit8', 'rsub-int/lit8', 'mul-int/lit8', 'div-int/lit8', 'rem-int/lit8', 'and-int/lit8', 'or-int/lit8', 'xor-int/lit8', 'shl-int/lit8', 'shr-int/lit8', 'ushr-int/lit8'];
  LIT8_OPS.forEach((name, idx) => defOp(0xd8 + idx, name, '22b'));

  // Fill any remaining opcodes with safe 10x fallback
  for (let i = 0; i < 256; i++) {
    if (!OPCODE_TABLE[i]) {
      defOp(i, `unused_${i.toString(16).padStart(2, '0')}`, '10x');
    }
  }

  // ==================== DEX BINARY PARSER ====================
  function parseDexFile(bytes, dexName = 'classes.dex', resourceTable = null) {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (bytes.length < 0x70) {
      throw new Error(`${dexName}: File too small to be a valid DEX (< 112 bytes)`);
    }

    const magicStr = new TextDecoder('ascii').decode(bytes.subarray(0, 8));
    if (!magicStr.startsWith('dex\n')) {
      throw new Error(`${dexName}: Invalid DEX magic header`);
    }
    const version = magicStr.slice(4, 7);
    const checksum = dv.getUint32(8, true);
    const signatureHex = Array.from(bytes.subarray(12, 32)).map(b => b.toString(16).padStart(2, '0')).join('');
    const fileSize = dv.getUint32(32, true);
    const headerSize = dv.getUint32(36, true);
    const endianTag = dv.getUint32(40, true);

    const stringIdsSize = dv.getUint32(56, true);
    const stringIdsOff  = dv.getUint32(60, true);
    const typeIdsSize   = dv.getUint32(64, true);
    const typeIdsOff    = dv.getUint32(68, true);
    const protoIdsSize  = dv.getUint32(72, true);
    const protoIdsOff   = dv.getUint32(76, true);
    const fieldIdsSize  = dv.getUint32(80, true);
    const fieldIdsOff   = dv.getUint32(84, true);
    const methodIdsSize = dv.getUint32(88, true);
    const methodIdsOff  = dv.getUint32(92, true);
    const classDefsSize = dv.getUint32(96, true);
    const classDefsOff  = dv.getUint32(100, true);

    // 1. Parse Strings
    const strings = new Array(stringIdsSize);
    for (let i = 0; i < stringIdsSize; i++) {
      const strDataOff = dv.getUint32(stringIdsOff + i * 4, true);
      strings[i] = (strDataOff > 0 && strDataOff < bytes.length) ? decodeMutf8(bytes, strDataOff) : '';
    }

    // 2. Parse Types
    const types = new Array(typeIdsSize);
    for (let i = 0; i < typeIdsSize; i++) {
      const descIdx = dv.getUint32(typeIdsOff + i * 4, true);
      types[i] = strings[descIdx] || '';
    }

    function readTypeList(offset) {
      if (offset === 0 || offset + 4 > bytes.length) return [];
      const size = dv.getUint32(offset, true);
      const list = [];
      for (let i = 0; i < size; i++) {
        const typeIdx = dv.getUint16(offset + 4 + i * 2, true);
        list.push(types[typeIdx] || 'Ljava/lang/Object;');
      }
      return list;
    }

    // 3. Parse Protos
    const protos = new Array(protoIdsSize);
    for (let i = 0; i < protoIdsSize; i++) {
      const base = protoIdsOff + i * 12;
      const shortyIdx = dv.getUint32(base, true);
      const returnTypeIdx = dv.getUint32(base + 4, true);
      const paramsOff = dv.getUint32(base + 8, true);
      protos[i] = {
        shorty: strings[shortyIdx] || '',
        returnType: types[returnTypeIdx] || 'V',
        parameters: readTypeList(paramsOff)
      };
    }

    // 4. Parse Fields
    const fields = new Array(fieldIdsSize);
    for (let i = 0; i < fieldIdsSize; i++) {
      const base = fieldIdsOff + i * 8;
      const classIdx = dv.getUint16(base, true);
      const typeIdx = dv.getUint16(base + 2, true);
      const nameIdx = dv.getUint32(base + 4, true);
      fields[i] = {
        id: i,
        classDescriptor: types[classIdx] || '',
        className: descriptorToFullClassName(types[classIdx] || ''),
        typeDescriptor: types[typeIdx] || '',
        name: strings[nameIdx] || `field_${i}`
      };
    }

    // 5. Parse Methods
    const methods = new Array(methodIdsSize);
    for (let i = 0; i < methodIdsSize; i++) {
      const base = methodIdsOff + i * 8;
      const classIdx = dv.getUint16(base, true);
      const protoIdx = dv.getUint16(base + 2, true);
      const nameIdx = dv.getUint32(base + 4, true);
      const proto = protos[protoIdx] || { returnType: 'V', parameters: [] };
      methods[i] = {
        id: i,
        classDescriptor: types[classIdx] || '',
        className: descriptorToFullClassName(types[classIdx] || ''),
        name: strings[nameIdx] || `method_${i}`,
        proto,
        signature: `${types[classIdx]}->${strings[nameIdx]}(${proto.parameters.join('')})${proto.returnType}`
      };
    }

    // Helper: Parse encoded_value (for static field initializers)
    function readEncodedValue(posObj) {
      if (posObj.pos >= bytes.length) return null;
      const argAndType = bytes[posObj.pos++];
      const valueType = argAndType & 0x1f;
      const valueArg = (argAndType >>> 5) & 0x07;
      const size = valueArg + 1;

      function readSignedInt(n) {
        let val = 0;
        for (let i = 0; i < n; i++) {
          val |= (bytes[posObj.pos++] << (i * 8));
        }
        const shift = (4 - n) * 8;
        return (val << shift) >> shift;
      }

      function readUnsignedInt(n) {
        let val = 0;
        for (let i = 0; i < n; i++) {
          val |= (bytes[posObj.pos++] << (i * 8));
        }
        return val >>> 0;
      }

      switch (valueType) {
        case 0x00: return String(readSignedInt(1)); // VALUE_BYTE
        case 0x02: return String(readSignedInt(size)); // VALUE_SHORT
        case 0x03: return `'${String.fromCharCode(readUnsignedInt(size))}'`; // VALUE_CHAR
        case 0x04: return String(readSignedInt(size)); // VALUE_INT
        case 0x06: { // VALUE_LONG
          let lo = 0, hi = 0;
          for (let i = 0; i < size; i++) {
            const b = bytes[posObj.pos++];
            if (i < 4) lo |= (b << (i * 8));
            else hi |= (b << ((i - 4) * 8));
          }
          return `${lo >>> 0}L`;
        }
        case 0x10: { // VALUE_FLOAT
          const buf = new Uint8Array(4);
          for (let i = 0; i < size; i++) buf[4 - size + i] = bytes[posObj.pos++];
          return `${Math.round(new DataView(buf.buffer).getFloat32(0, true) * 1000) / 1000}f`;
        }
        case 0x11: { // VALUE_DOUBLE
          const buf = new Uint8Array(8);
          for (let i = 0; i < size; i++) buf[8 - size + i] = bytes[posObj.pos++];
          return String(new DataView(buf.buffer).getFloat64(0, true));
        }
        case 0x17: { // VALUE_STRING
          const idx = readUnsignedInt(size);
          return `"${escapeJavaString(strings[idx] || '')}"`;
        }
        case 0x18: { // VALUE_TYPE
          const idx = readUnsignedInt(size);
          return `${descriptorToJavaType(types[idx] || '')}.class`;
        }
        case 0x1b: { // VALUE_ENUM
          const idx = readUnsignedInt(size);
          const f = fields[idx];
          return f ? `${descriptorToJavaType(f.classDescriptor)}.${f.name}` : 'null';
        }
        case 0x1e: // VALUE_NULL
          return 'null';
        case 0x1f: // VALUE_BOOLEAN
          return valueArg !== 0 ? 'true' : 'false';
        default:
          posObj.pos += size;
          return null;
      }
    }

    // Helper: Parse debug_info_item for parameter names & line numbers
    function parseDebugInfo(debugOff, paramCount) {
      if (!debugOff || debugOff >= bytes.length) return { lineStart: 0, paramNames: [], addressLines: new Map() };
      const posObj = { pos: debugOff };
      const lineStart = readUleb128(bytes, posObj);
      const parametersSize = readUleb128(bytes, posObj);
      const paramNames = [];
      for (let i = 0; i < parametersSize && i < 64; i++) {
        const nameIdxPlus1 = readUleb128(bytes, posObj);
        paramNames.push(nameIdxPlus1 > 0 ? (strings[nameIdxPlus1 - 1] || null) : null);
      }

      const addressLines = new Map();
      let addr = 0;
      let line = lineStart;
      let steps = 0;
      while (posObj.pos < bytes.length && steps++ < 10000) {
        const op = bytes[posObj.pos++];
        if (op === 0x00) break; // DBG_END_SEQUENCE
        else if (op === 0x01) { // DBG_ADVANCE_PC
          addr += readUleb128(bytes, posObj);
        } else if (op === 0x02) { // DBG_ADVANCE_LINE
          line += readSleb128(bytes, posObj);
        } else if (op === 0x03) { // DBG_START_LOCAL
          readUleb128(bytes, posObj);
          readUleb128(bytes, posObj);
          readUleb128(bytes, posObj);
        } else if (op === 0x04) { // DBG_START_LOCAL_EXTENDED
          readUleb128(bytes, posObj);
          readUleb128(bytes, posObj);
          readUleb128(bytes, posObj);
          readUleb128(bytes, posObj);
        } else if (op === 0x05 || op === 0x06) { // DBG_END_LOCAL / DBG_RESTART_LOCAL
          readUleb128(bytes, posObj);
        } else if (op === 0x09) { // DBG_SET_FILE
          readUleb128(bytes, posObj);
        } else if (op >= 0x0a) {
          const adj = op - 0x0a;
          addr += Math.floor(adj / 15);
          line += -4 + (adj % 15);
          addressLines.set(addr, line);
        }
      }
      return { lineStart, paramNames, addressLines };
    }

    // Helper: Parse code_item and decode Dalvik instructions
    function parseCodeItem(codeOff, methodMeta, isStatic) {
      if (!codeOff || codeOff + 16 > bytes.length) return null;
      const registersSize = dv.getUint16(codeOff, true);
      const insSize = dv.getUint16(codeOff + 2, true);
      const outsSize = dv.getUint16(codeOff + 4, true);
      const triesSize = dv.getUint16(codeOff + 6, true);
      const debugInfoOff = dv.getUint32(codeOff + 8, true);
      const insnsSize = dv.getUint32(codeOff + 12, true); // in 16-bit code units
      const insnsBase = codeOff + 16;

      const debugInfo = parseDebugInfo(debugInfoOff, methodMeta.proto.parameters.length);

      function u16(unitIdx) {
        const bytePos = insnsBase + unitIdx * 2;
        return bytePos + 2 <= bytes.length ? dv.getUint16(bytePos, true) : 0;
      }
      function s16(unitIdx) {
        const bytePos = insnsBase + unitIdx * 2;
        return bytePos + 2 <= bytes.length ? dv.getInt16(bytePos, true) : 0;
      }
      function u32(unitIdx) {
        const bytePos = insnsBase + unitIdx * 2;
        return bytePos + 4 <= bytes.length ? dv.getUint32(bytePos, true) : 0;
      }
      function s32(unitIdx) {
        const bytePos = insnsBase + unitIdx * 2;
        return bytePos + 4 <= bytes.length ? dv.getInt32(bytePos, true) : 0;
      }

      const paramStartReg = registersSize - insSize;
      function regName(r) {
        if (r >= paramStartReg) {
          return `p${r - paramStartReg}`;
        }
        return `v${r}`;
      }

      // Decode all instructions
      const instructions = [];
      const payloadMap = new Map();
      let pc = 0;

      while (pc < insnsSize) {
        const word0 = u16(pc);
        // Check pseudo-instructions (payloads)
        if (word0 === 0x0100) { // packed-switch-payload
          const size = u16(pc + 1);
          const firstKey = s32(pc + 2);
          const targets = [];
          for (let i = 0; i < size; i++) {
            targets.push({ key: firstKey + i, relTarget: s32(pc + 4 + i * 2) });
          }
          const unitLen = 4 + size * 2;
          payloadMap.set(pc, { type: 'packed-switch', firstKey, targets });
          instructions.push({ pc, unitLen, opcode: 0x00, name: '.packed-switch-payload', fmt: 'payload', smali: `.packed-switch 0x${firstKey.toString(16)}`, rawHex: '0001' });
          pc += unitLen;
          continue;
        } else if (word0 === 0x0200) { // sparse-switch-payload
          const size = u16(pc + 1);
          const targets = [];
          for (let i = 0; i < size; i++) {
            const key = s32(pc + 2 + i * 2);
            const relTarget = s32(pc + 2 + size * 2 + i * 2);
            targets.push({ key, relTarget });
          }
          const unitLen = 2 + size * 4;
          payloadMap.set(pc, { type: 'sparse-switch', targets });
          instructions.push({ pc, unitLen, opcode: 0x00, name: '.sparse-switch-payload', fmt: 'payload', smali: '.sparse-switch', rawHex: '0002' });
          pc += unitLen;
          continue;
        } else if (word0 === 0x0300) { // fill-array-data-payload
          const elemWidth = u16(pc + 1);
          const size = u32(pc + 2);
          const totalBytes = size * elemWidth;
          const unitLen = 4 + Math.ceil(totalBytes / 2);
          payloadMap.set(pc, { type: 'array-data', elemWidth, size });
          instructions.push({ pc, unitLen, opcode: 0x00, name: '.array-data-payload', fmt: 'payload', smali: `.array-data ${elemWidth}`, rawHex: '0003' });
          pc += unitLen;
          continue;
        }

        const op = word0 & 0xff;
        const hi = (word0 >>> 8) & 0xff;
        const meta = OPCODE_TABLE[op];
        const fmt = meta.fmt;

        let unitLen = 1;
        let vA = 0, vB = 0, vC = 0;
        let args = [];
        let literal = 0;
        let target = null;
        let refIndex = null;
        let refObj = null;

        switch (fmt) {
          case '10x':
            unitLen = 1;
            break;
          case '12x':
            unitLen = 1;
            vA = hi & 0x0f;
            vB = (hi >>> 4) & 0x0f;
            break;
          case '11n':
            unitLen = 1;
            vA = hi & 0x0f;
            literal = ((hi >>> 4) & 0x0f);
            if (literal & 0x08) literal |= ~0x0f; // sign-extend 4-bit
            break;
          case '11x':
            unitLen = 1;
            vA = hi;
            break;
          case '10t': {
            unitLen = 1;
            const offset8 = (hi & 0x80) ? (hi - 256) : hi;
            target = pc + offset8;
            break;
          }
          case '20t':
            unitLen = 2;
            target = pc + s16(pc + 1);
            break;
          case '22x':
            unitLen = 2;
            vA = hi;
            vB = u16(pc + 1);
            break;
          case '21t':
            unitLen = 2;
            vA = hi;
            target = pc + s16(pc + 1);
            break;
          case '21s':
            unitLen = 2;
            vA = hi;
            literal = s16(pc + 1);
            break;
          case '21h':
            unitLen = 2;
            vA = hi;
            literal = op === 0x15 ? (s16(pc + 1) << 16) : s16(pc + 1);
            break;
          case '21c':
            unitLen = 2;
            vA = hi;
            refIndex = u16(pc + 1);
            break;
          case '23x': {
            unitLen = 2;
            vA = hi;
            const w1 = u16(pc + 1);
            vB = w1 & 0xff;
            vC = (w1 >>> 8) & 0xff;
            break;
          }
          case '22b': {
            unitLen = 2;
            vA = hi;
            const w1 = u16(pc + 1);
            vB = w1 & 0xff;
            const lit8 = (w1 >>> 8) & 0xff;
            literal = (lit8 & 0x80) ? (lit8 - 256) : lit8;
            break;
          }
          case '22t':
            unitLen = 2;
            vA = hi & 0x0f;
            vB = (hi >>> 4) & 0x0f;
            target = pc + s16(pc + 1);
            break;
          case '22s':
            unitLen = 2;
            vA = hi & 0x0f;
            vB = (hi >>> 4) & 0x0f;
            literal = s16(pc + 1);
            break;
          case '22c':
            unitLen = 2;
            vA = hi & 0x0f;
            vB = (hi >>> 4) & 0x0f;
            refIndex = u16(pc + 1);
            break;
          case '30t':
            unitLen = 3;
            target = pc + s32(pc + 1);
            break;
          case '32x':
            unitLen = 3;
            vA = u16(pc + 1);
            vB = u16(pc + 2);
            break;
          case '31i':
            unitLen = 3;
            vA = hi;
            literal = s32(pc + 1);
            break;
          case '31t':
            unitLen = 3;
            vA = hi;
            target = pc + s32(pc + 1);
            break;
          case '31c':
            unitLen = 3;
            vA = hi;
            refIndex = u32(pc + 1);
            break;
          case '35c': {
            unitLen = 3;
            const count = (hi >>> 4) & 0x0f;
            const regG = hi & 0x0f;
            refIndex = u16(pc + 1);
            const regsWord = u16(pc + 2);
            const rList = [
              regsWord & 0x0f,
              (regsWord >>> 4) & 0x0f,
              (regsWord >>> 8) & 0x0f,
              (regsWord >>> 12) & 0x0f,
              regG
            ];
            args = rList.slice(0, count);
            break;
          }
          case '3rc': {
            unitLen = 3;
            const count = hi;
            refIndex = u16(pc + 1);
            const startReg = u16(pc + 2);
            for (let r = 0; r < count; r++) args.push(startReg + r);
            break;
          }
          case '51l': {
            unitLen = 5;
            vA = hi;
            const lo = u32(pc + 1);
            const high = s32(pc + 3);
            literal = `${high !== 0 ? '0x' + (high >>> 0).toString(16) + (lo >>> 0).toString(16).padStart(8, '0') : lo}L`;
            break;
          }
        }

        // Resolve reference
        let refText = '';
        if (meta.ref === 'string') {
          const strVal = strings[refIndex] || '';
          refObj = strVal;
          refText = `"${escapeJavaString(strVal)}"`;
        } else if (meta.ref === 'type') {
          const tVal = types[refIndex] || 'Ljava/lang/Object;';
          refObj = tVal;
          refText = tVal;
        } else if (meta.ref === 'field') {
          const fVal = fields[refIndex] || { classDescriptor: 'Ljava/lang/Object;', name: `f_${refIndex}`, typeDescriptor: 'I' };
          refObj = fVal;
          refText = `${fVal.classDescriptor}->${fVal.name}:${fVal.typeDescriptor}`;
        } else if (meta.ref === 'method') {
          const mVal = methods[refIndex] || { classDescriptor: 'Ljava/lang/Object;', name: `m_${refIndex}`, proto: { parameters: [], returnType: 'V' }, signature: '' };
          refObj = mVal;
          refText = mVal.signature;
        }

        // Build raw hex string
        const hexParts = [];
        for (let u = 0; u < unitLen; u++) {
          const w = u16(pc + u);
          hexParts.push((w & 0xff).toString(16).padStart(2, '0') + ((w >>> 8) & 0xff).toString(16).padStart(2, '0'));
        }

        // Format Smali instruction text
        let smaliOperands = '';
        switch (fmt) {
          case '10x': smaliOperands = ''; break;
          case '12x':
          case '22x':
          case '32x': smaliOperands = `${regName(vA)}, ${regName(vB)}`; break;
          case '11n':
          case '21s':
          case '21h':
          case '31i': {
            const hexLit = literal < 0 ? `-0x${(-literal).toString(16)}` : `0x${(literal >>> 0).toString(16)}`;
            let resComment = '';
            if (resourceTable && resourceTable.byId && resourceTable.byId.has(literal >>> 0)) {
              const r = resourceTable.byId.get(literal >>> 0);
              resComment = ` # @${r.type}/${r.name}`;
            }
            smaliOperands = `${regName(vA)}, ${hexLit}${resComment}`;
            break;
          }
          case '51l': smaliOperands = `${regName(vA)}, ${literal}`; break;
          case '11x': smaliOperands = `${regName(vA)}`; break;
          case '10t':
          case '20t':
          case '30t': smaliOperands = `:goto_${target.toString(16)}`; break;
          case '21t': smaliOperands = `${regName(vA)}, :cond_${target.toString(16)}`; break;
          case '22t': smaliOperands = `${regName(vA)}, ${regName(vB)}, :cond_${target.toString(16)}`; break;
          case '31t': smaliOperands = `${regName(vA)}, :payload_${target.toString(16)}`; break;
          case '21c':
          case '31c': smaliOperands = `${regName(vA)}, ${refText}`; break;
          case '22c': smaliOperands = `${regName(vA)}, ${regName(vB)}, ${refText}`; break;
          case '23x': smaliOperands = `${regName(vA)}, ${regName(vB)}, ${regName(vC)}`; break;
          case '22b':
          case '22s': smaliOperands = `${regName(vA)}, ${regName(vB)}, ${literal < 0 ? '-0x' + (-literal).toString(16) : '0x' + literal.toString(16)}`; break;
          case '35c':
          case '3rc': smaliOperands = `{${args.map(regName).join(', ')}}, ${refText}`; break;
        }

        instructions.push({
          pc,
          unitLen,
          opcode: op,
          name: meta.name,
          fmt,
          refType: meta.ref,
          vA,
          vB,
          vC,
          args,
          literal,
          target,
          refIndex,
          refObj,
          rawHex: hexParts.join(' '),
          smali: smaliOperands ? `${meta.name} ${smaliOperands}` : meta.name,
          line: debugInfo.addressLines.get(pc) || null
        });

        pc += unitLen;
      }

      // Parse try_items & catch_handlers if triesSize > 0
      const tries = [];
      if (triesSize > 0) {
        let triesPos = insnsBase + insnsSize * 2;
        if (insnsSize % 2 !== 0) triesPos += 2; // 4-byte alignment padding
        const handlersBase = triesPos + triesSize * 8;

        for (let t = 0; t < triesSize; t++) {
          const tBase = triesPos + t * 8;
          if (tBase + 8 > bytes.length) break;
          const startAddr = dv.getUint32(tBase, true);
          const insnCount = dv.getUint16(tBase + 4, true);
          const handlerOff = dv.getUint16(tBase + 6, true);

          const hPosObj = { pos: handlersBase + handlerOff };
          const listSize = readSleb128(bytes, hPosObj);
          const catchCount = Math.abs(listSize);
          const handlers = [];
          for (let h = 0; h < catchCount; h++) {
            const typeIdx = readUleb128(bytes, hPosObj);
            const addr = readUleb128(bytes, hPosObj);
            handlers.push({
              exceptionType: types[typeIdx] || 'Ljava/lang/Throwable;',
              handlerAddr: addr
            });
          }
          if (listSize <= 0) {
            const catchAllAddr = readUleb128(bytes, hPosObj);
            handlers.push({
              exceptionType: 'Ljava/lang/Throwable;',
              handlerAddr: catchAllAddr,
              isCatchAll: true
            });
          }
          tries.push({
            startAddr,
            endAddr: startAddr + insnCount,
            handlers
          });
        }
      }

      return {
        registersSize,
        insSize,
        outsSize,
        triesSize,
        insnsSize,
        debugInfo,
        instructions,
        payloadMap,
        tries
      };
    }

    // 6. Parse Class Definitions
    const classes = [];
    for (let i = 0; i < classDefsSize; i++) {
      const base = classDefsOff + i * 32;
      if (base + 32 > bytes.length) break;

      const classIdx = dv.getUint32(base, true);
      const accessFlags = dv.getUint32(base + 4, true);
      const superclassIdx = dv.getUint32(base + 8, true);
      const interfacesOff = dv.getUint32(base + 12, true);
      const sourceFileIdx = dv.getUint32(base + 16, true);
      const annotationsOff = dv.getUint32(base + 20, true);
      const classDataOff = dv.getUint32(base + 24, true);
      const staticValuesOff = dv.getUint32(base + 28, true);

      const classDesc = types[classIdx] || `LUnknownClass_${i};`;
      const fullClassName = descriptorToFullClassName(classDesc);
      const lastDot = fullClassName.lastIndexOf('.');
      const packageName = lastDot !== -1 ? fullClassName.slice(0, lastDot) : '';
      const simpleName = lastDot !== -1 ? fullClassName.slice(lastDot + 1) : fullClassName;

      const superDesc = superclassIdx !== 0xFFFFFFFF ? (types[superclassIdx] || 'Ljava/lang/Object;') : null;
      const interfaces = readTypeList(interfacesOff);
      const sourceFile = sourceFileIdx !== 0xFFFFFFFF ? (strings[sourceFileIdx] || null) : `${simpleName}.java`;

      // Read static field initial values if present
      const staticInitValues = [];
      if (staticValuesOff > 0 && staticValuesOff < bytes.length) {
        const posObj = { pos: staticValuesOff };
        const count = readUleb128(bytes, posObj);
        for (let k = 0; k < count; k++) {
          staticInitValues.push(readEncodedValue(posObj));
        }
      }

      const staticFields = [];
      const instanceFields = [];
      const directMethods = [];
      const virtualMethods = [];

      if (classDataOff > 0 && classDataOff < bytes.length) {
        const posObj = { pos: classDataOff };
        const staticFieldsSize = readUleb128(bytes, posObj);
        const instanceFieldsSize = readUleb128(bytes, posObj);
        const directMethodsSize = readUleb128(bytes, posObj);
        const virtualMethodsSize = readUleb128(bytes, posObj);

        let fIdx = 0;
        for (let k = 0; k < staticFieldsSize; k++) {
          fIdx += readUleb128(bytes, posObj);
          const flags = readUleb128(bytes, posObj);
          const fMeta = fields[fIdx] || { name: `sfield_${k}`, typeDescriptor: 'I' };
          staticFields.push({
            fieldId: fIdx,
            name: fMeta.name,
            typeDescriptor: fMeta.typeDescriptor,
            accessFlags: flags,
            initialValue: staticInitValues[k] !== undefined ? staticInitValues[k] : null
          });
        }

        fIdx = 0;
        for (let k = 0; k < instanceFieldsSize; k++) {
          fIdx += readUleb128(bytes, posObj);
          const flags = readUleb128(bytes, posObj);
          const fMeta = fields[fIdx] || { name: `ifield_${k}`, typeDescriptor: 'I' };
          instanceFields.push({
            fieldId: fIdx,
            name: fMeta.name,
            typeDescriptor: fMeta.typeDescriptor,
            accessFlags: flags
          });
        }

        let mIdx = 0;
        for (let k = 0; k < directMethodsSize; k++) {
          mIdx += readUleb128(bytes, posObj);
          const flags = readUleb128(bytes, posObj);
          const codeOff = readUleb128(bytes, posObj);
          const mMeta = methods[mIdx] || { name: `dmethod_${k}`, proto: { returnType: 'V', parameters: [] }, signature: '' };
          const isStatic = (flags & ACCESS_FLAGS.ACC_STATIC) !== 0;
          directMethods.push({
            methodId: mIdx,
            name: mMeta.name,
            proto: mMeta.proto,
            signature: mMeta.signature,
            accessFlags: flags,
            isDirect: true,
            isStatic,
            isNative: (flags & ACCESS_FLAGS.ACC_NATIVE) !== 0,
            isConstructor: mMeta.name === '<init>' || mMeta.name === '<clinit>',
            codeOff,
            code: parseCodeItem(codeOff, mMeta, isStatic)
          });
        }

        mIdx = 0;
        for (let k = 0; k < virtualMethodsSize; k++) {
          mIdx += readUleb128(bytes, posObj);
          const flags = readUleb128(bytes, posObj);
          const codeOff = readUleb128(bytes, posObj);
          const mMeta = methods[mIdx] || { name: `vmethod_${k}`, proto: { returnType: 'V', parameters: [] }, signature: '' };
          const isStatic = (flags & ACCESS_FLAGS.ACC_STATIC) !== 0;
          virtualMethods.push({
            methodId: mIdx,
            name: mMeta.name,
            proto: mMeta.proto,
            signature: mMeta.signature,
            accessFlags: flags,
            isDirect: false,
            isStatic,
            isNative: (flags & ACCESS_FLAGS.ACC_NATIVE) !== 0,
            isConstructor: false,
            codeOff,
            code: parseCodeItem(codeOff, mMeta, isStatic)
          });
        }
      }

      const clsObj = {
        id: i,
        dexName,
        descriptor: classDesc,
        fullName: fullClassName,
        packageName,
        simpleName,
        superDescriptor: superDesc,
        superName: superDesc ? descriptorToFullClassName(superDesc) : null,
        interfaces,
        sourceFile,
        accessFlags,
        isInterface: (accessFlags & ACCESS_FLAGS.ACC_INTERFACE) !== 0,
        isEnum: (accessFlags & ACCESS_FLAGS.ACC_ENUM) !== 0,
        isAbstract: (accessFlags & ACCESS_FLAGS.ACC_ABSTRACT) !== 0,
        staticFields,
        instanceFields,
        directMethods,
        virtualMethods,
        allMethods: [...directMethods, ...virtualMethods],
        _decompiledCache: null
      };

      classes.push(clsObj);
    }

    return {
      dexName,
      version,
      fileSize,
      checksum: '0x' + checksum.toString(16).padStart(8, '0'),
      signatureHex,
      endianTag: '0x' + endianTag.toString(16),
      strings,
      types,
      protos,
      fields,
      methods,
      classes
    };
  }

  // ==================== CONTROL FLOW GRAPH (CFG) BUILDER ====================
  function buildMethodCFG(method) {
    if (!method.code || !method.code.instructions.length) {
      return { blocks: [], edges: [] };
    }
    const insns = method.code.instructions.filter(ins => ins.fmt !== 'payload');
    if (!insns.length) return { blocks: [], edges: [] };

    const leaders = new Set([insns[0].pc]);
    const insnByPc = new Map();
    insns.forEach((ins, idx) => insnByPc.set(ins.pc, { ins, idx }));

    // Identify basic block leaders
    for (let i = 0; i < insns.length; i++) {
      const ins = insns[i];
      const op = ins.opcode;
      const isBranch = (op >= 0x28 && op <= 0x2c) || (op >= 0x32 && op <= 0x3d);
      const isReturnOrThrow = (op >= 0x0e && op <= 0x11) || op === 0x27;

      if (isBranch) {
        if (ins.target != null && insnByPc.has(ins.target)) {
          leaders.add(ins.target);
        }
        // Switch targets
        if ((op === 0x2b || op === 0x2c) && method.code.payloadMap.has(ins.target)) {
          const payload = method.code.payloadMap.get(ins.target);
          for (const t of payload.targets) {
            const absTarget = ins.pc + t.relTarget;
            if (insnByPc.has(absTarget)) leaders.add(absTarget);
          }
        }
        if (i + 1 < insns.length) leaders.add(insns[i + 1].pc);
      } else if (isReturnOrThrow) {
        if (i + 1 < insns.length) leaders.add(insns[i + 1].pc);
      }
    }

    // Try/catch boundaries are also leaders
    for (const tr of method.code.tries) {
      if (insnByPc.has(tr.startAddr)) leaders.add(tr.startAddr);
      if (insnByPc.has(tr.endAddr)) leaders.add(tr.endAddr);
      for (const h of tr.handlers) {
        if (insnByPc.has(h.handlerAddr)) leaders.add(h.handlerAddr);
      }
    }

    const sortedLeaders = Array.from(leaders).sort((a, b) => a - b);
    const blocks = [];
    const blockByStartPc = new Map();

    for (let b = 0; b < sortedLeaders.length; b++) {
      const startPc = sortedLeaders[b];
      const nextLeaderPc = b + 1 < sortedLeaders.length ? sortedLeaders[b + 1] : Infinity;
      const blockInsns = insns.filter(ins => ins.pc >= startPc && ins.pc < nextLeaderPc);
      if (!blockInsns.length) continue;
      const lastIns = blockInsns[blockInsns.length - 1];
      const block = {
        id: `B${blocks.length}`,
        index: blocks.length,
        startPc,
        endPc: lastIns.pc,
        instructions: blockInsns,
        outEdges: [],
        inEdges: []
      };
      blocks.push(block);
      blockByStartPc.set(startPc, block);
    }

    const edges = [];
    function addEdge(fromBlock, toPc, type, label = '') {
      const toBlock = blockByStartPc.get(toPc);
      if (!toBlock) return;
      const edge = { from: fromBlock.id, to: toBlock.id, fromIndex: fromBlock.index, toIndex: toBlock.index, type, label };
      edges.push(edge);
      fromBlock.outEdges.push(edge);
      toBlock.inEdges.push(edge);
    }

    for (let b = 0; b < blocks.length; b++) {
      const block = blocks[b];
      const lastIns = block.instructions[block.instructions.length - 1];
      const op = lastIns.opcode;
      const nextBlock = b + 1 < blocks.length ? blocks[b + 1] : null;

      if (op >= 0x0e && op <= 0x11) {
        // return - no outgoing edges
      } else if (op === 0x27) {
        // throw
      } else if (op >= 0x28 && op <= 0x2a) {
        // unconditional goto
        addEdge(block, lastIns.target, 'jump', 'goto');
      } else if (op >= 0x32 && op <= 0x3d) {
        // conditional branch
        addEdge(block, lastIns.target, 'true', 'true');
        if (nextBlock) addEdge(block, nextBlock.startPc, 'false', 'false');
      } else if (op === 0x2b || op === 0x2c) {
        const payload = method.code.payloadMap.get(lastIns.target);
        if (payload) {
          for (const t of payload.targets) {
            addEdge(block, lastIns.pc + t.relTarget, 'switch', `case ${t.key}`);
          }
        }
        if (nextBlock) addEdge(block, nextBlock.startPc, 'default', 'default');
      } else {
        if (nextBlock) addEdge(block, nextBlock.startPc, 'fallthrough', '');
      }
    }

    return { blocks, edges };
  }

  // ==================== SMALI SOURCE GENERATOR ====================
  function generateSmaliForClass(cls) {
    const lines = [];
    const flags = formatAccessFlags(cls.accessFlags, cls.isInterface ? 'interface' : 'class').join(' ');
    lines.push(`.class ${flags ? flags + ' ' : ''}${cls.descriptor}`);
    if (cls.superDescriptor) {
      lines.push(`.super ${cls.superDescriptor}`);
    }
    if (cls.sourceFile) {
      lines.push(`.source "${cls.sourceFile}"`);
    }
    for (const iface of cls.interfaces) {
      lines.push(`.implements ${iface}`);
    }
    lines.push('');

    if (cls.staticFields.length > 0) {
      lines.push('# static fields');
      for (const sf of cls.staticFields) {
        const fFlags = formatAccessFlags(sf.accessFlags, 'field').join(' ');
        const initPart = sf.initialValue != null ? ` = ${sf.initialValue}` : '';
        lines.push(`.field ${fFlags ? fFlags + ' ' : ''}${sf.name}:${sf.typeDescriptor}${initPart}`);
      }
      lines.push('');
    }

    if (cls.instanceFields.length > 0) {
      lines.push('# instance fields');
      for (const f of cls.instanceFields) {
        const fFlags = formatAccessFlags(f.accessFlags, 'field').join(' ');
        lines.push(`.field ${fFlags ? fFlags + ' ' : ''}${f.name}:${f.typeDescriptor}`);
      }
      lines.push('');
    }

    function renderMethodsSection(title, methodList) {
      if (!methodList.length) return;
      lines.push(`# ${title}`);
      for (const m of methodList) {
        const mFlags = formatAccessFlags(m.accessFlags, 'method').join(' ');
        const ctorFlag = m.isConstructor ? 'constructor ' : '';
        const sig = `${m.name}(${m.proto.parameters.join('')})${m.proto.returnType}`;
        lines.push(`.method ${mFlags ? mFlags + ' ' : ''}${ctorFlag}${sig}`);

        if (m.code) {
          lines.push(`    .registers ${m.code.registersSize}`);
          // Collect branch targets to emit labels
          const labelByPc = new Map();
          for (const ins of m.code.instructions) {
            if (ins.target != null) {
              const prefix = (ins.opcode >= 0x32 && ins.opcode <= 0x3d) ? 'cond' : (ins.opcode === 0x2b || ins.opcode === 0x2c ? 'payload' : 'goto');
              labelByPc.set(ins.target, `:${prefix}_${ins.target.toString(16)}`);
            }
          }
          for (const tr of m.code.tries) {
            labelByPc.set(tr.startAddr, `:try_start_${tr.startAddr.toString(16)}`);
            labelByPc.set(tr.endAddr, `:try_end_${tr.endAddr.toString(16)}`);
            for (const h of tr.handlers) {
              labelByPc.set(h.handlerAddr, `:catch_${h.handlerAddr.toString(16)}`);
            }
          }

          for (const ins of m.code.instructions) {
            if (labelByPc.has(ins.pc)) {
              lines.push(`    ${labelByPc.get(ins.pc)}`);
            }
            if (ins.line != null) {
              lines.push(`    .line ${ins.line}`);
            }
            const addrHex = ins.pc.toString(16).padStart(4, '0');
            lines.push(`    ${ins.smali}    # @${addrHex} [${ins.rawHex}]`);
          }
        }
        lines.push('.end method');
        lines.push('');
      }
    }

    renderMethodsSection('direct methods', cls.directMethods);
    renderMethodsSection('virtual methods', cls.virtualMethods);

    return lines.join('\n');
  }

  // ==================== DALVIK-TO-JAVA AST DECOMPILER ENGINE ====================
  const INVERT_COND = {
    'if-eq': '!=', 'if-ne': '==', 'if-lt': '>=', 'if-ge': '<', 'if-gt': '<=', 'if-le': '>',
    'if-eqz': '!=', 'if-nez': '==', 'if-ltz': '>=', 'if-gez': '<', 'if-gtz': '<=', 'if-lez': '>'
  };
  const DIRECT_COND = {
    'if-eq': '==', 'if-ne': '!=', 'if-lt': '<', 'if-ge': '>=', 'if-gt': '>', 'if-le': '<=',
    'if-eqz': '==', 'if-nez': '!=', 'if-ltz': '<', 'if-gez': '>=', 'if-gtz': '>', 'if-lez': '<='
  };

  function decompileMethodToJava(cls, method, importsSet, resourceTable = null, crossRefs = []) {
    const indent1 = '    ';
    const indent2 = '        ';
    const mFlags = formatAccessFlags(method.accessFlags, 'method');
    const returnJavaType = descriptorToJavaType(method.proto.returnType, importsSet);

    // Build parameter names & types
    const paramDecls = [];
    const paramRegMap = new Map();
    const totalRegs = method.code ? method.code.registersSize : 0;
    const insSize = method.code ? method.code.insSize : 0;
    let regCursor = totalRegs - insSize;

    if (!method.isStatic) {
      paramRegMap.set(regCursor, { expr: 'this', type: cls.simpleName, isParam: true });
      regCursor++;
    }

    const debugParamNames = (method.code && method.code.debugInfo && method.code.debugInfo.paramNames) || [];
    for (let p = 0; p < method.proto.parameters.length; p++) {
      const pDesc = method.proto.parameters[p];
      const pType = descriptorToJavaType(pDesc, importsSet);
      const pName = debugParamNames[p] || `arg${p}`;
      paramDecls.push(`${pType} ${pName}`);
      paramRegMap.set(regCursor, { expr: pName, type: pType, isParam: true });
      regCursor += (pDesc === 'J' || pDesc === 'D') ? 2 : 1;
    }

    // Method header
    let header;
    if (method.name === '<clinit>') {
      header = `${indent1}static`;
    } else if (method.name === '<init>') {
      const fStr = mFlags.length ? mFlags.join(' ') + ' ' : '';
      header = `${indent1}${fStr}${cls.simpleName}(${paramDecls.join(', ')})`;
    } else {
      const fStr = mFlags.length ? mFlags.join(' ') + ' ' : '';
      header = `${indent1}${fStr}${returnJavaType} ${method.name}(${paramDecls.join(', ')})`;
    }

    if (!method.code) {
      return `${header};\n`;
    }

    // Symbolic state for decompilation
    const insns = method.code.instructions;
    const regState = new Map();
    for (const [r, info] of paramRegMap.entries()) {
      regState.set(r, { expr: info.expr, type: info.type, declared: true });
    }

    const declaredVars = new Set();
    let lastResult = { expr: 'result', type: 'Object' };

    function getRegExpr(r) {
      if (regState.has(r)) return regState.get(r).expr;
      if (paramRegMap.has(r)) return paramRegMap.get(r).expr;
      return `v${r}`;
    }

    function getRegType(r) {
      if (regState.has(r)) return regState.get(r).type;
      if (paramRegMap.has(r)) return paramRegMap.get(r).type;
      return 'int';
    }

    function setReg(r, expr, type = 'int') {
      regState.set(r, { expr, type });
    }

    function formatResourceOrInt(lit, typeHint = 'int') {
      const u = lit >>> 0;
      if (resourceTable && resourceTable.byId && resourceTable.byId.has(u)) {
        const res = resourceTable.byId.get(u);
        return `R.${res.type}.${res.name} /* 0x${u.toString(16)} */`;
      }
      if (typeHint === 'boolean') {
        return lit !== 0 ? 'true' : 'false';
      }
      if (u >= 0x7f000000 && u <= 0x7fffffff) {
        return `0x${u.toString(16)}`;
      }
      return String(lit);
    }

    // Identify loop headers and registers mutated inside loops
    const loopHeaders = new Map(); // startPc -> latchPc
    const loopMutatedRegs = new Set();
    const insnIdxByPc = new Map();
    insns.forEach((ins, idx) => insnIdxByPc.set(ins.pc, idx));

    for (let i = 0; i < insns.length; i++) {
      const ins = insns[i];
      if (ins.target != null && ins.target <= ins.pc && ins.opcode >= 0x28 && ins.opcode <= 0x3d) {
        loopHeaders.set(ins.target, ins.pc);
        const startIdx = insnIdxByPc.get(ins.target) || 0;
        for (let k = startIdx; k <= i; k++) {
          const bodyIns = insns[k];
          if (bodyIns.opcode >= 0x90 && bodyIns.opcode <= 0xe2) {
            loopMutatedRegs.add(bodyIns.vA);
          }
        }
      }
    }

    const statements = [];
    let indentLevel = 2;
    let activeLoopLatchPc = -1;
    const closeIndentAtPc = new Map(); // pc -> Array of closing actions

    function pushCloseAt(pc, action) {
      if (!closeIndentAtPc.has(pc)) closeIndentAtPc.set(pc, []);
      closeIndentAtPc.get(pc).push(action);
    }

    function emit(line) {
      statements.push('    '.repeat(indentLevel) + line);
    }

    function assignVarIfLoopMutated(reg, expr, type) {
      if (loopMutatedRegs.has(reg) && !paramRegMap.has(reg)) {
        const varName = `v${reg}`;
        if (!declaredVars.has(varName)) {
          declaredVars.add(varName);
          emit(`${type} ${varName} = ${expr};`);
        } else if (varName !== expr) {
          emit(`${varName} = ${expr};`);
        }
        setReg(reg, varName, type);
        return true;
      }
      return false;
    }

    // Try/catch starts & ends
    const tryStartAtPc = new Map();
    const tryEndAtPc = new Map();
    for (const tr of method.code.tries) {
      tryStartAtPc.set(tr.startAddr, tr);
      tryEndAtPc.set(tr.endAddr, tr);
    }

    for (let i = 0; i < insns.length; i++) {
      const ins = insns[i];
      if (ins.fmt === 'payload') continue;

      // Close blocks scheduled at this PC
      if (closeIndentAtPc.has(ins.pc)) {
        const actions = closeIndentAtPc.get(ins.pc);
        for (const act of actions) {
          if (act.type === 'close') {
            if (act.isLoop) activeLoopLatchPc = -1;
            indentLevel = Math.max(2, indentLevel - 1);
            emit('}');
          } else if (act.type === 'else') {
            indentLevel = Math.max(2, indentLevel - 1);
            emit('} else {');
            indentLevel++;
          }
        }
      }

      if (tryStartAtPc.has(ins.pc)) {
        emit('try {');
        indentLevel++;
      }

      if (loopHeaders.has(ins.pc)) {
        emit('while (true) {');
        indentLevel++;
        const latchPc = loopHeaders.get(ins.pc);
        activeLoopLatchPc = latchPc;
        const latchIdx = insnIdxByPc.get(latchPc);
        if (latchIdx != null && latchIdx + 1 < insns.length) {
          pushCloseAt(insns[latchIdx + 1].pc, { type: 'close', isLoop: true });
        }
      }

      const op = ins.opcode;
      const name = ins.name;

      // 1. Move instructions
      if (op >= 0x01 && op <= 0x09) {
        const srcExpr = getRegExpr(ins.vB);
        const srcType = getRegType(ins.vB);
        const varName = paramRegMap.has(ins.vA) ? paramRegMap.get(ins.vA).expr : `v${ins.vA}`;
        if (!declaredVars.has(varName) && !paramRegMap.has(ins.vA)) {
          declaredVars.add(varName);
          emit(`${srcType} ${varName} = ${srcExpr};`);
        } else if (varName !== srcExpr) {
          emit(`${varName} = ${srcExpr};`);
        }
        setReg(ins.vA, varName, srcType);
      }
      // 2. Move-result
      else if (op >= 0x0a && op <= 0x0c) {
        if (lastResult.isStringBuilder) {
          setReg(ins.vA, lastResult.expr, lastResult.type);
        } else {
          // Check if vA is used before being overwritten
          let usedCount = 0;
          for (let k = i + 1; k < insns.length; k++) {
            const nk = insns[k];
            const fmtReadsB = ['12x', '22x', '32x', '22t', '22s', '22b', '22c', '23x'].includes(nk.fmt);
            const fmtReadsC = nk.fmt === '23x';
            const readsA = (nk.args && nk.args.includes(ins.vA)) ||
              ([0x0f, 0x10, 0x11, 0x27, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d].includes(nk.opcode) && nk.vA === ins.vA) ||
              (fmtReadsB && nk.vB === ins.vA) ||
              (fmtReadsC && nk.vC === ins.vA);
            if (readsA) usedCount++;
            const writesA = nk.vA === ins.vA && [0x01,0x02,0x03,0x0a,0x0b,0x0c,0x12,0x13,0x14,0x15,0x1a,0x1b,0x1c,0x22,0x23].includes(nk.opcode);
            if (writesA) break;
          }
          if (usedCount === 0) {
            const varName = `v${ins.vA}`;
            if (!declaredVars.has(varName)) {
              declaredVars.add(varName);
              emit(`${lastResult.type} ${varName} = ${lastResult.expr};`);
            } else {
              emit(`${varName} = ${lastResult.expr};`);
            }
            setReg(ins.vA, varName, lastResult.type);
          } else {
            setReg(ins.vA, lastResult.expr, lastResult.type);
          }
        }
      }
      // 3. Move-exception
      else if (op === 0x0d) {
        setReg(ins.vA, 'e', 'Throwable');
      }
      // 4. Return instructions
      else if (op === 0x0e) {
        if (i < insns.length - 1) emit('return;');
      }
      else if (op >= 0x0f && op <= 0x11) {
        let retExpr = getRegExpr(ins.vA);
        if (returnJavaType === 'boolean' && (retExpr === '0' || retExpr === '1')) {
          retExpr = retExpr === '1' ? 'true' : 'false';
        }
        emit(`return ${retExpr};`);
      }
      // 5. Const numbers
      else if (op >= 0x12 && op <= 0x19) {
        const isWide = op >= 0x16 && op <= 0x19;
        const litStr = typeof ins.literal === 'string' ? ins.literal : formatResourceOrInt(ins.literal);
        const t = isWide ? 'long' : 'int';
        if (!assignVarIfLoopMutated(ins.vA, litStr, t)) {
          setReg(ins.vA, litStr, t);
        }
      }
      // 6. Const-string
      else if (op === 0x1a || op === 0x1b) {
        setReg(ins.vA, `"${escapeJavaString(ins.refObj)}"`, 'String');
      }
      // 7. Const-class
      else if (op === 0x1c) {
        const tName = descriptorToJavaType(ins.refObj, importsSet);
        setReg(ins.vA, `${tName}.class`, 'Class<?>');
      }
      // 8. Check-cast & instance-of
      else if (op === 0x1f) {
        const tName = descriptorToJavaType(ins.refObj, importsSet);
        const inner = getRegExpr(ins.vA);
        setReg(ins.vA, `((${tName}) ${inner})`, tName);
      }
      else if (op === 0x20) {
        const tName = descriptorToJavaType(ins.refObj, importsSet);
        setReg(ins.vA, `(${getRegExpr(ins.vB)} instanceof ${tName})`, 'boolean');
      }
      // 9. Array length & allocation
      else if (op === 0x21) {
        setReg(ins.vA, `${getRegExpr(ins.vB)}.length`, 'int');
      }
      else if (op === 0x22) {
        // new-instance: defer until <init> invoke-direct
        const tName = descriptorToJavaType(ins.refObj, importsSet);
        setReg(ins.vA, `__NEW__:${tName}`, tName);
      }
      else if (op === 0x23) {
        const arrType = descriptorToJavaType(ins.refObj, importsSet).replace(/\[\]$/, '');
        setReg(ins.vA, `new ${arrType}[${getRegExpr(ins.vB)}]`, `${arrType}[]`);
      }
      // 10. Throw
      else if (op === 0x27) {
        emit(`throw ${getRegExpr(ins.vA)};`);
      }
      // 11. Comparison ops (cmpl/cmpg/cmp-long)
      else if (op >= 0x2d && op <= 0x31) {
        setReg(ins.vA, `Long.compare(${getRegExpr(ins.vB)}, ${getRegExpr(ins.vC)})`, 'int');
      }
      // 12. Conditional branches (if-* and if-*z)
      else if (op >= 0x32 && op <= 0x3d) {
        const isZeroCmp = op >= 0x38;
        const lhs = getRegExpr(ins.vA);
        const lhsType = getRegType(ins.vA);
        let rhs = isZeroCmp ? '0' : getRegExpr(ins.vB);
        if (isZeroCmp && lhsType === 'boolean') rhs = 'false';
        else if (isZeroCmp && !['int', 'long', 'float', 'double', 'byte', 'short', 'char'].includes(lhsType)) rhs = 'null';

        if (activeLoopLatchPc !== -1 && ins.target > activeLoopLatchPc) {
          // Loop exit condition jumping past the loop latch
          const opSym = DIRECT_COND[name] || '==';
          emit(`if (${lhs} ${opSym} ${rhs}) break;`);
        } else if (ins.target > ins.pc) {
          const opSym = INVERT_COND[name] || '!=';
          let condStr = `${lhs} ${opSym} ${rhs}`;
          if (lhsType === 'boolean' && rhs === 'false') {
            condStr = opSym === '!=' ? lhs : `!${lhs}`;
          }
          emit(`if (${condStr}) {`);
          indentLevel++;

          // Check if the instruction right before target is an unconditional goto (meaning an else branch!)
          const targetIdx = insnIdxByPc.get(ins.target);
          if (targetIdx != null && targetIdx > 0) {
            const prevIns = insns[targetIdx - 1];
            if (prevIns.opcode >= 0x28 && prevIns.opcode <= 0x2a && prevIns.target > ins.target) {
              pushCloseAt(ins.target, { type: 'else' });
              pushCloseAt(prevIns.target, { type: 'close' });
            } else {
              pushCloseAt(ins.target, { type: 'close' });
            }
          } else {
            pushCloseAt(ins.target, { type: 'close' });
          }
        } else {
          // Backward branch or loop exit
          const opSym = DIRECT_COND[name] || '==';
          emit(`if (!(${lhs} ${opSym} ${rhs})) break;`);
        }
      }
      // 13. Switch statements
      else if (op === 0x2b || op === 0x2c) {
        const swExpr = getRegExpr(ins.vA);
        const payload = method.code.payloadMap.get(ins.target);
        if (payload) {
          emit(`switch (${swExpr}) {`);
          for (const t of payload.targets) {
            emit(`    case ${t.key}: /* -> @0x${(ins.pc + t.relTarget).toString(16)} */ break;`);
          }
          emit('}');
        }
      }
      // 14. Array get / put
      else if (op >= 0x44 && op <= 0x4a) {
        setReg(ins.vA, `${getRegExpr(ins.vB)}[${getRegExpr(ins.vC)}]`, 'Object');
      }
      else if (op >= 0x4b && op <= 0x51) {
        emit(`${getRegExpr(ins.vB)}[${getRegExpr(ins.vC)}] = ${getRegExpr(ins.vA)};`);
      }
      // 15. Instance field get / put (iget* / iput*)
      else if (op >= 0x52 && op <= 0x58) {
        const f = ins.refObj;
        const objExpr = getRegExpr(ins.vB);
        const fType = descriptorToJavaType(f.typeDescriptor, importsSet);
        setReg(ins.vA, `${objExpr}.${f.name}`, fType);
      }
      else if (op >= 0x59 && op <= 0x5f) {
        const f = ins.refObj;
        const objExpr = getRegExpr(ins.vB);
        const fType = descriptorToJavaType(f.typeDescriptor, importsSet);
        let valExpr = getRegExpr(ins.vA);
        if (fType === 'boolean' && (valExpr === '0' || valExpr === '1')) {
          valExpr = valExpr === '1' ? 'true' : 'false';
        }
        emit(`${objExpr}.${f.name} = ${valExpr};`);
      }
      // 16. Static field get / put (sget* / sput*)
      else if (op >= 0x60 && op <= 0x66) {
        const f = ins.refObj;
        const ownerType = descriptorToJavaType(f.classDescriptor, importsSet);
        const fType = descriptorToJavaType(f.typeDescriptor, importsSet);
        const prefix = ownerType === cls.simpleName ? '' : `${ownerType}.`;
        setReg(ins.vA, `${prefix}${f.name}`, fType);
      }
      else if (op >= 0x67 && op <= 0x6d) {
        const f = ins.refObj;
        const ownerType = descriptorToJavaType(f.classDescriptor, importsSet);
        const fType = descriptorToJavaType(f.typeDescriptor, importsSet);
        const prefix = ownerType === cls.simpleName ? '' : `${ownerType}.`;
        let valExpr = getRegExpr(ins.vA);
        if (fType === 'boolean' && (valExpr === '0' || valExpr === '1')) {
          valExpr = valExpr === '1' ? 'true' : 'false';
        }
        emit(`${prefix}${f.name} = ${valExpr};`);
      }
      // 17. Method Invocations (invoke-virtual / super / direct / static / interface)
      else if (op >= 0x6e && op <= 0x78) {
        const mRef = ins.refObj;
        const isStaticCall = op === 0x71 || op === 0x77;
        const isSuperCall = op === 0x6f || op === 0x75;
        const ownerJava = descriptorToJavaType(mRef.classDescriptor, importsSet);
        const retType = descriptorToJavaType(mRef.proto.returnType, importsSet);

        crossRefs.push({
          fromClass: cls.fullName,
          fromMethod: method.name,
          toClass: mRef.className,
          toMethod: mRef.name,
          signature: mRef.signature
        });

        // Map arguments (accounting for wide 64-bit registers J/D taking 2 registers)
        const callArgs = [];
        let argCursor = isStaticCall ? 0 : 1;
        for (let pIdx = 0; pIdx < mRef.proto.parameters.length && argCursor < ins.args.length; pIdx++) {
          const pDesc = mRef.proto.parameters[pIdx];
          const rNum = ins.args[argCursor];
          let aExpr = getRegExpr(rNum);
          if (pDesc === 'Z' && (aExpr === '0' || aExpr === '1')) {
            aExpr = aExpr === '1' ? 'true' : 'false';
          } else if ((pDesc.startsWith('L') || pDesc.startsWith('[')) && aExpr === '0') {
            aExpr = 'null';
          }
          callArgs.push(aExpr);
          argCursor += (pDesc === 'J' || pDesc === 'D') ? 2 : 1;
        }

        const nextIns = i + 1 < insns.length ? insns[i + 1] : null;
        const resultCaptured = nextIns && nextIns.opcode >= 0x0a && nextIns.opcode <= 0x0c;

        if (mRef.name === '<init>') {
          const recvReg = ins.args[0];
          const recvExpr = getRegExpr(recvReg);
          if (recvExpr === 'this') {
            if (ownerJava !== 'Object' || callArgs.length > 0) {
              emit(`super(${callArgs.join(', ')});`);
            }
          } else if (recvExpr.startsWith('__NEW__:')) {
            const newType = recvExpr.slice('__NEW__:'.length);
            if (newType === 'StringBuilder') {
              const initStr = callArgs.length ? callArgs[0] : '';
              setReg(recvReg, initStr ? `${initStr}` : '""', 'StringBuilder');
            } else {
              setReg(recvReg, `new ${newType}(${callArgs.join(', ')})`, newType);
            }
          } else {
            emit(`new ${ownerJava}(${callArgs.join(', ')});`);
          }
        } else if (!isStaticCall && mRef.className === 'java.lang.StringBuilder') {
          // Fold StringBuilder.append and .toString into clean Java string concatenation
          const recvReg = ins.args[0];
          const curSb = getRegExpr(recvReg);
          if (mRef.name === 'append' && callArgs.length === 1) {
            const appended = curSb === '""' || !curSb ? callArgs[0] : `${curSb} + ${callArgs[0]}`;
            setReg(recvReg, appended, 'StringBuilder');
            lastResult = { expr: appended, type: 'StringBuilder', isStringBuilder: true };
          } else if (mRef.name === 'toString') {
            lastResult = { expr: curSb || '""', type: 'String', isStringBuilder: true };
          }
        } else {
          let callExpr;
          if (isStaticCall) {
            const prefix = ownerJava === cls.simpleName ? '' : `${ownerJava}.`;
            callExpr = `${prefix}${mRef.name}(${callArgs.join(', ')})`;
          } else if (isSuperCall) {
            callExpr = `super.${mRef.name}(${callArgs.join(', ')})`;
          } else {
            const recvExpr = getRegExpr(ins.args[0]);
            const prefix = recvExpr === 'this' ? 'this.' : `${recvExpr}.`;
            callExpr = `${prefix}${mRef.name}(${callArgs.join(', ')})`;
          }

          if (resultCaptured) {
            lastResult = { expr: callExpr, type: retType, isStringBuilder: false };
          } else {
            emit(`${callExpr};`);
          }
        }
      }
      // 18. Unary operations (0x7b..0x8f)
      else if (op >= 0x7b && op <= 0x8f) {
        const src = getRegExpr(ins.vB);
        if (name.startsWith('neg-')) setReg(ins.vA, `(-${src})`, getRegType(ins.vB));
        else if (name.startsWith('not-')) setReg(ins.vA, `(~${src})`, getRegType(ins.vB));
        else {
          const targetType = name.split('-to-')[1] || 'int';
          setReg(ins.vA, `((${targetType}) ${src})`, targetType);
        }
      }
      // 19. Binary operations (23x, 12x /2addr, 22s /lit16, 22b /lit8)
      else if (op >= 0x90 && op <= 0xe2) {
        const OP_SYMBOLS = {
          add: '+', sub: '-', rsub: '-', mul: '*', div: '/', rem: '%',
          and: '&', or: '|', xor: '^', shl: '<<', shr: '>>', ushr: '>>>'
        };
        const baseOp = name.split('-')[0];
        const sym = OP_SYMBOLS[baseOp] || '+';
        const isLong = name.includes('-long');
        const isFloat = name.includes('-float');
        const isDouble = name.includes('-double');
        const resType = isDouble ? 'double' : (isFloat ? 'float' : (isLong ? 'long' : 'int'));

        let binExpr;
        if (op >= 0x90 && op <= 0xaf) {
          binExpr = `(${getRegExpr(ins.vB)} ${sym} ${getRegExpr(ins.vC)})`;
        } else if (op >= 0xb0 && op <= 0xcf) {
          binExpr = `(${getRegExpr(ins.vA)} ${sym} ${getRegExpr(ins.vB)})`;
        } else {
          // lit16 or lit8
          if (baseOp === 'rsub') {
            binExpr = `(${ins.literal} - ${getRegExpr(ins.vB)})`;
          } else {
            binExpr = `(${getRegExpr(ins.vB)} ${sym} ${ins.literal})`;
          }
        }
        if (!assignVarIfLoopMutated(ins.vA, binExpr, resType)) {
          setReg(ins.vA, binExpr, resType);
        }
      }

      if (tryEndAtPc.has(ins.pc)) {
        const tr = tryEndAtPc.get(ins.pc);
        indentLevel = Math.max(2, indentLevel - 1);
        for (const h of tr.handlers) {
          const exType = descriptorToJavaType(h.exceptionType, importsSet);
          emit(`} catch (${exType} e) {`);
          emit(`    // Handler @0x${h.handlerAddr.toString(16)}`);
        }
        emit('}');
      }
    }

    while (indentLevel > 2) {
      indentLevel--;
      statements.push('    '.repeat(indentLevel) + '}');
    }

    const bodyLines = statements.length ? statements.join('\n') : `${indent2}// empty method body`;
    return `${header} {\n${bodyLines}\n${indent1}}\n`;
  }

  function decompileClassToJava(cls, resourceTable = null) {
    if (cls._decompiledCache) return cls._decompiledCache;

    const importsSet = new Set();
    const crossRefs = [];
    const lines = [];

    // Format class declaration
    const cFlags = formatAccessFlags(cls.accessFlags, cls.isInterface ? 'interface' : 'class');
    const kw = cls.isInterface ? 'interface' : (cls.isEnum ? 'enum' : 'class');
    let classDecl = `${cFlags.length ? cFlags.join(' ') + ' ' : ''}${kw} ${cls.simpleName}`;

    if (cls.superDescriptor && cls.superDescriptor !== 'Ljava/lang/Object;' && !cls.isEnum) {
      const superJava = descriptorToJavaType(cls.superDescriptor, importsSet);
      classDecl += ` extends ${superJava}`;
    }
    if (cls.interfaces.length > 0) {
      const ifaceNames = cls.interfaces.map(d => descriptorToJavaType(d, importsSet));
      classDecl += cls.isInterface ? ` extends ${ifaceNames.join(', ')}` : ` implements ${ifaceNames.join(', ')}`;
    }

    // Fields
    const fieldLines = [];
    for (const sf of cls.staticFields) {
      const fFlags = formatAccessFlags(sf.accessFlags, 'field').join(' ');
      const fType = descriptorToJavaType(sf.typeDescriptor, importsSet);
      const initStr = sf.initialValue != null ? ` = ${sf.initialValue}` : '';
      fieldLines.push(`    ${fFlags ? fFlags + ' ' : ''}${fType} ${sf.name}${initStr};`);
    }
    for (const f of cls.instanceFields) {
      const fFlags = formatAccessFlags(f.accessFlags, 'field').join(' ');
      const fType = descriptorToJavaType(f.typeDescriptor, importsSet);
      fieldLines.push(`    ${fFlags ? fFlags + ' ' : ''}${fType} ${f.name};`);
    }

    // Methods
    const methodBlocks = [];
    for (const m of cls.allMethods) {
      methodBlocks.push(decompileMethodToJava(cls, m, importsSet, resourceTable, crossRefs));
    }

    // Assemble file header with package & sorted imports
    if (cls.packageName) {
      lines.push(`package ${cls.packageName};`);
      lines.push('');
    }

    const sortedImports = Array.from(importsSet)
      .filter(imp => {
        const impPkg = imp.slice(0, imp.lastIndexOf('.'));
        return impPkg && impPkg !== cls.packageName;
      })
      .sort();

    if (sortedImports.length > 0) {
      for (const imp of sortedImports) {
        lines.push(`import ${imp};`);
      }
      lines.push('');
    }

    lines.push(`/**`);
    lines.push(` * Decompiled by ArgonDEX Studio`);
    lines.push(` * Source: ${cls.sourceFile || 'Unknown'} (${cls.dexName})`);
    lines.push(` * Descriptor: ${cls.descriptor}`);
    lines.push(` */`);
    lines.push(`${classDecl} {`);
    if (fieldLines.length > 0) {
      lines.push('');
      lines.push(...fieldLines);
    }
    if (methodBlocks.length > 0) {
      lines.push('');
      lines.push(methodBlocks.join('\n'));
    }
    lines.push('}');

    const smali = generateSmaliForClass(cls);
    const result = {
      java: lines.join('\n'),
      smali,
      crossRefs
    };
    cls._decompiledCache = result;
    return result;
  }

  global.ArgonDex = {
    parseDexFile,
    decompileClassToJava,
    generateSmaliForClass,
    buildMethodCFG,
    descriptorToJavaType,
    descriptorToFullClassName,
    formatAccessFlags,
    sanitizeClassPath
  };
})(typeof window !== 'undefined' ? window : globalThis);
