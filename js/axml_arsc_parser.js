/**
 * ArgonDEX Studio - Android Binary XML (AXML) & Resource Table (resources.arsc) Parser
 * Decodes compiled AXML chunks, String Pools (UTF-8 & UTF-16), Resource Maps, and ARSC packages.
 */

(function (global) {
  'use strict';

  // Chunk Types
  const RES_NULL_TYPE               = 0x0000;
  const RES_STRING_POOL_TYPE        = 0x0001;
  const RES_TABLE_TYPE              = 0x0002;
  const RES_XML_TYPE                = 0x0003;
  const RES_XML_START_NAMESPACE_TYPE= 0x0100;
  const RES_XML_END_NAMESPACE_TYPE  = 0x0101;
  const RES_XML_START_ELEMENT_TYPE  = 0x0102;
  const RES_XML_END_ELEMENT_TYPE    = 0x0103;
  const RES_XML_CDATA_TYPE          = 0x0104;
  const RES_XML_RESOURCE_MAP_TYPE   = 0x0180;
  const RES_TABLE_PACKAGE_TYPE      = 0x0200;
  const RES_TABLE_TYPE_TYPE         = 0x0201;
  const RES_TABLE_TYPE_SPEC_TYPE    = 0x0202;

  // Res_value dataType constants
  const TYPE_NULL             = 0x00;
  const TYPE_REFERENCE        = 0x01;
  const TYPE_ATTRIBUTE        = 0x02;
  const TYPE_STRING           = 0x03;
  const TYPE_FLOAT            = 0x04;
  const TYPE_DIMENSION        = 0x05;
  const TYPE_FRACTION         = 0x06;
  const TYPE_DYNAMIC_REFERENCE= 0x07;
  const TYPE_INT_DEC          = 0x10;
  const TYPE_INT_HEX          = 0x11;
  const TYPE_INT_BOOLEAN      = 0x12;
  const TYPE_INT_COLOR_ARGB8  = 0x1c;
  const TYPE_INT_COLOR_RGB8   = 0x1d;
  const TYPE_INT_COLOR_ARGB4  = 0x1e;
  const TYPE_INT_COLOR_RGB4   = 0x1f;

  // Android framework system attribute resource IDs (0x0101xxxx)
  const ANDROID_SYSTEM_ATTRS = {
    0x01010000: 'theme',
    0x01010001: 'label',
    0x01010002: 'icon',
    0x01010003: 'name',
    0x01010006: 'permission',
    0x01010007: 'readPermission',
    0x01010008: 'writePermission',
    0x0101000e: 'enabled',
    0x0101000f: 'debuggable',
    0x01010010: 'exported',
    0x01010011: 'process',
    0x01010012: 'taskAffinity',
    0x01010013: 'multiprocess',
    0x01010018: 'authorities',
    0x0101001b: 'grantUriPermissions',
    0x0101001c: 'priority',
    0x0101001d: 'launchMode',
    0x0101001e: 'screenOrientation',
    0x0101001f: 'configChanges',
    0x01010020: 'description',
    0x01010025: 'mimeType',
    0x01010026: 'scheme',
    0x01010027: 'host',
    0x01010028: 'port',
    0x01010029: 'path',
    0x0101002a: 'pathPrefix',
    0x0101002b: 'pathPattern',
    0x01010063: 'id',
    0x010100d0: 'id',
    0x010100d4: 'background',
    0x010100d5: 'padding',
    0x010100f4: 'layout_width',
    0x010100f5: 'layout_height',
    0x010100c4: 'orientation',
    0x0101014f: 'text',
    0x0101020c: 'minSdkVersion',
    0x0101021b: 'versionCode',
    0x0101021c: 'versionName',
    0x01010270: 'targetSdkVersion',
    0x01010271: 'maxSdkVersion',
    0x01010280: 'allowBackup',
    0x01010281: 'killAfterRestore',
    0x0101028f: 'largeHeap',
    0x010102b7: ' installLocation',
    0x010102c5: 'hardwareAccelerated',
    0x010103a6: 'supportsRtl',
    0x010103f2: 'fullBackupContent',
    0x010104ce: 'extractNativeLibs',
    0x010104ec: 'networkSecurityConfig',
    0x010104f0: 'roundIcon',
    0x0101050c: 'usesCleartextTraffic',
    0x01010540: 'appComponentFactory',
    0x01010572: 'compileSdkVersion',
    0x01010573: 'compileSdkVersionCodename',
    0x01010607: 'dataExtractionRules'
  };

  // Permission metadata for security & manifest inspection
  const PERMISSION_CATALOG = {
    'android.permission.INTERNET': { level: 'normal', desc: 'Full network socket access (HTTP/HTTPS/TCP/UDP).' },
    'android.permission.ACCESS_NETWORK_STATE': { level: 'normal', desc: 'View network connectivity status.' },
    'android.permission.READ_EXTERNAL_STORAGE': { level: 'dangerous', desc: 'Read shared external storage files.' },
    'android.permission.WRITE_EXTERNAL_STORAGE': { level: 'dangerous', desc: 'Modify or delete files on shared external storage.' },
    'android.permission.MANAGE_EXTERNAL_STORAGE': { level: 'dangerous', desc: 'Broad access to all files on external storage.' },
    'android.permission.CAMERA': { level: 'dangerous', desc: 'Capture photos and video from hardware camera.' },
    'android.permission.RECORD_AUDIO': { level: 'dangerous', desc: 'Record microphone audio stream.' },
    'android.permission.ACCESS_FINE_LOCATION': { level: 'dangerous', desc: 'Access precise GPS and network location.' },
    'android.permission.ACCESS_COARSE_LOCATION': { level: 'dangerous', desc: 'Access approximate cell/Wi-Fi location.' },
    'android.permission.ACCESS_BACKGROUND_LOCATION': { level: 'dangerous', desc: 'Track device location while app is in background.' },
    'android.permission.READ_CONTACTS': { level: 'dangerous', desc: 'Read user address book and contact records.' },
    'android.permission.WRITE_CONTACTS': { level: 'dangerous', desc: 'Modify user address book contacts.' },
    'android.permission.READ_SMS': { level: 'dangerous', desc: 'Read SMS/MMS messages (often used for OTP interception).' },
    'android.permission.SEND_SMS': { level: 'dangerous', desc: 'Send SMS messages directly (potential toll fraud risk).' },
    'android.permission.RECEIVE_SMS': { level: 'dangerous', desc: 'Monitor incoming SMS messages.' },
    'android.permission.READ_PHONE_STATE': { level: 'dangerous', desc: 'Read cellular network info, phone state, and call status.' },
    'android.permission.CALL_PHONE': { level: 'dangerous', desc: 'Initiate phone calls without dialer UI confirmation.' },
    'android.permission.READ_CALL_LOG': { level: 'dangerous', desc: 'Read user incoming/outgoing call history.' },
    'android.permission.SYSTEM_ALERT_WINDOW': { level: 'dangerous', desc: 'Draw overlays on top of other apps (tapjacking / overlay risk).' },
    'android.permission.REQUEST_INSTALL_PACKAGES': { level: 'dangerous', desc: 'Prompt installation of arbitrary secondary APK packages.' },
    'android.permission.BIND_ACCESSIBILITY_SERVICE': { level: 'signature|privileged', desc: 'Observe screen contents and perform automated UI actions.' },
    'android.permission.USE_BIOMETRIC': { level: 'normal', desc: 'Use hardware biometric authentication prompt.' },
    'android.permission.USE_FINGERPRINT': { level: 'normal', desc: 'Use fingerprint hardware for authentication.' },
    'android.permission.RECEIVE_BOOT_COMPLETED': { level: 'normal', desc: 'Start background components automatically after device boot.' }
  };

  // ==================== STRING POOL PARSER ====================
  function parseStringPool(bytes, chunkOffset) {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const type = dv.getUint16(chunkOffset, true);
    const headerSize = dv.getUint16(chunkOffset + 2, true);
    const chunkSize = dv.getUint32(chunkOffset + 4, true);
    if (type !== RES_STRING_POOL_TYPE) {
      throw new Error(`Expected RES_STRING_POOL_TYPE (0x0001), got 0x${type.toString(16)}`);
    }

    const stringCount = dv.getUint32(chunkOffset + 8, true);
    const styleCount = dv.getUint32(chunkOffset + 12, true);
    const flags = dv.getUint32(chunkOffset + 16, true);
    const stringsStart = dv.getUint32(chunkOffset + 20, true);
    const isUTF8 = (flags & (1 << 8)) !== 0;

    const offsetsBase = chunkOffset + headerSize;
    const poolBase = chunkOffset + stringsStart;
    const strings = new Array(stringCount);
    const utf8Decoder = new TextDecoder('utf-8', { fatal: false });
    const utf16Decoder = new TextDecoder('utf-16le', { fatal: false });

    for (let i = 0; i < stringCount; i++) {
      const relOffset = dv.getUint32(offsetsBase + i * 4, true);
      let pos = poolBase + relOffset;
      if (pos >= chunkOffset + chunkSize || pos >= bytes.length) {
        strings[i] = '';
        continue;
      }

      if (isUTF8) {
        // UTF-8 length encoded as 1 or 2 bytes (char len, then byte len)
        let charLen = bytes[pos++];
        if (charLen & 0x80) {
          charLen = ((charLen & 0x7F) << 8) | bytes[pos++];
        }
        let byteLen = bytes[pos++];
        if (byteLen & 0x80) {
          byteLen = ((byteLen & 0x7F) << 8) | bytes[pos++];
        }
        strings[i] = utf8Decoder.decode(bytes.subarray(pos, pos + byteLen));
      } else {
        // UTF-16LE length encoded as 1 or 2 16-bit units
        let u16Len = dv.getUint16(pos, true);
        pos += 2;
        if (u16Len & 0x8000) {
          u16Len = ((u16Len & 0x7FFF) << 16) | dv.getUint16(pos, true);
          pos += 2;
        }
        const byteLen = u16Len * 2;
        strings[i] = utf16Decoder.decode(bytes.subarray(pos, pos + byteLen));
      }
    }

    return {
      strings,
      chunkSize,
      isUTF8,
      styleCount
    };
  }

  // ==================== TYPED VALUE FORMATTER ====================
  const DIMENSION_UNITS = ['px', 'dp', 'sp', 'pt', 'in', 'mm'];
  const FRACTION_UNITS = ['%', '%p'];
  const RADIX_MULTS = [1.0 / (1 << 23), 1.0 / (1 << 15), 1.0 / (1 << 7), 1.0];

  function decodeComplexUnit(data, isFraction) {
    const unit = data & 0x0f;
    const radix = (data >> 4) & 0x03;
    const mantissa = (data >> 8) & 0xffffff;
    const signedMantissa = (mantissa & 0x800000) ? (mantissa - 0x1000000) : mantissa;
    const val = signedMantissa * RADIX_MULTS[radix];
    const unitStr = isFraction ? (FRACTION_UNITS[unit] || '%') : (DIMENSION_UNITS[unit] || 'px');
    return `${Math.round(val * 100) / 100}${unitStr}`;
  }

  function formatTypedValue(dataType, data, stringPool, resourceTable = null, attrName = '') {
    switch (dataType) {
      case TYPE_NULL:
        return data === 0 ? null : '@empty';
      case TYPE_REFERENCE:
      case TYPE_DYNAMIC_REFERENCE: {
        if (data === 0) return '@null';
        const hexId = '0x' + (data >>> 0).toString(16).padStart(8, '0');
        if (resourceTable && resourceTable.byId && resourceTable.byId.has(data >>> 0)) {
          const entry = resourceTable.byId.get(data >>> 0);
          return `@${entry.type}/${entry.name}`;
        }
        return `@${hexId}`;
      }
      case TYPE_ATTRIBUTE: {
        const hexId = '0x' + (data >>> 0).toString(16).padStart(8, '0');
        if (resourceTable && resourceTable.byId && resourceTable.byId.has(data >>> 0)) {
          const entry = resourceTable.byId.get(data >>> 0);
          return `?${entry.type}/${entry.name}`;
        }
        return `?${hexId}`;
      }
      case TYPE_STRING:
        return (stringPool && data >= 0 && data < stringPool.length) ? stringPool[data] : `string#${data}`;
      case TYPE_FLOAT: {
        const buf = new ArrayBuffer(4);
        const dv = new DataView(buf);
        dv.setUint32(0, data >>> 0, true);
        return String(Math.round(dv.getFloat32(0, true) * 10000) / 10000);
      }
      case TYPE_DIMENSION:
        return decodeComplexUnit(data, false);
      case TYPE_FRACTION:
        return decodeComplexUnit(data, true);
      case TYPE_INT_DEC: {
        // Signed 32-bit int
        const signed = data | 0;
        if (attrName === 'screenOrientation') {
          const map = { '-1': 'unspecified', 0: 'landscape', 1: 'portrait', 2: 'user', 3: 'behind', 4: 'sensor' };
          if (map[signed]) return map[signed];
        }
        if (attrName === 'launchMode') {
          const map = { 0: 'standard', 1: 'singleTop', 2: 'singleTask', 3: 'singleInstance', 4: 'singleInstancePerTask' };
          if (map[signed]) return map[signed];
        }
        return String(signed);
      }
      case TYPE_INT_HEX:
        return '0x' + (data >>> 0).toString(16);
      case TYPE_INT_BOOLEAN:
        return data !== 0 ? 'true' : 'false';
      case TYPE_INT_COLOR_ARGB8:
        return '#' + (data >>> 0).toString(16).padStart(8, '0');
      case TYPE_INT_COLOR_RGB8:
        return '#' + ((data >>> 0) & 0xFFFFFF).toString(16).padStart(6, '0');
      case TYPE_INT_COLOR_ARGB4:
        return '#' + ((data >>> 0) & 0xFFFF).toString(16).padStart(4, '0');
      case TYPE_INT_COLOR_RGB4:
        return '#' + ((data >>> 0) & 0xFFF).toString(16).padStart(3, '0');
      default:
        return `0x${(data >>> 0).toString(16)}`;
    }
  }

  // ==================== RESOURCES.ARSC PARSER ====================
  function parseResourcesArsc(bytes) {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (bytes.length < 12) throw new Error('resources.arsc too small');

    const rootType = dv.getUint16(0, true);
    const rootHeaderSize = dv.getUint16(2, true);
    const rootChunkSize = dv.getUint32(4, true);
    const packageCount = dv.getUint32(8, true);

    if (rootType !== RES_TABLE_TYPE) {
      throw new Error(`Invalid resources.arsc header: expected 0x0002, got 0x${rootType.toString(16)}`);
    }

    let offset = rootHeaderSize;
    let globalStrings = [];
    const entries = [];
    const byId = new Map();
    const packages = [];

    while (offset + 8 <= bytes.length && offset < rootChunkSize) {
      const cType = dv.getUint16(offset, true);
      const cHeaderSize = dv.getUint16(offset + 2, true);
      const cSize = dv.getUint32(offset + 4, true);
      if (cSize < 8 || offset + cSize > bytes.length) break;

      if (cType === RES_STRING_POOL_TYPE) {
        const pool = parseStringPool(bytes, offset);
        globalStrings = pool.strings;
      } else if (cType === RES_TABLE_PACKAGE_TYPE) {
        const pkgId = dv.getUint32(offset + 8, true);
        // Package name is 128 char16_t (256 bytes) at offset + 12
        const nameBytes = bytes.subarray(offset + 12, offset + 268);
        let pkgName = new TextDecoder('utf-16le').decode(nameBytes);
        const nullIdx = pkgName.indexOf('\0');
        if (nullIdx !== -1) pkgName = pkgName.slice(0, nullIdx);

        const typeStringsOffset = dv.getUint32(offset + 268, true);
        const keyStringsOffset = dv.getUint32(offset + 276, true);

        let typeStrings = [];
        let keyStrings = [];
        if (typeStringsOffset > 0 && offset + typeStringsOffset < bytes.length) {
          typeStrings = parseStringPool(bytes, offset + typeStringsOffset).strings;
        }
        if (keyStringsOffset > 0 && offset + keyStringsOffset < bytes.length) {
          keyStrings = parseStringPool(bytes, offset + keyStringsOffset).strings;
        }

        packages.push({ id: pkgId, name: pkgName, typeCount: typeStrings.length, keyCount: keyStrings.length });

        // Walk inner chunks inside package
        let subPos = offset + cHeaderSize;
        const pkgEnd = Math.min(bytes.length, offset + cSize);

        while (subPos + 8 <= pkgEnd) {
          const sType = dv.getUint16(subPos, true);
          const sHeaderSize = dv.getUint16(subPos + 2, true);
          const sSize = dv.getUint32(subPos + 4, true);
          if (sSize < 8 || subPos + sSize > pkgEnd) break;

          if (sType === RES_TABLE_TYPE_TYPE) {
            const typeId = bytes[subPos + 8]; // 1-based
            const resFlags = bytes[subPos + 9];
            const entryCount = dv.getUint32(subPos + 12, true);
            const entriesStart = dv.getUint32(subPos + 16, true);
            const typeName = typeStrings[typeId - 1] || `type_${typeId}`;
            const isSparse = (resFlags & 0x01) !== 0;

            const offsetsStart = subPos + sHeaderSize;
            const dataStart = subPos + entriesStart;

            if (!isSparse) {
              for (let eIdx = 0; eIdx < entryCount; eIdx++) {
                if (offsetsStart + eIdx * 4 + 4 > pkgEnd) break;
                const entryOffset = dv.getUint32(offsetsStart + eIdx * 4, true);
                if (entryOffset === 0xFFFFFFFF) continue; // NO_ENTRY

                const ePos = dataStart + entryOffset;
                if (ePos + 8 > pkgEnd) continue;

                const eSize = dv.getUint16(ePos, true);
                const eFlags = dv.getUint16(ePos + 2, true);
                const keyIdx = dv.getUint32(ePos + 4, true);
                const keyName = keyStrings[keyIdx] || `res_${eIdx}`;
                const resId = ((pkgId & 0xFF) << 24) | ((typeId & 0xFF) << 16) | (eIdx & 0xFFFF);
                const idHex = '0x' + (resId >>> 0).toString(16).padStart(8, '0');

                let valStr = '(complex/bag)';
                if ((eFlags & 0x0001) === 0 && ePos + eSize + 8 <= pkgEnd) {
                  // Simple Res_value follows immediately after ResTable_entry
                  const vType = bytes[ePos + eSize + 3];
                  const vData = dv.getUint32(ePos + eSize + 4, true);
                  valStr = formatTypedValue(vType, vData, globalStrings, null);
                }

                const record = {
                  id: resId >>> 0,
                  idHex,
                  packageName: pkgName,
                  type: typeName,
                  name: keyName,
                  value: valStr
                };
                if (!byId.has(resId >>> 0)) {
                  byId.set(resId >>> 0, record);
                  entries.push(record);
                }
              }
            }
          }
          subPos += sSize;
        }
      }
      offset += cSize;
    }

    return {
      packages,
      globalStringCount: globalStrings.length,
      entries,
      byId
    };
  }

  // ==================== BINARY XML (AXML) PARSER ====================
  function escapeXml(str) {
    if (str == null) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function parseAxml(bytes, resourceTable = null) {
    // Check if already plain text XML
    if (bytes.length >= 5 && bytes[0] === 0x3C) { // '<'
      const plainXml = new TextDecoder('utf-8').decode(bytes);
      return {
        isBinary: false,
        xml: plainXml,
        root: null,
        stringPool: [],
        resourceIds: []
      };
    }

    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (bytes.length < 8) throw new Error('AXML file too small');

    const fileType = dv.getUint16(0, true);
    const fileHeaderSize = dv.getUint16(2, true);
    const fileSize = dv.getUint32(4, true);

    if (fileType !== RES_XML_TYPE) {
      throw new Error(`Invalid AXML header: expected 0x0003, got 0x${fileType.toString(16)}`);
    }

    let offset = fileHeaderSize;
    let stringPool = [];
    const resourceIds = [];
    const nsPrefixByUri = new Map();
    const pendingNamespaces = [];

    const rootHolder = { children: [] };
    const stack = [rootHolder];

    function getStr(idx) {
      if (idx === 0xFFFFFFFF || idx < 0 || idx >= stringPool.length) return null;
      return stringPool[idx];
    }

    function resolveAttrName(nameIdx, nsIdx) {
      let rawName = getStr(nameIdx);
      if ((!rawName || rawName === '') && nameIdx < resourceIds.length) {
        const resId = resourceIds[nameIdx];
        if (ANDROID_SYSTEM_ATTRS[resId]) {
          rawName = ANDROID_SYSTEM_ATTRS[resId];
        } else if (resourceTable && resourceTable.byId && resourceTable.byId.has(resId)) {
          rawName = resourceTable.byId.get(resId).name;
        } else {
          rawName = `attr_0x${resId.toString(16)}`;
        }
      }
      const nsUri = getStr(nsIdx);
      let prefix = nsUri ? nsPrefixByUri.get(nsUri) : null;
      if (!prefix && nameIdx < resourceIds.length && (resourceIds[nameIdx] >>> 24) === 0x01) {
        prefix = 'android';
      }
      return {
        rawName: rawName || `attr_${nameIdx}`,
        qName: prefix ? `${prefix}:${rawName}` : (rawName || `attr_${nameIdx}`)
      };
    }

    while (offset + 8 <= bytes.length && offset < fileSize) {
      const cType = dv.getUint16(offset, true);
      const cHeaderSize = dv.getUint16(offset + 2, true);
      const cSize = dv.getUint32(offset + 4, true);
      if (cSize < 8 || offset + cSize > bytes.length) break;

      if (cType === RES_STRING_POOL_TYPE) {
        const pool = parseStringPool(bytes, offset);
        stringPool = pool.strings;
      } else if (cType === RES_XML_RESOURCE_MAP_TYPE) {
        const count = Math.floor((cSize - cHeaderSize) / 4);
        for (let i = 0; i < count; i++) {
          resourceIds.push(dv.getUint32(offset + cHeaderSize + i * 4, true));
        }
      } else if (cType === RES_XML_START_NAMESPACE_TYPE) {
        const prefixIdx = dv.getUint32(offset + 16, true);
        const uriIdx = dv.getUint32(offset + 20, true);
        const prefix = getStr(prefixIdx) || 'android';
        const uri = getStr(uriIdx) || 'http://schemas.android.com/apk/res/android';
        nsPrefixByUri.set(uri, prefix);
        pendingNamespaces.push({ prefix, uri });
      } else if (cType === RES_XML_START_ELEMENT_TYPE) {
        const lineNumber = dv.getUint32(offset + 8, true);
        const nsIdx = dv.getUint32(offset + 16, true);
        const nameIdx = dv.getUint32(offset + 20, true);
        const attrStart = dv.getUint16(offset + 24, true);
        const attrSize = dv.getUint16(offset + 26, true);
        const attrCount = dv.getUint16(offset + 28, true);

        const tagName = getStr(nameIdx) || 'unknown';
        const nsUri = getStr(nsIdx);
        const tagPrefix = nsUri ? nsPrefixByUri.get(nsUri) : null;
        const qTagName = tagPrefix ? `${tagPrefix}:${tagName}` : tagName;

        const attributes = [];
        const attrMap = {};

        for (const ns of pendingNamespaces) {
          attributes.push({
            name: `xmlns:${ns.prefix}`,
            rawName: ns.prefix,
            value: ns.uri
          });
        }
        pendingNamespaces.length = 0;

        let attrPos = offset + cHeaderSize + attrStart;
        for (let a = 0; a < attrCount; a++) {
          if (attrPos + 20 > offset + cSize) break;
          const aNsIdx = dv.getUint32(attrPos, true);
          const aNameIdx = dv.getUint32(attrPos + 4, true);
          const aRawValIdx = dv.getUint32(attrPos + 8, true);
          const aDataType = bytes[attrPos + 15];
          const aData = dv.getUint32(attrPos + 16, true);

          const { rawName, qName } = resolveAttrName(aNameIdx, aNsIdx);
          let val = formatTypedValue(aDataType, aData, stringPool, resourceTable, rawName);
          if ((aDataType === TYPE_STRING || val == null) && aRawValIdx !== 0xFFFFFFFF) {
            val = getStr(aRawValIdx);
          }

          attributes.push({
            name: qName,
            rawName,
            value: val != null ? String(val) : '',
            dataType: aDataType,
            rawData: aData
          });
          attrMap[qName] = val != null ? String(val) : '';
          attrMap[rawName] = val != null ? String(val) : '';

          attrPos += attrSize || 20;
        }

        const node = {
          tag: qTagName,
          rawTag: tagName,
          lineNumber,
          attributes,
          attrMap,
          children: [],
          text: ''
        };

        stack[stack.length - 1].children.push(node);
        stack.push(node);
      } else if (cType === RES_XML_END_ELEMENT_TYPE) {
        if (stack.length > 1) stack.pop();
      } else if (cType === RES_XML_CDATA_TYPE) {
        const dataIdx = dv.getUint32(offset + 16, true);
        const text = getStr(dataIdx);
        if (text && stack.length > 1) {
          stack[stack.length - 1].text += text;
        }
      }

      offset += cSize;
    }

    // Reconstruct well-formatted XML text
    const lines = ['<?xml version="1.0" encoding="utf-8"?>'];
    function renderNode(node, depth) {
      const indent = '    '.repeat(depth);
      const attrs = node.attributes.map(a => `${a.name}="${escapeXml(a.value)}"`);
      let openTag = `${indent}<${node.tag}`;
      if (attrs.length === 1) {
        openTag += ` ${attrs[0]}`;
      } else if (attrs.length > 1) {
        openTag += '\n' + attrs.map(a => `${indent}    ${a}`).join('\n');
      }

      if (node.children.length === 0 && !node.text) {
        lines.push(`${openTag} />`);
      } else if (node.children.length === 0 && node.text) {
        lines.push(`${openTag}>${escapeXml(node.text)}</${node.tag}>`);
      } else {
        lines.push(`${openTag}>`);
        for (const child of node.children) {
          renderNode(child, depth + 1);
        }
        lines.push(`${indent}</${node.tag}>`);
      }
    }

    const rootNode = rootHolder.children[0] || null;
    if (rootNode) {
      renderNode(rootNode, 0);
    }

    return {
      isBinary: true,
      xml: lines.join('\n'),
      root: rootNode,
      stringPool,
      resourceIds
    };
  }

  // ==================== ANDROID MANIFEST SEMANTIC ANALYZER ====================
  function analyzeManifest(parsedAxml) {
    const root = parsedAxml.root;
    if (!root) {
      return {
        packageName: 'unknown.package',
        versionCode: '1',
        versionName: '1.0',
        minSdkVersion: '21',
        targetSdkVersion: '34',
        compileSdkVersion: '34',
        debuggable: false,
        allowBackup: true,
        usesCleartextTraffic: false,
        networkSecurityConfig: null,
        permissions: [],
        activities: [],
        services: [],
        receivers: [],
        providers: [],
        deepLinks: []
      };
    }

    const pkg = root.attrMap['package'] || 'unknown.package';
    const versionCode = root.attrMap['versionCode'] || '1';
    const versionName = root.attrMap['versionName'] || '1.0';
    const compileSdkVersion = root.attrMap['compileSdkVersion'] || '34';

    let minSdkVersion = '21';
    let targetSdkVersion = '34';
    const permissions = [];
    const activities = [];
    const services = [];
    const receivers = [];
    const providers = [];
    const deepLinks = [];

    let appAttrs = {};

    function normalizeCompName(name) {
      if (!name) return '';
      if (name.startsWith('.')) return pkg + name;
      if (!name.includes('.')) return pkg + '.' + name;
      return name;
    }

    function extractIntentFilters(compNode, compName, compType) {
      const filters = [];
      for (const child of compNode.children) {
        if (child.rawTag === 'intent-filter') {
          const actions = [];
          const categories = [];
          const dataSpecs = [];
          for (const item of child.children) {
            if (item.rawTag === 'action' && item.attrMap['name']) {
              actions.push(item.attrMap['name']);
            } else if (item.rawTag === 'category' && item.attrMap['name']) {
              categories.push(item.attrMap['name']);
            } else if (item.rawTag === 'data') {
              const scheme = item.attrMap['scheme'] || '';
              const host = item.attrMap['host'] || '';
              const path = item.attrMap['path'] || item.attrMap['pathPrefix'] || '';
              const mimeType = item.attrMap['mimeType'] || '';
              dataSpecs.push({ scheme, host, path, mimeType });
              if (scheme) {
                deepLinks.push({
                  component: compName,
                  componentType: compType,
                  uri: `${scheme}://${host}${path}`,
                  browsable: categories.includes('android.intent.category.BROWSABLE')
                });
              }
            }
          }
          filters.push({ actions, categories, data: dataSpecs });
        }
      }
      return filters;
    }

    for (const node of root.children) {
      if (node.rawTag === 'uses-sdk') {
        if (node.attrMap['minSdkVersion']) minSdkVersion = node.attrMap['minSdkVersion'];
        if (node.attrMap['targetSdkVersion']) targetSdkVersion = node.attrMap['targetSdkVersion'];
      } else if (node.rawTag === 'uses-permission' || node.rawTag === 'uses-permission-sdk-23') {
        const permName = node.attrMap['name'] || '';
        const meta = PERMISSION_CATALOG[permName] || {
          level: permName.includes('WRITE') || permName.includes('READ') || permName.includes('LOCATION') ? 'dangerous' : 'normal',
          desc: 'Application or platform permission.'
        };
        permissions.push({
          name: permName,
          level: meta.level,
          description: meta.desc
        });
      } else if (node.rawTag === 'application') {
        appAttrs = node.attrMap;
        for (const comp of node.children) {
          const rawName = comp.attrMap['name'] || '';
          const fullName = normalizeCompName(rawName);
          const intentFilters = extractIntentFilters(comp, fullName, comp.rawTag);
          const hasIntentFilter = intentFilters.length > 0;
          // In Android < 12, components with intent-filters default to exported=true
          const explicitExported = comp.attrMap['exported'];
          const isExported = explicitExported !== undefined
            ? explicitExported === 'true'
            : hasIntentFilter;
          const permission = comp.attrMap['permission'] || null;

          const record = {
            name: fullName,
            shortName: rawName,
            exported: isExported,
            explicitExported: explicitExported !== undefined,
            permission,
            enabled: comp.attrMap['enabled'] !== 'false',
            intentFilters,
            isMainLauncher: intentFilters.some(
              f => f.actions.includes('android.intent.action.MAIN') &&
                   f.categories.includes('android.intent.category.LAUNCHER')
            )
          };

          if (comp.rawTag === 'activity' || comp.rawTag === 'activity-alias') {
            record.launchMode = comp.attrMap['launchMode'] || 'standard';
            activities.push(record);
          } else if (comp.rawTag === 'service') {
            services.push(record);
          } else if (comp.rawTag === 'receiver') {
            receivers.push(record);
          } else if (comp.rawTag === 'provider') {
            record.authorities = comp.attrMap['authorities'] || '';
            record.grantUriPermissions = comp.attrMap['grantUriPermissions'] === 'true';
            providers.push(record);
          }
        }
      }
    }

    return {
      packageName: pkg,
      versionCode,
      versionName,
      minSdkVersion,
      targetSdkVersion,
      compileSdkVersion,
      appLabel: appAttrs['label'] || pkg,
      appIcon: appAttrs['icon'] || '',
      applicationClass: appAttrs['name'] ? normalizeCompName(appAttrs['name']) : null,
      debuggable: appAttrs['debuggable'] === 'true',
      allowBackup: appAttrs['allowBackup'] !== 'false',
      usesCleartextTraffic: appAttrs['usesCleartextTraffic'] === 'true',
      networkSecurityConfig: appAttrs['networkSecurityConfig'] || null,
      extractNativeLibs: appAttrs['extractNativeLibs'] !== 'false',
      permissions,
      activities,
      services,
      receivers,
      providers,
      deepLinks
    };
  }

  global.ArgonAxml = {
    parseStringPool,
    parseResourcesArsc,
    parseAxml,
    analyzeManifest,
    ANDROID_SYSTEM_ATTRS,
    PERMISSION_CATALOG
  };
})(typeof window !== 'undefined' ? window : globalThis);
