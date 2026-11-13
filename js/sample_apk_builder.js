/**
 * ArgonDEX Studio - Binary Android APK Synthesizer
 * Builds a complete, binary-accurate Android APK in memory (AXML, ARSC, DEX, ELF .so, X.509, APK Sig Block v2)
 * so users can immediately test deep decompilation, CFG, Smali, ARSC resolution, JNI bridging, and security auditing,
 * or download the generated .apk file to inspect in external tools.
 */

(function (global) {
  'use strict';

  // ==================== BINARY BUFFER WRITER ====================
  class BinaryWriter {
    constructor(initialCapacity = 4096) {
      this.buf = new Uint8Array(initialCapacity);
      this.pos = 0;
    }
    ensure(extra) {
      if (this.pos + extra <= this.buf.length) return;
      let nextLen = this.buf.length * 2;
      while (nextLen < this.pos + extra) nextLen *= 2;
      const next = new Uint8Array(nextLen);
      next.set(this.buf.subarray(0, this.pos));
      this.buf = next;
    }
    align4() {
      while (this.pos % 4 !== 0) this.u8(0);
    }
    u8(v) {
      this.ensure(1);
      this.buf[this.pos++] = v & 0xff;
    }
    u16(v) {
      this.ensure(2);
      this.buf[this.pos++] = v & 0xff;
      this.buf[this.pos++] = (v >>> 8) & 0xff;
    }
    s16(v) {
      this.u16(v & 0xffff);
    }
    u32(v) {
      this.ensure(4);
      this.buf[this.pos++] = v & 0xff;
      this.buf[this.pos++] = (v >>> 8) & 0xff;
      this.buf[this.pos++] = (v >>> 16) & 0xff;
      this.buf[this.pos++] = (v >>> 24) & 0xff;
    }
    s32(v) {
      this.u32(v >>> 0);
    }
    u64(lo, hi = 0) {
      this.u32(lo);
      this.u32(hi);
    }
    bytes(arr) {
      this.ensure(arr.length);
      this.buf.set(arr, this.pos);
      this.pos += arr.length;
    }
    uleb128(val) {
      let v = val >>> 0;
      do {
        let b = v & 0x7f;
        v >>>= 7;
        if (v !== 0) b |= 0x80;
        this.u8(b);
      } while (v !== 0);
    }
    sleb128(val) {
      let v = val | 0;
      let more = true;
      while (more) {
        let b = v & 0x7f;
        v >>= 7;
        if ((v === 0 && (b & 0x40) === 0) || (v === -1 && (b & 0x40) !== 0)) {
          more = false;
        } else {
          b |= 0x80;
        }
        this.u8(b);
      }
    }
    toUint8Array() {
      return this.buf.slice(0, this.pos);
    }
  }

  // ==================== UTF-16LE STRING POOL BUILDER (FOR AXML & ARSC) ====================
  function buildStringPoolChunk(strings) {
    const strBuffers = [];
    const offsets = [];
    let currentOffset = 0;

    for (const s of strings) {
      offsets.push(currentOffset);
      const u16Len = s.length;
      const b = new Uint8Array(2 + u16Len * 2 + 2);
      const dv = new DataView(b.buffer);
      dv.setUint16(0, u16Len, true);
      for (let i = 0; i < u16Len; i++) {
        dv.setUint16(2 + i * 2, s.charCodeAt(i), true);
      }
      dv.setUint16(2 + u16Len * 2, 0, true); // null terminator
      strBuffers.push(b);
      currentOffset += b.length;
    }

    const w = new BinaryWriter();
    const headerSize = 28;
    const stringsStart = headerSize + strings.length * 4;
    let totalDataLen = currentOffset;
    const pad = (4 - (totalDataLen % 4)) % 4;
    const chunkSize = stringsStart + totalDataLen + pad;

    w.u16(0x0001); // RES_STRING_POOL_TYPE
    w.u16(headerSize);
    w.u32(chunkSize);
    w.u32(strings.length);
    w.u32(0); // styleCount
    w.u32(0); // flags (UTF-16LE)
    w.u32(stringsStart);
    w.u32(0); // stylesStart
    for (const off of offsets) w.u32(off);
    for (const b of strBuffers) w.bytes(b);
    w.align4();
    return w.toUint8Array();
  }

  // ==================== BINARY AXML BUILDER ====================
  function buildBinaryAxml(treeSpec) {
    // treeSpec: { namespaces: [{prefix, uri}], root: { tag, attrs: [{ns, name, resId, type, data, rawStr}], children: [...] } }
    const stringSet = new Map();
    const attrNameStrings = [];
    const attrResIds = [];

    function addString(s) {
      if (s == null) return 0xFFFFFFFF;
      if (stringSet.has(s)) return stringSet.get(s);
      const idx = stringSet.size;
      stringSet.set(s, idx);
      return idx;
    }

    // First register all attribute names that have system resource IDs so they sit at indices 0..K-1
    function collectResAttrs(node) {
      for (const a of (node.attrs || [])) {
        if (a.resId && !stringSet.has(a.name)) {
          addString(a.name);
          attrResIds.push(a.resId);
        }
      }
      for (const c of (node.children || [])) collectResAttrs(c);
    }
    collectResAttrs(treeSpec.root);

    // Register remaining strings
    for (const ns of (treeSpec.namespaces || [])) {
      addString(ns.prefix);
      addString(ns.uri);
    }
    function collectAllStrings(node) {
      addString(node.tag);
      for (const a of (node.attrs || [])) {
        addString(a.name);
        if (a.rawStr != null) addString(a.rawStr);
      }
      for (const c of (node.children || [])) collectAllStrings(c);
    }
    collectAllStrings(treeSpec.root);

    const poolBytes = buildStringPoolChunk(Array.from(stringSet.keys()));

    // Resource Map Chunk (0x0180)
    const resMapW = new BinaryWriter();
    resMapW.u16(0x0180);
    resMapW.u16(8);
    resMapW.u32(8 + attrResIds.length * 4);
    for (const id of attrResIds) resMapW.u32(id);
    const resMapBytes = resMapW.toUint8Array();

    // XML Body Chunks
    const bodyW = new BinaryWriter();
    let lineNo = 2;

    for (const ns of (treeSpec.namespaces || [])) {
      bodyW.u16(0x0100); // START_NAMESPACE
      bodyW.u16(16);
      bodyW.u32(24);
      bodyW.u32(lineNo);
      bodyW.u32(0xFFFFFFFF);
      bodyW.u32(addString(ns.prefix));
      bodyW.u32(addString(ns.uri));
    }

    function writeElement(node) {
      const myLine = lineNo++;
      const attrs = node.attrs || [];
      const chunkSize = 36 + attrs.length * 20;

      bodyW.u16(0x0102); // START_ELEMENT
      bodyW.u16(16);
      bodyW.u32(chunkSize);
      bodyW.u32(myLine);
      bodyW.u32(0xFFFFFFFF);
      bodyW.u32(0xFFFFFFFF); // elem ns
      bodyW.u32(addString(node.tag));
      bodyW.u16(20); // attrStart
      bodyW.u16(20); // attrSize
      bodyW.u16(attrs.length);
      bodyW.u16(0); // idIndex
      bodyW.u16(0); // classIndex
      bodyW.u16(0); // styleIndex

      for (const a of attrs) {
        const nsIdx = a.ns ? addString(a.ns) : 0xFFFFFFFF;
        const nameIdx = addString(a.name);
        const rawValIdx = a.rawStr != null ? addString(a.rawStr) : 0xFFFFFFFF;
        const dataType = a.type;
        const data = a.type === 0x03 ? rawValIdx : (a.data >>> 0);

        bodyW.u32(nsIdx);
        bodyW.u32(nameIdx);
        bodyW.u32(rawValIdx);
        bodyW.u16(8); // Res_value size
        bodyW.u8(0);  // res0
        bodyW.u8(dataType);
        bodyW.u32(data);
      }

      for (const child of (node.children || [])) {
        writeElement(child);
      }

      bodyW.u16(0x0103); // END_ELEMENT
      bodyW.u16(16);
      bodyW.u32(24);
      bodyW.u32(lineNo++);
      bodyW.u32(0xFFFFFFFF);
      bodyW.u32(0xFFFFFFFF);
      bodyW.u32(addString(node.tag));
    }

    writeElement(treeSpec.root);

    for (const ns of (treeSpec.namespaces || []).slice().reverse()) {
      bodyW.u16(0x0101); // END_NAMESPACE
      bodyW.u16(16);
      bodyW.u32(24);
      bodyW.u32(lineNo++);
      bodyW.u32(0xFFFFFFFF);
      bodyW.u32(addString(ns.prefix));
      bodyW.u32(addString(ns.uri));
    }

    const bodyBytes = bodyW.toUint8Array();
    const totalSize = 8 + poolBytes.length + resMapBytes.length + bodyBytes.length;

    const finalW = new BinaryWriter(totalSize);
    finalW.u16(0x0003); // RES_XML_TYPE
    finalW.u16(8);
    finalW.u32(totalSize);
    finalW.bytes(poolBytes);
    finalW.bytes(resMapBytes);
    finalW.bytes(bodyBytes);
    return finalW.toUint8Array();
  }

  // ==================== BINARY RESOURCES.ARSC BUILDER ====================
  function buildSampleResourcesArsc() {
    const globalStrings = [
      'ArgonVault Security Suite',
      'http://api.argonvault.internal/v2/sync',
      'res/layout/activity_main.xml',
      'Unlock Hardware Vault',
      'Vault Status: Locked (AES-256 + TEE)'
    ];
    const typeStrings = ['string', 'layout', 'id', 'color'];
    const keyStrings = [
      'app_name',            // 0 -> 0x7f010000
      'vault_sync_endpoint', // 1 -> 0x7f010001
      'btn_unlock_label',    // 2 -> 0x7f010002
      'status_default',      // 3 -> 0x7f010003
      'activity_main',       // 4 -> 0x7f020000
      'btn_unlock',          // 5 -> 0x7f030000
      'txt_status',          // 6 -> 0x7f030001
      'webview_portal',      // 7 -> 0x7f030002
      'argon_cyan'           // 8 -> 0x7f040000
    ];

    const globalPool = buildStringPoolChunk(globalStrings);
    const typePool = buildStringPoolChunk(typeStrings);
    const keyPool = buildStringPoolChunk(keyStrings);

    function buildTypeChunk(typeId, entriesList) {
      // entriesList: Array of { keyIdx, dataType, data }
      const tw = new BinaryWriter();
      const headerSize = 52;
      const offsetsSize = entriesList.length * 4;
      const entriesStart = headerSize + offsetsSize;
      const chunkSize = entriesStart + entriesList.length * 16;

      tw.u16(0x0201); // RES_TABLE_TYPE_TYPE
      tw.u16(headerSize);
      tw.u32(chunkSize);
      tw.u8(typeId);
      tw.u8(0); // flags
      tw.u16(0);
      tw.u32(entriesList.length);
      tw.u32(entriesStart);
      // 32-byte ResTable_config
      tw.u32(32);
      for (let i = 0; i < 7; i++) tw.u32(0);

      for (let i = 0; i < entriesList.length; i++) {
        tw.u32(i * 16);
      }
      for (const e of entriesList) {
        tw.u16(8); // entry header size
        tw.u16(0); // simple entry
        tw.u32(e.keyIdx);
        tw.u16(8); // Res_value size
        tw.u8(0);
        tw.u8(e.dataType);
        tw.u32(e.data >>> 0);
      }
      return tw.toUint8Array();
    }

    const stringTypeChunk = buildTypeChunk(1, [
      { keyIdx: 0, dataType: 0x03, data: 0 }, // @string/app_name -> 0x7f010000
      { keyIdx: 1, dataType: 0x03, data: 1 }, // @string/vault_sync_endpoint -> 0x7f010001
      { keyIdx: 2, dataType: 0x03, data: 3 }, // @string/btn_unlock_label -> 0x7f010002
      { keyIdx: 3, dataType: 0x03, data: 4 }  // @string/status_default -> 0x7f010003
    ]);
    const layoutTypeChunk = buildTypeChunk(2, [
      { keyIdx: 4, dataType: 0x03, data: 2 }  // @layout/activity_main -> 0x7f020000
    ]);
    const idTypeChunk = buildTypeChunk(3, [
      { keyIdx: 5, dataType: 0x12, data: 0 }, // @id/btn_unlock -> 0x7f030000
      { keyIdx: 6, dataType: 0x12, data: 0 }, // @id/txt_status -> 0x7f030001
      { keyIdx: 7, dataType: 0x12, data: 0 }  // @id/webview_portal -> 0x7f030002
    ]);
    const colorTypeChunk = buildTypeChunk(4, [
      { keyIdx: 8, dataType: 0x1c, data: 0xFF00E5FF } // @color/argon_cyan -> 0x7f040000
    ]);

    const pkgHeaderSize = 288;
    const typeStringsOff = pkgHeaderSize;
    const keyStringsOff = typeStringsOff + typePool.length;
    const pkgBodySize = typePool.length + keyPool.length +
      stringTypeChunk.length + layoutTypeChunk.length + idTypeChunk.length + colorTypeChunk.length;
    const pkgTotalSize = pkgHeaderSize + pkgBodySize;

    const pw = new BinaryWriter(pkgTotalSize);
    pw.u16(0x0200); // RES_TABLE_PACKAGE_TYPE
    pw.u16(pkgHeaderSize);
    pw.u32(pkgTotalSize);
    pw.u32(0x7f); // package ID = 0x7f
    const pkgName = 'com.argon.vault';
    for (let i = 0; i < 128; i++) {
      pw.u16(i < pkgName.length ? pkgName.charCodeAt(i) : 0);
    }
    pw.u32(typeStringsOff);
    pw.u32(0); // lastPublicType
    pw.u32(keyStringsOff);
    pw.u32(0); // lastPublicKey
    pw.u32(0); // typeIdOffset
    pw.bytes(typePool);
    pw.bytes(keyPool);
    pw.bytes(stringTypeChunk);
    pw.bytes(layoutTypeChunk);
    pw.bytes(idTypeChunk);
    pw.bytes(colorTypeChunk);
    const pkgBytes = pw.toUint8Array();

    const rootTotal = 12 + globalPool.length + pkgBytes.length;
    const rw = new BinaryWriter(rootTotal);
    rw.u16(0x0002); // RES_TABLE_TYPE
    rw.u16(12);
    rw.u32(rootTotal);
    rw.u32(1); // packageCount
    rw.bytes(globalPool);
    rw.bytes(pkgBytes);
    return rw.toUint8Array();
  }

  // ==================== BINARY MANIFEST & LAYOUT BUILDERS ====================
  function buildSampleManifestAxml() {
    const NS_ANDROID = 'http://schemas.android.com/apk/res/android';
    const strAttr = (ns, name, resId, val) => ({ ns, name, resId, type: 0x03, data: 0, rawStr: val });
    const intAttr = (ns, name, resId, val) => ({ ns, name, resId, type: 0x10, data: val, rawStr: null });
    const boolAttr = (ns, name, resId, val) => ({ ns, name, resId, type: 0x12, data: val ? 0xFFFFFFFF : 0, rawStr: null });
    const refAttr = (ns, name, resId, val) => ({ ns, name, resId, type: 0x01, data: val, rawStr: null });

    return buildBinaryAxml({
      namespaces: [{ prefix: 'android', uri: NS_ANDROID }],
      root: {
        tag: 'manifest',
        attrs: [
          strAttr(null, 'package', 0, 'com.argon.vault'),
          intAttr(NS_ANDROID, 'versionCode', 0x0101021b, 20401),
          strAttr(NS_ANDROID, 'versionName', 0x0101021c, '2.4.1-argon'),
          intAttr(NS_ANDROID, 'compileSdkVersion', 0x01010572, 34)
        ],
        children: [
          {
            tag: 'uses-sdk',
            attrs: [
              intAttr(NS_ANDROID, 'minSdkVersion', 0x0101020c, 26),
              intAttr(NS_ANDROID, 'targetSdkVersion', 0x01010270, 34)
            ],
            children: []
          },
          { tag: 'uses-permission', attrs: [strAttr(NS_ANDROID, 'name', 0x01010003, 'android.permission.INTERNET')], children: [] },
          { tag: 'uses-permission', attrs: [strAttr(NS_ANDROID, 'name', 0x01010003, 'android.permission.ACCESS_NETWORK_STATE')], children: [] },
          { tag: 'uses-permission', attrs: [strAttr(NS_ANDROID, 'name', 0x01010003, 'android.permission.USE_BIOMETRIC')], children: [] },
          { tag: 'uses-permission', attrs: [strAttr(NS_ANDROID, 'name', 0x01010003, 'android.permission.READ_EXTERNAL_STORAGE')], children: [] },
          { tag: 'uses-permission', attrs: [strAttr(NS_ANDROID, 'name', 0x01010003, 'android.permission.CAMERA')], children: [] },
          {
            tag: 'application',
            attrs: [
              refAttr(NS_ANDROID, 'label', 0x01010001, 0x7f010000),
              boolAttr(NS_ANDROID, 'debuggable', 0x0101000f, true),
              boolAttr(NS_ANDROID, 'allowBackup', 0x01010280, true),
              boolAttr(NS_ANDROID, 'usesCleartextTraffic', 0x0101050c, true),
              boolAttr(NS_ANDROID, 'supportsRtl', 0x010103a6, true)
            ],
            children: [
              {
                tag: 'activity',
                attrs: [
                  strAttr(NS_ANDROID, 'name', 0x01010003, 'com.argon.vault.MainActivity'),
                  boolAttr(NS_ANDROID, 'exported', 0x01010010, true)
                ],
                children: [
                  {
                    tag: 'intent-filter',
                    attrs: [],
                    children: [
                      { tag: 'action', attrs: [strAttr(NS_ANDROID, 'name', 0x01010003, 'android.intent.action.MAIN')], children: [] },
                      { tag: 'category', attrs: [strAttr(NS_ANDROID, 'name', 0x01010003, 'android.intent.category.LAUNCHER')], children: [] }
                    ]
                  },
                  {
                    tag: 'intent-filter',
                    attrs: [],
                    children: [
                      { tag: 'action', attrs: [strAttr(NS_ANDROID, 'name', 0x01010003, 'android.intent.action.VIEW')], children: [] },
                      { tag: 'category', attrs: [strAttr(NS_ANDROID, 'name', 0x01010003, 'android.intent.category.DEFAULT')], children: [] },
                      { tag: 'category', attrs: [strAttr(NS_ANDROID, 'name', 0x01010003, 'android.intent.category.BROWSABLE')], children: [] },
                      {
                        tag: 'data',
                        attrs: [
                          strAttr(NS_ANDROID, 'scheme', 0x01010026, 'argonvault'),
                          strAttr(NS_ANDROID, 'host', 0x01010027, 'unlock'),
                          strAttr(NS_ANDROID, 'pathPrefix', 0x0101002a, '/token')
                        ],
                        children: []
                      }
                    ]
                  }
                ]
              },
              {
                tag: 'service',
                attrs: [
                  strAttr(NS_ANDROID, 'name', 0x01010003, 'com.argon.vault.net.VaultSyncService'),
                  boolAttr(NS_ANDROID, 'exported', 0x01010010, true)
                ],
                children: []
              },
              {
                tag: 'provider',
                attrs: [
                  strAttr(NS_ANDROID, 'name', 0x01010003, 'com.argon.vault.db.VaultContentProvider'),
                  strAttr(NS_ANDROID, 'authorities', 0x01010018, 'com.argon.vault.provider'),
                  boolAttr(NS_ANDROID, 'exported', 0x01010010, true),
                  boolAttr(NS_ANDROID, 'grantUriPermissions', 0x0101001b, true)
                ],
                children: []
              }
            ]
          }
        ]
      }
    });
  }

  function buildSampleLayoutAxml() {
    const NS_ANDROID = 'http://schemas.android.com/apk/res/android';
    const strAttr = (ns, name, resId, val) => ({ ns, name, resId, type: 0x03, data: 0, rawStr: val });
    const intAttr = (ns, name, resId, val) => ({ ns, name, resId, type: 0x10, data: val, rawStr: null });
    const refAttr = (ns, name, resId, val) => ({ ns, name, resId, type: 0x01, data: val, rawStr: null });
    const colorAttr = (ns, name, resId, val) => ({ ns, name, resId, type: 0x1c, data: val, rawStr: null });

    return buildBinaryAxml({
      namespaces: [{ prefix: 'android', uri: NS_ANDROID }],
      root: {
        tag: 'LinearLayout',
        attrs: [
          intAttr(NS_ANDROID, 'orientation', 0x010100c4, 1),
          intAttr(NS_ANDROID, 'layout_width', 0x010100f4, -1),
          intAttr(NS_ANDROID, 'layout_height', 0x010100f5, -1),
          colorAttr(NS_ANDROID, 'background', 0x010100d4, 0xFF0B0F19)
        ],
        children: [
          {
            tag: 'TextView',
            attrs: [
              refAttr(NS_ANDROID, 'id', 0x010100d0, 0x7f030001),
              refAttr(NS_ANDROID, 'text', 0x0101014f, 0x7f010003)
            ],
            children: []
          },
          {
            tag: 'Button',
            attrs: [
              refAttr(NS_ANDROID, 'id', 0x010100d0, 0x7f030000),
              refAttr(NS_ANDROID, 'text', 0x0101014f, 0x7f010002)
            ],
            children: []
          },
          {
            tag: 'android.webkit.WebView',
            attrs: [
              refAttr(NS_ANDROID, 'id', 0x010100d0, 0x7f030002)
            ],
            children: []
          }
        ]
      }
    });
  }

  // ==================== BINARY DALVIK DEX BUILDER ====================
  function buildSampleDex() {
    // Construct a complete, valid DEX file with sorted strings, types, protos, fields, methods, classes, and Dalvik bytecode!
    const stringSet = new Set([
      '<clinit>', '<init>',
      'AES/ECB/PKCS5Padding',
      'AIzaSyD9ArgonVaultHardcodedApiKey8842109',
      'ApiClient.java', 'ArgonVault', 'CryptoEngine.java',
      'I', 'II', 'IJ', 'ILjava/lang/String;',
      'J', 'L', 'LI', 'LL', 'LLL', 'LZ',
      'Landroid/app/Activity;',
      'Landroid/database/Cursor;',
      'Landroid/database/sqlite/SQLiteDatabase;',
      'Landroid/os/Bundle;',
      'Landroid/util/Log;',
      'Landroid/webkit/WebSettings;',
      'Landroid/webkit/WebView;',
      'Lcom/argon/vault/MainActivity;',
      'Lcom/argon/vault/NativeBridge;',
      'Lcom/argon/vault/crypto/CryptoEngine;',
      'Lcom/argon/vault/db/VaultDatabase;',
      'Lcom/argon/vault/net/ApiClient;',
      'Lcom/argon/vault/obf/a;',
      'Ljava/lang/Object;',
      'Ljava/lang/String;',
      'Ljava/lang/StringBuilder;',
      'Ljava/lang/System;',
      'Ljava/security/MessageDigest;',
      'Ljavax/crypto/Cipher;',
      'MD5',
      'MainActivity.java',
      'NativeBridge.java',
      'ProGuard',
      'SELECT secret_blob FROM vault_items WHERE owner = \'',
      'V', 'VI', 'VL', 'VZ', 'Vault initialized with endpoint: ',
      'VaultDatabase.java',
      'Z', 'ZI', 'ZL',
      '[B',
      '\' AND status = 1',
      'a', 'b',
      'addJavascriptInterface',
      'apiEndpoint',
      'append',
      'buildSyncUrl',
      'computeRollingHash',
      'deriveHardwareKey',
      'encryptPayload',
      'equals',
      'getBytes',
      'getInstance',
      'getSettings',
      'http://api.argonvault.internal/v2/sync?token=',
      'i',
      'init',
      'initWebViewPortal',
      'isUnlocked',
      'loadLibrary',
      'loadUrl',
      'masterApiKey',
      'native-vault',
      'onCreate',
      'queryVaultSecret',
      'rawQuery',
      'retryCount',
      'setContentView',
      'setJavaScriptEnabled',
      'toString',
      'verifyDeviceIntegrity',
      'verifyMasterPin'
    ]);

    const strings = Array.from(stringSet).sort();
    const strIdx = (s) => {
      const idx = strings.indexOf(s);
      if (idx === -1) throw new Error(`Missing DEX string: ${s}`);
      return idx;
    };

    const typeDescs = [
      'I', 'J', 'V', 'Z', '[B',
      'Landroid/app/Activity;',
      'Landroid/database/Cursor;',
      'Landroid/database/sqlite/SQLiteDatabase;',
      'Landroid/os/Bundle;',
      'Landroid/util/Log;',
      'Landroid/webkit/WebSettings;',
      'Landroid/webkit/WebView;',
      'Lcom/argon/vault/MainActivity;',
      'Lcom/argon/vault/NativeBridge;',
      'Lcom/argon/vault/crypto/CryptoEngine;',
      'Lcom/argon/vault/db/VaultDatabase;',
      'Lcom/argon/vault/net/ApiClient;',
      'Lcom/argon/vault/obf/a;',
      'Ljava/lang/Object;',
      'Ljava/lang/String;',
      'Ljava/lang/StringBuilder;',
      'Ljava/lang/System;',
      'Ljava/security/MessageDigest;',
      'Ljavax/crypto/Cipher;'
    ].sort();
    const typeIdx = (t) => {
      const idx = typeDescs.indexOf(t);
      if (idx === -1) throw new Error(`Missing DEX type: ${t}`);
      return idx;
    };

    // Protos: { shorty, returnType, params: [] }
    const protoDefs = [
      { key: '()V', shorty: 'V', ret: 'V', params: [] },
      { key: '(I)V', shorty: 'VI', ret: 'V', params: ['I'] },
      { key: '(Z)V', shorty: 'VZ', ret: 'V', params: ['Z'] },
      { key: '(Landroid/os/Bundle;)V', shorty: 'VL', ret: 'V', params: ['Landroid/os/Bundle;'] },
      { key: '(Landroid/webkit/WebView;)V', shorty: 'VL', ret: 'V', params: ['Landroid/webkit/WebView;'] },
      { key: '(Ljava/lang/String;)V', shorty: 'VL', ret: 'V', params: ['Ljava/lang/String;'] },
      { key: '(Ljava/lang/Object;Ljava/lang/String;)V', shorty: 'VLL', ret: 'V', params: ['Ljava/lang/Object;', 'Ljava/lang/String;'] },
      { key: '(I)Z', shorty: 'ZI', ret: 'Z', params: ['I'] },
      { key: '(Ljava/lang/Object;)Z', shorty: 'ZL', ret: 'Z', params: ['Ljava/lang/Object;'] },
      { key: '(Ljava/lang/String;)Z', shorty: 'ZL', ret: 'Z', params: ['Ljava/lang/String;'] },
      { key: '(II)I', shorty: 'III', ret: 'I', params: ['I', 'I'] },
      { key: '(Ljava/lang/String;Ljava/lang/String;)I', shorty: 'ILL', ret: 'I', params: ['Ljava/lang/String;', 'Ljava/lang/String;'] },
      { key: '()Ljava/lang/String;', shorty: 'L', ret: 'Ljava/lang/String;', params: [] },
      { key: '(Ljava/lang/String;)Ljava/lang/String;', shorty: 'LL', ret: 'Ljava/lang/String;', params: ['Ljava/lang/String;'] },
      { key: '(Ljava/lang/String;)Ljava/lang/StringBuilder;', shorty: 'LL', ret: 'Ljava/lang/StringBuilder;', params: ['Ljava/lang/String;'] },
      { key: '()Landroid/webkit/WebSettings;', shorty: 'L', ret: 'Landroid/webkit/WebSettings;', params: [] },
      { key: '(Ljava/lang/String;)Ljavax/crypto/Cipher;', shorty: 'LL', ret: 'Ljavax/crypto/Cipher;', params: ['Ljava/lang/String;'] },
      { key: '(Ljava/lang/String;)Ljava/security/MessageDigest;', shorty: 'LL', ret: 'Ljava/security/MessageDigest;', params: ['Ljava/lang/String;'] },
      { key: '(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;', shorty: 'LLL', ret: 'Landroid/database/Cursor;', params: ['Ljava/lang/String;', 'Ljava/lang/String;'] },
      { key: '(Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;)Landroid/database/Cursor;', shorty: 'LLL', ret: 'Landroid/database/Cursor;', params: ['Landroid/database/sqlite/SQLiteDatabase;', 'Ljava/lang/String;'] },
      { key: '(Ljava/lang/String;I)[B', shorty: 'LLI', ret: '[B', params: ['Ljava/lang/String;', 'I'] },
      { key: '(Ljava/lang/String;)[B', shorty: 'LL', ret: '[B', params: ['Ljava/lang/String;'] }
    ];
    // Ensure shorty strings exist
    for (const p of protoDefs) {
      if (!strings.includes(p.shorty)) strings.push(p.shorty);
    }
    strings.sort();

    const protoIdx = (key) => {
      const idx = protoDefs.findIndex(p => p.key === key);
      if (idx === -1) throw new Error(`Missing proto: ${key}`);
      return idx;
    };

    // Fields: { cls, type, name }
    const fieldDefs = [
      { cls: 'Lcom/argon/vault/MainActivity;', type: 'Ljava/lang/String;', name: 'masterApiKey' },
      { cls: 'Lcom/argon/vault/MainActivity;', type: 'Z', name: 'isUnlocked' },
      { cls: 'Lcom/argon/vault/net/ApiClient;', type: 'Ljava/lang/String;', name: 'apiEndpoint' },
      { cls: 'Lcom/argon/vault/net/ApiClient;', type: 'I', name: 'retryCount' },
      { cls: 'Lcom/argon/vault/obf/a;', type: 'Ljava/lang/String;', name: 'a' },
      { cls: 'Lcom/argon/vault/obf/a;', type: 'I', name: 'b' }
    ];
    const fieldIdx = (cls, name) => fieldDefs.findIndex(f => f.cls === cls && f.name === name);

    // Methods: { cls, name, proto }
    const methodDefs = [
      // Framework & Java standard methods
      { cls: 'Landroid/app/Activity;', name: '<init>', proto: '()V' },
      { cls: 'Landroid/app/Activity;', name: 'onCreate', proto: '(Landroid/os/Bundle;)V' },
      { cls: 'Landroid/app/Activity;', name: 'setContentView', proto: '(I)V' },
      { cls: 'Landroid/database/sqlite/SQLiteDatabase;', name: 'rawQuery', proto: '(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;' },
      { cls: 'Landroid/util/Log;', name: 'i', proto: '(Ljava/lang/String;Ljava/lang/String;)I' },
      { cls: 'Landroid/webkit/WebSettings;', name: 'setJavaScriptEnabled', proto: '(Z)V' },
      { cls: 'Landroid/webkit/WebView;', name: 'addJavascriptInterface', proto: '(Ljava/lang/Object;Ljava/lang/String;)V' },
      { cls: 'Landroid/webkit/WebView;', name: 'getSettings', proto: '()Landroid/webkit/WebSettings;' },
      { cls: 'Landroid/webkit/WebView;', name: 'loadUrl', proto: '(Ljava/lang/String;)V' },
      // App methods
      { cls: 'Lcom/argon/vault/MainActivity;', name: '<init>', proto: '()V' },
      { cls: 'Lcom/argon/vault/MainActivity;', name: 'initWebViewPortal', proto: '(Landroid/webkit/WebView;)V' },
      { cls: 'Lcom/argon/vault/MainActivity;', name: 'onCreate', proto: '(Landroid/os/Bundle;)V' },
      { cls: 'Lcom/argon/vault/MainActivity;', name: 'verifyMasterPin', proto: '(Ljava/lang/String;)Z' },
      { cls: 'Lcom/argon/vault/NativeBridge;', name: '<clinit>', proto: '()V' },
      { cls: 'Lcom/argon/vault/NativeBridge;', name: '<init>', proto: '()V' },
      { cls: 'Lcom/argon/vault/NativeBridge;', name: 'deriveHardwareKey', proto: '(Ljava/lang/String;I)[B' },
      { cls: 'Lcom/argon/vault/NativeBridge;', name: 'verifyDeviceIntegrity', proto: '(I)Z' },
      { cls: 'Lcom/argon/vault/crypto/CryptoEngine;', name: '<init>', proto: '()V' },
      { cls: 'Lcom/argon/vault/crypto/CryptoEngine;', name: 'computeRollingHash', proto: '(II)I' },
      { cls: 'Lcom/argon/vault/crypto/CryptoEngine;', name: 'encryptPayload', proto: '(Ljava/lang/String;)[B' },
      { cls: 'Lcom/argon/vault/db/VaultDatabase;', name: '<init>', proto: '()V' },
      { cls: 'Lcom/argon/vault/db/VaultDatabase;', name: 'queryVaultSecret', proto: '(Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;)Landroid/database/Cursor;' },
      { cls: 'Lcom/argon/vault/net/ApiClient;', name: '<init>', proto: '()V' },
      { cls: 'Lcom/argon/vault/net/ApiClient;', name: 'buildSyncUrl', proto: '(Ljava/lang/String;)Ljava/lang/String;' },
      { cls: 'Lcom/argon/vault/obf/a;', name: '<init>', proto: '()V' },
      { cls: 'Lcom/argon/vault/obf/a;', name: 'a', proto: '(Ljava/lang/String;)[B' },
      { cls: 'Lcom/argon/vault/obf/a;', name: 'b', proto: '(II)I' },
      { cls: 'Ljava/lang/Object;', name: '<init>', proto: '()V' },
      { cls: 'Ljava/lang/String;', name: 'equals', proto: '(Ljava/lang/Object;)Z' },
      { cls: 'Ljava/lang/String;', name: 'getBytes', proto: '()[B' },
      { cls: 'Ljava/lang/StringBuilder;', name: '<init>', proto: '()V' },
      { cls: 'Ljava/lang/StringBuilder;', name: 'append', proto: '(Ljava/lang/String;)Ljava/lang/StringBuilder;' },
      { cls: 'Ljava/lang/StringBuilder;', name: 'toString', proto: '()Ljava/lang/String;' },
      { cls: 'Ljava/lang/System;', name: 'loadLibrary', proto: '(Ljava/lang/String;)V' },
      { cls: 'Ljava/security/MessageDigest;', name: 'getInstance', proto: '(Ljava/lang/String;)Ljava/security/MessageDigest;' },
      { cls: 'Ljavax/crypto/Cipher;', name: 'getInstance', proto: '(Ljava/lang/String;)Ljavax/crypto/Cipher;' }
    ];
    // Ensure '()[B' proto exists
    protoDefs.push({ key: '()[B', shorty: 'L', ret: '[B', params: [] });

    const mIdx = (cls, name, proto) => {
      const idx = methodDefs.findIndex(m => m.cls === cls && m.name === name && (!proto || m.proto === proto));
      if (idx === -1) throw new Error(`Missing method: ${cls}->${name}`);
      return idx;
    };

    // Dalvik Instruction Assembler Helpers (returns array of 16-bit words)
    const op10x = (op) => [op];
    const op11n = (op, vA, lit4) => [op | ((vA & 0xf) << 8) | ((lit4 & 0xf) << 12)];
    const op11x = (op, vA) => [op | ((vA & 0xff) << 8)];
    const op12x = (op, vA, vB) => [op | ((vA & 0xf) << 8) | ((vB & 0xf) << 12)];
    const op21c = (op, vA, ref) => [op | ((vA & 0xff) << 8), ref & 0xffff];
    const op21s = (op, vA, lit16) => [op | ((vA & 0xff) << 8), lit16 & 0xffff];
    const op21t = (op, vA, rel16) => [op | ((vA & 0xff) << 8), rel16 & 0xffff];
    const op22c = (op, vA, vB, ref) => [op | ((vA & 0xf) << 8) | ((vB & 0xf) << 12), ref & 0xffff];
    const op22t = (op, vA, vB, rel16) => [op | ((vA & 0xf) << 8) | ((vB & 0xf) << 12), rel16 & 0xffff];
    const op22b = (op, vA, vB, lit8) => [op | ((vA & 0xff) << 8), (vB & 0xff) | ((lit8 & 0xff) << 8)];
    const op23x = (op, vA, vB, vC) => [op | ((vA & 0xff) << 8), (vB & 0xff) | ((vC & 0xff) << 8)];
    const op31i = (op, vA, lit32) => [op | ((vA & 0xff) << 8), lit32 & 0xffff, (lit32 >>> 16) & 0xffff];
    const op10t = (op, rel8) => [op | ((rel8 & 0xff) << 8)];
    const op35c = (op, regs, ref) => {
      const count = regs.length;
      const rC = regs[0] || 0, rD = regs[1] || 0, rE = regs[2] || 0, rF = regs[3] || 0, rG = regs[4] || 0;
      return [
        op | ((rG & 0xf) << 8) | ((count & 0xf) << 12),
        ref & 0xffff,
        (rC & 0xf) | ((rD & 0xf) << 4) | ((rE & 0xf) << 8) | ((rF & 0xf) << 12)
      ];
    };

    // Define classes with their fields & methods
    const classSpecs = [
      // 1. com.argon.vault.MainActivity
      {
        cls: 'Lcom/argon/vault/MainActivity;',
        accessFlags: 0x0001, // public
        superCls: 'Landroid/app/Activity;',
        sourceFile: 'MainActivity.java',
        staticFields: [
          { fieldId: fieldIdx('Lcom/argon/vault/MainActivity;', 'masterApiKey'), accessFlags: 0x0019 } // public static final
        ],
        instanceFields: [
          { fieldId: fieldIdx('Lcom/argon/vault/MainActivity;', 'isUnlocked'), accessFlags: 0x0002 } // private
        ],
        directMethods: [
          {
            methodId: mIdx('Lcom/argon/vault/MainActivity;', '<init>'),
            accessFlags: 0x10001, // public constructor
            code: {
              regs: 2, ins: 1, outs: 1,
              words: [
                ...op35c(0x70, [1], mIdx('Landroid/app/Activity;', '<init>')), // invoke-direct {p0}, Activity-><init>()V
                ...op21c(0x1a, 0, strIdx('AIzaSyD9ArgonVaultHardcodedApiKey8842109')), // const-string v0, "..."
                ...op21c(0x69, 0, fieldIdx('Lcom/argon/vault/MainActivity;', 'masterApiKey')), // sput-object v0, masterApiKey
                ...op11n(0x12, 0, 0), // const/4 v0, 0
                ...op22c(0x5c, 0, 1, fieldIdx('Lcom/argon/vault/MainActivity;', 'isUnlocked')), // iput-boolean v0, p0, isUnlocked
                ...op10x(0x0e) // return-void
              ]
            }
          }
        ],
        virtualMethods: [
          {
            methodId: mIdx('Lcom/argon/vault/MainActivity;', 'onCreate'),
            accessFlags: 0x0004, // protected
            code: {
              regs: 4, ins: 2, outs: 2,
              words: [
                ...op35c(0x6f, [2, 3], mIdx('Landroid/app/Activity;', 'onCreate')), // invoke-super {p0, p1}, Activity->onCreate
                ...op31i(0x14, 0, 0x7f020000), // const v0, 0x7f020000 (@layout/activity_main)
                ...op35c(0x6e, [2, 0], mIdx('Landroid/app/Activity;', 'setContentView')), // invoke-virtual {p0, v0}, setContentView
                ...op21c(0x1a, 0, strIdx('ArgonVault')), // const-string v0, "ArgonVault"
                ...op21c(0x1a, 1, strIdx('Vault initialized with endpoint: ')), // const-string v1
                ...op35c(0x71, [0, 1], mIdx('Landroid/util/Log;', 'i')), // invoke-static {v0, v1}, Log->i
                ...op10x(0x0e) // return-void
              ]
            }
          },
          {
            methodId: mIdx('Lcom/argon/vault/MainActivity;', 'initWebViewPortal'),
            accessFlags: 0x0001, // public
            code: {
              regs: 4, ins: 2, outs: 3,
              words: [
                ...op35c(0x6e, [3], mIdx('Landroid/webkit/WebView;', 'getSettings')), // invoke-virtual {p1}, WebView->getSettings
                ...op11x(0x0c, 0), // move-result-object v0
                ...op11n(0x12, 1, 1), // const/4 v1, 1 (true)
                ...op35c(0x6e, [0, 1], mIdx('Landroid/webkit/WebSettings;', 'setJavaScriptEnabled')), // setJavaScriptEnabled(true)
                ...op21c(0x1a, 1, strIdx('ArgonVault')), // const-string v1, "ArgonVault"
                ...op35c(0x6e, [3, 2, 1], mIdx('Landroid/webkit/WebView;', 'addJavascriptInterface')), // addJavascriptInterface(this, "ArgonVault")
                ...op21c(0x1a, 1, strIdx('http://api.argonvault.internal/v2/sync?token=')), // const-string v1
                ...op35c(0x6e, [3, 1], mIdx('Landroid/webkit/WebView;', 'loadUrl')), // loadUrl
                ...op10x(0x0e)
              ]
            }
          },
          {
            methodId: mIdx('Lcom/argon/vault/MainActivity;', 'verifyMasterPin'),
            accessFlags: 0x0001, // public
            code: {
              regs: 4, ins: 2, outs: 2,
              words: [
                ...op21s(0x13, 0, 1337), // const/16 v0, 1337 (0 words..1)
                ...op35c(0x71, [0], mIdx('Lcom/argon/vault/NativeBridge;', 'verifyDeviceIntegrity')), // 2..4
                ...op11x(0x0a, 1), // move-result v1 (5)
                ...op21t(0x38, 1, 6), // if-eqz v1, +6 -> pc 12 (6..7)
                ...op11n(0x12, 0, 1), // const/4 v0, 1 (8)
                ...op22c(0x5c, 0, 2, fieldIdx('Lcom/argon/vault/MainActivity;', 'isUnlocked')), // iput-boolean (9..10)
                ...op11x(0x0f, 0), // return v0 (11)
                ...op11n(0x12, 0, 0), // const/4 v0, 0 (12)
                ...op11x(0x0f, 0) // return v0 (13)
              ]
            }
          }
        ]
      },
      // 2. com.argon.vault.NativeBridge
      {
        cls: 'Lcom/argon/vault/NativeBridge;',
        accessFlags: 0x0001,
        superCls: 'Ljava/lang/Object;',
        sourceFile: 'NativeBridge.java',
        staticFields: [],
        instanceFields: [],
        directMethods: [
          {
            methodId: mIdx('Lcom/argon/vault/NativeBridge;', '<clinit>'),
            accessFlags: 0x10008, // static constructor
            code: {
              regs: 1, ins: 0, outs: 1,
              words: [
                ...op21c(0x1a, 0, strIdx('native-vault')),
                ...op35c(0x71, [0], mIdx('Ljava/lang/System;', 'loadLibrary')),
                ...op10x(0x0e)
              ]
            }
          },
          {
            methodId: mIdx('Lcom/argon/vault/NativeBridge;', '<init>'),
            accessFlags: 0x10001,
            code: {
              regs: 1, ins: 1, outs: 1,
              words: [
                ...op35c(0x70, [0], mIdx('Ljava/lang/Object;', '<init>')),
                ...op10x(0x0e)
              ]
            }
          },
          {
            methodId: mIdx('Lcom/argon/vault/NativeBridge;', 'deriveHardwareKey'),
            accessFlags: 0x0109, // public static native
            code: null
          },
          {
            methodId: mIdx('Lcom/argon/vault/NativeBridge;', 'verifyDeviceIntegrity'),
            accessFlags: 0x0109, // public static native
            code: null
          }
        ],
        virtualMethods: []
      },
      // 3. com.argon.vault.crypto.CryptoEngine
      {
        cls: 'Lcom/argon/vault/crypto/CryptoEngine;',
        accessFlags: 0x0001,
        superCls: 'Ljava/lang/Object;',
        sourceFile: 'CryptoEngine.java',
        staticFields: [],
        instanceFields: [],
        directMethods: [
          {
            methodId: mIdx('Lcom/argon/vault/crypto/CryptoEngine;', '<init>'),
            accessFlags: 0x10001,
            code: {
              regs: 1, ins: 1, outs: 1,
              words: [
                ...op35c(0x70, [0], mIdx('Ljava/lang/Object;', '<init>')),
                ...op10x(0x0e)
              ]
            }
          }
        ],
        virtualMethods: [
          {
            methodId: mIdx('Lcom/argon/vault/crypto/CryptoEngine;', 'computeRollingHash'),
            accessFlags: 0x0001,
            code: {
              regs: 5, ins: 3, outs: 0,
              words: [
                // int v0 = 0; int v1 = arg0; while (v0 < arg1) { v1 = (v1 * 31) ^ v0; v0 = v0 + 1; } return v1;
                ...op11n(0x12, 0, 0), // pc 0: const/4 v0, 0
                ...op12x(0x01, 1, 3), // pc 1: move v1, p1
                ...op22t(0x35, 0, 4, 8), // pc 2..3: if-ge v0, p2, +8 -> pc 10
                ...op22b(0xda, 1, 1, 31), // pc 4..5: mul-int/lit8 v1, v1, 31
                ...op12x(0xb7, 1, 0), // pc 6: xor-int/2addr v1, v0
                ...op22b(0xd8, 0, 0, 1), // pc 7..8: add-int/lit8 v0, v0, 1
                ...op10t(0x28, -7), // pc 9: goto -7 -> pc 2
                ...op11x(0x0f, 1) // pc 10: return v1
              ]
            }
          },
          {
            methodId: mIdx('Lcom/argon/vault/crypto/CryptoEngine;', 'encryptPayload'),
            accessFlags: 0x0001,
            code: {
              regs: 4, ins: 2, outs: 2,
              words: [
                ...op21c(0x1a, 0, strIdx('AES/ECB/PKCS5Padding')),
                ...op35c(0x71, [0], mIdx('Ljavax/crypto/Cipher;', 'getInstance')),
                ...op11x(0x0c, 0),
                ...op21c(0x1a, 1, strIdx('MD5')),
                ...op35c(0x71, [1], mIdx('Ljava/security/MessageDigest;', 'getInstance')),
                ...op11x(0x0c, 1),
                ...op21s(0x13, 1, 256),
                ...op35c(0x71, [3, 1], mIdx('Lcom/argon/vault/NativeBridge;', 'deriveHardwareKey')),
                ...op11x(0x0c, 1),
                ...op11x(0x11, 1) // return-object v1
              ]
            }
          }
        ]
      },
      // 4. com.argon.vault.db.VaultDatabase
      {
        cls: 'Lcom/argon/vault/db/VaultDatabase;',
        accessFlags: 0x0001,
        superCls: 'Ljava/lang/Object;',
        sourceFile: 'VaultDatabase.java',
        staticFields: [],
        instanceFields: [],
        directMethods: [
          {
            methodId: mIdx('Lcom/argon/vault/db/VaultDatabase;', '<init>'),
            accessFlags: 0x10001,
            code: {
              regs: 1, ins: 1, outs: 1,
              words: [
                ...op35c(0x70, [0], mIdx('Ljava/lang/Object;', '<init>')),
                ...op10x(0x0e)
              ]
            }
          }
        ],
        virtualMethods: [
          {
            methodId: mIdx('Lcom/argon/vault/db/VaultDatabase;', 'queryVaultSecret'),
            accessFlags: 0x0001,
            code: {
              regs: 6, ins: 3, outs: 3,
              words: [
                ...op21c(0x22, 0, typeIdx('Ljava/lang/StringBuilder;')), // new-instance v0, StringBuilder
                ...op35c(0x70, [0], mIdx('Ljava/lang/StringBuilder;', '<init>')),
                ...op21c(0x1a, 1, strIdx("SELECT secret_blob FROM vault_items WHERE owner = '")),
                ...op35c(0x6e, [0, 1], mIdx('Ljava/lang/StringBuilder;', 'append')),
                ...op11x(0x0c, 0),
                ...op35c(0x6e, [0, 5], mIdx('Ljava/lang/StringBuilder;', 'append')), // append(p2)
                ...op11x(0x0c, 0),
                ...op21c(0x1a, 1, strIdx("' AND status = 1")),
                ...op35c(0x6e, [0, 1], mIdx('Ljava/lang/StringBuilder;', 'append')),
                ...op11x(0x0c, 0),
                ...op35c(0x6e, [0], mIdx('Ljava/lang/StringBuilder;', 'toString')),
                ...op11x(0x0c, 0),
                ...op11n(0x12, 1, 0), // const/4 v1, 0 (null selectionArgs)
                ...op35c(0x6e, [4, 0, 1], mIdx('Landroid/database/sqlite/SQLiteDatabase;', 'rawQuery')),
                ...op11x(0x0c, 2),
                ...op11x(0x11, 2) // return-object v2
              ]
            }
          }
        ]
      },
      // 5. com.argon.vault.net.ApiClient
      {
        cls: 'Lcom/argon/vault/net/ApiClient;',
        accessFlags: 0x0001,
        superCls: 'Ljava/lang/Object;',
        sourceFile: 'ApiClient.java',
        staticFields: [],
        instanceFields: [
          { fieldId: fieldIdx('Lcom/argon/vault/net/ApiClient;', 'apiEndpoint'), accessFlags: 0x0002 },
          { fieldId: fieldIdx('Lcom/argon/vault/net/ApiClient;', 'retryCount'), accessFlags: 0x0002 }
        ],
        directMethods: [
          {
            methodId: mIdx('Lcom/argon/vault/net/ApiClient;', '<init>'),
            accessFlags: 0x10001,
            code: {
              regs: 3, ins: 1, outs: 1,
              words: [
                ...op35c(0x70, [2], mIdx('Ljava/lang/Object;', '<init>')),
                ...op21c(0x1a, 0, strIdx('http://api.argonvault.internal/v2/sync?token=')),
                ...op22c(0x5b, 0, 2, fieldIdx('Lcom/argon/vault/net/ApiClient;', 'apiEndpoint')),
                ...op11n(0x12, 0, 3),
                ...op22c(0x59, 0, 2, fieldIdx('Lcom/argon/vault/net/ApiClient;', 'retryCount')),
                ...op10x(0x0e)
              ]
            }
          }
        ],
        virtualMethods: [
          {
            methodId: mIdx('Lcom/argon/vault/net/ApiClient;', 'buildSyncUrl'),
            accessFlags: 0x0001,
            code: {
              regs: 4, ins: 2, outs: 2,
              words: [
                ...op21c(0x22, 0, typeIdx('Ljava/lang/StringBuilder;')),
                ...op35c(0x70, [0], mIdx('Ljava/lang/StringBuilder;', '<init>')),
                ...op22c(0x54, 1, 2, fieldIdx('Lcom/argon/vault/net/ApiClient;', 'apiEndpoint')),
                ...op35c(0x6e, [0, 1], mIdx('Ljava/lang/StringBuilder;', 'append')),
                ...op11x(0x0c, 0),
                ...op35c(0x6e, [0, 3], mIdx('Ljava/lang/StringBuilder;', 'append')),
                ...op11x(0x0c, 0),
                ...op35c(0x6e, [0], mIdx('Ljava/lang/StringBuilder;', 'toString')),
                ...op11x(0x0c, 0),
                ...op11x(0x11, 0)
              ]
            }
          }
        ]
      },
      // 6. com.argon.vault.obf.a (ProGuard / R8 Obfuscated Class for Smart Deobfuscation showcase)
      {
        cls: 'Lcom/argon/vault/obf/a;',
        accessFlags: 0x0011, // public final
        superCls: 'Ljava/lang/Object;',
        sourceFile: 'ProGuard',
        staticFields: [],
        instanceFields: [
          { fieldId: fieldIdx('Lcom/argon/vault/obf/a;', 'a'), accessFlags: 0x0002 },
          { fieldId: fieldIdx('Lcom/argon/vault/obf/a;', 'b'), accessFlags: 0x0002 }
        ],
        directMethods: [
          {
            methodId: mIdx('Lcom/argon/vault/obf/a;', '<init>'),
            accessFlags: 0x10001,
            code: {
              regs: 3, ins: 1, outs: 1,
              words: [
                ...op35c(0x70, [2], mIdx('Ljava/lang/Object;', '<init>')),
                ...op21c(0x1a, 0, strIdx('AES/ECB/PKCS5Padding')),
                ...op22c(0x5b, 0, 2, fieldIdx('Lcom/argon/vault/obf/a;', 'a')),
                ...op21s(0x13, 0, 256),
                ...op22c(0x59, 0, 2, fieldIdx('Lcom/argon/vault/obf/a;', 'b')),
                ...op10x(0x0e)
              ]
            }
          }
        ],
        virtualMethods: [
          {
            methodId: mIdx('Lcom/argon/vault/obf/a;', 'a'),
            accessFlags: 0x0001,
            code: {
              regs: 4, ins: 2, outs: 2,
              words: [
                ...op11x(0x1d, 2), // monitor-enter p0 (synchronized block)
                ...op22c(0x54, 0, 2, fieldIdx('Lcom/argon/vault/obf/a;', 'a')),
                ...op35c(0x71, [0], mIdx('Ljavax/crypto/Cipher;', 'getInstance')),
                ...op11x(0x0c, 0),
                ...op22c(0x52, 1, 2, fieldIdx('Lcom/argon/vault/obf/a;', 'b')),
                ...op35c(0x71, [3, 1], mIdx('Lcom/argon/vault/NativeBridge;', 'deriveHardwareKey')),
                ...op11x(0x0c, 1),
                ...op11x(0x1e, 2), // monitor-exit p0
                ...op11x(0x11, 1)
              ]
            }
          },
          {
            methodId: mIdx('Lcom/argon/vault/obf/a;', 'b'),
            accessFlags: 0x0001,
            code: {
              regs: 4, ins: 3, outs: 0,
              words: [
                ...op21s(0x13, 1, 10), // const/16 v1, 10 (pc 0..1)
                ...op22c(0x23, 0, 1, typeIdx('[B')), // new-array v0, v1, [B (pc 2..3)
                0x26 | (0 << 8), 10, 0, // fill-array-data v0, +10 -> pc 14 (pc 4..6)
                ...op22b(0xdf, 1, 1, 0x5a), // xor-int/lit8 v1, v1, 0x5a (pc 7..8)
                ...op23x(0x90, 0, 2, 3), // add-int v0, p1, p2 (pc 9..10)
                ...op22b(0xda, 0, 0, 31), // mul-int/lit8 v0, v0, 31 (pc 11..12)
                ...op11x(0x0f, 0), // return v0 (pc 13)
                // fill-array-data-payload @ pc 14: "ARGON_KEY!" ^ 0x5A
                0x0300, 0x0001, 10, 0,
                0x081b, 0x151d, 0x0514, 0x1f11, 0x7b03
              ]
            }
          }
        ]
      }
    ];

    // Layout DEX sections sequentially after fixed tables
    const headerSize = 0x70; // 112 bytes
    const stringIdsOff = headerSize;
    const typeIdsOff = stringIdsOff + strings.length * 4;
    const protoIdsOff = typeIdsOff + typeDescs.length * 4;
    const fieldIdsOff = protoIdsOff + protoDefs.length * 12;
    const methodIdsOff = fieldIdsOff + fieldDefs.length * 8;
    const classDefsOff = methodIdsOff + methodDefs.length * 8;
    const dataStartOff = classDefsOff + classSpecs.length * 32;

    const dataW = new BinaryWriter(8192);
    // Pad dataW with dummy bytes up to dataStartOff so dataW.pos matches absolute file offsets!
    for (let i = 0; i < dataStartOff; i++) dataW.u8(0);

    // 1. Write type_lists for protos
    const protoParamOffsets = [];
    for (const p of protoDefs) {
      if (p.params.length === 0) {
        protoParamOffsets.push(0);
      } else {
        dataW.align4();
        protoParamOffsets.push(dataW.pos);
        dataW.u32(p.params.length);
        for (const pt of p.params) {
          dataW.u16(typeIdx(pt));
        }
      }
    }

    // 2. Write code_items for methods (ensure sorted by fieldId/methodId for valid ULEB128 deltas)
    for (const c of classSpecs) {
      c.staticFields.sort((a, b) => a.fieldId - b.fieldId);
      c.instanceFields.sort((a, b) => a.fieldId - b.fieldId);
      c.directMethods.sort((a, b) => a.methodId - b.methodId);
      c.virtualMethods.sort((a, b) => a.methodId - b.methodId);
      for (const m of [...c.directMethods, ...c.virtualMethods]) {
        if (!m.code) {
          m.codeOff = 0;
        } else {
          dataW.align4();
          m.codeOff = dataW.pos;
          dataW.u16(m.code.regs);
          dataW.u16(m.code.ins);
          dataW.u16(m.code.outs);
          dataW.u16(0); // tries_size
          dataW.u32(0); // debug_info_off
          dataW.u32(m.code.words.length);
          for (const w of m.code.words) dataW.u16(w);
        }
      }
    }

    // 3. Write string_data_items
    const stringDataOffsets = [];
    const utf8Encoder = new TextEncoder();
    for (const s of strings) {
      stringDataOffsets.push(dataW.pos);
      dataW.uleb128(s.length);
      dataW.bytes(utf8Encoder.encode(s));
      dataW.u8(0); // null terminator
    }

    // 4. Write class_data_items
    for (const c of classSpecs) {
      c.classDataOff = dataW.pos;
      dataW.uleb128(c.staticFields.length);
      dataW.uleb128(c.instanceFields.length);
      dataW.uleb128(c.directMethods.length);
      dataW.uleb128(c.virtualMethods.length);

      let prevId = 0;
      for (const sf of c.staticFields) {
        dataW.uleb128(sf.fieldId - prevId);
        prevId = sf.fieldId;
        dataW.uleb128(sf.accessFlags);
      }
      prevId = 0;
      for (const f of c.instanceFields) {
        dataW.uleb128(f.fieldId - prevId);
        prevId = f.fieldId;
        dataW.uleb128(f.accessFlags);
      }
      prevId = 0;
      for (const m of c.directMethods) {
        dataW.uleb128(m.methodId - prevId);
        prevId = m.methodId;
        dataW.uleb128(m.accessFlags);
        dataW.uleb128(m.codeOff);
      }
      prevId = 0;
      for (const m of c.virtualMethods) {
        dataW.uleb128(m.methodId - prevId);
        prevId = m.methodId;
        dataW.uleb128(m.accessFlags);
        dataW.uleb128(m.codeOff);
      }
    }

    dataW.align4();
    const fullBytes = dataW.toUint8Array();
    const dv = new DataView(fullBytes.buffer);

    // Fill Header (0x00 .. 0x6F)
    const magic = [0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x38, 0x00]; // "dex\n038\0"
    fullBytes.set(magic, 0);
    dv.setUint32(32, fullBytes.length, true); // file_size
    dv.setUint32(36, 0x70, true);             // header_size
    dv.setUint32(40, 0x12345678, true);       // endian_tag
    dv.setUint32(56, strings.length, true);   // string_ids_size
    dv.setUint32(60, stringIdsOff, true);     // string_ids_off
    dv.setUint32(64, typeDescs.length, true); // type_ids_size
    dv.setUint32(68, typeIdsOff, true);       // type_ids_off
    dv.setUint32(72, protoDefs.length, true); // proto_ids_size
    dv.setUint32(76, protoIdsOff, true);      // proto_ids_off
    dv.setUint32(80, fieldDefs.length, true); // field_ids_size
    dv.setUint32(84, fieldIdsOff, true);      // field_ids_off
    dv.setUint32(88, methodDefs.length, true);// method_ids_size
    dv.setUint32(92, methodIdsOff, true);     // method_ids_off
    dv.setUint32(96, classSpecs.length, true);// class_defs_size
    dv.setUint32(100, classDefsOff, true);    // class_defs_off
    dv.setUint32(104, fullBytes.length - dataStartOff, true); // data_size
    dv.setUint32(108, dataStartOff, true);    // data_off

    // Fill string_ids
    for (let i = 0; i < strings.length; i++) {
      dv.setUint32(stringIdsOff + i * 4, stringDataOffsets[i], true);
    }
    // Fill type_ids
    for (let i = 0; i < typeDescs.length; i++) {
      dv.setUint32(typeIdsOff + i * 4, strIdx(typeDescs[i]), true);
    }
    // Fill proto_ids
    for (let i = 0; i < protoDefs.length; i++) {
      const base = protoIdsOff + i * 12;
      dv.setUint32(base, strIdx(protoDefs[i].shorty), true);
      dv.setUint32(base + 4, typeIdx(protoDefs[i].ret), true);
      dv.setUint32(base + 8, protoParamOffsets[i], true);
    }
    // Fill field_ids
    for (let i = 0; i < fieldDefs.length; i++) {
      const base = fieldIdsOff + i * 8;
      dv.setUint16(base, typeIdx(fieldDefs[i].cls), true);
      dv.setUint16(base + 2, typeIdx(fieldDefs[i].type), true);
      dv.setUint32(base + 4, strIdx(fieldDefs[i].name), true);
    }
    // Fill method_ids
    for (let i = 0; i < methodDefs.length; i++) {
      const base = methodIdsOff + i * 8;
      dv.setUint16(base, typeIdx(methodDefs[i].cls), true);
      dv.setUint16(base + 2, protoIdx(methodDefs[i].proto), true);
      dv.setUint32(base + 4, strIdx(methodDefs[i].name), true);
    }
    // Fill class_defs
    for (let i = 0; i < classSpecs.length; i++) {
      const base = classDefsOff + i * 32;
      const c = classSpecs[i];
      dv.setUint32(base, typeIdx(c.cls), true);
      dv.setUint32(base + 4, c.accessFlags, true);
      dv.setUint32(base + 8, typeIdx(c.superCls), true);
      dv.setUint32(base + 12, 0, true); // interfaces_off
      dv.setUint32(base + 16, strIdx(c.sourceFile), true);
      dv.setUint32(base + 20, 0, true); // annotations_off
      dv.setUint32(base + 24, c.classDataOff, true);
      dv.setUint32(base + 28, 0, true); // static_values_off
    }

    // Compute SHA-1 signature (bytes 32..end -> offset 12..31) BEFORE Adler32 checksum (bytes 12..end -> offset 8..11)
    if (typeof global.ArgonZip.pureJsSha1Bytes === 'function') {
      const sha1 = global.ArgonZip.pureJsSha1Bytes(fullBytes, 32, fullBytes.length);
      fullBytes.set(sha1, 12);
    }

    // Compute Adler32 checksum over bytes 12..end
    const checksum = global.ArgonZip.adler32(fullBytes, 12, fullBytes.length);
    dv.setUint32(8, checksum, true);

    return fullBytes;
  }

  // ==================== BINARY 64-BIT AARCH64 ELF (.SO) BUILDER ====================
  function buildSampleElfSo() {
    // Builds a valid 64-bit Little-Endian AArch64 ELF shared library with:
    // - Program headers: PT_LOAD, PT_DYNAMIC, PT_GNU_STACK, PT_GNU_RELRO
    // - Section headers: NULL, .dynsym, .dynstr, .dynamic, .text, .shstrtab
    // - Exported JNI functions: JNI_OnLoad, Java_com_argon_vault_NativeBridge_deriveHardwareKey, Java_com_argon_vault_NativeBridge_verifyDeviceIntegrity
    // - Imported libc/liblog functions: __android_log_print, memcpy, malloc
    const shstrList = ['', '.dynsym', '.dynstr', '.dynamic', '.text', '.shstrtab'];
    const dynstrList = [
      '',
      'libnative-vault.so',
      'liblog.so',
      'libc.so',
      'libcrypto.so',
      '__android_log_print',
      'memcpy',
      'JNI_OnLoad',
      'Java_com_argon_vault_NativeBridge_deriveHardwareKey',
      'Java_com_argon_vault_NativeBridge_verifyDeviceIntegrity'
    ];

    function buildStrTab(list) {
      const encoder = new TextEncoder();
      const offsets = {};
      const chunks = [];
      let pos = 0;
      for (const s of list) {
        offsets[s] = pos;
        const b = encoder.encode(s);
        chunks.push(b);
        chunks.push(new Uint8Array([0]));
        pos += b.length + 1;
      }
      const w = new BinaryWriter(pos + 4);
      for (const c of chunks) w.bytes(c);
      w.align4();
      return { bytes: w.toUint8Array(), offsets };
    }

    const shstr = buildStrTab(shstrList);
    const dynstr = buildStrTab(dynstrList);

    // Build .dynsym (24 bytes per Elf64_Sym)
    const symDefs = [
      { name: '', bind: 0, type: 0, shndx: 0, val: 0, size: 0 },
      { name: '__android_log_print', bind: 1, type: 2, shndx: 0, val: 0, size: 0 },
      { name: 'memcpy', bind: 1, type: 2, shndx: 0, val: 0, size: 0 },
      { name: 'JNI_OnLoad', bind: 1, type: 2, shndx: 4, val: 0x1000, size: 16 },
      { name: 'Java_com_argon_vault_NativeBridge_deriveHardwareKey', bind: 1, type: 2, shndx: 4, val: 0x1010, size: 32 },
      { name: 'Java_com_argon_vault_NativeBridge_verifyDeviceIntegrity', bind: 1, type: 2, shndx: 4, val: 0x1030, size: 20 }
    ];
    const dynsymW = new BinaryWriter();
    for (const s of symDefs) {
      dynsymW.u32(dynstr.offsets[s.name] || 0);
      dynsymW.u8((s.bind << 4) | (s.type & 0xf));
      dynsymW.u8(0); // st_other
      dynsymW.u16(s.shndx);
      dynsymW.u64(s.val, 0);
      dynsymW.u64(s.size, 0);
    }
    const dynsymBytes = dynsymW.toUint8Array();

    // Build .dynamic (16 bytes per Elf64_Dyn)
    const dynamicW = new BinaryWriter();
    const addDyn = (tag, val) => { dynamicW.u64(tag, 0); dynamicW.u64(val, 0); };
    addDyn(14, dynstr.offsets['libnative-vault.so']); // DT_SONAME
    addDyn(1, dynstr.offsets['liblog.so']);           // DT_NEEDED
    addDyn(1, dynstr.offsets['libc.so']);             // DT_NEEDED
    addDyn(1, dynstr.offsets['libcrypto.so']);        // DT_NEEDED
    addDyn(24, 1);                                    // DT_BIND_NOW
    addDyn(0, 0);                                     // DT_NULL
    const dynamicBytes = dynamicW.toUint8Array();

    // Build .text (AArch64 instructions + embedded AES S-Box & ChaCha20 sigma constant)
    const textW = new BinaryWriter();
    // 0x1000: JNI_OnLoad (4 words = 16 bytes)
    textW.u32(0xa9bf7bfd); // stp x29, x30, [sp]
    textW.u32(0x528000c0); // movz w0, #0x6
    textW.u32(0x72a00020); // movk w0, #0x1, lsl #16 (JNI_VERSION_1_6 = 0x00010006)
    textW.u32(0xd65f03c0); // ret

    // 0x1010: Java_com_argon_vault_NativeBridge_deriveHardwareKey (8 words = 32 bytes)
    textW.u32(0xa9bf7bfd); // stp x29, x30, [sp]
    textW.u32(0xaa0003f3); // mov x19, x0 (JNIEnv*)
    textW.u32(0xaa0203f4); // mov x20, x2 (jstring salt)
    textW.u32(0x910083ff); // add sp, sp, #0x20
    textW.u32(0xca140260); // eor x0, x19, x20
    textW.u32(0x94000004); // bl 0x1030
    textW.u32(0xa8c17bfd); // ldp x29, x30, [sp]
    textW.u32(0xd65f03c0); // ret

    // 0x1030: Java_com_argon_vault_NativeBridge_verifyDeviceIntegrity (5 words = 20 bytes)
    textW.u32(0x7105395f); // subs wzr, w10, #0x14e
    textW.u32(0x52800020); // movz w0, #0x1
    textW.u32(0x11000400); // add w0, w0, #0x1
    textW.u32(0x51000400); // sub w0, w0, #0x1
    textW.u32(0xd65f03c0); // ret

    // Append AES Rijndael S-Box prefix & ChaCha20 constant in read-only data pool
    textW.bytes(new Uint8Array([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76]));
    textW.bytes(new TextEncoder().encode('expand 32-byte k'));
    const textBytes = textW.toUint8Array();

    const ehdrSize = 64;
    const phdrCount = 4;
    const phdrSize = 56;
    const phoff = ehdrSize;
    const dynsymOff = phoff + phdrCount * phdrSize;
    const dynstrOff = dynsymOff + dynsymBytes.length;
    const dynamicOff = dynstrOff + dynstr.bytes.length;
    const textOff = dynamicOff + dynamicBytes.length;
    const shstrOff = textOff + textBytes.length;
    const shoff = shstrOff + shstr.bytes.length;

    const w = new BinaryWriter(shoff + 6 * 64);
    // Elf64_Ehdr
    w.bytes(new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    w.u16(3);   // ET_DYN (PIE / Shared Library)
    w.u16(183); // EM_AARCH64
    w.u32(1);   // EV_CURRENT
    w.u64(0x1000, 0); // e_entry
    w.u64(phoff, 0);
    w.u64(shoff, 0);
    w.u32(0);   // e_flags
    w.u16(ehdrSize);
    w.u16(phdrSize);
    w.u16(phdrCount);
    w.u16(64);  // e_shentsize
    w.u16(6);   // e_shnum
    w.u16(5);   // e_shstrndx

    // Elf64_Phdr [4]
    function writePhdr(type, flags, offset, vaddr, filesz) {
      w.u32(type);
      w.u32(flags);
      w.u64(offset, 0);
      w.u64(vaddr, 0);
      w.u64(vaddr, 0);
      w.u64(filesz, 0);
      w.u64(filesz, 0);
      w.u64(0x1000, 0);
    }
    writePhdr(1, 5, 0, 0x0, shoff);                       // PT_LOAD (R-X)
    writePhdr(2, 6, dynamicOff, dynamicOff, dynamicBytes.length); // PT_DYNAMIC (RW-)
    writePhdr(0x6474e551, 6, 0, 0, 0);                    // PT_GNU_STACK (RW- -> NX enabled!)
    writePhdr(0x6474e552, 4, dynamicOff, dynamicOff, dynamicBytes.length); // PT_GNU_RELRO (R--)

    // Section bodies
    w.bytes(dynsymBytes);
    w.bytes(dynstr.bytes);
    w.bytes(dynamicBytes);
    w.bytes(textBytes);
    w.bytes(shstr.bytes);

    // Elf64_Shdr [6]
    function writeShdr(nameStr, type, flags, addr, offset, size, entsize) {
      w.u32(shstr.offsets[nameStr] || 0);
      w.u32(type);
      w.u64(flags, 0);
      w.u64(addr, 0);
      w.u64(offset, 0);
      w.u64(size, 0);
      w.u32(0); // sh_link
      w.u32(0); // sh_info
      w.u64(8, 0); // sh_addralign
      w.u64(entsize, 0);
    }
    writeShdr('', 0, 0, 0, 0, 0, 0);
    writeShdr('.dynsym', 11, 2, dynsymOff, dynsymOff, dynsymBytes.length, 24);
    writeShdr('.dynstr', 3, 2, dynstrOff, dynstrOff, dynstr.bytes.length, 0);
    writeShdr('.dynamic', 6, 3, dynamicOff, dynamicOff, dynamicBytes.length, 16);
    writeShdr('.text', 1, 6, 0x1000, textOff, textBytes.length, 0);
    writeShdr('.shstrtab', 3, 0, 0, shstrOff, shstr.bytes.length, 0);

    return w.toUint8Array();
  }

  // ==================== DER X.509 CERTIFICATE & APK SIG BLOCK V2 BUILDER ====================
  function buildSampleCertRsa() {
    const w = new BinaryWriter();
    const encoder = new TextEncoder();
    function writeOidAndStr(oidBytes, str) {
      w.u8(0x06); w.u8(oidBytes.length); w.bytes(new Uint8Array(oidBytes));
      const sb = encoder.encode(str);
      w.u8(0x0c); w.u8(sb.length); w.bytes(sb);
    }
    w.u8(0x30); w.u8(0x80); // ASN.1 Sequence
    writeOidAndStr([0x55, 0x04, 0x03], 'ArgonVault Release Engineering'); // CN
    writeOidAndStr([0x55, 0x04, 0x0a], 'Argon Security Labs Inc.');       // O
    writeOidAndStr([0x55, 0x04, 0x06], 'JP');                             // C
    // SHA256withRSA OID: 1.2.840.113549.1.1.11
    w.u8(0x06); w.u8(9); w.bytes(new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]));
    // UTCTime validity
    const t1 = encoder.encode('260101000000Z');
    const t2 = encoder.encode('360101000000Z');
    w.u8(0x17); w.u8(13); w.bytes(t1);
    w.u8(0x17); w.u8(13); w.bytes(t2);
    return w.toUint8Array();
  }

  function buildSampleApkSigningBlockV2() {
    const w = new BinaryWriter();
    // Pair 1: APK Signature Scheme v2 (ID 0x7109871a), 32 bytes payload
    const pair1Size = 4 + 32;
    // Pair 2: APK Signature Scheme v3 (ID 0xf05368c0), 32 bytes payload
    const pair2Size = 4 + 32;
    const totalBlockSizeField = (8 + pair1Size) + (8 + pair2Size) + 24;

    w.u64(totalBlockSizeField, 0);
    // Pair 1
    w.u64(pair1Size, 0);
    w.u32(0x7109871a);
    for (let i = 0; i < 8; i++) w.u32(0xA4602000 + i);
    // Pair 2
    w.u64(pair2Size, 0);
    w.u32(0xf05368c0);
    for (let i = 0; i < 8; i++) w.u32(0xB3001000 + i);

    w.u64(totalBlockSizeField, 0);
    w.bytes(new TextEncoder().encode('APK Sig Block 42'));
    return w.toUint8Array();
  }

  function generateSampleApkBuffer() {
    const manifestBytes = buildSampleManifestAxml();
    const arscBytes = buildSampleResourcesArsc();
    const layoutBytes = buildSampleLayoutAxml();
    const dexBytes = buildSampleDex();
    const elfBytes = buildSampleElfSo();
    const certBytes = buildSampleCertRsa();
    const sigBlock = buildSampleApkSigningBlockV2();

    const configJson = new TextEncoder().encode(JSON.stringify({
      vaultVersion: '2.4.1-argon',
      teeProvider: 'StrongBox-Keymaster4',
      pinIterations: 100000,
      endpoints: [
        'https://vault.argonsecurity.io/api/v2/attest',
        'http://api.argonvault.internal/v2/sync'
      ]
    }, null, 2));

    const files = [
      { name: 'AndroidManifest.xml', data: manifestBytes },
      { name: 'resources.arsc', data: arscBytes },
      { name: 'res/layout/activity_main.xml', data: layoutBytes },
      { name: 'classes.dex', data: dexBytes },
      { name: 'lib/arm64-v8a/libnative-vault.so', data: elfBytes },
      { name: 'assets/vault_config.json', data: configJson },
      { name: 'META-INF/CERT.RSA', data: certBytes }
    ];

    return global.ArgonZip.buildZipArchive(files, sigBlock);
  }

  global.ArgonSampleBuilder = {
    generateSampleApkBuffer
  };
})(typeof window !== 'undefined' ? window : globalThis);
