/**
 * ArgonDEX Studio - Native ELF (.so) Binary Inspector & OWASP MASVS Static Security Auditor
 */

(function (global) {
  'use strict';

  // ==================== ELF BINARY PARSER (.SO) ====================
  const EM_ARCHITECTURES = {
    3: 'x86 (IA-32)',
    8: 'MIPS',
    40: 'ARM (32-bit)',
    62: 'x86_64 (AMD64)',
    183: 'ARM64 (AArch64)',
    243: 'RISC-V'
  };

  const SHT_NAMES = {
    0: 'NULL', 1: 'PROGBITS', 2: 'SYMTAB', 3: 'STRTAB', 4: 'RELA',
    5: 'HASH', 6: 'DYNAMIC', 7: 'NOTE', 8: 'NOBITS', 9: 'REL',
    11: 'DYNSYM', 14: 'INIT_ARRAY', 15: 'FINI_ARRAY'
  };

  const PT_NAMES = {
    0: 'PT_NULL', 1: 'PT_LOAD', 2: 'PT_DYNAMIC', 3: 'PT_INTERP',
    4: 'PT_NOTE', 6: 'PT_PHDR', 7: 'PT_TLS',
    0x6474e550: 'PT_GNU_EH_FRAME',
    0x6474e551: 'PT_GNU_STACK',
    0x6474e552: 'PT_GNU_RELRO',
    0x6474e553: 'PT_GNU_PROPERTY'
  };

  function readNullTerminatedAscii(bytes, offset, maxLen = 512) {
    if (offset < 0 || offset >= bytes.length) return '';
    let end = offset;
    const limit = Math.min(bytes.length, offset + maxLen);
    while (end < limit && bytes[end] !== 0) end++;
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes.subarray(offset, end));
  }

  function demangleJniSymbol(symName) {
    if (symName === 'JNI_OnLoad' || symName === 'JNI_OnUnload') {
      return { isJni: true, type: 'lifecycle', className: '(Global VM)', methodName: symName };
    }
    if (!symName.startsWith('Java_')) return null;
    // Format: Java_pkg_sub_ClassName_methodName or with __sig
    const body = symName.slice(5);
    const doubleUnderscore = body.indexOf('__');
    const cleanBody = doubleUnderscore !== -1 ? body.slice(0, doubleUnderscore) : body;
    // Handle _1 escape for underscore inside identifiers
    const parts = cleanBody.replace(/_1/g, '\u0000').split('_').map(s => s.replace(/\u0000/g, '_'));
    if (parts.length < 2) return null;
    const methodName = parts[parts.length - 1];
    const className = parts.slice(0, -1).join('.');
    return {
      isJni: true,
      type: 'method',
      className,
      methodName
    };
  }

  function parseElfBinary(bytes, fileName = 'libnative.so') {
    if (bytes.length < 64 || bytes[0] !== 0x7f || bytes[1] !== 0x45 || bytes[2] !== 0x4c || bytes[3] !== 0x46) {
      throw new Error(`${fileName}: Invalid ELF magic header`);
    }

    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const elfClass = bytes[4]; // 1 = 32-bit, 2 = 64-bit
    const is64 = elfClass === 2;
    const isLE = bytes[5] === 1;
    const eType = dv.getUint16(16, isLE);
    const eMachine = dv.getUint16(18, isLE);

    function u64(off) {
      const lo = dv.getUint32(off, isLE);
      const hi = dv.getUint32(off + 4, isLE);
      return isLE ? (lo + hi * 0x100000000) : (hi + lo * 0x100000000);
    }

    const eEntry = is64 ? u64(24) : dv.getUint32(24, isLE);
    const ePhoff = is64 ? u64(32) : dv.getUint32(28, isLE);
    const eShoff = is64 ? u64(40) : dv.getUint32(32, isLE);
    const ePhentsize = dv.getUint16(is64 ? 54 : 42, isLE);
    const ePhnum = dv.getUint16(is64 ? 56 : 44, isLE);
    const eShentsize = dv.getUint16(is64 ? 58 : 46, isLE);
    const eShnum = dv.getUint16(is64 ? 60 : 48, isLE);
    const eShstrndx = dv.getUint16(is64 ? 62 : 50, isLE);

    // 1. Parse Program Headers
    const programHeaders = [];
    let hasGnuRelro = false;
    let nxEnabled = true;
    for (let i = 0; i < ePhnum; i++) {
      const base = ePhoff + i * ePhentsize;
      if (base + ePhentsize > bytes.length) break;
      const pType = dv.getUint32(base, isLE);
      const pFlags = is64 ? dv.getUint32(base + 4, isLE) : dv.getUint32(base + 24, isLE);
      const pOffset = is64 ? u64(base + 8) : dv.getUint32(base + 4, isLE);
      const pVaddr = is64 ? u64(base + 16) : dv.getUint32(base + 8, isLE);
      const pFilesz = is64 ? u64(base + 32) : dv.getUint32(base + 16, isLE);
      const pMemsz = is64 ? u64(base + 40) : dv.getUint32(base + 20, isLE);

      if (pType === 0x6474e552) hasGnuRelro = true;
      if (pType === 0x6474e551 && (pFlags & 0x1)) nxEnabled = false; // PF_X on stack

      programHeaders.push({
        type: PT_NAMES[pType] || `0x${pType.toString(16)}`,
        offset: pOffset,
        vaddr: '0x' + pVaddr.toString(16),
        filesz: pFilesz,
        memsz: pMemsz,
        flags: `${(pFlags & 4) ? 'R' : '-'}${(pFlags & 2) ? 'W' : '-'}${(pFlags & 1) ? 'X' : '-'}`
      });
    }

    // 2. Parse Section Headers
    const sections = [];
    let shstrtabOff = 0;
    if (eShstrndx < eShnum && eShoff > 0) {
      const strSecBase = eShoff + eShstrndx * eShentsize;
      if (strSecBase + eShentsize <= bytes.length) {
        shstrtabOff = is64 ? u64(strSecBase + 24) : dv.getUint32(strSecBase + 16, isLE);
      }
    }

    let dynsymSec = null;
    let dynstrSec = null;
    let dynamicSec = null;

    for (let i = 0; i < eShnum; i++) {
      const base = eShoff + i * eShentsize;
      if (base + eShentsize > bytes.length) break;
      const shNameIdx = dv.getUint32(base, isLE);
      const shType = dv.getUint32(base + 4, isLE);
      const shOffset = is64 ? u64(base + 24) : dv.getUint32(base + 16, isLE);
      const shSize = is64 ? u64(base + 32) : dv.getUint32(base + 20, isLE);
      const shEntsize = is64 ? u64(base + 56) : dv.getUint32(base + 36, isLE);

      const secName = shstrtabOff ? readNullTerminatedAscii(bytes, shstrtabOff + shNameIdx) : `sec_${i}`;
      const secObj = {
        index: i,
        name: secName,
        type: SHT_NAMES[shType] || `0x${shType.toString(16)}`,
        offset: shOffset,
        size: shSize,
        entsize: shEntsize
      };
      sections.push(secObj);

      if (shType === 11 || secName === '.dynsym') dynsymSec = secObj;
      if (secName === '.dynstr') dynstrSec = secObj;
      if (shType === 6 || secName === '.dynamic') dynamicSec = secObj;
    }

    // 3. Parse Dynamic Symbols (.dynsym + .dynstr)
    const exportedSymbols = [];
    const importedSymbols = [];
    const jniMethods = [];
    let hasStackCanary = false;
    let hasFortify = false;

    if (dynsymSec && dynstrSec && dynsymSec.offset + dynsymSec.size <= bytes.length) {
      const symEntSize = dynsymSec.entsize || (is64 ? 24 : 16);
      const count = Math.floor(dynsymSec.size / symEntSize);

      for (let i = 0; i < count && i < 8000; i++) {
        const sBase = dynsymSec.offset + i * symEntSize;
        const stName = dv.getUint32(sBase, isLE);
        const stInfo = is64 ? bytes[sBase + 4] : bytes[sBase + 12];
        const stShndx = is64 ? dv.getUint16(sBase + 6, isLE) : dv.getUint16(sBase + 14, isLE);
        const stValue = is64 ? u64(sBase + 8) : dv.getUint32(sBase + 4, isLE);
        const stSize = is64 ? u64(sBase + 16) : dv.getUint32(sBase + 8, isLE);

        const symName = readNullTerminatedAscii(bytes, dynstrSec.offset + stName);
        if (!symName) continue;

        if (symName.includes('__stack_chk_fail') || symName.includes('__stack_chk_guard')) {
          hasStackCanary = true;
        }
        if (symName.endsWith('_chk')) {
          hasFortify = true;
        }

        const bind = stInfo >>> 4; // 1 = GLOBAL, 2 = WEAK
        const type = stInfo & 0x0f; // 1 = OBJECT, 2 = FUNC
        const symRecord = {
          name: symName,
          address: '0x' + stValue.toString(16).padStart(8, '0'),
          size: stSize,
          bind: bind === 1 ? 'GLOBAL' : (bind === 2 ? 'WEAK' : 'LOCAL'),
          type: type === 2 ? 'FUNC' : (type === 1 ? 'OBJECT' : 'OTHER')
        };

        if (stShndx === 0) {
          importedSymbols.push(symRecord);
        } else {
          exportedSymbols.push(symRecord);
          const jniInfo = demangleJniSymbol(symName);
          if (jniInfo) {
            jniMethods.push({
              ...jniInfo,
              symbol: symName,
              address: symRecord.address,
              library: fileName
            });
          }
        }
      }
    }

    // 4. Parse .dynamic section for DT_NEEDED shared libraries & BIND_NOW
    const neededLibraries = [];
    let soName = null;
    let bindNow = false;

    if (dynamicSec && dynstrSec && dynamicSec.offset + dynamicSec.size <= bytes.length) {
      const dynEntSize = is64 ? 16 : 8;
      const count = Math.floor(dynamicSec.size / dynEntSize);
      for (let i = 0; i < count; i++) {
        const dBase = dynamicSec.offset + i * dynEntSize;
        const dTag = is64 ? u64(dBase) : dv.getUint32(dBase, isLE);
        const dVal = is64 ? u64(dBase + 8) : dv.getUint32(dBase + 4, isLE);
        if (dTag === 0) break;
        if (dTag === 1) { // DT_NEEDED
          const lib = readNullTerminatedAscii(bytes, dynstrSec.offset + dVal);
          if (lib) neededLibraries.push(lib);
        } else if (dTag === 14) { // DT_SONAME
          soName = readNullTerminatedAscii(bytes, dynstrSec.offset + dVal);
        } else if (dTag === 24 || (dTag === 30 && (dVal & 0x8)) || (dTag === 0x6ffffffb && (dVal & 0x1))) {
          bindNow = true;
        }
      }
    }

    return {
      fileName,
      fileSize: bytes.length,
      bitness: is64 ? '64-bit' : '32-bit',
      endianness: isLE ? 'Little Endian' : 'Big Endian',
      architecture: EM_ARCHITECTURES[eMachine] || `Machine_${eMachine}`,
      elfType: eType === 3 ? 'DYN (Shared Object / PIE)' : (eType === 2 ? 'EXEC' : `TYPE_${eType}`),
      entryPoint: '0x' + eEntry.toString(16),
      soName: soName || fileName.split('/').pop(),
      hardening: {
        pie: eType === 3,
        nx: nxEnabled,
        relro: hasGnuRelro ? (bindNow ? 'Full RELRO' : 'Partial RELRO') : 'None',
        stackCanary: hasStackCanary,
        fortify: hasFortify
      },
      neededLibraries,
      jniMethods,
      exportedSymbols,
      importedSymbols,
      sections,
      programHeaders
    };
  }

  // ==================== STATIC SECURITY & ARCHITECTURE AUDITOR ====================
  function runStaticSecurityAudit(manifest, dexFiles, elfFiles, signingBlock, certificates) {
    const findings = [];
    let score = 100;

    function addFinding(severity, category, title, description, location, cwe, remediation) {
      const weights = { CRITICAL: 18, HIGH: 12, MEDIUM: 6, LOW: 2, INFO: 0 };
      score = Math.max(0, score - (weights[severity] || 0));
      findings.push({
        id: `F-${(findings.length + 1).toString().padStart(3, '0')}`,
        severity,
        category,
        title,
        description,
        location,
        cwe,
        remediation
      });
    }

    // 1. Manifest Security Checks
    if (manifest) {
      if (manifest.debuggable) {
        addFinding(
          'CRITICAL',
          'Manifest / Build Config',
          'Application is Debuggable (android:debuggable="true")',
          'Enabling android:debuggable in production allows local attackers or untrusted apps with shell access to attach JDWP debuggers, dump memory, and execute arbitrary code in the app context.',
          { file: 'AndroidManifest.xml', target: '<application android:debuggable="true">' },
          'CWE-489 / MASVS-RESILIENCE-2',
          'Set android:debuggable="false" in release build variants.'
        );
      }

      if (manifest.usesCleartextTraffic) {
        addFinding(
          'HIGH',
          'Network Security',
          'Cleartext HTTP Traffic Permitted (android:usesCleartextTraffic="true")',
          'The application explicitly permits unencrypted HTTP network connections, exposing sensitive API traffic to Man-in-the-Middle (MitM) interception.',
          { file: 'AndroidManifest.xml', target: '<application android:usesCleartextTraffic="true">' },
          'CWE-319 / MASVS-NETWORK-1',
          'Disable usesCleartextTraffic and enforce TLS 1.2/1.3 via network_security_config.xml.'
        );
      }

      if (manifest.allowBackup) {
        addFinding(
          'MEDIUM',
          'Data Storage',
          'ADB Backup Enabled (android:allowBackup="true")',
          'Allowing full application data backup via adb allows anyone with USB debugging access to extract SharedPreferences, SQLite databases, and tokens.',
          { file: 'AndroidManifest.xml', target: '<application android:allowBackup="true">' },
          'CWE-530 / MASVS-STORAGE-2',
          'Set android:allowBackup="false" or configure restrictive <data-extraction-rules>.'
        );
      }

      // Check exported components without permission protection
      const allComponents = [
        ...manifest.activities.map(c => ({ ...c, type: 'Activity' })),
        ...manifest.services.map(c => ({ ...c, type: 'Service' })),
        ...manifest.receivers.map(c => ({ ...c, type: 'BroadcastReceiver' })),
        ...manifest.providers.map(c => ({ ...c, type: 'ContentProvider' }))
      ];

      for (const comp of allComponents) {
        if (comp.exported && !comp.isMainLauncher && !comp.permission) {
          addFinding(
            comp.type === 'ContentProvider' || comp.type === 'Service' ? 'HIGH' : 'MEDIUM',
            'IPC / Component Exposure',
            `Exported ${comp.type} Without Permission Restriction: ${comp.shortName}`,
            `Component "${comp.name}" is exported and accessible to any third-party app on the device without requiring a custom or signature permission.`,
            { file: 'AndroidManifest.xml', className: comp.name, target: comp.name },
            'CWE-926 / MASVS-PLATFORM-1',
            'Set android:exported="false" if internal, or enforce a signature-level android:permission.'
          );
        }
      }
    }

    // 2. DEX Bytecode & Constant Pool Security Scan
    const extractedUrls = [];
    const extractedSecrets = [];

    const SECRET_REGEXES = [
      { name: 'Hardcoded API Key / Bearer Token', re: /(?:api[_-]?key|secret|token|auth_token|access_key)[a-z0-9_]*\s*[:=]\s*['"]?[A-Za-z0-9_\-]{12,}['"]?/i },
      { name: 'AWS Access Key ID', re: /\bAKIA[0-9A-Z]{16}\b/ },
      { name: 'Google Cloud / Firebase API Key', re: /\bAIza[0-9A-Za-z\-_]{35}\b/ },
      { name: 'Private Key PEM Block', re: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/ },
      { name: 'Hardcoded AES/HMAC Master Secret', re: /\b(?:AES_KEY|MASTER_KEY|HMAC_SECRET|VAULT_SECRET)[A-Za-z0-9_:=\-]{4,}/i }
    ];

    for (const dex of dexFiles) {
      // Scan strings for URLs and secrets
      for (const s of dex.strings) {
        if (/^https?:\/\/[^\s"'<>]+/i.test(s)) {
          const isHttp = s.toLowerCase().startsWith('http://') && !s.includes('schemas.android.com');
          extractedUrls.push({ url: s, dex: dex.dexName, cleartext: isHttp });
          if (isHttp) {
            addFinding(
              'MEDIUM',
              'Network Security',
              `Hardcoded Cleartext HTTP Endpoint: ${s.slice(0, 60)}`,
              `Found unencrypted HTTP URL "${s}" in ${dex.dexName} string pool.`,
              { file: dex.dexName, target: s },
              'CWE-319 / MASVS-NETWORK-1',
              'Migrate endpoint to HTTPS (TLS).'
            );
          }
        }
        for (const rule of SECRET_REGEXES) {
          if (rule.re.test(s)) {
            extractedSecrets.push({ type: rule.name, value: s, dex: dex.dexName });
            addFinding(
              'HIGH',
              'Hardcoded Credentials',
              `${rule.name} Detected in DEX String Pool`,
              `Constant string matching sensitive credential pattern found: "${s.slice(0, 64)}"`,
              { file: dex.dexName, target: s },
              'CWE-798 / MASVS-STORAGE-1',
              'Never embed static API keys or cryptographic keys in DEX bytecode; fetch ephemeral tokens or use Android Keystore.'
            );
          }
        }
      }

      // Scan method instructions for dangerous API calls
      for (const cls of dex.classes) {
        for (const m of cls.allMethods) {
          if (!m.code) continue;
          const insns = m.code.instructions;
          for (let i = 0; i < insns.length; i++) {
            const ins = insns[i];
            if (ins.refType === 'string' && typeof ins.refObj === 'string') {
              const strVal = ins.refObj;
              if (/AES\/ECB/i.test(strVal) || /^DES(\/|$)/i.test(strVal)) {
                addFinding(
                  'HIGH',
                  'Cryptography',
                  `Insecure Cipher Mode (${strVal}) in ${cls.simpleName}.${m.name}()`,
                  `ECB mode or DES cipher ("${strVal}") lacks semantic security and leaks plaintext block patterns.`,
                  { file: dex.dexName, className: cls.fullName, methodName: m.name, target: `${cls.fullName}.${m.name}` },
                  'CWE-327 / MASVS-CRYPTO-1',
                  'Use AES/GCM/NoPadding with a 96-bit random IV and 128-bit authentication tag.'
                );
              }
              if (/^(MD5|SHA-?1)$/i.test(strVal)) {
                addFinding(
                  'MEDIUM',
                  'Cryptography',
                  `Weak Hash Algorithm (${strVal}) in ${cls.simpleName}.${m.name}()`,
                  `Cryptographically broken digest "${strVal}" used in ${cls.fullName}.${m.name}().`,
                  { file: dex.dexName, className: cls.fullName, methodName: m.name, target: `${cls.fullName}.${m.name}` },
                  'CWE-328 / MASVS-CRYPTO-1',
                  'Use SHA-256, SHA-384, or SHA-512.'
                );
              }
            } else if (ins.refType === 'method' && ins.refObj) {
              const mRef = ins.refObj;
              const sig = mRef.signature;

              if (sig.includes('Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V')) {
                addFinding(
                  'MEDIUM',
                  'WebView Security',
                  `WebView JavaScript Enabled in ${cls.simpleName}.${m.name}()`,
                  `Enabling JavaScript in WebView can lead to XSS or bridge exploitation if untrusted URLs or intent extras are loaded.`,
                  { file: dex.dexName, className: cls.fullName, methodName: m.name, target: `${cls.fullName}.${m.name}` },
                  'CWE-79 / MASVS-PLATFORM-2',
                  'Restrict WebView navigation to trusted HTTPS origins and disable file/universal access.'
                );
              }

              if (sig.includes('Landroid/webkit/WebView;->addJavascriptInterface(')) {
                addFinding(
                  'HIGH',
                  'WebView Security',
                  `WebView Native JavaScript Bridge Exposed in ${cls.simpleName}.${m.name}()`,
                  `addJavascriptInterface exposes Java object methods to JavaScript executing inside the WebView.`,
                  { file: dex.dexName, className: cls.fullName, methodName: m.name, target: `${cls.fullName}.${m.name}` },
                  'CWE-749 / MASVS-PLATFORM-2',
                  'Ensure @JavascriptInterface methods validate caller origin and only load pinned HTTPS content.'
                );
              }

              if (sig.includes('Landroid/database/sqlite/SQLiteDatabase;->rawQuery(') ||
                  sig.includes('Landroid/database/sqlite/SQLiteDatabase;->execSQL(')) {
                addFinding(
                  'HIGH',
                  'SQL Injection',
                  `Raw SQL Query Execution in ${cls.simpleName}.${m.name}()`,
                  `Direct invocation of ${mRef.name}() detected in ${cls.fullName}.${m.name}(). If user input is concatenated into the SQL string, local SQL injection is possible.`,
                  { file: dex.dexName, className: cls.fullName, methodName: m.name, target: `${cls.fullName}.${m.name}` },
                  'CWE-89 / MASVS-CODE-4',
                  'Use parameterized queries with "?" placeholders or SQLiteStatement bindings.'
                );
              }

              if (sig.includes('Ljava/lang/Runtime;->exec(') || sig.includes('Ljava/lang/ProcessBuilder;-><init>')) {
                addFinding(
                  'HIGH',
                  'Command Execution',
                  `OS Shell Command Execution in ${cls.simpleName}.${m.name}()`,
                  `Invocation of ${mRef.className}.${mRef.name}() executes native OS processes.`,
                  { file: dex.dexName, className: cls.fullName, methodName: m.name, target: `${cls.fullName}.${m.name}` },
                  'CWE-78 / MASVS-CODE-4',
                  'Avoid shell command execution or strictly whitelist arguments.'
                );
              }

              if (sig.includes('Ldalvik/system/DexClassLoader;-><init>') || sig.includes('Ldalvik/system/InMemoryDexClassLoader;-><init>')) {
                addFinding(
                  'MEDIUM',
                  'Dynamic Code Loading',
                  `Dynamic DEX ClassLoader in ${cls.simpleName}.${m.name}()`,
                  `Application dynamically loads executable DEX bytecode at runtime.`,
                  { file: dex.dexName, className: cls.fullName, methodName: m.name, target: `${cls.fullName}.${m.name}` },
                  'CWE-470 / MASVS-CODE-2',
                  'Verify cryptographic signatures of dynamically loaded code and store exclusively in app-private read-only storage.'
                );
              }
            }
          }
        }
      }
    }

    // 3. Native ELF Binary Hardening Checks
    for (const elf of elfFiles) {
      if (!elf.hardening.stackCanary) {
        addFinding(
          'LOW',
          'Native Binary Hardening',
          `Missing Stack Canary in ${elf.fileName}`,
          `Native library ${elf.fileName} (${elf.architecture}) does not reference __stack_chk_fail stack protector symbols.`,
          { file: elf.fileName, target: elf.fileName },
          'CWE-121 / MASVS-CODE-3',
          'Compile NDK C/C++ code with -fstack-protector-strong.'
        );
      }
    }

    // 4. APK Signing Checks
    if (!signingBlock || (!signingBlock.v2Signed && !signingBlock.v3Signed)) {
      addFinding(
        'MEDIUM',
        'APK Integrity & Signing',
        'Missing APK Signature Scheme v2 / v3 Block',
        'APK relies only on legacy JAR signing (v1) or is unsigned, making it susceptible to Janus-style ZIP/DEX injection on older Android versions.',
        { file: 'APK Signing Block', target: 'META-INF/' },
        'CWE-347 / MASVS-RESILIENCE-1',
        'Sign APK with apksigner enabling v2 and v3 signature schemes.'
      );
    }

    const grade = score >= 90 ? 'A' : (score >= 75 ? 'B' : (score >= 60 ? 'C' : (score >= 45 ? 'D' : 'F')));

    return {
      score,
      grade,
      findings,
      extractedUrls,
      extractedSecrets
    };
  }

  global.ArgonElfSecurity = {
    parseElfBinary,
    demangleJniSymbol,
    runStaticSecurityAudit
  };
})(typeof window !== 'undefined' ? window : globalThis);
