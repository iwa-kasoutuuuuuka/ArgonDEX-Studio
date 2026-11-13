/**
 * ArgonDEX Studio v3.0 — Advanced Static & Native Analysis Engine
 * - Multi-Hop Worklist Inter-Procedural SSA Source-to-Sink Taint Analysis (with Async/Callback bridging)
 * - Dalvik Static String Decryptor (XOR Byte-Array / fill-array-data / Base64 Emulation)
 * - Smart Deobfuscator & Semantic Symbol Renamer (ProGuard/R8 inference)
 * - CFG Dominator Tree & McCabe Cyclomatic Complexity Analyzer
 * - ARM64 (AArch64) Native Machine Code Disassembler (with Symbol/PLT target resolution)
 * - ARM64-to-Pseudo-C Structured Native Decompiler
 * - Automated Frida Dynamic Hook Script Generator (Java + Native JNI Interceptor)
 * - Cryptographic Constant & S-Box Scanner (DEX & ELF .rodata)
 */

(function (global) {
  'use strict';

  // ==================== 1. MULTI-HOP WORKLIST INTER-PROCEDURAL SSA TAINT ENGINE ====================
  const TAINT_SOURCES = [
    { match: 'Landroid/content/Intent;->getStringExtra', label: 'Intent Extra (IPC Input)', category: 'IPC_INPUT', risk: 'HIGH' },
    { match: 'Landroid/content/Intent;->getData', label: 'Intent Deep-Link URI', category: 'URI_INPUT', risk: 'HIGH' },
    { match: 'Landroid/net/Uri;->getQueryParameter', label: 'URI Query Parameter', category: 'URI_INPUT', risk: 'HIGH' },
    { match: 'Landroid/content/SharedPreferences;->getString', label: 'SharedPreferences Storage', category: 'STORAGE_SOURCE', risk: 'MEDIUM' },
    { match: 'Landroid/database/Cursor;->getString', label: 'SQLite Cursor Column', category: 'DB_SOURCE', risk: 'MEDIUM' },
    { match: 'Landroid/widget/EditText;->getText', label: 'User UI Text Input', category: 'UI_INPUT', risk: 'MEDIUM' },
    { match: 'Lcom/argon/vault/NativeBridge;->deriveHardwareKey', label: 'Hardware TEE Derived Key', category: 'SENSITIVE_SECRET', risk: 'CRITICAL' }
  ];

  const TAINT_SINKS = [
    { match: 'Landroid/database/sqlite/SQLiteDatabase;->rawQuery', label: 'SQLite rawQuery() Sink', vuln: 'SQL Injection (CWE-89)', severity: 'CRITICAL' },
    { match: 'Landroid/database/sqlite/SQLiteDatabase;->execSQL', label: 'SQLite execSQL() Sink', vuln: 'SQL Injection (CWE-89)', severity: 'CRITICAL' },
    { match: 'Landroid/webkit/WebView;->loadUrl', label: 'WebView.loadUrl() Sink', vuln: 'Cross-Site Scripting / Arbitrary Navigation (CWE-79)', severity: 'HIGH' },
    { match: 'Landroid/webkit/WebView;->evaluateJavascript', label: 'WebView.evaluateJavascript() Sink', vuln: 'DOM XSS / Code Injection (CWE-94)', severity: 'CRITICAL' },
    { match: 'Ljava/lang/Runtime;->exec', label: 'Runtime.exec() OS Command Sink', vuln: 'OS Command Injection (CWE-78)', severity: 'CRITICAL' },
    { match: 'Landroid/util/Log;->', label: 'Android System Logcat Sink', vuln: 'Sensitive Data Exposure in Logs (CWE-532)', severity: 'MEDIUM' },
    { match: 'Ljava/net/URL;-><init>', label: 'Network URL Connection Sink', vuln: 'Data Exfiltration / SSRF (CWE-918)', severity: 'HIGH' },
    { match: 'Ljavax/crypto/spec/SecretKeySpec;-><init>', label: 'Cryptographic Key Material Sink', vuln: 'Predictable / Static Key Material (CWE-321)', severity: 'HIGH' },
    { match: 'Lcom/argon/vault/NativeBridge;->deriveHardwareKey', label: 'JNI Hardware Key Derivation Sink', vuln: 'Unvalidated Input to Native TEE Key Derivation (CWE-20 / MASVS-CRYPTO-1)', severity: 'HIGH' }
  ];

  function runTaintAnalysis(dexFiles) {
    const taintFlows = [];
    const globalTaintedFields = new Map(); // "Lpkg/Cls;->fieldName" -> TaintRecord
    const methodSummaries = new Map();     // "Lpkg/Cls;->m(Proto)Ret" -> { returnsParamTaint: Set<argSlot>, returnsConstantTaint: TaintRecord|null, paramToSink: Map<argSlot, SinkSummary> }

    // Collect all methods across all DEX files for fixed-point worklist iteration
    const allMethodEntries = [];
    for (const dex of dexFiles) {
      for (const cls of dex.classes) {
        for (const method of cls.allMethods) {
          if (!method.code) continue;
          const sig = `${cls.descriptor}->${method.name}(${method.proto.parameters.join('')})${method.proto.returnType}`;
          allMethodEntries.push({ cls, method, sig });
          methodSummaries.set(sig, {
            returnsParamTaint: new Set(),
            returnsConstantTaint: null,
            paramToSink: new Map()
          });
        }
      }
    }

    // Pass 1: Fixed-Point Worklist Iteration (k = 6 max hops across call graph & fields)
    const MAX_WORKLIST_ITERS = 6;
    for (let iter = 0; iter < MAX_WORKLIST_ITERS; iter++) {
      let changed = false;
      for (const { cls, method, sig } of allMethodEntries) {
        const summary = methodSummaries.get(sig);
        const insns = method.code.instructions;
        const paramStart = method.code.registersSize - method.code.insSize;
        const regParamOrigin = new Map(); // reg -> argSlotIndex (0-based in ins.args)
        for (let slot = 0; slot < method.code.insSize; slot++) {
          regParamOrigin.set(paramStart + slot, slot);
        }
        let pendingReturnOrigin = null;

        for (let i = 0; i < insns.length; i++) {
          const ins = insns[i];
          const op = ins.opcode;
          if (op >= 0x01 && op <= 0x09) {
            if (regParamOrigin.has(ins.vB)) regParamOrigin.set(ins.vA, regParamOrigin.get(ins.vB));
            else regParamOrigin.delete(ins.vA);
          } else if (op >= 0x0a && op <= 0x0c) {
            if (pendingReturnOrigin != null) {
              regParamOrigin.set(ins.vA, pendingReturnOrigin);
              pendingReturnOrigin = null;
            } else {
              regParamOrigin.delete(ins.vA);
            }
          } else if (op >= 0x6e && op <= 0x78) {
            pendingReturnOrigin = null;
            const mRef = ins.refObj;
            if (!mRef) continue;
            const calleeSig = mRef.signature;
            const calleeSum = methodSummaries.get(calleeSig);

            // Propagate through StringBuilder / String / formatting or known callee summaries
            const argOrigins = (ins.args || []).map(r => regParamOrigin.get(r)).filter(v => v != null);
            if (
              argOrigins.length > 0 &&
              (mRef.className === 'java.lang.StringBuilder' || mRef.className === 'java.lang.String' || mRef.name.startsWith('build') || mRef.name.startsWith('format'))
            ) {
              pendingReturnOrigin = argOrigins[0];
              if (ins.args.length > 0) regParamOrigin.set(ins.args[0], argOrigins[0]);
            } else if (calleeSum) {
              for (let aIdx = 0; aIdx < (ins.args || []).length; aIdx++) {
                const callerOrigin = regParamOrigin.get(ins.args[aIdx]);
                if (callerOrigin != null) {
                  if (calleeSum.returnsParamTaint.has(aIdx)) {
                    pendingReturnOrigin = callerOrigin;
                  }
                  if (calleeSum.paramToSink.has(aIdx) && !summary.paramToSink.has(callerOrigin)) {
                    const subSink = calleeSum.paramToSink.get(aIdx);
                    summary.paramToSink.set(callerOrigin, {
                      ...subSink,
                      viaHop: `${mRef.className.split('.').pop()}.${mRef.name}()`
                    });
                    changed = true;
                  }
                }
              }
            }

            // Direct sink hit inside this method
            const matchedSink = TAINT_SINKS.find(snk => calleeSig.startsWith(snk.match));
            if (matchedSink && argOrigins.length > 0) {
              const originSlot = argOrigins[0];
              if (!summary.paramToSink.has(originSlot)) {
                summary.paramToSink.set(originSlot, {
                  sink: matchedSink,
                  calleeSig,
                  viaHop: `${cls.simpleName}.${method.name}()`
                });
                changed = true;
              }
            }
          } else if (op >= 0x0f && op <= 0x11) {
            if (regParamOrigin.has(ins.vA)) {
              const slot = regParamOrigin.get(ins.vA);
              if (!summary.returnsParamTaint.has(slot)) {
                summary.returnsParamTaint.add(slot);
                changed = true;
              }
            }
          }
        }
      }
      if (!changed) break;
    }

    // Pass 2: Full Intra- & Inter-Procedural SSA Taint Flow Extraction
    const emittedKeys = new Set();

    for (const dex of dexFiles) {
      for (const cls of dex.classes) {
        const taintedFields = new Map(); // fieldName -> TaintRecord

        for (const method of cls.allMethods) {
          if (!method.code) continue;
          const insns = method.code.instructions;
          const totalRegs = method.code.registersSize;
          const insSize = method.code.insSize;
          const paramStart = totalRegs - insSize;

          const regTaint = new Map();

          // Entry taint sources: method parameters of String / Uri / Intent
          let pCursor = method.isStatic ? paramStart : paramStart + 1;
          for (let pIdx = 0; pIdx < method.proto.parameters.length; pIdx++) {
            const pDesc = method.proto.parameters[pIdx];
            if (pDesc === 'Ljava/lang/String;' || pDesc === 'Landroid/content/Intent;' || pDesc === 'Landroid/net/Uri;') {
              regTaint.set(pCursor, {
                sourceLabel: `Method Parameter arg${pIdx} (${cls.simpleName}.${method.name})`,
                category: 'METHOD_PARAM',
                risk: 'HIGH',
                steps: [`[Entry] Parameter p${pCursor - paramStart} (arg${pIdx}: ${pDesc.split('/').pop().replace(';', '')}) enters ${cls.simpleName}.${method.name}()`]
              });
            }
            pCursor += (pDesc === 'J' || pDesc === 'D') ? 2 : 1;
          }

          let pendingInvokeTaint = null;

          for (let i = 0; i < insns.length; i++) {
            const ins = insns[i];
            const op = ins.opcode;
            const pcHex = `0x${ins.pc.toString(16).padStart(4, '0')}`;

            // 1. Move propagation
            if (op >= 0x01 && op <= 0x09) {
              if (regTaint.has(ins.vB)) {
                const prev = regTaint.get(ins.vB);
                regTaint.set(ins.vA, {
                  ...prev,
                  steps: [...prev.steps, `[${pcHex}] ${ins.name}: propagates taint v${ins.vB} → v${ins.vA}`]
                });
              } else {
                regTaint.delete(ins.vA);
              }
            }
            // 2. Move-result propagation
            else if (op >= 0x0a && op <= 0x0c) {
              if (pendingInvokeTaint) {
                regTaint.set(ins.vA, {
                  ...pendingInvokeTaint,
                  steps: [...pendingInvokeTaint.steps, `[${pcHex}] ${ins.name}: captures tainted result into v${ins.vA}`]
                });
                pendingInvokeTaint = null;
              } else {
                regTaint.delete(ins.vA);
              }
            }
            // 3. Const-string (hardcoded secret / cleartext HTTP URL, excluding SQL query strings)
            else if (op === 0x1a || op === 0x1b) {
              const sVal = String(ins.refObj || '');
              const isSqlPrefix = /^\s*(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP)\b/i.test(sVal);
              if (!isSqlPrefix && /AIza[0-9A-Za-z\-_]{20,}|AKIA[0-9A-Z]{16}|SECRET_KEY|MASTER_KEY|PRIVATE_KEY/i.test(sVal)) {
                regTaint.set(ins.vA, {
                  sourceLabel: `Hardcoded Credential ("${sVal.slice(0, 28)}...")`,
                  category: 'HARDCODED_SECRET',
                  risk: 'CRITICAL',
                  steps: [`[${pcHex}] const-string loads secret into v${ins.vA}`]
                });
              } else if (sVal.startsWith('http://') && !sVal.includes('schemas.android.com')) {
                regTaint.set(ins.vA, {
                  sourceLabel: `Cleartext HTTP Endpoint ("${sVal.slice(0, 36)}...")`,
                  category: 'CLEARTEXT_URI',
                  risk: 'HIGH',
                  steps: [`[${pcHex}] const-string loads cleartext HTTP URL into v${ins.vA}`]
                });
              } else {
                regTaint.delete(ins.vA);
              }
            }
            // 4. Field reads/writes (intra-class & cross-class globalTaintedFields)
            else if (op >= 0x52 && op <= 0x58) { // iget*
              const f = ins.refObj;
              const gKey = f ? `${f.classDescriptor}->${f.name}` : '';
              const ft = (f && taintedFields.get(f.name)) || globalTaintedFields.get(gKey);
              if (ft) {
                regTaint.set(ins.vA, {
                  ...ft,
                  steps: [...ft.steps, `[${pcHex}] ${ins.name}: loads tainted field ${f.name} into v${ins.vA}`]
                });
              }
            }
            else if (op >= 0x59 && op <= 0x5f) { // iput*
              const f = ins.refObj;
              if (f && regTaint.has(ins.vA)) {
                const rt = regTaint.get(ins.vA);
                const updated = {
                  ...rt,
                  steps: [...rt.steps, `[${pcHex}] ${ins.name}: stores taint from v${ins.vA} into field this.${f.name}`]
                };
                taintedFields.set(f.name, updated);
                globalTaintedFields.set(`${f.classDescriptor}->${f.name}`, updated);
              }
            }
            else if (op >= 0x60 && op <= 0x66) { // sget*
              const f = ins.refObj;
              const gKey = f ? `${f.classDescriptor}->${f.name}` : '';
              const ft = (f && taintedFields.get(f.name)) || globalTaintedFields.get(gKey);
              if (ft) {
                regTaint.set(ins.vA, {
                  ...ft,
                  steps: [...ft.steps, `[${pcHex}] ${ins.name}: loads tainted static field ${f.name} into v${ins.vA}`]
                });
              }
            }
            else if (op >= 0x67 && op <= 0x6d) { // sput*
              const f = ins.refObj;
              if (f && regTaint.has(ins.vA)) {
                const rt = regTaint.get(ins.vA);
                const updated = {
                  ...rt,
                  steps: [...rt.steps, `[${pcHex}] ${ins.name}: stores taint from v${ins.vA} into static field ${f.name}`]
                };
                taintedFields.set(f.name, updated);
                globalTaintedFields.set(`${f.classDescriptor}->${f.name}`, updated);
              }
            }
            // 5. Method Invocations (Sources, Inter-Procedural Summary Propagators, and Direct/Transitive Sinks)
            else if (op >= 0x6e && op <= 0x78) {
              pendingInvokeTaint = null;
              const mRef = ins.refObj;
              if (!mRef) continue;
              const sig = mRef.signature;
              const calleeSummary = methodSummaries.get(sig);

              // Check if invocation is a known Taint Source
              const matchedSource = TAINT_SOURCES.find(src => sig.startsWith(src.match));
              if (matchedSource) {
                pendingInvokeTaint = {
                  sourceLabel: matchedSource.label,
                  category: matchedSource.category,
                  risk: matchedSource.risk,
                  steps: [`[${pcHex}] Source API invoked: ${mRef.className}.${mRef.name}()`]
                };
              }

              const taintedArgs = (ins.args || []).filter(r => regTaint.has(r));
              if (taintedArgs.length > 0) {
                // Prefer newly appended parameter taint (e.g. args[1] in StringBuilder.append) over receiver taint
                const preferredReg = (ins.args && ins.args.length > 1 && regTaint.has(ins.args[1]))
                  ? ins.args[1]
                  : taintedArgs[0];
                const primaryTaint = regTaint.get(preferredReg);
                const touchesPropagator =
                  mRef.className === 'java.lang.StringBuilder' ||
                  mRef.className === 'java.lang.String' ||
                  mRef.name.startsWith('build') ||
                  mRef.name.startsWith('format') ||
                  (calleeSummary && calleeSummary.returnsParamTaint.size > 0);

                if (touchesPropagator) {
                  const propagated = {
                    ...primaryTaint,
                    steps: [...primaryTaint.steps, `[${pcHex}] Taint propagated via ${mRef.className.split('.').pop()}.${mRef.name}()`]
                  };
                  if (ins.args.length > 0) {
                    regTaint.set(ins.args[0], propagated);
                  }
                  pendingInvokeTaint = propagated;
                }

                // Direct Sink hit
                const matchedSink = TAINT_SINKS.find(snk => sig.startsWith(snk.match));
                if (matchedSink) {
                  const dedupKey = `${cls.fullName}#${method.name}#${pcHex}#${matchedSink.label}`;
                  if (!emittedKeys.has(dedupKey)) {
                    emittedKeys.add(dedupKey);
                    taintFlows.push({
                      id: `TF-${(taintFlows.length + 1).toString().padStart(3, '0')}`,
                      severity: matchedSink.severity,
                      vulnerability: matchedSink.vuln,
                      className: cls.fullName,
                      methodName: method.name,
                      source: primaryTaint.sourceLabel,
                      sink: `${matchedSink.label} (${mRef.className.split('.').pop()}.${mRef.name})`,
                      sinkPc: pcHex,
                      steps: [
                        ...primaryTaint.steps,
                        `[${pcHex}] 🚨 SINK REACHED: Tainted register passed to ${mRef.signature}`
                      ]
                    });
                  }
                } else if (calleeSummary) {
                  // Inter-procedural transitive sink hit discovered by Worklist Pass 1!
                  for (let aIdx = 0; aIdx < (ins.args || []).length; aIdx++) {
                    const r = ins.args[aIdx];
                    if (regTaint.has(r) && calleeSummary.paramToSink.has(aIdx)) {
                      const tInfo = regTaint.get(r);
                      const transSink = calleeSummary.paramToSink.get(aIdx);
                      const dedupKey = `${cls.fullName}#${method.name}#${pcHex}#${transSink.sink.label}`;
                      if (!emittedKeys.has(dedupKey)) {
                        emittedKeys.add(dedupKey);
                        taintFlows.push({
                          id: `TF-${(taintFlows.length + 1).toString().padStart(3, '0')}`,
                          severity: transSink.sink.severity,
                          vulnerability: transSink.sink.vuln,
                          className: cls.fullName,
                          methodName: method.name,
                          source: tInfo.sourceLabel,
                          sink: `${transSink.sink.label} (via ${transSink.viaHop})`,
                          sinkPc: pcHex,
                          steps: [
                            ...tInfo.steps,
                            `[${pcHex}] Inter-procedural call → ${mRef.signature}`,
                            `[Transitive] 🚨 SINK REACHED inside ${transSink.viaHop}: ${transSink.calleeSig}`
                          ]
                        });
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }

    return taintFlows;
  }

  // ==================== 1B. DALVIK STATIC STRING DECRYPTOR (XOR / ARRAY EMULATOR) ====================
  function decryptObfuscatedStrings(dexFiles) {
    const decryptedStrings = [];

    for (const dex of dexFiles) {
      for (const cls of dex.classes) {
        for (const method of cls.allMethods) {
          if (!method.code) continue;
          const insns = method.code.instructions;
          const payloadMap = method.code.payloadMap;
          if (!payloadMap || payloadMap.size === 0) continue;

          // Collect XOR key candidates inside this method (xor-int/lit8 0xdf, xor-int/lit16 0xd7, or const)
          const xorKeyCandidates = new Set();
          for (const ins of insns) {
            if (ins.opcode === 0xdf || ins.opcode === 0xd7) {
              xorKeyCandidates.add(ins.literal & 0xff);
            } else if (ins.opcode >= 0x12 && ins.opcode <= 0x14 && typeof ins.literal === 'number') {
              if (ins.literal > 0 && ins.literal <= 0xff) xorKeyCandidates.add(ins.literal & 0xff);
            }
          }

          for (const [payloadPc, payload] of payloadMap.entries()) {
            if (payload.type !== 'array-data' || !payload.rawBytes || payload.rawBytes.length < 4) continue;
            const raw = payload.rawBytes;

            // Try explicit method XOR keys first, then fallback to single-byte key scan if high ASCII confidence
            const keysToTry = [...xorKeyCandidates];
            if (keysToTry.length === 0) {
              for (let k = 1; k < 255; k++) keysToTry.push(k);
            }

            for (const key of keysToTry) {
              let printable = true;
              let alphaNumCount = 0;
              const chars = [];
              for (let b = 0; b < raw.length; b++) {
                const decByte = (raw[b] ^ key) & 0xff;
                if (decByte < 0x20 || decByte > 0x7e) {
                  printable = false;
                  break;
                }
                if ((decByte >= 0x30 && decByte <= 0x39) || (decByte >= 0x41 && decByte <= 0x5a) || (decByte >= 0x61 && decByte <= 0x7a) || decByte === 0x5f) {
                  alphaNumCount++;
                }
                chars.push(String.fromCharCode(decByte));
              }

              if (printable && alphaNumCount >= Math.ceil(raw.length * 0.6)) {
                const plaintext = chars.join('');
                decryptedStrings.push({
                  className: cls.fullName,
                  methodName: method.name,
                  payloadPc: `0x${payloadPc.toString(16).padStart(4, '0')}`,
                  cipherType: `XOR Byte-Array (key=0x${key.toString(16).padStart(2, '0')})`,
                  keyHex: `0x${key.toString(16).padStart(2, '0')}`,
                  encryptedHex: Array.from(raw).map(x => x.toString(16).padStart(2, '0')).join(' '),
                  decrypted: plaintext
                });
                break;
              }
            }
          }
        }
      }
    }

    return decryptedStrings;
  }

  // ==================== 2. DEOBFUSCATION & PACKER/OBFUSCATOR FINGERPRINTER ====================
  function analyzeObfuscationAndGenerateMappings(apk, dexFiles, elfFiles) {
    let totalClasses = 0;
    let shortNamedClasses = 0;
    let totalMethods = 0;
    let shortNamedMethods = 0;
    let totalFields = 0;
    let shortNamedFields = 0;

    const classRenames = new Map();  // fullName -> suggestedFullName
    const methodRenames = new Map(); // fullName#methodName -> suggestedMethodName
    const fieldRenames = new Map();  // fullName#fieldName -> suggestedFieldName
    const renameReasons = [];
    const decryptedStrings = decryptObfuscatedStrings(dexFiles);

    for (const dex of dexFiles) {
      for (const cls of dex.classes) {
        totalClasses++;
        const isObfClass = /^[a-zA-Z]{1,2}(\$[a-zA-Z0-9]{1,2})?$/.test(cls.simpleName);
        if (isObfClass) shortNamedClasses++;

        // Infer semantic class name if obfuscated
        if (isObfClass) {
          let inferredBase = null;
          let reason = '';
          if (cls.superName === 'android.app.Activity' || cls.superName?.endsWith('Activity')) {
            inferredBase = 'InferredActivity';
            reason = `Extends ${cls.superName}`;
          } else if (cls.superName === 'android.app.Service') {
            inferredBase = 'InferredService';
            reason = 'Extends android.app.Service';
          } else if (cls.superName === 'android.content.BroadcastReceiver') {
            inferredBase = 'InferredReceiver';
            reason = 'Extends BroadcastReceiver';
          } else {
            const classStrings = [];
            const calledApis = [];
            for (const m of cls.allMethods) {
              if (!m.code) continue;
              for (const ins of m.code.instructions) {
                if (ins.refType === 'string' && typeof ins.refObj === 'string') classStrings.push(ins.refObj);
                if (ins.refType === 'method' && ins.refObj) calledApis.push(ins.refObj.signature);
              }
            }
            if (calledApis.some(s => s.includes('Cipher') || s.includes('MessageDigest') || s.includes('SecretKey'))) {
              inferredBase = 'CryptoTokenHelper';
              reason = 'Invokes javax.crypto.Cipher / MessageDigest APIs';
            } else if (calledApis.some(s => s.includes('SQLiteDatabase') || s.includes('Cursor'))) {
              inferredBase = 'SqliteDaoHelper';
              reason = 'Invokes android.database.sqlite APIs';
            } else if (calledApis.some(s => s.includes('Http') || s.includes('WebView') || classStrings.some(u => u.startsWith('http')))) {
              inferredBase = 'NetworkTransportHelper';
              reason = 'Contains HTTP endpoints / network transport calls';
            } else {
              inferredBase = `DeobfComponent_${cls.simpleName.toUpperCase()}`;
              reason = 'Short single-letter ProGuard/R8 identifier';
            }
          }

          const newFull = cls.packageName ? `${cls.packageName}.${inferredBase}` : inferredBase;
          classRenames.set(cls.fullName, {
            originalSimple: cls.simpleName,
            originalFull: cls.fullName,
            newSimple: inferredBase,
            newFull,
            reason
          });
          renameReasons.push({
            kind: 'CLASS',
            original: cls.fullName,
            renamed: newFull,
            reason
          });
        }

        // Check fields
        for (const f of [...cls.staticFields, ...cls.instanceFields]) {
          totalFields++;
          if (/^[a-zA-Z]{1,2}$/.test(f.name)) {
            shortNamedFields++;
            const typeJava = global.ArgonDex.descriptorToJavaType(f.typeDescriptor).replace(/\[\]/g, 'Array');
            const newFieldName = `m${typeJava}_${f.name}`;
            fieldRenames.set(`${cls.fullName}#${f.name}`, newFieldName);
            renameReasons.push({
              kind: 'FIELD',
              original: `${cls.simpleName}.${f.name}`,
              renamed: newFieldName,
              reason: `Typed field inference (${f.typeDescriptor})`
            });
          }
        }

        // Check methods
        for (const m of cls.allMethods) {
          if (m.isConstructor) continue;
          totalMethods++;
          if (/^[a-zA-Z]{1,2}$/.test(m.name)) {
            shortNamedMethods++;
            let semanticName = `method_${m.name}`;
            let mReason = 'Signature & opcode pattern inference';

            if (m.code) {
              const apis = m.code.instructions
                .filter(ins => ins.refType === 'method' && ins.refObj)
                .map(ins => ins.refObj.name);
              if (apis.includes('getInstance') || apis.includes('doFinal')) {
                semanticName = `transformCrypto_${m.name}`;
                mReason = 'Calls cryptographic transformation APIs';
              } else if (apis.includes('rawQuery') || apis.includes('execSQL')) {
                semanticName = `executeQuery_${m.name}`;
                mReason = 'Calls SQLite query execution API';
              } else if (apis.includes('append') && apis.includes('toString')) {
                semanticName = `formatString_${m.name}`;
                mReason = 'Builds string via StringBuilder chain';
              } else if (m.proto.returnType === 'Z') {
                semanticName = `checkCondition_${m.name}`;
                mReason = 'Boolean predicate method';
              } else if (m.proto.returnType === 'I') {
                semanticName = `computeInt_${m.name}`;
                mReason = 'Integer computation & XOR array method';
              }
            }
            methodRenames.set(`${cls.fullName}#${m.name}`, semanticName);
            renameReasons.push({
              kind: 'METHOD',
              original: `${cls.simpleName}.${m.name}()`,
              renamed: `${semanticName}()`,
              reason: mReason
            });
          }
        }
      }
    }

    const obfuscationRatio = totalClasses + totalMethods + totalFields > 0
      ? Math.round(((shortNamedClasses + shortNamedMethods + shortNamedFields) / (totalClasses + totalMethods + totalFields)) * 100)
      : 0;

    // Detect Frameworks, Packers & Toolchains
    const fingerprints = [];
    const entryNames = (apk && apk.entries) ? apk.entries.map(e => e.name) : [];
    if (entryNames.some(n => n.includes('libflutter.so') || n.includes('libapp.so'))) {
      fingerprints.push({ name: 'Flutter / Dart AOT Engine', type: 'Framework', confidence: 'High' });
    }
    if (entryNames.some(n => n.includes('libhermes.so') || n.includes('index.android.bundle'))) {
      fingerprints.push({ name: 'React Native (Hermes Bytecode)', type: 'Framework', confidence: 'High' });
    }
    if (entryNames.some(n => n.includes('libil2cpp.so'))) {
      fingerprints.push({ name: 'Unity 3D (IL2CPP Native)', type: 'Game Engine', confidence: 'High' });
    }
    if (shortNamedClasses > 0 || shortNamedMethods > 0) {
      fingerprints.push({
        name: 'R8 / ProGuard Identifier Minification',
        type: 'Obfuscator',
        confidence: `${obfuscationRatio}% Symbol Density`
      });
    }
    if (decryptedStrings.length > 0) {
      fingerprints.push({
        name: `XOR Byte-Array String Encryption (${decryptedStrings.length} decrypted)`,
        type: 'String Obfuscation',
        confidence: 'Statically Decrypted'
      });
    }
    if (elfFiles && elfFiles.length > 0) {
      fingerprints.push({
        name: `Android NDK Native JNI (${elfFiles.map(e => e.architecture).join(', ')})`,
        type: 'Native Toolchain',
        confidence: 'Confirmed'
      });
    }
    if (apk && apk.signingBlock && (apk.signingBlock.v2Signed || apk.signingBlock.v3Signed)) {
      fingerprints.push({
        name: `Android apksigner (Scheme ${apk.signingBlock.v3Signed ? 'v2 + v3' : 'v2'})`,
        type: 'Build / Signing',
        confidence: 'Confirmed'
      });
    }

    return {
      obfuscationRatio,
      shortNamedClasses,
      shortNamedMethods,
      shortNamedFields,
      classRenames,
      methodRenames,
      fieldRenames,
      renameReasons,
      fingerprints,
      decryptedStrings
    };
  }

  function escapeRegExp(str) {
    return String(str).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  function applySmartDeobfuscationToJava(javaSource, cls, deobfData) {
    if (!deobfData || !cls) return javaSource;
    let out = javaSource;

    // 1. Context-aware field replacements (declarations "Type f;" and field accesses "this.f")
    for (const f of [...(cls.staticFields || []), ...(cls.instanceFields || [])]) {
      const key = `${cls.fullName}#${f.name}`;
      if (deobfData.fieldRenames && deobfData.fieldRenames.has(key)) {
        const newName = deobfData.fieldRenames.get(key);
        const safeF = escapeRegExp(f.name);
        const fDeclRe = new RegExp(`(\\b(?:private|public|protected|static|final|volatile|transient)\\s+[A-Za-z0-9_<>\\[\\]]+\\s+)${safeF}(\\s*[=;])`, 'g');
        out = out.replace(fDeclRe, `$1${newName}$2`);
        const fAccessRe = new RegExp(`\\bthis\\.${safeF}\\b`, 'g');
        out = out.replace(fAccessRe, `this.${newName}`);
      }
    }

    // 2. Context-aware class & constructor replacement
    if (deobfData.classRenames && deobfData.classRenames.has(cls.fullName)) {
      const info = deobfData.classRenames.get(cls.fullName);
      const safeC = escapeRegExp(info.originalSimple || info.oldShort || '');
      const newSimple = info.newSimple || info.newShort || safeC;
      if (safeC) {
        const clsDeclRe = new RegExp(`(\\b(?:class|interface|enum)\\s+)${safeC}\\b`, 'g');
        out = out.replace(clsDeclRe, `$1${newSimple} /* obf: ${info.originalSimple || safeC} */`);
        const ctorRe = new RegExp(`(\\b(?:public|protected|private)\\s+)${safeC}\\(`, 'g');
        out = out.replace(ctorRe, `$1${newSimple}(`);
      }
      if (info.originalFull && info.newFull) {
        out = `// [ArgonDEX Smart Deobfuscator] Renamed class '${info.originalFull}' -> '${info.newFull}' (${info.reason})\n` + out;
      }
    }

    // 3. Context-aware method replacements (method declarations & calls, excluding constructor)
    for (const m of (cls.allMethods || [])) {
      if (m.isConstructor) continue;
      const key = `${cls.fullName}#${m.name}`;
      if (deobfData.methodRenames && deobfData.methodRenames.has(key)) {
        const newName = deobfData.methodRenames.get(key);
        const safeM = escapeRegExp(m.name);
        const mDeclRe = new RegExp(`(\\b(?:void|boolean|byte|short|char|int|long|float|double|String|Object|Cursor|[A-Za-z0-9_]+\\[\\])\\s+)${safeM}\\(`, 'g');
        out = out.replace(mDeclRe, `$1${newName}(`);
        const mCallRe = new RegExp(`\\.${safeM}\\(`, 'g');
        out = out.replace(mCallRe, `.${newName}(`);
      }
    }

    // 4. Annotate statically decrypted XOR byte arrays in deobfuscated Java
    if (deobfData.decryptedStrings && deobfData.decryptedStrings.length > 0) {
      for (const dec of deobfData.decryptedStrings) {
        if (dec.className === cls.fullName) {
          out = out.replace(
            /(new\s+byte\[\]\s*\{[^}]+\})/,
            `$1 /* 🔓 Decrypted ${dec.cipherType}: "${dec.decrypted}" */`
          );
        }
      }
    }

    return out;
  }

  // ==================== 3. CFG DOMINATOR TREE & CYCLOMATIC COMPLEXITY ====================
  function computeCfgMetrics(cfg) {
    const N = cfg.blocks.length;
    const E = cfg.edges.length;
    if (N === 0) {
      return { cyclomaticComplexity: 1, blockCount: 0, edgeCount: 0, loopCount: 0, dominators: [], dominatorMap: new Map() };
    }
    const cyclomaticComplexity = Math.max(1, E - N + 2);
    let backEdges = 0;
    for (const edge of cfg.edges) {
      if (edge.toIndex <= edge.fromIndex) backEdges++;
    }

    const dom = new Array(N);
    dom[0] = new Set([0]);
    for (let i = 1; i < N; i++) {
      const all = new Set();
      for (let k = 0; k < N; k++) all.add(k);
      dom[i] = all;
    }

    let changed = true;
    let iter = 0;
    while (changed && iter++ < 50) {
      changed = false;
      for (let i = 1; i < N; i++) {
        const preds = cfg.blocks[i].inEdges.map(e => e.fromIndex);
        let newDom;
        if (preds.length === 0) {
          newDom = new Set([i]);
        } else {
          newDom = new Set(dom[preds[0]]);
          for (let p = 1; p < preds.length; p++) {
            const predSet = dom[preds[p]];
            for (const elem of Array.from(newDom)) {
              if (!predSet.has(elem)) newDom.delete(elem);
            }
          }
          newDom.add(i);
        }
        if (newDom.size !== dom[i].size) {
          dom[i] = newDom;
          changed = true;
        }
      }
    }

    const dominatorMap = new Map();
    const dominators = cfg.blocks.map((b, idx) => {
      if (idx === 0) {
        dominatorMap.set(b.id, '(Entry Root)');
        return { blockId: b.id, idom: '(Entry Root)', domSet: ['B0'] };
      }
      const strictDoms = Array.from(dom[idx]).filter(d => d !== idx);
      const idomIdx = strictDoms.length ? strictDoms[strictDoms.length - 1] : 0;
      const idomStr = `B${idomIdx}`;
      dominatorMap.set(b.id, idomStr);
      return {
        blockId: b.id,
        idom: idomStr,
        domSet: Array.from(dom[idx]).map(d => `B${d}`)
      };
    });

    return {
      cyclomaticComplexity,
      blockCount: N,
      edgeCount: E,
      loopCount: backEdges,
      dominators,
      dominatorMap
    };
  }

  // ==================== 4. ARM64 (AARCH64) DISASSEMBLER & PSEUDO-C DECOMPILER ====================
  function regX(n, is64 = true) {
    if (n === 31) return is64 ? 'xzr/sp' : 'wzr';
    return (is64 ? 'x' : 'w') + n;
  }

  function decodeArm64Instruction(word, vaddr, symAtVaddr = null) {
    if (word === 0xd503233f) return { mnemonic: 'paciasp', operands: '', comment: 'Pointer Authentication prologue' };
    if (word === 0xd50323bf) return { mnemonic: 'autiasp', operands: '', comment: 'Pointer Authentication epilogue' };
    if (word === 0xd65f03c0) return { mnemonic: 'ret', operands: 'x30', comment: 'Subroutine return' };
    if ((word & 0xfffffc1f) === 0xd65f0000) {
      const rn = (word >>> 5) & 0x1f;
      return { mnemonic: 'ret', operands: regX(rn), comment: 'Return to register' };
    }
    if (word === 0xd503201f) return { mnemonic: 'nop', operands: '', comment: 'No operation' };

    const sf = (word >>> 31) & 1;
    const is64 = sf === 1;
    const rd = word & 0x1f;
    const rn = (word >>> 5) & 0x1f;
    const rm = (word >>> 16) & 0x1f;

    // Move Wide Immediate: MOVZ (opc=10), MOVN (opc=00), MOVK (opc=11)
    if (((word >>> 23) & 0x3f) === 0x25) {
      const opc = (word >>> 29) & 0x3;
      const hw = ((word >>> 21) & 0x3) * 16;
      const imm16 = (word >>> 5) & 0xffff;
      const mnem = opc === 2 ? 'movz' : (opc === 3 ? 'movk' : 'movn');
      const shiftStr = hw > 0 ? `, lsl #${hw}` : '';
      return {
        mnemonic: mnem,
        operands: `${regX(rd, is64)}, #0x${imm16.toString(16)}${shiftStr}`,
        comment: hw === 0 && opc === 2 ? `=${imm16}` : '',
        rd, is64, imm16, hw
      };
    }

    // ADD / SUB (immediate)
    if (((word >>> 23) & 0x3f) === 0x22) {
      const isSub = ((word >>> 30) & 1) === 1;
      const imm12 = (word >>> 10) & 0xfff;
      const sh = ((word >>> 22) & 1) ? 12 : 0;
      const val = imm12 << sh;
      return {
        mnemonic: isSub ? 'sub' : 'add',
        operands: `${regX(rd, is64)}, ${regX(rn, is64)}, #0x${val.toString(16)}`,
        comment: `${val}`,
        rd, rn, is64, imm: val
      };
    }

    // ADD / SUB (shifted register)
    if (((word >>> 24) & 0x1f) === 0x0b) {
      const isSub = ((word >>> 30) & 1) === 1;
      if (!isSub && rn === 31) {
        return { mnemonic: 'mov', operands: `${regX(rd, is64)}, ${regX(rm, is64)}`, comment: 'Register copy', rd, rm, is64 };
      }
      return {
        mnemonic: isSub ? 'sub' : 'add',
        operands: `${regX(rd, is64)}, ${regX(rn, is64)}, ${regX(rm, is64)}`,
        comment: '',
        rd, rn, rm, is64
      };
    }

    // Logical (shifted register): AND (00), ORR (01), EOR (10)
    if (((word >>> 24) & 0x1f) === 0x0a) {
      const opc = (word >>> 29) & 0x3;
      if (opc === 1 && rn === 31) {
        return { mnemonic: 'mov', operands: `${regX(rd, is64)}, ${regX(rm, is64)}`, comment: 'ORR alias', rd, rm, is64 };
      }
      const mnem = opc === 0 ? 'and' : (opc === 1 ? 'orr' : (opc === 2 ? 'eor' : 'ands'));
      return {
        mnemonic: mnem,
        operands: `${regX(rd, is64)}, ${regX(rn, is64)}, ${regX(rm, is64)}`,
        comment: '',
        rd, rn, rm, is64
      };
    }

    // Unconditional Branch (immediate): B / BL with Symbol / PLT target resolution
    if (((word >>> 26) & 0x1f) === 0x05) {
      const isLink = ((word >>> 31) & 1) === 1;
      let imm26 = word & 0x03ffffff;
      if (imm26 & 0x02000000) imm26 -= 0x04000000;
      const target = vaddr + imm26 * 4;
      const resolvedSym = (symAtVaddr && symAtVaddr.get(target)) || `sub_${target.toString(16)}`;
      return {
        mnemonic: isLink ? 'bl' : 'b',
        operands: `0x${target.toString(16)} <${resolvedSym}>`,
        comment: isLink ? `Call ${resolvedSym}()` : `Jump to ${resolvedSym}`,
        target,
        targetSymbol: resolvedSym
      };
    }

    // CBZ / CBNZ (Compare and Branch on Zero / Non-Zero)
    if (((word >>> 25) & 0x3f) === 0x1a) {
      const isNz = ((word >>> 24) & 1) === 1;
      let imm19 = (word >>> 5) & 0x7ffff;
      if (imm19 & 0x40000) imm19 -= 0x80000;
      const target = vaddr + imm19 * 4;
      return {
        mnemonic: isNz ? 'cbnz' : 'cbz',
        operands: `${regX(rd, is64)}, 0x${target.toString(16)}`,
        comment: isNz ? 'Branch if != 0' : 'Branch if == 0',
        rd, target
      };
    }

    // STP / LDP (64-bit pre/post/signed offset)
    if (((word >>> 25) & 0x1f) === 0x14 || ((word >>> 25) & 0x1f) === 0x15) {
      const isLoad = ((word >>> 22) & 1) === 1;
      const rt2 = (word >>> 10) & 0x1f;
      return {
        mnemonic: isLoad ? 'ldp' : 'stp',
        operands: `${regX(rd, true)}, ${regX(rt2, true)}, [${regX(rn, true)}]`,
        comment: isLoad ? 'Load pair (epilogue)' : 'Store pair (prologue)'
      };
    }

    // LDR / STR (unsigned immediate 64/32-bit)
    if (((word >>> 24) & 0x3f) === 0x39) {
      const isLoad = ((word >>> 22) & 1) === 1;
      const imm12 = ((word >>> 10) & 0xfff) * (is64 ? 8 : 4);
      return {
        mnemonic: isLoad ? 'ldr' : 'str',
        operands: `${regX(rd, is64)}, [${regX(rn, true)}${imm12 ? ', #0x' + imm12.toString(16) : ''}]`,
        comment: '',
        rd, rn, imm: imm12, is64
      };
    }

    return {
      mnemonic: '.word',
      operands: `0x${(word >>> 0).toString(16).padStart(8, '0')}`,
      comment: 'AArch64 instruction word'
    };
  }

  function disassembleElfTextSection(bytes, elfMeta) {
    const textSec = elfMeta.sections.find(s => s.name === '.text');
    if (!textSec || textSec.size === 0 || textSec.offset + textSec.size > bytes.length) {
      return [];
    }

    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const baseVaddr = 0x1000;
    const symAtVaddr = new Map();
    for (const exp of (elfMeta.exportedSymbols || [])) {
      const addrNum = parseInt(exp.address, 16);
      symAtVaddr.set(addrNum, exp.name);
    }

    // First pass: identify internal subroutine targets (BL targets) so unnamed helpers also get labels
    const wordCount = Math.min(512, Math.floor(textSec.size / 4));
    for (let i = 0; i < wordCount; i++) {
      const fileOff = textSec.offset + i * 4;
      const vaddr = baseVaddr + i * 4;
      const word = dv.getUint32(fileOff, true);
      if (((word >>> 26) & 0x1f) === 0x05 && ((word >>> 31) & 1) === 1) {
        let imm26 = word & 0x03ffffff;
        if (imm26 & 0x02000000) imm26 -= 0x04000000;
        const target = vaddr + imm26 * 4;
        if (!symAtVaddr.has(target)) {
          symAtVaddr.set(target, `sub_${target.toString(16)}_internal`);
        }
      }
    }

    const lines = [];
    for (let i = 0; i < wordCount; i++) {
      const fileOff = textSec.offset + i * 4;
      const vaddr = baseVaddr + i * 4;
      const word = dv.getUint32(fileOff, true);
      const decoded = decodeArm64Instruction(word, vaddr, symAtVaddr);
      const hexBytes = [
        bytes[fileOff].toString(16).padStart(2, '0'),
        bytes[fileOff + 1].toString(16).padStart(2, '0'),
        bytes[fileOff + 2].toString(16).padStart(2, '0'),
        bytes[fileOff + 3].toString(16).padStart(2, '0')
      ].join(' ');

      lines.push({
        label: symAtVaddr.get(vaddr) || null,
        vaddr: '0x' + vaddr.toString(16).padStart(8, '0'),
        fileOffset: '0x' + fileOff.toString(16).padStart(4, '0'),
        hexBytes,
        mnemonic: decoded.mnemonic,
        operands: decoded.operands,
        comment: decoded.comment,
        _decoded: decoded
      });
    }
    return lines;
  }

  /**
   * Decompiles ARM64 (.text) disassembly into structured Pseudo-C functions
   * with JNI parameter typing (JNIEnv* env, jobject thiz, ...) and symbolic expression folding.
   */
  function decompileArm64ToPseudoC(bytes, elfMeta) {
    const disasm = elfMeta.disassembly && elfMeta.disassembly.length > 0
      ? elfMeta.disassembly
      : disassembleElfTextSection(bytes, elfMeta);
    if (!disasm || disasm.length === 0) return '// No .text instructions available for Pseudo-C decompilation.';

    // Group instructions by function labels
    const functions = [];
    let currentFn = null;
    for (const ins of disasm) {
      if (ins.label) {
        currentFn = { name: ins.label, vaddr: ins.vaddr, insns: [] };
        functions.push(currentFn);
      } else if (!currentFn) {
        currentFn = { name: `sub_${ins.vaddr.replace(/^0x0*/, '')}`, vaddr: ins.vaddr, insns: [] };
        functions.push(currentFn);
      }
      currentFn.insns.push(ins);
    }

    const cBlocks = [
      '/*',
      ` * ArgonDEX Studio — ARM64 (AArch64) to Pseudo-C Native Decompiler`,
      ` * Binary: ${elfMeta.fileName} (${elfMeta.architecture})`,
      ' */',
      '#include <jni.h>',
      '#include <stdint.h>',
      ''
    ];

    for (const fn of functions) {
      let signature;
      const regExpr = new Map();

      if (fn.name === 'JNI_OnLoad') {
        signature = `JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm /* x0 */, void* reserved /* x1 */)`;
        regExpr.set(0, 'vm');
        regExpr.set(1, 'reserved');
      } else if (fn.name.startsWith('Java_')) {
        signature = `JNIEXPORT uint64_t JNICALL ${fn.name}(JNIEnv* env /* x0 */, jobject thiz /* x1 */, uint64_t arg0 /* x2 */, uint64_t arg1 /* x3 */)`;
        regExpr.set(0, 'env');
        regExpr.set(1, 'thiz');
        regExpr.set(2, 'arg0');
        regExpr.set(3, 'arg1');
      } else {
        signature = `static uint64_t ${fn.name}(uint64_t a0 /* x0 */, uint64_t a1 /* x1 */)`;
        regExpr.set(0, 'a0');
        regExpr.set(1, 'a1');
      }

      const body = [];
      const getR = (r) => regExpr.has(r) ? regExpr.get(r) : (r === 31 ? 'sp' : `x${r}`);
      let movzConst = new Map(); // reg -> numeric value for MOVZ+MOVK folding

      for (const ins of fn.insns) {
        const d = ins._decoded || {};
        const m = ins.mnemonic;

        if (m === 'stp' || m === 'ldp' || m === 'paciasp' || m === 'autiasp' || m === 'nop') {
          continue; // Hide stack frame prologue/epilogue noise
        } else if (m === 'movz') {
          const val = (d.imm16 || 0) << (d.hw || 0);
          movzConst.set(d.rd, val >>> 0);
          regExpr.set(d.rd, `0x${(val >>> 0).toString(16)}`);
        } else if (m === 'movk') {
          const prev = movzConst.get(d.rd) || 0;
          const combined = (prev | ((d.imm16 || 0) << (d.hw || 0))) >>> 0;
          movzConst.set(d.rd, combined);
          const comment = combined === 0x10006 ? ' /* JNI_VERSION_1_6 */' : '';
          regExpr.set(d.rd, `0x${combined.toString(16)}${comment}`);
        } else if (m === 'mov') {
          const src = getR(d.rm);
          if (d.rd >= 19 && d.rd <= 28) {
            body.push(`    uint64_t x${d.rd} = ${src};`);
            regExpr.set(d.rd, `x${d.rd}`);
          } else {
            regExpr.set(d.rd, src);
          }
        } else if (m === 'add' || m === 'sub' || m === 'eor' || m === 'orr' || m === 'and') {
          const opMap = { add: '+', sub: '-', eor: '^', orr: '|', and: '&' };
          const sym = opMap[m] || '+';
          if (d.rd === 31 || d.rn === 31) continue; // Stack pointer adjustment
          const lhs = getR(d.rn);
          const rhs = d.imm != null ? `0x${d.imm.toString(16)}` : getR(d.rm);
          const expr = `(${lhs} ${sym} ${rhs})`;
          body.push(`    uint64_t v_${ins.vaddr.slice(-4)} = ${expr};`);
          regExpr.set(d.rd, `v_${ins.vaddr.slice(-4)}`);
        } else if (m === 'ldr') {
          const base = getR(d.rn);
          const off = d.imm ? ` + 0x${d.imm.toString(16)}` : '';
          const loadExpr = `*(uint64_t*)((uintptr_t)${base}${off})`;
          body.push(`    uint64_t mem_${ins.vaddr.slice(-4)} = ${loadExpr};`);
          regExpr.set(d.rd, `mem_${ins.vaddr.slice(-4)}`);
        } else if (m === 'str') {
          const base = getR(d.rn);
          const off = d.imm ? ` + 0x${d.imm.toString(16)}` : '';
          body.push(`    *(uint64_t*)((uintptr_t)${base}${off}) = ${getR(d.rd)};`);
        } else if (m === 'bl') {
          const callee = d.targetSymbol || `sub_${(d.target || 0).toString(16)}`;
          const callExpr = `${callee}(${getR(0)}, ${getR(1)})`;
          body.push(`    uint64_t call_${ins.vaddr.slice(-4)} = ${callExpr};`);
          regExpr.set(0, `call_${ins.vaddr.slice(-4)}`);
        } else if (m === 'cbz' || m === 'cbnz') {
          const condOp = m === 'cbz' ? '==' : '!=';
          body.push(`    if (${getR(d.rd)} ${condOp} 0) goto loc_${(d.target || 0).toString(16)};`);
        } else if (m === 'ret') {
          body.push(`    return ${getR(0)};`);
          break; // Stop linear function body after terminal return
        }
      }

      if (body.length === 0) {
        body.push(`    return ${getR(0)};`);
      }

      cBlocks.push(`// @vaddr ${fn.vaddr}`);
      cBlocks.push(`${signature} {`);
      cBlocks.push(...body);
      cBlocks.push('}');
      cBlocks.push('');
    }

    return cBlocks.join('\n');
  }

  // ==================== 5. AUTOMATED FRIDA DYNAMIC HOOK SCRIPT GENERATOR ====================
  function generateFridaHookScript(apk, manifestInfo, dexFiles, elfFiles, taintFlows, deobfData) {
    const pkg = (manifestInfo && manifestInfo.packageName) || 'com.target.app';
    const lines = [
      '/**',
      ` * ArgonDEX Studio — Auto-Generated Frida Dynamic Instrumentation Script`,
      ` * Target APK : ${(apk && apk.fileName) || 'app.apk'} (${pkg})`,
      ` * Run Command: frida -U -f ${pkg} -l frida_argon_hooks.js --no-pause`,
      ' */',
      '',
      'Java.perform(function () {',
      `  console.log("[*] ArgonDEX Frida Hook Suite attached to ${pkg}");`,
      '',
      '  // 1. Cryptographic Key & Cipher Interceptor (MASVS-CRYPTO)',
      '  try {',
      '    var Cipher = Java.use("javax.crypto.Cipher");',
      '    Cipher.getInstance.overload("java.lang.String").implementation = function (transformation) {',
      '      console.log("[Crypto] Cipher.getInstance(\\"" + transformation + "\\")");',
      '      return this.getInstance(transformation);',
      '    };',
      '  } catch (e) {}',
      ''
    ];

    // 2. Hook Taint Sinks & Vulnerable Methods discovered by SSA Taint Engine
    const hookedMethods = new Set();
    for (const tf of (taintFlows || [])) {
      const hookKey = `${tf.className}#${tf.methodName}`;
      if (hookedMethods.has(hookKey)) continue;
      hookedMethods.add(hookKey);
      lines.push(`  // [Taint Flow ${tf.id}] ${tf.vulnerability} in ${tf.className}.${tf.methodName}`);
      lines.push('  try {');
      lines.push(`    var Cls_${tf.id.replace('-', '_')} = Java.use(${JSON.stringify(tf.className)});`);
      lines.push(`    Cls_${tf.id.replace('-', '_')}[${JSON.stringify(tf.methodName)}].overloads.forEach(function (ov) {`);
      lines.push('      ov.implementation = function () {');
      lines.push(`        console.log("[🚨 ${tf.id}] ${tf.className}.${tf.methodName}() invoked with args:", JSON.stringify(Array.prototype.slice.call(arguments)));`);
      lines.push('        var ret = ov.apply(this, arguments);');
      lines.push(`        console.log("[🚨 ${tf.id}] ${tf.className}.${tf.methodName}() returned:", ret);`);
      lines.push('        return ret;');
      lines.push('      };');
      lines.push('    });');
      lines.push('  } catch (e) {}');
      lines.push('');
    }

    // 3. Hook Obfuscated Classes reconstructed by Smart Deobfuscator
    if (deobfData && deobfData.classRenames) {
      for (const [origFull, info] of deobfData.classRenames.entries()) {
        lines.push(`  // [Deobfuscated Class] ${origFull} -> ${info.newFull} (${info.reason})`);
        lines.push('  try {');
        lines.push(`    var ObfCls = Java.use(${JSON.stringify(origFull)});`);
        lines.push('    console.log("[Deobf] Loaded obfuscated class:", ' + JSON.stringify(origFull) + ');');
        lines.push('  } catch (e) {}');
        lines.push('');
      }
    }

    lines.push('});');
    lines.push('');

    // 4. Native ELF (.so) JNI Interceptor hooks
    for (const elf of (elfFiles || [])) {
      const soShort = elf.fileName.split('/').pop();
      lines.push(`// ==================== NATIVE ELF HOOKS: ${soShort} ====================`);
      for (const jni of (elf.jniMethods || [])) {
        lines.push(`try {`);
        lines.push(`  var sym_${jni.symbol} = Module.findExportByName(${JSON.stringify(soShort)}, ${JSON.stringify(jni.symbol)});`);
        lines.push(`  if (sym_${jni.symbol}) {`);
        lines.push(`    Interceptor.attach(sym_${jni.symbol}, {`);
        lines.push(`      onEnter: function (args) {`);
        lines.push(`        console.log("[Native JNI] -> ${jni.symbol} @ " + sym_${jni.symbol} + " | x2=" + args[2] + " x3=" + args[3]);`);
        lines.push(`      },`);
        lines.push(`      onLeave: function (retval) {`);
        lines.push(`        console.log("[Native JNI] <- ${jni.symbol} returned: " + retval);`);
        lines.push(`      }`);
        lines.push(`    });`);
        lines.push(`  }`);
        lines.push(`} catch (e) {}`);
        lines.push('');
      }
    }

    return lines.join('\n');
  }

  // ==================== 6. CRYPTOGRAPHIC S-BOX & CONSTANT SCANNER ====================
  function scanCryptographicConstants(apkEntries, rawApkBytes) {
    const hits = [];
    const SIGNATURES = [
      {
        name: 'AES Rijndael Forward S-Box (256-byte lookup table)',
        algo: 'AES-128/192/256',
        pattern: [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76]
      },
      {
        name: 'SHA-256 / SHA-224 Initial Hash Vector H0 (0x6a09e667)',
        algo: 'SHA-256',
        pattern: [0x67, 0xe6, 0x09, 0x6a, 0x85, 0xae, 0x67, 0xbb]
      },
      {
        name: 'ChaCha20 / Salsa20 Sigma Constant ("expand 32-byte k")',
        algo: 'ChaCha20 Stream Cipher',
        pattern: [0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x33, 0x32, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6b]
      }
    ];

    for (const sig of SIGNATURES) {
      const pat = sig.pattern;
      const firstByte = pat[0];
      const maxStart = rawApkBytes.length - pat.length;
      let pos = 0;
      while (pos <= maxStart) {
        pos = rawApkBytes.indexOf(firstByte, pos);
        if (pos === -1 || pos > maxStart) break;
        let match = true;
        for (let k = 1; k < pat.length; k++) {
          if (rawApkBytes[pos + k] !== pat[k]) {
            match = false;
            break;
          }
        }
        if (match) {
          hits.push({
            algorithm: sig.algo,
            description: sig.name,
            archiveOffset: '0x' + pos.toString(16).padStart(8, '0'),
            previewHex: pat.slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join(' ') + ' ...'
          });
          break;
        }
        pos++;
      }
    }

    return hits;
  }

  // ==================== 7. APK VERSION BINDIFF & UNIFIED AST DIFF ENGINE ====================
  function buildLineUnifiedDiff(oldText, newText, labelA = 'a', labelB = 'b') {
    const aLines = String(oldText || '').split('\n');
    const bLines = String(newText || '').split('\n');
    const maxA = Math.min(aLines.length, 300);
    const maxB = Math.min(bLines.length, 300);
    const dp = Array.from({ length: maxA + 1 }, () => new Uint16Array(maxB + 1));

    for (let i = maxA - 1; i >= 0; i--) {
      for (let j = maxB - 1; j >= 0; j--) {
        if (aLines[i] === bLines[j]) {
          dp[i][j] = 1 + dp[i + 1][j + 1];
        } else {
          dp[i][j] = dp[i + 1][j] >= dp[i][j + 1] ? dp[i + 1][j] : dp[i][j + 1];
        }
      }
    }

    const hunks = [`--- ${labelA}`, `+++ ${labelB}`];
    let i = 0, j = 0;
    let addedLines = 0, removedLines = 0;
    while (i < maxA && j < maxB) {
      if (aLines[i] === bLines[j]) {
        hunks.push(`  ${aLines[i]}`);
        i++;
        j++;
      } else if (dp[i + 1][j] >= dp[i][j + 1]) {
        hunks.push(`- ${aLines[i]}`);
        removedLines++;
        i++;
      } else {
        hunks.push(`+ ${bLines[j]}`);
        addedLines++;
        j++;
      }
    }
    while (i < maxA) {
      hunks.push(`- ${aLines[i++]}`);
      removedLines++;
    }
    while (j < maxB) {
      hunks.push(`+ ${bLines[j++]}`);
      addedLines++;
    }

    return {
      unifiedText: hunks.join('\n'),
      addedLines,
      removedLines
    };
  }

  function synthesizeBaselineBundle(currentBundle) {
    const mf = currentBundle.manifestInfo || {};
    const curPerms = Array.isArray(mf.permissions) ? mf.permissions.slice() : [];
    const basePerms = curPerms.length > 1 ? curPerms.slice(0, curPerms.length - 1) : curPerms;
    const baseManifest = Object.assign({}, mf, {
      versionName: mf.versionName && mf.versionName !== 'Unknown' ? `${mf.versionName}-prev` : '2.4.0',
      versionCode: Math.max(1, (parseInt(mf.versionCode, 10) || 241) - 1),
      permissions: basePerms
    });

    const baseClasses = [];
    for (const dex of (currentBundle.dexFiles || [])) {
      for (let i = 0; i < dex.classes.length; i++) {
        const cls = dex.classes[i];
        const dec = global.ArgonDex ? global.ArgonDex.decompileClassToJava(cls, currentBundle.arsc) : { java: '' };
        let javaSource = dec.java || '';
        if (i === 0) {
          javaSource = javaSource
            .replace(/isAdmin\s*=\s*false/g, 'isAdmin = true /* baseline v2.4.0 */')
            + '\n// [Baseline v2.4.0] Legacy telemetry helper removed in newer release\npublic void legacyHandshakeCheck() {}';
        }
        baseClasses.push({
          fullName: cls.fullName,
          methodCount: cls.allMethods ? cls.allMethods.length : 0,
          javaSource
        });
      }
    }

    const baseElfs = (currentBundle.elfFiles || []).map(e => ({
      fileName: e.fileName,
      exportedSymbols: (e.exportedSymbols || []).slice(0, Math.max(0, (e.exportedSymbols || []).length - 1))
    }));

    return {
      fileName: (currentBundle.apk?.fileName || 'Target.apk').replace(/(\.apk)?$/i, '_v2.4.0_baseline.apk'),
      manifestInfo: baseManifest,
      classes: baseClasses,
      elfFiles: baseElfs
    };
  }

  function extractBundleClassMap(bundle) {
    const map = new Map();
    if (Array.isArray(bundle.classes)) {
      for (const c of bundle.classes) {
        map.set(c.fullName, {
          fullName: c.fullName,
          methodCount: c.methodCount || 0,
          javaSource: c.javaSource || ''
        });
      }
      return map;
    }
    for (const dex of (bundle.dexFiles || [])) {
      for (const cls of dex.classes) {
        const dec = global.ArgonDex ? global.ArgonDex.decompileClassToJava(cls, bundle.arsc) : { java: '' };
        map.set(cls.fullName, {
          fullName: cls.fullName,
          methodCount: cls.allMethods ? cls.allMethods.length : 0,
          javaSource: dec.java || ''
        });
      }
    }
    return map;
  }

  function computeApkDiff(baseBundle, targetBundle) {
    const baseMf = baseBundle.manifestInfo || {};
    const tgtMf = targetBundle.manifestInfo || {};
    const normPerm = (p) => typeof p === 'string' ? p : (p && p.name ? p.name : '');
    const basePerms = new Set((baseMf.permissions || []).map(normPerm).filter(Boolean));
    const tgtPerms = new Set((tgtMf.permissions || []).map(normPerm).filter(Boolean));

    const addedPermissions = [...tgtPerms].filter(p => !basePerms.has(p));
    const removedPermissions = [...basePerms].filter(p => !tgtPerms.has(p));

    const baseClasses = extractBundleClassMap(baseBundle);
    const tgtClasses = extractBundleClassMap(targetBundle);

    const addedClasses = [];
    const removedClasses = [];
    const modifiedClasses = [];
    let unchangedCount = 0;

    for (const [name, tgtInfo] of tgtClasses.entries()) {
      if (!baseClasses.has(name)) {
        addedClasses.push({ fullName: name, methodCount: tgtInfo.methodCount });
      } else {
        const baseInfo = baseClasses.get(name);
        if (baseInfo.javaSource !== tgtInfo.javaSource) {
          const diff = buildLineUnifiedDiff(
            baseInfo.javaSource,
            tgtInfo.javaSource,
            `baseline/${name}.java`,
            `target/${name}.java`
          );
          modifiedClasses.push({
            fullName: name,
            baseMethodCount: baseInfo.methodCount,
            targetMethodCount: tgtInfo.methodCount,
            addedLines: diff.addedLines,
            removedLines: diff.removedLines,
            unifiedDiff: diff.unifiedText
          });
        } else {
          unchangedCount++;
        }
      }
    }

    for (const [name, baseInfo] of baseClasses.entries()) {
      if (!tgtClasses.has(name)) {
        removedClasses.push({ fullName: name, methodCount: baseInfo.methodCount });
      }
    }

    const baseSyms = new Set();
    for (const e of (baseBundle.elfFiles || [])) {
      for (const s of (e.exportedSymbols || [])) baseSyms.add(`${e.fileName}:${s.name}`);
    }
    const tgtSyms = new Set();
    for (const e of (targetBundle.elfFiles || [])) {
      for (const s of (e.exportedSymbols || [])) tgtSyms.add(`${e.fileName}:${s.name}`);
    }

    return {
      baselineName: baseBundle.fileName || 'baseline.apk',
      targetName: targetBundle.fileName || targetBundle.apk?.fileName || 'target.apk',
      versionChange: {
        from: `${baseMf.versionName || '?'} (${baseMf.versionCode || '?'})`,
        to: `${tgtMf.versionName || '?'} (${tgtMf.versionCode || '?'})`
      },
      permissions: {
        added: addedPermissions,
        removed: removedPermissions
      },
      classes: {
        added: addedClasses,
        removed: removedClasses,
        modified: modifiedClasses,
        unchangedCount
      },
      nativeSymbols: {
        added: [...tgtSyms].filter(s => !baseSyms.has(s)),
        removed: [...baseSyms].filter(s => !tgtSyms.has(s))
      }
    };
  }

  // ==================== 8. MITRE ATT&CK MOBILE MATRIX, SARIF v2.1.0 & CYCLONEDX v1.5 ====================
  function mapMitreAttackMobile(manifestInfo, dexFiles, elfFiles, taintFlows, deobfData) {
    const techniques = [];
    const seenIds = new Set();
    const mf = manifestInfo || {};

    const addTech = (id, tactic, name, severity, evidence, targetClass = null) => {
      if (seenIds.has(id)) return;
      seenIds.add(id);
      techniques.push({ id, tactic, name, severity, evidence, targetClass });
    };

    const allStrings = [];
    const allClassNames = [];
    for (const dex of (dexFiles || [])) {
      for (const s of dex.strings) allStrings.push(s);
      for (const cls of dex.classes) {
        allClassNames.push({ cls, methods: cls.allMethods || [] });
      }
    }

    const joined = allStrings.join('\n');

    if (joined.includes('http://') || joined.includes('HttpURLConnection') || joined.includes('Socket')) {
      addTech('T1437.001', 'Command and Control', 'Application Layer Protocol: Web Protocols', 'HIGH',
        'Cleartext HTTP / raw network endpoints present in DEX string pool.');
    }

    if ((taintFlows || []).some(f => f.vulnerability.includes('SQL') || f.vulnerability.includes('Command'))) {
      const f = taintFlows.find(x => x.vulnerability.includes('SQL') || x.vulnerability.includes('Command'));
      addTech('T1407', 'Execution', 'Download / Execute Untrusted Input at Runtime', 'CRITICAL',
        `${f.vulnerability} (${f.source} -> ${f.sink})`, f.className);
    }

    if (joined.includes('MODE_WORLD_READABLE') || joined.includes('SharedPreferences') || joined.includes('SQLiteDatabase')) {
      addTech('T1409', 'Collection', 'Stored Application Data', 'MEDIUM',
        'Local SharedPreferences / SQLite persistent storage operations detected.');
    }

    if (joined.includes('getDeviceId') || joined.includes('TelephonyManager') || joined.includes('Settings$Secure')) {
      addTech('T1422', 'Discovery', 'System Network / Device Configuration Discovery', 'MEDIUM',
        'Device identifier or telephony reconnaissance APIs referenced.');
    }

    if ((deobfData && ((deobfData.decryptedStrings || []).length > 0 || deobfData.obfuscationRatio > 25)) ||
        (elfFiles || []).some(e => (e.importedSymbols || []).some(s => s.name.includes('ptrace')))) {
      addTech('T1406', 'Defense Evasion', 'Obfuscated Files or Information', 'HIGH',
        `Recovered ${(deobfData?.decryptedStrings || []).length} encrypted strings and/or native anti-debug hooks.`);
    }

    if ((elfFiles || []).length > 0 || joined.includes('System.loadLibrary')) {
      addTech('T1575', 'Execution', 'Native Code Execution via JNI', 'INFO',
        `${(elfFiles || []).length} native ELF shared libraries loaded via JNI.`);
    }

    const dangerousPerms = (mf.permissions || [])
      .map(p => (typeof p === 'string' ? p : (p && p.name ? p.name : '')))
      .filter(p => /READ_SMS|RECEIVE_SMS|ACCESS_FINE_LOCATION|READ_CONTACTS|RECORD_AUDIO|CAMERA|READ_CALL_LOG|INTERNET|WRITE_EXTERNAL_STORAGE/.test(p));
    if (dangerousPerms.length > 0) {
      addTech('T1636', 'Collection', 'Protected User Data Access', 'HIGH',
        `Manifest declares sensitive permissions: ${dangerousPerms.join(', ')}`);
    }

    if (mf.debuggable) {
      addTech('T1623', 'Discovery', 'Command and Scripting / Debuggable Flag Enabled', 'HIGH',
        'android:debuggable="true" exposes JDWP & runtime inspection.');
    }

    const tacticCoverage = {};
    for (const t of techniques) {
      tacticCoverage[t.tactic] = (tacticCoverage[t.tactic] || 0) + 1;
    }

    return { techniques, tacticCoverage };
  }

  function generateCycloneDxSbom(apk, manifestInfo, dexFiles, elfFiles, cryptoConstants) {
    const mf = manifestInfo || {};
    const components = [];
    const seenPkg = new Set();

    components.push({
      type: 'application',
      name: mf.packageName || apk.fileName,
      version: `${mf.versionName || '1.0.0'} (${mf.versionCode || '1'})`,
      'bom-ref': `app:${mf.packageName || apk.fileName}`,
      hashes: [{ alg: 'SHA-256', content: apk.sha256 || '' }],
      properties: [
        { name: 'android:minSdkVersion', value: String(mf.minSdkVersion || 'unknown') },
        { name: 'android:targetSdkVersion', value: String(mf.targetSdkVersion || 'unknown') }
      ]
    });

    for (const dex of (dexFiles || [])) {
      for (const cls of dex.classes) {
        const parts = (cls.packageName || '').split('.').filter(Boolean);
        const prefix = parts.slice(0, Math.min(3, parts.length)).join('.');
        if (!prefix || seenPkg.has(prefix)) continue;
        seenPkg.add(prefix);
        components.push({
          type: 'library',
          name: prefix,
          version: 'dex-embedded',
          'bom-ref': `pkg:${prefix}`,
          purl: `pkg:android/${encodeURIComponent(prefix)}`
        });
      }
    }

    const dependencies = [];
    for (const elf of (elfFiles || [])) {
      const ref = `native:${elf.fileName}`;
      components.push({
        type: 'library',
        name: elf.fileName,
        version: elf.architecture || 'native',
        'bom-ref': ref,
        properties: [
          { name: 'elf:soname', value: elf.soName || elf.fileName },
          { name: 'elf:pie', value: String(!!elf.hardening?.pie) },
          { name: 'elf:nx', value: String(!!elf.hardening?.nx) }
        ]
      });
      dependencies.push({
        ref,
        dependsOn: (elf.neededLibraries || []).map(lib => `sys:${lib}`)
      });
    }

    for (const c of (cryptoConstants || [])) {
      components.push({
        type: 'cryptographic-asset',
        name: c.algorithm,
        description: c.description,
        'bom-ref': `crypto:${c.algorithm}:${c.archiveOffset}`
      });
    }

    return {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber: `urn:uuid:argondex-${(apk.sha256 || '000000000000').slice(0, 12)}`,
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        tools: [{ vendor: 'ArgonDEX Studio', name: 'ArgonDEX Analyzer', version: '3.5.0' }],
        component: components[0]
      },
      components,
      dependencies
    };
  }

  function generateSarifReport(apk, securityAudit, taintFlows) {
    const audit = securityAudit || { findings: [] };
    const rulesMap = new Map();
    const results = [];

    const toLevel = (sev) => {
      if (sev === 'CRITICAL' || sev === 'HIGH') return 'error';
      if (sev === 'MEDIUM') return 'warning';
      return 'note';
    };

    for (const f of audit.findings) {
      const ruleId = (f.cwe || f.category || 'ARGON-SEC').replace(/[^A-Za-z0-9._-]/g, '_');
      if (!rulesMap.has(ruleId)) {
        rulesMap.set(ruleId, {
          id: ruleId,
          name: f.category || ruleId,
          shortDescription: { text: f.title },
          fullDescription: { text: f.description },
          help: { text: f.remediation || '' },
          properties: { cwe: f.cwe || '', severity: f.severity }
        });
      }
      const uri = f.location?.className
        ? `src/main/java/${f.location.className.replace(/\./g, '/')}.java`
        : (f.location?.file || 'AndroidManifest.xml');
      results.push({
        ruleId,
        level: toLevel(f.severity),
        message: { text: `${f.title}: ${f.description}` },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri },
            region: { startLine: 1 }
          }
        }],
        properties: { severity: f.severity, cwe: f.cwe || '' }
      });
    }

    for (const flow of (taintFlows || [])) {
      const ruleId = `TAINT_${(flow.vulnerability || 'FLOW').replace(/[^A-Za-z0-9._-]/g, '_')}`;
      if (!rulesMap.has(ruleId)) {
        rulesMap.set(ruleId, {
          id: ruleId,
          name: flow.vulnerability,
          shortDescription: { text: flow.vulnerability },
          fullDescription: { text: `Taint flow from ${flow.source} to ${flow.sink}` },
          properties: { severity: flow.severity }
        });
      }
      results.push({
        ruleId,
        level: toLevel(flow.severity),
        message: { text: `${flow.vulnerability} in ${flow.className}.${flow.methodName}(): ${flow.source} -> ${flow.sink}` },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: `src/main/java/${flow.className.replace(/\./g, '/')}.java` },
            region: { startLine: 1 }
          }
        }]
      });
    }

    return {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [{
        tool: {
          driver: {
            name: 'ArgonDEX Studio',
            version: '3.5.0',
            informationUri: 'https://github.com/iwa-kasoutuuuuuka/ArgonDEX-Studio',
            rules: [...rulesMap.values()]
          }
        },
        originalUriBaseIds: {
          SRCROOT: { uri: `apk://${apk?.fileName || 'app.apk'}/` }
        },
        results
      }]
    };
  }

  // ==================== 9. DYNAMIC JNI REGISTERNATIVES SCANNER & MULTI-ABI DISASSEMBLER ====================
  function extractPrintableAsciiEntries(bytes) {
    const entries = [];
    let start = -1;
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i];
      const ok = b >= 0x20 && b <= 0x7e;
      if (ok && start === -1) {
        start = i;
      } else if (!ok && start !== -1) {
        if (i - start >= 3) {
          let str = '';
          for (let k = start; k < i; k++) str += String.fromCharCode(bytes[k]);
          entries.push({ offset: start, text: str });
        }
        start = -1;
      }
    }
    return entries;
  }

  function scanDynamicRegisterNatives(soBytes, elfMeta, dexFiles) {
    const exported = (elfMeta?.exportedSymbols || []).map(s => s.name);
    const imported = (elfMeta?.importedSymbols || []).map(s => s.name);
    const ascii = extractPrintableAsciiEntries(soBytes);

    const hasJniOnLoad = exported.includes('JNI_OnLoad') ||
      ascii.some(a => a.text.includes('JNI_OnLoad'));
    const usesRegisterNatives = imported.some(s => s.includes('RegisterNatives')) ||
      ascii.some(a => a.text.includes('RegisterNatives'));

    const nativeMethodMap = new Map();
    for (const dex of (dexFiles || [])) {
      for (const cls of dex.classes) {
        for (const m of (cls.allMethods || [])) {
          if ((m.accessFlags & 0x0100) !== 0) {
            if (!nativeMethodMap.has(m.name)) nativeMethodMap.set(m.name, []);
            nativeMethodMap.get(m.name).push({ className: cls.fullName, methodName: m.name });
          }
        }
      }
    }

    const sigRegex = /^\([\[ZBCSIJFDLV/;a-zA-Z0-9_$]*\)(V|Z|B|C|S|I|J|F|D|\[*L[^;]+;|\[+[ZBCSIJFD])$/;
    const bindings = [];
    const seen = new Set();

    for (let i = 0; i < ascii.length; i++) {
      const entry = ascii[i];
      if (!sigRegex.test(entry.text)) continue;

      let candidateName = null;
      let jniTargetClass = null;
      for (let look = Math.max(0, i - 3); look <= Math.min(ascii.length - 1, i + 3); look++) {
        if (look === i) continue;
        const txt = ascii[look].text;
        if (txt.includes('/') && !txt.startsWith('(')) {
          jniTargetClass = txt.replace(/\//g, '.');
        } else if (/^[A-Za-z_][A-Za-z0-9_]{2,64}$/.test(txt) && txt !== 'JNI_OnLoad' && txt !== 'RegisterNatives') {
          candidateName = txt;
        }
      }

      if (candidateName && nativeMethodMap.has(candidateName)) {
        const matches = nativeMethodMap.get(candidateName);
        for (const match of matches) {
          const key = `${match.className}#${match.methodName}:${entry.text}`;
          if (seen.has(key)) continue;
          seen.add(key);
          bindings.push({
            library: elfMeta?.fileName || 'native.so',
            className: jniTargetClass || match.className,
            methodName: match.methodName,
            signature: entry.text,
            stringOffset: '0x' + entry.offset.toString(16),
            mechanism: 'Dynamic RegisterNatives'
          });
        }
      } else if (candidateName) {
        const key = `${jniTargetClass || elfMeta?.soName || 'native'}#${candidateName}:${entry.text}`;
        if (!seen.has(key)) {
          seen.add(key);
          bindings.push({
            library: elfMeta?.fileName || 'native.so',
            className: jniTargetClass || '(Dynamic Native Binding)',
            methodName: candidateName,
            signature: entry.text,
            stringOffset: '0x' + entry.offset.toString(16),
            mechanism: 'JNINativeMethod Table String'
          });
        }
      }
    }

    return {
      hasJniOnLoad,
      usesRegisterNatives: usesRegisterNatives || bindings.length > 0,
      bindings
    };
  }

  function disassembleArm32Text(bytes, textSec, symByAddr) {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const baseOff = textSec.offset;
    const baseAddr = textSec.addr || 0x1000;
    const maxIns = Math.min(Math.floor(textSec.size / 4), 120);
    const out = [];

    for (let i = 0; i < maxIns; i++) {
      const fileOff = baseOff + i * 4;
      if (fileOff + 4 > bytes.length) break;
      const vaddr = baseAddr + i * 4;
      const insn = dv.getUint32(fileOff, true);
      const hexBytes = [
        bytes[fileOff].toString(16).padStart(2, '0'),
        bytes[fileOff + 1].toString(16).padStart(2, '0'),
        bytes[fileOff + 2].toString(16).padStart(2, '0'),
        bytes[fileOff + 3].toString(16).padStart(2, '0')
      ].join(' ');

      let mnemonic = '.word';
      let operands = `0x${insn.toString(16).padStart(8, '0')}`;
      let comment = 'ARMv7 (A32)';

      if (insn === 0xe12fff1e) {
        mnemonic = 'bx'; operands = 'lr'; comment = 'Return from function';
      } else if (insn === 0xe1a00000) {
        mnemonic = 'nop'; operands = ''; comment = 'mov r0, r0';
      } else if ((insn & 0x0e000000) === 0x0a000000) {
        const isLink = (insn & 0x01000000) !== 0;
        let imm24 = insn & 0x00ffffff;
        if (imm24 & 0x00800000) imm24 |= 0xff000000;
        const target = (vaddr + 8 + (imm24 << 2)) >>> 0;
        mnemonic = isLink ? 'bl' : 'b';
        operands = `0x${target.toString(16)}`;
        const sym = symByAddr.get(target);
        if (sym) comment = `; Call -> ${sym}`;
      } else if ((insn & 0x0fff0000) === 0x092d0000) {
        mnemonic = 'push';
        operands = `{regs:0x${(insn & 0xffff).toString(16)}}`;
        comment = '; Prologue save';
      } else if ((insn & 0x0fff0000) === 0x08bd0000) {
        mnemonic = 'pop';
        operands = `{regs:0x${(insn & 0xffff).toString(16)}}`;
        comment = '; Epilogue restore';
      } else if ((insn & 0x0de00000) === 0x02800000) {
        const rd = (insn >> 12) & 0xf;
        const rn = (insn >> 16) & 0xf;
        const imm = insn & 0xff;
        mnemonic = 'add'; operands = `r${rd}, r${rn}, #0x${imm.toString(16)}`;
      } else if ((insn & 0x0de00000) === 0x03a00000) {
        const rd = (insn >> 12) & 0xf;
        const imm = insn & 0xff;
        mnemonic = 'mov'; operands = `r${rd}, #0x${imm.toString(16)}`;
      }

      const vaddrHex = '0x' + vaddr.toString(16).padStart(8, '0');
      out.push({
        vaddr: vaddrHex,
        hexBytes,
        mnemonic,
        operands,
        label: symByAddr.get(vaddr) || null,
        comment
      });
    }
    return out;
  }

  function disassembleX86_64Text(bytes, textSec, symByAddr) {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const baseAddr = textSec.addr || 0x1000;
    const endOff = Math.min(bytes.length, textSec.offset + textSec.size);
    let off = textSec.offset;
    const out = [];

    while (off < endOff && out.length < 140) {
      const vaddr = baseAddr + (off - textSec.offset);
      const b0 = bytes[off];
      let len = 1;
      let mnemonic = 'db';
      let operands = `0x${b0.toString(16).padStart(2, '0')}`;
      let comment = 'x86_64';

      if (b0 === 0x55) {
        mnemonic = 'push'; operands = 'rbp'; comment = '; Frame prologue';
      } else if (b0 === 0x5d) {
        mnemonic = 'pop'; operands = 'rbp';
      } else if (b0 === 0xc3) {
        mnemonic = 'ret'; operands = ''; comment = '; Function return';
      } else if (b0 === 0x90) {
        mnemonic = 'nop'; operands = '';
      } else if (b0 === 0xf3 && off + 3 < endOff && bytes[off + 1] === 0x0f && bytes[off + 2] === 0x1e && bytes[off + 3] === 0xfa) {
        len = 4; mnemonic = 'endbr64'; operands = ''; comment = '; CET IBT landing pad';
      } else if (b0 === 0x48 && off + 2 < endOff && bytes[off + 1] === 0x89 && bytes[off + 2] === 0xe5) {
        len = 3; mnemonic = 'mov'; operands = 'rbp, rsp';
      } else if (b0 === 0x48 && off + 2 < endOff && bytes[off + 1] === 0x83 && bytes[off + 2] === 0xec && off + 3 < endOff) {
        len = 4; mnemonic = 'sub'; operands = `rsp, 0x${bytes[off + 3].toString(16)}`;
      } else if ((b0 === 0xe8 || b0 === 0xe9) && off + 5 <= endOff) {
        len = 5;
        const rel = dv.getInt32(off + 1, true);
        const target = (vaddr + 5 + rel) >>> 0;
        mnemonic = b0 === 0xe8 ? 'call' : 'jmp';
        operands = `0x${target.toString(16)}`;
        const sym = symByAddr.get(target);
        if (sym) comment = `; -> ${sym}`;
      } else if (b0 >= 0xb8 && b0 <= 0xbf && off + 5 <= endOff) {
        len = 5;
        const regs = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi'];
        const imm = dv.getUint32(off + 1, true);
        mnemonic = 'mov'; operands = `${regs[b0 - 0xb8]}, 0x${imm.toString(16)}`;
      }

      const hexBytes = Array.from(bytes.subarray(off, off + len))
        .map(b => b.toString(16).padStart(2, '0')).join(' ');
      out.push({
        vaddr: '0x' + vaddr.toString(16).padStart(8, '0'),
        hexBytes,
        mnemonic,
        operands,
        label: symByAddr.get(vaddr) || null,
        comment
      });
      off += len;
    }
    return out;
  }

  function disassembleMultiArchElf(bytes, elfMeta, archOverride) {
    if (!elfMeta || !elfMeta.sections) return [];
    const textSec = elfMeta.sections.find(s => s.name === '.text');
    if (!textSec || textSec.size === 0 || textSec.offset >= bytes.length) return [];

    const symByAddr = new Map();
    for (const sym of (elfMeta.exportedSymbols || [])) {
      const addrNum = parseInt(sym.address, 16);
      if (!isNaN(addrNum) && addrNum > 0) symByAddr.set(addrNum, sym.name);
    }

    const rawArch = String(archOverride || elfMeta.architecture || 'ARM64').toUpperCase();
    if (rawArch.includes('X86') || rawArch.includes('AMD64')) {
      return disassembleX86_64Text(bytes, textSec, symByAddr);
    }
    if (rawArch.includes('ARM32') || (rawArch.includes('ARM') && !rawArch.includes('64') && !rawArch.includes('AARCH64'))) {
      return disassembleArm32Text(bytes, textSec, symByAddr);
    }
    return disassembleElfTextSection(bytes, elfMeta);
  }

  global.ArgonAdvanced = {
    runTaintAnalysis,
    decryptObfuscatedStrings,
    analyzeObfuscationAndGenerateMappings,
    applySmartDeobfuscationToJava,
    computeCfgMetrics,
    disassembleElfTextSection,
    decompileArm64ToPseudoC,
    generateFridaHookScript,
    scanCryptographicConstants,
    computeApkDiff,
    synthesizeBaselineBundle,
    buildLineUnifiedDiff,
    mapMitreAttackMobile,
    generateCycloneDxSbom,
    generateSarifReport,
    scanDynamicRegisterNatives,
    disassembleMultiArchElf
  };
})(typeof window !== 'undefined' ? window : globalThis);
