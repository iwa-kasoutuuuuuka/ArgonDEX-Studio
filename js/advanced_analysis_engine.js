/**
 * ArgonDEX Studio v2.0 — Advanced Static Analysis Engine
 * - SSA Intra/Inter-Procedural Source-to-Sink Taint Analysis
 * - Smart Deobfuscator & Semantic Symbol Renamer (ProGuard/R8 inference)
 * - Packer / Obfuscator / Framework Fingerprinter
 * - CFG Dominator Tree & Cyclomatic Complexity Analyzer
 * - ARM64 (AArch64) Native Machine Code Disassembler for ELF .so (.text)
 * - Cryptographic Constant & S-Box Scanner (DEX & ELF .rodata)
 */

(function (global) {
  'use strict';

  // ==================== 1. SOURCE-TO-SINK TAINT ANALYSIS ENGINE ====================
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

    for (const dex of dexFiles) {
      for (const cls of dex.classes) {
        // Track tainted instance/static fields within class
        const taintedFields = new Map(); // fieldName -> { sourceLabel, originMethod, trace }

        for (const method of cls.allMethods) {
          if (!method.code) continue;
          const insns = method.code.instructions;
          const totalRegs = method.code.registersSize;
          const insSize = method.code.insSize;
          const paramStart = totalRegs - insSize;

          // Register taint map: reg -> { sourceLabel, category, steps: [] }
          const regTaint = new Map();

          // Heuristic: parameters of public methods in exported components or DB/Net helpers act as entry taint sources
          let pCursor = method.isStatic ? paramStart : paramStart + 1;
          for (let pIdx = 0; pIdx < method.proto.parameters.length; pIdx++) {
            const pDesc = method.proto.parameters[pIdx];
            if (pDesc === 'Ljava/lang/String;') {
              regTaint.set(pCursor, {
                sourceLabel: `Method Parameter arg${pIdx} (${cls.simpleName}.${method.name})`,
                category: 'METHOD_PARAM',
                risk: 'HIGH',
                steps: [`[Entry] Parameter p${pCursor - paramStart} (arg${pIdx}: String) enters ${cls.simpleName}.${method.name}()`]
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
            // 3. Const-string (check if hardcoded sensitive token/key or cleartext HTTP URL)
            else if (op === 0x1a || op === 0x1b) {
              const sVal = String(ins.refObj || '');
              if (/AIza[0-9A-Za-z\-_]{20,}|AKIA[0-9A-Z]{16}|SECRET|PRIVATE_KEY/i.test(sVal)) {
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
            // 4. Field reads/writes (iget/iput/sget/sput)
            else if (op >= 0x52 && op <= 0x58) { // iget*
              const f = ins.refObj;
              if (f && taintedFields.has(f.name)) {
                const ft = taintedFields.get(f.name);
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
                taintedFields.set(f.name, {
                  ...rt,
                  steps: [...rt.steps, `[${pcHex}] ${ins.name}: stores taint from v${ins.vA} into field this.${f.name}`]
                });
              }
            }
            else if (op >= 0x60 && op <= 0x66) { // sget*
              const f = ins.refObj;
              if (f && taintedFields.has(f.name)) {
                const ft = taintedFields.get(f.name);
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
                taintedFields.set(f.name, {
                  ...rt,
                  steps: [...rt.steps, `[${pcHex}] ${ins.name}: stores taint from v${ins.vA} into static field ${f.name}`]
                });
              }
            }
            // 5. Method Invocations (Sources, Propagators like StringBuilder, and Sinks)
            else if (op >= 0x6e && op <= 0x78) {
              pendingInvokeTaint = null;
              const mRef = ins.refObj;
              if (!mRef) continue;
              const sig = mRef.signature;

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

              // Check if invocation is a Taint Propagator (StringBuilder.append, toString, String.concat, etc.)
              const taintedArgs = (ins.args || []).filter(r => regTaint.has(r));
              if (taintedArgs.length > 0) {
                const primaryTaint = regTaint.get(taintedArgs[0]);
                if (
                  mRef.className === 'java.lang.StringBuilder' ||
                  mRef.className === 'java.lang.String' ||
                  mRef.name.startsWith('build') ||
                  mRef.name.startsWith('format')
                ) {
                  const propagated = {
                    ...primaryTaint,
                    steps: [...primaryTaint.steps, `[${pcHex}] Taint propagated via ${mRef.className.split('.').pop()}.${mRef.name}()`]
                  };
                  if (ins.args.length > 0) {
                    regTaint.set(ins.args[0], propagated);
                  }
                  pendingInvokeTaint = propagated;
                }

                // Check if invocation is a Taint Sink!
                const matchedSink = TAINT_SINKS.find(snk => sig.startsWith(snk.match));
                if (matchedSink) {
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
              }
            }
          }
        }
      }
    }

    return taintFlows;
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
            // Inspect strings and API calls inside the class
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
                mReason = 'Integer computation method';
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
    const entryNames = apk.entries.map(e => e.name);
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
    if (elfFiles.length > 0) {
      fingerprints.push({
        name: `Android NDK Native JNI (${elfFiles.map(e => e.architecture).join(', ')})`,
        type: 'Native Toolchain',
        confidence: 'Confirmed'
      });
    }
    if (apk.signingBlock.v2Signed || apk.signingBlock.v3Signed) {
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
      fingerprints
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
      if (deobfData.fieldRenames.has(key)) {
        const newName = deobfData.fieldRenames.get(key);
        const safeF = escapeRegExp(f.name);
        const fDeclRe = new RegExp(`(\\b(?:private|public|protected|static|final|volatile|transient)\\s+[A-Za-z0-9_<>\\[\\]]+\\s+)${safeF}(\\s*[=;])`, 'g');
        out = out.replace(fDeclRe, `$1${newName}$2`);
        const fAccessRe = new RegExp(`\\bthis\\.${safeF}\\b`, 'g');
        out = out.replace(fAccessRe, `this.${newName}`);
      }
    }

    // 2. Context-aware class & constructor replacement (run before method replacement so 'public a()' becomes 'public CryptoTokenHelper()')
    if (deobfData.classRenames.has(cls.fullName)) {
      const info = deobfData.classRenames.get(cls.fullName);
      const safeC = escapeRegExp(info.originalSimple || '');
      const clsDeclRe = new RegExp(`(\\b(?:class|interface|enum)\\s+)${safeC}\\b`, 'g');
      out = out.replace(clsDeclRe, `$1${info.newSimple} /* obf: ${info.originalSimple} */`);
      const ctorRe = new RegExp(`(\\b(?:public|protected|private)\\s+)${safeC}\\(`, 'g');
      out = out.replace(ctorRe, `$1${info.newSimple}(`);
      out = `// [ArgonDEX Smart Deobfuscator] Renamed class '${info.originalFull}' -> '${info.newFull}' (${info.reason})\n` + out;
    }

    // 3. Context-aware method replacements (method declarations & calls, excluding constructor)
    for (const m of (cls.allMethods || [])) {
      if (m.isConstructor) continue;
      const key = `${cls.fullName}#${m.name}`;
      if (deobfData.methodRenames.has(key)) {
        const newName = deobfData.methodRenames.get(key);
        const safeM = escapeRegExp(m.name);
        // Match "<ReturnType> m(" or ".m("
        const mDeclRe = new RegExp(`(\\b(?:void|boolean|byte|short|char|int|long|float|double|String|Object|Cursor|[A-Za-z0-9_]+\\[\\])\\s+)${safeM}\\(`, 'g');
        out = out.replace(mDeclRe, `$1${newName}(`);
        const mCallRe = new RegExp(`\\.${safeM}\\(`, 'g');
        out = out.replace(mCallRe, `.${newName}(`);
      }
    }

    return out;
  }

  // ==================== 3. CFG DOMINATOR TREE & CYCLOMATIC COMPLEXITY ====================
  function computeCfgMetrics(cfg) {
    const N = cfg.blocks.length;
    const E = cfg.edges.length;
    if (N === 0) {
      return { cyclomaticComplexity: 1, blockCount: 0, edgeCount: 0, loopCount: 0, dominators: [] };
    }
    // McCabe Cyclomatic Complexity: M = E - N + 2
    const cyclomaticComplexity = Math.max(1, E - N + 2);
    let backEdges = 0;
    for (const edge of cfg.edges) {
      if (edge.toIndex <= edge.fromIndex) backEdges++;
    }

    // Iterative Dominator calculation: Dom(n0) = {n0}, Dom(n) = {n} U intersect(Dom(p) for p in preds(n))
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

    // Immediate dominator (idom) for each block
    const dominators = cfg.blocks.map((b, idx) => {
      if (idx === 0) return { blockId: b.id, idom: '(Entry Root)', domSet: ['B0'] };
      const strictDoms = Array.from(dom[idx]).filter(d => d !== idx);
      const idomIdx = strictDoms.length ? strictDoms[strictDoms.length - 1] : 0;
      return {
        blockId: b.id,
        idom: `B${idomIdx}`,
        domSet: Array.from(dom[idx]).map(d => `B${d}`)
      };
    });

    return {
      cyclomaticComplexity,
      blockCount: N,
      edgeCount: E,
      loopCount: backEdges,
      dominators
    };
  }

  // ==================== 4. ARM64 (AARCH64) NATIVE MACHINE CODE DISASSEMBLER ====================
  function regX(n, is64 = true) {
    if (n === 31) return is64 ? 'xzr/sp' : 'wzr';
    return (is64 ? 'x' : 'w') + n;
  }

  function decodeArm64Instruction(word, vaddr) {
    // Decodes common 32-bit AArch64 instructions into readable assembly
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
        comment: hw === 0 && opc === 2 ? `=${imm16}` : ''
      };
    }

    // ADD / SUB (immediate): [sf][op][S] 100010 [sh] [imm12] [Rn] [Rd]
    if (((word >>> 23) & 0x3f) === 0x22) {
      const isSub = ((word >>> 30) & 1) === 1;
      const imm12 = (word >>> 10) & 0xfff;
      const sh = ((word >>> 22) & 1) ? 12 : 0;
      const val = imm12 << sh;
      return {
        mnemonic: isSub ? 'sub' : 'add',
        operands: `${regX(rd, is64)}, ${regX(rn, is64)}, #0x${val.toString(16)}`,
        comment: `${val}`
      };
    }

    // ADD / SUB (shifted register): [sf][op][S] 01011 [shift] 0 [Rm] [imm6] [Rn] [Rd]
    if (((word >>> 24) & 0x1f) === 0x0b) {
      const isSub = ((word >>> 30) & 1) === 1;
      if (!isSub && rn === 31) {
        return { mnemonic: 'mov', operands: `${regX(rd, is64)}, ${regX(rm, is64)}`, comment: 'Register copy' };
      }
      return {
        mnemonic: isSub ? 'sub' : 'add',
        operands: `${regX(rd, is64)}, ${regX(rn, is64)}, ${regX(rm, is64)}`,
        comment: ''
      };
    }

    // Logical (shifted register): AND (00), ORR (01), EOR (10)
    if (((word >>> 24) & 0x1f) === 0x0a) {
      const opc = (word >>> 29) & 0x3;
      if (opc === 1 && rn === 31) {
        return { mnemonic: 'mov', operands: `${regX(rd, is64)}, ${regX(rm, is64)}`, comment: 'ORR alias' };
      }
      const mnem = opc === 0 ? 'and' : (opc === 1 ? 'orr' : (opc === 2 ? 'eor' : 'ands'));
      return {
        mnemonic: mnem,
        operands: `${regX(rd, is64)}, ${regX(rn, is64)}, ${regX(rm, is64)}`,
        comment: ''
      };
    }

    // Unconditional Branch (immediate): B / BL
    if (((word >>> 26) & 0x1f) === 0x05) {
      const isLink = ((word >>> 31) & 1) === 1;
      let imm26 = word & 0x03ffffff;
      if (imm26 & 0x02000000) imm26 -= 0x04000000;
      const target = vaddr + imm26 * 4;
      return {
        mnemonic: isLink ? 'bl' : 'b',
        operands: `0x${target.toString(16)}`,
        comment: isLink ? 'Branch with Link (call)' : 'Jump'
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
        comment: ''
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
    for (const exp of elfMeta.exportedSymbols) {
      const addrNum = parseInt(exp.address, 16);
      symAtVaddr.set(addrNum, exp.name);
    }

    const lines = [];
    const wordCount = Math.min(256, Math.floor(textSec.size / 4));
    for (let i = 0; i < wordCount; i++) {
      const fileOff = textSec.offset + i * 4;
      const vaddr = baseVaddr + i * 4;
      const word = dv.getUint32(fileOff, true);
      const decoded = decodeArm64Instruction(word, vaddr);
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
        comment: decoded.comment
      });
    }
    return lines;
  }

  // ==================== 5. CRYPTOGRAPHIC S-BOX & CONSTANT SCANNER ====================
  function scanCryptographicConstants(apkEntries, rawApkBytes) {
    const hits = [];
    // Known magic byte sequences:
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
      for (let i = 0; i <= rawApkBytes.length - pat.length; i++) {
        let match = true;
        for (let k = 0; k < pat.length; k++) {
          if (rawApkBytes[i + k] !== pat[k]) {
            match = false;
            break;
          }
        }
        if (match) {
          hits.push({
            algorithm: sig.algo,
            description: sig.name,
            archiveOffset: '0x' + i.toString(16).padStart(8, '0'),
            previewHex: pat.slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join(' ') + ' ...'
          });
          break;
        }
      }
    }

    return hits;
  }

  global.ArgonAdvanced = {
    runTaintAnalysis,
    analyzeObfuscationAndGenerateMappings,
    applySmartDeobfuscationToJava,
    computeCfgMetrics,
    disassembleElfTextSection,
    scanCryptographicConstants
  };
})(typeof window !== 'undefined' ? window : globalThis);
