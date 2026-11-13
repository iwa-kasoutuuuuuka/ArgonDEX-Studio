/**
 * ArgonDEX Studio - Main IDE Controller, Syntax Highlighter, Interactive CFG/Call-Graph Renderer & Project Exporter
 */

(function (global) {
  'use strict';

  const State = {
    apk: null,
    manifestAxml: null,
    manifestInfo: null,
    arsc: null,
    dexFiles: [],
    allClasses: [],
    classByName: new Map(),
    elfFiles: [],
    jniByClassMethod: new Map(),
    securityAudit: null,
    mitreAttack: null,
    sbom: null,
    sarif: null,
    patchHistory: [],
    diffBaseline: null,
    diffResult: null,
    diffSelectedClassIdx: 0,
    elfArchOverride: 'AUTO',
    workerInfo: { mode: 'sync', durationMs: 0 },
    theme: 'dark',
    codeRenderLimit: 800,
    bgXrefToken: 0,
    allCrossRefs: [],

    // UI state
    sidebarTab: 'classes', // 'classes' | 'files' | 'strings'
    sidebarFilter: '',
    activeMode: 'code',    // 'overview' | 'code' | 'cfg' | 'taint' | 'manifest' | 'arsc' | 'elf' | 'security' | 'diff' | 'hex'
    codeSubMode: 'split',  // 'split' | 'java' | 'smali' | 'insns'
    cfgSubMode: 'method',  // 'method' | 'callgraph'
    selectedClass: null,
    selectedMethodIdx: 0,
    selectedXmlEntry: 'AndroidManifest.xml',
    selectedElfIdx: 0,
    selectedHexEntry: 'classes.dex',
    arscFilter: ''
  };

  // ==================== SYNTAX HIGHLIGHTERS ====================
  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  const JAVA_KEYWORDS = new Set([
    'package', 'import', 'public', 'private', 'protected', 'static', 'final', 'abstract',
    'synchronized', 'native', 'volatile', 'transient', 'class', 'interface', 'enum',
    'extends', 'implements', 'return', 'if', 'else', 'while', 'for', 'switch', 'case',
    'default', 'break', 'continue', 'new', 'try', 'catch', 'finally', 'throw', 'throws',
    'this', 'super', 'null', 'true', 'false', 'void', 'int', 'long', 'boolean', 'byte',
    'short', 'char', 'float', 'double', 'instanceof'
  ]);

  function highlightJavaLine(line) {
    const trimmed = line.trim();
    if (trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*')) {
      return `<span class="tok-com">${escapeHtml(line)}</span>`;
    }

    // Tokenize strings, comments, identifiers, numbers
    const tokenRegex = /("([^"\\]|\\.)*"|\/\*[\s\S]*?\*\/|\/\/.*$|\b0x[0-9a-fA-F]+\b|\b\d+\b|\b[A-Za-z_$][A-Za-z0-9_$]*\b)/g;
    let lastIndex = 0;
    let out = '';
    let match;

    while ((match = tokenRegex.exec(line)) !== null) {
      if (match.index > lastIndex) {
        out += escapeHtml(line.slice(lastIndex, match.index));
      }
      const tok = match[0];
      if (tok.startsWith('"')) {
        out += `<span class="tok-str">${escapeHtml(tok)}</span>`;
      } else if (tok.startsWith('//') || tok.startsWith('/*')) {
        out += `<span class="tok-com">${escapeHtml(tok)}</span>`;
      } else if (/^(0x[0-9a-fA-F]+|\d+)$/.test(tok)) {
        out += `<span class="tok-num">${tok}</span>`;
      } else if (JAVA_KEYWORDS.has(tok)) {
        out += `<span class="tok-kw">${tok}</span>`;
      } else if (State.classByName.has(tok) || Array.from(State.classByName.values()).some(c => c.simpleName === tok)) {
        out += `<span class="tok-xref" data-xref-class="${escapeHtml(tok)}" title="Jump to class ${escapeHtml(tok)}">${escapeHtml(tok)}</span>`;
      } else if (/^[A-Z][A-Za-z0-9_]*$/.test(tok)) {
        out += `<span class="tok-type">${escapeHtml(tok)}</span>`;
      } else {
        out += escapeHtml(tok);
      }
      lastIndex = tokenRegex.lastIndex;
    }
    if (lastIndex < line.length) {
      out += escapeHtml(line.slice(lastIndex));
    }
    return out;
  }

  function highlightSmaliLine(line) {
    const trimmed = line.trim();
    if (trimmed.startsWith('#')) {
      return `<span class="tok-com">${escapeHtml(line)}</span>`;
    }
    // Split comment at #
    const hashIdx = line.indexOf('#');
    const codePart = hashIdx !== -1 ? line.slice(0, hashIdx) : line;
    const comPart = hashIdx !== -1 ? `<span class="tok-com">${escapeHtml(line.slice(hashIdx))}</span>` : '';

    const tokenRegex = /("([^"\\]|\\.)*"|\.[a-zA-Z0-9_\-]+|:[a-zA-Z0-9_]+|\b[vp]\d+\b|-?0x[0-9a-fA-F]+|\bL[a-zA-Z0-9/$_]+;)/g;
    let lastIndex = 0;
    let out = '';
    let match;

    while ((match = tokenRegex.exec(codePart)) !== null) {
      if (match.index > lastIndex) {
        out += escapeHtml(codePart.slice(lastIndex, match.index));
      }
      const tok = match[0];
      if (tok.startsWith('"')) {
        out += `<span class="tok-str">${escapeHtml(tok)}</span>`;
      } else if (tok.startsWith('.')) {
        out += `<span class="tok-kw">${escapeHtml(tok)}</span>`;
      } else if (tok.startsWith(':')) {
        out += `<span class="tok-ann">${escapeHtml(tok)}</span>`;
      } else if (/^[vp]\d+$/.test(tok)) {
        out += `<span class="tok-reg">${tok}</span>`;
      } else if (tok.startsWith('0x') || tok.startsWith('-0x')) {
        out += `<span class="tok-num">${tok}</span>`;
      } else if (tok.startsWith('L') && tok.endsWith(';')) {
        const fullCls = global.ArgonDex.descriptorToFullClassName(tok);
        if (State.classByName.has(fullCls)) {
          out += `<span class="tok-xref" data-xref-class="${escapeHtml(fullCls)}">${escapeHtml(tok)}</span>`;
        } else {
          out += `<span class="tok-type">${escapeHtml(tok)}</span>`;
        }
      } else {
        out += escapeHtml(tok);
      }
      lastIndex = tokenRegex.lastIndex;
    }
    if (lastIndex < codePart.length) {
      out += escapeHtml(codePart.slice(lastIndex));
    }
    return out + comPart;
  }

  function highlightXmlLine(line) {
    return escapeHtml(line)
      .replace(/(&lt;\/?[a-zA-Z0-9:_\-.]+)/g, '<span class="tok-kw">$1</span>')
      .replace(/([a-zA-Z0-9:_\-]+)=(&quot;.*?&quot;)/g, '<span class="tok-type">$1</span>=<span class="tok-str">$2</span>')
      .replace(/(\/?&gt;)/g, '<span class="tok-kw">$1</span>');
  }

  function renderCodeLinesHtml(text, lang = 'java', maxLines = State.codeRenderLimit || 800) {
    const lines = String(text || '').split('\n');
    const renderCount = Math.min(lines.length, maxLines);
    const html = [];
    for (let i = 0; i < renderCount; i++) {
      const highlighted = lang === 'java'
        ? highlightJavaLine(lines[i])
        : (lang === 'smali' ? highlightSmaliLine(lines[i]) : highlightXmlLine(lines[i]));
      html.push(
        `<div class="code-line" data-line="${i + 1}">` +
          `<span class="line-num">${i + 1}</span>` +
          `<span class="line-content">${highlighted}</span>` +
        `</div>`
      );
    }
    if (lines.length > renderCount) {
      html.push(
        `<div class="code-chunk-banner" data-action="expand-code-lines">` +
          `⚡ Fast Chunk Mode: showing ${renderCount} / ${lines.length} lines — Click to load all lines` +
        `</div>`
      );
    }
    return html.join('');
  }

  function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  // ==================== CORE APK LOADING & ANALYSIS PIPELINE ====================
  async function loadAndAnalyzeInputFile(arrayBuffer, fileName) {
    setStatus(`Parsing binary image: ${fileName} (${formatBytes(arrayBuffer.byteLength)})...`);
    const bytes = new Uint8Array(arrayBuffer);

    // Check if user dropped a standalone .dex, .so, .xml, or .arsc file instead of a full .apk
    const isDex = bytes.length > 8 && new TextDecoder().decode(bytes.subarray(0, 4)) === 'dex\n';
    const isElf = bytes.length > 4 && bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46;
    const isAxml = bytes.length > 8 && bytes[0] === 0x03 && bytes[1] === 0x00 && bytes[2] === 0x08 && bytes[3] === 0x00;
    const isArsc = bytes.length > 8 && bytes[0] === 0x02 && bytes[1] === 0x00 && bytes[2] === 0x0c && bytes[3] === 0x00;

    if (isDex || isElf || isAxml || isArsc) {
      // Wrap standalone binary file into a synthetic archive container so all tools work seamlessly
      const entryName = isDex ? 'classes.dex' : (isElf ? `lib/arm64-v8a/${fileName}` : (isArsc ? 'resources.arsc' : 'AndroidManifest.xml'));
      const wrappedZip = global.ArgonZip.buildZipArchive([{ name: entryName, data: bytes }]);
      return loadAndAnalyzeApkBuffer(wrappedZip.buffer, fileName);
    }

    return loadAndAnalyzeApkBuffer(arrayBuffer, fileName);
  }

  function yieldToUi() {
    return new Promise(resolve => setTimeout(resolve, 0));
  }

  // Inline Blob Web Worker (CORS & file:// safe with graceful main-thread fallback)
  function createInlineAnalysisWorker() {
    if (typeof Worker === 'undefined' || typeof Blob === 'undefined' || typeof URL === 'undefined' || typeof URL.createObjectURL !== 'function') {
      return null;
    }
    const workerCode = `
      self.onmessage = function(ev) {
        const payload = ev.data || {};
        const bytes = payload.bytes instanceof Uint8Array ? payload.bytes : new Uint8Array(payload.bytes || []);
        const counts = new Uint32Array(256);
        for (let i = 0; i < bytes.length; i++) counts[bytes[i]]++;
        let entropy = 0;
        const len = bytes.length || 1;
        for (let b = 0; b < 256; b++) {
          if (counts[b] > 0) {
            const p = counts[b] / len;
            entropy -= p * Math.log2(p);
          }
        }
        const sigs = [
          { name: 'AES Rijndael Forward S-Box (256-byte lookup table)', algo: 'AES-128/192/256', pattern: [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76] },
          { name: 'SHA-256 / SHA-224 Initial Hash Vector H0 (0x6a09e667)', algo: 'SHA-256', pattern: [0x67, 0xe6, 0x09, 0x6a, 0x85, 0xae, 0x67, 0xbb] },
          { name: 'ChaCha20 / Salsa20 Sigma Constant ("expand 32-byte k")', algo: 'ChaCha20 Stream Cipher', pattern: [0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x33, 0x32, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6b] }
        ];
        const cryptoHits = [];
        for (const sig of sigs) {
          const pat = sig.pattern;
          const maxStart = bytes.length - pat.length;
          let pos = 0;
          while (pos <= maxStart) {
            pos = bytes.indexOf(pat[0], pos);
            if (pos === -1 || pos > maxStart) break;
            let ok = true;
            for (let k = 1; k < pat.length; k++) {
              if (bytes[pos + k] !== pat[k]) { ok = false; break; }
            }
            if (ok) {
              cryptoHits.push({
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
        self.postMessage({ ok: true, entropy: Math.round(entropy * 1000) / 1000, scannedBytes: bytes.length, cryptoHits });
      };
    `;
    try {
      const blob = new Blob([workerCode], { type: 'application/javascript' });
      const blobUrl = URL.createObjectURL(blob);
      const worker = new Worker(blobUrl);
      return {
        worker,
        dispose() {
          try { worker.terminate(); } catch (_) {}
          try { URL.revokeObjectURL(blobUrl); } catch (_) {}
        }
      };
    } catch (_) {
      return null;
    }
  }

  function runOffloadedWorkerTelemetry(rawBytes) {
    const tStart = typeof performance !== 'undefined' ? performance.now() : Date.now();
    const handle = createInlineAnalysisWorker();
    if (!handle) {
      const ent = global.ArgonZip && rawBytes ? global.ArgonZip.computeShannonEntropy(rawBytes) : 0;
      return Promise.resolve({
        mode: 'main-thread-fallback',
        entropy: ent,
        durationMs: Math.round((typeof performance !== 'undefined' ? performance.now() : Date.now()) - tStart)
      });
    }
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        handle.dispose();
        resolve({ mode: 'worker-timeout-fallback', entropy: 0, durationMs: 0 });
      }, 1500);
      handle.worker.onmessage = (ev) => {
        clearTimeout(timer);
        const data = ev.data || {};
        handle.dispose();
        resolve({
          mode: 'inline-blob-worker',
          entropy: data.entropy || 0,
          cryptoHits: Array.isArray(data.cryptoHits) ? data.cryptoHits : null,
          durationMs: Math.round((typeof performance !== 'undefined' ? performance.now() : Date.now()) - tStart)
        });
      };
      handle.worker.onerror = () => {
        clearTimeout(timer);
        handle.dispose();
        const ent = global.ArgonZip && rawBytes ? global.ArgonZip.computeShannonEntropy(rawBytes) : 0;
        resolve({ mode: 'worker-error-fallback', entropy: ent, durationMs: 0 });
      };
      try {
        const copy = new Uint8Array(rawBytes || []);
        handle.worker.postMessage({ bytes: copy }, [copy.buffer]);
      } catch (_) {
        clearTimeout(timer);
        handle.dispose();
        resolve({ mode: 'worker-transfer-fallback', entropy: 0, durationMs: 0 });
      }
    });
  }

  async function loadAndAnalyzeApkBuffer(arrayBuffer, fileName) {
    const t0 = performance.now();
    setStatus(`Parsing ZIP archive & APK Signing Block (${fileName})...`);
    await yieldToUi();
    const apk = await global.ArgonZip.parseApkArchive(arrayBuffer, fileName);

    // 1. Parse resources.arsc first so resource IDs (0x7f...) resolve everywhere
    let arsc = null;
    if (apk.entryMap.has('resources.arsc')) {
      try {
        const arscBytes = await apk.entryMap.get('resources.arsc').extract();
        arsc = global.ArgonAxml.parseResourcesArsc(arscBytes);
      } catch (e) {
        console.warn('ARSC parse warning:', e);
      }
    }

    // 2. Parse AndroidManifest.xml
    let manifestAxml = null;
    let manifestInfo = null;
    if (apk.entryMap.has('AndroidManifest.xml')) {
      try {
        const mfBytes = await apk.entryMap.get('AndroidManifest.xml').extract();
        manifestAxml = global.ArgonAxml.parseAxml(mfBytes, arsc);
        manifestInfo = global.ArgonAxml.analyzeManifest(manifestAxml);
      } catch (e) {
        console.warn('Manifest parse warning:', e);
      }
    }

    // 3. Parse all classes*.dex files with non-blocking chunk yields for large Multi-DEX APKs
    const dexFiles = [];
    const allClasses = [];
    const classByName = new Map();
    const allCrossRefs = [];

    const dexEntries = apk.entries
      .filter(e => /^classes\d*\.dex$/i.test(e.name) || e.name.endsWith('.dex'))
      .sort((a, b) => a.name.localeCompare(b.name));

    for (const dexEntry of dexEntries) {
      try {
        setStatus(`Decoding Dalvik bytecode (${dexEntry.name})...`);
        await yieldToUi();
        const dexBytes = await dexEntry.extract();
        const parsedDex = global.ArgonDex.parseDexFile(dexBytes, dexEntry.name, arsc);
        dexFiles.push(parsedDex);
        for (const cls of parsedDex.classes) {
          allClasses.push(cls);
          classByName.set(cls.fullName, cls);
          classByName.set(cls.simpleName, cls);
        }
      } catch (e) {
        console.warn(`DEX parse warning (${dexEntry.name}):`, e);
      }
    }

    // Defer cross-reference pre-decompilation to idle background batches so initial render is instant
    function scheduleBackgroundCrossRefBuild(classesList, resTable, targetList, token) {
      const limit = Math.min(classesList.length, 250);
      let idx = 0;
      const runBatch = () => {
        if (State.bgXrefToken !== token) return;
        const end = Math.min(limit, idx + 40);
        for (; idx < end; idx++) {
          const dec = global.ArgonDex.decompileClassToJava(classesList[idx], resTable);
          for (const xref of dec.crossRefs) {
            targetList.push(xref);
          }
        }
        if (idx < limit) {
          if (typeof requestIdleCallback === 'function') {
            requestIdleCallback(runBatch, { timeout: 150 });
          } else {
            setTimeout(runBatch, 0);
          }
        }
      };
      if (limit > 0) setTimeout(runBatch, 0);
    }

    // 4. Parse all native ELF (.so) libraries + Multi-ABI Disassembly + RegisterNatives + Pseudo-C
    const elfFiles = [];
    const jniByClassMethod = new Map();
    const soEntries = apk.entries.filter(e => e.name.endsWith('.so'));
    for (const soEntry of soEntries) {
      try {
        const soBytes = await soEntry.extract();
        const parsedElf = global.ArgonElfSecurity.parseElfBinary(soBytes, soEntry.name);
        parsedElf.rawBytes = new Uint8Array(soBytes);
        parsedElf.disassembly = global.ArgonAdvanced
          ? global.ArgonAdvanced.disassembleMultiArchElf(soBytes, parsedElf)
          : [];
        parsedElf.pseudoC = global.ArgonAdvanced
          ? global.ArgonAdvanced.decompileArm64ToPseudoC(soBytes, parsedElf)
          : '';
        parsedElf.registerNatives = global.ArgonAdvanced
          ? global.ArgonAdvanced.scanDynamicRegisterNatives(soBytes, parsedElf, dexFiles)
          : { hasJniOnLoad: false, usesRegisterNatives: false, bindings: [] };
        elfFiles.push(parsedElf);
        for (const jni of parsedElf.jniMethods) {
          if (jni.type === 'method') {
            jniByClassMethod.set(`${jni.className}#${jni.methodName}`, jni);
          }
        }
        for (const dyn of (parsedElf.registerNatives.bindings || [])) {
          if (dyn.className && !dyn.className.startsWith('(')) {
            jniByClassMethod.set(`${dyn.className}#${dyn.methodName}`, {
              symbol: `${dyn.methodName} (RegisterNatives)`,
              address: dyn.stringOffset,
              library: parsedElf.fileName,
              className: dyn.className,
              methodName: dyn.methodName,
              type: 'dynamic'
            });
          }
        }
      } catch (e) {
        console.warn(`ELF parse warning (${soEntry.name}):`, e);
      }
    }

    // 5. Run Static Security Audit + Taint + Deobfuscation + MITRE + SBOM + SARIF + Inline Blob Worker Telemetry
    const securityAudit = global.ArgonElfSecurity.runStaticSecurityAudit(
      manifestInfo,
      dexFiles,
      elfFiles,
      apk.signingBlock,
      apk.certificates
    );
    const taintFlows = global.ArgonAdvanced ? global.ArgonAdvanced.runTaintAnalysis(dexFiles) : [];
    const deobfData = global.ArgonAdvanced
      ? global.ArgonAdvanced.analyzeObfuscationAndGenerateMappings(apk, dexFiles, elfFiles)
      : null;
    const workerInfo = await runOffloadedWorkerTelemetry(apk.rawBytes);
    const cryptoConstants = (workerInfo && Array.isArray(workerInfo.cryptoHits))
      ? workerInfo.cryptoHits
      : (global.ArgonAdvanced ? global.ArgonAdvanced.scanCryptographicConstants(apk.entries, apk.rawBytes) : []);
    const fridaScript = global.ArgonAdvanced
      ? global.ArgonAdvanced.generateFridaHookScript(apk, manifestInfo, dexFiles, elfFiles, taintFlows, deobfData)
      : '';
    const mitreAttack = global.ArgonAdvanced
      ? global.ArgonAdvanced.mapMitreAttackMobile(manifestInfo, dexFiles, elfFiles, taintFlows, deobfData)
      : { techniques: [], tacticCoverage: {} };
    const sbom = global.ArgonAdvanced
      ? global.ArgonAdvanced.generateCycloneDxSbom(apk, manifestInfo, dexFiles, elfFiles, cryptoConstants)
      : null;
    const sarif = global.ArgonAdvanced
      ? global.ArgonAdvanced.generateSarifReport(apk, securityAudit, taintFlows)
      : null;

    // Update global state
    State.apk = apk;
    State.arsc = arsc;
    State.manifestAxml = manifestAxml;
    State.manifestInfo = manifestInfo;
    State.dexFiles = dexFiles;
    State.allClasses = allClasses;
    State.classByName = classByName;
    State.elfFiles = elfFiles;
    State.jniByClassMethod = jniByClassMethod;
    State.securityAudit = securityAudit;
    State.taintFlows = taintFlows;
    State.deobfData = deobfData;
    State.cryptoConstants = cryptoConstants;
    State.fridaScript = fridaScript;
    State.mitreAttack = mitreAttack;
    State.sbom = sbom;
    State.sarif = sarif;
    State.patchHistory = [];
    State.diffBaseline = null;
    State.diffResult = null;
    State.diffSelectedClassIdx = 0;
    State.elfArchOverride = 'AUTO';
    State.workerInfo = workerInfo;
    State.sidebarRenderLimit = 300;
    State.codeRenderLimit = 800;
    State.bgXrefToken = (State.bgXrefToken || 0) + 1;
    if (State.smartDeobfEnabled === undefined) State.smartDeobfEnabled = true;
    State.allCrossRefs = allCrossRefs;

    State.selectedClass = allClasses[0] || null;
    State.selectedMethodIdx = 0;
    State.selectedXmlEntry = apk.entryMap.has('AndroidManifest.xml')
      ? 'AndroidManifest.xml'
      : (apk.entries.find(e => e.name.endsWith('.xml'))?.name || '');
    State.selectedElfIdx = 0;
    State.selectedHexEntry = apk.entries[0]?.name || '';

    const elapsedMs = Math.round(performance.now() - t0);
    setStatus(
      `Loaded ${apk.fileName} (${formatBytes(apk.fileSize)}) in ${elapsedMs}ms | ` +
      `${allClasses.length} classes | ${arsc ? arsc.entries.length : 0} resources | ` +
      `${elfFiles.length} native libs | Security Score: ${securityAudit.score}/100 (${securityAudit.grade})`
    );

    renderAll();
    scheduleBackgroundCrossRefBuild(allClasses, arsc, allCrossRefs, State.bgXrefToken);
  }

  function setStatus(msg) {
    const el = document.getElementById('status-text');
    if (el) el.textContent = msg;
  }

  // ==================== UI RENDERERS ====================
  function renderAll() {
    renderTopNavbarInfo();
    renderLeftSidebar();
    renderModeTabbar();
    renderCenterWorkbench();
    renderRightInspector();
  }

  function renderTopNavbarInfo() {
    const pill = document.getElementById('active-apk-pill');
    if (!pill || !State.apk) return;
    const pkg = State.manifestInfo ? State.manifestInfo.packageName : State.apk.fileName;
    const ver = State.manifestInfo ? `v${State.manifestInfo.versionName}` : '';
    pill.innerHTML = `
      <span class="dot"></span>
      <span><strong>${escapeHtml(State.apk.fileName)}</strong> (${escapeHtml(pkg)} ${escapeHtml(ver)})</span>
      <span style="color:var(--text-muted)">|</span>
      <span style="color:var(--accent-cyan)">${formatBytes(State.apk.fileSize)}</span>
    `;
  }

  function renderLeftSidebar() {
    // Update active tab button
    document.querySelectorAll('.sidebar-tab').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.tab === State.sidebarTab);
    });

    const container = document.getElementById('tree-container');
    if (!container || !State.apk) return;
    const filter = State.sidebarFilter.trim().toLowerCase();
    const html = [];

    if (State.sidebarTab === 'classes') {
      // Group classes by packageName
      const byPkg = new Map();
      for (const cls of State.allClasses) {
        if (filter && !cls.fullName.toLowerCase().includes(filter)) continue;
        const pkg = cls.packageName || '(default package)';
        if (!byPkg.has(pkg)) byPkg.set(pkg, []);
        byPkg.get(pkg).push(cls);
      }

      if (byPkg.size === 0) {
        html.push(`<div style="padding:16px;color:var(--text-muted)">No matching DEX classes found.</div>`);
      } else {
        const maxItems = State.sidebarRenderLimit || 300;
        let renderedCount = 0;
        let totalMatched = 0;
        for (const clsList of byPkg.values()) totalMatched += clsList.length;

        for (const [pkg, clsList] of byPkg.entries()) {
          if (renderedCount >= maxItems) break;
          html.push(`
            <div class="tree-group-header">
              <span>📦 ${escapeHtml(pkg)}</span>
              <span>${clsList.length}</span>
            </div>
          `);
          for (const cls of clsList) {
            if (renderedCount >= maxItems) break;
            renderedCount++;
            const isSel = State.selectedClass && State.selectedClass.fullName === cls.fullName && State.activeMode === 'code';
            const iconCls = cls.isInterface ? 'icon-iface' : 'icon-cls';
            const iconChar = cls.isInterface ? 'I' : 'C';
            html.push(`
              <div class="tree-item ${isSel ? 'active' : ''}" data-action="select-class" data-classname="${escapeHtml(cls.fullName)}">
                <span class="tree-icon ${iconCls}">${iconChar}</span>
                <span>${escapeHtml(cls.simpleName)}</span>
                <span class="tree-meta">${cls.allMethods.length}m</span>
              </div>
            `);
          }
        }
        if (totalMatched > renderedCount) {
          html.push(`
            <div class="tree-item" data-action="load-more-classes" style="justify-content:center;color:var(--accent-cyan);font-weight:700">
              <span>➕ Show more classes (${renderedCount} / ${totalMatched})</span>
            </div>
          `);
        }
      }
    } else if (State.sidebarTab === 'files') {
      const entries = State.apk.entries.filter(e => !filter || e.name.toLowerCase().includes(filter));
      html.push(`
        <div class="tree-group-header">
          <span>🗂️ APK Archive Entries</span>
          <span>${entries.length}</span>
        </div>
      `);
      for (const entry of entries) {
        let iconCls = 'icon-file', iconTxt = 'F';
        if (entry.name.endsWith('.xml')) { iconCls = 'icon-xml'; iconTxt = 'X'; }
        else if (entry.name.endsWith('.dex')) { iconCls = 'icon-cls'; iconTxt = 'D'; }
        else if (entry.name.endsWith('.arsc')) { iconCls = 'icon-arsc'; iconTxt = 'R'; }
        else if (entry.name.endsWith('.so')) { iconCls = 'icon-so'; iconTxt = 'S'; }
        else if (entry.name.startsWith('META-INF/')) { iconCls = 'icon-cert'; iconTxt = 'K'; }

        html.push(`
          <div class="tree-item" data-action="select-file" data-filename="${escapeHtml(entry.name)}">
            <span class="tree-icon ${iconCls}">${iconTxt}</span>
            <span title="${escapeHtml(entry.name)}">${escapeHtml(entry.name)}</span>
            <span class="tree-meta">${formatBytes(entry.uncompressedSize)}</span>
          </div>
        `);
      }
    } else if (State.sidebarTab === 'strings') {
      const allStrings = [];
      for (const dex of State.dexFiles) {
        for (let i = 0; i < dex.strings.length; i++) {
          const s = dex.strings[i];
          if (s.length < 2) continue;
          if (filter && !s.toLowerCase().includes(filter)) continue;
          allStrings.push({ str: s, dex: dex.dexName, idx: i });
          if (allStrings.length >= 400) break;
        }
      }
      html.push(`
        <div class="tree-group-header">
          <span>🔤 DEX Constant Strings</span>
          <span>${allStrings.length} shown</span>
        </div>
      `);
      for (const item of allStrings) {
        html.push(`
          <div class="tree-item" data-action="search-string" data-str="${escapeHtml(item.str)}">
            <span class="tree-icon icon-arsc">"</span>
            <span title="${escapeHtml(item.str)}">${escapeHtml(item.str)}</span>
          </div>
        `);
      }
    }

    container.innerHTML = html.join('');
  }

  function renderModeTabbar() {
    document.querySelectorAll('.mode-tab').forEach(tab => {
      tab.classList.toggle('active', tab.dataset.mode === State.activeMode);
    });

    const clsBadge = document.getElementById('badge-classes');
    if (clsBadge) clsBadge.textContent = State.allClasses.length;

    const arscBadge = document.getElementById('badge-arsc');
    if (arscBadge) arscBadge.textContent = State.arsc ? State.arsc.entries.length : 0;

    const elfBadge = document.getElementById('badge-elf');
    if (elfBadge) elfBadge.textContent = State.elfFiles.length;

    const secBadge = document.getElementById('badge-security');
    if (secBadge && State.securityAudit) {
      secBadge.textContent = State.securityAudit.findings.length;
    }

    const taintBadge = document.getElementById('badge-taint');
    if (taintBadge && State.taintFlows) {
      taintBadge.textContent = State.taintFlows.length;
    }

    // Show/hide right inspector only in 'code' and 'cfg' modes
    const ws = document.getElementById('main-workspace');
    if (ws) {
      ws.classList.toggle('hide-right-inspector', !['code', 'cfg'].includes(State.activeMode));
    }
  }

  function renderCenterWorkbench() {
    const body = document.getElementById('workbench-body');
    const subtoolbar = document.getElementById('code-subtoolbar');
    if (!body || !State.apk) return;

    if (State.activeMode === 'code') {
      subtoolbar.style.display = 'flex';
      renderCodeStudioView(body, subtoolbar);
    } else {
      subtoolbar.style.display = 'none';
      if (State.activeMode === 'overview') renderOverviewDashboard(body);
      else if (State.activeMode === 'cfg') renderCfgAndCallGraphView(body);
      else if (State.activeMode === 'taint') renderTaintAndDeobfView(body);
      else if (State.activeMode === 'manifest') renderManifestAndXmlView(body);
      else if (State.activeMode === 'arsc') renderArscTableView(body);
      else if (State.activeMode === 'elf') renderElfNativeInspectorView(body);
      else if (State.activeMode === 'security') renderSecurityAuditView(body);
      else if (State.activeMode === 'diff') renderDiffAndPatchView(body);
      else if (State.activeMode === 'hex') renderHexInspectorView(body);
    }
  }

  // -------------------- VIEW 1: JAVA / SMALI / BYTECODE STUDIO --------------------
  function renderCodeStudioView(body, subtoolbar) {
    const cls = State.selectedClass;
    if (!cls) {
      body.innerHTML = `<div class="dashboard-pad"><div class="section-card"><div class="section-card-body">No DEX classes found in this file.</div></div></div>`;
      return;
    }

    const decompiled = global.ArgonDex.decompileClassToJava(cls, State.arsc);
    const javaCodeToRender = (State.smartDeobfEnabled && global.ArgonAdvanced)
      ? global.ArgonAdvanced.applySmartDeobfuscationToJava(decompiled.java, cls, State.deobfData)
      : decompiled.java;

    subtoolbar.innerHTML = `
      <div class="breadcrumb-trail">
        <span>${escapeHtml(cls.dexName)}</span>
        <span>›</span>
        <span>${escapeHtml(cls.packageName || '(default)')}</span>
        <span>›</span>
        <strong>${escapeHtml(cls.simpleName)}.java</strong>
      </div>
      <div class="view-toggle-group">
        <button class="view-pill ${State.smartDeobfEnabled ? 'active' : ''}" id="btn-toggle-deobf" title="Semantic Auto-Deobfuscation for ProGuard/R8 short identifiers">
          🪄 Smart Deobf: ${State.smartDeobfEnabled ? 'ON' : 'OFF'}
        </button>
        <button class="view-pill ${State.codeSubMode === 'split' ? 'active' : ''}" data-submode="split">Split (Java ↔ Smali)</button>
        <button class="view-pill ${State.codeSubMode === 'java' ? 'active' : ''}" data-submode="java">Java Source</button>
        <button class="view-pill ${State.codeSubMode === 'smali' ? 'active' : ''}" data-submode="smali">Smali Assembly</button>
        <button class="view-pill ${State.codeSubMode === 'insns' ? 'active' : ''}" data-submode="insns">Dalvik Opcode Table</button>
        <button class="view-pill" id="btn-copy-java" title="Copy Decompiled Java to Clipboard">📋 Copy Java</button>
      </div>
    `;

    if (State.codeSubMode === 'split') {
      body.innerHTML = `
        <div class="split-code-pane">
          <div class="code-scroll-box" id="java-scroll-pane">
            <div class="code-pane-label">
              <span>☕ DECOMPILED JAVA SOURCE (${escapeHtml(cls.simpleName)}.java)</span>
              <span>AST + Expression Folding ${State.smartDeobfEnabled ? '+ Smart Deobfuscator' : ''}</span>
            </div>
            ${renderCodeLinesHtml(javaCodeToRender, 'java')}
          </div>
          <div class="code-scroll-box" id="smali-scroll-pane">
            <div class="code-pane-label">
              <span>⚙️ SMALI DISASSEMBLY (${escapeHtml(cls.descriptor)})</span>
              <span>Dalvik Registers & Offsets</span>
            </div>
            ${renderCodeLinesHtml(decompiled.smali, 'smali')}
          </div>
        </div>
      `;
    } else if (State.codeSubMode === 'java') {
      body.innerHTML = `
        <div class="single-code-pane">
          <div class="code-scroll-box">
            <div class="code-pane-label">
              <span>☕ DECOMPILED JAVA SOURCE (${escapeHtml(cls.fullName)})</span>
              <span>Click any highlighted class identifier to jump to definition</span>
            </div>
            ${renderCodeLinesHtml(javaCodeToRender, 'java')}
          </div>
        </div>
      `;
    } else if (State.codeSubMode === 'smali') {
      body.innerHTML = `
        <div class="single-code-pane">
          <div class="code-scroll-box">
            <div class="code-pane-label">
              <span>⚙️ SMALI DISASSEMBLY (${escapeHtml(cls.descriptor)})</span>
              <span>${cls.allMethods.length} methods</span>
            </div>
            ${renderCodeLinesHtml(decompiled.smali, 'smali')}
          </div>
        </div>
      `;
    } else if (State.codeSubMode === 'insns') {
      const rows = [];
      for (const m of cls.allMethods) {
        const sig = `${m.name}(${m.proto.parameters.join('')})${m.proto.returnType}`;
        const jniLink = State.jniByClassMethod.get(`${cls.fullName}#${m.name}`);
        rows.push(`
          <tr style="background:var(--bg-elevated)">
            <td colspan="6" style="font-weight:700;color:var(--accent-cyan)">
              Method: ${escapeHtml(sig)}
              ${m.code ? `(Registers: ${m.code.registersSize}, Ins: ${m.code.insSize}, Outs: ${m.code.outsSize}, Code Units: ${m.code.insnsSize})` : '(NATIVE / ABSTRACT)'}
              ${jniLink ? `<span class="badge badge-ok" style="margin-left:10px">JNI Linked → ${escapeHtml(jniLink.symbol)} @ ${jniLink.address} (${escapeHtml(jniLink.library)})</span>` : ''}
            </td>
          </tr>
        `);
        if (m.code) {
          for (const ins of m.code.instructions) {
            const isBranch = ins.opcode >= 0x32 && ins.opcode <= 0x3d;
            const isConst = ins.opcode >= 0x12 && ins.opcode <= 0x15;
            const patchBtns = [];
            if (isBranch) {
              patchBtns.push(`<button class="btn" style="padding:2px 6px;font-size:10px;border-color:var(--accent-amber);color:var(--accent-amber)" data-patch-op="invert-branch" data-dex-name="${escapeHtml(cls.dexName)}" data-file-off="${ins.fileByteOffset}" data-unit-len="${ins.unitLen}">Flip Branch</button>`);
            }
            if (isConst) {
              patchBtns.push(`<button class="btn" style="padding:2px 6px;font-size:10px;border-color:var(--accent-emerald);color:var(--accent-emerald)" data-patch-op="const-true" data-dex-name="${escapeHtml(cls.dexName)}" data-file-off="${ins.fileByteOffset}" data-unit-len="${ins.unitLen}">Force 1</button>`);
            }
            patchBtns.push(`<button class="btn" style="padding:2px 6px;font-size:10px" data-patch-op="nop" data-dex-name="${escapeHtml(cls.dexName)}" data-file-off="${ins.fileByteOffset}" data-unit-len="${ins.unitLen}">NOP</button>`);

            rows.push(`
              <tr>
                <td style="color:var(--accent-indigo)">+0x${ins.pc.toString(16).padStart(4, '0')} <div style="font-size:9.5px;color:var(--text-muted)">@0x${(ins.fileByteOffset || 0).toString(16)}</div></td>
                <td style="color:var(--text-muted)">${escapeHtml(ins.rawHex)}</td>
                <td><span class="badge badge-low">${escapeHtml(ins.fmt)}</span></td>
                <td style="color:var(--accent-amber);font-weight:700">${escapeHtml(ins.name)}</td>
                <td>${ highlightSmaliLine(ins.smali) }</td>
                <td style="white-space:nowrap">${patchBtns.join(' ')}</td>
              </tr>
            `);
          }
        }
      }

      body.innerHTML = `
        <div class="dashboard-pad">
          <div class="section-card">
            <div class="section-card-header">
              <span>Dalvik 16-bit Bytecode Instruction Stream &amp; Live Patcher — ${escapeHtml(cls.fullName)}</span>
              <span>DEX Version ${escapeHtml(State.dexFiles[0]?.version || '038')} | Inline Bytecode Patching</span>
            </div>
            <table class="data-table">
              <thead>
                <tr>
                  <th style="width:95px">Code / File Off</th>
                  <th style="width:150px">Raw 16-Bit Hex</th>
                  <th style="width:75px">Format</th>
                  <th style="width:150px">Opcode Mnemonic</th>
                  <th>Disassembled Smali &amp; Resolved Pool References</th>
                  <th style="width:165px">Bytecode Patch</th>
                </tr>
              </thead>
              <tbody>${rows.join('')}</tbody>
            </table>
          </div>
        </div>
      `;
    }
  }

  // -------------------- VIEW 2: OVERVIEW & ARCHITECTURE DASHBOARD --------------------
  function renderOverviewDashboard(body) {
    const apk = State.apk;
    const mf = State.manifestInfo || {};
    const audit = State.securityAudit || { score: 100, grade: 'A', findings: [] };

    let totalMethods = 0;
    let totalStrings = 0;
    for (const d of State.dexFiles) {
      totalMethods += d.methods.length;
      totalStrings += d.strings.length;
    }

    const catColors = {
      dex: '#00e5ff',
      native: '#f43f5e',
      res: '#f59e0b',
      arsc: '#10b981',
      assets: '#a855f7',
      manifest: '#3b82f6',
      'Signature/META-INF': '#6366f1',
      other: '#64748b'
    };

    const barSegments = [];
    const legendItems = [];
    const totalUncompressed = apk.entries.reduce((acc, e) => acc + e.uncompressedSize, 0) || 1;

    for (const [cat, info] of Object.entries(apk.categoryBreakdown)) {
      if (info.uncompressed === 0) continue;
      const pct = Math.max(1.5, Math.round((info.uncompressed / totalUncompressed) * 1000) / 10);
      const col = catColors[cat] || '#64748b';
      barSegments.push(`<div style="width:${pct}%;background:${col}" title="${cat}: ${formatBytes(info.uncompressed)} (${pct}%)"></div>`);
      legendItems.push(`
        <div class="size-legend-item">
          <span class="legend-dot" style="background:${col}"></span>
          <span><strong>${escapeHtml(cat)}</strong>: ${formatBytes(info.uncompressed)} (${info.count} files)</span>
        </div>
      `);
    }

    body.innerHTML = `
      <div class="dashboard-pad">
        <div class="stats-grid">
          <div class="stat-card">
            <span class="label">Package Identifier</span>
            <span class="value" style="font-size:15px;color:var(--accent-cyan)">${escapeHtml(mf.packageName || apk.fileName)}</span>
            <span class="sub">Version: ${escapeHtml(mf.versionName || 'N/A')} (Code ${escapeHtml(mf.versionCode || '1')})</span>
          </div>
          <div class="stat-card">
            <span class="label">Target / Min SDK</span>
            <span class="value">API ${escapeHtml(mf.targetSdkVersion || '34')}</span>
            <span class="sub">Min SDK: API ${escapeHtml(mf.minSdkVersion || '21')} | Compile: ${escapeHtml(mf.compileSdkVersion || '34')}</span>
          </div>
          <div class="stat-card">
            <span class="label">DEX Bytecode Scope</span>
            <span class="value">${State.allClasses.length} Classes</span>
            <span class="sub">${totalMethods} Method Refs | ${totalStrings} Strings</span>
          </div>
          <div class="stat-card">
            <span class="label">Native & Resources</span>
            <span class="value">${State.elfFiles.length} ELF (.so)</span>
            <span class="sub">${State.arsc ? State.arsc.entries.length : 0} ARSC IDs | Entropy: ${apk.entropy} bits/B</span>
          </div>
          <div class="stat-card">
            <span class="label">MASVS Security Rating</span>
            <span class="value" style="color:${audit.score >= 75 ? 'var(--accent-emerald)' : (audit.score >= 50 ? 'var(--accent-amber)' : 'var(--sev-critical)')}">
              ${audit.score}/100 (Grade ${audit.grade})
            </span>
            <span class="sub">${audit.findings.length} static security findings detected</span>
          </div>
        </div>

        <div class="section-card">
          <div class="section-card-header">
            <span>📊 APK Binary Composition & Uncompressed Size Breakdown</span>
            <span>SHA-256: ${apk.sha256.slice(0, 32)}...</span>
          </div>
          <div class="section-card-body">
            <div class="size-bar-stack">${barSegments.join('')}</div>
            <div class="size-legend">${legendItems.join('')}</div>
          </div>
        </div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
          <div class="section-card">
            <div class="section-card-header">
              <span>🔐 APK Signing Block (v1 / v2 / v3) & X.509 Certificates</span>
              <span class="badge ${apk.signingBlock.v2Signed || apk.signingBlock.v3Signed ? 'badge-ok' : 'badge-medium'}">
                ${apk.signingBlock.v3Signed ? 'v2 + v3 Signed' : (apk.signingBlock.v2Signed ? 'v2 Signed' : 'v1 / Unsigned')}
              </span>
            </div>
            <div class="section-card-body" style="font-family:var(--font-mono);font-size:12px;line-height:1.7">
              <div><strong>APK Signing Block Present:</strong> ${apk.signingBlock.present ? `Yes (${formatBytes(apk.signingBlock.blockSize)} @ 0x${apk.signingBlock.blockStart.toString(16)})` : 'No'}</div>
              ${apk.signingBlock.schemes.map(s => `<div>• Block ID <code>${s.id}</code>: ${escapeHtml(s.name)} (${s.size} B)</div>`).join('')}
              <hr style="border:none;border-top:1px solid var(--border-subtle);margin:10px 0"/>
              ${apk.certificates.length ? apk.certificates.map(c => `
                <div><strong>Certificate File:</strong> ${escapeHtml(c.file)}</div>
                <div><strong>Subject / Issuer DN:</strong> ${escapeHtml(c.subjectOrIssuer)}</div>
                <div><strong>Validity Period:</strong> ${escapeHtml(c.validFrom)} → ${escapeHtml(c.validUntil)}</div>
                <div><strong>Cert SHA-256:</strong> ${c.sha256.slice(0, 32)}...</div>
              `).join('') : '<div>No META-INF/*.RSA certificate found.</div>'}
            </div>
          </div>

          <div class="section-card">
            <div class="section-card-header">
              <span>⚡ Quick Navigation & Entry Points</span>
              <span>Interactive Jump</span>
            </div>
            <div class="section-card-body" style="display:flex;flex-direction:column;gap:8px">
              ${State.allClasses.slice(0, 5).map(c => `
                <div style="display:flex;justify-content:space-between;align-items:center;padding:6px 10px;background:var(--bg-root);border-radius:6px;border:1px solid var(--border-subtle)">
                  <span style="font-family:var(--font-mono)"><strong>${escapeHtml(c.fullName)}</strong></span>
                  <button class="btn" data-action="select-class" data-classname="${escapeHtml(c.fullName)}">Open Java & Smali →</button>
                </div>
              `).join('')}
            </div>
          </div>
        </div>
      </div>
    `;
  }

  // -------------------- VIEW 3: INTERACTIVE CONTROL FLOW GRAPH (CFG) & CALL GRAPH --------------------
  function renderCfgAndCallGraphView(body) {
    const cls = State.selectedClass || State.allClasses[0];
    const methods = cls ? cls.allMethods : [];
    const curMethod = methods[State.selectedMethodIdx] || methods[0] || null;
    const cfg = curMethod ? global.ArgonDex.buildMethodCFG(curMethod) : { blocks: [], edges: [] };
    const metrics = global.ArgonAdvanced ? global.ArgonAdvanced.computeCfgMetrics(cfg) : { cyclomaticComplexity: 1, blockCount: 0, edgeCount: 0, loopCount: 0, dominators: [] };

    body.innerHTML = `
      <div class="cfg-wrapper">
        <div class="cfg-toolbar">
          <button class="view-pill ${State.cfgSubMode === 'method' ? 'active' : ''}" data-cfgmode="method">Method Basic-Block CFG</button>
          <button class="view-pill ${State.cfgSubMode === 'callgraph' ? 'active' : ''}" data-cfgmode="callgraph">App Architecture & JNI Call Graph</button>
          ${State.cfgSubMode === 'method' && cls ? `
            <span style="color:var(--text-muted)">|</span>
            <span style="font-family:var(--font-mono);font-size:11px;color:var(--accent-cyan)">${escapeHtml(cls.simpleName)} ::</span>
            <select id="cfg-method-select" style="background:var(--bg-root);color:#fff;border:1px solid var(--border-subtle);padding:4px 8px;border-radius:4px;font-family:var(--font-mono);font-size:11px">
              ${methods.map((m, idx) => `<option value="${idx}" ${idx === State.selectedMethodIdx ? 'selected' : ''}>${escapeHtml(m.name)}(${escapeHtml(m.proto.parameters.join(''))})${escapeHtml(m.proto.returnType)}</option>`).join('')}
            </select>
            <span class="badge badge-ok" title="McCabe Cyclomatic Complexity M = E - N + 2">Cyclomatic M = ${metrics.cyclomaticComplexity}</span>
            <span class="badge badge-low">Blocks: ${metrics.blockCount} | Edges: ${metrics.edgeCount} | Loops: ${metrics.loopCount}</span>
          ` : ''}
          <span style="color:var(--text-muted);font-size:11px;margin-left:4px">(Drag to pan, scroll to zoom)</span>
        </div>
        <canvas id="cfg-canvas" style="width:100%;height:100%;cursor:grab"></canvas>
      </div>
    `;

    const canvas = document.getElementById('cfg-canvas');
    if (!canvas) return;

    const selectEl = document.getElementById('cfg-method-select');
    if (selectEl) {
      selectEl.addEventListener('change', (e) => {
        State.selectedMethodIdx = parseInt(e.target.value, 10) || 0;
        renderCfgAndCallGraphView(body);
        renderRightInspector();
      });
    }

    if (State.cfgSubMode === 'method' && curMethod) {
      drawMethodCfgCanvas(canvas, cls, curMethod, cfg, metrics);
    } else {
      drawApplicationCallGraphCanvas(canvas);
    }
  }

  function drawMethodCfgCanvas(canvas, cls, method, cfg, metrics) {
    const rect = canvas.parentElement.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    const ctx = canvas.getContext('2d');

    let panX = 60, panY = 80, scale = 1.0;

    // Layout blocks vertically with branch offsets
    const nodeW = 430;
    const nodes = cfg.blocks.map((b, idx) => {
      const h = 36 + b.instructions.length * 19;
      const colOffset = (idx % 2 === 1 && cfg.blocks.length > 2) ? 260 : 0;
      return {
        block: b,
        x: 160 + colOffset,
        y: 20 + idx * 165,
        w: nodeW,
        h
      };
    });

    function renderFrame() {
      ctx.save();
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, rect.width, rect.height);
      ctx.translate(panX, panY);
      ctx.scale(scale, scale);

      if (nodes.length === 0) {
        ctx.fillStyle = '#94a3b8';
        ctx.font = '14px JetBrains Mono, monospace';
        ctx.fillText(`Method ${cls.simpleName}.${method.name}() is native or has no Dalvik bytecode.`, 60, 60);
        ctx.restore();
        return;
      }

      // Draw directed edges
      for (const edge of cfg.edges) {
        const fromNode = nodes[edge.fromIndex];
        const toNode = nodes[edge.toIndex];
        if (!fromNode || !toNode) continue;

        const startX = fromNode.x + fromNode.w / 2;
        const startY = fromNode.y + fromNode.h;
        const endX = toNode.x + toNode.w / 2;
        const endY = toNode.y;

        ctx.beginPath();
        ctx.lineWidth = 2;
        if (edge.type === 'true') ctx.strokeStyle = '#10b981';
        else if (edge.type === 'false') ctx.strokeStyle = '#f43f5e';
        else if (edge.type === 'jump') ctx.strokeStyle = '#00e5ff';
        else ctx.strokeStyle = '#64748b';

        if (toNode.y <= fromNode.y) {
          // Backward loop edge curving around the left side
          const loopX = Math.min(fromNode.x, toNode.x) - 70;
          ctx.moveTo(fromNode.x, fromNode.y + fromNode.h / 2);
          ctx.bezierCurveTo(loopX, fromNode.y + fromNode.h / 2, loopX, toNode.y + toNode.h / 2, toNode.x, toNode.y + toNode.h / 2);
        } else {
          ctx.moveTo(startX, startY);
          ctx.bezierCurveTo(startX, (startY + endY) / 2, endX, (startY + endY) / 2, endX, endY);
        }
        ctx.stroke();

        // Edge label
        if (edge.label) {
          ctx.fillStyle = ctx.strokeStyle;
          ctx.font = 'bold 11px JetBrains Mono, monospace';
          ctx.fillText(edge.label, (startX + endX) / 2 + 8, (startY + endY) / 2);
        }
      }

      // Draw Basic Block nodes
      for (const n of nodes) {
        ctx.fillStyle = '#0f172a';
        ctx.strokeStyle = '#00e5ff';
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.roundRect(n.x, n.y, n.w, n.h, 8);
        ctx.fill();
        ctx.stroke();

        // Header bar
        ctx.fillStyle = '#1e293b';
        ctx.beginPath();
        ctx.roundRect(n.x, n.y, n.w, 26, [8, 8, 0, 0]);
        ctx.fill();

        ctx.fillStyle = '#00e5ff';
        ctx.font = 'bold 11.5px JetBrains Mono, monospace';
        const idomLabel = (metrics && metrics.dominatorMap && metrics.dominatorMap.get(n.block.id)) || '';
        ctx.fillText(
          `Block ${n.block.id}  [@0x${n.block.startPc.toString(16).padStart(4, '0')}..@0x${n.block.endPc.toString(16).padStart(4, '0')}]${idomLabel ? '  idom:' + idomLabel : ''}`,
          n.x + 12,
          n.y + 17
        );

        // Instructions
        ctx.font = '11.5px JetBrains Mono, monospace';
        n.block.instructions.forEach((ins, idx) => {
          const iy = n.y + 42 + idx * 19;
          ctx.fillStyle = '#64748b';
          ctx.fillText(`+${ins.pc.toString(16).padStart(3, '0')}:`, n.x + 10, iy);
          ctx.fillStyle = '#fbbf24';
          ctx.fillText(ins.name, n.x + 56, iy);
          ctx.fillStyle = '#e2e8f0';
          const ops = ins.smali.slice(ins.name.length).trim();
          ctx.fillText(ops.length > 42 ? ops.slice(0, 42) + '…' : ops, n.x + 165, iy);
        });
      }

      ctx.restore();
    }

    attachCanvasPanZoom(canvas, (dx, dy, ds) => {
      panX += dx;
      panY += dy;
      scale = Math.max(0.35, Math.min(2.5, scale * ds));
      renderFrame();
    });
    renderFrame();
  }

  function drawApplicationCallGraphCanvas(canvas) {
    const rect = canvas.parentElement.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    const ctx = canvas.getContext('2d');

    let panX = 60, panY = 60, scale = 1.0;

    // Build nodes for DEX classes and Native ELF JNI libraries
    const graphNodes = [];
    const nodeByKey = new Map();

    State.allClasses.forEach((cls, idx) => {
      const angle = (idx / Math.max(1, State.allClasses.length)) * Math.PI * 2;
      const node = {
        key: cls.fullName,
        title: cls.simpleName,
        sub: cls.packageName,
        kind: 'DEX Class',
        color: '#00e5ff',
        x: 380 + Math.cos(angle) * 230,
        y: 260 + Math.sin(angle) * 170,
        w: 200,
        h: 58
      };
      graphNodes.push(node);
      nodeByKey.set(cls.fullName, node);
    });

    State.elfFiles.forEach((elf, idx) => {
      const node = {
        key: elf.fileName,
        title: elf.soName,
        sub: `${elf.architecture} (${elf.jniMethods.length} JNI)`,
        kind: 'ELF .so',
        color: '#f43f5e',
        x: 740,
        y: 140 + idx * 140,
        w: 215,
        h: 58
      };
      graphNodes.push(node);
      nodeByKey.set(elf.fileName, node);
    });

    function renderFrame() {
      ctx.save();
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, rect.width, rect.height);
      ctx.translate(panX, panY);
      ctx.scale(scale, scale);

      // Draw XREF call edges
      for (const xref of State.allCrossRefs) {
        const nFrom = nodeByKey.get(xref.fromClass);
        const nTo = nodeByKey.get(xref.toClass);
        if (nFrom && nTo && nFrom !== nTo) {
          ctx.beginPath();
          ctx.strokeStyle = 'rgba(0, 229, 255, 0.45)';
          ctx.lineWidth = 2;
          ctx.moveTo(nFrom.x + nFrom.w / 2, nFrom.y + nFrom.h / 2);
          ctx.lineTo(nTo.x + nTo.w / 2, nTo.y + nTo.h / 2);
          ctx.stroke();

          ctx.fillStyle = '#38bdf8';
          ctx.font = '10.5px JetBrains Mono, monospace';
          ctx.fillText(
            `.${xref.toMethod}()`,
            (nFrom.x + nTo.x + nFrom.w) / 2,
            (nFrom.y + nTo.y + nFrom.h) / 2 - 6
          );
        }
      }

      // Draw JNI Bridge edges from classes to ELF .so
      for (const elf of State.elfFiles) {
        const elfNode = nodeByKey.get(elf.fileName);
        for (const jni of elf.jniMethods) {
          const clsNode = nodeByKey.get(jni.className);
          if (clsNode && elfNode) {
            ctx.beginPath();
            ctx.setLineDash([5, 4]);
            ctx.strokeStyle = '#f43f5e';
            ctx.lineWidth = 2;
            ctx.moveTo(clsNode.x + clsNode.w / 2, clsNode.y + clsNode.h / 2);
            ctx.lineTo(elfNode.x + elfNode.w / 2, elfNode.y + elfNode.h / 2);
            ctx.stroke();
            ctx.setLineDash([]);

            ctx.fillStyle = '#fb7185';
            ctx.font = 'bold 10.5px JetBrains Mono, monospace';
            ctx.fillText(
              `JNI: ${jni.methodName}`,
              (clsNode.x + elfNode.x + clsNode.w) / 2 - 20,
              (clsNode.y + elfNode.y + clsNode.h) / 2 + 12
            );
          }
        }
      }

      // Draw Nodes
      for (const n of graphNodes) {
        ctx.fillStyle = '#0f172a';
        ctx.strokeStyle = n.color;
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.roundRect(n.x, n.y, n.w, n.h, 10);
        ctx.fill();
        ctx.stroke();

        ctx.fillStyle = n.color;
        ctx.font = 'bold 12px JetBrains Mono, monospace';
        ctx.fillText(`${n.title}`, n.x + 12, n.y + 24);

        ctx.fillStyle = '#94a3b8';
        ctx.font = '10.5px JetBrains Mono, monospace';
        ctx.fillText(`${n.sub}`, n.x + 12, n.y + 42);
      }

      ctx.restore();
    }

    attachCanvasPanZoom(canvas, (dx, dy, ds) => {
      panX += dx;
      panY += dy;
      scale = Math.max(0.4, Math.min(2.4, scale * ds));
      renderFrame();
    });
    renderFrame();
  }

  function attachCanvasPanZoom(canvas, onUpdate) {
    let dragging = false;
    let lastX = 0, lastY = 0;
    canvas.onmousedown = (e) => {
      dragging = true;
      lastX = e.clientX;
      lastY = e.clientY;
      canvas.style.cursor = 'grabbing';
    };
    window.onmouseup = () => {
      dragging = false;
      canvas.style.cursor = 'grab';
    };
    canvas.onmousemove = (e) => {
      if (!dragging) return;
      const dx = e.clientX - lastX;
      const dy = e.clientY - lastY;
      lastX = e.clientX;
      lastY = e.clientY;
      onUpdate(dx, dy, 1.0);
    };
    canvas.onwheel = (e) => {
      e.preventDefault();
      const ds = e.deltaY < 0 ? 1.1 : 0.9;
      onUpdate(0, 0, ds);
    };
  }

  // -------------------- VIEW 4: MANIFEST & BINARY AXML INSPECTOR --------------------
  async function renderManifestAndXmlView(body) {
    const xmlEntries = State.apk.entries.filter(e => e.name.endsWith('.xml'));
    const curEntryName = State.selectedXmlEntry || 'AndroidManifest.xml';
    const entryObj = State.apk.entryMap.get(curEntryName);

    let decodedXml = '<!-- Select an XML file -->';
    if (entryObj) {
      try {
        const rawBytes = await entryObj.extract();
        const parsed = global.ArgonAxml.parseAxml(rawBytes, State.arsc);
        decodedXml = parsed.xml;
      } catch (e) {
        decodedXml = `<!-- Error decoding AXML ${curEntryName}: ${e.message} -->`;
      }
    }

    const mf = State.manifestInfo;
    const allComps = mf ? [
      ...mf.activities.map(c => ({ ...c, type: 'Activity' })),
      ...mf.services.map(c => ({ ...c, type: 'Service' })),
      ...mf.receivers.map(c => ({ ...c, type: 'Receiver' })),
      ...mf.providers.map(c => ({ ...c, type: 'Provider' }))
    ] : [];

    body.innerHTML = `
      <div class="dashboard-pad">
        ${mf ? `
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
          <div class="section-card">
            <div class="section-card-header">
              <span>🛡️ Requested Android Permissions (${mf.permissions.length})</span>
              <span>Protection Level</span>
            </div>
            <table class="data-table">
              <thead>
                <tr><th>Permission Name</th><th>Level</th><th>Description</th></tr>
              </thead>
              <tbody>
                ${mf.permissions.map(p => `
                  <tr>
                    <td>${escapeHtml(p.name)}</td>
                    <td><span class="badge ${p.level === 'dangerous' ? 'badge-high' : 'badge-low'}">${escapeHtml(p.level)}</span></td>
                    <td style="color:var(--text-secondary)">${escapeHtml(p.description)}</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>

          <div class="section-card">
            <div class="section-card-header">
              <span>🧩 Declared Application Components (${allComps.length})</span>
              <span>IPC & Deep Links</span>
            </div>
            <table class="data-table">
              <thead>
                <tr><th>Type</th><th>Component Class</th><th>Exported</th><th>Intent / URI Schemes</th></tr>
              </thead>
              <tbody>
                ${allComps.map(c => `
                  <tr>
                    <td><span class="badge badge-low">${escapeHtml(c.type)}</span></td>
                    <td>
                      <span class="tok-xref" data-xref-class="${escapeHtml(c.name)}">${escapeHtml(c.name)}</span>
                    </td>
                    <td>
                      <span class="badge ${c.exported ? 'badge-medium' : 'badge-ok'}">${c.exported ? 'EXPORTED' : 'INTERNAL'}</span>
                    </td>
                    <td style="color:var(--text-secondary)">
                      ${c.intentFilters.map(f => f.actions.join(', ')).join(' | ') || (c.authorities ? 'authority: ' + escapeHtml(c.authorities) : '—')}
                    </td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        </div>
        ` : ''}

        <div class="section-card">
          <div class="section-card-header">
            <div style="display:flex;align-items:center;gap:10px">
              <span>📄 Reconstructed Binary AXML Source</span>
              <select id="axml-file-select" style="background:var(--bg-root);color:#fff;border:1px solid var(--border-subtle);padding:4px 10px;border-radius:5px;font-family:var(--font-mono);font-size:12px">
                ${xmlEntries.map(e => `<option value="${escapeHtml(e.name)}" ${e.name === curEntryName ? 'selected' : ''}>${escapeHtml(e.name)} (${formatBytes(e.uncompressedSize)})</option>`).join('')}
              </select>
            </div>
            <span>Resolved with resources.arsc & Android System Attrs</span>
          </div>
          <div class="code-scroll-box" style="max-height:480px">
            ${renderCodeLinesHtml(decodedXml, 'xml')}
          </div>
        </div>
      </div>
    `;

    const sel = document.getElementById('axml-file-select');
    if (sel) {
      sel.addEventListener('change', (e) => {
        State.selectedXmlEntry = e.target.value;
        renderManifestAndXmlView(body);
      });
    }
  }

  // -------------------- VIEW 5: RESOURCES.ARSC TABLE BROWSER --------------------
  function renderArscTableView(body) {
    if (!State.arsc) {
      body.innerHTML = `<div class="dashboard-pad"><div class="section-card"><div class="section-card-body">No resources.arsc table present in this file.</div></div></div>`;
      return;
    }

    const q = State.arscFilter.trim().toLowerCase();
    const filtered = State.arsc.entries.filter(e =>
      !q ||
      e.idHex.toLowerCase().includes(q) ||
      e.type.toLowerCase().includes(q) ||
      e.name.toLowerCase().includes(q) ||
      String(e.value).toLowerCase().includes(q)
    );

    body.innerHTML = `
      <div class="dashboard-pad">
        <div class="section-card">
          <div class="section-card-header">
            <span>🎨 Compiled Resource Table (resources.arsc) — ${filtered.length} of ${State.arsc.entries.length} Entries</span>
            <input type="text" id="arsc-search-input" class="tree-filter-input" style="width:280px" placeholder="Filter by 0x7f..., @string, name, value..." value="${escapeHtml(State.arscFilter)}"/>
          </div>
          <table class="data-table">
            <thead>
              <tr>
                <th style="width:120px">Resource ID</th>
                <th style="width:110px">Type</th>
                <th style="width:240px">Symbolic Reference</th>
                <th style="width:220px">Java R Constant</th>
                <th>Resolved Value / Payload</th>
              </tr>
            </thead>
            <tbody>
              ${filtered.slice(0, 500).map(e => `
                <tr>
                  <td style="color:var(--accent-purple);font-weight:700">${e.idHex}</td>
                  <td><span class="badge badge-low">@${escapeHtml(e.type)}</span></td>
                  <td style="color:var(--accent-cyan)">@${escapeHtml(e.type)}/${escapeHtml(e.name)}</td>
                  <td style="color:var(--text-secondary)">R.${escapeHtml(e.type)}.${escapeHtml(e.name)}</td>
                  <td>${escapeHtml(e.value)}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;

    const input = document.getElementById('arsc-search-input');
    if (input) {
      input.focus();
      input.setSelectionRange(input.value.length, input.value.length);
      input.addEventListener('input', (e) => {
        State.arscFilter = e.target.value;
        renderArscTableView(body);
      });
    }
  }

  // -------------------- VIEW 6: NATIVE ELF (.SO) & JNI INSPECTOR --------------------
  function renderElfNativeInspectorView(body) {
    if (State.elfFiles.length === 0) {
      body.innerHTML = `<div class="dashboard-pad"><div class="section-card"><div class="section-card-body">No native ELF shared libraries (lib/*/*.so) found in this APK.</div></div></div>`;
      return;
    }

    const elf = State.elfFiles[State.selectedElfIdx] || State.elfFiles[0];
    const h = elf.hardening;
    const archMode = State.elfArchOverride && State.elfArchOverride !== 'AUTO' ? State.elfArchOverride : elf.architecture;
    const disasmRows = (global.ArgonAdvanced && elf.rawBytes)
      ? global.ArgonAdvanced.disassembleMultiArchElf(elf.rawBytes, elf, State.elfArchOverride === 'AUTO' ? null : State.elfArchOverride)
      : (elf.disassembly || []);
    const regNat = elf.registerNatives || { hasJniOnLoad: false, usesRegisterNatives: false, bindings: [] };

    body.innerHTML = `
      <div class="dashboard-pad">
        <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px">
          <div style="display:flex;align-items:center;gap:12px">
            <span style="font-weight:700;font-size:14px">Select Native Library (.so):</span>
            <select id="elf-file-select" style="background:var(--bg-panel);color:#fff;border:1px solid var(--accent-cyan);padding:6px 12px;border-radius:6px;font-family:var(--font-mono)">
              ${State.elfFiles.map((f, i) => `<option value="${i}" ${i === State.selectedElfIdx ? 'selected' : ''}>${escapeHtml(f.fileName)} (${escapeHtml(f.architecture)}, ${formatBytes(f.fileSize)})</option>`).join('')}
            </select>
            <select id="elf-arch-select" style="background:var(--bg-panel);color:var(--accent-amber);border:1px solid var(--border);padding:6px 10px;border-radius:6px;font-family:var(--font-mono)">
              <option value="AUTO" ${State.elfArchOverride === 'AUTO' ? 'selected' : ''}>ABI: Auto (${escapeHtml(elf.architecture)})</option>
              <option value="ARM64" ${State.elfArchOverride === 'ARM64' ? 'selected' : ''}>Force ARM64 (AArch64)</option>
              <option value="ARM32" ${State.elfArchOverride === 'ARM32' ? 'selected' : ''}>Force ARM32 (ARMv7)</option>
              <option value="X86_64" ${State.elfArchOverride === 'X86_64' ? 'selected' : ''}>Force x86_64 (AMD64)</option>
            </select>
          </div>
          <div style="display:flex;gap:8px">
            <span class="badge ${h.pie ? 'badge-ok' : 'badge-high'}">PIE: ${h.pie ? 'Enabled' : 'No'}</span>
            <span class="badge ${h.nx ? 'badge-ok' : 'badge-critical'}">NX Stack: ${h.nx ? 'Enabled' : 'Executable!'}</span>
            <span class="badge ${h.relro !== 'None' ? 'badge-ok' : 'badge-medium'}">RELRO: ${escapeHtml(h.relro)}</span>
            <span class="badge ${h.stackCanary ? 'badge-ok' : 'badge-medium'}">Canary: ${h.stackCanary ? 'Present' : 'Not Detected'}</span>
          </div>
        </div>

        <div class="stats-grid">
          <div class="stat-card">
            <span class="label">CPU Architecture</span>
            <span class="value" style="font-size:17px;color:var(--accent-cyan)">${escapeHtml(elf.architecture)}</span>
            <span class="sub">${escapeHtml(elf.bitness)} | ${escapeHtml(elf.endianness)}</span>
          </div>
          <div class="stat-card">
            <span class="label">ELF Type & Entry</span>
            <span class="value" style="font-size:17px">${escapeHtml(elf.elfType)}</span>
            <span class="sub">Entry VAddr: ${elf.entryPoint} | SONAME: ${escapeHtml(elf.soName)}</span>
          </div>
          <div class="stat-card">
            <span class="label">Shared Dependencies (DT_NEEDED)</span>
            <span class="value" style="font-size:17px">${elf.neededLibraries.length} Libraries</span>
            <span class="sub">${escapeHtml(elf.neededLibraries.join(', ') || 'None')}</span>
          </div>
          <div class="stat-card">
            <span class="label">JNI Exported Bridges</span>
            <span class="value" style="font-size:17px;color:var(--accent-emerald)">${elf.jniMethods.length} JNI Functions</span>
            <span class="sub">${elf.exportedSymbols.length} Exported | ${elf.importedSymbols.length} Imported</span>
          </div>
        </div>

        <div class="section-card">
          <div class="section-card-header">
            <span>🔗 Discovered JNI Bridge Methods (Java ↔ Native C/C++ Auto-Linker)</span>
            <span>Click Target Java Class to Jump to Decompiled DEX Declaration</span>
          </div>
          <table class="data-table">
            <thead>
              <tr>
                <th>Native Symbol (.dynsym)</th>
                <th>Virtual Address</th>
                <th>Linked Java Class</th>
                <th>Java Native Method</th>
              </tr>
            </thead>
            <tbody>
              ${elf.jniMethods.map(j => `
                <tr>
                  <td style="color:var(--accent-rose);font-weight:700">${escapeHtml(j.symbol)}</td>
                  <td style="color:var(--accent-indigo)">${j.address}</td>
                  <td><span class="tok-xref" data-xref-class="${escapeHtml(j.className)}">${escapeHtml(j.className)}</span></td>
                  <td style="color:var(--accent-emerald);font-weight:700">${escapeHtml(j.methodName)}()</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
          <div class="section-card">
            <div class="section-card-header">
              <span>📤 Dynamic Symbol Table (.dynsym Exports & Imports)</span>
              <span>${elf.exportedSymbols.length + elf.importedSymbols.length} Symbols</span>
            </div>
            <table class="data-table">
              <thead>
                <tr><th>Direction</th><th>Bind / Type</th><th>VAddr</th><th>Symbol Name</th></tr>
              </thead>
              <tbody>
                ${elf.exportedSymbols.map(s => `
                  <tr>
                    <td><span class="badge badge-ok">EXPORT</span></td>
                    <td>${s.bind} ${s.type}</td>
                    <td style="color:var(--accent-indigo)">${s.address}</td>
                    <td>${escapeHtml(s.name)}</td>
                  </tr>
                `).join('')}
                ${elf.importedSymbols.map(s => `
                  <tr>
                    <td><span class="badge badge-low">IMPORT</span></td>
                    <td>${s.bind} ${s.type}</td>
                    <td style="color:var(--text-muted)">UND</td>
                    <td style="color:var(--text-secondary)">${escapeHtml(s.name)}</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>

          <div class="section-card">
            <div class="section-card-header">
              <span>📐 ELF Section Headers (${elf.sections.length})</span>
              <span>File Layout</span>
            </div>
            <table class="data-table">
              <thead>
                <tr><th>Idx</th><th>Section Name</th><th>Type</th><th>File Offset</th><th>Size</th></tr>
              </thead>
              <tbody>
                ${elf.sections.map(s => `
                  <tr>
                    <td>${s.index}</td>
                    <td style="color:var(--accent-cyan);font-weight:600">${escapeHtml(s.name || '(null)')}</td>
                    <td>${escapeHtml(s.type)}</td>
                    <td>0x${s.offset.toString(16)}</td>
                    <td>${formatBytes(s.size)}</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        </div>

        <div style="display:grid;grid-template-columns:1.1fr 0.9fr;gap:16px">
          <div class="section-card">
            <div class="section-card-header">
              <span>⚙️ Multi-ABI Disassembler [${escapeHtml(archMode)}] — .text (${disasmRows.length} Instructions)</span>
              <span>ARM64 / ARM32 / x86_64 + PLT Targets</span>
            </div>
            <table class="data-table">
              <thead>
                <tr>
                  <th style="width:110px">VAddr</th>
                  <th style="width:115px">Opcode</th>
                  <th style="width:90px">Mnemonic</th>
                  <th>Operands</th>
                  <th>Symbol / Comment</th>
                </tr>
              </thead>
              <tbody>
                ${disasmRows.map(ins => `
                  <tr ${ins.label ? 'style="background:rgba(0, 229, 255, 0.08)"' : ''}>
                    <td style="color:var(--accent-indigo);font-weight:600">${ins.vaddr}</td>
                    <td style="color:var(--text-secondary)">${ins.hexBytes}</td>
                    <td style="color:var(--accent-amber);font-weight:700">${escapeHtml(ins.mnemonic)}</td>
                    <td style="color:var(--accent-emerald);font-weight:600">${escapeHtml(ins.operands)}</td>
                    <td>
                      ${ins.label ? `<span class="badge badge-critical" style="margin-right:6px">${escapeHtml(ins.label)}:</span>` : ''}
                      <span style="color:var(--text-muted)">${escapeHtml(ins.comment)}</span>
                    </td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>

          <div class="section-card">
            <div class="section-card-header">
              <span>🔬 ARM64-to-Pseudo-C Native Decompiler</span>
              <span class="badge badge-ok">AAPCS64 + JNI Recovery</span>
            </div>
            <div class="code-scroll-box" style="max-height:520px">
              ${renderCodeLinesHtml(elf.pseudoC || '// No Pseudo-C output', 'java')}
            </div>
          </div>
        </div>

        <div class="section-card">
          <div class="section-card-header">
            <span>🧩 Dynamic JNI RegisterNatives &amp; JNINativeMethod Table Scanner</span>
            <span>JNI_OnLoad: ${regNat.hasJniOnLoad ? 'DETECTED' : 'No'} | RegisterNatives: ${regNat.usesRegisterNatives ? 'ACTIVE' : 'No'}</span>
          </div>
          <table class="data-table">
            <thead>
              <tr>
                <th>Mechanism</th>
                <th>Target Java Class</th>
                <th>Native Method</th>
                <th>JNI Signature String</th>
                <th>ELF String Offset</th>
              </tr>
            </thead>
            <tbody>
              ${(regNat.bindings || []).map(b => `
                <tr>
                  <td><span class="badge badge-medium">${escapeHtml(b.mechanism)}</span></td>
                  <td>${b.className && !b.className.startsWith('(') ? `<span class="tok-xref" data-xref-class="${escapeHtml(b.className)}">${escapeHtml(b.className)}</span>` : escapeHtml(b.className)}</td>
                  <td style="color:var(--accent-emerald);font-weight:700">${escapeHtml(b.methodName)}()</td>
                  <td style="font-family:var(--font-mono);color:var(--accent-cyan)">${escapeHtml(b.signature)}</td>
                  <td style="color:var(--accent-indigo)">${escapeHtml(b.stringOffset)}</td>
                </tr>
              `).join('') || '<tr><td colspan="5" style="color:var(--text-muted)">No dynamic RegisterNatives JNINativeMethod string tables found (static Java_* exports active).</td></tr>'}
            </tbody>
          </table>
        </div>
      </div>
    `;

    const sel = document.getElementById('elf-file-select');
    if (sel) {
      sel.addEventListener('change', (e) => {
        State.selectedElfIdx = parseInt(e.target.value, 10) || 0;
        renderElfNativeInspectorView(body);
      });
    }
    const archSel = document.getElementById('elf-arch-select');
    if (archSel) {
      archSel.addEventListener('change', (e) => {
        State.elfArchOverride = e.target.value || 'AUTO';
        renderElfNativeInspectorView(body);
      });
    }
  }

  // -------------------- VIEW 6.5: SOURCE-TO-SINK TAINT, DEOBFUSCATOR & CRYPTO S-BOX SCANNER --------------------
  function renderTaintAndDeobfView(body) {
    const flows = State.taintFlows || [];
    const deobf = State.deobfData || { obfuscationRatio: 0, renameReasons: [], fingerprints: [] };
    const cryptoHits = State.cryptoConstants || [];

    body.innerHTML = `
      <div class="dashboard-pad">
        <div class="stats-grid">
          <div class="stat-card">
            <span class="label">Source-to-Sink Taint Flows</span>
            <span class="value" style="color:var(--sev-critical)">${flows.length} Flows</span>
            <span class="sub">SSA Register &amp; Field Data-Flow Tracking</span>
          </div>
          <div class="stat-card">
            <span class="label">Obfuscation Density</span>
            <span class="value" style="color:var(--accent-amber)">${deobf.obfuscationRatio}%</span>
            <span class="sub">${deobf.renameReasons.length} obfuscated symbols auto-recovered</span>
          </div>
          <div class="stat-card">
            <span class="label">Crypto S-Boxes &amp; Constants</span>
            <span class="value" style="color:var(--accent-cyan)">${cryptoHits.length} Signatures</span>
            <span class="sub">Binary pattern scan across DEX &amp; ELF .rodata</span>
          </div>
          <div class="stat-card">
            <span class="label">Toolchain Fingerprints</span>
            <span class="value" style="color:var(--accent-emerald)">${deobf.fingerprints.length} Detected</span>
            <span class="sub">${escapeHtml(deobf.fingerprints.map(f => f.type).join(', '))}</span>
          </div>
        </div>

        <div class="section-card">
          <div class="section-card-header">
            <span>🧬 Intra/Inter-Procedural Source-to-Sink Data-Flow Taint Analysis (${flows.length} Verified Paths)</span>
            <span>Tracks Untrusted Inputs &amp; Hardware Secrets → Dangerous Sinks</span>
          </div>
          <table class="data-table">
            <thead>
              <tr>
                <th style="width:90px">ID / Risk</th>
                <th style="width:210px">Vulnerability Class</th>
                <th style="width:220px">Taint Source → Sink</th>
                <th>Step-by-Step Dalvik Bytecode Propagation Trace</th>
                <th style="width:170px">Target Method</th>
              </tr>
            </thead>
            <tbody>
              ${flows.map(f => `
                <tr>
                  <td>
                    <div style="font-weight:700">${f.id}</div>
                    <span class="badge ${f.severity === 'CRITICAL' ? 'badge-critical' : 'badge-high'}">${f.severity}</span>
                  </td>
                  <td style="font-weight:700;color:var(--accent-rose)">${escapeHtml(f.vulnerability)}</td>
                  <td>
                    <div><span class="badge badge-low">SRC</span> ${escapeHtml(f.source)}</div>
                    <div style="margin-top:4px"><span class="badge badge-critical">SNK</span> ${escapeHtml(f.sink)}</div>
                  </td>
                  <td>
                    <div style="display:flex;flex-direction:column;gap:3px;font-size:11px;color:var(--text-secondary)">
                      ${f.steps.map(st => `<div>• ${escapeHtml(st)}</div>`).join('')}
                    </div>
                  </td>
                  <td>
                    <span class="tok-xref" data-xref-class="${escapeHtml(f.className)}">${escapeHtml(f.className.split('.').pop())}.${escapeHtml(f.methodName)}()</span>
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
          <div class="section-card">
            <div class="section-card-header">
              <span>🪄 Smart Deobfuscator Symbol Reconstruction (${deobf.renameReasons.length})</span>
              <span class="badge badge-ok">ProGuard / R8 Heuristic Mapper</span>
            </div>
            <table class="data-table">
              <thead>
                <tr><th>Type</th><th>Obfuscated Symbol</th><th>Inferred Semantic Name</th><th>Inference Rationale</th></tr>
              </thead>
              <tbody>
                ${deobf.renameReasons.map(r => `
                  <tr>
                    <td><span class="badge badge-low">${r.kind}</span></td>
                    <td style="color:var(--accent-amber);font-weight:700">${escapeHtml(r.original)}</td>
                    <td style="color:var(--accent-emerald);font-weight:700">${escapeHtml(r.renamed)}</td>
                    <td style="color:var(--text-secondary)">${escapeHtml(r.reason)}</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>

          <div style="display:flex;flex-direction:column;gap:16px">
            <div class="section-card">
              <div class="section-card-header">
                <span>🔑 Cryptographic S-Box &amp; Constant Scanner (${cryptoHits.length})</span>
                <span>Binary Signature Match</span>
              </div>
              <table class="data-table">
                <thead>
                  <tr><th>Algorithm</th><th>Signature Description</th><th>Archive Offset</th></tr>
                </thead>
                <tbody>
                  ${cryptoHits.map(c => `
                    <tr>
                      <td><span class="badge badge-ok">${escapeHtml(c.algorithm)}</span></td>
                      <td>
                        <div>${escapeHtml(c.description)}</div>
                        <div style="font-size:10.5px;color:var(--text-muted)">Bytes: ${c.previewHex}</div>
                      </td>
                      <td style="color:var(--accent-indigo)">${c.archiveOffset}</td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>

            <div class="section-card">
              <div class="section-card-header">
                <span>🔓 Statically Decrypted XOR / Obfuscated Strings (${(deobf.decryptedStrings || []).length})</span>
                <span class="badge badge-ok">Dalvik Emulated Decryptor</span>
              </div>
              <table class="data-table">
                <thead>
                  <tr><th>Location</th><th>Cipher / Key</th><th>Encrypted Bytes</th><th>Decrypted Plaintext</th></tr>
                </thead>
                <tbody>
                  ${(deobf.decryptedStrings || []).map(d => `
                    <tr>
                      <td><span class="tok-xref" data-xref-class="${escapeHtml(d.className)}">${escapeHtml(d.className.split('.').pop())}.${escapeHtml(d.methodName)}()</span></td>
                      <td><span class="badge badge-medium">${escapeHtml(d.cipherType)}</span></td>
                      <td style="color:var(--text-muted);font-family:var(--font-mono);font-size:11px">${escapeHtml(d.encryptedHex)}</td>
                      <td style="color:var(--accent-emerald);font-weight:700;font-family:var(--font-mono)">"${escapeHtml(d.decrypted)}"</td>
                    </tr>
                  `).join('') || '<tr><td colspan="4" style="color:var(--text-muted)">No XOR-encrypted byte arrays detected.</td></tr>'}
                </tbody>
              </table>
            </div>

            <div class="section-card">
              <div class="section-card-header">
                <span>🧬 Compiler, Packer &amp; Toolchain Fingerprints</span>
                <span>Heuristic Signatures</span>
              </div>
              <table class="data-table">
                <thead>
                  <tr><th>Category</th><th>Detected Technology</th><th>Confidence / Metric</th></tr>
                </thead>
                <tbody>
                  ${deobf.fingerprints.map(fp => `
                    <tr>
                      <td><span class="badge badge-low">${escapeHtml(fp.type)}</span></td>
                      <td style="font-weight:700;color:var(--accent-cyan)">${escapeHtml(fp.name)}</td>
                      <td>${escapeHtml(fp.confidence)}</td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div class="section-card">
          <div class="section-card-header">
            <span>⚡ Automated Frida Dynamic Instrumentation Script (Java Sinks + Crypto + Native JNI Interceptor)</span>
            <button class="btn btn-primary" id="btn-download-frida" style="padding:3px 10px;font-size:11px">⬇️ Download frida_argon_hooks.js</button>
          </div>
          <div class="code-scroll-box" style="max-height:280px">
            ${renderCodeLinesHtml(State.fridaScript || '// No Frida script generated', 'java')}
          </div>
        </div>
      </div>
    `;

    const btnFrida = document.getElementById('btn-download-frida');
    if (btnFrida) {
      btnFrida.addEventListener('click', () => {
        const blob = new Blob([State.fridaScript || ''], { type: 'application/javascript' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'frida_argon_hooks.js';
        a.click();
        URL.revokeObjectURL(url);
      });
    }
  }

  // -------------------- VIEW 7: OWASP MASVS STATIC SECURITY AUDITOR --------------------
  function renderSecurityAuditView(body) {
    const audit = State.securityAudit;
    if (!audit) return;

    const badgeClassForSev = (sev) => {
      if (sev === 'CRITICAL') return 'badge-critical';
      if (sev === 'HIGH') return 'badge-high';
      if (sev === 'MEDIUM') return 'badge-medium';
      return 'badge-low';
    };

    body.innerHTML = `
      <div class="dashboard-pad">
        <div class="stats-grid">
          <div class="stat-card">
            <span class="label">Overall Security Score</span>
            <span class="value" style="color:${audit.score >= 75 ? 'var(--accent-emerald)' : (audit.score >= 50 ? 'var(--accent-amber)' : 'var(--sev-critical)')}">
              ${audit.score} / 100 (Grade ${audit.grade})
            </span>
            <span class="sub">Automated OWASP MASVS & CWE Static Assessment</span>
          </div>
          <div class="stat-card">
            <span class="label">Critical & High Findings</span>
            <span class="value" style="color:var(--sev-critical)">
              ${audit.findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').length}
            </span>
            <span class="sub">Immediate remediation recommended</span>
          </div>
          <div class="stat-card">
            <span class="label">Medium & Low Findings</span>
            <span class="value" style="color:var(--accent-amber)">
              ${audit.findings.filter(f => f.severity === 'MEDIUM' || f.severity === 'LOW').length}
            </span>
            <span class="sub">Defense-in-depth hardening items</span>
          </div>
          <div class="stat-card">
            <span class="label">Extracted Network Endpoints</span>
            <span class="value" style="color:var(--accent-cyan)">${audit.extractedUrls.length} URLs</span>
            <span class="sub">${audit.extractedSecrets.length} credential patterns flagged</span>
          </div>
        </div>

        <div style="display:flex;gap:10px;align-items:center;margin-bottom:14px;flex-wrap:wrap">
          <button class="btn btn-primary" id="btn-export-sarif">📄 Export SARIF v2.1.0 (.sarif.json)</button>
          <button class="btn" id="btn-export-sbom" style="border-color:var(--accent-emerald);color:var(--accent-emerald)">📦 Export CycloneDX v1.5 SBOM (.json)</button>
          <span style="color:var(--text-muted);font-size:11.5px;margin-left:auto">
            Worker Telemetry: <strong style="color:var(--accent-cyan)">${escapeHtml(State.workerInfo?.mode || 'sync')}</strong> (${State.workerInfo?.durationMs || 0}ms)
          </span>
        </div>

        <div class="section-card">
          <div class="section-card-header">
            <span>🎯 MITRE ATT&amp;CK® Mobile Matrix Mapping (${(State.mitreAttack?.techniques || []).length} Techniques)</span>
            <span>Adversarial Tactic &amp; Technique Coverage</span>
          </div>
          <table class="data-table">
            <thead>
              <tr>
                <th style="width:110px">Technique ID</th>
                <th style="width:155px">Tactic</th>
                <th style="width:240px">Technique Name</th>
                <th style="width:90px">Severity</th>
                <th>Static Evidence</th>
              </tr>
            </thead>
            <tbody>
              ${(State.mitreAttack?.techniques || []).map(t => `
                <tr>
                  <td style="color:var(--accent-cyan);font-weight:700">${escapeHtml(t.id)}</td>
                  <td><span class="badge badge-low">${escapeHtml(t.tactic)}</span></td>
                  <td style="font-weight:600">${escapeHtml(t.name)}</td>
                  <td><span class="badge ${badgeClassForSev(t.severity)}">${escapeHtml(t.severity)}</span></td>
                  <td style="color:var(--text-secondary)">
                    ${escapeHtml(t.evidence)}
                    ${t.targetClass ? ` <span class="tok-xref" data-xref-class="${escapeHtml(t.targetClass)}">[Inspect Class]</span>` : ''}
                  </td>
                </tr>
              `).join('') || '<tr><td colspan="5" style="color:var(--text-muted)">No MITRE ATT&amp;CK Mobile techniques matched.</td></tr>'}
            </tbody>
          </table>
        </div>

        <div class="section-card">
          <div class="section-card-header">
            <span>🚨 Static Security Audit Findings (${audit.findings.length})</span>
            <span>Click any Class Location to inspect decompiled source</span>
          </div>
          <table class="data-table">
            <thead>
              <tr>
                <th style="width:95px">Severity</th>
                <th style="width:155px">Category / CWE</th>
                <th>Finding & Technical Impact</th>
                <th style="width:230px">Code Location</th>
                <th style="width:260px">Remediation</th>
              </tr>
            </thead>
            <tbody>
              ${audit.findings.map(f => `
                <tr>
                  <td><span class="badge ${badgeClassForSev(f.severity)}">${f.severity}</span></td>
                  <td>
                    <div style="font-weight:700">${escapeHtml(f.category)}</div>
                    <div style="color:var(--text-muted);font-size:10.5px">${escapeHtml(f.cwe)}</div>
                  </td>
                  <td>
                    <div style="font-weight:700;color:var(--text-primary);margin-bottom:3px">${escapeHtml(f.title)}</div>
                    <div style="color:var(--text-secondary);font-size:11.5px">${escapeHtml(f.description)}</div>
                  </td>
                  <td>
                    ${f.location.className
                      ? `<span class="tok-xref" data-xref-class="${escapeHtml(f.location.className)}">${escapeHtml(f.location.target)}</span>`
                      : `<span style="color:var(--accent-amber)">${escapeHtml(f.location.file)}: ${escapeHtml(f.location.target)}</span>`}
                  </td>
                  <td style="color:var(--accent-emerald);font-size:11.5px">${escapeHtml(f.remediation)}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;

    const downloadJsonObj = (obj, filename) => {
      const blob = new Blob([JSON.stringify(obj, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    };
    document.getElementById('btn-export-sarif')?.addEventListener('click', () => {
      if (State.sarif) {
        const base = (State.apk?.fileName || 'argondex').replace(/\.apk$/i, '');
        downloadJsonObj(State.sarif, `${base}.sarif.json`);
        setStatus(`Exported SARIF v2.1.0 report (${State.sarif.runs?.[0]?.results?.length || 0} results).`);
      }
    });
    document.getElementById('btn-export-sbom')?.addEventListener('click', () => {
      if (State.sbom) {
        const base = (State.apk?.fileName || 'argondex').replace(/\.apk$/i, '');
        downloadJsonObj(State.sbom, `${base}_sbom_cyclonedx.json`);
        setStatus(`Exported CycloneDX v1.5 SBOM (${State.sbom.components?.length || 0} components).`);
      }
    });
  }

  // -------------------- VIEW 7.5: APK VERSION BINDIFF & ROUND-TRIP BYTECODE PATCHER --------------------
  function applyLiveBytecodePatch(dexName, fileByteOffset, patchType, unitLen) {
    const dexIdx = State.dexFiles.findIndex(d => d.dexName === dexName);
    if (dexIdx === -1) throw new Error(`DEX not found: ${dexName}`);
    const dex = State.dexFiles[dexIdx];
    if (!dex.rawBytes) throw new Error(`DEX rawBytes unavailable for ${dexName}`);
    const patchRes = global.ArgonDex.patchDexInstruction(dex.rawBytes, fileByteOffset, { type: patchType, unitLen });
    const reparsed = global.ArgonDex.parseDexFile(patchRes.bytes, dex.dexName, State.arsc);
    State.dexFiles[dexIdx] = reparsed;

    // Rebuild class index while keeping current selected class synced to newly patched AST
    const prevSelFull = State.selectedClass ? State.selectedClass.fullName : null;
    const allClasses = [];
    const classByName = new Map();
    for (const d of State.dexFiles) {
      for (const c of d.classes) {
        allClasses.push(c);
        classByName.set(c.fullName, c);
        if (!classByName.has(c.simpleName)) classByName.set(c.simpleName, c);
      }
    }
    State.allClasses = allClasses;
    State.classByName = classByName;
    if (prevSelFull && classByName.has(prevSelFull)) {
      State.selectedClass = classByName.get(prevSelFull);
    }

    State.patchHistory.push({
      dexName: dex.dexName,
      fileByteOffset,
      patchType,
      oldWordsHex: patchRes.oldWordsHex,
      newWordsHex: patchRes.newWordsHex,
      checksumHex: patchRes.checksumHex,
      signatureHex: patchRes.signatureHex,
      timestamp: new Date().toISOString()
    });

    setStatus(`Patched ${dex.dexName} @0x${fileByteOffset.toString(16)} (${patchType}) | New Adler-32: ${patchRes.checksumHex}`);
    if (typeof document !== 'undefined' && document.getElementById('workbench-body')) {
      renderAll();
    }
    return patchRes;
  }

  async function downloadPatchedApk() {
    if (!State.apk) return;
    const patchedDexMap = new Map(State.dexFiles.map(d => [d.dexName, d.rawBytes]));
    const zipEntries = [];
    for (const entry of State.apk.entries) {
      // Strip stale v1 signatures since modified bytecode invalidates original JAR manifest digests
      if (/^META-INF\/.*\.(SF|RSA|DSA|EC)$/i.test(entry.name) || entry.name === 'META-INF/MANIFEST.MF') {
        continue;
      }
      if (patchedDexMap.has(entry.name)) {
        zipEntries.push({ name: entry.name, data: patchedDexMap.get(entry.name) });
      } else {
        zipEntries.push({ name: entry.name, data: await entry.extract() });
      }
    }
    const apkOut = global.ArgonZip.buildZipArchive(zipEntries);
    const blob = new Blob([apkOut], { type: 'application/vnd.android.package-archive' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const baseName = State.apk.fileName.replace(/\.apk$/i, '');
    a.download = `${baseName}_patched_unsigned.apk`;
    a.click();
    URL.revokeObjectURL(url);
    setStatus(`Rebuilt patched APK (${formatBytes(apkOut.length)}) with updated DEX SHA-1 & Adler-32 checksums (ready for apksigner).`);
  }

  function renderDiffAndPatchView(body) {
    const patches = State.patchHistory || [];
    const diff = State.diffResult;
    const modList = diff ? diff.classes.modified : [];
    const selectedMod = modList[State.diffSelectedClassIdx] || modList[0] || null;

    const renderUnifiedDiffHtml = (text) => {
      return String(text || '').split('\n').map(line => {
        if (line.startsWith('+')) return `<div style="background:rgba(16,185,129,0.16);color:#6ee7b7;padding:1px 8px;font-family:var(--font-mono);font-size:12px">${escapeHtml(line)}</div>`;
        if (line.startsWith('-')) return `<div style="background:rgba(244,63,94,0.16);color:#fda4af;padding:1px 8px;font-family:var(--font-mono);font-size:12px">${escapeHtml(line)}</div>`;
        return `<div style="color:var(--text-secondary);padding:1px 8px;font-family:var(--font-mono);font-size:12px">${escapeHtml(line)}</div>`;
      }).join('');
    };

    body.innerHTML = `
      <div class="dashboard-pad">
        <div class="section-card">
          <div class="section-card-header">
            <span>🩹 Round-Trip DEX Bytecode Patcher &amp; Rebuilt APK Exporter (${patches.length} Active Patches)</span>
            <button class="btn btn-primary" id="btn-download-patched-apk" style="padding:4px 12px;font-size:11.5px">📦 Rebuild &amp; Download Patched APK</button>
          </div>
          <div style="padding:10px 14px;color:var(--text-secondary);font-size:12px;border-bottom:1px solid var(--border)">
            Tip: Open <strong>Code &amp; Smali Studio → Bytecode Hex</strong> submode to patch live Dalvik instructions (<em>Flip Branch</em>, <em>Force 1</em>, <em>NOP</em>). SHA-1 (<code>0x0C..0x1F</code>) and Adler-32 (<code>0x08..0x0B</code>) are automatically recalculated.
          </div>
          <table class="data-table">
            <thead>
              <tr>
                <th>DEX File</th>
                <th>File Offset</th>
                <th>Patch Op</th>
                <th>Original Hex → Patched Hex</th>
                <th>Recalculated Adler-32</th>
              </tr>
            </thead>
            <tbody>
              ${patches.map(p => `
                <tr>
                  <td style="color:var(--accent-cyan)">${escapeHtml(p.dexName)}</td>
                  <td style="color:var(--accent-indigo)">0x${p.fileByteOffset.toString(16)}</td>
                  <td><span class="badge badge-medium">${escapeHtml(p.patchType)}</span></td>
                  <td style="font-family:var(--font-mono)"><span style="color:var(--accent-rose)">${escapeHtml(p.oldWordsHex)}</span> → <span style="color:var(--accent-emerald)">${escapeHtml(p.newWordsHex)}</span></td>
                  <td style="color:var(--accent-amber);font-weight:700">${escapeHtml(p.checksumHex)}</td>
                </tr>
              `).join('') || '<tr><td colspan="5" style="color:var(--text-muted)">No live bytecode patches applied yet. Switch to Code Studio → Bytecode Hex to patch an instruction.</td></tr>'}
            </tbody>
          </table>
        </div>

        <div class="section-card">
          <div class="section-card-header">
            <span>⚖️ APK Version BinDiff &amp; Tamper Comparison Engine</span>
            <div style="display:flex;gap:8px">
              <button class="btn btn-primary" id="btn-synth-diff" style="padding:4px 10px;font-size:11px">⚡ Compare vs Baseline (v2.4.0)</button>
              <button class="btn" id="btn-load-diff-apk" style="padding:4px 10px;font-size:11px">📂 Load Comparison Baseline APK</button>
              <input type="file" id="diff-baseline-input" accept=".apk,.dex" style="display:none" />
            </div>
          </div>
          ${diff ? `
            <div style="padding:12px 14px">
              <div class="stats-grid" style="margin-bottom:12px">
                <div class="stat-card">
                  <span class="label">Baseline → Target</span>
                  <span class="value" style="font-size:14px;color:var(--accent-cyan)">${escapeHtml(diff.baselineName)} → ${escapeHtml(diff.targetName)}</span>
                  <span class="sub">Version: ${escapeHtml(diff.versionChange.from)} → ${escapeHtml(diff.versionChange.to)}</span>
                </div>
                <div class="stat-card">
                  <span class="label">Permissions Delta</span>
                  <span class="value" style="font-size:16px">+${diff.permissions.added.length} / -${diff.permissions.removed.length}</span>
                  <span class="sub">${escapeHtml(diff.permissions.added.join(', ') || 'No added permissions')}</span>
                </div>
                <div class="stat-card">
                  <span class="label">DEX Classes Changed</span>
                  <span class="value" style="font-size:16px;color:var(--accent-amber)">${modList.length} Modified</span>
                  <span class="sub">+${diff.classes.added.length} added | -${diff.classes.removed.length} removed | ${diff.classes.unchangedCount} unchanged</span>
                </div>
                <div class="stat-card">
                  <span class="label">Native Symbols Delta</span>
                  <span class="value" style="font-size:16px">+${diff.nativeSymbols.added.length} / -${diff.nativeSymbols.removed.length}</span>
                  <span class="sub">ELF .dynsym export comparison</span>
                </div>
              </div>
              <div style="display:flex;gap:12px;align-items:center;margin-bottom:10px">
                <span style="font-weight:700">Modified Class Unified Java AST Diff:</span>
                <select id="diff-class-select" style="background:var(--bg-panel);color:#fff;border:1px solid var(--border);padding:5px 10px;border-radius:6px;font-family:var(--font-mono)">
                  ${modList.map((m, idx) => `<option value="${idx}" ${idx === State.diffSelectedClassIdx ? 'selected' : ''}>${escapeHtml(m.fullName)} (+${m.addedLines}/-${m.removedLines})</option>`).join('')}
                </select>
              </div>
              <div class="code-scroll-box" style="max-height:360px;padding:8px 0">
                ${selectedMod ? renderUnifiedDiffHtml(selectedMod.unifiedDiff) : '<div style="padding:12px;color:var(--text-muted)">All DEX classes match the baseline identically!</div>'}
              </div>
            </div>
          ` : `
            <div style="padding:18px;color:var(--text-secondary)">
              Click <strong>Compare vs Baseline (v2.4.0)</strong> for an instant diff against a synthesized previous release, or load a second <code>.apk</code> file to diff permissions, classes, native symbols, and decompiled Java ASTs.
            </div>
          `}
        </div>
      </div>
    `;

    document.getElementById('btn-download-patched-apk')?.addEventListener('click', downloadPatchedApk);
    document.getElementById('btn-synth-diff')?.addEventListener('click', () => {
      const targetBundle = {
        apk: State.apk,
        fileName: State.apk.fileName,
        manifestInfo: State.manifestInfo,
        dexFiles: State.dexFiles,
        elfFiles: State.elfFiles,
        arsc: State.arsc
      };
      const baseBundle = global.ArgonAdvanced.synthesizeBaselineBundle(targetBundle);
      State.diffBaseline = baseBundle;
      State.diffResult = global.ArgonAdvanced.computeApkDiff(baseBundle, targetBundle);
      State.diffSelectedClassIdx = 0;
      renderDiffAndPatchView(body);
    });

    const diffInput = document.getElementById('diff-baseline-input');
    document.getElementById('btn-load-diff-apk')?.addEventListener('click', () => diffInput?.click());
    diffInput?.addEventListener('change', async (e) => {
      const f = e.target.files?.[0];
      if (!f) return;
      const ab = await f.arrayBuffer();
      const baseApk = await global.ArgonZip.parseApkArchive(ab, f.name);
      const baseDexFiles = [];
      for (const entry of baseApk.entries.filter(x => x.name.endsWith('.dex'))) {
        baseDexFiles.push(global.ArgonDex.parseDexFile(await entry.extract(), entry.name));
      }
      let baseMf = null;
      const mfEntry = baseApk.entryMap.get('AndroidManifest.xml');
      if (mfEntry) {
        const axml = global.ArgonAxml.parseAxml(await mfEntry.extract(), State.arsc);
        baseMf = global.ArgonAxml.analyzeManifest(axml);
      }
      const baseElfs = [];
      for (const so of baseApk.entries.filter(x => x.name.endsWith('.so'))) {
        baseElfs.push(global.ArgonElfSecurity.parseElfBinary(await so.extract(), so.name));
      }
      const baseBundle = { fileName: f.name, apk: baseApk, manifestInfo: baseMf, dexFiles: baseDexFiles, elfFiles: baseElfs };
      const targetBundle = {
        apk: State.apk,
        fileName: State.apk.fileName,
        manifestInfo: State.manifestInfo,
        dexFiles: State.dexFiles,
        elfFiles: State.elfFiles,
        arsc: State.arsc
      };
      State.diffBaseline = baseBundle;
      State.diffResult = global.ArgonAdvanced.computeApkDiff(baseBundle, targetBundle);
      State.diffSelectedClassIdx = 0;
      renderDiffAndPatchView(body);
    });

    document.getElementById('diff-class-select')?.addEventListener('change', (e) => {
      State.diffSelectedClassIdx = parseInt(e.target.value, 10) || 0;
      renderDiffAndPatchView(body);
    });
  }

  // -------------------- VIEW 8: BINARY HEX & ASCII INSPECTOR --------------------
  async function renderHexInspectorView(body) {
    const entryName = State.selectedHexEntry || State.apk.entries[0]?.name;
    const entry = State.apk.entryMap.get(entryName);
    let bytes = new Uint8Array(0);
    if (entry) {
      try {
        bytes = await entry.extract();
      } catch (e) {
        // ignore
      }
    }

    const maxBytes = Math.min(bytes.length, 4096); // Show first 4KB for instant rendering
    const rows = [];
    for (let offset = 0; offset < maxBytes; offset += 16) {
      const slice = bytes.subarray(offset, Math.min(maxBytes, offset + 16));
      const hexParts = [];
      let ascii = '';
      for (let i = 0; i < 16; i++) {
        if (i < slice.length) {
          const b = slice[i];
          hexParts.push(b.toString(16).padStart(2, '0').toUpperCase());
          ascii += (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.';
        } else {
          hexParts.push('  ');
          ascii += ' ';
        }
        if (i === 7) hexParts.push('');
      }
      rows.push(`
        <div class="hex-row">
          <span class="hex-offset">${offset.toString(16).padStart(8, '0').toUpperCase()}</span>
          <span class="hex-bytes">${hexParts.join(' ')}</span>
          <span class="hex-ascii">|${escapeHtml(ascii)}|</span>
        </div>
      `);
    }

    body.innerHTML = `
      <div class="dashboard-pad">
        <div class="section-card">
          <div class="section-card-header">
            <div style="display:flex;align-items:center;gap:10px">
              <span>🔢 Binary Hex & Structure Inspector</span>
              <select id="hex-file-select" style="background:var(--bg-root);color:#fff;border:1px solid var(--border-subtle);padding:4px 10px;border-radius:5px;font-family:var(--font-mono);font-size:12px">
                ${State.apk.entries.map(e => `<option value="${escapeHtml(e.name)}" ${e.name === entryName ? 'selected' : ''}>${escapeHtml(e.name)} (${formatBytes(e.uncompressedSize)})</option>`).join('')}
              </select>
            </div>
            <span>Showing ${formatBytes(maxBytes)} of ${formatBytes(bytes.length)} (CRC32: ${entry ? entry.crc32 : 'N/A'})</span>
          </div>
          <div class="hex-grid">${rows.join('')}</div>
        </div>
      </div>
    `;

    const sel = document.getElementById('hex-file-select');
    if (sel) {
      sel.addEventListener('change', (e) => {
        State.selectedHexEntry = e.target.value;
        renderHexInspectorView(body);
      });
    }
  }

  // ==================== RIGHT SIDEBAR: CLASS OUTLINE & XREFS ====================
  function renderRightInspector() {
    const panel = document.getElementById('right-inspector');
    if (!panel) return;
    const cls = State.selectedClass;
    if (!cls) {
      panel.innerHTML = `<div class="inspector-section"><div class="inspector-title">Class Inspector</div><div style="color:var(--text-muted)">Select a class to inspect methods & XREFs.</div></div>`;
      return;
    }

    const incomingXrefs = State.allCrossRefs.filter(x => x.toClass === cls.fullName);
    const outgoingXrefs = State.allCrossRefs.filter(x => x.fromClass === cls.fullName);

    panel.innerHTML = `
      <div class="inspector-section">
        <div class="inspector-title">
          <span>🏛️ Class Structure</span>
          <span class="badge badge-low">${escapeHtml(cls.dexName)}</span>
        </div>
        <div style="font-family:var(--font-mono);font-size:11.5px;line-height:1.6">
          <div style="color:var(--accent-cyan);font-weight:700">${escapeHtml(cls.fullName)}</div>
          <div style="color:var(--text-secondary)">Super: ${escapeHtml(cls.superName || 'java.lang.Object')}</div>
          <div style="color:var(--text-muted)">Fields: ${cls.staticFields.length} static, ${cls.instanceFields.length} instance</div>
        </div>
      </div>

      <div class="inspector-section" style="padding-bottom:6px">
        <div class="inspector-title">
          <span>⚡ Methods (${cls.allMethods.length})</span>
          <span style="font-size:10px;color:var(--accent-cyan)">Click for CFG</span>
        </div>
      </div>
      <div class="method-list">
        ${cls.allMethods.map((m, idx) => {
          const jni = State.jniByClassMethod.get(`${cls.fullName}#${m.name}`);
          const flags = global.ArgonDex.formatAccessFlags(m.accessFlags, 'method').join(' ');
          return `
            <div class="method-card ${idx === State.selectedMethodIdx ? 'active' : ''}" data-action="select-method" data-method-idx="${idx}">
              <div class="m-name">
                <span>${escapeHtml(m.name)}()</span>
                ${jni ? `<span class="badge badge-ok" title="${escapeHtml(jni.symbol)}">JNI .so</span>` : (m.code ? `<span style="font-size:10px;color:var(--text-muted)">${m.code.instructions.length} ops</span>` : '')}
              </div>
              <div class="m-sig">${escapeHtml(flags)} (${escapeHtml(m.proto.parameters.join(''))}) → ${escapeHtml(m.proto.returnType)}</div>
            </div>
          `;
        }).join('')}
      </div>

      <div class="inspector-section" style="border-top:1px solid var(--border-subtle);max-height:190px;overflow-y:auto">
        <div class="inspector-title">
          <span>🔗 Cross-References (XREFs)</span>
          <span>${incomingXrefs.length} in / ${outgoingXrefs.length} out</span>
        </div>
        <div style="font-family:var(--font-mono);font-size:11px;display:flex;flex-direction:column;gap:5px">
          ${incomingXrefs.map(x => `
            <div>
              <span class="badge badge-ok">CALLER</span>
              <span class="tok-xref" data-xref-class="${escapeHtml(x.fromClass)}">${escapeHtml(x.fromClass.split('.').pop())}.${escapeHtml(x.fromMethod)}()</span>
            </div>
          `).join('')}
          ${outgoingXrefs.slice(0, 12).map(x => `
            <div>
              <span class="badge badge-low">CALLS</span>
              <span class="tok-xref" data-xref-class="${escapeHtml(x.toClass)}">${escapeHtml(x.toClass.split('.').pop())}.${escapeHtml(x.toMethod)}()</span>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }

  // ==================== GLOBAL SEARCH PALETTE (CTRL+K) ====================
  function openGlobalSearchModal(initialQuery = '') {
    const modal = document.getElementById('search-modal');
    const input = document.getElementById('global-search-input');
    if (!modal || !input) return;
    modal.classList.add('visible');
    input.value = initialQuery;
    input.focus();
    renderGlobalSearchResults(initialQuery);
  }

  function closeGlobalSearchModal() {
    const modal = document.getElementById('search-modal');
    if (modal) modal.classList.remove('visible');
  }

  function renderGlobalSearchResults(query) {
    const listEl = document.getElementById('global-search-results');
    if (!listEl || !State.apk) return;
    const q = query.trim().toLowerCase();
    const hits = [];
    const MAX_HITS = 80;

    // 1. Search classes & methods (with early exit at MAX_HITS for large multi-DEX APKs)
    outerLoop:
    for (const cls of State.allClasses) {
      if (!q || cls.fullName.toLowerCase().includes(q)) {
        hits.push({
          type: 'CLASS',
          badge: 'badge-low',
          label: cls.fullName,
          sub: `${cls.dexName} (${cls.allMethods.length} methods)`,
          className: cls.fullName
        });
        if (hits.length >= MAX_HITS) break outerLoop;
      }
      for (const m of cls.allMethods) {
        const fullSig = `${cls.fullName}.${m.name}`;
        if (q && fullSig.toLowerCase().includes(q)) {
          hits.push({
            type: 'METHOD',
            badge: 'badge-ok',
            label: `${cls.simpleName}.${m.name}(${m.proto.parameters.join('')})`,
            sub: cls.fullName,
            className: cls.fullName
          });
          if (hits.length >= MAX_HITS) break outerLoop;
        }
        // Search inside method string constants
        if (q && m.code) {
          for (const ins of m.code.instructions) {
            if (ins.refType === 'string' && typeof ins.refObj === 'string' && ins.refObj.toLowerCase().includes(q)) {
              hits.push({
                type: 'STRING REF',
                badge: 'badge-medium',
                label: `"${ins.refObj.slice(0, 65)}"`,
                sub: `Used in ${cls.fullName}.${m.name}()`,
                className: cls.fullName
              });
              if (hits.length >= MAX_HITS) break outerLoop;
              break;
            }
          }
        }
      }
    }

    // 2. Search JNI symbols
    for (const elf of State.elfFiles) {
      for (const jni of elf.jniMethods) {
        if (q && jni.symbol.toLowerCase().includes(q)) {
          hits.push({
            type: 'JNI .SO',
            badge: 'badge-critical',
            label: jni.symbol,
            sub: `${elf.fileName} @ ${jni.address}`,
            className: jni.className
          });
        }
      }
    }

    listEl.innerHTML = hits.slice(0, 60).map(h => `
      <div class="search-hit" data-xref-class="${escapeHtml(h.className)}">
        <div>
          <span class="badge ${h.badge}" style="margin-right:8px">${h.type}</span>
          <strong>${escapeHtml(h.label)}</strong>
        </div>
        <span style="color:var(--text-muted);font-size:11px">${escapeHtml(h.sub)}</span>
      </div>
    `).join('') || `<div style="padding:18px;color:var(--text-muted);text-align:center">No symbols or strings matching "${escapeHtml(query)}"</div>`;
  }

  // ==================== EXPORT DECOMPILED PROJECT (.ZIP) ====================
  function exportDecompiledProjectZip() {
    if (!State.apk) return;
    setStatus('Building decompiled source archive (.zip)...');
    const encoder = new TextEncoder();
    const outFiles = [];

    // 1. Reconstructed AndroidManifest.xml
    if (State.manifestAxml) {
      outFiles.push({
        name: 'AndroidManifest.xml',
        data: encoder.encode(State.manifestAxml.xml)
      });
    }

    // 2. All Decompiled .java and .smali files
    for (const cls of State.allClasses) {
      const dec = global.ArgonDex.decompileClassToJava(cls, State.arsc);
      const relPath = global.ArgonDex.sanitizeClassPath(cls.fullName);
      outFiles.push({
        name: `src/main/java/${relPath}.java`,
        data: encoder.encode(dec.java)
      });
      outFiles.push({
        name: `smali/${relPath}.smali`,
        data: encoder.encode(dec.smali)
      });
    }

    // 3. Resources table dump
    if (State.arsc) {
      outFiles.push({
        name: 'resources_table.json',
        data: encoder.encode(JSON.stringify(State.arsc.entries, null, 2))
      });
    }

    // 4. Security Audit, Frida Hook Script & Native Pseudo-C Report
    if (State.fridaScript) {
      outFiles.push({
        name: 'frida_argon_hooks.js',
        data: encoder.encode(State.fridaScript)
      });
    }

    for (const elf of State.elfFiles) {
      if (elf.pseudoC) {
        const baseSo = elf.fileName.split('/').pop().replace(/[^A-Za-z0-9_.-]/g, '_');
        outFiles.push({
          name: `native_pseudo_c/${baseSo}.c`,
          data: encoder.encode(elf.pseudoC)
        });
      }
    }

    if (State.securityAudit) {
      outFiles.push({
        name: 'security_audit_report.json',
        data: encoder.encode(JSON.stringify({
          apkFileName: State.apk.fileName,
          sha256: State.apk.sha256,
          manifest: State.manifestInfo,
          securityAudit: State.securityAudit,
          mitreAttack: State.mitreAttack,
          taintFlows: State.taintFlows,
          decryptedStrings: State.deobfData ? State.deobfData.decryptedStrings : [],
          nativeLibraries: State.elfFiles.map(e => ({
            fileName: e.fileName,
            architecture: e.architecture,
            hardening: e.hardening,
            jniMethods: e.jniMethods,
            registerNatives: e.registerNatives
          }))
        }, null, 2))
      });
    }
    if (State.sarif) {
      outFiles.push({
        name: 'sarif_report.sarif.json',
        data: encoder.encode(JSON.stringify(State.sarif, null, 2))
      });
    }
    if (State.sbom) {
      outFiles.push({
        name: 'sbom_cyclonedx.json',
        data: encoder.encode(JSON.stringify(State.sbom, null, 2))
      });
    }

    const zipBytes = global.ArgonZip.buildZipArchive(outFiles);
    const blob = new Blob([zipBytes], { type: 'application/zip' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const baseName = State.apk.fileName.replace(/\.apk$/i, '');
    a.download = `${baseName}_decompiled_source.zip`;
    a.click();
    URL.revokeObjectURL(url);
    setStatus(`Exported ${outFiles.length} decompiled files to ${baseName}_decompiled_source.zip (${formatBytes(zipBytes.length)})`);
  }

  function downloadSampleApkFile() {
    const apkBytes = global.ArgonSampleBuilder.generateSampleApkBuffer();
    const blob = new Blob([apkBytes], { type: 'application/vnd.android.package-archive' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'ArgonVault_v2.4.1_sample.apk';
    a.click();
    URL.revokeObjectURL(url);
    setStatus('Downloaded ArgonVault_v2.4.1_sample.apk');
  }

  // ==================== EVENT LISTENERS & INITIALIZATION ====================
  function jumpToClass(className) {
    if (!className) return;
    let target = State.classByName.get(className);
    if (!target) {
      const simple = className.split('.').pop();
      target = State.classByName.get(simple);
    }
    if (target) {
      State.selectedClass = target;
      State.selectedMethodIdx = 0;
      State.codeRenderLimit = 800;
      State.activeMode = 'code';
      closeGlobalSearchModal();
      renderAll();
    } else {
      setStatus(`External framework/SDK class reference: ${className}`);
    }
  }

  function applyTheme(theme) {
    const next = theme === 'light' ? 'light' : 'dark';
    State.theme = next;
    if (typeof document !== 'undefined') {
      document.documentElement.dataset.theme = next;
      const btn = document.getElementById('btn-theme-toggle');
      if (btn) btn.textContent = next === 'light' ? '🌙 Dark' : '☀️ Light';
    }
    try {
      if (typeof localStorage !== 'undefined') localStorage.setItem('argondex_theme', next);
    } catch (_) {}
  }

  function initApp() {
    let savedTheme = 'dark';
    try {
      if (typeof localStorage !== 'undefined') savedTheme = localStorage.getItem('argondex_theme') || 'dark';
    } catch (_) {}
    applyTheme(savedTheme);

    document.getElementById('btn-theme-toggle')?.addEventListener('click', () => {
      applyTheme(State.theme === 'light' ? 'dark' : 'light');
    });
    // Top bar buttons
    const fileInput = document.getElementById('apk-file-input');
    document.getElementById('btn-open-apk')?.addEventListener('click', () => fileInput?.click());
    fileInput?.addEventListener('change', async (e) => {
      const file = e.target.files?.[0];
      if (!file) return;
      const ab = await file.arrayBuffer();
      await loadAndAnalyzeInputFile(ab, file.name);
    });

    document.getElementById('btn-load-sample')?.addEventListener('click', async () => {
      const sampleBytes = global.ArgonSampleBuilder.generateSampleApkBuffer();
      await loadAndAnalyzeApkBuffer(sampleBytes.buffer, 'ArgonVault_v2.4.1.apk');
    });

    document.getElementById('btn-download-sample')?.addEventListener('click', downloadSampleApkFile);
    document.getElementById('btn-export-zip')?.addEventListener('click', exportDecompiledProjectZip);
    document.getElementById('btn-global-search')?.addEventListener('click', () => openGlobalSearchModal(''));

    // Sidebar tabs & filter
    document.querySelectorAll('.sidebar-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        State.sidebarTab = tab.dataset.tab;
        renderLeftSidebar();
      });
    });

    document.getElementById('sidebar-filter-input')?.addEventListener('input', (e) => {
      State.sidebarFilter = e.target.value;
      renderLeftSidebar();
    });

    // Mode tabs
    document.querySelectorAll('.mode-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        State.activeMode = tab.dataset.mode;
        renderAll();
      });
    });

    // Global delegated clicks
    document.body.addEventListener('click', (e) => {
      const submodeBtn = e.target.closest('[data-submode]');
      if (submodeBtn) {
        State.codeSubMode = submodeBtn.dataset.submode;
        renderCenterWorkbench();
        return;
      }

      const cfgModeBtn = e.target.closest('[data-cfgmode]');
      if (cfgModeBtn) {
        State.cfgSubMode = cfgModeBtn.dataset.cfgmode;
        renderCenterWorkbench();
        return;
      }

      if (e.target.closest('#btn-toggle-deobf')) {
        State.smartDeobfEnabled = !State.smartDeobfEnabled;
        setStatus(`Smart Auto-Deobfuscator ${State.smartDeobfEnabled ? 'ENABLED' : 'DISABLED'}`);
        renderCenterWorkbench();
        return;
      }

      if (e.target.closest('#btn-copy-java')) {
        if (State.selectedClass) {
          const dec = global.ArgonDex.decompileClassToJava(State.selectedClass, State.arsc);
          navigator.clipboard?.writeText(dec.java);
          setStatus(`Copied ${State.selectedClass.fullName}.java to clipboard.`);
        }
        return;
      }

      const patchBtn = e.target.closest('[data-patch-op]');
      if (patchBtn) {
        try {
          applyLiveBytecodePatch(
            patchBtn.dataset.dexName,
            parseInt(patchBtn.dataset.fileOff, 10),
            patchBtn.dataset.patchOp,
            parseInt(patchBtn.dataset.unitLen, 10) || 1
          );
        } catch (err) {
          setStatus(`Bytecode patch failed: ${err.message}`);
        }
        return;
      }

      const xrefEl = e.target.closest('[data-xref-class]');
      if (xrefEl) {
        jumpToClass(xrefEl.dataset.xrefClass);
        return;
      }

      const actionEl = e.target.closest('[data-action]');
      if (actionEl) {
        const act = actionEl.dataset.action;
        if (act === 'select-class') {
          jumpToClass(actionEl.dataset.classname);
        } else if (act === 'load-more-classes') {
          State.sidebarRenderLimit = (State.sidebarRenderLimit || 300) + 500;
          renderLeftSidebar();
        } else if (act === 'expand-code-lines') {
          State.codeRenderLimit = Number.MAX_SAFE_INTEGER;
          renderCenterWorkbench();
        } else if (act === 'select-file') {
          const fname = actionEl.dataset.filename;
          if (fname.endsWith('.xml')) {
            State.selectedXmlEntry = fname;
            State.activeMode = 'manifest';
          } else if (fname === 'resources.arsc') {
            State.activeMode = 'arsc';
          } else if (fname.endsWith('.so')) {
            const idx = State.elfFiles.findIndex(f => f.fileName === fname);
            if (idx !== -1) State.selectedElfIdx = idx;
            State.activeMode = 'elf';
          } else if (fname.endsWith('.dex')) {
            State.activeMode = 'code';
          } else {
            State.selectedHexEntry = fname;
            State.activeMode = 'hex';
          }
          renderAll();
        } else if (act === 'search-string') {
          openGlobalSearchModal(actionEl.dataset.str);
        } else if (act === 'select-method') {
          State.selectedMethodIdx = parseInt(actionEl.dataset.methodIdx, 10) || 0;
          if (State.activeMode === 'cfg') {
            State.cfgSubMode = 'method';
            renderCenterWorkbench();
          } else {
            // Scroll to method name in code view or switch to CFG on double-click
            const m = State.selectedClass?.allMethods[State.selectedMethodIdx];
            if (m) setStatus(`Selected method: ${State.selectedClass.simpleName}.${m.name}() — Click 'Control Flow & Call Graph' tab to view its Basic-Block CFG.`);
          }
          renderRightInspector();
        }
      }
    });

    // Global Search Modal events
    const searchModal = document.getElementById('search-modal');
    const searchInput = document.getElementById('global-search-input');
    searchModal?.addEventListener('click', (e) => {
      if (e.target === searchModal) closeGlobalSearchModal();
    });
    let searchDebounceTimer = null;
    searchInput?.addEventListener('input', (e) => {
      const val = e.target.value;
      if (searchDebounceTimer) clearTimeout(searchDebounceTimer);
      searchDebounceTimer = setTimeout(() => renderGlobalSearchResults(val), 90);
    });

    // Keyboard shortcuts (Ctrl+K / Escape)
    window.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        openGlobalSearchModal('');
      } else if (e.key === 'Escape') {
        closeGlobalSearchModal();
      }
    });

    // Drag and Drop anywhere on window
    const dropOverlay = document.getElementById('dropzone-overlay');
    window.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropOverlay?.classList.add('visible');
    });
    dropOverlay?.addEventListener('dragleave', (e) => {
      if (e.target === dropOverlay) dropOverlay.classList.remove('visible');
    });
    window.addEventListener('drop', async (e) => {
      e.preventDefault();
      dropOverlay?.classList.remove('visible');
      const file = e.dataTransfer?.files?.[0];
      if (!file) return;
      const ab = await file.arrayBuffer();
      await loadAndAnalyzeInputFile(ab, file.name);
    });

    // Auto-load the built-in binary Showcase APK on startup so the studio is immediately alive!
    const sampleBytes = global.ArgonSampleBuilder.generateSampleApkBuffer();
    loadAndAnalyzeApkBuffer(sampleBytes.buffer, 'ArgonVault_v2.4.1.apk');
  }

  global.ArgonApp = {
    State,
    escapeHtml,
    highlightJavaLine,
    highlightSmaliLine,
    highlightXmlLine,
    renderCodeLinesHtml,
    applyTheme,
    createInlineAnalysisWorker,
    applyLiveBytecodePatch
  };

  if (typeof window !== 'undefined' && typeof window.addEventListener === 'function') {
    window.addEventListener('DOMContentLoaded', initApp);
  }
})(typeof window !== 'undefined' ? window : globalThis);
