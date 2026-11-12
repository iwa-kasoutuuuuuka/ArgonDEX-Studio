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
    allCrossRefs: [],

    // UI state
    sidebarTab: 'classes', // 'classes' | 'files' | 'strings'
    sidebarFilter: '',
    activeMode: 'code',    // 'overview' | 'code' | 'cfg' | 'manifest' | 'arsc' | 'elf' | 'security' | 'hex'
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

  function renderCodeLinesHtml(text, lang = 'java') {
    const lines = text.split('\n');
    const html = [];
    for (let i = 0; i < lines.length; i++) {
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

  async function loadAndAnalyzeApkBuffer(arrayBuffer, fileName) {
    const t0 = performance.now();
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

    // 3. Parse all classes*.dex files
    const dexFiles = [];
    const allClasses = [];
    const classByName = new Map();
    const allCrossRefs = [];

    const dexEntries = apk.entries
      .filter(e => /^classes\d*\.dex$/i.test(e.name) || e.name.endsWith('.dex'))
      .sort((a, b) => a.name.localeCompare(b.name));

    for (const dexEntry of dexEntries) {
      try {
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

    // Pre-decompile classes to collect cross-references
    for (const cls of allClasses) {
      const dec = global.ArgonDex.decompileClassToJava(cls, arsc);
      for (const xref of dec.crossRefs) {
        allCrossRefs.push(xref);
      }
    }

    // 4. Parse all native ELF (.so) libraries
    const elfFiles = [];
    const jniByClassMethod = new Map();
    const soEntries = apk.entries.filter(e => e.name.endsWith('.so'));
    for (const soEntry of soEntries) {
      try {
        const soBytes = await soEntry.extract();
        const parsedElf = global.ArgonElfSecurity.parseElfBinary(soBytes, soEntry.name);
        parsedElf.disassembly = global.ArgonAdvanced
          ? global.ArgonAdvanced.disassembleElfTextSection(soBytes, parsedElf)
          : [];
        elfFiles.push(parsedElf);
        for (const jni of parsedElf.jniMethods) {
          if (jni.type === 'method') {
            jniByClassMethod.set(`${jni.className}#${jni.methodName}`, jni);
          }
        }
      } catch (e) {
        console.warn(`ELF parse warning (${soEntry.name}):`, e);
      }
    }

    // 5. Run Static Security Audit + Taint Analysis + Deobfuscation + Crypto S-Box Scan
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
    const cryptoConstants = global.ArgonAdvanced
      ? global.ArgonAdvanced.scanCryptographicConstants(apk.entries, apk.rawBytes)
      : [];

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
        for (const [pkg, clsList] of byPkg.entries()) {
          html.push(`
            <div class="tree-group-header">
              <span>📦 ${escapeHtml(pkg)}</span>
              <span>${clsList.length}</span>
            </div>
          `);
          for (const cls of clsList) {
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
            <td colspan="5" style="font-weight:700;color:var(--accent-cyan)">
              Method: ${escapeHtml(sig)}
              ${m.code ? `(Registers: ${m.code.registersSize}, Ins: ${m.code.insSize}, Outs: ${m.code.outsSize}, Code Units: ${m.code.insnsSize})` : '(NATIVE / ABSTRACT)'}
              ${jniLink ? `<span class="badge badge-ok" style="margin-left:10px">JNI Linked → ${escapeHtml(jniLink.symbol)} @ ${jniLink.address} (${escapeHtml(jniLink.library)})</span>` : ''}
            </td>
          </tr>
        `);
        if (m.code) {
          for (const ins of m.code.instructions) {
            rows.push(`
              <tr>
                <td style="color:var(--accent-indigo)">+0x${ins.pc.toString(16).padStart(4, '0')}</td>
                <td style="color:var(--text-muted)">${escapeHtml(ins.rawHex)}</td>
                <td><span class="badge badge-low">${escapeHtml(ins.fmt)}</span></td>
                <td style="color:var(--accent-amber);font-weight:700">${escapeHtml(ins.name)}</td>
                <td>${ highlightSmaliLine(ins.smali) }</td>
              </tr>
            `);
          }
        }
      }

      body.innerHTML = `
        <div class="dashboard-pad">
          <div class="section-card">
            <div class="section-card-header">
              <span>Dalvik 16-bit Bytecode Instruction Stream — ${escapeHtml(cls.fullName)}</span>
              <span>DEX Version ${escapeHtml(State.dexFiles[0]?.version || '038')}</span>
            </div>
            <table class="data-table">
              <thead>
                <tr>
                  <th style="width:90px">Code Offset</th>
                  <th style="width:160px">Raw 16-Bit Hex</th>
                  <th style="width:80px">Format</th>
                  <th style="width:160px">Opcode Mnemonic</th>
                  <th>Disassembled Smali & Resolved Pool References</th>
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
        ctx.fillText(
          `Block ${n.block.id}  [@0x${n.block.startPc.toString(16).padStart(4, '0')} .. @0x${n.block.endPc.toString(16).padStart(4, '0')}]`,
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

    body.innerHTML = `
      <div class="dashboard-pad">
        <div style="display:flex;align-items:center;justify-content:space-between">
          <div style="display:flex;align-items:center;gap:12px">
            <span style="font-weight:700;font-size:14px">Select Native Library (.so):</span>
            <select id="elf-file-select" style="background:var(--bg-panel);color:#fff;border:1px solid var(--accent-cyan);padding:6px 12px;border-radius:6px;font-family:var(--font-mono)">
              ${State.elfFiles.map((f, i) => `<option value="${i}" ${i === State.selectedElfIdx ? 'selected' : ''}>${escapeHtml(f.fileName)} (${escapeHtml(f.architecture)}, ${formatBytes(f.fileSize)})</option>`).join('')}
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

        <div class="section-card">
          <div class="section-card-header">
            <span>⚙️ Native ARM64 (AArch64) Machine Code Disassembler — .text Section (${(elf.disassembly || []).length} Instructions)</span>
            <span>Direct 32-bit Instruction Word Decoding</span>
          </div>
          <table class="data-table">
            <thead>
              <tr>
                <th style="width:130px">Virtual Addr</th>
                <th style="width:100px">File Off</th>
                <th style="width:130px">32-Bit Opcode</th>
                <th style="width:110px">Mnemonic</th>
                <th>Operands</th>
                <th>Exported Symbol / Comment</th>
              </tr>
            </thead>
            <tbody>
              ${(elf.disassembly || []).map(ins => `
                <tr ${ins.label ? 'style="background:rgba(0, 229, 255, 0.08)"' : ''}>
                  <td style="color:var(--accent-indigo);font-weight:600">${ins.vaddr}</td>
                  <td style="color:var(--text-muted)">${ins.fileOffset}</td>
                  <td style="color:var(--text-secondary)">${ins.hexBytes}</td>
                  <td style="color:var(--accent-amber);font-weight:700">${escapeHtml(ins.mnemonic)}</td>
                  <td style="color:var(--accent-emerald);font-weight:600">${escapeHtml(ins.operands)}</td>
                  <td>
                    ${ins.label ? `<span class="badge badge-critical" style="margin-right:8px">${escapeHtml(ins.label)}:</span>` : ''}
                    <span style="color:var(--text-muted)">${escapeHtml(ins.comment)}</span>
                  </td>
                </tr>
              `).join('')}
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
      </div>
    `;
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

    // 1. Search classes & methods
    for (const cls of State.allClasses) {
      if (!q || cls.fullName.toLowerCase().includes(q)) {
        hits.push({
          type: 'CLASS',
          badge: 'badge-low',
          label: cls.fullName,
          sub: `${cls.dexName} (${cls.allMethods.length} methods)`,
          className: cls.fullName
        });
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

    // 4. Security Audit & ELF Native Report
    if (State.securityAudit) {
      outFiles.push({
        name: 'security_audit_report.json',
        data: encoder.encode(JSON.stringify({
          apkFileName: State.apk.fileName,
          sha256: State.apk.sha256,
          manifest: State.manifestInfo,
          securityAudit: State.securityAudit,
          nativeLibraries: State.elfFiles
        }, null, 2))
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
      State.activeMode = 'code';
      closeGlobalSearchModal();
      renderAll();
    } else {
      setStatus(`External framework/SDK class reference: ${className}`);
    }
  }

  function initApp() {
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
    searchInput?.addEventListener('input', (e) => {
      renderGlobalSearchResults(e.target.value);
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
    highlightXmlLine
  };

  if (typeof window !== 'undefined' && typeof window.addEventListener === 'function') {
    window.addEventListener('DOMContentLoaded', initApp);
  }
})(typeof window !== 'undefined' ? window : globalThis);
