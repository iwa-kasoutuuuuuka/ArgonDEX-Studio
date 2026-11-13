/**
 * ArgonDEX Studio — Automated Debugging, Functional & Self-Vulnerability Verification Suite
 * Run via: node tests/test_suite.js
 */

'use strict';

const assert = require('assert');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
require(path.join(ROOT, 'js/zip_engine.js'));
require(path.join(ROOT, 'js/axml_arsc_parser.js'));
require(path.join(ROOT, 'js/dex_decompiler.js'));
require(path.join(ROOT, 'js/elf_security_engine.js'));
require(path.join(ROOT, 'js/advanced_analysis_engine.js'));
require(path.join(ROOT, 'js/sample_apk_builder.js'));
require(path.join(ROOT, 'js/app.js'));

let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(`  [PASS] ${name}`);
    passed++;
  } catch (err) {
    console.error(`  [FAIL] ${name}`);
    console.error(`         ${err && err.stack ? err.stack : err}`);
    failed++;
  }
}

(async () => {
  console.log('====================================================================');
  console.log(' ArgonDEX Studio — Automated Debug & Vulnerability Verification');
  console.log('====================================================================');

  let sampleBuffer = null;
  let apk = null;
  let arsc = null;
  let manifestAxml = null;
  let manifestInfo = null;
  let dex = null;
  let elf = null;

  await test('1. Synthesize multi-component binary APK (ArgonVault_v2.4.1_sample.apk)', async () => {
    sampleBuffer = globalThis.ArgonSampleBuilder.generateSampleApkBuffer();
    assert(sampleBuffer instanceof Uint8Array, 'Expected Uint8Array');
    assert(sampleBuffer.length > 10000, `Expected APK > 10KB, got ${sampleBuffer.length}`);
  });

  await test('2. Parse ZIP archive, APK Signing Block v2/v3 & X.509 DER Certificate', async () => {
    const ab = sampleBuffer.buffer.slice(sampleBuffer.byteOffset, sampleBuffer.byteOffset + sampleBuffer.byteLength);
    apk = await globalThis.ArgonZip.parseApkArchive(ab, 'ArgonVault_v2.4.1_sample.apk');
    assert.strictEqual(apk.entries.length, 7, 'Expected 7 entries in sample APK');
    assert(apk.signingBlock && apk.signingBlock.present, 'Expected APK Signing Block v2/v3 to be present');
    assert(apk.signingBlock.v2Signed && apk.signingBlock.v3Signed, 'Expected both v2 and v3 scheme IDs');
    assert(apk.certificates && apk.certificates.length >= 1, 'Expected X.509 certificate in META-INF/CERT.RSA');
  });

  await test('3. Parse resources.arsc & resolve 0x7f resource IDs', async () => {
    const arscBytes = await apk.entryMap.get('resources.arsc').extract();
    arsc = globalThis.ArgonAxml.parseResourcesArsc(arscBytes);
    assert(arsc && arsc.entries.length >= 8, `Expected >= 8 resources, got ${arsc ? arsc.entries.length : 0}`);
    const resolved = arsc.byId.get(0x7f010000);
    assert(resolved && resolved.name === 'app_name', 'Expected 0x7f010000 to resolve to @string/app_name');
  });

  await test('4. Parse Binary AndroidManifest.xml (AXML) & extract components/flags', async () => {
    const mfBytes = await apk.entryMap.get('AndroidManifest.xml').extract();
    manifestAxml = globalThis.ArgonAxml.parseAxml(mfBytes, arsc);
    manifestInfo = globalThis.ArgonAxml.analyzeManifest(manifestAxml);
    assert.strictEqual(manifestInfo.packageName, 'com.argon.vault');
    assert.strictEqual(manifestInfo.debuggable, true);
    assert.strictEqual(manifestInfo.allowBackup, true);
    assert.strictEqual(manifestInfo.usesCleartextTraffic, true);
    assert(manifestInfo.permissions.some(p => p.name === 'android.permission.INTERNET'));
  });

  await test('5. Parse classes.dex, disassemble 6 classes & verify sorted methodId deltas', async () => {
    const dexBytes = await apk.entryMap.get('classes.dex').extract();
    dex = globalThis.ArgonDex.parseDexFile(dexBytes, 'classes.dex', arsc);
    assert.strictEqual(dex.classes.length, 6, 'Expected 6 classes in classes.dex');
    const mainAct = dex.classes.find(c => c.fullName === 'com.argon.vault.MainActivity');
    assert(mainAct, 'Expected MainActivity');
    const methodNames = mainAct.allMethods.map(m => m.name);
    assert(methodNames.includes('onCreate'), 'Expected onCreate method');
    assert(methodNames.includes('initWebViewPortal'), 'Expected initWebViewPortal (verifies sorted methodId delta fix)');
    assert(methodNames.includes('verifyMasterPin'), 'Expected verifyMasterPin (verifies sorted methodId delta fix)');
  });

  await test('6. Decompile Dalvik bytecode to structured Java AST & compute CFG Dominator / McCabe metrics', async () => {
    const mainAct = dex.classes.find(c => c.fullName === 'com.argon.vault.MainActivity');
    const dec = globalThis.ArgonDex.decompileClassToJava(mainAct, arsc);
    assert(dec.java.includes('public class MainActivity extends Activity'), 'Expected class header');
    assert(dec.java.includes('R.layout.activity_main'), 'Expected R.layout.activity_main resource synthesis');
    for (const m of mainAct.allMethods) {
      if (m.cfg && m.cfg.blocks.length > 0) {
        const metrics = globalThis.ArgonAdvanced.computeCfgMetrics(m.cfg);
        assert(metrics.cyclomaticComplexity >= 1, 'Expected McCabe complexity >= 1');
        assert(metrics.dominators instanceof Map, 'Expected Immediate Dominator map');
      }
    }
  });

  await test('7. Parse 64-bit ELF (libnative-vault.so), disassemble ARM64 .text & scan Crypto S-Boxes', async () => {
    const soBytes = await apk.entryMap.get('lib/arm64-v8a/libnative-vault.so').extract();
    elf = globalThis.ArgonElfSecurity.parseElfBinary(soBytes, 'lib/arm64-v8a/libnative-vault.so');
    assert(elf && elf.architecture.includes('ARM64'), 'Expected valid 64-bit ARM64 ELF');
    const disasm = globalThis.ArgonAdvanced.disassembleElfTextSection(soBytes, elf);
    assert(disasm.length >= 16, `Expected >= 16 disassembled ARM64 instructions, got ${disasm.length}`);
    assert.strictEqual(disasm[0].mnemonic, 'stp', 'Expected stp prologue instruction');
    assert(disasm.some(i => i.mnemonic === 'ret'), 'Expected ret epilogue instruction');

    const cryptoHits = globalThis.ArgonAdvanced.scanCryptographicConstants(apk.entries, apk.rawBytes);
    assert(cryptoHits.some(c => c.description.includes('AES Rijndael')), 'Expected AES Rijndael S-Box signature');
    assert(cryptoHits.some(c => c.algorithm.includes('ChaCha20')), 'Expected ChaCha20 signature');
  });

  await test('8. Run Inter-Procedural SSA Source-to-Sink Taint Analysis', async () => {
    const flows = globalThis.ArgonAdvanced.runTaintAnalysis([dex]);
    assert(flows.length >= 4, `Expected >= 4 taint flows, got ${flows.length}`);
    assert(flows.some(f => f.vulnerability.includes('CWE-89')), 'Expected SQL Injection taint flow (CWE-89)');
    assert(flows.some(f => f.vulnerability.includes('CWE-20')), 'Expected JNI Hardware Key Derivation taint flow (CWE-20)');
    assert(flows.some(f => f.sink.includes('WebView.loadUrl')), 'Expected WebView.loadUrl sink taint flow');
  });

  await test('9. Run Smart ProGuard/R8 Auto-Deobfuscation without constructor collision', async () => {
    const deobf = globalThis.ArgonAdvanced.analyzeObfuscationAndGenerateMappings(apk, [dex], [elf]);
    assert(deobf.classRenames.has('com.argon.vault.obf.a'), 'Expected obfuscated class com.argon.vault.obf.a to be detected');
    const obfCls = dex.classes.find(c => c.fullName === 'com.argon.vault.obf.a');
    const dec = globalThis.ArgonDex.decompileClassToJava(obfCls, arsc);
    const rewritten = globalThis.ArgonAdvanced.applySmartDeobfuscationToJava(dec.java, obfCls, deobf);
    assert(rewritten.includes('public final class CryptoTokenHelper'), 'Expected class renamed to CryptoTokenHelper');
    assert(rewritten.includes('public CryptoTokenHelper()'), 'Expected constructor renamed to CryptoTokenHelper() without method name collision');
    assert(rewritten.includes('public byte[] transformCrypto_a('), 'Expected method a() renamed to transformCrypto_a()');
  });

  await test('10. [Security] DOM XSS Prevention in escapeHtml & Syntax Highlighters', async () => {
    const payload = '"><img src=x onerror="alert(\'xss\')">';
    const escaped = globalThis.ArgonApp.escapeHtml(payload);
    assert(!escaped.includes('<'), 'Unescaped < found');
    assert(!escaped.includes('>'), 'Unescaped > found');
    assert(!escaped.includes('"'), 'Unescaped " found');
    assert(!escaped.includes("'"), "Unescaped ' found");
    assert.strictEqual(escaped, '&quot;&gt;&lt;img src=x onerror=&quot;alert(&#39;xss&#39;)&quot;&gt;');

    const highlighted = globalThis.ArgonApp.highlightJavaLine(`String s = "${payload}";`);
    assert(!highlighted.includes('<img'), 'Unescaped <img tag leaked through Java syntax highlighter');
  });

  await test('11. [Security] Zip-Slip & Path Traversal Prevention in sanitizeClassPath', async () => {
    const maliciousClassName = '../../../../etc/passwd';
    const sanitized = globalThis.ArgonDex.sanitizeClassPath(maliciousClassName);
    assert(!sanitized.includes('..'), `Path traversal '..' leaked in: ${sanitized}`);
    assert(!sanitized.startsWith('/'), `Leading slash leaked in: ${sanitized}`);
  });

  await test('12. [Security] Malformed AXML / ARSC Zero-Size Chunk Infinite Loop Guard', async () => {
    // Craft an AXML header (0x00080003) followed by a malformed chunk with size = 0
    const badAxml = new Uint8Array(16);
    const dv = new DataView(badAxml.buffer);
    dv.setUint32(0, 0x00080003, true);
    dv.setUint32(4, 16, true);
    dv.setUint16(8, 0x0001, true); // RES_STRING_POOL_TYPE
    dv.setUint16(10, 8, true);
    dv.setUint32(12, 0, true);     // Malformed chunkSize = 0 (would cause infinite loop if unguarded)
    const resAxml = globalThis.ArgonAxml.parseAxml(badAxml, null);
    assert(resAxml && typeof resAxml.xml === 'string', 'Expected parseAxml to return gracefully on malformed chunkSize=0');

    // Craft an ARSC header (0x000C0002) followed by a malformed chunk with size = 2
    const badArsc = new Uint8Array(20);
    const dv2 = new DataView(badArsc.buffer);
    dv2.setUint16(0, 0x0002, true);
    dv2.setUint16(2, 12, true);
    dv2.setUint32(4, 20, true);
    dv2.setUint32(8, 1, true);
    dv2.setUint16(12, 0x0200, true); // RES_TABLE_PACKAGE_TYPE
    dv2.setUint16(14, 8, true);
    dv2.setUint32(16, 2, true);      // Malformed chunkSize = 2 (< 8)
    const resArsc = globalThis.ArgonAxml.parseResourcesArsc(badArsc);
    assert(resArsc && Array.isArray(resArsc.entries), 'Expected parseResourcesArsc to return gracefully on malformed chunkSize=2');
  });

  await test('13. [Security] Deobfuscator RegExp Metacharacter Injection Guard', async () => {
    const fakeCls = { fullName: 'com.test.Class$Inner[0]' };
    const fakeDeobf = {
      classRenames: new Map([['com.test.Class$Inner[0]', { oldShort: 'Class$Inner[0]', newShort: 'SafeInner', newFull: 'com.test.SafeInner' }]]),
      fieldRenames: new Map([['com.test.Class$Inner[0].$f(', 'safeField']]),
      methodRenames: new Map([['com.test.Class$Inner[0].*m+', 'safeMethod']])
    };
    const out = globalThis.ArgonAdvanced.applySmartDeobfuscationToJava(
      'public class Class$Inner[0] { private int $f(; public void *m+() {} }',
      fakeCls,
      fakeDeobf
    );
    assert(typeof out === 'string', 'Expected RegExp escaping to prevent SyntaxError');
  });

  await test('14. [Phase 1] Synchronized Block, fill-array-data Literal & Dalvik XOR String Decryptor', async () => {
    const obfCls = dex.classes.find(c => c.fullName === 'com.argon.vault.obf.a');
    const dec = globalThis.ArgonDex.decompileClassToJava(obfCls, arsc);
    assert(dec.java.includes('synchronized (this) {'), 'Expected monitor-enter/exit to reconstruct synchronized (this) block');
    assert(dec.java.includes('new byte[]{ 0x1b, 0x08, 0x1d, 0x15'), 'Expected fill-array-data payload to reconstruct byte[] initializer');

    const decrypted = globalThis.ArgonAdvanced.decryptObfuscatedStrings([dex]);
    assert(decrypted.length >= 1, 'Expected at least 1 statically decrypted XOR string');
    assert.strictEqual(decrypted[0].decrypted, 'ARGON_KEY!', 'Expected XOR-encrypted payload to decrypt to ARGON_KEY!');
  });

  await test('15. [Phase 2] ARM64 BL Target Symbol Resolution & ARM64-to-Pseudo-C Native Decompiler', async () => {
    const soBytes = await apk.entryMap.get('lib/arm64-v8a/libnative-vault.so').extract();
    const disasm = globalThis.ArgonAdvanced.disassembleElfTextSection(soBytes, elf);
    const blIns = disasm.find(i => i.mnemonic === 'bl');
    assert(blIns && blIns.operands.includes('<sub_'), 'Expected BL instruction to resolve target subroutine symbol');

    const pseudoC = globalThis.ArgonAdvanced.decompileArm64ToPseudoC(soBytes, elf);
    assert(pseudoC.includes('JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm'), 'Expected JNI_OnLoad signature in Pseudo-C');
    assert(pseudoC.includes('Java_com_argon_vault_NativeBridge_deriveHardwareKey(JNIEnv* env'), 'Expected JNI method in Pseudo-C');
    assert(pseudoC.includes('0x10006 /* JNI_VERSION_1_6 */'), 'Expected MOVZ+MOVK folding for JNI_VERSION_1_6');
  });

  await test('16. [Phase 2] Automated Frida Hook Script Generator (Java + Native Interceptor)', async () => {
    const flows = globalThis.ArgonAdvanced.runTaintAnalysis([dex]);
    const deobf = globalThis.ArgonAdvanced.analyzeObfuscationAndGenerateMappings(apk, [dex], [elf]);
    const fridaJs = globalThis.ArgonAdvanced.generateFridaHookScript(apk, manifestInfo, [dex], [elf], flows, deobf);
    assert(fridaJs.includes('Java.perform(function ()'), 'Expected Java.perform block');
    assert(fridaJs.includes('Interceptor.attach('), 'Expected native Interceptor.attach block');
    assert(fridaJs.includes('Java_com_argon_vault_NativeBridge_deriveHardwareKey'), 'Expected JNI hook target');
  });

  await test('17. [Phase 3] Multi-Hop Worklist SSA Taint Engine & Decompilation Memoization Cache', async () => {
    const mainAct = dex.classes.find(c => c.fullName === 'com.argon.vault.MainActivity');
    const dec1 = globalThis.ArgonDex.decompileClassToJava(mainAct, arsc);
    const dec2 = globalThis.ArgonDex.decompileClassToJava(mainAct, arsc);
    assert.strictEqual(dec1, dec2, 'Expected decompileClassToJava to return memoized _decompiledCache reference');
  });

  await test('18. [Debug Verification] Structured while(cond) Folding & SQLi Parameter Taint Attribution', async () => {
    const cryptoCls = dex.classes.find(c => c.fullName === 'com.argon.vault.crypto.CryptoEngine');
    const decCrypto = globalThis.ArgonDex.decompileClassToJava(cryptoCls, arsc);
    assert(decCrypto.java.includes('while (v0 < arg1) {'), 'Expected loop header branch to fold into while (v0 < arg1)');
    assert(!decCrypto.java.includes('while (true)'), 'Expected no raw while (true) in computeRollingHash');

    const flows = globalThis.ArgonAdvanced.runTaintAnalysis([dex]);
    const sqliFlow = flows.find(f => f.vulnerability.includes('CWE-89'));
    assert(sqliFlow, 'Expected CWE-89 SQLi flow');
    assert(sqliFlow.source.includes('Method Parameter arg1'), `Expected SQLi source to be Method Parameter arg1, got: ${sqliFlow.source}`);
  });

  await test('19. Round-Trip DEX Bytecode Patcher & Pure-JS SHA-1 / Adler-32 Checksum Recalculator', async () => {
    const dexBytes = await apk.entryMap.get('classes.dex').extract();
    // Verify built sample DEX already has valid non-zero SHA-1 signature at bytes 12..31
    const origSha1 = globalThis.ArgonZip.sha1Hex(dexBytes, 32, dexBytes.length);
    const hdrSha1 = Array.from(dexBytes.subarray(12, 32)).map(b => b.toString(16).padStart(2, '0')).join('');
    assert.strictEqual(origSha1, hdrSha1, 'Expected generated DEX SHA-1 header (0x0C..0x1F) to match content');

    let targetInsn = null;
    for (const cls of dex.classes) {
      for (const m of cls.allMethods) {
        if (!m.code) continue;
        targetInsn = m.code.instructions.find(i => i.opcode >= 0x32 && i.opcode <= 0x3d);
        if (targetInsn) break;
      }
      if (targetInsn) break;
    }
    assert(targetInsn && Number.isInteger(targetInsn.fileByteOffset), 'Expected conditional branch with fileByteOffset');

    const patched = globalThis.ArgonDex.patchDexInstruction(dexBytes, targetInsn.fileByteOffset, {
      type: 'invert-branch',
      unitLen: targetInsn.unitLen
    });
    assert.notStrictEqual(patched.oldWordsHex, patched.newWordsHex, 'Expected branch opcode bytes to change after invert-branch');

    const expectedSha1 = globalThis.ArgonZip.sha1Hex(patched.bytes, 32, patched.bytes.length);
    assert.strictEqual(patched.signatureHex, expectedSha1, 'Expected recalculated SHA-1 digest');

    const reparsedDex = globalThis.ArgonDex.parseDexFile(patched.bytes, 'classes.dex');
    assert.strictEqual(reparsedDex.checksum, patched.checksumHex, 'Expected reparsed DEX Adler-32 checksum to match');
    assert.strictEqual(reparsedDex.signatureHex, patched.signatureHex, 'Expected reparsed DEX SHA-1 signature to match');

    // Round-trip repack into APK ZIP and re-parse
    const rebuiltApk = globalThis.ArgonZip.buildZipArchive([{ name: 'classes.dex', data: patched.bytes }]);
    const reparsedApk = await globalThis.ArgonZip.parseApkArchive(rebuiltApk.buffer, 'patched.apk');
    assert(reparsedApk.entryMap.has('classes.dex'), 'Expected rebuilt APK to contain classes.dex');
  });

  await test('20. APK Version BinDiff & Line-Level Unified Java AST Diff Engine', async () => {
    const manifestEntry = apk.entryMap.get('AndroidManifest.xml');
    const axml = globalThis.ArgonAxml.parseAxml(await manifestEntry.extract(), arsc);
    const mfInfo = globalThis.ArgonAxml.analyzeManifest(axml);
    const soBytes = await apk.entryMap.get('lib/arm64-v8a/libnative-vault.so').extract();
    const parsedElf = globalThis.ArgonElfSecurity.parseElfBinary(soBytes, 'lib/arm64-v8a/libnative-vault.so');

    const currentBundle = { apk, manifestInfo: mfInfo, dexFiles: [dex], elfFiles: [parsedElf], arsc };
    const baselineBundle = globalThis.ArgonAdvanced.synthesizeBaselineBundle(currentBundle);
    const diff = globalThis.ArgonAdvanced.computeApkDiff(baselineBundle, currentBundle);

    assert(diff.permissions.added.length >= 1, 'Expected permissions delta between baseline and target');
    assert(diff.classes.modified.length >= 1, 'Expected modified Java class diff');
    assert(diff.classes.modified[0].unifiedDiff.includes('--- '), 'Expected unified diff header');
    assert(diff.nativeSymbols.added.length >= 1, 'Expected native symbol export diff');
  });

  await test('21. MITRE ATT&CK Mobile Matrix, SARIF v2.1.0 & CycloneDX v1.5 SBOM Exporters', async () => {
    const manifestEntry = apk.entryMap.get('AndroidManifest.xml');
    const axml = globalThis.ArgonAxml.parseAxml(await manifestEntry.extract(), arsc);
    const mfInfo = globalThis.ArgonAxml.analyzeManifest(axml);
    const soBytes = await apk.entryMap.get('lib/arm64-v8a/libnative-vault.so').extract();
    const parsedElf = globalThis.ArgonElfSecurity.parseElfBinary(soBytes, 'lib/arm64-v8a/libnative-vault.so');
    const taintFlows = globalThis.ArgonAdvanced.runTaintAnalysis([dex]);
    const deobfData = globalThis.ArgonAdvanced.analyzeObfuscationAndGenerateMappings(apk, [dex], [parsedElf]);
    const cryptoHits = globalThis.ArgonAdvanced.scanCryptographicConstants(apk.entries, apk.rawBytes);
    const audit = globalThis.ArgonElfSecurity.runStaticSecurityAudit(mfInfo, [dex], [parsedElf], apk.signingBlock, apk.certificates);

    const mitre = globalThis.ArgonAdvanced.mapMitreAttackMobile(mfInfo, [dex], [parsedElf], taintFlows, deobfData);
    assert(mitre.techniques.length >= 4, `Expected >=4 MITRE techniques, got ${mitre.techniques.length}`);
    assert(mitre.techniques.some(t => t.id === 'T1575'), 'Expected T1575 Native Code Execution');

    const sbom = globalThis.ArgonAdvanced.generateCycloneDxSbom(apk, mfInfo, [dex], [parsedElf], cryptoHits);
    assert.strictEqual(sbom.bomFormat, 'CycloneDX');
    assert.strictEqual(sbom.specVersion, '1.5');
    assert(sbom.components.length >= 3, 'Expected SBOM components (app + packages + native)');

    const sarif = globalThis.ArgonAdvanced.generateSarifReport(apk, audit, taintFlows);
    assert.strictEqual(sarif.version, '2.1.0');
    assert(sarif.runs[0].results.length >= audit.findings.length, 'Expected SARIF results for all audit findings');
  });

  await test('22. JNI RegisterNatives Dynamic Binding Scanner & Multi-ABI (ARM32 / x86_64 / ARM64) Disassembler', async () => {
    const soBytes = await apk.entryMap.get('lib/arm64-v8a/libnative-vault.so').extract();
    const parsedElf = globalThis.ArgonElfSecurity.parseElfBinary(soBytes, 'lib/arm64-v8a/libnative-vault.so');

    // Synthesize a RegisterNatives JNINativeMethod string buffer appended inside ELF bytes for detection test
    const regStr = new TextEncoder().encode('JNI_OnLoad\0RegisterNatives\0verifySignatureNative\0(Ljava/lang/String;)Z\0');
    const extSo = new Uint8Array(soBytes.length + regStr.length);
    extSo.set(soBytes, 0);
    extSo.set(regStr, soBytes.length);

    const regRes = globalThis.ArgonAdvanced.scanDynamicRegisterNatives(extSo, parsedElf, [dex]);
    assert(regRes.hasJniOnLoad && regRes.usesRegisterNatives, 'Expected JNI_OnLoad and RegisterNatives detection');
    assert(regRes.bindings.some(b => b.signature === '(Ljava/lang/String;)Z'), 'Expected JNINativeMethod signature extraction');

    const arm64Dis = globalThis.ArgonAdvanced.disassembleMultiArchElf(soBytes, parsedElf, 'ARM64');
    assert(arm64Dis.length > 0, 'Expected ARM64 disassembly output');

    // Craft minimal .text slice with ARM32 BX LR (0xe12fff1e) & NOP (0xe1a00000) and x86_64 prologue + ret
    const fakeArm32Bytes = new Uint8Array([0x00, 0x00, 0xa0, 0xe1, 0x1e, 0xff, 0x2f, 0xe1]);
    const fakeMeta32 = { architecture: 'ARM32', exportedSymbols: [], sections: [{ name: '.text', offset: 0, addr: 0x1000, size: 8 }] };
    const arm32Dis = globalThis.ArgonAdvanced.disassembleMultiArchElf(fakeArm32Bytes, fakeMeta32, 'ARM32');
    assert.strictEqual(arm32Dis[0].mnemonic, 'nop');
    assert.strictEqual(arm32Dis[1].mnemonic, 'bx');
    assert.strictEqual(arm32Dis[1].operands, 'lr');

    const fakeX64Bytes = new Uint8Array([0x55, 0x48, 0x89, 0xe5, 0xc3]);
    const fakeMeta64 = { architecture: 'x86_64', exportedSymbols: [], sections: [{ name: '.text', offset: 0, addr: 0x2000, size: 5 }] };
    const x64Dis = globalThis.ArgonAdvanced.disassembleMultiArchElf(fakeX64Bytes, fakeMeta64, 'X86_64');
    assert.strictEqual(x64Dis[0].mnemonic, 'push');
    assert.strictEqual(x64Dis[1].mnemonic, 'mov');
    assert.strictEqual(x64Dis[2].mnemonic, 'ret');
  });

  await test('23. Inline Blob Web Worker Helper & Main Controller Safe Fallback', async () => {
    require('../js/app.js');
    assert(globalThis.ArgonApp && typeof globalThis.ArgonApp.createInlineAnalysisWorker === 'function', 'Expected ArgonApp.createInlineAnalysisWorker export');
    assert(typeof globalThis.ArgonApp.applyLiveBytecodePatch === 'function', 'Expected ArgonApp.applyLiveBytecodePatch export');
    // In Node environment without window.Worker, createInlineAnalysisWorker cleanly returns null (safe fallback)
    const workerHandle = globalThis.ArgonApp.createInlineAnalysisWorker();
    assert.strictEqual(workerHandle, null);
  });

  await test('24. Performance Optimizations (NMAX Adler-32, indexOf Crypto Scan, Chunked Code Render) & Theme Toggle', async () => {
    // 1. Verify NMAX=5552 Adler-32 matches naive byte-by-byte modulo over 20KB buffer
    const bigBuf = new Uint8Array(20000);
    for (let i = 0; i < bigBuf.length; i++) bigBuf[i] = (i * 131 + 17) & 0xff;
    let ra = 1, rb = 0;
    for (let i = 0; i < bigBuf.length; i++) {
      ra = (ra + bigBuf[i]) % 65521;
      rb = (rb + ra) % 65521;
    }
    const expectedAdler = ((rb << 16) | ra) >>> 0;
    assert.strictEqual(globalThis.ArgonZip.adler32(bigBuf), expectedAdler, 'Expected NMAX Adler-32 to match reference');

    // 2. Verify indexOf crypto scanner finds signature placed past 1MB offset
    const largeScanBuf = new Uint8Array(1024 * 1024 + 32);
    largeScanBuf.set([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76], 1024 * 1024);
    const hits = globalThis.ArgonAdvanced.scanCryptographicConstants([], largeScanBuf);
    assert(hits.some(h => h.algorithm.includes('AES')), 'Expected indexOf crypto scanner to find AES S-Box at 1MB+');

    // 3. Verify chunked code renderer caps initial lines and emits expand banner
    const longJava = Array.from({ length: 1200 }, (_, i) => `int x${i} = ${i};`).join('\n');
    const chunkHtml = globalThis.ArgonApp.renderCodeLinesHtml(longJava, 'java', 800);
    assert(chunkHtml.includes('data-action="expand-code-lines"'), 'Expected expand-code-lines banner for >800 lines');
    assert(!chunkHtml.includes('x1199'), 'Expected lines beyond chunk limit not to be eagerly rendered');

    // 4. Verify Dark / Light theme state toggle
    globalThis.ArgonApp.applyTheme('light');
    assert.strictEqual(globalThis.ArgonApp.State.theme, 'light');
    globalThis.ArgonApp.applyTheme('dark');
    assert.strictEqual(globalThis.ArgonApp.State.theme, 'dark');
  });

  console.log('====================================================================');
  console.log(` Results: ${passed} passed, ${failed} failed`);
  console.log('====================================================================');
  if (failed > 0) process.exit(1);
})();
