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

  console.log('====================================================================');
  console.log(` Results: ${passed} passed, ${failed} failed`);
  console.log('====================================================================');
  if (failed > 0) process.exit(1);
})();
