#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ArgonDEX Studio — CLI Decompiler & Local Studio Server
Usage:
  1. Decompile an APK to Java, Smali, XML & Security Audit Report:
     python argondex_cli.py decompile <path/to/app.apk> --out ./decompiled_out

  2. Generate the built-in binary Showcase APK (ArgonVault_v2.4.1_sample.apk):
     python argondex_cli.py generate-sample --out ./ArgonVault_v2.4.1_sample.apk

  3. Start the interactive ArgonDEX Studio Web IDE server:
     python argondex_cli.py serve --port 8765
"""

import argparse
import http.server
import json
import os
import pathlib
import socketserver
import subprocess
import sys
import webbrowser

ROOT_DIR = pathlib.Path(__file__).resolve().parent


def run_node_decompile(apk_path: pathlib.Path, out_dir: pathlib.Path) -> dict:
    """Invokes the ArgonDEX core binary engine via Node.js to decompile an APK to disk."""
    js_runner = """
const fs = require('fs');
const path = require('path');
const root = process.argv[1];
const apkPath = process.argv[2];
const outDir = path.resolve(process.argv[3]);

require(path.join(root, 'js/zip_engine.js'));
require(path.join(root, 'js/axml_arsc_parser.js'));
require(path.join(root, 'js/dex_decompiler.js'));
require(path.join(root, 'js/elf_security_engine.js'));
require(path.join(root, 'js/advanced_analysis_engine.js'));
require(path.join(root, 'js/sample_apk_builder.js'));

function safeWriteFile(baseDir, relativeFile, content) {
  const resolvedBase = path.resolve(baseDir);
  const resolvedTarget = path.resolve(resolvedBase, relativeFile);
  if (!resolvedTarget.startsWith(resolvedBase + path.sep) && resolvedTarget !== resolvedBase) {
    throw new Error('Blocked path traversal attempt: ' + relativeFile);
  }
  fs.mkdirSync(path.dirname(resolvedTarget), { recursive: true });
  fs.writeFileSync(resolvedTarget, content, 'utf8');
  return resolvedTarget;
}

(async () => {
  const buf = fs.readFileSync(apkPath);
  const ab = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  const apk = await globalThis.ArgonZip.parseApkArchive(ab, path.basename(apkPath));

  let arsc = null;
  if (apk.entryMap.has('resources.arsc')) {
    const arscBytes = await apk.entryMap.get('resources.arsc').extract();
    arsc = globalThis.ArgonAxml.parseResourcesArsc(arscBytes);
  }

  let manifestAxml = null;
  let manifestInfo = null;
  if (apk.entryMap.has('AndroidManifest.xml')) {
    const mfBytes = await apk.entryMap.get('AndroidManifest.xml').extract();
    manifestAxml = globalThis.ArgonAxml.parseAxml(mfBytes, arsc);
    manifestInfo = globalThis.ArgonAxml.analyzeManifest(manifestAxml);
  }

  fs.mkdirSync(outDir, { recursive: true });
  if (manifestAxml) {
    safeWriteFile(outDir, 'AndroidManifest.xml', manifestAxml.xml);
  }

  const dexFiles = [];
  const classSummaries = [];
  for (const entry of apk.entries) {
    if (entry.name.endsWith('.dex')) {
      const dexBytes = await entry.extract();
      const dex = globalThis.ArgonDex.parseDexFile(dexBytes, entry.name, arsc);
      dexFiles.push(dex);
      for (const cls of dex.classes) {
        const dec = globalThis.ArgonDex.decompileClassToJava(cls, arsc);
        const relPath = globalThis.ArgonDex.sanitizeClassPath(cls.fullName);
        const javaTarget = safeWriteFile(outDir, path.join('src/main/java', relPath + '.java'), dec.java);
        safeWriteFile(outDir, path.join('smali', relPath + '.smali'), dec.smali);
        classSummaries.push({
          fullName: cls.fullName,
          methods: cls.allMethods.length,
          javaPath: path.relative(outDir, javaTarget)
        });
      }
    }
  }

  const elfFiles = [];
  for (const entry of apk.entries) {
    if (entry.name.endsWith('.so')) {
      const soBytes = await entry.extract();
      const parsedElf = globalThis.ArgonElfSecurity.parseElfBinary(soBytes, entry.name);
      parsedElf.disassembly = globalThis.ArgonAdvanced.disassembleElfTextSection(soBytes, parsedElf);
      parsedElf.pseudoC = globalThis.ArgonAdvanced.decompileArm64ToPseudoC(soBytes, parsedElf);
      const baseSo = entry.name.split('/').pop().replace(/[^A-Za-z0-9_.-]/g, '_');
      safeWriteFile(outDir, path.join('native_pseudo_c', baseSo + '.c'), parsedElf.pseudoC);
      elfFiles.push(parsedElf);
    }
  }

  const deobfData = globalThis.ArgonAdvanced.analyzeObfuscationAndGenerateMappings(apk, dexFiles, elfFiles);
  for (const dex of dexFiles) {
    for (const cls of dex.classes) {
      if (deobfData.classRenames.has(cls.fullName)) {
        const dec = globalThis.ArgonDex.decompileClassToJava(cls, arsc);
        const deobfJava = globalThis.ArgonAdvanced.applySmartDeobfuscationToJava(dec.java, cls, deobfData);
        const info = deobfData.classRenames.get(cls.fullName);
        const safeRel = globalThis.ArgonDex.sanitizeClassPath(info.newFull);
        safeWriteFile(outDir, path.join('src/main/java', safeRel + '.java'), deobfJava);
      }
    }
  }

  const taintFlows = globalThis.ArgonAdvanced.runTaintAnalysis(dexFiles);
  const cryptoConstants = globalThis.ArgonAdvanced.scanCryptographicConstants(apk.entries, apk.rawBytes);
  const fridaScript = globalThis.ArgonAdvanced.generateFridaHookScript(apk, manifestInfo, dexFiles, elfFiles, taintFlows, deobfData);
  safeWriteFile(outDir, 'frida_argon_hooks.js', fridaScript);

  const audit = globalThis.ArgonElfSecurity.runStaticSecurityAudit(
    manifestInfo, dexFiles, elfFiles, apk.signingBlock, apk.certificates
  );

  if (arsc) {
    safeWriteFile(outDir, 'resources_table.json', JSON.stringify(arsc.entries, null, 2));
  }

  const report = {
    fileName: apk.fileName,
    fileSize: apk.fileSize,
    sha256: apk.sha256,
    entropy: apk.entropy,
    signingBlock: apk.signingBlock,
    certificates: apk.certificates,
    manifest: manifestInfo,
    classes: classSummaries,
    taintFlows,
    deobfuscation: {
      obfuscationRatio: deobfData.obfuscationRatio,
      renames: deobfData.renameReasons,
      decryptedStrings: deobfData.decryptedStrings,
      fingerprints: deobfData.fingerprints
    },
    cryptoConstants,
    nativeLibraries: elfFiles.map(e => ({
      fileName: e.fileName,
      architecture: e.architecture,
      hardening: e.hardening,
      jniMethods: e.jniMethods,
      disassemblyCount: (e.disassembly || []).length,
      disassembly: e.disassembly,
      pseudoC: e.pseudoC
    })),
    securityAudit: audit
  };
  safeWriteFile(outDir, 'security_audit_report.json', JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report));
})();
"""
    res = subprocess.run(
        ["node", "-e", js_runner, str(ROOT_DIR), str(apk_path), str(out_dir)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True
    )
    return json.loads(res.stdout.strip().splitlines()[-1])


def generate_sample_apk(out_path: pathlib.Path) -> None:
    js_runner = """
const fs = require('fs');
const path = require('path');
const root = process.argv[1];
const outPath = process.argv[2];
require(path.join(root, 'js/zip_engine.js'));
require(path.join(root, 'js/sample_apk_builder.js'));
const bytes = globalThis.ArgonSampleBuilder.generateSampleApkBuffer();
fs.writeFileSync(outPath, Buffer.from(bytes));
console.log('Wrote', bytes.length, 'bytes to', outPath);
"""
    subprocess.run(["node", "-e", js_runner, str(ROOT_DIR), str(out_path)], check=True)


def serve_studio(port: int, open_browser: bool = False) -> None:
    os.chdir(ROOT_DIR)
    handler = http.server.SimpleHTTPRequestHandler
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("127.0.0.1", port), handler) as httpd:
        url = f"http://127.0.0.1:{port}"
        print(f"============================================================")
        print(f" ArgonDEX Studio Web IDE running at: {url}")
        print(f"============================================================")
        if open_browser:
            webbrowser.open(url)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down ArgonDEX Studio server.")


def main():
    parser = argparse.ArgumentParser(description="ArgonDEX Studio CLI & Server")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_dec = sub.add_parser("decompile", help="Decompile an APK to Java, Smali, Manifest XML, and Security Report")
    p_dec.add_argument("apk", type=pathlib.Path, help="Path to input .apk file")
    p_dec.add_argument("--out", "-o", type=pathlib.Path, default=pathlib.Path("./decompiled_out"), help="Output directory")

    p_sample = sub.add_parser("generate-sample", help="Generate the binary ArgonVault_v2.4.1_sample.apk")
    p_sample.add_argument("--out", "-o", type=pathlib.Path, default=ROOT_DIR / "ArgonVault_v2.4.1_sample.apk")

    p_serve = sub.add_parser("serve", help="Start local HTTP server for ArgonDEX Studio Web IDE")
    p_serve.add_argument("--port", "-p", type=int, default=8765)
    p_serve.add_argument("--open", action="store_true")

    args = parser.parse_args()
    if args.cmd == "generate-sample":
        generate_sample_apk(args.out.resolve())
    elif args.cmd == "decompile":
        report = run_node_decompile(args.apk.resolve(), args.out.resolve())
        mf = report.get("manifest") or {}
        audit = report.get("securityAudit") or {}
        print("=" * 68)
        print(f" ArgonDEX Studio — Decompilation & Security Report")
        print("=" * 68)
        print(f" APK File      : {report['fileName']} ({report['fileSize']} bytes)")
        print(f" SHA-256       : {report['sha256']}")
        print(f" Package       : {mf.get('packageName')} (v{mf.get('versionName')}, SDK {mf.get('minSdkVersion')}->{mf.get('targetSdkVersion')})")
        print(f" Classes       : {len(report['classes'])} decompiled to Java & Smali")
        print(f" Taint Flows   : {len(report.get('taintFlows', []))} source-to-sink propagation paths")
        print(f" Deobfuscator  : {len(report.get('deobfuscation', {}).get('renames', []))} obfuscated symbols reconstructed ({report.get('deobfuscation', {}).get('obfuscationRatio', 0)}% density)")
        print(f" Crypto S-Box  : {len(report.get('cryptoConstants', []))} binary cryptographic signatures")
        print(f" Native Libs   : {len(report['nativeLibraries'])} ELF .so binaries (ARM64 .text disassembled)")
        print(f" Security Score: {audit.get('score')}/100 (Grade {audit.get('grade')}) — {len(audit.get('findings', []))} findings")
        print(f" Output Folder : {args.out.resolve()}")
        print("=" * 68)
    elif args.cmd == "serve":
        serve_studio(args.port, args.open)


if __name__ == "__main__":
    main()
