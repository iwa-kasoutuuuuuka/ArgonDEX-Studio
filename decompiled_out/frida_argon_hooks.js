/**
 * ArgonDEX Studio — Auto-Generated Frida Dynamic Instrumentation Script
 * Target APK : ArgonVault_v2.4.1_sample.apk (com.argon.vault)
 * Run Command: frida -U -f com.argon.vault -l frida_argon_hooks.js --no-pause
 */

Java.perform(function () {
  console.log("[*] ArgonDEX Frida Hook Suite attached to com.argon.vault");

  // 1. Cryptographic Key & Cipher Interceptor (MASVS-CRYPTO)
  try {
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.getInstance.overload("java.lang.String").implementation = function (transformation) {
      console.log("[Crypto] Cipher.getInstance(\"" + transformation + "\")");
      return this.getInstance(transformation);
    };
  } catch (e) {}

  // [Taint Flow TF-001] Cross-Site Scripting / Arbitrary Navigation (CWE-79) in com.argon.vault.MainActivity.initWebViewPortal
  try {
    var Cls_TF_001 = Java.use("com.argon.vault.MainActivity");
    Cls_TF_001["initWebViewPortal"].overloads.forEach(function (ov) {
      ov.implementation = function () {
        console.log("[🚨 TF-001] com.argon.vault.MainActivity.initWebViewPortal() invoked with args:", JSON.stringify(Array.prototype.slice.call(arguments)));
        var ret = ov.apply(this, arguments);
        console.log("[🚨 TF-001] com.argon.vault.MainActivity.initWebViewPortal() returned:", ret);
        return ret;
      };
    });
  } catch (e) {}

  // [Taint Flow TF-002] Unvalidated Input to Native TEE Key Derivation (CWE-20 / MASVS-CRYPTO-1) in com.argon.vault.crypto.CryptoEngine.encryptPayload
  try {
    var Cls_TF_002 = Java.use("com.argon.vault.crypto.CryptoEngine");
    Cls_TF_002["encryptPayload"].overloads.forEach(function (ov) {
      ov.implementation = function () {
        console.log("[🚨 TF-002] com.argon.vault.crypto.CryptoEngine.encryptPayload() invoked with args:", JSON.stringify(Array.prototype.slice.call(arguments)));
        var ret = ov.apply(this, arguments);
        console.log("[🚨 TF-002] com.argon.vault.crypto.CryptoEngine.encryptPayload() returned:", ret);
        return ret;
      };
    });
  } catch (e) {}

  // [Taint Flow TF-003] SQL Injection (CWE-89) in com.argon.vault.db.VaultDatabase.queryVaultSecret
  try {
    var Cls_TF_003 = Java.use("com.argon.vault.db.VaultDatabase");
    Cls_TF_003["queryVaultSecret"].overloads.forEach(function (ov) {
      ov.implementation = function () {
        console.log("[🚨 TF-003] com.argon.vault.db.VaultDatabase.queryVaultSecret() invoked with args:", JSON.stringify(Array.prototype.slice.call(arguments)));
        var ret = ov.apply(this, arguments);
        console.log("[🚨 TF-003] com.argon.vault.db.VaultDatabase.queryVaultSecret() returned:", ret);
        return ret;
      };
    });
  } catch (e) {}

  // [Taint Flow TF-004] Unvalidated Input to Native TEE Key Derivation (CWE-20 / MASVS-CRYPTO-1) in com.argon.vault.obf.a.a
  try {
    var Cls_TF_004 = Java.use("com.argon.vault.obf.a");
    Cls_TF_004["a"].overloads.forEach(function (ov) {
      ov.implementation = function () {
        console.log("[🚨 TF-004] com.argon.vault.obf.a.a() invoked with args:", JSON.stringify(Array.prototype.slice.call(arguments)));
        var ret = ov.apply(this, arguments);
        console.log("[🚨 TF-004] com.argon.vault.obf.a.a() returned:", ret);
        return ret;
      };
    });
  } catch (e) {}

  // [Deobfuscated Class] com.argon.vault.obf.a -> com.argon.vault.obf.CryptoTokenHelper (Invokes javax.crypto.Cipher / MessageDigest APIs)
  try {
    var ObfCls = Java.use("com.argon.vault.obf.a");
    console.log("[Deobf] Loaded obfuscated class:", "com.argon.vault.obf.a");
  } catch (e) {}

});

// ==================== NATIVE ELF HOOKS: libnative-vault.so ====================
try {
  var sym_JNI_OnLoad = Module.findExportByName("libnative-vault.so", "JNI_OnLoad");
  if (sym_JNI_OnLoad) {
    Interceptor.attach(sym_JNI_OnLoad, {
      onEnter: function (args) {
        console.log("[Native JNI] -> JNI_OnLoad @ " + sym_JNI_OnLoad + " | x2=" + args[2] + " x3=" + args[3]);
      },
      onLeave: function (retval) {
        console.log("[Native JNI] <- JNI_OnLoad returned: " + retval);
      }
    });
  }
} catch (e) {}

try {
  var sym_Java_com_argon_vault_NativeBridge_deriveHardwareKey = Module.findExportByName("libnative-vault.so", "Java_com_argon_vault_NativeBridge_deriveHardwareKey");
  if (sym_Java_com_argon_vault_NativeBridge_deriveHardwareKey) {
    Interceptor.attach(sym_Java_com_argon_vault_NativeBridge_deriveHardwareKey, {
      onEnter: function (args) {
        console.log("[Native JNI] -> Java_com_argon_vault_NativeBridge_deriveHardwareKey @ " + sym_Java_com_argon_vault_NativeBridge_deriveHardwareKey + " | x2=" + args[2] + " x3=" + args[3]);
      },
      onLeave: function (retval) {
        console.log("[Native JNI] <- Java_com_argon_vault_NativeBridge_deriveHardwareKey returned: " + retval);
      }
    });
  }
} catch (e) {}

try {
  var sym_Java_com_argon_vault_NativeBridge_verifyDeviceIntegrity = Module.findExportByName("libnative-vault.so", "Java_com_argon_vault_NativeBridge_verifyDeviceIntegrity");
  if (sym_Java_com_argon_vault_NativeBridge_verifyDeviceIntegrity) {
    Interceptor.attach(sym_Java_com_argon_vault_NativeBridge_verifyDeviceIntegrity, {
      onEnter: function (args) {
        console.log("[Native JNI] -> Java_com_argon_vault_NativeBridge_verifyDeviceIntegrity @ " + sym_Java_com_argon_vault_NativeBridge_verifyDeviceIntegrity + " | x2=" + args[2] + " x3=" + args[3]);
      },
      onLeave: function (retval) {
        console.log("[Native JNI] <- Java_com_argon_vault_NativeBridge_verifyDeviceIntegrity returned: " + retval);
      }
    });
  }
} catch (e) {}
