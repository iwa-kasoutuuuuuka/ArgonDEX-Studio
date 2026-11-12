// [ArgonDEX Smart Deobfuscator] Renamed class 'com.argon.vault.obf.a' -> 'com.argon.vault.obf.CryptoTokenHelper' (Invokes javax.crypto.Cipher / MessageDigest APIs)
package com.argon.vault.obf;

import com.argon.vault.NativeBridge;
import javax.crypto.Cipher;

/**
 * Decompiled by ArgonDEX Studio
 * Source: ProGuard (classes.dex)
 * Descriptor: Lcom/argon/vault/obf/a;
 */
public final class CryptoTokenHelper /* obf: a */ {

    private String mString_a;
    private int mint_b;

    public CryptoTokenHelper() {
        this.mString_a = "AES/ECB/PKCS5Padding";
        this.mint_b = 256;
    }

    public byte[] transformCrypto_a(String arg0) {
        synchronized (this) {
            Cipher v0 = Cipher.getInstance(this.mString_a);
        }
        return NativeBridge.deriveHardwareKey(arg0, this.mint_b);
    }

    public int computeInt_b(int arg0, int arg1) {
        byte[] v0 = new byte[]{ 0x1b, 0x08, 0x1d, 0x15, 0x14, 0x05, 0x11, 0x1f, 0x03, 0x7b } /* 🔓 Decrypted XOR Byte-Array (key=0x5a): "ARGON_KEY!" */;
        return ((arg0 + arg1) * 31);
    }

}