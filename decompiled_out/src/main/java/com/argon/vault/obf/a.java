package com.argon.vault.obf;

import com.argon.vault.NativeBridge;
import javax.crypto.Cipher;

/**
 * Decompiled by ArgonDEX Studio
 * Source: ProGuard (classes.dex)
 * Descriptor: Lcom/argon/vault/obf/a;
 */
public final class a {

    private String a;
    private int b;

    public a() {
        this.a = "AES/ECB/PKCS5Padding";
        this.b = 256;
    }

    public byte[] a(String arg0) {
        synchronized (this) {
            Cipher v0 = Cipher.getInstance(this.a);
        }
        return NativeBridge.deriveHardwareKey(arg0, this.b);
    }

    public int b(int arg0, int arg1) {
        byte[] v0 = new byte[]{ 0x1b, 0x08, 0x1d, 0x15, 0x14, 0x05, 0x11, 0x1f, 0x03, 0x7b };
        return ((arg0 + arg1) * 31);
    }

}