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
        Cipher v0 = Cipher.getInstance(this.a);
        return NativeBridge.deriveHardwareKey(arg0, this.b);
    }

    public int b(int arg0, int arg1) {
        return ((arg0 + arg1) * 31);
    }

}