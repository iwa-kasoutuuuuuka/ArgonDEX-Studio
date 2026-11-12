package com.argon.vault.crypto;

import com.argon.vault.NativeBridge;
import java.security.MessageDigest;
import javax.crypto.Cipher;

/**
 * Decompiled by ArgonDEX Studio
 * Source: CryptoEngine.java (classes.dex)
 * Descriptor: Lcom/argon/vault/crypto/CryptoEngine;
 */
public class CryptoEngine {

    public CryptoEngine() {
        // empty method body
    }

    public int computeRollingHash(int arg0, int arg1) {
        int v0 = 0;
        int v1 = arg0;
        while (v0 < arg1) {
            v1 = (v1 * 31);
            v1 = (v1 ^ v0);
            v0 = (v0 + 1);
        }
        return v1;
    }

    public byte[] encryptPayload(String arg0) {
        Cipher v0 = Cipher.getInstance("AES/ECB/PKCS5Padding");
        MessageDigest v1 = MessageDigest.getInstance("MD5");
        return NativeBridge.deriveHardwareKey(arg0, 256);
    }

}