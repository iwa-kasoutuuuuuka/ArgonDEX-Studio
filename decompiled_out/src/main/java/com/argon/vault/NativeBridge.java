package com.argon.vault;

/**
 * Decompiled by ArgonDEX Studio
 * Source: NativeBridge.java (classes.dex)
 * Descriptor: Lcom/argon/vault/NativeBridge;
 */
public class NativeBridge {

    static {
        System.loadLibrary("native-vault");
    }

    public NativeBridge() {
        // empty method body
    }

    public static native byte[] deriveHardwareKey(String arg0, int arg1);

    public static native boolean verifyDeviceIntegrity(int arg0);

}