package com.argon.vault.db;

import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;

/**
 * Decompiled by ArgonDEX Studio
 * Source: VaultDatabase.java (classes.dex)
 * Descriptor: Lcom/argon/vault/db/VaultDatabase;
 */
public class VaultDatabase {

    public VaultDatabase() {
        // empty method body
    }

    public Cursor queryVaultSecret(SQLiteDatabase arg0, String arg1) {
        return arg0.rawQuery("SELECT secret_blob FROM vault_items WHERE owner = '" + arg1 + "' AND status = 1", null);
    }

}