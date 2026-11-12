package com.argon.vault.net;

/**
 * Decompiled by ArgonDEX Studio
 * Source: ApiClient.java (classes.dex)
 * Descriptor: Lcom/argon/vault/net/ApiClient;
 */
public class ApiClient {

    private String apiEndpoint;
    private int retryCount;

    public ApiClient() {
        this.apiEndpoint = "http://api.argonvault.internal/v2/sync?token=";
        this.retryCount = 3;
    }

    public String buildSyncUrl(String arg0) {
        return this.apiEndpoint + arg0;
    }

}