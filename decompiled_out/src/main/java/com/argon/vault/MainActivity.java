package com.argon.vault;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.webkit.WebSettings;
import android.webkit.WebView;

/**
 * Decompiled by ArgonDEX Studio
 * Source: MainActivity.java (classes.dex)
 * Descriptor: Lcom/argon/vault/MainActivity;
 */
public class MainActivity extends Activity {

    public static final String masterApiKey;
    private boolean isUnlocked;

    public MainActivity() {
        super();
        masterApiKey = "AIzaSyD9ArgonVaultHardcodedApiKey8842109";
        this.isUnlocked = false;
    }

    public void initWebViewPortal(WebView arg0) {
        arg0.getSettings().setJavaScriptEnabled(true);
        arg0.addJavascriptInterface(this, "ArgonVault");
        arg0.loadUrl("http://api.argonvault.internal/v2/sync?token=");
    }

    protected void onCreate(Bundle arg0) {
        super.onCreate(arg0);
        this.setContentView(R.layout.activity_main /* 0x7f020000 */);
        Log.i("ArgonVault", "Vault initialized with endpoint: ");
    }

    public boolean verifyMasterPin(String arg0) {
        if (NativeBridge.verifyDeviceIntegrity(1337)) {
            this.isUnlocked = true;
            return true;
        }
        return false;
    }

}