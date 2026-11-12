.class public Lcom/argon/vault/MainActivity;
.super Landroid/app/Activity;
.source "MainActivity.java"

# static fields
.field public static final masterApiKey:Ljava/lang/String;

# instance fields
.field private isUnlocked:Z

# direct methods
.method public constructor <init>()V
    .registers 2
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V    # @0000 [7010 0000 0100]
    const-string v0, "AIzaSyD9ArgonVaultHardcodedApiKey8842109"    # @0003 [1a00 0400]
    sput-object v0, Lcom/argon/vault/MainActivity;->masterApiKey:Ljava/lang/String;    # @0005 [6900 0000]
    const/4 v0, 0x0    # @0007 [1200]
    iput-boolean v0, p0, Lcom/argon/vault/MainActivity;->isUnlocked:Z    # @0008 [5c10 0100]
    return-void    # @000a [0e00]
.end method

# virtual methods
.method public initWebViewPortal(Landroid/webkit/WebView;)V
    .registers 4
    invoke-virtual {p1}, Landroid/webkit/WebView;->getSettings()Landroid/webkit/WebSettings;    # @0000 [6e10 0700 0300]
    move-result-object v0    # @0003 [0c00]
    const/4 v1, 0x1    # @0004 [1211]
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V    # @0005 [6e20 0500 1000]
    const-string v1, "ArgonVault"    # @0008 [1a01 0600]
    invoke-virtual {p1, p0, v1}, Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V    # @000a [6e30 0600 2301]
    const-string v1, "http://api.argonvault.internal/v2/sync?token="    # @000d [1a01 4500]
    invoke-virtual {p1, v1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V    # @000f [6e20 0800 1300]
    return-void    # @0012 [0e00]
.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .registers 4
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V    # @0000 [6f20 0100 3200]
    const v0, 0x7f020000 # @layout/activity_main    # @0003 [1400 0000 027f]
    invoke-virtual {p0, v0}, Landroid/app/Activity;->setContentView(I)V    # @0006 [6e20 0200 0200]
    const-string v0, "ArgonVault"    # @0009 [1a00 0600]
    const-string v1, "Vault initialized with endpoint: "    # @000b [1a01 3200]
    invoke-static {v0, v1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I    # @000d [7120 0400 1000]
    return-void    # @0010 [0e00]
.end method

.method public verifyMasterPin(Ljava/lang/String;)Z
    .registers 4
    const/16 v0, 0x539    # @0000 [1300 3905]
    invoke-static {v0}, Lcom/argon/vault/NativeBridge;->verifyDeviceIntegrity(I)Z    # @0002 [7110 1000 0000]
    move-result v1    # @0005 [0a01]
    if-eqz v1, :cond_c    # @0006 [3801 0600]
    const/4 v0, 0x1    # @0008 [1210]
    iput-boolean v0, p0, Lcom/argon/vault/MainActivity;->isUnlocked:Z    # @0009 [5c20 0100]
    return v0    # @000b [0f00]
    :cond_c
    const/4 v0, 0x0    # @000c [1200]
    return v0    # @000d [0f00]
.end method
