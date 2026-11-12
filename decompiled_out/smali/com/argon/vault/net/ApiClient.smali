.class public Lcom/argon/vault/net/ApiClient;
.super Ljava/lang/Object;
.source "ApiClient.java"

# instance fields
.field private apiEndpoint:Ljava/lang/String;
.field private retryCount:I

# direct methods
.method public constructor <init>()V
    .registers 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V    # @0000 [7010 1b00 0200]
    const-string v0, "http://api.argonvault.internal/v2/sync?token="    # @0003 [1a00 4500]
    iput-object v0, p0, Lcom/argon/vault/net/ApiClient;->apiEndpoint:Ljava/lang/String;    # @0005 [5b20 0200]
    const/4 v0, 0x3    # @0007 [1230]
    iput v0, p0, Lcom/argon/vault/net/ApiClient;->retryCount:I    # @0008 [5920 0300]
    return-void    # @000a [0e00]
.end method

# virtual methods
.method public buildSyncUrl(Ljava/lang/String;)Ljava/lang/String;
    .registers 4
    new-instance v0, Ljava/lang/StringBuilder;    # @0000 [2200 1100]
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V    # @0002 [7010 1e00 0000]
    iget-object v1, p0, Lcom/argon/vault/net/ApiClient;->apiEndpoint:Ljava/lang/String;    # @0005 [5421 0200]
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;    # @0007 [6e20 1f00 1000]
    move-result-object v0    # @000a [0c00]
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;    # @000b [6e20 1f00 3000]
    move-result-object v0    # @000e [0c00]
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;    # @000f [6e10 2000 0000]
    move-result-object v0    # @0012 [0c00]
    return-object v0    # @0013 [1100]
.end method
