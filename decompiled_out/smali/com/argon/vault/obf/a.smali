.class public final Lcom/argon/vault/obf/a;
.super Ljava/lang/Object;
.source "ProGuard"

# instance fields
.field private a:Ljava/lang/String;
.field private b:I

# direct methods
.method public constructor <init>()V
    .registers 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V    # @0000 [7010 1b00 0200]
    const-string v0, "AES/ECB/PKCS5Padding"    # @0003 [1a00 0300]
    iput-object v0, p0, Lcom/argon/vault/obf/a;->a:Ljava/lang/String;    # @0005 [5b20 0400]
    const/16 v0, 0x100    # @0007 [1300 0001]
    iput v0, p0, Lcom/argon/vault/obf/a;->b:I    # @0009 [5920 0500]
    return-void    # @000b [0e00]
.end method

# virtual methods
.method public a(Ljava/lang/String;)[B
    .registers 4
    monitor-enter p0    # @0000 [1d02]
    iget-object v0, p0, Lcom/argon/vault/obf/a;->a:Ljava/lang/String;    # @0001 [5420 0400]
    invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;    # @0003 [7110 2300 0000]
    move-result-object v0    # @0006 [0c00]
    iget v1, p0, Lcom/argon/vault/obf/a;->b:I    # @0007 [5221 0500]
    invoke-static {p1, v1}, Lcom/argon/vault/NativeBridge;->deriveHardwareKey(Ljava/lang/String;I)[B    # @0009 [7120 0f00 1300]
    move-result-object v1    # @000c [0c01]
    monitor-exit p0    # @000d [1e02]
    return-object v1    # @000e [1101]
.end method

.method public b(II)I
    .registers 4
    const/16 p0, 0xa    # @0000 [1301 0a00]
    new-array v0, p0, [B    # @0002 [2310 1700]
    fill-array-data v0, :payload_e    # @0004 [2600 0a00 0000]
    xor-int/lit8 p0, p0, 0x5a    # @0007 [df01 015a]
    add-int v0, p1, p2    # @0009 [9000 0203]
    mul-int/lit8 v0, v0, 0x1f    # @000b [da00 001f]
    return v0    # @000d [0f00]
    :goto_e
    .array-data 1    # @000e [0003]
.end method
