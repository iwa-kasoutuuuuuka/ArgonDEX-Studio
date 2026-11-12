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
    iget-object v0, p0, Lcom/argon/vault/obf/a;->a:Ljava/lang/String;    # @0000 [5420 0400]
    invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;    # @0002 [7110 2300 0000]
    move-result-object v0    # @0005 [0c00]
    iget v1, p0, Lcom/argon/vault/obf/a;->b:I    # @0006 [5221 0500]
    invoke-static {p1, v1}, Lcom/argon/vault/NativeBridge;->deriveHardwareKey(Ljava/lang/String;I)[B    # @0008 [7120 0f00 1300]
    move-result-object v1    # @000b [0c01]
    return-object v1    # @000c [1101]
.end method

.method public b(II)I
    .registers 4
    add-int v0, p1, p2    # @0000 [9000 0203]
    mul-int/lit8 v0, v0, 0x1f    # @0002 [da00 001f]
    return v0    # @0004 [0f00]
.end method
