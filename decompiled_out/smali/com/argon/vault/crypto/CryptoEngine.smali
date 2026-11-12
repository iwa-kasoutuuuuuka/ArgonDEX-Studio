.class public Lcom/argon/vault/crypto/CryptoEngine;
.super Ljava/lang/Object;
.source "CryptoEngine.java"

# direct methods
.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V    # @0000 [7010 1b00 0000]
    return-void    # @0003 [0e00]
.end method

# virtual methods
.method public computeRollingHash(II)I
    .registers 5
    const/4 v0, 0x0    # @0000 [1200]
    move v1, p1    # @0001 [0131]
    :goto_2
    if-ge v0, p2, :cond_a    # @0002 [3540 0800]
    mul-int/lit8 v1, v1, 0x1f    # @0004 [da01 011f]
    xor-int/2addr v1, v0    # @0006 [b701]
    add-int/lit8 v0, v0, 0x1    # @0007 [d800 0001]
    goto :goto_2    # @0009 [28f9]
    :cond_a
    return v1    # @000a [0f01]
.end method

.method public encryptPayload(Ljava/lang/String;)[B
    .registers 4
    const-string v0, "AES/ECB/PKCS5Padding"    # @0000 [1a00 0300]
    invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;    # @0002 [7110 2300 0000]
    move-result-object v0    # @0005 [0c00]
    const-string v1, "MD5"    # @0006 [1a01 2800]
    invoke-static {v1}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;    # @0008 [7110 2200 0100]
    move-result-object v1    # @000b [0c01]
    const/16 v1, 0x100    # @000c [1301 0001]
    invoke-static {p1, v1}, Lcom/argon/vault/NativeBridge;->deriveHardwareKey(Ljava/lang/String;I)[B    # @000e [7120 0f00 1300]
    move-result-object v1    # @0011 [0c01]
    return-object v1    # @0012 [1101]
.end method
