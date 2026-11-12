.class public Lcom/argon/vault/NativeBridge;
.super Ljava/lang/Object;
.source "NativeBridge.java"

# direct methods
.method static constructor <clinit>()V
    .registers 1
    const-string v0, "native-vault"    # @0000 [1a00 4d00]
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V    # @0002 [7110 2100 0000]
    return-void    # @0005 [0e00]
.end method

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V    # @0000 [7010 1b00 0000]
    return-void    # @0003 [0e00]
.end method

.method public static native deriveHardwareKey(Ljava/lang/String;I)[B
.end method

.method public static native verifyDeviceIntegrity(I)Z
.end method
