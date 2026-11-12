.class public Lcom/argon/vault/db/VaultDatabase;
.super Ljava/lang/Object;
.source "VaultDatabase.java"

# direct methods
.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V    # @0000 [7010 1b00 0000]
    return-void    # @0003 [0e00]
.end method

# virtual methods
.method public queryVaultSecret(Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;)Landroid/database/Cursor;
    .registers 6
    new-instance v0, Ljava/lang/StringBuilder;    # @0000 [2200 1100]
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V    # @0002 [7010 1e00 0000]
    const-string v1, "SELECT secret_blob FROM vault_items WHERE owner = '"    # @0005 [1a01 2c00]
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;    # @0007 [6e20 1f00 1000]
    move-result-object v0    # @000a [0c00]
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;    # @000b [6e20 1f00 5000]
    move-result-object v0    # @000e [0c00]
    const-string v1, "' AND status = 1"    # @000f [1a01 0000]
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;    # @0011 [6e20 1f00 1000]
    move-result-object v0    # @0014 [0c00]
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;    # @0015 [6e10 2000 0000]
    move-result-object v0    # @0018 [0c00]
    const/4 v1, 0x0    # @0019 [1201]
    invoke-virtual {p1, v0, v1}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;    # @001a [6e30 0300 0401]
    move-result-object v2    # @001d [0c02]
    return-object v2    # @001e [1102]
.end method
