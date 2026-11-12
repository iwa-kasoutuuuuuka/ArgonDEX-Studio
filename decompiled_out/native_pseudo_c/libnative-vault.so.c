/*
 * ArgonDEX Studio — ARM64 (AArch64) to Pseudo-C Native Decompiler
 * Binary: lib/arm64-v8a/libnative-vault.so (ARM64 (AArch64))
 */
#include <jni.h>
#include <stdint.h>

// @vaddr 0x00001000
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm /* x0 */, void* reserved /* x1 */) {
    return 0x10006 /* JNI_VERSION_1_6 */;
}

// @vaddr 0x00001010
JNIEXPORT uint64_t JNICALL Java_com_argon_vault_NativeBridge_deriveHardwareKey(JNIEnv* env /* x0 */, jobject thiz /* x1 */, uint64_t arg0 /* x2 */, uint64_t arg1 /* x3 */) {
    uint64_t x19 = env;
    uint64_t x20 = arg0;
    uint64_t v_1020 = (x19 ^ x20);
    uint64_t call_1024 = sub_1034_internal(v_1020, thiz);
    return call_1024;
}

// @vaddr 0x00001030
JNIEXPORT uint64_t JNICALL Java_com_argon_vault_NativeBridge_verifyDeviceIntegrity(JNIEnv* env /* x0 */, jobject thiz /* x1 */, uint64_t arg0 /* x2 */, uint64_t arg1 /* x3 */) {
    return env;
}

// @vaddr 0x00001034
static uint64_t sub_1034_internal(uint64_t a0 /* x0 */, uint64_t a1 /* x1 */) {
    uint64_t v_1038 = (0x1 + 0x1);
    uint64_t v_103c = (v_1038 - 0x1);
    return v_103c;
}
