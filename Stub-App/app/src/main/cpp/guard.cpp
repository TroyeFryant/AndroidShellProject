#include <jni.h>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include "anti_debug.h"

// ╔════════════════════════════════════════════════════════════╗
// ║  自实现 AES-128-CBC 解密（无外部依赖，与 PC 端 Java 对称）   ║
// ╚════════════════════════════════════════════════════════════╝

static const int AES_BLOCK_SIZE = 16;
static const int AES_KEY_SIZE   = 16;
static const int AES_ROUNDS     = 10;

static const uint8_t DEFAULT_KEY[AES_KEY_SIZE] = {
    0x53, 0x68, 0x65, 0x6C, 0x6C, 0x50, 0x72, 0x6F,
    0x74, 0x65, 0x63, 0x74, 0x30, 0x31, 0x32, 0x33
};

// ── AES 查找表 ──────────────────────────────────────────────

static const uint8_t SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t INV_SBOX[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static const uint8_t RCON[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// ── GF(2^8) 乘法 ───────────────────────────────────────────

static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

// ── 密钥扩展 ────────────────────────────────────────────────

static void aes_key_expansion(const uint8_t key[AES_KEY_SIZE],
                              uint8_t roundKeys[176]) {
    memcpy(roundKeys, key, AES_KEY_SIZE);

    uint8_t temp[4];
    int bytesGenerated = AES_KEY_SIZE;
    int rconIdx = 0;

    while (bytesGenerated < 176) {
        memcpy(temp, roundKeys + bytesGenerated - 4, 4);

        if (bytesGenerated % AES_KEY_SIZE == 0) {
            uint8_t t = temp[0];
            temp[0] = temp[1]; temp[1] = temp[2];
            temp[2] = temp[3]; temp[3] = t;
            for (int i = 0; i < 4; ++i) temp[i] = SBOX[temp[i]];
            temp[0] ^= RCON[rconIdx++];
        }

        for (int i = 0; i < 4; ++i) {
            roundKeys[bytesGenerated] =
                roundKeys[bytesGenerated - AES_KEY_SIZE] ^ temp[i];
            ++bytesGenerated;
        }
    }
}

// ── AES 单块解密 ───────────────────────────────────────────

static void inv_sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; ++i) state[i] = INV_SBOX[state[i]];
}

static void inv_shift_rows(uint8_t s[16]) {
    uint8_t t;
    t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
    t = s[2]; s[2] = s[10]; s[10] = t;
    t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
}

static void inv_mix_columns(uint8_t s[16]) {
    for (int c = 0; c < 4; ++c) {
        int i = c * 4;
        uint8_t a0 = s[i], a1 = s[i+1], a2 = s[i+2], a3 = s[i+3];
        s[i  ] = gmul(a0,0x0e) ^ gmul(a1,0x0b) ^ gmul(a2,0x0d) ^ gmul(a3,0x09);
        s[i+1] = gmul(a0,0x09) ^ gmul(a1,0x0e) ^ gmul(a2,0x0b) ^ gmul(a3,0x0d);
        s[i+2] = gmul(a0,0x0d) ^ gmul(a1,0x09) ^ gmul(a2,0x0e) ^ gmul(a3,0x0b);
        s[i+3] = gmul(a0,0x0b) ^ gmul(a1,0x0d) ^ gmul(a2,0x09) ^ gmul(a3,0x0e);
    }
}

static void add_round_key(uint8_t state[16], const uint8_t *rk) {
    for (int i = 0; i < 16; ++i) state[i] ^= rk[i];
}

static void aes_decrypt_block(const uint8_t in[16], uint8_t out[16],
                              const uint8_t roundKeys[176]) {
    uint8_t state[16];
    memcpy(state, in, 16);

    add_round_key(state, roundKeys + AES_ROUNDS * 16);

    for (int r = AES_ROUNDS - 1; r >= 1; --r) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, roundKeys + r * 16);
        inv_mix_columns(state);
    }

    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, roundKeys);

    memcpy(out, state, 16);
}

// ╔════════════════════════════════════════════════════════════╗
// ║  自实现 SHA-256 + HMAC-SHA256（密文完整性校验）              ║
// ╚════════════════════════════════════════════════════════════╝

static const uint32_t SHA256_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define SHA_ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define SHA_CH(x,y,z) (((x)&(y))^((~(x))&(z)))
#define SHA_MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define SHA_EP0(x) (SHA_ROTR(x,2)^SHA_ROTR(x,13)^SHA_ROTR(x,22))
#define SHA_EP1(x) (SHA_ROTR(x,6)^SHA_ROTR(x,11)^SHA_ROTR(x,25))
#define SHA_SIG0(x) (SHA_ROTR(x,7)^SHA_ROTR(x,18)^((x)>>3))
#define SHA_SIG1(x) (SHA_ROTR(x,17)^SHA_ROTR(x,19)^((x)>>10))

static void sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    uint32_t h0=0x6a09e667, h1=0xbb67ae85, h2=0x3c6ef372, h3=0xa54ff53a;
    uint32_t h4=0x510e527f, h5=0x9b05688c, h6=0x1f83d9ab, h7=0x5be0cd19;

    size_t bitLen = len * 8;
    size_t padLen = ((len % 64 < 56) ? 56 : 120) - (len % 64);
    size_t totalLen = len + padLen + 8;

    auto *msg = static_cast<uint8_t *>(calloc(totalLen, 1));
    memcpy(msg, data, len);
    msg[len] = 0x80;
    for (int i = 0; i < 8; i++) msg[totalLen - 1 - i] = (uint8_t)(bitLen >> (i * 8));

    for (size_t offset = 0; offset < totalLen; offset += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = ((uint32_t)msg[offset+i*4]<<24)|((uint32_t)msg[offset+i*4+1]<<16)|
                   ((uint32_t)msg[offset+i*4+2]<<8)|msg[offset+i*4+3];
        for (int i = 16; i < 64; i++)
            w[i] = SHA_SIG1(w[i-2]) + w[i-7] + SHA_SIG0(w[i-15]) + w[i-16];

        uint32_t a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
        for (int i = 0; i < 64; i++) {
            uint32_t t1 = h + SHA_EP1(e) + SHA_CH(e,f,g) + SHA256_K[i] + w[i];
            uint32_t t2 = SHA_EP0(a) + SHA_MAJ(a,b,c);
            h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h0+=a; h1+=b; h2+=c; h3+=d; h4+=e; h5+=f; h6+=g; h7+=h;
    }
    free(msg);

    uint32_t hh[8] = {h0,h1,h2,h3,h4,h5,h6,h7};
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(hh[i]>>24);
        out[i*4+1] = (uint8_t)(hh[i]>>16);
        out[i*4+2] = (uint8_t)(hh[i]>>8);
        out[i*4+3] = (uint8_t)(hh[i]);
    }
}

static void hmac_sha256(const uint8_t *key, int keyLen,
                        const uint8_t *data, int dataLen,
                        uint8_t out[32]) {
    uint8_t kpad[64];
    memset(kpad, 0, 64);
    if (keyLen > 64) {
        sha256(key, keyLen, kpad);
    } else {
        memcpy(kpad, key, keyLen);
    }

    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = kpad[i] ^ 0x36;
        opad[i] = kpad[i] ^ 0x5c;
    }

    size_t innerLen = 64 + dataLen;
    auto *inner = static_cast<uint8_t *>(malloc(innerLen));
    memcpy(inner, ipad, 64);
    memcpy(inner + 64, data, dataLen);
    uint8_t innerHash[32];
    sha256(inner, innerLen, innerHash);
    memset(inner, 0, innerLen);
    free(inner);

    uint8_t outer[64 + 32];
    memcpy(outer, opad, 64);
    memcpy(outer + 64, innerHash, 32);
    sha256(outer, 96, out);
    memset(kpad, 0, 64);
}

static int constant_time_compare(const uint8_t *a, const uint8_t *b, int len) {
    uint8_t result = 0;
    for (int i = 0; i < len; i++) result |= a[i] ^ b[i];
    return result == 0;
}

// ── AES-128-CBC 解密 + PKCS7 去填充 ────────────────────────

static const int HMAC_SIZE = 32;

static uint8_t *aes_cbc_decrypt(const uint8_t *data, int dataLen,
                                const uint8_t *key, int *outLen) {
    if (dataLen < AES_BLOCK_SIZE + AES_BLOCK_SIZE + HMAC_SIZE) {
        return nullptr;
    }

    int payloadLen = dataLen - HMAC_SIZE;
    const uint8_t *expectedHmac = data + payloadLen;

    const uint8_t *useKey = key ? key : DEFAULT_KEY;

    uint8_t computedHmac[32];
    hmac_sha256(useKey, AES_KEY_SIZE, data, payloadLen, computedHmac);
    if (!constant_time_compare(expectedHmac, computedHmac, HMAC_SIZE)) {
        return nullptr;
    }

    if ((payloadLen - AES_BLOCK_SIZE) % AES_BLOCK_SIZE != 0) {
        return nullptr;
    }

    const uint8_t *iv         = data;
    const uint8_t *ciphertext = data + AES_BLOCK_SIZE;
    int cipherLen             = payloadLen - AES_BLOCK_SIZE;
    int blockCount            = cipherLen / AES_BLOCK_SIZE;

    uint8_t roundKeys[176];
    aes_key_expansion(useKey, roundKeys);

    auto *plain = static_cast<uint8_t *>(malloc(cipherLen));
    if (!plain) return nullptr;

    uint8_t prevBlock[AES_BLOCK_SIZE];
    memcpy(prevBlock, iv, AES_BLOCK_SIZE);

    for (int b = 0; b < blockCount; ++b) {
        const uint8_t *src = ciphertext + b * AES_BLOCK_SIZE;
        uint8_t *dst       = plain      + b * AES_BLOCK_SIZE;

        aes_decrypt_block(src, dst, roundKeys);

        for (int i = 0; i < AES_BLOCK_SIZE; ++i) dst[i] ^= prevBlock[i];

        memcpy(prevBlock, src, AES_BLOCK_SIZE);
    }

    // 清除栈上的轮密钥
    memset(roundKeys, 0, sizeof(roundKeys));

    uint8_t pad = plain[cipherLen - 1];
    if (pad == 0 || pad > AES_BLOCK_SIZE) {
        free(plain);
        return nullptr;
    }
    for (int i = 0; i < pad; ++i) {
        if (plain[cipherLen - 1 - i] != pad) {
            free(plain);
            return nullptr;
        }
    }

    *outLen = cipherLen - pad;
    return plain;
}

// ╔════════════════════════════════════════════════════════════╗
// ║  JNI 实现                                                  ║
// ╚════════════════════════════════════════════════════════════╝

static jbyteArray nativeDecryptDex(JNIEnv *env, jobject /* thiz */,
                                   jbyteArray jData, jbyteArray jKey) {
    if (!jData) return nullptr;

    jint dataLen = env->GetArrayLength(jData);
    auto *data = reinterpret_cast<uint8_t *>(env->GetByteArrayElements(jData, nullptr));

    uint8_t *keyBytes = nullptr;
    if (jKey && env->GetArrayLength(jKey) == AES_KEY_SIZE) {
        keyBytes = reinterpret_cast<uint8_t *>(env->GetByteArrayElements(jKey, nullptr));
    }

    int plainLen = 0;
    uint8_t *plain = aes_cbc_decrypt(data, dataLen, keyBytes, &plainLen);

    env->ReleaseByteArrayElements(jData, reinterpret_cast<jbyte *>(data), JNI_ABORT);
    if (keyBytes) {
        memset(keyBytes, 0, AES_KEY_SIZE);
        env->ReleaseByteArrayElements(jKey, reinterpret_cast<jbyte *>(keyBytes), 0);
    }

    if (!plain) return nullptr;

    jbyteArray result = env->NewByteArray(plainLen);
    env->SetByteArrayRegion(result, 0, plainLen, reinterpret_cast<jbyte *>(plain));

    memset(plain, 0, plainLen);
    free(plain);

    return result;
}

static void nativeInitAntiDebug(JNIEnv * /* env */, jobject /* thiz */) {
    start_anti_debug();
}

static void nativeTimingCheck(JNIEnv *, jobject) {
    timing_check_end();
    timing_check_begin();
}

// ── JNI 动态注册 & JNI_OnLoad ───────────────────────────────

static const JNINativeMethod METHODS[] = {
    {"decryptDex",    "([B[B)[B", reinterpret_cast<void *>(nativeDecryptDex)},
    {"initAntiDebug", "()V",      reinterpret_cast<void *>(nativeInitAntiDebug)},
    {"timingCheck",   "()V",      reinterpret_cast<void *>(nativeTimingCheck)}
};

static const char *CLASS_PROXY_APP = "com/shell/stub/ProxyApplication";

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void * /* reserved */) {
    JNIEnv *env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    jclass clazz = env->FindClass(CLASS_PROXY_APP);
    if (!clazz) return JNI_ERR;

    if (env->RegisterNatives(clazz, METHODS,
                             sizeof(METHODS) / sizeof(METHODS[0])) < 0) {
        return JNI_ERR;
    }

    start_anti_debug();

    return JNI_VERSION_1_6;
}
