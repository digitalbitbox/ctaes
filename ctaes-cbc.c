#include "ctaes-cbc.h"

static void Xor128(uint8_t* buf1, const uint8_t* buf2) {
    int i;
    for (i = 0; i < 16; i++) {
        buf1[i] ^= buf2[i];
    }
}

static void AESCBC_encrypt(const AES_state* rounds, uint8_t* iv, int nk, size_t blocks, unsigned char* encrypted, const unsigned char* plain) {
    size_t i, j;
    unsigned char buf[16];

    for (i = 0; i < blocks; i++) {
        for (j = 0; j < 16; j++) {
            buf[j] = *(plain++);
        }
        Xor128(buf, iv);
        AES_encrypt(rounds, nk, encrypted, buf);
        for (j = 0; j < 16; j++) {
            iv[j] = encrypted[j];
        }
        encrypted += 16;
    }
}

static void AESCBC_decrypt(const AES_state* rounds, uint8_t* iv, int nk, size_t blocks, unsigned char* plain, const unsigned char* encrypted) {
    size_t i, j;
    uint8_t next_iv[16];

    for (i = 0; i < blocks; i++) {
        for (j = 0; j < 16; j++) {
            next_iv[j] = encrypted[j];
        }
        AES_decrypt(rounds, nk, plain, encrypted);
        Xor128(plain, iv);
        for (j = 0; j < 16; j++) {
            iv[j] = next_iv[j];
        }
        plain += 16;
        encrypted += 16;
    }
}

void AES128_CBC_init(AES128_CBC_ctx* ctx, const unsigned char* key16, const uint8_t* iv) {
    size_t i;
    AES128_init(&(ctx->ctx), key16);
    for (i = 0; i < 16; i++) {
        ctx->iv[i] = iv[i];
    }
}

void AES192_CBC_init(AES192_CBC_ctx* ctx, const unsigned char* key16, const uint8_t* iv) {
    size_t i;
    AES192_init(&(ctx->ctx), key16);
    for (i = 0; i < 16; i++) {
        ctx->iv[i] = iv[i];
    }
}

void AES256_CBC_init(AES256_CBC_ctx* ctx, const unsigned char* key16, const uint8_t* iv) {
    size_t i;
    AES256_init(&(ctx->ctx), key16);
    for (i = 0; i < 16; i++) {
        ctx->iv[i] = iv[i];
    }
}

void AES128_CBC_encrypt(AES128_CBC_ctx* ctx, size_t blocks, unsigned char* encrypted, const unsigned char* plain) {
    AESCBC_encrypt(ctx->ctx.rk, ctx->iv, 10, blocks, encrypted, plain);
}

void AES128_CBC_decrypt(AES128_CBC_ctx* ctx, size_t blocks, unsigned char* plain, const unsigned char *encrypted) {
    AESCBC_decrypt(ctx->ctx.rk, ctx->iv, 10, blocks, plain, encrypted);
}

void AES192_CBC_encrypt(AES192_CBC_ctx* ctx, size_t blocks, unsigned char* encrypted, const unsigned char* plain) {
    AESCBC_encrypt(ctx->ctx.rk, ctx->iv, 12, blocks, encrypted, plain);
}

void AES192_CBC_decrypt(AES192_CBC_ctx* ctx, size_t blocks, unsigned char* plain, const unsigned char *encrypted) {
    AESCBC_decrypt(ctx->ctx.rk, ctx->iv, 12, blocks, plain, encrypted);
}

void AES256_CBC_encrypt(AES256_CBC_ctx* ctx, size_t blocks, unsigned char* encrypted, const unsigned char* plain) {
    AESCBC_encrypt(ctx->ctx.rk, ctx->iv, 14, blocks, encrypted, plain);
}

void AES256_CBC_decrypt(AES256_CBC_ctx* ctx, size_t blocks, unsigned char* plain, const unsigned char *encrypted) {
    AESCBC_decrypt(ctx->ctx.rk, ctx->iv, 14, blocks, plain, encrypted);
}

