#ifndef _CTAES_CBC_H_
#define _CTAES_CBC_H_ 1

#include "ctaes.h"

typedef struct {
    AES128_ctx ctx;
    uint8_t iv[16];
} AES128_CBC_ctx;

typedef struct {
    AES192_ctx ctx;
    uint8_t iv[16];
} AES192_CBC_ctx;

typedef struct {
    AES256_ctx ctx;
    uint8_t iv[16];
} AES256_CBC_ctx;

void AES128_CBC_init(AES128_CBC_ctx* ctx, const unsigned char* key16, const uint8_t* iv);
void AES128_CBC_encrypt(AES128_CBC_ctx* ctx, size_t blocks, unsigned char* encrypted, const unsigned char* plain);
void AES128_CBC_decrypt(AES128_CBC_ctx* ctx, size_t blocks, unsigned char* plain, const unsigned char *encrypted);

void AES192_CBC_init(AES192_CBC_ctx* ctx, const unsigned char* key16, const uint8_t* iv);
void AES192_CBC_encrypt(AES192_CBC_ctx* ctx, size_t blocks, unsigned char* encrypted, const unsigned char* plain);
void AES192_CBC_decrypt(AES192_CBC_ctx* ctx, size_t blocks, unsigned char* plain, const unsigned char *encrypted);

void AES256_CBC_init(AES256_CBC_ctx* ctx, const unsigned char* key16, const uint8_t* iv);
void AES256_CBC_encrypt(AES256_CBC_ctx* ctx, size_t blocks, unsigned char* encrypted, const unsigned char* plain);
void AES256_CBC_decrypt(AES256_CBC_ctx* ctx, size_t blocks, unsigned char* plain, const unsigned char *encrypted);

#endif
