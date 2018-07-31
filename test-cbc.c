#include "ctaes-cbc.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>

typedef struct {
    int keysize;
    const char* key;
    const char* iv;
    int nblocks;
    const char* plain;
    const char* cipher;
} ctaes_cbc_test;

static const ctaes_cbc_test ctaes_cbc_tests[] = {
    /* AES-CBC test vectors from NIST sp800-38a. */
    {
        128, "2b7e151628aed2a6abf7158809cf4f3c", "000102030405060708090a0b0c0d0e0f", 4,
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7"
    },
    {
        192, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "000102030405060708090a0b0c0d0e0f", 4,
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        "4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd"
    },
    {
        256, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "000102030405060708090a0b0c0d0e0f", 4,
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b"
    }
};

static void from_hex(unsigned char* data, int len, const char* hex) {
    int p;
    for (p = 0; p < len; p++) {
        int v = 0;
        int n;
        for (n = 0; n < 2; n++) {
            assert((*hex >= '0' && *hex <= '9') || (*hex >= 'a' && *hex <= 'f'));
            if (*hex >= '0' && *hex <= '9') {
                v |= (*hex - '0') << (4 * (1 - n));
            } else {
                v |= (*hex - 'a' + 10) << (4 * (1 - n));
            }
            hex++;
        }
        *(data++) = v;
    }
    assert(*hex == 0);
}

int main(void) {
    int i;
    int fail = 0;
    for (i = 0; i < sizeof(ctaes_cbc_tests) / sizeof(ctaes_cbc_tests[0]); i++) {
        const ctaes_cbc_test* test = &ctaes_cbc_tests[i];
        unsigned char key[32], iv[16], plain[test->nblocks * 16], cipher[test->nblocks * 16], ciphered[test->nblocks * 16], deciphered[test->nblocks * 16];
        assert(test->keysize == 128 || test->keysize == 192 || test->keysize == 256);
        from_hex(iv, 16, test->iv);
        from_hex(plain, test->nblocks * 16, test->plain);
        from_hex(cipher, test->nblocks * 16, test->cipher);
        switch (test->keysize) {
            case 128: {
                AES128_CBC_ctx ctx;
                from_hex(key, 16, test->key);
                AES128_CBC_init(&ctx, key, iv);
                AES128_CBC_encrypt(&ctx, test->nblocks, ciphered, plain);
                AES128_CBC_init(&ctx, key, iv);
                AES128_CBC_decrypt(&ctx, test->nblocks, deciphered, cipher);
                break;
            }
            case 192: {
                AES192_CBC_ctx ctx;
                from_hex(key, 24, test->key);
                AES192_CBC_init(&ctx, key, iv);
                AES192_CBC_encrypt(&ctx, test->nblocks, ciphered, plain);
                AES192_CBC_init(&ctx, key, iv);
                AES192_CBC_decrypt(&ctx, test->nblocks, deciphered, cipher);
                break;
            }
            case 256: {
                AES256_CBC_ctx ctx;
                from_hex(key, 32, test->key);
                AES256_CBC_init(&ctx, key, iv);
                AES256_CBC_encrypt(&ctx, test->nblocks, ciphered, plain);
                AES256_CBC_init(&ctx, key, iv);
                AES256_CBC_decrypt(&ctx, test->nblocks, deciphered, cipher);
                break;
            }
        }
        if (memcmp(cipher, ciphered, test->nblocks * 16)) {
            fprintf(stderr, "E(key=\"%s\", plain=\"%s\") != \"%s\"\n", test->key, test->plain, test->cipher);
            fail++;
        }
        if (memcmp(plain, deciphered, test->nblocks * 16)) {
            fprintf(stderr, "D(key=\"%s\", cipher=\"%s\") != \"%s\"\n", test->key, test->cipher, test->plain);
            fail++;
        }
    }
    if (fail == 0) {
        fprintf(stderr, "All tests successful\n");
    } else {
        fprintf(stderr, "%i tests failed\n", fail);
    }
    return (fail != 0);
}

