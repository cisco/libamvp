/*
 * Copyright (c) 2021, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libamvp/LICENSE
 */


#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "app_lcl.h"
#include "safe_lib.h"


/* This is a public domain base64 implementation written by WEI Zhicheng. */
enum { BASE64_OK = 0, BASE64_INVALID };

#define BASE64_ENCODE_OUT_SIZE(s)    (((s) + 2) / 3 * 4)
#define BASE64_DECODE_OUT_SIZE(s)    (((s)) / 4 * 3)

#define BASE64_PAD    '='

#define BASE64DE_FIRST    '+'
#define BASE64DE_LAST    'z'

/* ASCII order for BASE 64 decode, -1 in unused character */
static const signed char base64de[] = {
    /* '+', ',', '-', '.', '/', '0', '1', '2', */
    62, -1, -1, -1, 63, 52, 53, 54,

    /* '3', '4', '5', '6', '7', '8', '9', ':', */
    55, 56, 57, 58, 59, 60, 61, -1,

    /* ';', '<', '=', '>', '?', '@', 'A', 'B', */
    -1, -1, -1, -1, -1, -1, 0,  1,

    /* 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', */
    2,  3,  4,  5,  6,  7,  8,  9,

    /* 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', */
    10, 11, 12, 13, 14, 15, 16, 17,

    /* 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', */
    18, 19, 20, 21, 22, 23, 24, 25,

    /* '[', '\', ']', '^', '_', '`', 'a', 'b', */
    -1, -1, -1, -1, -1, -1, 26, 27,

    /* 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', */
    28, 29, 30, 31, 32, 33, 34, 35,

    /* 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', */
    36, 37, 38, 39, 40, 41, 42, 43,

    /* 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', */
    44, 45, 46, 47, 48, 49, 50, 51,
};

static unsigned int
base64_decode(const char *in, unsigned int inlen, unsigned char *out) {
    unsigned int i, j;

    for (i = j = 0; i < inlen; i++) {
        int c;
        int s = i % 4;             /* from 8/gcd(6, 8) */

        if (in[i] == '=')
            return j;

        if (in[i] < BASE64DE_FIRST || in[i] > BASE64DE_LAST ||
            (c = base64de[in[i] - BASE64DE_FIRST]) == -1)
            return 0;

        switch (s) {
        case 0:
            out[j] = ((unsigned int)c << 2) & 0xFF;
            continue;
        case 1:
            out[j++] += ((unsigned int)c >> 4) & 0x3;

            /* if not last char with padding */
            if (i < (inlen - 3) || in[inlen - 2] != '=')
                out[j] = ((unsigned int)c & 0xF) << 4;
            continue;
        case 2:
            out[j++] += ((unsigned int)c >> 2) & 0xF;

            /* if not last char with padding */
            if (i < (inlen - 2) || in[inlen - 1] != '=')
                out[j] =  ((unsigned int)c & 0x3) << 6;
            continue;
        case 3:
            out[j++] += (unsigned char)c;
            continue;;
        default:
            return 0;
        }
    }

    return j;
}

const int DIGITS_POWER[]
    //  0  1   2    3     4      5       6        7         8
    = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };

#define T_LEN 8
#define MAX_LEN 512

#if OPENSSL_VERSION_NUMBER < 0x30000000L
static int hmac_totp(const char *key,
                     const unsigned char *msg,
                     char *hash,
                     int hash_max,
                     const EVP_MD *md,
                     unsigned int key_len) {
    int len = 0;
    unsigned char buff[MAX_LEN];
    HMAC_CTX *ctx;

    ctx = HMAC_CTX_new();
    HMAC_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
    if (!HMAC_Init_ex(ctx, key, key_len, md, NULL)) goto end;
    if (!HMAC_Update(ctx, msg, T_LEN)) goto end;
    if (!HMAC_Final(ctx, buff, (unsigned int *)&len)) goto end;
    memcpy_s(hash, hash_max, buff, len);

end:
    if (ctx) HMAC_CTX_free(ctx);
    return len;
}
#else
static int hmac_totp(const char *key,
                     const unsigned char *msg,
                     char *hash,
                     int hash_max,
                     const char *md_name,
                     unsigned int key_len) {
    int len = 0;
    unsigned char buff[MAX_LEN];
    EVP_Q_mac(NULL, "HMAC", NULL, md_name, NULL, key, key_len, msg, T_LEN, buff, MAX_LEN, (long unsigned int *)&len);
    memcpy_s(hash, hash_max, buff, len);
    return len;
}
#endif

static AMVP_RESULT totp(char **token, int token_max) {
    char hash[MAX_LEN] = {0};
    int os, bin, otp;
    int md_len;
    time_t t;
    unsigned char token_buff[T_LEN + 1] = {0};
    char *new_seed = NULL;
    char *seed = NULL;
    int seed_len = 0;

    seed = getenv("AMV_TOTP_SEED");
    if (!seed) {
        /* Not required to use 2-factor auth */
        return AMVP_SUCCESS;
    }

    new_seed = calloc(AMVP_TOTP_TOKEN_MAX, sizeof(char));
    if (!new_seed) {
        printf("Failed to malloc new_seed\n");
        return AMVP_MALLOC_FAIL;
    }

    t = time(NULL);

    // RFC4226
    t = t / 30;
    token_buff[0] = (t >> T_LEN * 7) & 0xff;
    token_buff[1] = (t >> T_LEN * 6) & 0xff;
    token_buff[2] = (t >> T_LEN * 5) & 0xff;
    token_buff[3] = (t >> T_LEN * 4) & 0xff;
    token_buff[4] = (t >> T_LEN * 3) & 0xff;
    token_buff[5] = (t >> T_LEN * 2) & 0xff;
    token_buff[6] = (t >> T_LEN * 1) & 0xff;
    token_buff[7] = t & 0xff;

#define MAX_SEED_LEN 64
    seed_len = base64_decode(seed, strnlen_s(seed, MAX_SEED_LEN), (unsigned char *)new_seed);
    if (seed_len  == 0) {
        printf("Failed to decode TOTP seed\n");
        free(new_seed);
        return AMVP_TOTP_FAIL;
    }


    // use passed hash function
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    md_len = hmac_totp(new_seed, token_buff, hash, sizeof(hash), EVP_sha256(), seed_len);
#else
    md_len = hmac_totp(new_seed, token_buff, hash, sizeof(hash), "SHA2-256", seed_len);
#endif
    if (md_len == 0) {
        printf("Failed to create TOTP\n");
        free(new_seed);
        return AMVP_TOTP_FAIL;
    }
    os = hash[(int)md_len - 1] & 0xf;

    bin = ((hash[os + 0] & 0x7f) << 24) |
          ((hash[os + 1] & 0xff) << 16) |
          ((hash[os + 2] & 0xff) <<  8) |
          ((hash[os + 3] & 0xff) <<  0);

    otp = bin % DIGITS_POWER[AMVP_TOTP_LENGTH];

    // generate format string like "%08d" to fix digits using 0
    sprintf((char *)token_buff, "%08d", otp);
    memcpy_s((char *)*token, token_max, token_buff, AMVP_TOTP_LENGTH);
    free(new_seed);
    return AMVP_SUCCESS;
}

int app_setup_two_factor_auth(AMVP_CTX *ctx) {
    AMVP_RESULT rv = 0;

    if (getenv("AMV_TOTP_SEED")) {
        /*
         * Specify the callback to be used for 2-FA to perform
         * TOTP calculation
         */
        rv = amvp_set_2fa_callback(ctx, &totp);
        if (rv != AMVP_SUCCESS) {
            printf("Failed to set Two-factor authentication callback\n");
            return 1;
        }
    } else {
        return 1;
    }

    return 0;
}

unsigned int swap_uint_endian(unsigned int i) {
    int a = 0, b = 0, c = 0, d = 0;
    a = (i >> 24) & 0x000000ff;
    b = (i >> 8) & 0x0000ff00;
    c = (i << 8) & 0x00ff0000;
    d = (i << 24) & 0xff000000;
	return (a | b | c | d);
}

int check_is_little_endian() {
    short int n = 1;
    char *ptr = (char *)&n;
    if (ptr[0] == 1) {
        return 1;
    }
    return 0;
}
char *remove_str_const(const char *str) {
    int len = 0;
    char *ret = NULL;
    len = strnlen_s(str, ALG_STR_MAX_LEN + 1);
    if (len > ALG_STR_MAX_LEN) {
        printf("Alg string too long\n");
        return NULL;
    }

    ret = calloc(len + 1, sizeof(char));
    if (!ret) {
        printf("Error allocating memory when removing const from str\n");
        return NULL;
    }

    if (strncpy_s(ret, len + 1, str, len)) {
        printf("Error copying string to non-const buffer\n");
        free(ret);
        return NULL;
    }

    return ret;
}

int save_string_to_file(const char *str, const char *path) {
    int rv = 1;

    if (!str) {
        return 1;
    }

    FILE *fp = NULL;
    fp = fopen(path, "w");
    if (!fp) {
        return 1;
    }

    if (fputs(str, fp) == EOF) {
        goto end;
    }

    rv = 0;
 end:
    if (fp && fclose(fp) == EOF) {
        printf("Encountered an error attempting to close output file. Cannot guarantee file integrity.\n");
    }
    return rv;
}
