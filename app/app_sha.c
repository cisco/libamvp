/*
 * Copyright (c) 2021, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libacvp/LICENSE
 */


#include <openssl/evp.h>

#include "amvp/amvp.h"
#include "app_lcl.h"
#ifdef AMVP_NO_RUNTIME
# include "app_fips_lcl.h"
#endif

int app_sha_handler(AMVP_TEST_CASE *test_case) {
    AMVP_HASH_TC    *tc;
    const EVP_MD    *md;
    EVP_MD_CTX *md_ctx = NULL;
    /* assume fail */
    int rc = 1;
    int sha3 = 0, shake = 0;
    AMVP_SUB_HASH alg;

    if (!test_case) {
        return 1;
    }

    tc = test_case->tc.hash;
    if (!tc) return rc;

    alg = amvp_get_hash_alg(tc->cipher);
    if (alg == 0) {
        printf("Invalid cipher value");
        return 1;
    }

    switch (alg) {
    case AMVP_SUB_HASH_SHA1:
        md = EVP_sha1();
        break;
    case AMVP_SUB_HASH_SHA2_224:
        md = EVP_sha224();
        break;
    case AMVP_SUB_HASH_SHA2_256:
        md = EVP_sha256();
        break;
    case AMVP_SUB_HASH_SHA2_384:
        md = EVP_sha384();
        break;
    case AMVP_SUB_HASH_SHA2_512:
        md = EVP_sha512();
        break;
#if (!defined AMVP_NO_RUNTIME && OPENSSL_VERSION_NUMBER >= 0x10101010L) || (FIPS_MODULE_VERSION_NUMBER >= 0x70000002L)
    case AMVP_SUB_HASH_SHA2_512_224:
        md = EVP_sha512_224();
        break;
    case AMVP_SUB_HASH_SHA2_512_256:
        md = EVP_sha512_256();
        break;
    case AMVP_SUB_HASH_SHA3_224:
        md = EVP_sha3_224();
        sha3 = 1;
        break;
    case AMVP_SUB_HASH_SHA3_256:
        md = EVP_sha3_256();
        sha3 = 1;
        break;
    case AMVP_SUB_HASH_SHA3_384:
        md = EVP_sha3_384();
        sha3 = 1;
        break;
    case AMVP_SUB_HASH_SHA3_512:
        md = EVP_sha3_512();
        sha3 = 1;
        break;
    case AMVP_SUB_HASH_SHAKE_128:
        md = EVP_shake128();
        shake = 1;
        break;
    case AMVP_SUB_HASH_SHAKE_256:
        md = EVP_shake256();
        shake = 1;
        break;
#else
    case AMVP_SUB_HASH_SHA2_512_224:
    case AMVP_SUB_HASH_SHA2_512_256:
    case AMVP_SUB_HASH_SHA3_224:
    case AMVP_SUB_HASH_SHA3_256:
    case AMVP_SUB_HASH_SHA3_384:
    case AMVP_SUB_HASH_SHA3_512:
    case AMVP_SUB_HASH_SHAKE_128:
    case AMVP_SUB_HASH_SHAKE_256:
#endif
    default:
        printf("Error: Unsupported hash algorithm requested by AMVP server\n");
        return AMVP_NO_CAP;
    }

    if (!tc->md) {
        printf("\nCrypto module error, md memory not allocated by library\n");
        goto end;
    }
    md_ctx = EVP_MD_CTX_create();

    if (tc->test_type == AMVP_HASH_TEST_TYPE_MCT && !sha3 && !shake) {
        /* If Monte Carlo we need to be able to init and then update
         * one thousand times before we complete each iteration.
         * This style doesn't apply to sha3 MCT.
         */
        if (!tc->m1 || !tc->m2 || !tc->m3) {
            printf("\nCrypto module error, m1, m2, or m3 missing in sha mct test case\n");
            goto end;
        }
        if (!EVP_DigestInit_ex(md_ctx, md, NULL)) {
            printf("\nCrypto module error, EVP_DigestInit_ex failed\n");
            goto end;
        }
        if (!EVP_DigestUpdate(md_ctx, tc->m1, tc->msg_len)) {
            printf("\nCrypto module error, EVP_DigestUpdate failed\n");
            goto end;
        }
        if (!EVP_DigestUpdate(md_ctx, tc->m2, tc->msg_len)) {
            printf("\nCrypto module error, EVP_DigestUpdate failed\n");
            goto end;
        }
        if (!EVP_DigestUpdate(md_ctx, tc->m3, tc->msg_len)) {
            printf("\nCrypto module error, EVP_DigestUpdate failed\n");
            goto end;
        }
        if (!EVP_DigestFinal(md_ctx, tc->md, &tc->md_len)) {
            printf("\nCrypto module error, EVP_DigestFinal failed\n");
            goto end;
        }
    } else {
        if (!tc->msg) {
            printf("\nCrypto module error, msg missing in sha test case\n");
            goto end;
        }
        if (!EVP_DigestInit_ex(md_ctx, md, NULL)) {
            printf("\nCrypto module error, EVP_DigestInit_ex failed\n");
            goto end;
        }

        if (!EVP_DigestUpdate(md_ctx, tc->msg, tc->msg_len)) {
            printf("\nCrypto module error, EVP_DigestUpdate failed\n");
            goto end;
        }

#if OPENSSL_VERSION_NUMBER >= 0x10101010L /* OpenSSL 1.1.1 or greater */
        if (tc->test_type == AMVP_HASH_TEST_TYPE_VOT ||
            (tc->test_type == AMVP_HASH_TEST_TYPE_MCT && shake)) {
            /*
             * Use the XOF oriented function.
             * Skip past the other "EVP_DigestFinal".
             */
            if (!EVP_DigestFinalXOF(md_ctx, tc->md, tc->xof_len)) {
                printf("\nCrypto module error, EVP_DigestFinal failed\n");
                goto end;
            }
            tc->md_len = tc->xof_len;
            rc = 0;
            goto end;
        }
#endif

        if (!EVP_DigestFinal(md_ctx, tc->md, &tc->md_len)) {
            printf("\nCrypto module error, EVP_DigestFinal failed\n");
            goto end;
        }
    }

    rc = 0;

end:
    if (md_ctx) EVP_MD_CTX_destroy(md_ctx);

    return rc;
}

