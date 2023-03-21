/** @file */
/*
 * Copyright (c) 2019, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libamvp/LICENSE
 */

//
// Created by edaw on 2019-01-07.
//

#if OPENSSL_VERSION_NUMBER >= 0x30000000L

#include "ut_common.h"
#include "app_common.h"
#include "amvp/amvp_lcl.h"

AMVP_CTX *ctx;
AMVP_TEST_CASE *test_case;
AMVP_ECDSA_TC *ecdsa_tc;
AMVP_RESULT rv;

int initialize_ecdsa_tc(AMVP_CIPHER cipher,
                        AMVP_ECDSA_TC *stc,
                        AMVP_EC_CURVE curve,
                        AMVP_ECDSA_SECRET_GEN_MODE secret_gen_mode,
                        AMVP_HASH_ALG hash_alg,
                        char *qx,
                        char *qy,
                        char *message,
                        char *r,
                        char *s,
                        int corrupt) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    
    memset(stc, 0x0, sizeof(AMVP_ECDSA_TC));
    
    stc->cipher = cipher;
    stc->hash_alg = hash_alg;
    stc->curve = curve;
    stc->secret_gen_mode = secret_gen_mode;
    
    if (qx) {
        stc->qx = calloc(AMVP_RSA_EXP_LEN_MAX, sizeof(char));
        if (!stc->qx) { goto err; }
    }
    if (qy) {
        stc->qy = calloc(AMVP_RSA_EXP_LEN_MAX, sizeof(char));
        if (!stc->qy) { goto err; }
    }
    if (s) {
        stc->s = calloc(AMVP_RSA_EXP_LEN_MAX, sizeof(char));
        if (!stc->s) { goto err; }
    }
    if (r) {
        stc->r = calloc(AMVP_RSA_EXP_LEN_MAX, sizeof(char));
        if (!stc->r) { goto err; }
    }
    if (message) {
        stc->message = calloc(AMVP_RSA_EXP_LEN_MAX, sizeof(char));
        if (!stc->message) { goto err; }
    }
    
    if (cipher == AMVP_ECDSA_KEYVER || cipher == AMVP_ECDSA_SIGVER) {
        if (qx) {
            rv = amvp_hexstr_to_bin(qx, stc->qx, AMVP_RSA_EXP_LEN_MAX, &(stc->qx_len));
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("Hex conversion failure (qx)");
                goto err;
            }
        }
        if (qy) {
            rv = amvp_hexstr_to_bin(qy, stc->qy, AMVP_RSA_EXP_LEN_MAX, &(stc->qy_len));
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("Hex conversion failure (qy)");
                goto err;
            }
        }
    }
    if (cipher == AMVP_ECDSA_SIGVER) {
        if (r) {
            rv = amvp_hexstr_to_bin(r, stc->r, AMVP_RSA_EXP_LEN_MAX, &(stc->r_len));
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("Hex conversion failure (r)");
                goto err;
            }
        }
        if (s) {
            rv = amvp_hexstr_to_bin(s, stc->s, AMVP_RSA_EXP_LEN_MAX, &(stc->s_len));
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("Hex conversion failure (s)");
                goto err;
            }
        }
    }
    if (cipher == AMVP_ECDSA_SIGVER || cipher == AMVP_ECDSA_SIGGEN) {
        if (message) {
            rv = amvp_hexstr_to_bin(message, stc->message, AMVP_RSA_MSGLEN_MAX, &(stc->msg_len));
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("Hex conversion failure (message)");
                goto err;
            }
        }
    }
    
    return 1;
    
err:
    AMVP_LOG_ERR("Failed to allocate buffer in ECDSA test case");
    if (stc->qx) free(stc->qx);
    if (stc->qy) free(stc->qy);
    if (stc->r) free(stc->r);
    if (stc->s) free(stc->s);
    if (stc->d) free(stc->d);
    if (stc->message) free(stc->message);
    
    return 0;
}

void free_ecdsa_tc(AMVP_ECDSA_TC *stc) {
    if (stc->qy) { free(stc->qy); }
    if (stc->qx) { free(stc->qx); }
    if (stc->d) { free(stc->d); }
    if (stc->r) { free(stc->r); }
    if (stc->s) { free(stc->s); }
    if (stc->message) { free(stc->message); }
    memset(stc, 0x0, sizeof(AMVP_ECDSA_TC));
}

// cipher, ecdsa tc, curve, secret gen mode, hash_alg, qx, qy, message, r, s, corrupt

/*
 * missing ec curve in ecdsa tc test case
 */
Test(APP_ECDSA_HANDLER, missing_curve_app) {
    ecdsa_tc = calloc(1, sizeof(AMVP_ECDSA_TC));
    
    if (!initialize_ecdsa_tc(AMVP_ECDSA_KEYGEN, ecdsa_tc, 0, AMVP_ECDSA_SECRET_GEN_EXTRA_BITS, AMVP_SHA256,
                             NULL, NULL, NULL, NULL, NULL, 0)) {
        cr_assert_fail("hash init tc failure");
    }
    test_case = calloc(1, sizeof(AMVP_TEST_CASE));
    test_case->tc.ecdsa = ecdsa_tc;
    
    rv = app_ecdsa_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_ecdsa_tc(ecdsa_tc);
    free(test_case);
    free(ecdsa_tc);
}

/*
 * hash alg in ecdsa tc test case
 */
Test(APP_ECDSA_HANDLER, missing_hash_alg_app) {
    ecdsa_tc = calloc(1, sizeof(AMVP_ECDSA_TC));
    
    if (!initialize_ecdsa_tc(AMVP_ECDSA_SIGGEN, ecdsa_tc, AMVP_EC_CURVE_P256, AMVP_ECDSA_SECRET_GEN_EXTRA_BITS, 0,
        NULL, NULL, NULL, NULL, NULL, 0)) {
        cr_assert_fail("hash init tc failure");
    }
    test_case = calloc(1, sizeof(AMVP_TEST_CASE));
    test_case->tc.ecdsa = ecdsa_tc;
    
    rv = app_ecdsa_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_ecdsa_tc(ecdsa_tc);
    free(test_case);
    free(ecdsa_tc);
}

/*
 * missing qx or qy in keyver in ecdsa tc test case
 */
Test(APP_ECDSA_HANDLER, missing_keyver_qx_qy) {
    ecdsa_tc = calloc(1, sizeof(AMVP_ECDSA_TC));
    char qx[] = "aaaa";
    char qy[] = "aaaa";
    
    /* both are missing */
    if (!initialize_ecdsa_tc(AMVP_ECDSA_KEYVER, ecdsa_tc, AMVP_EC_CURVE_P256, AMVP_ECDSA_SECRET_GEN_EXTRA_BITS, 0,
        NULL, NULL, NULL, NULL, NULL, 0)) {
        cr_assert_fail("hash init tc failure");
    }
    test_case = calloc(1, sizeof(AMVP_TEST_CASE));
    test_case->tc.ecdsa = ecdsa_tc;
    
    rv = app_ecdsa_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_ecdsa_tc(ecdsa_tc);
    if (test_case) free(test_case);

    /* qy is missing */
    if (!initialize_ecdsa_tc(AMVP_ECDSA_KEYVER, ecdsa_tc, AMVP_EC_CURVE_P256, AMVP_ECDSA_SECRET_GEN_EXTRA_BITS, 0,
        qx, NULL, NULL, NULL, NULL, 0)) {
        cr_assert_fail("hash init tc failure");
    }
    test_case = calloc(1, sizeof(AMVP_TEST_CASE));
    test_case->tc.ecdsa = ecdsa_tc;
    
    rv = app_ecdsa_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_ecdsa_tc(ecdsa_tc);
    if (test_case) free(test_case);
    
    /* qx is missing */
    if (!initialize_ecdsa_tc(AMVP_ECDSA_KEYVER, ecdsa_tc, AMVP_EC_CURVE_P256, AMVP_ECDSA_SECRET_GEN_EXTRA_BITS, 0,
        NULL, qy, NULL, NULL, NULL, 0)) {
        cr_assert_fail("hash init tc failure");
    }
    test_case = calloc(1, sizeof(AMVP_TEST_CASE));
    test_case->tc.ecdsa = ecdsa_tc;
    
    rv = app_ecdsa_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_ecdsa_tc(ecdsa_tc);
    if (test_case) free(test_case);
    free(ecdsa_tc);
}

/*
 * missing message in siggen ecdsa tc test case
 */
Test(APP_ECDSA_HANDLER, missing_siggen_msg) {
    ecdsa_tc = calloc(1, sizeof(AMVP_ECDSA_TC));
    
    if (!initialize_ecdsa_tc(AMVP_ECDSA_SIGGEN, ecdsa_tc, AMVP_EC_CURVE_P256, AMVP_ECDSA_SECRET_GEN_EXTRA_BITS, 0,
        NULL, NULL, NULL, NULL, NULL, 0)) {
        cr_assert_fail("hash init tc failure");
    }
    test_case = calloc(1, sizeof(AMVP_TEST_CASE));
    test_case->tc.ecdsa = ecdsa_tc;
    
    rv = app_ecdsa_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_ecdsa_tc(ecdsa_tc);
    free(test_case);
    free(ecdsa_tc);
}

/*
 * missing message in sigver ecdsa tc test case
 */
Test(APP_ECDSA_HANDLER, missing_sigver_msg) {
    char r[] = "aaaa";
    char s[] = "aaaa";
    char qx[] = "aaaa";
    char qy[] = "aaaa";
    ecdsa_tc = calloc(1, sizeof(AMVP_ECDSA_TC));
    
    if (!initialize_ecdsa_tc(AMVP_ECDSA_SIGVER, ecdsa_tc, AMVP_EC_CURVE_P256, AMVP_ECDSA_SECRET_GEN_EXTRA_BITS, AMVP_SHA256,
        qx, qy, NULL, r, s, 0)) {
        cr_assert_fail("hash init tc failure");
    }
    test_case = calloc(1, sizeof(AMVP_TEST_CASE));
    test_case->tc.ecdsa = ecdsa_tc;
    
    rv = app_ecdsa_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_ecdsa_tc(ecdsa_tc);
    free(test_case);
    free(ecdsa_tc);
}

/*
 * missing r or s in sigver in ecdsa tc test case
 */
Test(APP_ECDSA_HANDLER, missing_sigver_r_s) {
    ecdsa_tc = calloc(1, sizeof(AMVP_ECDSA_TC));
    char qx[] = "aaaa";
    char qy[] = "aaaa";
    char r[] = "aaaa";
    char s[] = "aaaa";
    char msg[] = "aaaa";
    
    /* both are missing */
    if (!initialize_ecdsa_tc(AMVP_ECDSA_SIGVER, ecdsa_tc, AMVP_EC_CURVE_P256, AMVP_ECDSA_SECRET_GEN_EXTRA_BITS, AMVP_SHA256,
        qx, qy, msg, NULL, NULL, 0)) {
        cr_assert_fail("hash init tc failure");
    }
    test_case = calloc(1, sizeof(AMVP_TEST_CASE));
    test_case->tc.ecdsa = ecdsa_tc;
    
    rv = app_ecdsa_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_ecdsa_tc(ecdsa_tc);
    if (test_case) free(test_case);

    /* r is missing */
    if (!initialize_ecdsa_tc(AMVP_ECDSA_SIGVER, ecdsa_tc, AMVP_EC_CURVE_P256, AMVP_ECDSA_SECRET_GEN_EXTRA_BITS, AMVP_SHA256,
            qx, qy, msg, NULL, s, 0)) {
        cr_assert_fail("hash init tc failure");
    }
    test_case = calloc(1, sizeof(AMVP_TEST_CASE));
    test_case->tc.ecdsa = ecdsa_tc;
    
    rv = app_ecdsa_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_ecdsa_tc(ecdsa_tc);
    if (test_case) free(test_case);
    
    /* s is missing */
    if (!initialize_ecdsa_tc(AMVP_ECDSA_SIGVER, ecdsa_tc, AMVP_EC_CURVE_P256, AMVP_ECDSA_SECRET_GEN_EXTRA_BITS, AMVP_SHA256,
        qx, qy, msg, r, NULL, 0)) {
        cr_assert_fail("hash init tc failure");
    }
    test_case = calloc(1, sizeof(AMVP_TEST_CASE));
    test_case->tc.ecdsa = ecdsa_tc;
    
    rv = app_ecdsa_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_ecdsa_tc(ecdsa_tc);
    if (test_case) free(test_case);
    free(ecdsa_tc);
}

/*
 * missing qx or qy in sigver in ecdsa tc test case
 */
Test(APP_ECDSA_HANDLER, missing_sigver_qx_qy) {
    ecdsa_tc = calloc(1, sizeof(AMVP_ECDSA_TC));
    char qx[] = "aaaa";
    char qy[] = "aaaa";
    char r[] = "aaaa";
    char s[] = "aaaa";
    char msg[] = "aaaa";
    
    /* both are missing */
    if (!initialize_ecdsa_tc(AMVP_ECDSA_SIGVER, ecdsa_tc, AMVP_EC_CURVE_P256, AMVP_ECDSA_SECRET_GEN_EXTRA_BITS, 0,
        NULL, NULL, msg, r, s, 0)) {
        cr_assert_fail("hash init tc failure");
    }
    test_case = calloc(1, sizeof(AMVP_TEST_CASE));
    test_case->tc.ecdsa = ecdsa_tc;
    
    rv = app_ecdsa_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_ecdsa_tc(ecdsa_tc);
    if (test_case) free(test_case);
    
    /* qy is missing */
    if (!initialize_ecdsa_tc(AMVP_ECDSA_SIGVER, ecdsa_tc, AMVP_EC_CURVE_P256, AMVP_ECDSA_SECRET_GEN_EXTRA_BITS, 0,
        qx, NULL, msg, r, s, 0)) {
        cr_assert_fail("hash init tc failure");
    }
    test_case = calloc(1, sizeof(AMVP_TEST_CASE));
    test_case->tc.ecdsa = ecdsa_tc;
    
    rv = app_ecdsa_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_ecdsa_tc(ecdsa_tc);
    if (test_case) free(test_case);
    
    /* qx is missing */
    if (!initialize_ecdsa_tc(AMVP_ECDSA_SIGVER, ecdsa_tc, AMVP_EC_CURVE_P256, AMVP_ECDSA_SECRET_GEN_EXTRA_BITS, 0,
        NULL, qy, msg, r, s, 0)) {
        cr_assert_fail("hash init tc failure");
    }
    test_case = calloc(1, sizeof(AMVP_TEST_CASE));
    test_case->tc.ecdsa = ecdsa_tc;
    
    rv = app_ecdsa_handler(test_case);
    cr_assert_neq(rv, 0);
    
    free_ecdsa_tc(ecdsa_tc);
    if (test_case) free(test_case);
    free(ecdsa_tc);
}

#endif

