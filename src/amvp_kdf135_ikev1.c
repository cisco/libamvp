/** @file */
/*
 * Copyright (c) 2019, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libamvp/LICENSE
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "amvp.h"
#include "amvp_lcl.h"
#include "parson.h"
#include "safe_lib.h"

/*
 * Forward prototypes for local functions
 */
static AMVP_RESULT amvp_kdf135_ikev1_output_tc(AMVP_CTX *ctx, AMVP_KDF135_IKEV1_TC *stc, JSON_Object *tc_rsp) {
    AMVP_RESULT rv;
    char *tmp = NULL;

    tmp = calloc(AMVP_KDF135_IKEV1_SKEY_STR_MAX + 1, sizeof(char));
    if (!tmp) {
        AMVP_LOG_ERR("Unable to malloc in amvp_kdf135 tpm_output_tc");
        return AMVP_MALLOC_FAIL;
    }

    rv = amvp_bin_to_hexstr(stc->s_key_id, stc->s_key_id_len, tmp, AMVP_KDF135_IKEV1_SKEY_STR_MAX);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("hex conversion failure (s_key_id)");
        goto err;
    }
    json_object_set_string(tc_rsp, "sKeyId", (const char *)tmp);
    memzero_s(tmp, AMVP_KDF135_IKEV1_SKEY_STR_MAX);

    rv = amvp_bin_to_hexstr(stc->s_key_id_d, stc->s_key_id_d_len, tmp, AMVP_KDF135_IKEV1_SKEY_STR_MAX);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("hex conversion failure (s_key_id_d)");
        goto err;
    }
    json_object_set_string(tc_rsp, "sKeyIdD", (const char *)tmp);
    memzero_s(tmp, AMVP_KDF135_IKEV1_SKEY_STR_MAX);

    rv = amvp_bin_to_hexstr(stc->s_key_id_a, stc->s_key_id_a_len, tmp, AMVP_KDF135_IKEV1_SKEY_STR_MAX);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("hex conversion failure (s_key_id_a)");
        goto err;
    }
    json_object_set_string(tc_rsp, "sKeyIdA", (const char *)tmp);
    memzero_s(tmp, AMVP_KDF135_IKEV1_SKEY_STR_MAX);

    rv = amvp_bin_to_hexstr(stc->s_key_id_e, stc->s_key_id_e_len, tmp, AMVP_KDF135_IKEV1_SKEY_STR_MAX);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("hex conversion failure (s_key_id_e)");
        goto err;
    }
    json_object_set_string(tc_rsp, "sKeyIdE", (const char *)tmp);
    memzero_s(tmp, AMVP_KDF135_IKEV1_SKEY_STR_MAX);

err:
    free(tmp);
    return rv;
}

static AMVP_RESULT amvp_kdf135_ikev1_init_tc(AMVP_CTX *ctx,
                                             AMVP_KDF135_IKEV1_TC *stc,
                                             unsigned int tc_id,
                                             AMVP_HASH_ALG hash_alg,
                                             AMVP_KDF135_IKEV1_AUTH_METHOD auth_method,
                                             int init_nonce_len,
                                             int resp_nonce_len,
                                             int dh_secret_len,
                                             int psk_len,
                                             const char *init_nonce,
                                             const char *resp_nonce,
                                             const char *init_ckey,
                                             const char *resp_ckey,
                                             const char *gxy,
                                             const char *psk) {
    AMVP_RESULT rv = AMVP_SUCCESS;

    memzero_s(stc, sizeof(AMVP_KDF135_IKEV1_TC));

    stc->tc_id = tc_id;

    stc->hash_alg = hash_alg;
    stc->auth_method = auth_method;

    stc->init_nonce_len = AMVP_BIT2BYTE(init_nonce_len);
    stc->resp_nonce_len = AMVP_BIT2BYTE(resp_nonce_len);
    stc->dh_secret_len = AMVP_BIT2BYTE(dh_secret_len);
    stc->psk_len = AMVP_BIT2BYTE(psk_len);

    stc->init_nonce = calloc(AMVP_KDF135_IKEV1_INIT_NONCE_BYTE_MAX,
                             sizeof(unsigned char));
    if (!stc->init_nonce) { return AMVP_MALLOC_FAIL; }
    rv = amvp_hexstr_to_bin(init_nonce, stc->init_nonce, AMVP_KDF135_IKEV1_INIT_NONCE_BYTE_MAX, NULL);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (init_nonce)");
        return rv;
    }

    stc->resp_nonce = calloc(AMVP_KDF135_IKEV1_RESP_NONCE_BYTE_MAX,
                             sizeof(unsigned char));
    if (!stc->resp_nonce) { return AMVP_MALLOC_FAIL; }
    rv = amvp_hexstr_to_bin(resp_nonce, stc->resp_nonce, AMVP_KDF135_IKEV1_RESP_NONCE_BYTE_MAX, NULL);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (resp_nonce)");
        return rv;
    }

    stc->init_ckey = calloc(AMVP_KDF135_IKEV1_COOKIE_BYTE_MAX,
                            sizeof(unsigned char));
    if (!stc->init_ckey) { return AMVP_MALLOC_FAIL; }
    rv = amvp_hexstr_to_bin(init_ckey, stc->init_ckey, AMVP_KDF135_IKEV1_COOKIE_BYTE_MAX, NULL);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (init_ckey)");
        return rv;
    }

    stc->resp_ckey = calloc(AMVP_KDF135_IKEV1_COOKIE_BYTE_MAX,
                            sizeof(unsigned char));
    if (!stc->resp_ckey) { return AMVP_MALLOC_FAIL; }
    rv = amvp_hexstr_to_bin(resp_ckey, stc->resp_ckey, AMVP_KDF135_IKEV1_COOKIE_BYTE_MAX, NULL);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (resp_ckey)");
        return rv;
    }

    stc->gxy = calloc(AMVP_KDF135_IKEV1_DH_SHARED_SECRET_BYTE_MAX,
                      sizeof(unsigned char));
    if (!stc->gxy) { return AMVP_MALLOC_FAIL; }
    rv = amvp_hexstr_to_bin(gxy, stc->gxy, AMVP_KDF135_IKEV1_DH_SHARED_SECRET_BYTE_MAX, NULL);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (gxy)");
        return rv;
    }

    if (psk != NULL) {
        /* Only for PSK authentication method */
        stc->psk = calloc(AMVP_KDF135_IKEV1_PSK_BYTE_MAX,
                          sizeof(unsigned char));
        if (!stc->psk) { return AMVP_MALLOC_FAIL; }
        rv = amvp_hexstr_to_bin(psk, stc->psk, AMVP_KDF135_IKEV1_PSK_BYTE_MAX, NULL);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (psk)");
            return rv;
        }
    }

    stc->s_key_id = calloc(AMVP_KDF135_IKEV1_SKEY_BYTE_MAX,
                           sizeof(unsigned char));
    if (!stc->s_key_id) { return AMVP_MALLOC_FAIL; }
    stc->s_key_id_a = calloc(AMVP_KDF135_IKEV1_SKEY_BYTE_MAX,
                             sizeof(unsigned char));
    if (!stc->s_key_id_a) { return AMVP_MALLOC_FAIL; }
    stc->s_key_id_d = calloc(AMVP_KDF135_IKEV1_SKEY_BYTE_MAX,
                             sizeof(unsigned char));
    if (!stc->s_key_id_d) { return AMVP_MALLOC_FAIL; }
    stc->s_key_id_e = calloc(AMVP_KDF135_IKEV1_SKEY_BYTE_MAX,
                             sizeof(unsigned char));
    if (!stc->s_key_id_e) { return AMVP_MALLOC_FAIL; }

    return rv;
}

static AMVP_RESULT amvp_kdf135_ikev1_release_tc(AMVP_KDF135_IKEV1_TC *stc) {
    if (stc->init_nonce) { free(stc->init_nonce); }
    if (stc->resp_nonce) { free(stc->resp_nonce); }
    if (stc->init_ckey) { free(stc->init_ckey); }
    if (stc->resp_ckey) { free(stc->resp_ckey); }
    if (stc->gxy) { free(stc->gxy); }
    if (stc->psk) { free(stc->psk); }
    if (stc->s_key_id) { free(stc->s_key_id); }
    if (stc->s_key_id_d) { free(stc->s_key_id_d); }
    if (stc->s_key_id_a) { free(stc->s_key_id_a); }
    if (stc->s_key_id_e) { free(stc->s_key_id_e); }
    memzero_s(stc, sizeof(AMVP_KDF135_IKEV1_TC));
    return AMVP_SUCCESS;
}

static AMVP_KDF135_IKEV1_AUTH_METHOD read_auth_method(const char *str) {
    int diff = 1;

    strcmp_s(AMVP_AUTH_METHOD_DSA_STR, 3, str, &diff);
    if (!diff) return AMVP_KDF135_IKEV1_AMETH_DSA;

    strcmp_s(AMVP_AUTH_METHOD_PSK_STR, 3, str, &diff);
    if (!diff) return AMVP_KDF135_IKEV1_AMETH_PSK;

    strcmp_s(AMVP_AUTH_METHOD_PKE_STR, 3, str, &diff);
    if (!diff) return AMVP_KDF135_IKEV1_AMETH_PKE;

    return 0;
}

AMVP_RESULT amvp_kdf135_ikev1_kat_handler(AMVP_CTX *ctx, JSON_Object *obj) {
    unsigned int tc_id;
    JSON_Value *groupval;
    JSON_Object *groupobj = NULL;
    JSON_Value *testval;
    JSON_Object *testobj = NULL;
    JSON_Array *groups;
    JSON_Array *tests;

    JSON_Value *reg_arry_val = NULL;
    JSON_Object *reg_obj = NULL;
    JSON_Array *reg_arry = NULL;

    int i, g_cnt;
    int j, t_cnt;

    JSON_Value *r_vs_val = NULL;
    JSON_Object *r_vs = NULL;
    JSON_Array *r_tarr = NULL, *r_garr = NULL;  /* Response testarray, grouparray */
    JSON_Value *r_tval = NULL, *r_gval = NULL;  /* Response testval, groupval */
    JSON_Object *r_tobj = NULL, *r_gobj = NULL; /* Response testobj, groupobj */
    AMVP_CAPS_LIST *cap;
    AMVP_KDF135_IKEV1_TC stc;
    AMVP_TEST_CASE tc;
    AMVP_RESULT rv;
    const char *alg_str = json_object_get_string(obj, "algorithm");
    const char *mode_str = NULL;
    AMVP_CIPHER alg_id;
    char *json_result;

    AMVP_HASH_ALG hash_alg = 0;
    AMVP_KDF135_IKEV1_AUTH_METHOD auth_method = 0;
    const char *hash_alg_str = NULL, *auth_method_str = NULL;
    const char *init_ckey = NULL, *resp_ckey = NULL, *gxy = NULL, *psk = NULL, *init_nonce = NULL, *resp_nonce = NULL;
    unsigned int init_nonce_len = 0, resp_nonce_len = 0;
    int dh_secret_len = 0, psk_len = 0;

    if (!ctx) {
        AMVP_LOG_ERR("No ctx for handler operation");
        return AMVP_NO_CTX;
    }

    if (!alg_str) {
        AMVP_LOG_ERR("unable to parse 'algorithm' from JSON.");
        return AMVP_MALFORMED_JSON;
    }

    mode_str = json_object_get_string(obj, "mode");
    if (!mode_str) {
        AMVP_LOG_ERR("unable to parse 'mode' from JSON.");
        return AMVP_MALFORMED_JSON;
    }

    alg_id = amvp_lookup_cipher_w_mode_index(alg_str, mode_str);
    if (alg_id != AMVP_KDF135_IKEV1) {
        AMVP_LOG_ERR("Server JSON invalid 'algorithm' or 'mode'");
        return AMVP_INVALID_ARG;
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.kdf135_ikev1 = &stc;
    stc.cipher = alg_id;

    cap = amvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        AMVP_LOG_ERR("AMVP server requesting unsupported capability %s : %d.", alg_str, alg_id);
        return AMVP_UNSUPPORTED_OP;
    }

    /*
     * Create AMVP array for response
     */
    rv = amvp_create_array(&reg_obj, &reg_arry_val, &reg_arry);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Failed to create JSON response struct. ");
        return rv;
    }

    /*
     * Start to build the JSON response
     */
    rv = amvp_setup_json_rsp_group(&ctx, &reg_arry_val, &r_vs_val, &r_vs, alg_str, &r_garr);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Failed to setup json response");
        return rv;
    }

    groups = json_object_get_array(obj, "testGroups");
    g_cnt = json_array_get_count(groups);
    for (i = 0; i < g_cnt; i++) {
        int tgId = 0;
        groupval = json_array_get_value(groups, i);
        groupobj = json_value_get_object(groupval);

        /*
         * Create a new group in the response with the tgid
         * and an array of tests
         */
        r_gval = json_value_init_object();
        r_gobj = json_value_get_object(r_gval);
        tgId = json_object_get_number(groupobj, "tgId");
        if (!tgId) {
            AMVP_LOG_ERR("Missing tgid from server JSON groub obj");
            rv = AMVP_MALFORMED_JSON;
            goto err;
        }
        json_object_set_number(r_gobj, "tgId", tgId);
        json_object_set_value(r_gobj, "tests", json_value_init_array());
        r_tarr = json_object_get_array(r_gobj, "tests");

        hash_alg_str = json_object_get_string(groupobj, "hashAlg");
        if (!hash_alg_str) {
            AMVP_LOG_ERR("Failed to include hashAlg");
            rv = AMVP_MISSING_ARG;
            goto err;
        }
        hash_alg = amvp_lookup_hash_alg(hash_alg_str);
        if (hash_alg != AMVP_SHA1 && hash_alg != AMVP_SHA224 &&
            hash_alg != AMVP_SHA256 && hash_alg != AMVP_SHA384 &&
            hash_alg != AMVP_SHA512) {
            AMVP_LOG_ERR("AMVP server requesting invalid hashAlg");
            rv = AMVP_INVALID_ARG;
            goto err;
        }

        auth_method_str = json_object_get_string(groupobj, "authenticationMethod");
        if (!auth_method_str) {
            AMVP_LOG_ERR("Failed to include authenticationMethod");
            rv = AMVP_MISSING_ARG;
            goto err;
        }
        auth_method = read_auth_method(auth_method_str);
        if (!auth_method) {
            AMVP_LOG_ERR("AMVP server requesting invalid authenticationMethod");
            rv = AMVP_INVALID_ARG;
            goto err;
        }

        init_nonce_len = json_object_get_number(groupobj, "nInitLength");
        if (!(init_nonce_len >= AMVP_KDF135_IKEV1_INIT_NONCE_BIT_MIN &&
              init_nonce_len <= AMVP_KDF135_IKEV1_INIT_NONCE_BIT_MAX)) {
            AMVP_LOG_ERR("nInitLength incorrect, %d", init_nonce_len);
            rv = AMVP_INVALID_ARG;
            goto err;
        }

        resp_nonce_len = json_object_get_number(groupobj, "nRespLength");
        if (!(resp_nonce_len >= AMVP_KDF135_IKEV1_RESP_NONCE_BIT_MIN &&
              resp_nonce_len <= AMVP_KDF135_IKEV1_RESP_NONCE_BIT_MAX)) {
            AMVP_LOG_ERR("nRespLength incorrect, %d", resp_nonce_len);
            rv = AMVP_INVALID_ARG;
            goto err;
        }

        dh_secret_len = json_object_get_number(groupobj, "dhLength");
        if (!(dh_secret_len >= AMVP_KDF135_IKEV1_DH_SHARED_SECRET_BIT_MIN &&
              dh_secret_len <= AMVP_KDF135_IKEV1_DH_SHARED_SECRET_BIT_MAX)) {
            AMVP_LOG_ERR("dhLength incorrect, %d", dh_secret_len);
            rv = AMVP_INVALID_ARG;
            goto err;
        }

        if (auth_method == AMVP_KDF135_IKEV1_AMETH_PSK) {
            /* Only for PSK authentication method */
            psk_len = json_object_get_number(groupobj, "preSharedKeyLength");
            if (!(psk_len >= AMVP_KDF135_IKEV1_PSK_BIT_MIN &&
                  psk_len <= AMVP_KDF135_IKEV1_PSK_BIT_MAX)) {
                AMVP_LOG_ERR("preSharedKeyLength incorrect, %d", psk_len);
                rv = AMVP_INVALID_ARG;
                goto err;
            }
        }

        AMVP_LOG_VERBOSE("\n    Test group: %d", i);
        AMVP_LOG_VERBOSE("        hash alg: %s", hash_alg_str);
        AMVP_LOG_VERBOSE("     auth method: %s", auth_method_str);
        AMVP_LOG_VERBOSE("  init nonce len: %d", init_nonce_len);
        AMVP_LOG_VERBOSE("  resp nonce len: %d", resp_nonce_len);
        AMVP_LOG_VERBOSE("   dh secret len: %d", dh_secret_len);
        AMVP_LOG_VERBOSE("         psk len: %d", psk_len);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);

        for (j = 0; j < t_cnt; j++) {
            AMVP_LOG_VERBOSE("Found new KDF IKEv1 test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            tc_id = json_object_get_number(testobj, "tcId");

            init_nonce = json_object_get_string(testobj, "nInit");
            if (!init_nonce) {
                AMVP_LOG_ERR("Failed to include nInit");
                rv = AMVP_MISSING_ARG;
                goto err;
            }
            if (strnlen_s(init_nonce,
                        AMVP_KDF135_IKEV1_INIT_NONCE_STR_MAX + 1) != ((init_nonce_len + 7) / 8) * 2) {
                AMVP_LOG_ERR("nInit length(%d) incorrect, expected(%d)",
                             (int)strnlen_s(init_nonce,
                                     AMVP_KDF135_IKEV1_INIT_NONCE_STR_MAX + 1),
                             ((init_nonce_len + 7) / 8) * 2);
                rv = AMVP_INVALID_ARG;
                goto err;
            }

            resp_nonce = json_object_get_string(testobj, "nResp");
            if (!resp_nonce) {
                AMVP_LOG_ERR("Failed to include nResp");
                rv = AMVP_MISSING_ARG;
                goto err;
            }
            if (strnlen_s(resp_nonce,
                        AMVP_KDF135_IKEV1_RESP_NONCE_STR_MAX + 1) != ((resp_nonce_len + 7) / 8) * 2) {
                AMVP_LOG_ERR("nResp length(%d) incorrect, expected(%d)",
                             (int)strnlen_s(resp_nonce, AMVP_KDF135_IKEV1_RESP_NONCE_STR_MAX + 1),
                             ((resp_nonce_len + 7) / 8) * 2);
                rv = AMVP_INVALID_ARG;
                goto err;
            }

            init_ckey = json_object_get_string(testobj, "ckyInit");
            if (!init_ckey) {
                AMVP_LOG_ERR("Failed to include ckyInit");
                rv = AMVP_MISSING_ARG;
                goto err;
            }
            if (strnlen_s(init_ckey, AMVP_KDF135_IKEV1_COOKIE_STR_MAX + 1)
                > AMVP_KDF135_IKEV1_COOKIE_STR_MAX) {
                AMVP_LOG_ERR("ckyInit too long, max allowed=(%d)",
                             AMVP_KDF135_IKEV1_COOKIE_STR_MAX);
                rv = AMVP_INVALID_ARG;
                goto err;
            }

            resp_ckey = json_object_get_string(testobj, "ckyResp");
            if (!resp_ckey) {
                AMVP_LOG_ERR("Failed to include ckyResp");
                rv = AMVP_MISSING_ARG;
                goto err;
            }
            if (strnlen_s(resp_ckey, AMVP_KDF135_IKEV1_COOKIE_STR_MAX + 1)
                > AMVP_KDF135_IKEV1_COOKIE_STR_MAX) {
                AMVP_LOG_ERR("ckyResp too long, max allowed=(%d)",
                             AMVP_KDF135_IKEV1_COOKIE_STR_MAX);
                rv = AMVP_INVALID_ARG;
                goto err;
            }

            gxy = json_object_get_string(testobj, "gxy");
            if (!gxy) {
                AMVP_LOG_ERR("Failed to include gxy");
                rv = AMVP_MISSING_ARG;
                goto err;
            }
            if (strnlen_s(gxy, AMVP_KDF135_IKEV1_DH_SHARED_SECRET_STR_MAX + 1)
                > AMVP_KDF135_IKEV1_DH_SHARED_SECRET_STR_MAX) {
                AMVP_LOG_ERR("gxy too long, max allowed=(%d)",
                             AMVP_KDF135_IKEV1_DH_SHARED_SECRET_STR_MAX);
                rv = AMVP_INVALID_ARG;
                goto err;
            }


            if (auth_method == AMVP_KDF135_IKEV1_AMETH_PSK) {
                /* Only for PSK authentication method */
                psk = json_object_get_string(testobj, "preSharedKey");
                if (!psk) {
                    AMVP_LOG_ERR("Failed to include preSharedKey");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(psk, AMVP_KDF135_IKEV1_PSK_STR_MAX + 1)
                    > AMVP_KDF135_IKEV1_PSK_STR_MAX) {
                    AMVP_LOG_ERR("preSharedKey too long, max allowed=(%d)",
                                 AMVP_KDF135_IKEV1_PSK_STR_MAX);
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }
            }

            AMVP_LOG_VERBOSE("        Test case: %d", j);
            AMVP_LOG_VERBOSE("             tcId: %d", tc_id);

            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);

            json_object_set_number(r_tobj, "tcId", tc_id);

            /*
             * Setup the test case data that will be passed down to
             * the crypto module2
             */
            rv = amvp_kdf135_ikev1_init_tc(ctx, &stc, tc_id, hash_alg, auth_method,
                                           init_nonce_len, resp_nonce_len,
                                           dh_secret_len, psk_len,
                                           init_nonce, resp_nonce,
                                           init_ckey, resp_ckey,
                                           gxy, psk);
            if (rv != AMVP_SUCCESS) {
                amvp_kdf135_ikev1_release_tc(&stc);
                json_value_free(r_tval);
                goto err;
            }

            /* Process the current test vector... */
            if ((cap->crypto_handler)(&tc)) {
                AMVP_LOG_ERR("crypto module failed the KDF IKEv1 operation");
                amvp_kdf135_ikev1_release_tc(&stc);
                rv = AMVP_CRYPTO_MODULE_FAIL;
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Output the test case results using JSON
             */
            rv = amvp_kdf135_ikev1_output_tc(ctx, &stc, r_tobj);
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("JSON output failure in hash module");
                amvp_kdf135_ikev1_release_tc(&stc);
                json_value_free(r_tval);
                goto err;
            }
            /*
             * Release all the memory associated with the test case
             */
            amvp_kdf135_ikev1_release_tc(&stc);

            /* Append the test response value to array */
            json_array_append_value(r_tarr, r_tval);
        }
        json_array_append_value(r_garr, r_gval);
    }

    json_array_append_value(reg_arry, r_vs_val);

    json_result = json_serialize_to_string_pretty(ctx->kat_resp, NULL);
    AMVP_LOG_VERBOSE("\n\n%s\n\n", json_result);
    json_free_serialized_string(json_result);
    rv = AMVP_SUCCESS;

err:
    if (rv != AMVP_SUCCESS) {
        amvp_release_json(r_vs_val, r_gval);
    }
    return rv;
}
