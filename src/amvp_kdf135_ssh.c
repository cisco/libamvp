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
static AMVP_RESULT amvp_kdf135_ssh_output_tc(AMVP_CTX *ctx, AMVP_KDF135_SSH_TC *stc, JSON_Object *tc_rsp);

static AMVP_RESULT amvp_kdf135_ssh_init_tc(AMVP_KDF135_SSH_TC *stc,
                                           unsigned int tc_id,
                                           AMVP_CIPHER alg_id,
                                           unsigned int sha_type,
                                           unsigned int e_key_len,
                                           unsigned int i_key_len,
                                           unsigned int iv_len,
                                           unsigned int hash_len,
                                           const char *shared_secret_k,
                                           const char *hash_h,
                                           const char *session_id);

static AMVP_RESULT amvp_kdf135_ssh_release_tc(AMVP_KDF135_SSH_TC *stc);

AMVP_RESULT amvp_kdf135_ssh_kat_handler(AMVP_CTX *ctx, JSON_Object *obj) {
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
    AMVP_KDF135_SSH_TC stc;
    AMVP_TEST_CASE tc;
    AMVP_RESULT rv;

    AMVP_CIPHER alg_id;
    const char *alg_str = NULL;
    const char *mode_str = NULL;
    const char *cipher_str = NULL;
    const char *shared_secret_str = NULL;
    const char *session_id_str = NULL;
    const char *hash_str = NULL;
    char *json_result;

    if (!ctx) {
        AMVP_LOG_ERR("No ctx for handler operation");
        return AMVP_NO_CTX;
    }

    if (!obj) {
        AMVP_LOG_ERR("No obj for handler operation");
        return AMVP_MALFORMED_JSON;
    }

    alg_str = json_object_get_string(obj, "algorithm");
    if (!alg_str) {
        AMVP_LOG_ERR("unable to parse 'algorithm' from JSON");
        return AMVP_MALFORMED_JSON;
    }

    mode_str = json_object_get_string(obj, "mode");
    if (!mode_str) {
        AMVP_LOG_ERR("unable to parse 'mode' from JSON");
        return AMVP_MALFORMED_JSON;
    }

    alg_id = amvp_lookup_cipher_w_mode_index(alg_str, mode_str);
    if (alg_id != AMVP_KDF135_SSH) {
        AMVP_LOG_ERR("Server JSON invalid 'algorithm' or 'mode'");
        return AMVP_INVALID_ARG;
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.kdf135_ssh = &stc;

    /*
     * Get the crypto module handler for this hash algorithm
     */
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
    if (!groups) {
        AMVP_LOG_ERR("Failed to include testGroups. ");
        rv = AMVP_MISSING_ARG;
        goto err;
    }

    g_cnt = json_array_get_count(groups);
    for (i = 0; i < g_cnt; i++) {
        int tgId = 0;
        int diff = 1;
        unsigned int e_key_len = 0, i_key_len = 0,
                     hash_len = 0, iv_len = 0;
        AMVP_HASH_ALG sha_type = 0;
        const char *sha_str = NULL;
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

        // Get the expected (user will generate) key and iv lengths
        cipher_str = json_object_get_string(groupobj, "cipher");
        if (!cipher_str) {
            AMVP_LOG_ERR("Failed to include cipher. ");
            rv = AMVP_MISSING_ARG;
            goto err;
        }

        sha_str = json_object_get_string(groupobj, "hashAlg");
        if (!sha_str) {
            AMVP_LOG_ERR("Failed to include hashAlg. ");
            rv = AMVP_MISSING_ARG;
            goto err;
        }

        sha_type = amvp_lookup_hash_alg(sha_str);
        if (sha_type == AMVP_SHA1) {
            i_key_len = hash_len = AMVP_SHA1_BYTE_LEN;
        } else if (sha_type == AMVP_SHA224) {
            i_key_len = hash_len = AMVP_SHA224_BYTE_LEN;
        } else if (sha_type == AMVP_SHA256) {
            i_key_len = hash_len = AMVP_SHA256_BYTE_LEN;
        } else if (sha_type == AMVP_SHA384) {
            i_key_len = hash_len = AMVP_SHA384_BYTE_LEN;
        } else if (sha_type == AMVP_SHA512) {
            i_key_len = hash_len = AMVP_SHA512_BYTE_LEN;
        } else {
            AMVP_LOG_ERR("AMVP server requesting invalid hashAlg");
            rv = AMVP_NO_CAP;
            goto err;
        }

        /*
         * Determine the encrypt key_len, inferred from cipher.
         */
        strcmp_s(AMVP_MODE_TDES, 4, cipher_str, &diff);
        if (!diff) {
            e_key_len = AMVP_KEY_LEN_TDES;
            iv_len = AMVP_BLOCK_LEN_TDES;
        }

        strcmp_s(AMVP_MODE_AES_128, 7, cipher_str, &diff);
        if (!diff) {
            e_key_len = AMVP_KEY_LEN_AES128;
            iv_len = AMVP_BLOCK_LEN_AES128;
        }

        strcmp_s(AMVP_MODE_AES_192, 7, cipher_str, &diff);
        if (!diff) {
            e_key_len = AMVP_KEY_LEN_AES192;
            iv_len = AMVP_BLOCK_LEN_AES192;
        }

        strcmp_s(AMVP_MODE_AES_256, 7, cipher_str, &diff);
        if (!diff) {
            e_key_len = AMVP_KEY_LEN_AES256;
            iv_len = AMVP_BLOCK_LEN_AES256;
        }

        if (!e_key_len || !iv_len) {
            AMVP_LOG_ERR("Unsupported cipher type");
            rv = AMVP_NO_CAP;
            goto err;
        }


        /*
         * Log Test Group information...
         */
        AMVP_LOG_VERBOSE("    Test group: %d", i);
        AMVP_LOG_VERBOSE("        cipher: %s", cipher_str);
        AMVP_LOG_VERBOSE("       hashAlg: %s", sha_str);

        tests = json_object_get_array(groupobj, "tests");
        if (!tests) {
            AMVP_LOG_ERR("Failed to include tests. ");
            rv = AMVP_MISSING_ARG;
            goto err;
        }

        t_cnt = json_array_get_count(tests);
        if (!t_cnt) {
            AMVP_LOG_ERR("Failed to include tests in array. ");
            rv = AMVP_MISSING_ARG;
            goto err;
        }

        for (j = 0; j < t_cnt; j++) {
            AMVP_LOG_VERBOSE("Found new KDF SSH test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            tc_id = json_object_get_number(testobj, "tcId");
            if (!tc_id) {
                AMVP_LOG_ERR("Failed to include tc_id. ");
                rv = AMVP_MISSING_ARG;
                goto err;
            }

            shared_secret_str = json_object_get_string(testobj, "k");
            if (!shared_secret_str) {
                AMVP_LOG_ERR("Failed to include k. ");
                rv = AMVP_MISSING_ARG;
                goto err;
            }

            hash_str = json_object_get_string(testobj, "h");
            if (!hash_str) {
                AMVP_LOG_ERR("Failed to include h. ");
                rv = AMVP_MISSING_ARG;
                goto err;
            }

            session_id_str = json_object_get_string(testobj, "sessionId");
            if (!session_id_str) {
                AMVP_LOG_ERR("Failed to include sessionId. ");
                rv = AMVP_MISSING_ARG;
                goto err;
            }

            AMVP_LOG_VERBOSE("        Test case: %d", j);
            AMVP_LOG_VERBOSE("             tcId: %d", tc_id);
            AMVP_LOG_VERBOSE("                k: %s", shared_secret_str);
            AMVP_LOG_VERBOSE("                h: %s", hash_str);
            AMVP_LOG_VERBOSE("       session_id: %s", session_id_str);

            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);

            json_object_set_number(r_tobj, "tcId", tc_id);

            /*
             * Setup the test case data that will be passed down to
             * the crypto module.
             */
            rv = amvp_kdf135_ssh_init_tc(&stc, tc_id, alg_id,
                                         sha_type, e_key_len, i_key_len, iv_len, hash_len,
                                         shared_secret_str, hash_str, session_id_str);
            if (rv != AMVP_SUCCESS) {
                amvp_kdf135_ssh_release_tc(&stc);
                json_value_free(r_tval);
                goto err;
            }

            /* Process the current test vector... */
            if ((cap->crypto_handler)(&tc)) {
                AMVP_LOG_ERR("crypto module failed the KDF SSH operation");
                amvp_kdf135_ssh_release_tc(&stc);
                rv = AMVP_CRYPTO_MODULE_FAIL;
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Output the test case results using JSON
             */
            rv = amvp_kdf135_ssh_output_tc(ctx, &stc, r_tobj);
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("JSON output failure in hash module");
                amvp_kdf135_ssh_release_tc(&stc);
                json_value_free(r_tval);
                goto err;
            }
            /*
             * Release all the memory associated with the test case
             */
            amvp_kdf135_ssh_release_tc(&stc);

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

/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static AMVP_RESULT amvp_kdf135_ssh_output_tc(AMVP_CTX *ctx,
                                             AMVP_KDF135_SSH_TC *stc,
                                             JSON_Object *tc_rsp) {
    char *tmp = NULL;
    AMVP_RESULT rv = AMVP_SUCCESS;

    if ((stc->iv_len * 2) > AMVP_KDF135_SSH_STR_OUT_MAX ||
        (stc->e_key_len * 2) > AMVP_KDF135_SSH_STR_OUT_MAX ||
        (stc->i_key_len * 2) > AMVP_KDF135_SSH_STR_OUT_MAX) {
        AMVP_LOG_ERR("iv_len*2(%u) || e_key_len*2(%u) || i_key_len*2(%u) > AMVP_KDF135_SSH_STR_OUT_MAX(%u)",
                     (stc->iv_len * 2), (stc->e_key_len * 2), (stc->i_key_len * 2),
                     AMVP_KDF135_SSH_STR_OUT_MAX);
        AMVP_LOG_ERR("Hint, make sure user isn't modifying those field values");
        return AMVP_DATA_TOO_LARGE;
    }

    tmp = calloc(AMVP_KDF135_SSH_STR_OUT_MAX + 1, sizeof(char));
    if (!tmp) {
        AMVP_LOG_ERR("Unable to malloc");
        return AMVP_MALLOC_FAIL;
    }

    rv = amvp_bin_to_hexstr(stc->cs_init_iv, stc->iv_len, tmp, AMVP_KDF135_SSH_STR_OUT_MAX);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("amvp_bin_to_hexstr() failure");
        goto err;
    }
    json_object_set_string(tc_rsp, "initialIvClient", tmp);
    memzero_s(tmp, AMVP_KDF135_SSH_STR_OUT_MAX);

    rv = amvp_bin_to_hexstr(stc->cs_encrypt_key, stc->e_key_len, tmp, AMVP_KDF135_SSH_STR_OUT_MAX);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("amvp_bin_to_hexstr() failure");
        goto err;
    }
    json_object_set_string(tc_rsp, "encryptionKeyClient", tmp);
    memzero_s(tmp, AMVP_KDF135_SSH_STR_OUT_MAX);

    rv = amvp_bin_to_hexstr(stc->cs_integrity_key, stc->i_key_len, tmp, AMVP_KDF135_SSH_STR_OUT_MAX);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("amvp_bin_to_hexstr() failure");
        goto err;
    }
    json_object_set_string(tc_rsp, "integrityKeyClient", tmp);
    memzero_s(tmp, AMVP_KDF135_SSH_STR_OUT_MAX);

    rv = amvp_bin_to_hexstr(stc->sc_init_iv, stc->iv_len, tmp, AMVP_KDF135_SSH_STR_OUT_MAX);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("amvp_bin_to_hexstr() failure");
        goto err;
    }
    json_object_set_string(tc_rsp, "initialIvServer", tmp);
    memzero_s(tmp, AMVP_KDF135_SSH_STR_OUT_MAX);

    rv = amvp_bin_to_hexstr(stc->sc_encrypt_key, stc->e_key_len, tmp, AMVP_KDF135_SSH_STR_OUT_MAX);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("amvp_bin_to_hexstr() failure");
        goto err;
    }
    json_object_set_string(tc_rsp, "encryptionKeyServer", tmp);
    memzero_s(tmp, AMVP_KDF135_SSH_STR_OUT_MAX);

    rv = amvp_bin_to_hexstr(stc->sc_integrity_key, stc->i_key_len, tmp, AMVP_KDF135_SSH_STR_OUT_MAX);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("amvp_bin_to_hexstr() failure");
        goto err;
    }
    json_object_set_string(tc_rsp, "integrityKeyServer", tmp);

err:
    free(tmp);
    return rv;
}

static AMVP_RESULT amvp_kdf135_ssh_init_tc(AMVP_KDF135_SSH_TC *stc,
                                           unsigned int tc_id,
                                           AMVP_CIPHER alg_id,
                                           AMVP_HASH_ALG sha_type,
                                           unsigned int e_key_len,
                                           unsigned int i_key_len,
                                           unsigned int iv_len,
                                           unsigned int hash_len,
                                           const char *shared_secret_k,
                                           const char *hash_h,
                                           const char *session_id) {
    unsigned int shared_secret_len = 0;
    unsigned int session_id_len = 0;
    AMVP_RESULT rv;

    memzero_s(stc, sizeof(AMVP_KDF135_SSH_TC));

    // Get the byte lengths
    shared_secret_len = strnlen_s(shared_secret_k, AMVP_KDF135_SSH_STR_IN_MAX) / 2;
    session_id_len = strnlen_s(session_id, AMVP_KDF135_SSH_STR_IN_MAX) / 2;

    stc->shared_secret_k = calloc(shared_secret_len, sizeof(unsigned char));
    if (!stc->shared_secret_k) { return AMVP_MALLOC_FAIL; }
    stc->hash_h = calloc(hash_len, sizeof(unsigned char));
    if (!stc->hash_h) { return AMVP_MALLOC_FAIL; }
    stc->session_id = calloc(session_id_len, sizeof(unsigned char));
    if (!stc->session_id) { return AMVP_MALLOC_FAIL; }

    // Convert from hex string to binary
    rv = amvp_hexstr_to_bin(shared_secret_k, (unsigned char *)stc->shared_secret_k,
                            shared_secret_len, NULL);
    if (rv != AMVP_SUCCESS) return rv;

    rv = amvp_hexstr_to_bin(hash_h, (unsigned char *)stc->hash_h, hash_len, NULL);
    if (rv != AMVP_SUCCESS) return rv;

    rv = amvp_hexstr_to_bin(session_id, (unsigned char *)stc->session_id, session_id_len, NULL);
    if (rv != AMVP_SUCCESS) return rv;

    // Allocate answer buffers
    stc->cs_init_iv = calloc(AMVP_KDF135_SSH_IV_MAX, sizeof(unsigned char));
    if (!stc->cs_init_iv) { return AMVP_MALLOC_FAIL; }
    stc->sc_init_iv = calloc(AMVP_KDF135_SSH_IV_MAX, sizeof(unsigned char));
    if (!stc->sc_init_iv) { return AMVP_MALLOC_FAIL; }

    stc->cs_encrypt_key = calloc(AMVP_KDF135_SSH_EKEY_MAX, sizeof(unsigned char));
    if (!stc->cs_encrypt_key) { return AMVP_MALLOC_FAIL; }
    stc->sc_encrypt_key = calloc(AMVP_KDF135_SSH_EKEY_MAX, sizeof(unsigned char));
    if (!stc->sc_encrypt_key) { return AMVP_MALLOC_FAIL; }

    stc->cs_integrity_key = calloc(AMVP_KDF135_SSH_IKEY_MAX, sizeof(unsigned char));
    if (!stc->cs_integrity_key) { return AMVP_MALLOC_FAIL; }
    stc->sc_integrity_key = calloc(AMVP_KDF135_SSH_IKEY_MAX, sizeof(unsigned char));
    if (!stc->sc_integrity_key) { return AMVP_MALLOC_FAIL; }

    stc->tc_id = tc_id;
    stc->cipher = alg_id;
    stc->sha_type = sha_type;
    stc->e_key_len = e_key_len;
    stc->i_key_len = i_key_len;
    stc->iv_len = iv_len;
    stc->shared_secret_len = shared_secret_len;
    stc->hash_len = hash_len;
    stc->session_id_len = session_id_len;

    return AMVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static AMVP_RESULT amvp_kdf135_ssh_release_tc(AMVP_KDF135_SSH_TC *stc) {
    if (stc->shared_secret_k) free(stc->shared_secret_k);
    if (stc->hash_h) free(stc->hash_h);
    if (stc->session_id) free(stc->session_id);
    if (stc->cs_init_iv) free(stc->cs_init_iv);
    if (stc->sc_init_iv) free(stc->sc_init_iv);
    if (stc->cs_encrypt_key) free(stc->cs_encrypt_key);
    if (stc->sc_encrypt_key) free(stc->sc_encrypt_key);
    if (stc->cs_integrity_key) free(stc->cs_integrity_key);
    if (stc->sc_integrity_key) free(stc->sc_integrity_key);

    memzero_s(stc, sizeof(AMVP_KDF135_SSH_TC));

    return AMVP_SUCCESS;
}
