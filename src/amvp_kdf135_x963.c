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
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static AMVP_RESULT amvp_kdf135_x963_output_tc(AMVP_CTX *ctx, AMVP_KDF135_X963_TC *stc, JSON_Object *tc_rsp) {
    AMVP_RESULT rv;
    char *tmp = NULL;

    tmp = calloc(AMVP_KDF135_X963_KEYDATA_MAX_CHARS + 1, sizeof(char));
    if (!tmp) {
        AMVP_LOG_ERR("Error allocating memory in X963 KDF TC output");
        return AMVP_MALLOC_FAIL;
    }
    rv = amvp_bin_to_hexstr(stc->key_data, stc->key_data_len, tmp, AMVP_KDF135_X963_KEYDATA_MAX_CHARS);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("hex conversion failure (key_data)");
        goto err;
    }
    json_object_set_string(tc_rsp, "keyData", (const char *)tmp);

err:
    if (tmp) free(tmp);
    return AMVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static AMVP_RESULT amvp_kdf135_x963_release_tc(AMVP_KDF135_X963_TC *stc) {
    if (stc->z) free(stc->z);
    if (stc->shared_info) free(stc->shared_info);
    if (stc->key_data) free(stc->key_data);
    memzero_s(stc, sizeof(AMVP_KDF135_X963_TC));
    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_kdf135_x963_init_tc(AMVP_CTX *ctx,
                                            AMVP_KDF135_X963_TC *stc,
                                            unsigned int tc_id,
                                            AMVP_HASH_ALG hash_alg,
                                            int field_size,
                                            int key_data_length,
                                            int shared_info_length,
                                            const char *z,
                                            const char *shared_info) {
    AMVP_RESULT rv = AMVP_SUCCESS;

    memzero_s(stc, sizeof(AMVP_KDF135_X963_TC));

    if (!hash_alg || !z || !shared_info) {
        AMVP_LOG_ERR("Missing parameters - initalize KDF135 X963 test case");
        return AMVP_INVALID_ARG;
    }

    stc->tc_id = tc_id;
    stc->hash_alg = hash_alg;
    stc->field_size = field_size / 8;
    stc->key_data_len = key_data_length / 8;
    stc->shared_info_len = shared_info_length / 8;

    stc->z = calloc(AMVP_KDF135_X963_INPUT_MAX, sizeof(char));
    if (!stc->z) { return AMVP_MALLOC_FAIL; }
    rv = amvp_hexstr_to_bin(z, stc->z, AMVP_KDF135_X963_INPUT_MAX, &stc->z_len);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (z)");
        return rv;
    }

    stc->shared_info = calloc(AMVP_KDF135_X963_INPUT_MAX, sizeof(char));
    if (!stc->shared_info) { return AMVP_MALLOC_FAIL; }
    rv = amvp_hexstr_to_bin(shared_info, stc->shared_info, AMVP_KDF135_X963_INPUT_MAX, NULL);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (shared_info)");
        return rv;
    }

    stc->key_data = calloc(AMVP_KDF135_X963_KEYDATA_MAX_BYTES, sizeof(char));
    if (!stc->key_data) { return AMVP_MALLOC_FAIL; }

    return AMVP_SUCCESS;
}

AMVP_RESULT amvp_kdf135_x963_kat_handler(AMVP_CTX *ctx, JSON_Object *obj) {
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

    int i = 0, g_cnt = 0;
    int j = 0, t_cnt = 0;

    JSON_Value *r_vs_val = NULL;
    JSON_Object *r_vs = NULL;
    JSON_Array *r_tarr = NULL, *r_garr = NULL;  /* Response testarray, grouparray */
    JSON_Value *r_tval = NULL, *r_gval = NULL;  /* Response testval, groupval */
    JSON_Object *r_tobj = NULL, *r_gobj = NULL; /* Response testobj, groupobj */
    AMVP_CAPS_LIST *cap;
    AMVP_KDF135_X963_TC stc;
    AMVP_TEST_CASE tc;
    AMVP_RESULT rv;
    const char *alg_str = NULL;
    const char *mode_str = NULL;
    AMVP_CIPHER alg_id;
    char *json_result;

    int field_size = 0, key_data_length = 0, shared_info_len = 0;
    const char *z = NULL, *shared_info = NULL;

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
        AMVP_LOG_ERR("Server JSON missing 'algorithm'");
        return AMVP_MISSING_ARG;
    }

    mode_str = json_object_get_string(obj, "mode");
    if (!mode_str) {
        AMVP_LOG_ERR("Server JSON missing 'mode'");
        return AMVP_MISSING_ARG;
    }
    
    alg_id = amvp_lookup_cipher_w_mode_index(alg_str, mode_str);
    if (alg_id != AMVP_KDF135_X963) {
        AMVP_LOG_ERR("Server JSON invalid 'algorithm' or 'mode'");
        return AMVP_INVALID_ARG;
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.kdf135_x963 = &stc;
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
    json_object_set_string(r_vs, "mode", "ansix9.63");

    groups = json_object_get_array(obj, "testGroups");
    if (!groups) {
        AMVP_LOG_ERR("Failed to include testGroups. ");
        rv = AMVP_MISSING_ARG;
        goto err;
    }

    g_cnt = json_array_get_count(groups);
    for (i = 0; i < g_cnt; i++) {
        int tgId = 0;
        AMVP_HASH_ALG hash_alg = 0;
        const char *hash_alg_str = NULL;

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

        field_size = json_object_get_number(groupobj, "fieldSize");
        if (!field_size) {
            AMVP_LOG_ERR("Failed to include field size. ");
            rv = AMVP_MISSING_ARG;
            goto err;
        }

        key_data_length = json_object_get_number(groupobj, "keyDataLength");
        if (!key_data_length) {
            AMVP_LOG_ERR("Failed to include key data length. ");
            rv = AMVP_MISSING_ARG;
            goto err;
        }

        shared_info_len = json_object_get_number(groupobj, "sharedInfoLength");

        hash_alg_str = json_object_get_string(groupobj, "hashAlg");
        if (!hash_alg_str) {
            AMVP_LOG_ERR("Failed to include hashAlg. ");
            rv = AMVP_MISSING_ARG;
            goto err;
        }
        hash_alg = amvp_lookup_hash_alg(hash_alg_str);
        if (hash_alg != AMVP_SHA224 && hash_alg != AMVP_SHA256 &&
            hash_alg != AMVP_SHA384 && hash_alg != AMVP_SHA512) {
            AMVP_LOG_ERR("Server JSON invalid 'hashAlg'");
            rv = AMVP_INVALID_ARG;
            goto err;
        }

        AMVP_LOG_VERBOSE("\n    Test group: %d", i);
        AMVP_LOG_VERBOSE("         hashAlg: %s", hash_alg_str);
        AMVP_LOG_VERBOSE("       fieldSize: %d", field_size);
        AMVP_LOG_VERBOSE("   sharedInfoLen: %d", shared_info_len);
        AMVP_LOG_VERBOSE("   keyDataLength: %d", key_data_length);

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
            AMVP_LOG_VERBOSE("Found new KDF135 X963 test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            tc_id = json_object_get_number(testobj, "tcId");
            if (!tc_id) {
                AMVP_LOG_ERR("Failed to include tc_id. ");
                rv = AMVP_MISSING_ARG;
                goto err;
            }

            z = json_object_get_string(testobj, "z");
            shared_info = json_object_get_string(testobj, "sharedInfo");
            if (!z) {
                AMVP_LOG_ERR("Failed to include z. ");
                rv = AMVP_INVALID_ARG;
                goto err;
            }

            if (!shared_info) {
                AMVP_LOG_ERR("Failed to include shared_info. ");
                rv = AMVP_INVALID_ARG;
                goto err;
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
             * the crypto module.
             */
            rv = amvp_kdf135_x963_init_tc(ctx, &stc, tc_id, hash_alg,
                                          field_size, key_data_length,
                                          shared_info_len, z, shared_info);
            if (rv != AMVP_SUCCESS) {
                amvp_kdf135_x963_release_tc(&stc);
                json_value_free(r_tval);
                goto err;
            }

            /* Process the current test vector... */
            if ((cap->crypto_handler)(&tc)) {
                AMVP_LOG_ERR("crypto module failed the KDF SSH operation");
                amvp_kdf135_x963_release_tc(&stc);
                rv = AMVP_CRYPTO_MODULE_FAIL;
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Output the test case results using JSON
             */
            rv = amvp_kdf135_x963_output_tc(ctx, &stc, r_tobj);
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("JSON output failure in hash module");
                amvp_kdf135_x963_release_tc(&stc);
                json_value_free(r_tval);
                goto err;
            }
            /*
             * Release all the memory associated with the test case
             */
            amvp_kdf135_x963_release_tc(&stc);

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
