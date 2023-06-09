/** @file */
/*
 * Copyright (c) 2020, Cisco Systems, Inc.
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
static AMVP_RESULT amvp_kdf108_output_tc(AMVP_CTX *ctx,
                                         AMVP_KDF108_TC *stc,
                                         JSON_Object *tc_rsp) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    char *tmp = NULL;

    tmp = calloc(AMVP_KDF108_KEYOUT_STR_MAX + 1, sizeof(char));
    if (!tmp) {
        AMVP_LOG_ERR("Unable to malloc");
        return AMVP_MALLOC_FAIL;
    }

    /*
     * Length check
     */
    if (stc->key_out_len > AMVP_KDF108_KEYOUT_BYTE_MAX) {
        AMVP_LOG_ERR("stc->key_out_len > AMVP_KDF108_KEYOUT_BYTE_MAX(%u)",
                     AMVP_KDF108_KEYOUT_BYTE_MAX);
        rv = AMVP_INVALID_ARG;
        goto end;
    }

    rv = amvp_bin_to_hexstr(stc->key_out, stc->key_out_len,
                            tmp, AMVP_KDF108_KEYOUT_STR_MAX);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("hex conversion failure (key_out)");
        goto end;
    }
    json_object_set_string(tc_rsp, "keyOut", tmp);

    free(tmp);

    tmp = calloc(AMVP_KDF108_FIXED_DATA_STR_MAX + 1, sizeof(char));
    if (!tmp) {
        AMVP_LOG_ERR("Unable to malloc");
        return AMVP_MALLOC_FAIL;
    }

    /*
     * Length check
     */
    if (stc->fixed_data_len > AMVP_KDF108_FIXED_DATA_BYTE_MAX) {
        AMVP_LOG_ERR("stc->fixed_data_len > AMVP_KDF108_FIXED_DATA_BYTE_MAX(%u)",
                     AMVP_KDF108_FIXED_DATA_BYTE_MAX);
        rv = AMVP_INVALID_ARG;
        goto end;
    }

    rv = amvp_bin_to_hexstr(stc->fixed_data, stc->fixed_data_len,
                            tmp, AMVP_KDF108_FIXED_DATA_STR_MAX);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("hex conversion failure (fixed_data)");
        goto end;
    }
    json_object_set_string(tc_rsp, "fixedData", tmp);

end:
    if (tmp) free(tmp);

    return rv;
}

static AMVP_RESULT amvp_kdf108_init_tc(AMVP_KDF108_TC *stc,
                                       unsigned int tc_id,
                                       AMVP_KDF108_MODE kdf_mode,
                                       AMVP_KDF108_MAC_MODE_VAL mac_mode,
                                       AMVP_KDF108_FIXED_DATA_ORDER_VAL counter_location,
                                       const char *key_in,
                                       const char *iv,
                                       int key_in_len,
                                       int key_out_len,
                                       int iv_len,
                                       int counter_len,
                                       int deferred) {
    AMVP_RESULT rv;

    memzero_s(stc, sizeof(AMVP_KDF108_TC));

    // Allocate space for the key_in (binary)
    stc->key_in = calloc(key_in_len, sizeof(unsigned char));
    if (!stc->key_in) { return AMVP_MALLOC_FAIL; }

    // Convert key_in from hex string to binary
    rv = amvp_hexstr_to_bin(key_in, stc->key_in, key_in_len, NULL);
    if (rv != AMVP_SUCCESS) return rv;

    if (iv != NULL) {
        /*
         * Feedback mode.
         * Allocate space for the iv.
         */
        stc->iv = calloc(iv_len, sizeof(unsigned char));
        if (!stc->iv) { return AMVP_MALLOC_FAIL; }

        // Convert iv from hex string to binary
        rv = amvp_hexstr_to_bin(iv, stc->iv, iv_len, NULL);
        if (rv != AMVP_SUCCESS) return rv;
    }

    /*
     * Allocate space for the key_out
     * User supplies the data.
     */
    stc->key_out = calloc(key_out_len, sizeof(unsigned char));
    if (!stc->key_out) { return AMVP_MALLOC_FAIL; }

    /*
     * Allocate space for the fixed_data.
     * User supplies the data.
     */
    stc->fixed_data = calloc(AMVP_KDF108_FIXED_DATA_BYTE_MAX,
                             sizeof(unsigned char));
    if (!stc->fixed_data) { return AMVP_MALLOC_FAIL; }

    stc->tc_id = tc_id;
    stc->cipher = AMVP_KDF108;
    stc->mode = kdf_mode;
    stc->mac_mode = mac_mode;
    stc->counter_location = counter_location;
    stc->key_in_len = key_in_len;
    stc->key_out_len = key_out_len;
    stc->counter_len = counter_len;
    stc->deferred = deferred;

    return AMVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static AMVP_RESULT amvp_kdf108_release_tc(AMVP_KDF108_TC *stc) {
    if (stc->key_in) free(stc->key_in);
    if (stc->key_out) free(stc->key_out);
    if (stc->fixed_data) free(stc->fixed_data);
    if (stc->iv) free(stc->iv);

    memzero_s(stc, sizeof(AMVP_KDF108_TC));
    return AMVP_SUCCESS;
}

AMVP_KDF108_MODE read_mode(const char *str) {
    int diff = 1;

    strcmp_s(AMVP_MODE_COUNTER, 7, str, &diff);
    if (!diff) return AMVP_KDF108_MODE_COUNTER;

    strcmp_s(AMVP_MODE_FEEDBACK, 8, str, &diff);
    if (!diff) return AMVP_KDF108_MODE_FEEDBACK;

    strcmp_s(AMVP_MODE_DPI, 25, str, &diff);
    if (!diff) return AMVP_KDF108_MODE_DPI;

    return 0;
}

AMVP_KDF108_MAC_MODE_VAL read_mac_mode(const char *str) {
    int diff = 1;

    strcmp_s(AMVP_ALG_HMAC_SHA1,
             AMVP_ALG_NAME_MAX,
             str, &diff);
    if (!diff) return AMVP_KDF108_MAC_MODE_HMAC_SHA1;

    strcmp_s(AMVP_ALG_HMAC_SHA2_224,
             AMVP_ALG_NAME_MAX,
             str, &diff);
    if (!diff) return AMVP_KDF108_MAC_MODE_HMAC_SHA224;

    strcmp_s(AMVP_ALG_HMAC_SHA2_256,
             AMVP_ALG_NAME_MAX,
             str, &diff);
    if (!diff) return AMVP_KDF108_MAC_MODE_HMAC_SHA256;

    strcmp_s(AMVP_ALG_HMAC_SHA2_384,
             AMVP_ALG_NAME_MAX,
             str, &diff);
    if (!diff) return AMVP_KDF108_MAC_MODE_HMAC_SHA384;

    strcmp_s(AMVP_ALG_HMAC_SHA2_512,
             AMVP_ALG_NAME_MAX,
             str, &diff);
    if (!diff) return AMVP_KDF108_MAC_MODE_HMAC_SHA512;

    strcmp_s(AMVP_ALG_HMAC_SHA2_512_224,
             AMVP_ALG_NAME_MAX,
             str, &diff);
    if (!diff) return AMVP_KDF108_MAC_MODE_HMAC_SHA512_224;

    strcmp_s(AMVP_ALG_HMAC_SHA2_512_256,
             AMVP_ALG_NAME_MAX,
             str, &diff);
    if (!diff) return AMVP_KDF108_MAC_MODE_HMAC_SHA512_256;

    strcmp_s(AMVP_ALG_HMAC_SHA3_224,
             AMVP_ALG_NAME_MAX,
             str, &diff);
    if (!diff) return AMVP_KDF108_MAC_MODE_HMAC_SHA3_224;

    strcmp_s(AMVP_ALG_HMAC_SHA3_256,
             AMVP_ALG_NAME_MAX,
             str, &diff);
    if (!diff) return AMVP_KDF108_MAC_MODE_HMAC_SHA3_256;

    strcmp_s(AMVP_ALG_HMAC_SHA3_384,
             AMVP_ALG_NAME_MAX,
             str, &diff);
    if (!diff) return AMVP_KDF108_MAC_MODE_HMAC_SHA3_384;

    strcmp_s(AMVP_ALG_HMAC_SHA3_512,
             AMVP_ALG_NAME_MAX,
             str, &diff);
    if (!diff) return AMVP_KDF108_MAC_MODE_HMAC_SHA3_512;


    strcmp_s(AMVP_ALG_CMAC_AES_128,
             AMVP_ALG_NAME_MAX,
             str, &diff);
    if (!diff) return AMVP_KDF108_MAC_MODE_CMAC_AES128;

    strcmp_s(AMVP_ALG_CMAC_AES_192,
             AMVP_ALG_NAME_MAX,
             str, &diff);
    if (!diff) return AMVP_KDF108_MAC_MODE_CMAC_AES192;

    strcmp_s(AMVP_ALG_CMAC_AES_256,
             AMVP_ALG_NAME_MAX,
             str, &diff);
    if (!diff) return AMVP_KDF108_MAC_MODE_CMAC_AES256;

    strcmp_s(AMVP_ALG_CMAC_TDES,
             AMVP_ALG_NAME_MAX,
             str, &diff);
    if (!diff) return AMVP_KDF108_MAC_MODE_CMAC_TDES;

    return 0;
}

AMVP_KDF108_FIXED_DATA_ORDER_VAL read_ctr_location(const char *str) {
    int diff = 1;

    strcmp_s(AMVP_FIXED_DATA_ORDER_AFTER_STR, 16, str, &diff);
    if (!diff) return AMVP_KDF108_FIXED_DATA_ORDER_AFTER;

    strcmp_s(AMVP_FIXED_DATA_ORDER_BEFORE_STR, 17, str, &diff);
    if (!diff) return AMVP_KDF108_FIXED_DATA_ORDER_BEFORE;

    strcmp_s(AMVP_FIXED_DATA_ORDER_MIDDLE_STR, 17, str, &diff);
    if (!diff) return AMVP_KDF108_FIXED_DATA_ORDER_MIDDLE;

    strcmp_s(AMVP_FIXED_DATA_ORDER_NONE_STR, 4, str, &diff);
    if (!diff) return AMVP_KDF108_FIXED_DATA_ORDER_NONE;

    strcmp_s(AMVP_FIXED_DATA_ORDER_BEFORE_ITERATOR_STR, 15, str, &diff);
    if (!diff) return AMVP_KDF108_FIXED_DATA_ORDER_BEFORE_ITERATOR;

    return 0;
}

AMVP_RESULT amvp_kdf108_kat_handler(AMVP_CTX *ctx, JSON_Object *obj) {
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
    AMVP_KDF108_TC stc;
    AMVP_TEST_CASE tc;
    AMVP_RESULT rv;
    const char *alg_str = NULL;
    AMVP_CIPHER alg_id = 0;
    char *json_result;

    AMVP_KDF108_MODE kdf_mode = 0;
    AMVP_KDF108_MAC_MODE_VAL mac_mode = 0;
    AMVP_KDF108_FIXED_DATA_ORDER_VAL ctr_loc = 0;
    int key_out_bit_len = 0, key_out_len = 0, key_in_len = 0,
        iv_len = 0, ctr_len = 0, deferred = 0;
    const char *kdf_mode_str = NULL, *mac_mode_str = NULL, *key_in_str = NULL,
               *iv_str = NULL, *ctr_loc_str = NULL;

    if (!ctx) {
        AMVP_LOG_ERR("No ctx for handler operation");
        return AMVP_NO_CTX;
    }

    alg_str = json_object_get_string(obj, "algorithm");
    if (!alg_str) {
        AMVP_LOG_ERR("unable to parse 'algorithm' from JSON.");
        return AMVP_MALFORMED_JSON;
    }
    alg_id = amvp_lookup_cipher_index(alg_str);
    if (alg_id != AMVP_KDF108) {
        AMVP_LOG_ERR("Invalid algorithm %s", alg_str);
        return AMVP_INVALID_ARG;
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.kdf108 = &stc;

    /*
     * Get the crypto module handler for this hash algorithm
     */
    cap = amvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        AMVP_LOG_ERR("AMVP server requesting unsupported capability");
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

        kdf_mode_str = json_object_get_string(groupobj, "kdfMode");
        if (!kdf_mode_str) {
            AMVP_LOG_ERR("Failed to include kdfMode");
            rv = AMVP_MISSING_ARG;
            goto err;
        }
        kdf_mode = read_mode(kdf_mode_str);
        if (!kdf_mode) {
            AMVP_LOG_ERR("Server JSON invalid kdfMode");
            rv = AMVP_INVALID_ARG;
            goto err;
        }

        mac_mode_str = json_object_get_string(groupobj, "macMode");
        if (!mac_mode_str) {
            AMVP_LOG_ERR("Server JSON missing macMode");
            rv = AMVP_MISSING_ARG;
            goto err;
        }
        mac_mode = read_mac_mode(mac_mode_str);
        if (!mac_mode) {
            AMVP_LOG_ERR("Server JSON invalid macMode");
            rv = AMVP_INVALID_ARG;
            goto err;
        }

        key_out_bit_len = json_object_get_number(groupobj, "keyOutLength");
        if (!key_out_bit_len || key_out_bit_len > AMVP_KDF108_KEYOUT_BIT_MAX) {
            AMVP_LOG_ERR("Server JSON invalid keyOutLength, (%d)", key_out_len);
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        // Get the keyout byte length  (+1 for overflow bits)
        key_out_len = (key_out_bit_len + 7) / 8;

        ctr_len = json_object_get_number(groupobj, "counterLength");
        if (kdf_mode == AMVP_KDF108_MODE_COUNTER) {
            /* Only check during counter mode */
            if (ctr_len != 8 && ctr_len != 16 &&
                ctr_len != 24 && ctr_len != 32) {
                AMVP_LOG_ERR("Server JSON invalid counterLength, (%d)", ctr_len);
                rv = AMVP_INVALID_ARG;
                goto err;
            }
        }

        ctr_loc_str = json_object_get_string(groupobj, "counterLocation");
        if (!ctr_loc_str) {
            AMVP_LOG_ERR("Server JSON missing counterLocation");
            rv = AMVP_MISSING_ARG;
            goto err;
        }
        ctr_loc = read_ctr_location(ctr_loc_str);
        if (!ctr_loc) {
            AMVP_LOG_ERR("Server JSON invalid counterLocation.");
            rv = AMVP_INVALID_ARG;
            goto err;
        }

        /*
         * Log Test Group information...
         */
        AMVP_LOG_VERBOSE("    Test group: %d", i);
        AMVP_LOG_VERBOSE("       kdfMode: %s", kdf_mode_str);
        AMVP_LOG_VERBOSE("       macMode: %s", mac_mode_str);
        AMVP_LOG_VERBOSE("     keyOutLen: %d", key_out_bit_len);
        AMVP_LOG_VERBOSE("    counterLen: %d", ctr_len);
        AMVP_LOG_VERBOSE("    counterLoc: %s", ctr_loc_str);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);
        for (j = 0; j < t_cnt; j++) {
            AMVP_LOG_VERBOSE("Found new kdf108 test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            tc_id = json_object_get_number(testobj, "tcId");

            key_in_str = json_object_get_string(testobj, "keyIn");
            if (!key_in_str) {
                AMVP_LOG_ERR("Server JSON missing keyIn");
                rv = AMVP_MISSING_ARG;
                goto err;
            }

            key_in_len = strnlen_s(key_in_str, AMVP_KDF108_KEYIN_STR_MAX + 1);
            if (key_in_len > AMVP_KDF108_KEYIN_STR_MAX) {
                AMVP_LOG_ERR("keyIn too long, max allowed=(%d)",
                             AMVP_KDF108_KEYIN_STR_MAX);
                rv = AMVP_INVALID_ARG;
                goto err;
            }
            // Convert to byte length
            key_in_len = key_in_len / 2;

            if (kdf_mode == AMVP_KDF108_MODE_FEEDBACK) {
                iv_str = json_object_get_string(testobj, "iv");
                if (!iv_str) {
                    AMVP_LOG_ERR("Server JSON missing iv");
                    rv = AMVP_MISSING_ARG;
                    goto err;
               }

                iv_len = strnlen_s(iv_str, AMVP_KDF108_IV_STR_MAX + 1);
                if (iv_len > AMVP_KDF108_IV_STR_MAX) {
                    AMVP_LOG_ERR("iv too long, max allowed=(%d)",
                                 AMVP_KDF108_IV_STR_MAX);
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }

                // Convert to byte length
                iv_len = iv_len / 2;
            }

            deferred = json_object_get_boolean(testobj, "deferred");
            if (deferred == -1 && ctr_loc == AMVP_KDF108_FIXED_DATA_ORDER_MIDDLE) {
                AMVP_LOG_ERR("Server JSON missing deferred");
                rv = AMVP_MISSING_ARG;
                goto err;
            }

            /*
             * Log Test Case information...
             */
            AMVP_LOG_VERBOSE("        Test case: %d", j);
            AMVP_LOG_VERBOSE("             tcId: %d", tc_id);
            AMVP_LOG_VERBOSE("            keyIn: %s", key_in_str);
            AMVP_LOG_VERBOSE("         deferred: %d", deferred);

            /*
             * Setup the test case data that will be passed down to
             * the crypto module.
             */
            rv = amvp_kdf108_init_tc(&stc, tc_id, kdf_mode, mac_mode,
                                     ctr_loc, key_in_str, iv_str, key_in_len,
                                     key_out_len, iv_len, ctr_len, deferred);
            if (rv != AMVP_SUCCESS) {
                amvp_kdf108_release_tc(&stc);
                goto err;
            }

            /* Process the current test vector... */
            if ((cap->crypto_handler)(&tc)) {
                AMVP_LOG_ERR("crypto module failed the operation");
                amvp_kdf108_release_tc(&stc);
                rv = AMVP_CRYPTO_MODULE_FAIL;
                goto err;
            }

            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);

            json_object_set_number(r_tobj, "tcId", tc_id);

            /*
             * Output the test case results using JSON
             */
            rv = amvp_kdf108_output_tc(ctx, &stc, r_tobj);
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("JSON output failure in kdf135 tpm module");
                json_value_free(r_tval);
                amvp_kdf108_release_tc(&stc);
                goto err;
            }
            /*
             * Release all the memory associated with the test case
             */
            amvp_kdf108_release_tc(&stc);

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
