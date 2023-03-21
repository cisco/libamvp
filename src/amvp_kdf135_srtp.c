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
static AMVP_RESULT amvp_kdf135_srtp_output_tc(AMVP_CTX *ctx, AMVP_KDF135_SRTP_TC *stc, JSON_Object *tc_rsp) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    char *tmp = NULL;

    tmp = calloc(AMVP_KDF135_SRTP_OUTPUT_MAX + 1, sizeof(char));
    if (!tmp) { return AMVP_MALLOC_FAIL; }

    rv = amvp_bin_to_hexstr(stc->srtp_ke, stc->aes_keylen / 8, tmp, AMVP_KDF135_SRTP_OUTPUT_MAX);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("hex conversion failure (srtp_ke)");
        goto err;
    }
    json_object_set_string(tc_rsp, "srtpKe", (const char *)tmp);
    memzero_s(tmp, AMVP_KDF135_SRTP_OUTPUT_MAX);

    rv = amvp_bin_to_hexstr(stc->srtp_ka, 160 / 8, tmp, AMVP_KDF135_SRTP_OUTPUT_MAX);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("hex conversion failure (srtp_ka)");
        goto err;
    }
    json_object_set_string(tc_rsp, "srtpKa", (const char *)tmp);
    memzero_s(tmp, AMVP_KDF135_SRTP_OUTPUT_MAX);

    rv = amvp_bin_to_hexstr(stc->srtp_ks, 112 / 8, tmp, AMVP_KDF135_SRTP_OUTPUT_MAX);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("hex conversion failure (srtp_ks)");
        goto err;
    }
    json_object_set_string(tc_rsp, "srtpKs", (const char *)tmp);
    memzero_s(tmp, AMVP_KDF135_SRTP_OUTPUT_MAX);

    rv = amvp_bin_to_hexstr(stc->srtcp_ke, stc->aes_keylen / 8, tmp, AMVP_KDF135_SRTP_OUTPUT_MAX);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("hex conversion failure (srtcp_ke)");
        goto err;
    }
    json_object_set_string(tc_rsp, "srtcpKe", (const char *)tmp);
    memzero_s(tmp, AMVP_KDF135_SRTP_OUTPUT_MAX);

    rv = amvp_bin_to_hexstr(stc->srtcp_ka, 160 / 8, tmp, AMVP_KDF135_SRTP_OUTPUT_MAX);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("hex conversion failure (srtcp_ka)");
        goto err;
    }
    json_object_set_string(tc_rsp, "srtcpKa", (const char *)tmp);
    memzero_s(tmp, AMVP_KDF135_SRTP_OUTPUT_MAX);

    rv = amvp_bin_to_hexstr(stc->srtcp_ks, 112 / 8, tmp, AMVP_KDF135_SRTP_OUTPUT_MAX);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("hex conversion failure (srtcp_ks)");
        goto err;
    }
    json_object_set_string(tc_rsp, "srtcpKs", (const char *)tmp);
    memzero_s(tmp, AMVP_KDF135_SRTP_OUTPUT_MAX);

err:
    free(tmp);
    return rv;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static AMVP_RESULT amvp_kdf135_srtp_release_tc(AMVP_KDF135_SRTP_TC *stc) {
    if (stc->kdr) free(stc->kdr);
    if (stc->master_key) free(stc->master_key);
    if (stc->master_salt) free(stc->master_salt);
    if (stc->idx) free(stc->idx);
    if (stc->srtcp_idx) free(stc->srtcp_idx);
    if (stc->srtp_ke) free(stc->srtp_ke);
    if (stc->srtp_ka) free(stc->srtp_ka);
    if (stc->srtp_ks) free(stc->srtp_ks);
    if (stc->srtcp_ke) free(stc->srtcp_ke);
    if (stc->srtcp_ka) free(stc->srtcp_ka);
    if (stc->srtcp_ks) free(stc->srtcp_ks);
    memzero_s(stc, sizeof(AMVP_KDF135_SRTP_TC));
    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_kdf135_srtp_init_tc(AMVP_CTX *ctx,
                                            AMVP_KDF135_SRTP_TC *stc,
                                            unsigned int tc_id,
                                            int aes_keylen,
                                            const char *kdr,
                                            const char *master_key,
                                            const char *master_salt,
                                            const char *idx,
                                            const char *srtcp_idx) {
    AMVP_RESULT rv = AMVP_SUCCESS;

    memzero_s(stc, sizeof(AMVP_KDF135_SRTP_TC));

    if (!kdr || !master_key || !master_salt || !idx || !srtcp_idx) {
        AMVP_LOG_ERR("Missing parameters - initalize KDF SRTP test case");
        return AMVP_INVALID_ARG;
    }

    stc->tc_id = tc_id;
    stc->aes_keylen = aes_keylen;

    stc->kdr = calloc(AMVP_KDF135_SRTP_KDR_STR_MAX, sizeof(char));
    if (!stc->kdr) { return AMVP_MALLOC_FAIL; }
    rv = amvp_hexstr_to_bin(kdr, stc->kdr, AMVP_KDF135_SRTP_KDR_STR_MAX, &(stc->kdr_len));
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (kdr)");
        return rv;
    }

    stc->master_key = calloc(AMVP_KDF135_SRTP_MASTER_MAX, sizeof(char));
    if (!stc->master_key) { return AMVP_MALLOC_FAIL; }
    rv = amvp_hexstr_to_bin(master_key, (unsigned char *)stc->master_key,
                            AMVP_KDF135_SRTP_MASTER_MAX, NULL);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (master_key)");
        return rv;
    }

    stc->master_salt = calloc(AMVP_KDF135_SRTP_MASTER_MAX, sizeof(char));
    if (!stc->master_salt) { return AMVP_MALLOC_FAIL; }
    rv = amvp_hexstr_to_bin(master_salt, (unsigned char *)stc->master_salt,
                            AMVP_KDF135_SRTP_MASTER_MAX, NULL);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (master_salt)");
        return rv;
    }

    stc->idx = calloc(AMVP_KDF135_SRTP_INDEX_MAX, sizeof(char));
    if (!stc->idx) { return AMVP_MALLOC_FAIL; }
    rv = amvp_hexstr_to_bin(idx, (unsigned char *)stc->idx, AMVP_KDF135_SRTP_INDEX_MAX,
                            NULL);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (idx)");
        return rv;
    }

    stc->srtcp_idx = calloc(AMVP_KDF135_SRTP_INDEX_MAX, sizeof(char));
    if (!stc->srtcp_idx) { return AMVP_MALLOC_FAIL; }
    rv = amvp_hexstr_to_bin(srtcp_idx, (unsigned char *)stc->srtcp_idx,
                            AMVP_KDF135_SRTP_INDEX_MAX, NULL);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (srtcp_idx)");
        return rv;
    }

    stc->srtp_ka = calloc(AMVP_KDF135_SRTP_OUTPUT_MAX, sizeof(char));
    if (!stc->srtp_ka) { return AMVP_MALLOC_FAIL; }
    stc->srtp_ke = calloc(AMVP_KDF135_SRTP_OUTPUT_MAX, sizeof(char));
    if (!stc->srtp_ke) { return AMVP_MALLOC_FAIL; }
    stc->srtp_ks = calloc(AMVP_KDF135_SRTP_OUTPUT_MAX, sizeof(char));
    if (!stc->srtp_ks) { return AMVP_MALLOC_FAIL; }
    stc->srtcp_ka = calloc(AMVP_KDF135_SRTP_OUTPUT_MAX, sizeof(char));
    if (!stc->srtcp_ka) { return AMVP_MALLOC_FAIL; }
    stc->srtcp_ke = calloc(AMVP_KDF135_SRTP_OUTPUT_MAX, sizeof(char));
    if (!stc->srtcp_ke) { return AMVP_MALLOC_FAIL; }
    stc->srtcp_ks = calloc(AMVP_KDF135_SRTP_OUTPUT_MAX, sizeof(char));
    if (!stc->srtcp_ks) { return AMVP_MALLOC_FAIL; }

    return AMVP_SUCCESS;
}

AMVP_RESULT amvp_kdf135_srtp_kat_handler(AMVP_CTX *ctx, JSON_Object *obj) {
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
    AMVP_KDF135_SRTP_TC stc;
    AMVP_TEST_CASE tc;
    AMVP_RESULT rv;
    const char *alg_str = json_object_get_string(obj, "algorithm");
    const char *mode_str = NULL;
    AMVP_CIPHER alg_id;
    char *json_result;

    int aes_key_length;
    const char *kdr = NULL, *master_key = NULL, *master_salt = NULL, *idx = NULL, *srtcp_idx = NULL;

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
    if (alg_id != AMVP_KDF135_SRTP) {
        AMVP_LOG_ERR("Server JSON invalid 'algorithm' or 'mode'");
        return AMVP_INVALID_ARG;
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.kdf135_srtp = &stc;
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
        goto err;
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

        aes_key_length = json_object_get_number(groupobj, "aesKeyLength");
        if (!aes_key_length) {
            AMVP_LOG_ERR("aesKeyLength incorrect, %d", aes_key_length);
            rv = AMVP_INVALID_ARG;
            goto err;
        }

        kdr = json_object_get_string(groupobj, "kdr");
        if (!kdr) {
            AMVP_LOG_ERR("Failed to include kdr");
            rv = AMVP_MISSING_ARG;
            goto err;
        }

        AMVP_LOG_VERBOSE("\n    Test group: %d", i);
        AMVP_LOG_VERBOSE("           kdr: %s", kdr);
        AMVP_LOG_VERBOSE("    key length: %d", aes_key_length);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);

        for (j = 0; j < t_cnt; j++) {
            AMVP_LOG_VERBOSE("Found new KDF SRTP test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            tc_id = json_object_get_number(testobj, "tcId");

            master_key = json_object_get_string(testobj, "masterKey");
            if (!master_key) {
                AMVP_LOG_ERR("Failed to include JSON key:\"masterKey\"");
                rv = AMVP_MISSING_ARG;
                goto err;
            }

            master_salt = json_object_get_string(testobj, "masterSalt");
            if (!master_salt) {
                AMVP_LOG_ERR("Failed to include JSON key:\"masterSalt\"");
                rv = AMVP_MISSING_ARG;
                goto err;
            }

            idx = json_object_get_string(testobj, "index");
            if (!idx) {
                AMVP_LOG_ERR("Failed to include JSON key:\"idx\"");
                rv = AMVP_MISSING_ARG;
                goto err;
            }

            srtcp_idx = json_object_get_string(testobj, "srtcpIndex");
            if (!srtcp_idx) {
                AMVP_LOG_ERR("Failed to include JSON key:\"srtcpIndex\"");
                rv = AMVP_MISSING_ARG;
                goto err;
            }

            AMVP_LOG_VERBOSE("        Test case: %d", j);
            AMVP_LOG_VERBOSE("             tcId: %d", tc_id);
            AMVP_LOG_VERBOSE("        masterKey: %s", master_key);
            AMVP_LOG_VERBOSE("       masterSalt: %s", master_salt);
            AMVP_LOG_VERBOSE("            idx: %s", idx);
            AMVP_LOG_VERBOSE("       srtcpIndex: %s", srtcp_idx);

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
            rv = amvp_kdf135_srtp_init_tc(ctx, &stc, tc_id, aes_key_length, kdr, master_key, master_salt, idx, srtcp_idx);
            if (rv != AMVP_SUCCESS) {
                amvp_kdf135_srtp_release_tc(&stc);
                json_value_free(r_tval);
                goto err;
            }

            /* Process the current test vector... */
            if ((cap->crypto_handler)(&tc)) {
                AMVP_LOG_ERR("crypto module failed");
                amvp_kdf135_srtp_release_tc(&stc);
                rv = AMVP_CRYPTO_MODULE_FAIL;
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Output the test case results using JSON
             */
            rv = amvp_kdf135_srtp_output_tc(ctx, &stc, r_tobj);
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("JSON output failure");
                amvp_kdf135_srtp_release_tc(&stc);
                json_value_free(r_tval);
                goto err;
            }
            /*
             * Release all the memory associated with the test case
             */
            amvp_kdf135_srtp_release_tc(&stc);

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
