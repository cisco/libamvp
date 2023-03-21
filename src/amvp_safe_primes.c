/** @file */
/*
 * Copyright (c) 2021, Cisco Systems, Inc.
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

static AMVP_SAFE_PRIMES_TEST_TYPE read_test_type(const char *str) {
    int diff = 1;

    strcmp_s("AFT", 3, str, &diff);
    if (!diff) return AMVP_SAFE_PRIMES_TT_AFT;

    strcmp_s("VAL", 3, str, &diff);
    if (!diff) return AMVP_SAFE_PRIMES_TT_VAL;

    return 0;
}

static AMVP_SAFE_PRIMES_PARAM amvp_convert_dgm_string(const char *dgm_str)
{
    int diff = 0;

    strcmp_s("MODP-2048", DGM_STR_MAX, dgm_str, &diff);
    if (!diff) return AMVP_SAFE_PRIMES_MODP2048;
    strcmp_s("MODP-3072", DGM_STR_MAX, dgm_str, &diff);
    if (!diff) return AMVP_SAFE_PRIMES_MODP3072;
    strcmp_s("MODP-4096", DGM_STR_MAX, dgm_str, &diff);
    if (!diff) return AMVP_SAFE_PRIMES_MODP4096;
    strcmp_s("MODP-6144", DGM_STR_MAX, dgm_str, &diff);
    if (!diff) return AMVP_SAFE_PRIMES_MODP6144;
    strcmp_s("MODP-8192", DGM_STR_MAX, dgm_str, &diff);
    if (!diff) return AMVP_SAFE_PRIMES_MODP8192;
    strcmp_s("ffdhe2048", DGM_STR_MAX, dgm_str, &diff);
    if (!diff) return AMVP_SAFE_PRIMES_FFDHE2048;
    strcmp_s("ffdhe3072", DGM_STR_MAX, dgm_str, &diff);
    if (!diff) return AMVP_SAFE_PRIMES_FFDHE3072;
    strcmp_s("ffdhe4096", DGM_STR_MAX, dgm_str, &diff);
    if (!diff) return AMVP_SAFE_PRIMES_FFDHE4096;
    strcmp_s("ffdhe6144", DGM_STR_MAX, dgm_str, &diff);
    if (!diff) return AMVP_SAFE_PRIMES_FFDHE6144;
    strcmp_s("ffdhe8192", DGM_STR_MAX, dgm_str, &diff);
    if (!diff) return AMVP_SAFE_PRIMES_FFDHE8192;

    return 0;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static AMVP_RESULT amvp_safe_primes_release_tc(AMVP_SAFE_PRIMES_TC *stc) {
    if (stc->x) free(stc->x);
    if (stc->y) free(stc->y);
    memzero_s(stc, sizeof(AMVP_SAFE_PRIMES_TC));
    return AMVP_SUCCESS;
}


static AMVP_RESULT amvp_safe_primes_output_tc(AMVP_CTX *ctx,
                                              AMVP_SAFE_PRIMES_TC *stc,
                                              JSON_Object *tc_rsp) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    char *tmp = NULL;

    if (stc->cipher == AMVP_SAFE_PRIMES_KEYVER) {

        if (stc->result) {
            json_object_set_boolean(tc_rsp, "testPassed", 1);
        } else {
            json_object_set_boolean(tc_rsp, "testPassed", 0);
        }

    } else {
        tmp = calloc(AMVP_SAFE_PRIMES_STR_MAX + 1, sizeof(char));
        if (!tmp) {
            AMVP_LOG_ERR("Unable to malloc in amvp_safe_primes_output_mct_tc");
            return AMVP_MALLOC_FAIL;
        }

        memzero_s(tmp, AMVP_SAFE_PRIMES_STR_MAX);
        rv = amvp_bin_to_hexstr(stc->x, stc->xlen, tmp, AMVP_SAFE_PRIMES_STR_MAX);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("hex conversion failure (x)");
            goto end;
        }
        json_object_set_string(tc_rsp, "x", tmp);

        memzero_s(tmp, AMVP_SAFE_PRIMES_STR_MAX);
        rv = amvp_bin_to_hexstr(stc->y, stc->ylen, tmp, AMVP_SAFE_PRIMES_STR_MAX);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("hex conversion failure (y)");
            goto end;
        }
        json_object_set_string(tc_rsp, "y", tmp);
    }

end:
    if (tmp) free(tmp);

    return rv;
}

static AMVP_RESULT amvp_safe_primes_init_tc(AMVP_CTX *ctx,
                                            int tg_id,
                                            int tc_id,
                                            AMVP_CIPHER alg_id,
                                            AMVP_SAFE_PRIMES_TC *stc,
                                            AMVP_SAFE_PRIMES_PARAM dgm,
                                            const char *x,
                                            const char *y,
                                            AMVP_SAFE_PRIMES_TEST_TYPE test_type) {
    AMVP_RESULT rv;

    stc->tg_id = tg_id;
    stc->tc_id = tc_id;
    stc->dgm = dgm;
    stc->test_type = test_type;
    stc-> cipher = alg_id;

    if (alg_id == AMVP_SAFE_PRIMES_KEYVER) {
        stc->y = calloc(1, AMVP_SAFE_PRIMES_BYTE_MAX);
        if (!stc->y) { return AMVP_MALLOC_FAIL; }
        rv = amvp_hexstr_to_bin(y, stc->y, AMVP_SAFE_PRIMES_BYTE_MAX, &(stc->ylen));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (y)");
            return rv;
        }
        stc->x = calloc(1, AMVP_SAFE_PRIMES_BYTE_MAX);
        if (!stc->x) { return AMVP_MALLOC_FAIL; }
        rv = amvp_hexstr_to_bin(x, stc->x, AMVP_SAFE_PRIMES_BYTE_MAX, &(stc->xlen));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (x)");
            return rv;
        }
    } else {
        stc->x = calloc(1, AMVP_SAFE_PRIMES_BYTE_MAX);
        if (!stc->x) { return AMVP_MALLOC_FAIL; }
        stc->y = calloc(1, AMVP_SAFE_PRIMES_BYTE_MAX);
        if (!stc->y) { return AMVP_MALLOC_FAIL; }
    }
    return AMVP_SUCCESS;
}



AMVP_RESULT amvp_safe_primes_kat_handler(AMVP_CTX *ctx, JSON_Object *obj) {
    JSON_Value *r_vs_val = NULL;
    JSON_Object *r_vs = NULL;
    JSON_Array *r_garr = NULL; /* Response testarray */
    JSON_Value *reg_arry_val = NULL;
    JSON_Array *reg_arry = NULL;
    JSON_Object *reg_obj = NULL;
    JSON_Value *groupval;
    JSON_Object *groupobj = NULL;
    JSON_Value *testval;
    JSON_Object *testobj = NULL;
    JSON_Array *groups;
    JSON_Array *tests, *r_tarr = NULL;
    JSON_Value *r_tval = NULL, *r_gval = NULL;  /* Response testval, groupval */
    JSON_Object *r_tobj = NULL, *r_gobj = NULL; /* Response testobj, groupobj */
    AMVP_CAPS_LIST *cap;
    AMVP_TEST_CASE tc;
    AMVP_SAFE_PRIMES_TC stc;
    AMVP_RESULT rv = AMVP_SUCCESS;
    const char *alg_str = NULL, *dgm_str = NULL, *test_type_str = NULL;
    char *json_result = NULL;
    AMVP_CIPHER alg_id;
    AMVP_SAFE_PRIMES_PARAM dgm;
    AMVP_SAFE_PRIMES_TEST_TYPE test_type;
    const char *mode_str = NULL, *x = NULL, *y = NULL;
    unsigned int i, g_cnt;
    int j, t_cnt, tc_id, tg_id;
    AMVP_SUB_KAS alg;

    if (!ctx) {
        AMVP_LOG_ERR("No ctx for handler operation");
        return AMVP_NO_CTX;
    }

    alg_str = json_object_get_string(obj, "algorithm");
    if (!alg_str) {
        AMVP_LOG_ERR("unable to parse 'algorithm' from JSON");
        return AMVP_MALFORMED_JSON;
    }

    mode_str = json_object_get_string(obj, "mode");
    if (!mode_str) {
        AMVP_LOG_ERR("unable to parse mode' from JSON");
        return AMVP_MALFORMED_JSON;
    }


    alg_id = amvp_lookup_cipher_w_mode_index(alg_str, mode_str);
    if (alg_id == 0) {
        AMVP_LOG_ERR("Server JSON invalid 'algorithm' or 'mode'");
        return AMVP_INVALID_ARG;
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.safe_primes = &stc;
    memzero_s(&stc, sizeof(AMVP_SAFE_PRIMES_TC));

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
    json_object_set_string(r_vs, "mode", mode_str);

    groups = json_object_get_array(obj, "testGroups");
    g_cnt = json_array_get_count(groups);

    for (i = 0; i < g_cnt; i++) {
        groupval = json_array_get_value(groups, i);
        groupobj = json_value_get_object(groupval);

        /*
         * Create a new group in the response with the tgid
         * and an array of tests
         */
        r_gval = json_value_init_object();
        r_gobj = json_value_get_object(r_gval);
        tg_id = json_object_get_number(groupobj, "tgId");
        if (!tg_id) {
            AMVP_LOG_ERR("Missing tgid from server JSON groub obj");
            rv = AMVP_MISSING_ARG;
            goto err;
        }
        json_object_set_number(r_gobj, "tg_id", tg_id);
        json_object_set_value(r_gobj, "tests", json_value_init_array());
        r_tarr = json_object_get_array(r_gobj, "tests");

        dgm_str = json_object_get_string(groupobj, "safePrimeGroup");
        if (!dgm_str) {
            AMVP_LOG_ERR("Server JSON missing 'safePrimeGroup'");
            rv = AMVP_MISSING_ARG;
            goto err;
        }
        dgm = amvp_convert_dgm_string(dgm_str);
        if (!dgm) {
            AMVP_LOG_ERR("safePrimeGroup invalid");
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        AMVP_LOG_VERBOSE("    Test group: %d", i);
        AMVP_LOG_VERBOSE("      test alg: %s", alg_str);
        AMVP_LOG_VERBOSE("      est mode: %s", mode_str);
        AMVP_LOG_VERBOSE("         group: %s", dgm_str);


        alg = amvp_get_kas_alg(alg_id);
        if (alg == 0) {
            AMVP_LOG_ERR("Invalid cipher value");
            rv = AMVP_INVALID_ARG;
            goto err;
        }
    
        switch (alg) {
        case AMVP_SUB_SAFE_PRIMES_KEYGEN:

            tests = json_object_get_array(groupobj, "tests");
            t_cnt = json_array_get_count(tests);

            for (j = 0; j < t_cnt; j++) {

                AMVP_LOG_VERBOSE("Found new SAFE-PRIMES test vector...");
                testval = json_array_get_value(tests, j);
                testobj = json_value_get_object(testval);
                tc_id = json_object_get_number(testobj, "tcId");
                if (!tc_id) {
                    AMVP_LOG_ERR("Server JSON missing 'tcId'");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }

                test_type_str = json_object_get_string(groupobj, "testType");
                if (!test_type_str) {
                    AMVP_LOG_ERR("Server JSON missing 'testType'");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }

                test_type = read_test_type(test_type_str);
                if (!test_type) {
                    AMVP_LOG_ERR("Server JSON invalid 'testType'");
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }
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
                rv = amvp_safe_primes_init_tc(ctx, tg_id, tc_id, alg_id, 
                                              &stc, dgm, x, y, test_type);
                if (rv != AMVP_SUCCESS) {
                    amvp_safe_primes_release_tc(&stc);
                    json_value_free(r_tval);
                    goto err;
                }

                /* Process the current KAT test vector... */
                if ((cap->crypto_handler)(&tc)) {
                    amvp_safe_primes_release_tc(&stc);
                    AMVP_LOG_ERR("crypto module failed the operation");
                    rv = AMVP_CRYPTO_MODULE_FAIL;
                    json_value_free(r_tval);
                    goto err;
                }

                /*
                 * Output the test case results using JSON
                 */
                rv = amvp_safe_primes_output_tc(ctx, &stc, r_tobj);
                if (rv != AMVP_SUCCESS) {
                    AMVP_LOG_ERR("JSON output failure in KAS-FFC module");
                    amvp_safe_primes_release_tc(&stc);
                    json_value_free(r_tval);
                    goto err;
                }

                /*
                 * Release all the memory associated with the test case
                 */
                amvp_safe_primes_release_tc(&stc);

                /* Append the test response value to array */
                json_array_append_value(r_tarr, r_tval);
            }
            break;
        
        case AMVP_SUB_SAFE_PRIMES_KEYVER:
            tests = json_object_get_array(groupobj, "tests");
            t_cnt = json_array_get_count(tests);

            for (j = 0; j < t_cnt; j++) {

                AMVP_LOG_VERBOSE("Found new SAFE-PRIMES test vector...");
                testval = json_array_get_value(tests, j);
                testobj = json_value_get_object(testval);
                tc_id = json_object_get_number(testobj, "tcId");
                if (!tc_id) {
                    AMVP_LOG_ERR("Server JSON missing 'tcId'");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }


                test_type_str = json_object_get_string(groupobj, "testType");
                if (!test_type_str) {
                    AMVP_LOG_ERR("Server JSON missing 'testType'");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }

                test_type = read_test_type(test_type_str);
                if (!test_type) {
                    AMVP_LOG_ERR("Server JSON invalid 'testType'");
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }
                /*
                 * Create a new test case in the response
                 */
                r_tval = json_value_init_object();
                r_tobj = json_value_get_object(r_tval);

                json_object_set_number(r_tobj, "tcId", tc_id);


                x = json_object_get_string(testobj, "x");
                if (!x) {
                    AMVP_LOG_ERR("Server JSON missing 'x'");
                    rv = AMVP_MISSING_ARG;
                    json_value_free(r_tval);
                    goto err;
                }

                y = json_object_get_string(testobj, "y");
                if (!y) {
                    AMVP_LOG_ERR("Server JSON missing 'y'");
                    rv = AMVP_MISSING_ARG;
                    json_value_free(r_tval);
                    goto err;
                }

                /*
                 * Setup the test case data that will be passed down to
                 * the crypto module.
                 */
                 rv = amvp_safe_primes_init_tc(ctx, tg_id, tc_id, alg_id, 
                                               &stc, dgm, x, y, test_type);
                if (rv != AMVP_SUCCESS) {
                    amvp_safe_primes_release_tc(&stc);
                    json_value_free(r_tval);
                    goto err;
                }

                /* Process the current KAT test vector... */
                if ((cap->crypto_handler)(&tc)) {
                    amvp_safe_primes_release_tc(&stc);
                    AMVP_LOG_ERR("crypto module failed the operation");
                    rv = AMVP_CRYPTO_MODULE_FAIL;
                    json_value_free(r_tval);
                    goto err;
                }

                /*
                 * Output the test case results using JSON
                 */
                rv = amvp_safe_primes_output_tc(ctx, &stc, r_tobj);
                if (rv != AMVP_SUCCESS) {
                    AMVP_LOG_ERR("JSON output failure in KAS-FFC module");
                    amvp_safe_primes_release_tc(&stc);
                    json_value_free(r_tval);
                    goto err;
                }

                /*
                 * Release all the memory associated with the test case
                 */
                amvp_safe_primes_release_tc(&stc);

                /* Append the test response value to array */
                json_array_append_value(r_tarr, r_tval);
            }
            break;
        case AMVP_SUB_KAS_ECC_CDH:
        case AMVP_SUB_KAS_ECC_COMP:
        case AMVP_SUB_KAS_ECC_NOCOMP:
        case AMVP_SUB_KAS_ECC_SSC:
        case AMVP_SUB_KAS_FFC_COMP:
        case AMVP_SUB_KAS_FFC_NOCOMP:
        case AMVP_SUB_KAS_FFC_SSC:
        case AMVP_SUB_KAS_IFC_SSC:
        case AMVP_SUB_KTS_IFC:
        case AMVP_SUB_KDA_HKDF:
        case AMVP_SUB_KDA_ONESTEP:
        case AMVP_SUB_KDA_TWOSTEP:
        default:
            break;
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
        json_value_free(r_gval);
        amvp_safe_primes_release_tc(&stc);
        json_value_free(r_vs_val);
    }
    return rv;
}
