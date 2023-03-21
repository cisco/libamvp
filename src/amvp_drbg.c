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
static AMVP_RESULT amvp_drbg_output_tc(AMVP_CTX *ctx, AMVP_DRBG_TC *stc, JSON_Object *tc_rsp);

static AMVP_RESULT amvp_drbg_init_tc(AMVP_CTX *ctx,
                                     AMVP_DRBG_TC *stc,
                                     unsigned int tc_id,
                                     const char *additional_input_0,
                                     const char *entropy_input_pr_0,
                                     const char *additional_input_1,
                                     const char *entropy_input_pr_1,
                                     const char *additional_input_2,
                                     const char *entropy_input_pr_2,
                                     int pr1_len,
                                     int pr2_len,
                                     const char *perso_string,
                                     const char *entropy,
                                     const char *nonce,
                                     int reseed,
                                     int der_func_enabled,
                                     int pred_resist_enabled,
                                     unsigned int additional_input_len,
                                     unsigned int perso_string_len,
                                     unsigned int entropy_len,
                                     unsigned int nonce_len,
                                     unsigned int drb_len,
                                     AMVP_DRBG_MODE mode_id,
                                     AMVP_CIPHER alg_id);

static AMVP_RESULT amvp_drbg_release_tc(AMVP_DRBG_TC *stc);

AMVP_RESULT amvp_drbg_kat_handler(AMVP_CTX *ctx, JSON_Object *obj) {
    char *json_result = NULL;

    JSON_Value *reg_arry_val = NULL;
    JSON_Object *reg_obj = NULL;
    JSON_Array *reg_arry = NULL;

    JSON_Value *groupval;
    JSON_Object *groupobj = NULL;
    JSON_Value *testval;
    JSON_Object *testobj = NULL;
    JSON_Array *groups;
    JSON_Array *tests;
    JSON_Array *pred_resist_input;
    int i, g_cnt;
    int j, t_cnt;
    JSON_Value *r_vs_val = NULL;
    JSON_Object *r_vs = NULL;
    JSON_Array *r_tarr = NULL, *r_garr = NULL;  /* Response testarray, grouparray */
    JSON_Value *r_tval = NULL, *r_gval = NULL;  /* Response testval, groupval */
    JSON_Object *r_tobj = NULL, *r_gobj = NULL; /* Response testobj, groupobj */
    AMVP_CAPS_LIST *cap;
    AMVP_DRBG_TC stc;
    AMVP_TEST_CASE tc;
    AMVP_RESULT rv;
    const char *alg_str = NULL, *int_use = NULL;
    AMVP_CIPHER alg_id;
    AMVP_DRBG_MODE mode_id;
    int index = 0;
    int pr1_len = 0, pr2_len = 0, diff = 0;

    if (!ctx) {
        AMVP_LOG_ERR("No ctx for handler operation");
        return AMVP_NO_CTX;
    }

    alg_str = json_object_get_string(obj, "algorithm");
    if (!alg_str) {
        AMVP_LOG_ERR("unable to parse 'algorithm' from JSON");
        return AMVP_MALFORMED_JSON;
    }

    AMVP_LOG_VERBOSE("    DRBG alg: %s", alg_str);

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.drbg = &stc;

    /*
     * Get the crypto module handler for this DRBG algorithm
     */
    alg_id = amvp_lookup_cipher_index(alg_str);
    if ((alg_id < AMVP_HASHDRBG) || (alg_id > AMVP_CTRDRBG)) {
        AMVP_LOG_ERR("unsupported algorithm (%s)", alg_str);
        return AMVP_UNSUPPORTED_OP;
    }

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
    AMVP_LOG_VERBOSE("Number of TestGroups: %d", g_cnt);
    for (i = 0; i < g_cnt; i++) {
        int tgId = 0;
        const char *mode_str = NULL;
        int der_func_enabled = 0, pred_resist_enabled = 0, reseed = 0;
        unsigned int perso_string_len = 0, entropy_len = 0, nonce_len = 0,
                     drb_len = 0, additional_input_len = 0;
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

        /*
         * Get DRBG Mode index
         */
        mode_str = json_object_get_string(groupobj, "mode");
        if (!mode_str) {
            AMVP_LOG_ERR("Server JSON missing 'mode'");
            rv = AMVP_MALFORMED_JSON;
            goto err;
        }
        mode_id = amvp_lookup_drbg_mode_index(mode_str);
        if (mode_id == 0) {
            AMVP_LOG_ERR("unsupported DRBG mode (%s)", mode_str);
            rv = AMVP_UNSUPPORTED_OP;
            goto err;
        }

        /*
         * Handle Group Params
         */
        pred_resist_enabled = json_object_get_boolean(groupobj, "predResistance");
        if (pred_resist_enabled == -1) {
            AMVP_LOG_ERR("Server JSON missing 'predResistance'");
            rv = AMVP_MISSING_ARG;
            goto err;
        }
        reseed = json_object_get_boolean(groupobj, "reSeed");
        if (reseed == -1) {
            AMVP_LOG_ERR("Server JSON missing reseedImplemented'");
            rv = AMVP_MISSING_ARG;
            goto err;
        }


        if (alg_id == AMVP_CTRDRBG) {
            der_func_enabled = json_object_get_boolean(groupobj, "derFunc");
            if (der_func_enabled == -1) {
                AMVP_LOG_ERR("Server JSON missing 'derFunc'");
                rv = AMVP_MISSING_ARG;
                goto err;
            }
        }

        entropy_len = json_object_get_number(groupobj, "entropyInputLen");
        if (entropy_len < AMVP_DRBG_ENTPY_IN_BIT_MIN ||
            entropy_len > AMVP_DRBG_ENTPY_IN_BIT_MAX) {
            AMVP_LOG_ERR("Server JSON invalid 'entropyInputLen'(%u)",
                         entropy_len);
            rv = AMVP_INVALID_ARG;
            goto err;
        }

        nonce_len = json_object_get_number(groupobj, "nonceLen");
        if (!(alg_id == AMVP_CTRDRBG && !der_func_enabled)) {
            /* Allowed to be 0 when counter mode and not using derivation func */
            if (nonce_len < AMVP_DRBG_NONCE_BIT_MIN ||
                nonce_len > AMVP_DRBG_NONCE_BIT_MAX) {
                AMVP_LOG_ERR("Server JSON invalid 'nonceLen'(%u)",
                             nonce_len);
                rv = AMVP_INVALID_ARG;
                goto err;
            }
        }

        perso_string_len = json_object_get_number(groupobj, "persoStringLen");
        if (perso_string_len > AMVP_DRBG_PER_SO_BIT_MAX) {
            AMVP_LOG_ERR("Server JSON invalid 'persoStringLen'(%u)",
                         nonce_len);
            rv = AMVP_INVALID_ARG;
            goto err;
        }

        drb_len = json_object_get_number(groupobj, "returnedBitsLen");
        if (!drb_len || drb_len > AMVP_DRB_BIT_MAX) {
            AMVP_LOG_ERR("Server JSON invalid 'returnedBitsLen'(%u)",
                         drb_len);
            rv = AMVP_INVALID_ARG;
            goto err;
        }

        additional_input_len = json_object_get_number(groupobj, "additionalInputLen");
        if (additional_input_len > AMVP_DRBG_ADDI_IN_BIT_MAX) {
            AMVP_LOG_ERR("Server JSON invalid 'additionalInputLen'(%u)",
                         additional_input_len);
            rv = AMVP_INVALID_ARG;
            goto err;
        }

        AMVP_LOG_VERBOSE("    Test group:");
        AMVP_LOG_VERBOSE("    DRBG mode: %s", mode_str);
        AMVP_LOG_VERBOSE("    derFunc: %s", der_func_enabled ? "true" : "false");
        AMVP_LOG_VERBOSE("    predResistance: %s", pred_resist_enabled ? "true" : "false");
        AMVP_LOG_VERBOSE("    reseed: %s", reseed ? "true" : "false");
        AMVP_LOG_VERBOSE("    entropyInputLen: %d", entropy_len);
        AMVP_LOG_VERBOSE("    additionalInputLen: %d", additional_input_len);
        AMVP_LOG_VERBOSE("    persoStringLen: %d", perso_string_len);
        AMVP_LOG_VERBOSE("    nonceLen: %d", nonce_len);
        AMVP_LOG_VERBOSE("    returnedBitsLen: %d", drb_len);

        /*
         * Handle test array
         */
        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);
        AMVP_LOG_VERBOSE("Number of Tests: %d", t_cnt);
        for (j = 0; j < t_cnt; j++) {
            JSON_Value *pr_input_val = NULL;
            JSON_Object *pr_input_obj = NULL;
            unsigned int tc_id = 0, pr_input_count = 0;
            const char *additional_input_0 = NULL, *entropy_input_pr_0 = NULL,
                       *additional_input_1 = NULL, *entropy_input_pr_1 = NULL,
                       *additional_input_2 = NULL, *entropy_input_pr_2 = NULL,
                       *perso_string = NULL, *entropy = NULL, *nonce = NULL;

            AMVP_LOG_VERBOSE("Found new DRBG test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            json_result = json_serialize_to_string_pretty(testval, NULL);
            AMVP_LOG_VERBOSE("json testval count: %d\n %s\n", i, json_result);
            json_free_serialized_string(json_result);

            tc_id = json_object_get_number(testobj, "tcId");

            perso_string = json_object_get_string(testobj, "persoString");
            if (!perso_string) {
                AMVP_LOG_ERR("Server JSON missing 'persoString'");
                rv = AMVP_MISSING_ARG;
                goto err;
            }
            if (strnlen_s(perso_string, AMVP_DRBG_PER_SO_STR_MAX + 1)
                > AMVP_DRBG_PER_SO_STR_MAX) {
                AMVP_LOG_ERR("persoString too long, max allowed=(%d)",
                             AMVP_DRBG_PER_SO_STR_MAX);
                rv = AMVP_INVALID_ARG;
                goto err;
            }

            entropy = json_object_get_string(testobj, "entropyInput");
            if (!entropy) {
                AMVP_LOG_ERR("Server JSON missing 'entropyInput'");
                rv = AMVP_MISSING_ARG;
                goto err;
            }
            if (strnlen_s(entropy, AMVP_DRBG_ENTPY_IN_STR_MAX + 1)
                > AMVP_DRBG_ENTPY_IN_STR_MAX) {
                AMVP_LOG_ERR("entropyInput too long, max allowed=(%d)",
                             AMVP_DRBG_ENTPY_IN_STR_MAX);
                rv = AMVP_INVALID_ARG;
                goto err;
            }

            nonce = json_object_get_string(testobj, "nonce");
            if (!nonce) {
                AMVP_LOG_ERR("Server JSON missing 'nonce'");
                rv = AMVP_MISSING_ARG;
                goto err;
            }
            if (strnlen_s(nonce, AMVP_DRBG_NONCE_STR_MAX + 1)
                > AMVP_DRBG_NONCE_STR_MAX) {
                AMVP_LOG_ERR("nonce too long, max allowed=(%d)",
                             AMVP_DRBG_NONCE_STR_MAX);
                rv = AMVP_INVALID_ARG;
                goto err;
            }

            AMVP_LOG_VERBOSE("        Test case: %d", j);
            AMVP_LOG_VERBOSE("             tcId: %d", tc_id);
            AMVP_LOG_VERBOSE("             entropyInput: %s", entropy);
            AMVP_LOG_VERBOSE("             perso_string: %s", perso_string);
            AMVP_LOG_VERBOSE("             nonce: %s", nonce);

            /*
             * Handle pred_resist_input array. Has at most 2 elements
             */
            pred_resist_input = json_object_get_array(testobj, "otherInput");
            if (!pred_resist_input) {
                AMVP_LOG_ERR("Server JSON missing 'otherInput'");
                rv = AMVP_MISSING_ARG;
                goto err;
            }

            pr_input_count = json_array_get_count(pred_resist_input);
            if (!pr_input_count) {
                AMVP_LOG_ERR("Server JSON array 'otherInput' is empty");
                rv = AMVP_INVALID_ARG;
                goto err;
            }

            index = 0;
            if (!pred_resist_enabled && reseed) {
                AMVP_LOG_VERBOSE("Found new DRBG Prediction Input...");

                /* Get 1st element from the array */
                pr_input_val = json_array_get_value(pred_resist_input, index);
                if (pr_input_val == NULL) {
                   AMVP_LOG_ERR("Server JSON, invalid pr_input_val array");
                   rv = AMVP_INVALID_ARG;
                   goto err;
                }
                pr_input_obj = json_value_get_object(pr_input_val);
            
                if (pr_input_count != 3) {
                   AMVP_LOG_ERR("Server JSON, invalid number of entries, %d", pr_input_count);
                   rv = AMVP_INVALID_ARG;
                   goto err;
                }

                int_use = json_object_get_string(pr_input_obj, "intendedUse");
                strncmp_s(int_use, 6, "reSeed", 6, &diff);
                if (diff) {
                   AMVP_LOG_ERR("Server JSON, intended use should be reSeed");
                   rv = AMVP_INVALID_ARG;
                   goto err;
                }

                additional_input_0 = json_object_get_string(pr_input_obj, "additionalInput");
                if (!additional_input_0) {
                   AMVP_LOG_ERR("Server JSON in otherInput[%d], missing 'additionalInput'", 0);
                   rv = AMVP_MISSING_ARG;
                   goto err;
                }
                if (strnlen_s(additional_input_0, AMVP_DRBG_ADDI_IN_STR_MAX + 1)
                    > AMVP_DRBG_ADDI_IN_STR_MAX) {
                    AMVP_LOG_ERR("In otherInput[%d], additionalInput too long. Max allowed=(%d)",
                                 0, AMVP_DRBG_ADDI_IN_STR_MAX);
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }

                entropy_input_pr_0 = json_object_get_string(pr_input_obj, "entropyInput");
                if (!entropy_input_pr_0) {
                   AMVP_LOG_ERR("Server JSON in otherInput[%d], missing 'entropyInput'", 0);
                   rv = AMVP_MISSING_ARG;
                   goto err;
                }
                if (strnlen_s(entropy_input_pr_0, AMVP_DRBG_ENTPY_IN_STR_MAX + 1)
                    > AMVP_DRBG_ENTPY_IN_STR_MAX) {
                    AMVP_LOG_ERR("In otherInput[%d], entropyInput too long. Max allowed=(%d)",
                                 0, AMVP_DRBG_ENTPY_IN_STR_MAX);
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }
                index++;
            }

            if ((index == 0) && (pr_input_count != 2)) {
               AMVP_LOG_ERR("Server JSON, invalid number of entries, %d", pr_input_count);
               rv = AMVP_INVALID_ARG;
               goto err;
            }

            /* Get 1st or 2nd element from the array */
            pr_input_val = json_array_get_value(pred_resist_input, index);
            if (pr_input_val == NULL) {
               AMVP_LOG_ERR("Server JSON, invalid pr_input_val array");
               rv = AMVP_INVALID_ARG;
               goto err;
            }
            pr_input_obj = json_value_get_object(pr_input_val);

            int_use = json_object_get_string(pr_input_obj, "intendedUse");
            strncmp_s(int_use, 8, "generate", 8, &diff);
            if (diff) {
               AMVP_LOG_ERR("Server JSON, intended use should be generate");
               rv = AMVP_INVALID_ARG;
               goto err;
            }

            additional_input_1 = json_object_get_string(pr_input_obj, "additionalInput");
            if (!additional_input_1) {
               AMVP_LOG_ERR("Server JSON in otherInput[%d], missing 'additionalInput'", 0);
               rv = AMVP_MISSING_ARG;
               goto err;
            }
            if (strnlen_s(additional_input_1, AMVP_DRBG_ADDI_IN_STR_MAX + 1)
                > AMVP_DRBG_ADDI_IN_STR_MAX) {
                AMVP_LOG_ERR("In otherInput[%d], additionalInput too long. Max allowed=(%d)",
                             0, AMVP_DRBG_ADDI_IN_STR_MAX);
                rv = AMVP_INVALID_ARG;
                goto err;
            }

            entropy_input_pr_1 = json_object_get_string(pr_input_obj, "entropyInput");
            if (!entropy_input_pr_1) {
                AMVP_LOG_ERR("Server JSON in otherInput[%d], missing 'entropyInput'", 0);
                rv = AMVP_MISSING_ARG;
                goto err;
            }
            pr1_len = strnlen_s(entropy_input_pr_1, AMVP_DRBG_ENTPY_IN_STR_MAX + 1);
            if (pr1_len > AMVP_DRBG_ENTPY_IN_STR_MAX) {
                AMVP_LOG_ERR("In otherInput[%d], entropyInput too long. Max allowed=(%d)",
                             0, AMVP_DRBG_ENTPY_IN_STR_MAX);
                rv = AMVP_INVALID_ARG;
                goto err;
            }
            pr1_len = pr1_len/2; 
            index++;
            /*
             * Get 2nd or 3rd element from the array
             */
            pr_input_val = json_array_get_value(pred_resist_input, index);
            if (pr_input_val == NULL) {
                AMVP_LOG_ERR("Server JSON, invalid pr_input_val array");
                rv = AMVP_INVALID_ARG;
                goto err;
            }
            pr_input_obj = json_value_get_object(pr_input_val);

            int_use = json_object_get_string(pr_input_obj, "intendedUse");
            strncmp_s(int_use, 8, "generate",8 , &diff);
            if (diff) {
                AMVP_LOG_ERR("Server JSON, intended use should be generate");
                rv = AMVP_INVALID_ARG;
                goto err;
            }

            additional_input_2 = json_object_get_string(pr_input_obj, "additionalInput");
            if (!additional_input_2) {
               AMVP_LOG_ERR("Server JSON in otherInput[%d], missing 'additionalInput'", 1);
               rv = AMVP_MISSING_ARG;
               goto err;
            }
            if (strnlen_s(additional_input_2, AMVP_DRBG_ADDI_IN_STR_MAX + 1)
                > AMVP_DRBG_ADDI_IN_STR_MAX) {
                AMVP_LOG_ERR("In otherInput[%d], additionalInput too long. Max allowed=(%d)",
                             1, AMVP_DRBG_ADDI_IN_STR_MAX);
                rv = AMVP_INVALID_ARG;
                goto err;
            }

            entropy_input_pr_2 = json_object_get_string(pr_input_obj, "entropyInput");
            if (!entropy_input_pr_2) {
                AMVP_LOG_ERR("Server JSON in otherInput[%d], missing 'entropyInput'", 1);
                rv = AMVP_MISSING_ARG;
                goto err;
            }
            pr2_len = strnlen_s(entropy_input_pr_2, AMVP_DRBG_ENTPY_IN_STR_MAX + 1);
            if (pr2_len > AMVP_DRBG_ENTPY_IN_STR_MAX) {
                AMVP_LOG_ERR("In otherInput[%d], entropyInput too long. Max allowed=(%d)",
                             1, AMVP_DRBG_ENTPY_IN_STR_MAX);
                rv = AMVP_INVALID_ARG;
                goto err;
            }
            pr2_len = pr2_len/2; 
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
            rv = amvp_drbg_init_tc(ctx, &stc, tc_id, additional_input_0,
                                   entropy_input_pr_0, additional_input_1,
                                   entropy_input_pr_1, additional_input_2,
                                   entropy_input_pr_2, pr1_len, pr2_len,
                                   perso_string,
                                   entropy, nonce, reseed,
                                   der_func_enabled, pred_resist_enabled,
                                   additional_input_len, perso_string_len,
                                   entropy_len, nonce_len,
                                   drb_len, mode_id, alg_id);

            if (rv != AMVP_SUCCESS) {
                amvp_drbg_release_tc(&stc);
                json_value_free(r_tval);
                goto err;
            }

            /* Process the current test vector... */
            if ((cap->crypto_handler)(&tc)) {
                AMVP_LOG_ERR("crypto module failed the operation");
                rv = AMVP_CRYPTO_MODULE_FAIL;
                amvp_drbg_release_tc(&stc);
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Output the test case results using JSON
             */
            rv = amvp_drbg_output_tc(ctx, &stc, r_tobj);
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("JSON output failure in DRBG module");
                amvp_drbg_release_tc(&stc);
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Release all the memory associated with the test case
             */
            amvp_drbg_release_tc(&stc);

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
static AMVP_RESULT amvp_drbg_output_tc(AMVP_CTX *ctx, AMVP_DRBG_TC *stc, JSON_Object *tc_rsp) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    char *tmp = NULL;

    tmp = calloc(AMVP_DRB_STR_MAX + 1, sizeof(char));
    if (!tmp) {
        AMVP_LOG_ERR("Unable to malloc in amvp_drbg_output_tc");
        return AMVP_MALLOC_FAIL;
    }

    rv = amvp_bin_to_hexstr(stc->drb, stc->drb_len, tmp, AMVP_DRB_STR_MAX);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("hex conversion failure (returnedBits)");
        goto end;
    }
    json_object_set_string(tc_rsp, "returnedBits", tmp);

end:
    if (tmp) free(tmp);

    return rv;
}

static AMVP_RESULT amvp_drbg_init_tc(AMVP_CTX *ctx,
                                     AMVP_DRBG_TC *stc,
                                     unsigned int tc_id,
                                     const char *additional_input_0,
                                     const char *entropy_input_pr_0,
                                     const char *additional_input_1,
                                     const char *entropy_input_pr_1,
                                     const char *additional_input_2,
                                     const char *entropy_input_pr_2,
                                     int pr1_len,
                                     int pr2_len,
                                     const char *perso_string,
                                     const char *entropy,
                                     const char *nonce,
                                     int reseed,
                                     int der_func_enabled,
                                     int pred_resist_enabled,
                                     unsigned int additional_input_len,
                                     unsigned int perso_string_len,
                                     unsigned int entropy_len,
                                     unsigned int nonce_len,
                                     unsigned int drb_len,
                                     AMVP_DRBG_MODE mode_id,
                                     AMVP_CIPHER alg_id) {
    AMVP_RESULT rv;

    memzero_s(stc, sizeof(AMVP_DRBG_TC));

    stc->drb = calloc(AMVP_DRB_BYTE_MAX, sizeof(unsigned char));
    if (!stc->drb) { return AMVP_MALLOC_FAIL; }
    stc->additional_input_0 = calloc(AMVP_DRBG_ADDI_IN_BYTE_MAX, sizeof(unsigned char));
    if (!stc->additional_input_0) { return AMVP_MALLOC_FAIL; }
    stc->additional_input_1 = calloc(AMVP_DRBG_ADDI_IN_BYTE_MAX, sizeof(unsigned char));
    if (!stc->additional_input_1) { return AMVP_MALLOC_FAIL; }
    stc->additional_input_2 = calloc(AMVP_DRBG_ADDI_IN_BYTE_MAX, sizeof(unsigned char));
    if (!stc->additional_input_2) { return AMVP_MALLOC_FAIL; }
    stc->entropy = calloc(AMVP_DRBG_ENTPY_IN_BYTE_MAX, sizeof(unsigned char));
    if (!stc->entropy) { return AMVP_MALLOC_FAIL; }
    stc->entropy_input_pr_0 = calloc(AMVP_DRBG_ENTPY_IN_BYTE_MAX, sizeof(unsigned char));
    if (!stc->entropy_input_pr_0) { return AMVP_MALLOC_FAIL; }
    stc->entropy_input_pr_1 = calloc(AMVP_DRBG_ENTPY_IN_BYTE_MAX, sizeof(unsigned char));
    if (!stc->entropy_input_pr_1) { return AMVP_MALLOC_FAIL; }
    stc->entropy_input_pr_2 = calloc(AMVP_DRBG_ENTPY_IN_BYTE_MAX, sizeof(unsigned char));
    if (!stc->entropy_input_pr_2) { return AMVP_MALLOC_FAIL; }
    stc->nonce = calloc(AMVP_DRBG_NONCE_BYTE_MAX, sizeof(unsigned char));
    if (!stc->nonce) { return AMVP_MALLOC_FAIL; }
    stc->perso_string = calloc(AMVP_DRBG_PER_SO_BYTE_MAX, sizeof(unsigned char));
    if (!stc->perso_string) { return AMVP_MALLOC_FAIL; }

    if (additional_input_0) {
        rv = amvp_hexstr_to_bin(additional_input_0, stc->additional_input_0,
                                AMVP_DRBG_ADDI_IN_BYTE_MAX, NULL);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (additional_input_0)");
            return rv;
        }
    }

    if (entropy_input_pr_0) {
        rv = amvp_hexstr_to_bin(entropy_input_pr_0, stc->entropy_input_pr_0,
                                AMVP_DRBG_ENTPY_IN_BYTE_MAX, NULL);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (entropy_input_pr_0)");
            return rv;
        }
    }

    if (additional_input_1) {
        rv = amvp_hexstr_to_bin(additional_input_1, stc->additional_input_1,
                                AMVP_DRBG_ADDI_IN_BYTE_MAX, NULL);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (additional_input_1)");
            return rv;
        }
    }

    if (entropy_input_pr_1) {
        rv = amvp_hexstr_to_bin(entropy_input_pr_1, stc->entropy_input_pr_1,
                                AMVP_DRBG_ENTPY_IN_BYTE_MAX, NULL);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (entropy_input_pr_1)");
            return rv;
        }
    }

    if (additional_input_2) {
        rv = amvp_hexstr_to_bin(additional_input_2, stc->additional_input_2,
                                AMVP_DRBG_ADDI_IN_BYTE_MAX, NULL);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (2nd additional_input_2)");
            return rv;
        }
    }

    if (entropy_input_pr_2) {
        rv = amvp_hexstr_to_bin(entropy_input_pr_2, stc->entropy_input_pr_2,
                                AMVP_DRBG_ENTPY_IN_BYTE_MAX, NULL);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (2nd entropy_input_pr_2)");
            return rv;
        }
    }

    if (entropy) {
        rv = amvp_hexstr_to_bin(entropy, stc->entropy,
                                AMVP_DRBG_ENTPY_IN_BYTE_MAX, NULL);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (entropy)");
            return rv;
        }
    }

    if (perso_string) {
        rv = amvp_hexstr_to_bin(perso_string, stc->perso_string,
                                AMVP_DRBG_PER_SO_BYTE_MAX, NULL);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (perso_string)");
            return rv;
        }
    }

    if (nonce) {
        rv = amvp_hexstr_to_bin(nonce, stc->nonce,
                                AMVP_DRBG_NONCE_BYTE_MAX, NULL);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (nonce)");
            return rv;
        }
    }

    stc->der_func_enabled = der_func_enabled;
    stc->pred_resist_enabled = pred_resist_enabled;
    stc->reseed = reseed;
    stc->pr1_len = pr1_len;
    stc->pr2_len = pr2_len;
    stc->additional_input_len = AMVP_BIT2BYTE(additional_input_len);
    stc->perso_string_len = AMVP_BIT2BYTE(perso_string_len);
    stc->entropy_len = AMVP_BIT2BYTE(entropy_len);
    stc->nonce_len = AMVP_BIT2BYTE(nonce_len);
    stc->drb_len = AMVP_BIT2BYTE(drb_len);

    stc->tc_id = tc_id;
    stc->mode = mode_id;
    stc->cipher = alg_id;

    return AMVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static AMVP_RESULT amvp_drbg_release_tc(AMVP_DRBG_TC *stc) {
    if (stc->drb) free(stc->drb);
    if (stc->additional_input_0) free(stc->additional_input_0);
    if (stc->additional_input_1) free(stc->additional_input_1);
    if (stc->additional_input_2) free(stc->additional_input_2);
    if (stc->entropy) free(stc->entropy);
    if (stc->entropy_input_pr_0) free(stc->entropy_input_pr_0);
    if (stc->entropy_input_pr_1) free(stc->entropy_input_pr_1);
    if (stc->entropy_input_pr_2) free(stc->entropy_input_pr_2);
    if (stc->nonce) free(stc->nonce);
    if (stc->perso_string) free(stc->perso_string);

    memzero_s(stc, sizeof(AMVP_DRBG_TC));
    return AMVP_SUCCESS;
}
