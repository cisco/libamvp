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

static AMVP_RESULT amvp_cmac_init_tc(AMVP_CTX *ctx,
                                     AMVP_CMAC_TC *stc,
                                     unsigned int tc_id,
                                     AMVP_CMAC_TESTTYPE testtype,
                                     const char *msg,
                                     unsigned int msg_len,
                                     const char *key,
                                     const char *key2,
                                     const char *key3,
                                     int direction_verify,
                                     const char *mac,
                                     unsigned int mac_len,
                                     AMVP_CIPHER alg_id) {
    AMVP_RESULT rv;

    if (!ctx) {
        return AMVP_NO_CTX;
    }
    if (alg_id != AMVP_CMAC_TDES && alg_id != AMVP_CMAC_AES) {
        return AMVP_INVALID_ARG;
    }
    if (!msg || !stc || !tc_id || !testtype || !key) {
        return AMVP_INVALID_ARG;
    }
    if (alg_id == AMVP_CMAC_TDES && (!key2 || !key3)) {
        return AMVP_INVALID_ARG;
    }
    if (direction_verify) {
        if (!mac_len || !mac) {
            return AMVP_INVALID_ARG;
        }
    }

    memzero_s(stc, sizeof(AMVP_CMAC_TC));

    stc->test_type = testtype;
    stc->msg = calloc(AMVP_CMAC_MSGLEN_MAX_STR, sizeof(unsigned char));
    if (!stc->msg) { return AMVP_MALLOC_FAIL; }

    stc->mac = calloc(AMVP_CMAC_MACLEN_MAX, sizeof(unsigned char));
    if (!stc->mac) { return AMVP_MALLOC_FAIL; }
    stc->key = calloc(1, AMVP_CMAC_KEY_MAX);
    if (!stc->key) { return AMVP_MALLOC_FAIL; }
    stc->mac_len = mac_len;

    if (direction_verify) {
        rv = amvp_hexstr_to_bin(mac, stc->mac, AMVP_CMAC_MACLEN_MAX, (int *)&(stc->mac_len));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex converstion failure (mac)");
            return rv;
        }
    }

    stc->key2 = calloc(1, AMVP_CMAC_KEY_MAX);
    if (!stc->key2) { return AMVP_MALLOC_FAIL; }
    stc->key3 = calloc(1, AMVP_CMAC_KEY_MAX);
    if (!stc->key3) { return AMVP_MALLOC_FAIL; }

    rv = amvp_hexstr_to_bin(msg, stc->msg, AMVP_CMAC_MSGLEN_MAX_STR, NULL);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex converstion failure (msg)");
        return rv;
    }

    if (alg_id == AMVP_CMAC_AES) {
        rv = amvp_hexstr_to_bin(key, stc->key, AMVP_CMAC_KEY_MAX, (int *)&(stc->key_len));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex converstion failure (key)");
            return rv;
        }
    } else if (alg_id == AMVP_CMAC_TDES) {
        rv = amvp_hexstr_to_bin(key, stc->key, AMVP_CMAC_KEY_MAX, NULL);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex converstion failure (key1)");
            return rv;
        }
        rv = amvp_hexstr_to_bin(key2, stc->key2, AMVP_CMAC_KEY_MAX, NULL);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex converstion failure (key2)");
            return rv;
        }
        rv = amvp_hexstr_to_bin(key3, stc->key3, AMVP_CMAC_KEY_MAX, NULL);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex converstion failure (key3)");
            return rv;
        }
    }

    if (direction_verify) {
        stc->verify = 1;
    }

    stc->tc_id = tc_id;
    stc->msg_len = msg_len;
    stc->cipher = alg_id;

    return AMVP_SUCCESS;
}

/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static AMVP_RESULT amvp_cmac_output_tc(AMVP_CTX *ctx, AMVP_CMAC_TC *stc, JSON_Object *tc_rsp) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    char *tmp = NULL;

    tmp = calloc(AMVP_CMAC_MACLEN_MAX + 1, sizeof(char));
    if (!tmp) {
        AMVP_LOG_ERR("Unable to malloc in amvp_cmac_output_tc");
        return AMVP_MALLOC_FAIL;
    }

    if (stc->verify) {
        json_object_set_boolean(tc_rsp, "testPassed", stc->ver_disposition);
    } else {
        rv = amvp_bin_to_hexstr(stc->mac, stc->mac_len, tmp, AMVP_CMAC_MACLEN_MAX);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("hex conversion failure (mac)");
            goto end;
        }
        json_object_set_string(tc_rsp, "mac", tmp);
    }

end:
    if (tmp) free(tmp);

    return rv;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static AMVP_RESULT amvp_cmac_release_tc(AMVP_CMAC_TC *stc) {
    if (stc->msg) free(stc->msg);
    if (stc->mac) free(stc->mac);
    if (stc->key) free(stc->key);
    if (stc->key2) free(stc->key2);
    if (stc->key3) free(stc->key3);
    memzero_s(stc, sizeof(AMVP_CMAC_TC));

    return AMVP_SUCCESS;
}

AMVP_RESULT amvp_cmac_kat_handler(AMVP_CTX *ctx, JSON_Object *obj) {
    unsigned int tc_id, msglen, keyLen = 0, keyingOption = 0, maclen, verify = 0;
    const char *msg = NULL, *key1 = NULL, *key2 = NULL, *key3 = NULL, *mac = NULL;
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
    AMVP_CMAC_TC stc;
    AMVP_TEST_CASE tc;
    AMVP_RESULT rv;
    const char *alg_str = json_object_get_string(obj, "algorithm");
    AMVP_CIPHER alg_id;
    char *json_result;
    AMVP_CMAC_TESTTYPE testtype;
    const char *direction = NULL, *test_type_str = NULL;
    int key1_len, key2_len, key3_len, json_msglen;

    if (!ctx) {
        AMVP_LOG_ERR("No ctx for handler operation");
        return AMVP_NO_CTX;
    }

    if (!obj) {
        AMVP_LOG_ERR("No obj for handler operation");
        return AMVP_MALFORMED_JSON;
    }

    if (!alg_str) {
        AMVP_LOG_ERR("ERROR: unable to parse 'algorithm' from JSON");
        return AMVP_MALFORMED_JSON;
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.cmac = &stc;

    /*
     * Get the crypto module handler for this hash algorithm
     */
    alg_id = amvp_lookup_cipher_index(alg_str);
    if (alg_id == 0) {
        AMVP_LOG_ERR("ERROR: unsupported algorithm (%s)", alg_str);
        return AMVP_UNSUPPORTED_OP;
    }
    cap = amvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        AMVP_LOG_ERR("ERROR: AMVP server requesting unsupported capability");
        return AMVP_UNSUPPORTED_OP;
    }

    /*
     * Create AMVP array for response
     */
    rv = amvp_create_array(&reg_obj, &reg_arry_val, &reg_arry);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("ERROR: Failed to create JSON response struct. ");
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
        int diff = 0;

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
            AMVP_LOG_ERR("Missing tgid from server JSON group obj");
            rv = AMVP_MALFORMED_JSON;
            goto err;
        }
        json_object_set_number(r_gobj, "tgId", tgId);
        json_object_set_value(r_gobj, "tests", json_value_init_array());
        r_tarr = json_object_get_array(r_gobj, "tests");

        if (alg_id == AMVP_CMAC_AES) {
            keyLen = json_object_get_number(groupobj, "keyLen");
            if (!keyLen) {
                AMVP_LOG_ERR("keylen missing from cmac aes json");
                rv = AMVP_MISSING_ARG;
                goto err;
            }
        } else if (alg_id == AMVP_CMAC_TDES) {
            keyingOption = json_object_get_number(groupobj, "keyingOption");
            if (keyingOption <= AMVP_CMAC_TDES_KEYING_OPTION_MIN ||
                keyingOption >= AMVP_CMAC_TDES_KEYING_OPTION_MAX) {
                AMVP_LOG_ERR("keyingOption missing or wrong from cmac tdes json");
                rv = AMVP_INVALID_ARG;
                goto err;
            }
        }

        test_type_str = json_object_get_string(groupobj, "testType");
        if (!test_type_str) {
            AMVP_LOG_ERR("Server JSON missing 'testType'");
            rv = AMVP_MISSING_ARG;
            goto err;
        }
        strcmp_s("AFT", 3, test_type_str, &diff);
        if (!diff) {
            testtype = AMVP_CMAC_TEST_TYPE_AFT;
        } else {
            AMVP_LOG_ERR("invalid 'testType' in server JSON.");
            rv = AMVP_UNSUPPORTED_OP;
            goto err;
        }

        direction = json_object_get_string(groupobj, "direction");
        if (!direction) {
            AMVP_LOG_ERR("Unable to parse 'direction' from JSON.");
            rv = AMVP_MALFORMED_JSON;
            goto err;
        }

        strcmp_s("ver", 3, direction, &diff);
        if (!diff) {
            verify = 1;
        } else {
            strcmp_s("gen", 3, direction, &diff);
            if (diff) {
                AMVP_LOG_ERR("'direction' should be 'gen' or 'ver'");
                rv = AMVP_UNSUPPORTED_OP;
                goto err;
            }
        }

        msglen = json_object_get_number(groupobj, "msgLen") / 8;

        maclen = json_object_get_number(groupobj, "macLen") / 8;
        if (!maclen) {
            AMVP_LOG_ERR("Server JSON missing 'macLen'");
            rv = AMVP_MISSING_ARG;
            goto err;
        }
        if (ctx->log_lvl == AMVP_LOG_LVL_VERBOSE) {
            AMVP_LOG_NEWLINE;
            AMVP_LOG_VERBOSE("    Test group: %d", i);
            AMVP_LOG_VERBOSE("      testtype: %s", test_type_str);
            AMVP_LOG_VERBOSE("           dir: %s", direction);
            AMVP_LOG_VERBOSE("        keylen: %d", keyLen);
            AMVP_LOG_VERBOSE("        msglen: %d", msglen);
            AMVP_LOG_VERBOSE("        maclen: %d", maclen);
        }


        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);
        for (j = 0; j < t_cnt; j++) {
             if (ctx->log_lvl == AMVP_LOG_LVL_VERBOSE) AMVP_LOG_NEWLINE;
            AMVP_LOG_VERBOSE("Found new cmac test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            tc_id = json_object_get_number(testobj, "tcId");
            msg = json_object_get_string(testobj, "message");

            /* msg can be null if msglen is 0 */
            if (msg) {
                json_msglen = strnlen_s(msg, AMVP_CMAC_MSGLEN_MAX_STR + 1);
                if (json_msglen > AMVP_CMAC_MSGLEN_MAX_STR) {
                    AMVP_LOG_ERR("'msg' too long");
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }
                if (!msglen && json_msglen > 0) {
                    AMVP_LOG_ERR("Server JSON missing 'msgLen'");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }
            } else if (msglen) {
                AMVP_LOG_ERR("msglen is nonzero, expected 'msg' in json");
                rv = AMVP_MISSING_ARG;
                goto err;
            }

            if (alg_id == AMVP_CMAC_AES) {
                key1 = json_object_get_string(testobj, "key");
                if (!key1) {
                    AMVP_LOG_ERR("Server JSON missing 'key'");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }
                key1_len = strnlen_s(key1, AMVP_CMAC_KEY_MAX + 1);
                if (key1_len > AMVP_CMAC_KEY_MAX) {
                    AMVP_LOG_ERR("Invalid length for 'key' attribute in CMAC-AES test");
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }
            } else if (alg_id == AMVP_CMAC_TDES) {
                key1 = json_object_get_string(testobj, "key1");
                key2 = json_object_get_string(testobj, "key2");
                key3 = json_object_get_string(testobj, "key3");
                if (!key1 || !key2 || !key3) {
                    AMVP_LOG_ERR("Server JSON missing 'key(1,2,3)' value");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }
                key1_len = strnlen_s(key1, AMVP_CMAC_KEY_MAX + 1);
                key2_len = strnlen_s(key2, AMVP_CMAC_KEY_MAX + 1);
                key3_len = strnlen_s(key3, AMVP_CMAC_KEY_MAX + 1);
                if (key1_len > AMVP_CMAC_KEY_MAX ||
                    key2_len > AMVP_CMAC_KEY_MAX ||
                    key3_len > AMVP_CMAC_KEY_MAX) {
                    AMVP_LOG_ERR("Invalid length for 'key(1|2|3)' attribute in CMAC-TDES test");
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }
            }

            if (verify) {
                mac = json_object_get_string(testobj, "mac");
                if (!mac) {
                    AMVP_LOG_ERR("Server JSON missing 'mac'");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }
            }

            AMVP_LOG_VERBOSE("        Test case: %d", j);
            AMVP_LOG_VERBOSE("             tcId: %d", tc_id);
            AMVP_LOG_VERBOSE("              msg: %s", msg);
            if (alg_id == AMVP_CMAC_AES) {
                AMVP_LOG_VERBOSE("              key: %s", key1);
            } else if (alg_id == AMVP_CMAC_TDES) {
                AMVP_LOG_VERBOSE("     keyingOption: %d", keyingOption);
                AMVP_LOG_VERBOSE("             key1: %s", key1);
                AMVP_LOG_VERBOSE("             key2: %s", key2);
                AMVP_LOG_VERBOSE("             key3: %s", key3);
            }

            if (verify) {
                AMVP_LOG_VERBOSE("              mac: %s", mac);
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
            rv = amvp_cmac_init_tc(ctx, &stc, tc_id, testtype, msg, msglen, key1, key2, key3,
                                   verify, mac, maclen, alg_id);
            if (rv != AMVP_SUCCESS) {
                amvp_cmac_release_tc(&stc);
                json_value_free(r_tval);
                goto err;
            }

            /* Process the current test vector... */
            if ((cap->crypto_handler)(&tc)) {
                AMVP_LOG_ERR("ERROR: crypto module failed the operation");
                amvp_cmac_release_tc(&stc);
                rv = AMVP_CRYPTO_MODULE_FAIL;
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Output the test case results using JSON
             */
            rv = amvp_cmac_output_tc(ctx, &stc, r_tobj);
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("ERROR: JSON output failure in hash module");
                amvp_cmac_release_tc(&stc);
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Release all the memory associated with the test case
             */
            amvp_cmac_release_tc(&stc);

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
