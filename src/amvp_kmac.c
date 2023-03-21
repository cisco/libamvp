/** @file */
/*
 * Copyright (c) 2022, Cisco Systems, Inc.
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

static AMVP_RESULT amvp_kmac_init_tc(AMVP_CTX *ctx,
                                     AMVP_KMAC_TC *stc,
                                     AMVP_CIPHER alg_id,
                                     int tc_id,
                                     AMVP_KMAC_TESTTYPE type,
                                     int xof,
                                     int hex_customization,
                                     const char *msg,
                                     int msg_len,
                                     const char *mac,
                                     int mac_len,
                                     const char *key,
                                     int key_len,
                                     const char *custom) {

    AMVP_RESULT rv;
    int len = 0;
    memzero_s(stc, sizeof(AMVP_KMAC_TC));

    stc->msg = calloc(1, AMVP_KMAC_MSG_BYTE_MAX);
    if (!stc->msg) { return AMVP_MALLOC_FAIL; }
    stc->mac = calloc(1, AMVP_KMAC_MAC_BYTE_MAX);
    if (!stc->mac) { return AMVP_MALLOC_FAIL; }
    stc->key = calloc(1, AMVP_KMAC_KEY_BYTE_MAX);
    if (!stc->key) { return AMVP_MALLOC_FAIL; }
    if (hex_customization) {
        stc->custom_hex = calloc(1, AMVP_KMAC_CUSTOM_HEX_BYTE_MAX);
        if (!stc->custom_hex) { return AMVP_MALLOC_FAIL; }
    } else {
        stc->custom = calloc(1, AMVP_KMAC_CUSTOM_STR_MAX);
        if (!stc->custom) { return AMVP_MALLOC_FAIL; }
    }

    rv = amvp_hexstr_to_bin(msg, stc->msg, AMVP_KMAC_MSG_BYTE_MAX, NULL);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex converstion failure (msg)");
        return rv;
    }

    rv = amvp_hexstr_to_bin(key, stc->key, AMVP_KMAC_KEY_BYTE_MAX, NULL);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex converstion failure (key)");
        return rv;
    }

    if (type == AMVP_KMAC_TEST_TYPE_MVT) {
        rv = amvp_hexstr_to_bin(mac, stc->mac, AMVP_KMAC_MAC_BYTE_MAX, NULL);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex converstion failure (mac)");
            return rv;
        }
    }

    if (hex_customization) {
        rv = amvp_hexstr_to_bin(custom, stc->custom_hex, AMVP_KMAC_CUSTOM_HEX_BYTE_MAX, &stc->custom_len);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex converstion failure (customizationHex)");
            return rv;
        }
    } else {
        len = strnlen_s(custom, AMVP_KMAC_CUSTOM_STR_MAX + 1);
        if (len > AMVP_KMAC_CUSTOM_STR_MAX) {
            AMVP_LOG_ERR("customization string too long");
            return AMVP_INVALID_ARG;
        }
        if (strncpy_s(stc->custom, AMVP_KMAC_CUSTOM_STR_MAX, custom, len)) {
            AMVP_LOG_ERR("String copy failure (customization)");
            return AMVP_INVALID_ARG;
        }
        stc->custom_len = len;
    }

    stc->tc_id = tc_id;
    stc->test_type = type;
    stc->xof = xof;
    stc->hex_customization = hex_customization;
    stc->mac_len = mac_len / 8;
    stc->msg_len = msg_len / 8;
    stc->key_len = key_len / 8;
    stc->cipher = alg_id;

    return AMVP_SUCCESS;
}

/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static AMVP_RESULT amvp_kmac_output_tc(AMVP_CTX *ctx, AMVP_KMAC_TC *stc, JSON_Object *tc_rsp) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    char *tmp = NULL;

    if (stc->test_type == AMVP_KMAC_TEST_TYPE_AFT) {
        tmp = calloc(AMVP_KMAC_MAC_STR_MAX + 1, sizeof(char));
        if (!tmp) {
            AMVP_LOG_ERR("Unable to malloc in amvp_kmac_output_tc");
            return AMVP_MALLOC_FAIL;
        }

        rv = amvp_bin_to_hexstr(stc->mac, stc->mac_len, tmp, AMVP_KMAC_MAC_STR_MAX);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("hex conversion failure (mac)");
            goto end;
        }
        json_object_set_string(tc_rsp, "mac", tmp);
    } else { /* verify */
        json_object_set_boolean(tc_rsp, "testPassed", stc->disposition);
    }

end:
    if (tmp) free(tmp);
    return rv;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static AMVP_RESULT amvp_kmac_release_tc(AMVP_KMAC_TC *stc) {
    if (stc->msg) free(stc->msg);
    if (stc->mac) free(stc->mac);
    if (stc->key) free(stc->key);
    if (stc->custom) free(stc->custom);
    if (stc->custom_hex) free(stc->custom_hex);
    memzero_s(stc, sizeof(AMVP_KMAC_TC));

    return AMVP_SUCCESS;
}

static AMVP_KMAC_TESTTYPE read_test_type(const char *str) {
    int diff = 1;

    strcmp_s("AFT", 3, str, &diff);
    if (!diff) return AMVP_KMAC_TEST_TYPE_AFT;

    strcmp_s("MVT", 3, str, &diff);
    if (!diff) return AMVP_KMAC_TEST_TYPE_MVT;

    return 0;
}

AMVP_RESULT amvp_kmac_kat_handler(AMVP_CTX *ctx, JSON_Object *obj) {
    int tc_id = 0, msglen = 0, keylen = 0, maclen = 0;
    const char *msg = NULL, *key = NULL, *mac = NULL, *type_str = NULL, *custom = NULL;
    int xof = 0, hex_customization = 0;
    AMVP_KMAC_TESTTYPE type;
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
    AMVP_KMAC_TC stc;
    AMVP_TEST_CASE tc;
    AMVP_RESULT rv;
    const char *alg_str = json_object_get_string(obj, "algorithm");
    AMVP_CIPHER alg_id;
    char *json_result;

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

    /* Get a reference to the abstracted test case */
    tc.tc.kmac = &stc;

    /* Get the crypto module handler for this kmac algorithm */
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
    if (!groups) {
        AMVP_LOG_ERR("Failed to include testGroups. ");
        rv = AMVP_MISSING_ARG;
        goto err;
    }
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

        type_str = json_object_get_string(groupobj, "testType");
        if (!type_str) {
            AMVP_LOG_ERR("Failed to include testType.");
            rv = AMVP_MISSING_ARG;
            goto err;
        }
        type = read_test_type(type_str);
        if (!type) {
            AMVP_LOG_ERR("Error parsing test type.");
            rv = AMVP_INVALID_ARG;
            goto err;
        }

        xof = json_object_get_boolean(groupobj, "xof");
        hex_customization = json_object_get_boolean(groupobj, "hexCustomization");

        AMVP_LOG_VERBOSE("    Test group: %d", i);
        AMVP_LOG_VERBOSE("      testType: %s", type_str);
        AMVP_LOG_VERBOSE("           xof: %d", xof);
        AMVP_LOG_VERBOSE("     hexCustom: %d", hex_customization);

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
            AMVP_LOG_VERBOSE("Found new kmac test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            tc_id = json_object_get_number(testobj, "tcId");
            if (!tc_id) {
                AMVP_LOG_ERR("Failed to include tc_id. ");
                rv = AMVP_MISSING_ARG;
                goto err;
            }

            msglen = json_object_get_number(testobj, "msgLen");
            if (msglen < 0) {
                AMVP_LOG_ERR("Invalid or missing msgLen");
                rv = AMVP_INVALID_ARG;
                goto err;
            }
            msg = json_object_get_string(testobj, "msg");
            if (!msg) {
                AMVP_LOG_ERR("Failed to include msg.");
                rv = AMVP_MISSING_ARG;
                goto err;
            }
            if ((int)strnlen_s(msg, AMVP_KMAC_MSG_STR_MAX) != msglen >> 2) {
                AMVP_LOG_ERR("msgLen(%d) or msg length(%zu) incorrect",
                             msglen, strnlen_s(msg, AMVP_KMAC_MSG_STR_MAX) >> 2);
                rv = AMVP_INVALID_ARG;
                goto err;
            }

            keylen = json_object_get_number(testobj, "keyLen");
            if (keylen <= 0) {
                AMVP_LOG_ERR("Invalid or missing keyLen");
                rv = AMVP_INVALID_ARG;
                goto err;
            }
            key = json_object_get_string(testobj, "key");
            if (!key) {
                AMVP_LOG_ERR("Failed to include key.");
                rv = AMVP_MISSING_ARG;
                goto err;
            }
            if ((int)strnlen_s(key, AMVP_KMAC_KEY_STR_MAX) != (keylen >> 2)) {
                AMVP_LOG_ERR("keyLen(%d) or key length(%zu) incorrect",
                             keylen, strnlen_s(key, AMVP_KMAC_KEY_STR_MAX) >> 2);
                rv = AMVP_INVALID_ARG;
                goto err;
            }

            maclen = json_object_get_number(testobj, "macLen");
            if (maclen <= 0) {
                AMVP_LOG_ERR("Invalid or missing keyLen");
                rv = AMVP_INVALID_ARG;
                goto err;
            }
            if (type == AMVP_KMAC_TEST_TYPE_MVT) {
                mac = json_object_get_string(testobj, "mac");
                if (!mac) {
                    AMVP_LOG_ERR("Failed to include mac in MVT test.");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }
                if ((int)strnlen_s(mac, AMVP_KMAC_MAC_STR_MAX) << 2 != maclen) {
                    AMVP_LOG_ERR("macLen(%d) or mac length(%zu) incorrect",
                                maclen, strnlen_s(mac, AMVP_KMAC_MAC_STR_MAX) << 2);
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }
            }

            if (hex_customization) {
                custom = json_object_get_string(testobj, "customizationHex");
                if (!custom) {
                    AMVP_LOG_ERR("Failed to include customizationHex.");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(custom, AMVP_KMAC_CUSTOM_HEX_STR_MAX + 1) > AMVP_KMAC_CUSTOM_HEX_STR_MAX) {
                    AMVP_LOG_ERR("customizationHex string too long in tcid %d", tc_id);
                }
            } else {
                custom = json_object_get_string(testobj, "customization");
                if (!custom) {
                    AMVP_LOG_ERR("Failed to include customization.");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(custom, AMVP_KMAC_CUSTOM_STR_MAX + 1) > AMVP_KMAC_CUSTOM_STR_MAX) {
                    AMVP_LOG_ERR("customization string too long in tcid %d", tc_id);
                }
            }

            AMVP_LOG_VERBOSE("        Test case: %d", j);
            AMVP_LOG_VERBOSE("             tcId: %d", tc_id);
            AMVP_LOG_VERBOSE("           msgLen: %d", msglen);
            if (type == AMVP_KMAC_TEST_TYPE_MVT) {
                AMVP_LOG_VERBOSE("              mac: %s", mac);
            }
            AMVP_LOG_VERBOSE("           macLen: %d", maclen);
            AMVP_LOG_VERBOSE("              msg: %s", msg);
            AMVP_LOG_VERBOSE("           keyLen: %d", keylen);
            AMVP_LOG_VERBOSE("              key: %s", key);

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
            rv = amvp_kmac_init_tc(ctx, &stc, alg_id, tc_id, type, xof, hex_customization,
                                     msg, msglen, mac, maclen, key, keylen, custom);
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("Error initializing KMAC test case");
                amvp_kmac_release_tc(&stc);
                json_value_free(r_tval);
                goto err;
            }

            /* Process the current test vector... */
            if ((cap->crypto_handler)(&tc)) {
                AMVP_LOG_ERR("ERROR: crypto module failed the operation");
                amvp_kmac_release_tc(&stc);
                json_value_free(r_tval);
                rv = AMVP_CRYPTO_MODULE_FAIL;
                goto err;
            }

            /*
             * Output the test case results using JSON
             */
            rv = amvp_kmac_output_tc(ctx, &stc, r_tobj);
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("ERROR: JSON output failure in kmac module");
                json_value_free(r_tval);
                amvp_kmac_release_tc(&stc);
                goto err;
            }
            /*
             * Release all the memory associated with the test case
             */
            amvp_kmac_release_tc(&stc);

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
