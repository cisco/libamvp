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

static AMVP_RESULT amvp_ecdsa_kat_handler_internal(AMVP_CTX *ctx, JSON_Object *obj, AMVP_CIPHER cipher);


/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static AMVP_RESULT amvp_ecdsa_output_tc(AMVP_CTX *ctx, AMVP_CIPHER cipher, AMVP_ECDSA_TC *stc, JSON_Object *tc_rsp) {
    AMVP_RESULT rv;
    char *tmp = NULL;

    tmp = calloc(AMVP_ECDSA_EXP_LEN_MAX + 1, sizeof(char));

    if (cipher == AMVP_ECDSA_KEYGEN) {
        rv = amvp_bin_to_hexstr(stc->qy, stc->qy_len, tmp, AMVP_ECDSA_EXP_LEN_MAX);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("hex conversion failure (qy)");
            goto err;
        }
        json_object_set_string(tc_rsp, "qy", (const char *)tmp);
        memzero_s(tmp, AMVP_ECDSA_EXP_LEN_MAX);

        rv = amvp_bin_to_hexstr(stc->qx, stc->qx_len, tmp, AMVP_ECDSA_EXP_LEN_MAX);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("hex conversion failure (qx)");
            goto err;
        }
        json_object_set_string(tc_rsp, "qx", (const char *)tmp);
        memzero_s(tmp, AMVP_ECDSA_EXP_LEN_MAX);

        rv = amvp_bin_to_hexstr(stc->d, stc->d_len, tmp, AMVP_ECDSA_EXP_LEN_MAX);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("hex conversion failure (d)");
            goto err;
        }
        json_object_set_string(tc_rsp, "d", (const char *)tmp);
        memzero_s(tmp, AMVP_ECDSA_EXP_LEN_MAX);
    }
    if (cipher == AMVP_ECDSA_KEYVER || cipher == AMVP_ECDSA_SIGVER) {
        json_object_set_boolean(tc_rsp, "testPassed", stc->ver_disposition);
    }
    if (cipher == AMVP_ECDSA_SIGGEN) {
        rv = amvp_bin_to_hexstr(stc->r, stc->r_len, tmp, AMVP_ECDSA_EXP_LEN_MAX);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("hex conversion failure (r)");
            goto err;
        }
        json_object_set_string(tc_rsp, "r", (const char *)tmp);
        memzero_s(tmp, AMVP_ECDSA_EXP_LEN_MAX);

        rv = amvp_bin_to_hexstr(stc->s, stc->s_len, tmp, AMVP_ECDSA_EXP_LEN_MAX);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("hex conversion failure (s)");
            goto err;
        }
        json_object_set_string(tc_rsp, "s", (const char *)tmp);
        memzero_s(tmp, AMVP_ECDSA_EXP_LEN_MAX);
    }

err:
    free(tmp);
    return AMVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */

static AMVP_RESULT amvp_ecdsa_release_tc(AMVP_ECDSA_TC *stc) {
    if (stc->qy) { free(stc->qy); }
    if (stc->qx) { free(stc->qx); }
    if (stc->d) { free(stc->d); }
    if (stc->r) { free(stc->r); }
    if (stc->s) { free(stc->s); }
    if (stc->message) { free(stc->message); }
    memzero_s(stc, sizeof(AMVP_ECDSA_TC));

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_ecdsa_init_tc(AMVP_CTX *ctx,
                                      AMVP_CIPHER cipher,
                                      int is_component,
                                      AMVP_ECDSA_TC *stc,
                                      int tg_id,
                                      unsigned int tc_id,
                                      AMVP_EC_CURVE curve,
                                      AMVP_ECDSA_SECRET_GEN_MODE secret_gen_mode,
                                      AMVP_HASH_ALG hash_alg,
                                      const char *qx,
                                      const char *qy,
                                      const char *message,
                                      const char *r,
                                      const char *s) {
    AMVP_RESULT rv = AMVP_SUCCESS;

    memzero_s(stc, sizeof(AMVP_ECDSA_TC));

    stc->tc_id = tc_id;
    stc->tg_id = tg_id;
    stc->cipher = cipher;
    stc->hash_alg = hash_alg;
    stc->curve = curve;
    stc->secret_gen_mode = secret_gen_mode;
    stc->is_component = is_component;

    stc->qx = calloc(AMVP_RSA_EXP_LEN_MAX, sizeof(char));
    if (!stc->qx) { goto err; }
    stc->qy = calloc(AMVP_RSA_EXP_LEN_MAX, sizeof(char));
    if (!stc->qy) { goto err; }
    stc->d = calloc(AMVP_RSA_EXP_LEN_MAX, sizeof(char));
    if (!stc->d) { goto err; }
    stc->s = calloc(AMVP_RSA_EXP_LEN_MAX, sizeof(char));
    if (!stc->s) { goto err; }
    stc->r = calloc(AMVP_RSA_EXP_LEN_MAX, sizeof(char));
    if (!stc->r) { goto err; }
    stc->message = calloc(AMVP_RSA_EXP_LEN_MAX, sizeof(char));
    if (!stc->message) { goto err; }

    if (cipher == AMVP_ECDSA_KEYVER || cipher == AMVP_ECDSA_SIGVER) {
        if (!qx || !qy) return AMVP_MISSING_ARG;

        rv = amvp_hexstr_to_bin(qx, stc->qx, AMVP_RSA_EXP_LEN_MAX, &(stc->qx_len));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (qx)");
            return rv;
        }

        rv = amvp_hexstr_to_bin(qy, stc->qy, AMVP_RSA_EXP_LEN_MAX, &(stc->qy_len));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (qy)");
            return rv;
        }
    }
    if (cipher == AMVP_ECDSA_SIGVER) {
        if (!r || !s) return AMVP_MISSING_ARG;

        rv = amvp_hexstr_to_bin(r, stc->r, AMVP_RSA_EXP_LEN_MAX, &(stc->r_len));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (r)");
            return rv;
        }

        rv = amvp_hexstr_to_bin(s, stc->s, AMVP_RSA_EXP_LEN_MAX, &(stc->s_len));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (s)");
            return rv;
        }
    }
    if (cipher == AMVP_ECDSA_SIGVER || cipher == AMVP_ECDSA_SIGGEN) {
        if (!message) return AMVP_MISSING_ARG;

        rv = amvp_hexstr_to_bin(message, stc->message, AMVP_RSA_MSGLEN_MAX, &(stc->msg_len));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (message)");
            return rv;
        }
    }

    return AMVP_SUCCESS;

err:
    AMVP_LOG_ERR("Failed to allocate buffer in ECDSA test case");
    if (stc->qx) free(stc->qx);
    if (stc->qy) free(stc->qy);
    if (stc->r) free(stc->r);
    if (stc->s) free(stc->s);
    if (stc->d) free(stc->d);
    if (stc->message) free(stc->message);
    return AMVP_MALLOC_FAIL;
}

AMVP_RESULT amvp_ecdsa_keygen_kat_handler(AMVP_CTX *ctx, JSON_Object *obj) {
    return amvp_ecdsa_kat_handler_internal(ctx, obj, AMVP_ECDSA_KEYGEN);
}

AMVP_RESULT amvp_ecdsa_keyver_kat_handler(AMVP_CTX *ctx, JSON_Object *obj) {
    return amvp_ecdsa_kat_handler_internal(ctx, obj, AMVP_ECDSA_KEYVER);
}

AMVP_RESULT amvp_ecdsa_siggen_kat_handler(AMVP_CTX *ctx, JSON_Object *obj) {
    return amvp_ecdsa_kat_handler_internal(ctx, obj, AMVP_ECDSA_SIGGEN);
}

AMVP_RESULT amvp_ecdsa_sigver_kat_handler(AMVP_CTX *ctx, JSON_Object *obj) {
    return amvp_ecdsa_kat_handler_internal(ctx, obj, AMVP_ECDSA_SIGVER);
}

static AMVP_ECDSA_SECRET_GEN_MODE read_secret_gen_mode(const char *str) {
    int diff = 1;

    strcmp_s(AMVP_ECDSA_EXTRA_BITS_STR,
             AMVP_ECDSA_EXTRA_BITS_STR_LEN,
             str, &diff);
    if (!diff) return AMVP_ECDSA_SECRET_GEN_EXTRA_BITS;

    strcmp_s(AMVP_ECDSA_TESTING_CANDIDATES_STR,
             AMVP_ECDSA_TESTING_CANDIDATES_STR_LEN,
             str, &diff);
    if (!diff) return AMVP_ECDSA_SECRET_GEN_TEST_CAND;

    return 0;
}

static AMVP_RESULT amvp_ecdsa_kat_handler_internal(AMVP_CTX *ctx, JSON_Object *obj, AMVP_CIPHER cipher) {
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
    AMVP_ECDSA_TC stc;
    AMVP_TEST_CASE tc;
    AMVP_RESULT rv;

    AMVP_CIPHER alg_id;
    char *json_result = NULL;
    const char *alg_str, *mode_str, *qx = NULL, *qy = NULL, *r = NULL, *s = NULL, *message = NULL;

    if (!ctx) {
        AMVP_LOG_ERR("No ctx for handler operation");
        return AMVP_NO_CTX;
    }

    alg_str = json_object_get_string(obj, "algorithm");
    if (!alg_str) {
        AMVP_LOG_ERR("ERROR: unable to parse 'algorithm' from JSON");
        return AMVP_MALFORMED_JSON;
    }

    memzero_s(&stc, sizeof(AMVP_ECDSA_TC));
    tc.tc.ecdsa = &stc;
    mode_str = json_object_get_string(obj, "mode");
    if (!mode_str) {
        AMVP_LOG_ERR("Server JSON missing 'mode_str'");
        return AMVP_MALFORMED_JSON;
    }

    alg_id = amvp_lookup_cipher_w_mode_index(alg_str, mode_str);
    if (alg_id != cipher) {
        AMVP_LOG_ERR("Server JSON invalid algorithm or mode");
        return AMVP_INVALID_ARG;
    }

    cap = amvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        AMVP_LOG_ERR("ERROR: AMVP server requesting unsupported capability");
        return AMVP_UNSUPPORTED_OP;
    }
    AMVP_LOG_VERBOSE("    ECDSA mode: %s", mode_str);

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
    json_object_set_string(r_vs, "mode", mode_str);

    groups = json_object_get_array(obj, "testGroups");
    if (!groups) {
        AMVP_LOG_ERR("Missing testGroups from server JSON");
        rv = AMVP_MALFORMED_JSON;
        goto err;
    }
    g_cnt = json_array_get_count(groups);

    for (i = 0; i < g_cnt; i++) {
        int tgId = 0, is_component = 0;
        AMVP_HASH_ALG hash_alg = 0;
        AMVP_EC_CURVE curve = 0;
        AMVP_ECDSA_SECRET_GEN_MODE secret_gen_mode = 0;
        const char *hash_alg_str = NULL, *curve_str = NULL,
                   *secret_gen_mode_str = NULL;

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
            rv = AMVP_MISSING_ARG;
            goto err;
        }
        json_object_set_number(r_gobj, "tgId", tgId);
        json_object_set_value(r_gobj, "tests", json_value_init_array());
        r_tarr = json_object_get_array(r_gobj, "tests");

        /*
         * Get a reference to the abstracted test case
         */
        curve_str = json_object_get_string(groupobj, "curve");
        if (!curve_str) {
            AMVP_LOG_ERR("Server JSON missing 'curve'");
            rv = AMVP_MISSING_ARG;
            goto err;
        }

        curve = amvp_lookup_ec_curve(alg_id, curve_str);
        if (!curve) {
            AMVP_LOG_ERR("Server JSON includes unrecognized curve");
            rv = AMVP_INVALID_ARG;
            goto err;
        }

        if (alg_id == AMVP_ECDSA_KEYGEN) {
            secret_gen_mode_str = json_object_get_string(groupobj, "secretGenerationMode");
            if (!secret_gen_mode_str) {
                AMVP_LOG_ERR("Server JSON missing 'secretGenerationMode'");
                rv = AMVP_MISSING_ARG;
                goto err;
            }

            secret_gen_mode = read_secret_gen_mode(secret_gen_mode_str);
            if (!secret_gen_mode) {
                AMVP_LOG_ERR("Server JSON invalid 'secretGenerationMode'");
                rv = AMVP_INVALID_ARG;
                goto err;
            }
        } else if (alg_id == AMVP_ECDSA_SIGGEN || alg_id == AMVP_ECDSA_SIGVER) {
            hash_alg_str = json_object_get_string(groupobj, "hashAlg");
            if (!hash_alg_str) {
                AMVP_LOG_ERR("Server JSON missing 'hashAlg'");
                rv = AMVP_MISSING_ARG;
                goto err;
            }

            hash_alg = amvp_lookup_hash_alg(hash_alg_str);
            if (!hash_alg || (alg_id == AMVP_ECDSA_SIGGEN && hash_alg == AMVP_SHA1)) {
                AMVP_LOG_ERR("Server JSON invalid 'hashAlg'");
                rv = AMVP_INVALID_ARG;
                goto err;
            }

            is_component = json_object_get_boolean(groupobj, "componentTest");
        }

        AMVP_LOG_VERBOSE("           Test group: %d", i);
        AMVP_LOG_VERBOSE("                curve: %s", curve_str);
        AMVP_LOG_VERBOSE(" secretGenerationMode: %s", secret_gen_mode_str);
        AMVP_LOG_VERBOSE("              hashAlg: %s", hash_alg_str);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);
        if (!t_cnt) {
            AMVP_LOG_ERR("Test array count is zero");
            rv = AMVP_MISSING_ARG;
            goto err;
        }

        for (j = 0; j < t_cnt; j++) {
            AMVP_LOG_VERBOSE("Found new ECDSA test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);
            tc_id = json_object_get_number(testobj, "tcId");

            if (alg_id == AMVP_ECDSA_KEYVER || alg_id == AMVP_ECDSA_SIGVER) {
                qx = json_object_get_string(testobj, "qx");
                qy = json_object_get_string(testobj, "qy");
                if (!qx || !qy) {
                    AMVP_LOG_ERR("Server JSON missing 'qx' or 'qy'");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(qx, AMVP_ECDSA_EXP_LEN_MAX + 1) > AMVP_ECDSA_EXP_LEN_MAX ||
                    strnlen_s(qy, AMVP_ECDSA_EXP_LEN_MAX + 1) > AMVP_ECDSA_EXP_LEN_MAX) {
                    AMVP_LOG_ERR("'qx' or 'qy' too long");
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }
            }
            if (alg_id == AMVP_ECDSA_SIGGEN || alg_id == AMVP_ECDSA_SIGVER) {
                message = json_object_get_string(testobj, "message");
                if (!message) {
                    AMVP_LOG_ERR("Server JSON missing 'message'");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(message, AMVP_ECDSA_MSGLEN_MAX + 1) > AMVP_ECDSA_MSGLEN_MAX) {
                    AMVP_LOG_ERR("message string too long");
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }
            }
            if (alg_id == AMVP_ECDSA_SIGVER) {
                r = json_object_get_string(testobj, "r");
                s = json_object_get_string(testobj, "s");
                if (!r || !s) {
                    AMVP_LOG_ERR("Server JSON missing 'r' or 's'");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(r, AMVP_ECDSA_EXP_LEN_MAX + 1) > AMVP_ECDSA_EXP_LEN_MAX ||
                    strnlen_s(s, AMVP_ECDSA_EXP_LEN_MAX + 1) > AMVP_ECDSA_EXP_LEN_MAX) {
                    AMVP_LOG_ERR("'r' or 's' too long");
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

            rv = amvp_ecdsa_init_tc(ctx, alg_id, is_component, &stc, tgId, tc_id, curve, secret_gen_mode, hash_alg, qx, qy, message, r, s);

            /* Process the current test vector... */
            if (rv == AMVP_SUCCESS) {
                if ((cap->crypto_handler)(&tc)) {
                    AMVP_LOG_ERR("ERROR: crypto module failed the operation");
                    rv = AMVP_CRYPTO_MODULE_FAIL;
                    json_value_free(r_tval);
                    goto err;
                }
            } else {
                AMVP_LOG_ERR("Failed to initialize ECDSA test case");
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Output the test case results using JSON
             */
            if (cipher == AMVP_ECDSA_SIGGEN) {
                char *tmp = calloc(AMVP_ECDSA_EXP_LEN_MAX + 1, sizeof(char));
                rv = amvp_bin_to_hexstr(stc.qy, stc.qy_len, tmp, AMVP_ECDSA_EXP_LEN_MAX);
                if (rv != AMVP_SUCCESS) {
                    AMVP_LOG_ERR("hex conversion failure (qy)");
                    free(tmp);
                    json_value_free(r_tval);
                    goto err;
                }
                json_object_set_string(r_gobj, "qy", (const char *)tmp);
                memzero_s(tmp, AMVP_ECDSA_EXP_LEN_MAX);

                rv = amvp_bin_to_hexstr(stc.qx, stc.qx_len, tmp, AMVP_ECDSA_EXP_LEN_MAX);
                if (rv != AMVP_SUCCESS) {
                    AMVP_LOG_ERR("hex conversion failure (qx)");
                    free(tmp);
                    json_value_free(r_tval);
                    goto err;
                }
                json_object_set_string(r_gobj, "qx", (const char *)tmp);
                memzero_s(tmp, AMVP_ECDSA_EXP_LEN_MAX);
                free(tmp);
            }
            rv = amvp_ecdsa_output_tc(ctx, alg_id, &stc, r_tobj);
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("ERROR: JSON output failure in hash module");
                json_value_free(r_tval);
                goto err;
            }

            /* Append the test response value to array */
            json_array_append_value(r_tarr, r_tval);

            /*
             * Release all the memory associated with the test case
             */
            amvp_ecdsa_release_tc(&stc);
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
        amvp_ecdsa_release_tc(&stc);
        amvp_release_json(r_vs_val, r_gval);
    }
    return rv;
}
