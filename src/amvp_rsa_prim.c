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

/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static AMVP_RESULT amvp_rsa_decprim_output_tc(AMVP_CTX *ctx, AMVP_RSA_PRIM_TC *stc, JSON_Object *tc_rsp) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    char *tmp = NULL;

    tmp = calloc(AMVP_RSA_EXP_LEN_MAX + 1, sizeof(char));
    if (!tmp) {
        AMVP_LOG_ERR("Unable to malloc in amvp_rsa_decprim tpm_output_tc");
        return AMVP_MALLOC_FAIL;
    }

    rv = amvp_bin_to_hexstr(stc->e, stc->e_len, tmp, AMVP_RSA_EXP_LEN_MAX);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("hex conversion failure (p)");
        goto err;
    }
    json_object_set_string(tc_rsp, "e", (const char *)tmp);
    memzero_s(tmp, AMVP_RSA_EXP_LEN_MAX);

    rv = amvp_bin_to_hexstr(stc->n, stc->n_len, tmp, AMVP_RSA_EXP_LEN_MAX);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("hex conversion failure (q)");
        goto err;
    }
    json_object_set_string(tc_rsp, "n", (const char *)tmp);
    memzero_s(tmp, AMVP_RSA_EXP_LEN_MAX);

    json_object_set_boolean(tc_rsp, "testPassed", stc->disposition);

    if (stc->disposition) {
        rv = amvp_bin_to_hexstr(stc->pt, stc->pt_len, tmp, AMVP_RSA_EXP_LEN_MAX);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("hex conversion failure (q)");
            goto err;
        }
        json_object_set_string(tc_rsp, "plainText", (const char *)tmp);
    }
err:
    if (tmp) free(tmp);

    return rv;
}

static AMVP_RESULT amvp_rsa_sigprim_output_tc(AMVP_CTX *ctx, AMVP_RSA_PRIM_TC *stc, JSON_Object *tc_rsp) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    char *tmp = NULL;

    tmp = calloc(AMVP_RSA_EXP_LEN_MAX + 1, sizeof(char));
    if (!tmp) {
        AMVP_LOG_ERR("Unable to malloc in amvp_rsa_decprim tpm_output_tc");
        return AMVP_MALLOC_FAIL;
    }

    if (stc->disposition) {
        rv = amvp_bin_to_hexstr(stc->signature, stc->sig_len, tmp, AMVP_RSA_EXP_LEN_MAX);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("hex conversion failure (q)");
            goto err;
        }
        json_object_set_string(tc_rsp, "signature", (const char *)tmp);
        json_object_set_boolean(tc_rsp, "testPassed", stc->disposition);
    } else {
        json_object_set_boolean(tc_rsp, "testPassed", stc->disposition);
    }

err:
    if (tmp) free(tmp);

    return rv;
}

static AMVP_RESULT amvp_rsa_decprim_release_tc(AMVP_RSA_PRIM_TC *stc) {
    if (stc->e) { free(stc->e); }
    if (stc->n) { free(stc->n); }
    if (stc->pt) { free(stc->pt); }
    if (stc->cipher) { free(stc->cipher); }
    if (stc->plaintext) { free(stc->plaintext); }
    memzero_s(stc, sizeof(AMVP_RSA_PRIM_TC));

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_rsa_sigprim_release_tc(AMVP_RSA_PRIM_TC *stc) {
    if (stc->e) { free(stc->e); }
    if (stc->d) { free(stc->d); }
    if (stc->n) { free(stc->n); }
    if (stc->p) { free(stc->p); }
    if (stc->q) { free(stc->q); }
    if (stc->dmp1) { free(stc->dmp1); }
    if (stc->dmq1) { free(stc->dmq1); }
    if (stc->iqmp) { free(stc->iqmp); }
    if (stc->pt) { free(stc->pt); }
    if (stc->msg) { free(stc->msg); }
    if (stc->signature) { free(stc->signature); }
    memzero_s(stc, sizeof(AMVP_RSA_PRIM_TC));

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_rsa_decprim_init_tc(AMVP_CTX *ctx,
                                            AMVP_RSA_PRIM_TC *stc,
                                            int modulo,
                                            int deferred,
                                            int pass,
                                            int fail,
                                            const char *cipher,
                                            int cipher_len) {
 
    AMVP_RESULT rv = AMVP_SUCCESS;

    memzero_s(stc, sizeof(AMVP_RSA_PRIM_TC));
    stc->modulo = modulo;
    stc->deferred = deferred;
    stc->pass = pass;
    stc->fail = fail;
    stc->cipher_len = cipher_len;
    stc->cipher = calloc(AMVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->cipher) { return AMVP_MALLOC_FAIL; }
    rv = amvp_hexstr_to_bin(cipher, stc->cipher, AMVP_RSA_EXP_BYTE_MAX, &(stc->cipher_len));
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (cipher)");
        return rv;
    }
    stc->plaintext = calloc(AMVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->plaintext) { return AMVP_MALLOC_FAIL; }
    stc->e = calloc(AMVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->e) { return AMVP_MALLOC_FAIL; }
    stc->n = calloc(AMVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->n) { return AMVP_MALLOC_FAIL; }
    stc->pt = calloc(AMVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->pt) { return AMVP_MALLOC_FAIL; }

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_rsa_sigprim_init_tc(AMVP_CTX *ctx,
                                            AMVP_RSA_PRIM_TC *stc,
                                            unsigned int modulo,
                                            unsigned int keyformat,
                                            const char *d_str,
                                            const char *e_str,
                                            const char *n_str,
                                            const char *p_str,
                                            const char *q_str,
                                            const char *dmp1_str,
                                            const char *dmq1_str,
                                            const char *iqmp_str,
                                            const char *msg) {
 
    AMVP_RESULT rv = AMVP_SUCCESS;

    memzero_s(stc, sizeof(AMVP_RSA_PRIM_TC));

    stc->e = calloc(AMVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->e) { return AMVP_MALLOC_FAIL; }
    rv = amvp_hexstr_to_bin(e_str, stc->e, AMVP_RSA_EXP_BYTE_MAX, &(stc->e_len));
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (e)");
        return rv;
    }

    if (d_str) {
        stc->d = calloc(AMVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
        if (!stc->d) { return AMVP_MALLOC_FAIL; }
        rv = amvp_hexstr_to_bin(d_str, stc->d, AMVP_RSA_EXP_BYTE_MAX, &(stc->d_len));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (d)");
            return rv;
        }
    }

    stc->n = calloc(AMVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->n) { return AMVP_MALLOC_FAIL; }
    rv = amvp_hexstr_to_bin(n_str, stc->n, AMVP_RSA_EXP_BYTE_MAX, &(stc->n_len));
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (n)");
        return rv;
    }

    if (p_str) {
        stc->p = calloc(AMVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
        if (!stc->p) { return AMVP_MALLOC_FAIL; }
        rv = amvp_hexstr_to_bin(p_str, stc->p, AMVP_RSA_EXP_BYTE_MAX, &(stc->p_len));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (p)");
            return rv;
        }
    }

    if (q_str) {
        stc->q = calloc(AMVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
        if (!stc->q) { return AMVP_MALLOC_FAIL; }
        rv = amvp_hexstr_to_bin(q_str, stc->q, AMVP_RSA_EXP_BYTE_MAX, &(stc->q_len));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (q");
            return rv;
        }
    }

    if (dmp1_str) {
        stc->dmp1 = calloc(AMVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
        if (!stc->dmp1) { return AMVP_MALLOC_FAIL; }
        rv = amvp_hexstr_to_bin(dmp1_str, stc->dmp1, AMVP_RSA_EXP_BYTE_MAX, &(stc->dmp1_len));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (dmp1)");
            return rv;
        }
    }

    if (dmq1_str) {
        stc->dmq1 = calloc(AMVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
        if (!stc->dmq1) { return AMVP_MALLOC_FAIL; }
        rv = amvp_hexstr_to_bin(dmq1_str, stc->dmq1, AMVP_RSA_EXP_BYTE_MAX, &(stc->dmq1_len));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (dmq1)");
            return rv;
        }
    }

    if (iqmp_str) {
        stc->iqmp = calloc(AMVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
        if (!stc->iqmp) { return AMVP_MALLOC_FAIL; }
        rv = amvp_hexstr_to_bin(iqmp_str, stc->iqmp, AMVP_RSA_EXP_BYTE_MAX, &(stc->iqmp_len));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (iqmp)");
            return rv;
        }
    }

    stc->msg = calloc(AMVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->msg) { return AMVP_MALLOC_FAIL; }
    rv = amvp_hexstr_to_bin(msg, stc->msg, AMVP_RSA_EXP_BYTE_MAX, &(stc->msg_len));
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (msg)");
        return rv;
    }

    stc->modulo = modulo;
    stc->key_format = keyformat;
    stc->signature = calloc(AMVP_RSA_EXP_BYTE_MAX, sizeof(unsigned char));
    if (!stc->signature) { return AMVP_MALLOC_FAIL; }

    return AMVP_SUCCESS;
}

AMVP_RESULT amvp_rsa_decprim_kat_handler(AMVP_CTX *ctx, JSON_Object *obj) {
    unsigned int tc_id;
    JSON_Value *groupval;
    JSON_Object *groupobj = NULL;
    JSON_Value *testval;
    JSON_Object *testobj = NULL;
    JSON_Array *groups;
    JSON_Array *tests;
    JSON_Value *ciphval;
    JSON_Object *ciphobj = NULL;
    JSON_Array *ciphers;

    JSON_Value *reg_arry_val = NULL;
    JSON_Object *reg_obj = NULL;
    JSON_Array *reg_arry = NULL;

    int i, g_cnt;
    int j, t_cnt;
    int c, c_cnt;

    JSON_Value *r_vs_val = NULL;
    JSON_Object *r_vs = NULL;
    JSON_Array *r_tarr = NULL, *r_garr = NULL, *r_carr = NULL;  /* Response testarray, grouparray */
    JSON_Value *r_tval = NULL, *r_gval = NULL, *r_cval = NULL;  /* Response testval, groupval */
    JSON_Object *r_tobj = NULL, *r_gobj = NULL, *r_cobj = NULL; /* Response testobj, groupobj */
    AMVP_CAPS_LIST *cap;
    AMVP_RSA_PRIM_TC stc;
    AMVP_TEST_CASE tc;
    AMVP_RESULT rv;

    AMVP_CIPHER alg_id;
    char *json_result = NULL;
    unsigned int mod = 0, total = 0, fail = 0, pass = 0;
    const char *alg_str = NULL, *mode_str, *cipher = NULL;
    int deferred = 0;
    int cipher_len;

    if (!ctx) {
        AMVP_LOG_ERR("No ctx for handler operation");
        return AMVP_NO_CTX;
    }

    alg_str = json_object_get_string(obj, "algorithm");
    if (!alg_str) {
        AMVP_LOG_ERR("Unable to parse 'algorithm' from JSON.");
        return AMVP_MALFORMED_JSON;
    }

    mode_str = json_object_get_string(obj, "mode");
    if (!mode_str) {
        AMVP_LOG_ERR("Unable to parse 'mode' from JSON.");
        return AMVP_MALFORMED_JSON;
    }

    alg_id = amvp_lookup_cipher_w_mode_index(alg_str, mode_str);
    if (alg_id != AMVP_RSA_DECPRIM) {
        AMVP_LOG_ERR("Server JSON invalid 'algorithm' or 'mode'");
        return AMVP_INVALID_ARG;
    }

    tc.tc.rsa_prim = &stc;
    memzero_s(&stc, sizeof(AMVP_RSA_PRIM_TC));

    cap = amvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        AMVP_LOG_ERR("Server requesting unsupported capability");
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
    json_object_set_string(r_vs, "mode", mode_str);

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

        mod = json_object_get_number(groupobj, "modulo");
        if (mod != 2048) {
            AMVP_LOG_ERR("Server JSON invalid modulo");
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        total = json_object_get_number(groupobj, "totalTestCases");
        if (total == 0) {
            AMVP_LOG_ERR("Server JSON invalid totalTestCases");
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        fail = json_object_get_number(groupobj, "totalFailingCases");
        if (fail == 0) {
            AMVP_LOG_ERR("Server JSON invalid totalFailingCases");
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        pass = total - fail;

        AMVP_LOG_VERBOSE("    Test group: %d", i);
        AMVP_LOG_VERBOSE("           modulo: %d", mod);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);

        for (j = 0; j < t_cnt; j++) {
            AMVP_LOG_VERBOSE("Found new RSA test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);
            tc_id = json_object_get_number(testobj, "tcId");

            AMVP_LOG_VERBOSE("        Test case: %d", j);
            AMVP_LOG_VERBOSE("             tcId: %d", tc_id);
            AMVP_LOG_VERBOSE("       totalCases: %d", total);
            AMVP_LOG_VERBOSE("     failingCases: %d", fail);

            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);
            json_object_set_number(r_tobj, "tcId", tc_id);

            /*
             * Retrieve values from JSON and initialize the tc
             */
            deferred = json_object_get_boolean(testobj, "deferred");
            if (deferred == -1) {
                AMVP_LOG_ERR("Server JSON missing 'deferred'");
                rv = AMVP_MISSING_ARG;
                json_value_free(r_tval);
                goto err;
            }

            ciphers = json_object_get_array(testobj, "resultsArray");
            c_cnt = json_array_get_count(ciphers);

            json_object_set_value(r_tobj, "resultsArray", json_value_init_array());
            r_carr = json_object_get_array(r_tobj, "resultsArray");

            for (c = 0; c < c_cnt; c++) {
                ciphval = json_array_get_value(ciphers, c);
                ciphobj = json_value_get_object(ciphval);

                r_cval = json_value_init_object();
                r_cobj = json_value_get_object(r_cval);

                cipher = json_object_get_string(ciphobj, "cipherText");
                if (!cipher) {
                    AMVP_LOG_ERR("Server JSON missing 'cipher'");
                    rv = AMVP_MISSING_ARG;
                    json_value_free(r_tval);
                    json_value_free(r_cval);
                    goto err;
                }
                cipher_len = strnlen_s(cipher, AMVP_RSA_EXP_BYTE_MAX + 1);
                if (cipher_len > AMVP_RSA_EXP_BYTE_MAX) {
                    AMVP_LOG_ERR("'cipher' too long, max allowed=(%d)",
                                 AMVP_RSA_SEEDLEN_MAX);
                    rv = AMVP_INVALID_ARG;
                    json_value_free(r_tval);
                    json_value_free(r_cval);
                    goto err;
                }

                rv = amvp_rsa_decprim_init_tc(ctx, &stc, mod, deferred, pass, 
                                              fail, cipher, cipher_len);

                /* Process the current test vector... */
                if (rv == AMVP_SUCCESS) {
                   fail = stc.fail;
                   pass = stc.pass;
                   do { 
                       if ((cap->crypto_handler)(&tc)) {
                           AMVP_LOG_ERR("ERROR: crypto module failed the operation");
                           rv = AMVP_CRYPTO_MODULE_FAIL;
                           json_value_free(r_tval);
                           json_value_free(r_cval);
                           goto err;
                       }
                    AMVP_LOG_INFO("Looping on fail/pass %d/%d %d/%d", fail, stc.fail, pass, stc.pass);
                    } while((fail == stc.fail) && (pass == stc.pass));
                }
                fail = stc.fail;
                pass = stc.pass;

                /*
                 * Output the test case results using JSON
                 */
                rv = amvp_rsa_decprim_output_tc(ctx, &stc, r_cobj);
                if (rv != AMVP_SUCCESS) {
                    AMVP_LOG_ERR("ERROR: JSON output failure in primitive module");
                    json_value_free(r_tval);
                    json_value_free(r_cval);
                    goto err;
                }
                /*
                 * Release all the memory associated with the test case
                 */
                amvp_rsa_decprim_release_tc(&stc);

                /* Append the cipher response value to array */
                json_array_append_value(r_carr, r_cval);
            }
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
        amvp_rsa_decprim_release_tc(&stc);
        amvp_release_json(r_vs_val, r_gval);
    }
    return rv;
}

AMVP_RESULT amvp_rsa_sigprim_kat_handler(AMVP_CTX *ctx, JSON_Object *obj) {
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
    AMVP_RSA_PRIM_TC stc;
    AMVP_TEST_CASE tc;
    int diff = 0;
    unsigned int mod = 0;
    unsigned int keyformat = 0;
    const char *key_format = NULL;
    AMVP_CIPHER alg_id;
    char *json_result = NULL;
    const char *mode_str;
    const char *msg;
    const char *e_str = NULL, *n_str = NULL, *d_str = NULL, *p_str = NULL, *q_str = NULL,
               *dmp1_str = NULL, *dmq1_str = NULL, *iqmp_str = NULL;
    const char *alg_str;
    unsigned int json_msglen;
    AMVP_RESULT rv;

    if (!ctx) {
        AMVP_LOG_ERR("No ctx for handler operation");
        return AMVP_NO_CTX;
    }

    alg_str = json_object_get_string(obj, "algorithm");
    if (!alg_str) {
        AMVP_LOG_ERR("ERROR: unable to parse 'algorithm' from JSON");
        return AMVP_MALFORMED_JSON;
    }

    mode_str = json_object_get_string(obj, "mode");
    if (!mode_str) {
        AMVP_LOG_ERR("Missing 'mode' from server json");
        return AMVP_MISSING_ARG;
    }

    alg_id = amvp_lookup_cipher_w_mode_index(alg_str, mode_str);
    if (alg_id != AMVP_RSA_SIGPRIM) {
        AMVP_LOG_ERR("Server JSON invalid 'algorithm' or 'mode'");
        return AMVP_INVALID_ARG;
    }

    cap = amvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        AMVP_LOG_ERR("ERROR: AMVP server requesting unsupported capability");
        return AMVP_UNSUPPORTED_OP;
    }

    AMVP_LOG_VERBOSE("    RSA mode: %s", mode_str);

    tc.tc.rsa_prim = &stc;
    memzero_s(&stc, sizeof(AMVP_RSA_PRIM_TC));

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

        mod = json_object_get_number(groupobj, "modulo");
        if (mod != 2048) {
            AMVP_LOG_ERR("Server JSON invalid modulo");
            rv = AMVP_INVALID_ARG;
            goto err;
        }

        key_format = json_object_get_string(groupobj, "keyFormat");
        if (!key_format) {
            AMVP_LOG_ERR("Missing keyFormat from server json");
            rv = AMVP_MISSING_ARG;
            goto err;
        }

        strcmp_s("standard", 8, key_format, &diff);
        if (!diff) keyformat = AMVP_RSA_PRIM_KEYFORMAT_STANDARD;

        strcmp_s("crt", 3, key_format, &diff);
        if (!diff) keyformat = AMVP_RSA_PRIM_KEYFORMAT_CRT;

        json_object_set_number(r_gobj, "tgId", tgId);
        json_object_set_value(r_gobj, "tests", json_value_init_array());
        r_tarr = json_object_get_array(r_gobj, "tests");

        AMVP_LOG_VERBOSE("       Test group: %d", i);
        AMVP_LOG_VERBOSE("       key format: %s", key_format);
        AMVP_LOG_VERBOSE("           modulo: %d", mod);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);

        for (j = 0; j < t_cnt; j++) {
            AMVP_LOG_VERBOSE("Found new RSA test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);
            tc_id = json_object_get_number(testobj, "tcId");
            if (!tc_id) {
                AMVP_LOG_ERR("Missing tc_id");
                rv = AMVP_MALFORMED_JSON;
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
             * Get a reference to the abstracted test case
             */

            e_str = json_object_get_string(testobj, "e");
            n_str = json_object_get_string(testobj, "n");
            if (!e_str || !n_str) {
                AMVP_LOG_ERR("Missing e|n from server json");
                rv = AMVP_MISSING_ARG;
                json_value_free(r_tval);
                goto err;
            }
            if ((strnlen_s(e_str, AMVP_RSA_EXP_LEN_MAX + 1) > AMVP_RSA_EXP_LEN_MAX) ||
                (strnlen_s(n_str, AMVP_RSA_EXP_LEN_MAX + 1) > AMVP_RSA_EXP_LEN_MAX)) {
                AMVP_LOG_ERR("server provided e/n of invalid length");
                rv = AMVP_INVALID_ARG;
                json_value_free(r_tval);
                goto err;
            }
            if (keyformat == AMVP_RSA_PRIM_KEYFORMAT_CRT) {
                p_str = json_object_get_string(testobj, "p");
                q_str = json_object_get_string(testobj, "q");
                dmp1_str = json_object_get_string(testobj, "dmp1");
                dmq1_str = json_object_get_string(testobj, "dmq1");
                iqmp_str = json_object_get_string(testobj, "iqmp");
                if (!p_str || !q_str || !dmp1_str || !dmq1_str || !iqmp_str) {
                    AMVP_LOG_ERR("Missing p|q|dmp1|dmq1|iqmp from server json");
                    rv = AMVP_MISSING_ARG;
                    json_value_free(r_tval);
                    goto err;
                }
                if ((strnlen_s(p_str, AMVP_RSA_EXP_LEN_MAX + 1) > AMVP_RSA_EXP_LEN_MAX) ||
                    (strnlen_s(q_str, AMVP_RSA_EXP_LEN_MAX + 1) > AMVP_RSA_EXP_LEN_MAX) ||
                    (strnlen_s(dmp1_str, AMVP_RSA_EXP_LEN_MAX + 1) > AMVP_RSA_EXP_LEN_MAX) ||
                    (strnlen_s(dmq1_str, AMVP_RSA_EXP_LEN_MAX + 1) > AMVP_RSA_EXP_LEN_MAX) ||
                    (strnlen_s(iqmp_str, AMVP_RSA_EXP_LEN_MAX + 1) > AMVP_RSA_EXP_LEN_MAX)) {
                    AMVP_LOG_ERR("server provided p/q/dmp1/dmq1/iqmp of invalid length");
                    rv = AMVP_INVALID_ARG;
                    json_value_free(r_tval);
                    goto err;
                }
            } else {
                d_str = json_object_get_string(testobj, "d");
                if (!d_str) {
                    AMVP_LOG_ERR("Missing d from server json");
                    rv = AMVP_MISSING_ARG;
                    json_value_free(r_tval);
                    goto err;
                }
                if (strnlen_s(d_str, AMVP_RSA_EXP_LEN_MAX + 1) > AMVP_RSA_EXP_LEN_MAX) {
                    AMVP_LOG_ERR("server provided d of invalid length");
                }
            }

            msg = json_object_get_string(testobj, "message");
            if (!msg) {
                AMVP_LOG_ERR("Missing 'message' from server json");
                rv = AMVP_MISSING_ARG;
                json_value_free(r_tval);
                goto err;
            }
            json_msglen = strnlen_s(msg, AMVP_RSA_MSGLEN_MAX + 1);
            if (json_msglen > AMVP_RSA_MSGLEN_MAX) {
                AMVP_LOG_ERR("'message' too long in server json");
                rv = AMVP_INVALID_ARG;
                json_value_free(r_tval);
                goto err;
            }
            AMVP_LOG_VERBOSE("              msg: %s", msg);

            rv = amvp_rsa_sigprim_init_tc(ctx, &stc, mod, keyformat, d_str, e_str, n_str, p_str,
                                          q_str, dmp1_str, dmq1_str, iqmp_str, msg);

            /* Process the current test vector... */
            if (rv == AMVP_SUCCESS) {
                if ((cap->crypto_handler)(&tc)) {
                    AMVP_LOG_ERR("ERROR: crypto module failed the operation");
                    rv = AMVP_CRYPTO_MODULE_FAIL;
                    json_value_free(r_tval);
                    goto err;
                }
            }

            /*
             * Output the test case results using JSON
             */
            rv = amvp_rsa_sigprim_output_tc(ctx, &stc, r_tobj);
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("ERROR: JSON output failure in hash module");
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Release all the memory associated with the test case
             */
            amvp_rsa_sigprim_release_tc(&stc);

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
        amvp_rsa_sigprim_release_tc(&stc);
        amvp_release_json(r_vs_val, r_gval);
    }
    return rv;
}

