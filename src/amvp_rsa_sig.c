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

static AMVP_RESULT amvp_rsa_sig_kat_handler_internal(AMVP_CTX *ctx, JSON_Object *obj, AMVP_CIPHER cipher);

/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static AMVP_RESULT amvp_rsa_sig_output_tc(AMVP_CTX *ctx, AMVP_RSA_SIG_TC *stc, JSON_Object *tc_rsp) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    char *tmp = NULL;

    if (stc->sig_mode == AMVP_RSA_SIGVER) {
        json_object_set_boolean(tc_rsp, "testPassed", stc->ver_disposition);
    } else {
        tmp = calloc(AMVP_RSA_SIGNATURE_MAX + 1, sizeof(char));
        if (!tmp) {
            AMVP_LOG_ERR("Unable to malloc in rsa_sigver tpm_output_tc");
            return AMVP_MALLOC_FAIL;
        }
        rv = amvp_bin_to_hexstr(stc->signature, stc->sig_len, tmp, AMVP_RSA_SIGNATURE_MAX);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("hex conversion failure (signature)");
            goto err;
        }
        json_object_set_string(tc_rsp, "signature", (const char *)tmp);
    }

err:
    if (tmp) free(tmp);
    return rv;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */

static AMVP_RESULT amvp_rsa_siggen_release_tc(AMVP_RSA_SIG_TC *stc) {
    if (stc->msg) { free(stc->msg); }
    if (stc->e) { free(stc->e); }
    if (stc->n) { free(stc->n); }
    if (stc->signature) { free(stc->signature); }
    if (stc->salt) { free(stc->salt); }
    memzero_s(stc, sizeof(AMVP_RSA_SIG_TC));
    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_rsa_sig_init_tc(AMVP_CTX *ctx,
                                        AMVP_CIPHER cipher,
                                        AMVP_RSA_SIG_TC *stc,
                                        int tgId,
                                        unsigned int tc_id,
                                        AMVP_RSA_SIG_TYPE sig_type,
                                        unsigned int mod,
                                        AMVP_HASH_ALG hash_alg,
                                        const char *e,
                                        const char *n,
                                        const char *msg,
                                        char *signature,
                                        const char *salt,
                                        int salt_len) {
    AMVP_RESULT rv;

    memzero_s(stc, sizeof(AMVP_RSA_SIG_TC));

    stc->msg = calloc(AMVP_RSA_MSGLEN_MAX, sizeof(char));
    if (!stc->msg) { return AMVP_MALLOC_FAIL; }
    stc->signature = calloc(AMVP_RSA_SIGNATURE_MAX, sizeof(char));
    if (!stc->signature) { return AMVP_MALLOC_FAIL; }
    stc->salt = calloc(AMVP_RSA_SIGNATURE_MAX, sizeof(char));
    if (!stc->salt) { return AMVP_MALLOC_FAIL; }

    stc->e = calloc(AMVP_RSA_EXP_LEN_MAX, sizeof(char));
    if (!stc->e) { return AMVP_MALLOC_FAIL; }
    stc->n = calloc(AMVP_RSA_EXP_LEN_MAX, sizeof(char));
    if (!stc->n) { goto err; }

    rv = amvp_hexstr_to_bin(msg, stc->msg, AMVP_RSA_MSGLEN_MAX, &(stc->msg_len));
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (msg)");
        return rv;
    }

    if (cipher == AMVP_RSA_SIGVER) {
        stc->sig_mode = AMVP_RSA_SIGVER;
        rv = amvp_hexstr_to_bin(e, stc->e, AMVP_RSA_EXP_LEN_MAX, &(stc->e_len));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (e)");
            return rv;
        }
        rv = amvp_hexstr_to_bin(n, stc->n, AMVP_RSA_EXP_LEN_MAX, &(stc->n_len));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (n)");
            return rv;
        }
        rv = amvp_hexstr_to_bin(signature, stc->signature, AMVP_RSA_SIGNATURE_MAX, &stc->sig_len);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (signature)");
            return rv;
        }
    } else {
        stc->sig_mode = AMVP_RSA_SIGGEN;
    }

    if (salt_len) {
        if (salt) {
            memcpy_s(stc->salt, AMVP_RSA_SIGNATURE_MAX,
                     salt, strnlen_s((const char *)salt, 256));
        }
    }
    stc->salt_len = salt_len;

    stc->tc_id = tc_id;
    stc->tg_id = tgId;
    stc->modulo = mod;
    stc->hash_alg = hash_alg;
    stc->sig_type = sig_type;

    return rv;

err:
    AMVP_LOG_ERR("Failed to allocate buffer in RSA test case");
    if (stc->n) free(stc->n);
    return AMVP_MALLOC_FAIL;
}

AMVP_RESULT amvp_rsa_siggen_kat_handler(AMVP_CTX *ctx, JSON_Object *obj) {
    return amvp_rsa_sig_kat_handler_internal(ctx, obj, AMVP_RSA_SIGGEN);
}

AMVP_RESULT amvp_rsa_sigver_kat_handler(AMVP_CTX *ctx, JSON_Object *obj) {
    return amvp_rsa_sig_kat_handler_internal(ctx, obj, AMVP_RSA_SIGVER);
}

static AMVP_RSA_SIG_TYPE read_sig_type(const char *str) {
    int diff = 1;

    strcmp_s(AMVP_RSA_SIG_TYPE_X931_STR,
             AMVP_RSA_SIG_TYPE_LEN_MAX,
             str, &diff);
    if (!diff) return AMVP_RSA_SIG_TYPE_X931;

    strcmp_s(AMVP_RSA_SIG_TYPE_PKCS1V15_STR,
             AMVP_RSA_SIG_TYPE_LEN_MAX,
             str, &diff);
    if (!diff) return AMVP_RSA_SIG_TYPE_PKCS1V15;

    strcmp_s(AMVP_RSA_SIG_TYPE_PKCS1PSS_STR,
             AMVP_RSA_SIG_TYPE_LEN_MAX,
             str, &diff);
    if (!diff) return AMVP_RSA_SIG_TYPE_PKCS1PSS;

    return 0;
}

static AMVP_RESULT amvp_rsa_sig_kat_handler_internal(AMVP_CTX *ctx, JSON_Object *obj, AMVP_CIPHER cipher) {
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
    AMVP_RSA_SIG_TC stc;
    AMVP_TEST_CASE tc;

    AMVP_CIPHER alg_id;
    char *json_result = NULL;
    const char *mode_str;
    unsigned int mod = 0, padding = 0;
    const char *msg,  *tmp_signature = NULL;
    char *signature = NULL;
    const char *e_str = NULL, *n_str = NULL;
    const char *salt = NULL, *alg_str;
    unsigned int salt_len = 0, json_msglen, json_siglen, p;
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
    if (alg_id != cipher) {
        AMVP_LOG_ERR("Server JSON invalid 'algorithm' or 'mode'");
        return AMVP_INVALID_ARG;
    }

    tc.tc.rsa_sig = &stc;
    memzero_s(&stc, sizeof(AMVP_RSA_SIG_TC));
    stc.sig_mode = alg_id;

    cap = amvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        AMVP_LOG_ERR("ERROR: AMVP server requesting unsupported capability");
        return AMVP_UNSUPPORTED_OP;
    }

    AMVP_LOG_VERBOSE("    RSA mode: %s", mode_str);

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
        AMVP_RSA_SIG_TYPE sig_type = 0;
        AMVP_HASH_ALG hash_alg = 0;
        const char *sig_type_str = NULL, *hash_alg_str = NULL;
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
         * Get a reference to the abstracted test case
         */
        sig_type_str = json_object_get_string(groupobj, "sigType");
        if (!sig_type_str) {
            AMVP_LOG_ERR("Missing sigType from rsa_siggen json");
            rv = AMVP_MISSING_ARG;
            goto err;
        }
        sig_type = read_sig_type(sig_type_str);
        if (!sig_type) {
            AMVP_LOG_ERR("Server JSON invalid 'sigType'");
            rv = AMVP_INVALID_ARG;
            goto err;
        }

        mod = json_object_get_number(groupobj, "modulo");
        if (!mod) {
            AMVP_LOG_ERR("Server JSON missing 'modulo'");
            rv = AMVP_MISSING_ARG;
            goto err;
        }
        if (mod != 1024 && mod != 1536 && mod != 2048 && mod != 3072 && mod != 4096) {
            AMVP_LOG_ERR("Server JSON invalid 'modulo', (%d)", mod);
            rv = AMVP_INVALID_ARG;
            goto err;
        }

        hash_alg_str = json_object_get_string(groupobj, "hashAlg");
        if (!hash_alg_str) {
            AMVP_LOG_ERR("Server JSON missing 'hashAlg'");
            rv = AMVP_MISSING_ARG;
            goto err;
        }
        hash_alg = amvp_lookup_hash_alg(hash_alg_str);
        if (!hash_alg || (alg_id == AMVP_RSA_SIGGEN && hash_alg == AMVP_SHA1)) {
            AMVP_LOG_ERR("Server JSON invalid 'hashAlg'");
            rv = AMVP_INVALID_ARG;
            goto err;
        }

        salt_len = json_object_get_number(groupobj, "saltLen");

        if (alg_id == AMVP_RSA_SIGVER) {
            e_str = json_object_get_string(groupobj, "e");
            n_str = json_object_get_string(groupobj, "n");
            if (!e_str || !n_str) {
                AMVP_LOG_ERR("Missing e|n from server json");
                rv = AMVP_MISSING_ARG;
                goto err;
            }
            if ((strnlen_s(e_str, AMVP_RSA_EXP_LEN_MAX + 1) > AMVP_RSA_EXP_LEN_MAX) ||
                (strnlen_s(n_str, AMVP_RSA_EXP_LEN_MAX + 1) > AMVP_RSA_EXP_LEN_MAX)) {
                AMVP_LOG_ERR("server provided e or n of invalid length");
                rv = AMVP_INVALID_ARG;
                goto err;
            }
        }

        AMVP_LOG_VERBOSE("       Test group: %d", i);
        AMVP_LOG_VERBOSE("          sigType: %s", sig_type_str);
        AMVP_LOG_VERBOSE("           modulo: %d", mod);
        AMVP_LOG_VERBOSE("          hashAlg: %s", hash_alg_str);

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


            if (alg_id == AMVP_RSA_SIGVER) {
                tmp_signature = json_object_get_string(testobj, "signature");
                if (!tmp_signature) {
                    AMVP_LOG_ERR("Missing 'signature' from server json");
                    rv = AMVP_MISSING_ARG;
                    json_value_free(r_tval);
                    goto err;
                }
                json_siglen = strnlen_s(tmp_signature, AMVP_RSA_SIGNATURE_MAX + 1);
                if (json_siglen > AMVP_RSA_SIGNATURE_MAX) {
                    AMVP_LOG_ERR("'signature' too long in server json");
                    rv = AMVP_INVALID_ARG;
                    json_value_free(r_tval);
                    goto err;
                }

                signature = calloc(mod/4 +1, sizeof(char));                    
                if (!signature) {
                    AMVP_LOG_ERR("Unable to malloc for signature");
                    rv = AMVP_MALLOC_FAIL;
                    goto err;
                }
                if (json_siglen != mod/4) {
                    padding = mod/4 - json_siglen;
                    for (p=0;p<padding;p++) {
                        signature[p] = 0x30;
                    }
                    memcpy_s(signature + padding, mod/4, tmp_signature, json_siglen);
                } else {
                    padding = 0;
                    memcpy_s(signature, mod/4, tmp_signature, json_siglen);
                }

                salt = json_object_get_string(testobj, "salt");
            }

            rv = amvp_rsa_sig_init_tc(ctx, alg_id, &stc, tgId, tc_id,
                                      sig_type, mod, hash_alg, e_str,
                                      n_str, msg, signature, salt, salt_len);
            free(signature);

            /* Process the current test vector... */
            if (rv == AMVP_SUCCESS) {
                if ((cap->crypto_handler)(&tc)) {
                    AMVP_LOG_ERR("ERROR: crypto module failed the operation");
                    rv = AMVP_CRYPTO_MODULE_FAIL;
                    json_value_free(r_tval);
                    goto err;
                }
            }
            if (alg_id == AMVP_RSA_SIGGEN) {
                char *tmp = calloc(AMVP_RSA_EXP_LEN_MAX + 1, sizeof(char));
                if (!tmp) {
                    AMVP_LOG_ERR("Unable to malloc in rsa_siggen tpm_output_tc");
                    rv = AMVP_MALLOC_FAIL;
                    json_value_free(r_tval);
                    goto err;
                }
                rv = amvp_bin_to_hexstr(stc.e, stc.e_len, tmp, AMVP_RSA_EXP_LEN_MAX);
                if (rv != AMVP_SUCCESS) {
                    AMVP_LOG_ERR("hex conversion failure (e)");
                    free(tmp);
                    json_value_free(r_tval);
                    goto err;
                }
                json_object_set_string(r_gobj, "e", tmp);
                memzero_s(tmp, AMVP_RSA_EXP_LEN_MAX);

                rv = amvp_bin_to_hexstr(stc.n, stc.n_len, tmp, AMVP_RSA_EXP_LEN_MAX);
                if (rv != AMVP_SUCCESS) {
                    AMVP_LOG_ERR("hex conversion failure (n)");
                    free(tmp);
                    json_value_free(r_tval);
                    goto err;
                }
                json_object_set_string(r_gobj, "n", tmp);
                free(tmp);
            }

            /*
             * Output the test case results using JSON
             */
            rv = amvp_rsa_sig_output_tc(ctx, &stc, r_tobj);
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("ERROR: JSON output failure in hash module");
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Release all the memory associated with the test case
             */
            amvp_rsa_siggen_release_tc(&stc);

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
        amvp_rsa_siggen_release_tc(&stc);
        amvp_release_json(r_vs_val, r_gval);
    }
    return rv;
}
