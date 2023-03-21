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


static AMVP_KAS_FFC_PARAM amvp_convert_dgm_string(const char *dgm_str)
{
    int diff = 0;

    strcmp_s("fb", DGM_STR_MAX, dgm_str, &diff);
    if (!diff) return AMVP_KAS_FFC_FB;
    strcmp_s("fc", DGM_STR_MAX, dgm_str, &diff);
    if (!diff) return AMVP_KAS_FFC_FC;
    strcmp_s("FB", DGM_STR_MAX, dgm_str, &diff);
    if (!diff) return AMVP_KAS_FFC_FB;
    strcmp_s("FC", DGM_STR_MAX, dgm_str, &diff);
    if (!diff) return AMVP_KAS_FFC_FC;
    strcmp_s("MODP-2048", DGM_STR_MAX, dgm_str, &diff);
    if (!diff) return AMVP_KAS_FFC_MODP2048;
    strcmp_s("MODP-3072", DGM_STR_MAX, dgm_str, &diff);
    if (!diff) return AMVP_KAS_FFC_MODP3072;
    strcmp_s("MODP-4096", DGM_STR_MAX, dgm_str, &diff);
    if (!diff) return AMVP_KAS_FFC_MODP4096;
    strcmp_s("MODP-6144", DGM_STR_MAX, dgm_str, &diff);
    if (!diff) return AMVP_KAS_FFC_MODP6144;
    strcmp_s("MODP-8192", DGM_STR_MAX, dgm_str, &diff);
    if (!diff) return AMVP_KAS_FFC_MODP8192;
    strcmp_s("ffdhe2048", DGM_STR_MAX, dgm_str, &diff);
    if (!diff) return AMVP_KAS_FFC_FFDHE2048;
    strcmp_s("ffdhe3072", DGM_STR_MAX, dgm_str, &diff);
    if (!diff) return AMVP_KAS_FFC_FFDHE3072;
    strcmp_s("ffdhe4096", DGM_STR_MAX, dgm_str, &diff);
    if (!diff) return AMVP_KAS_FFC_FFDHE4096;
    strcmp_s("ffdhe6144", DGM_STR_MAX, dgm_str, &diff);
    if (!diff) return AMVP_KAS_FFC_FFDHE6144;
    strcmp_s("ffdhe8192", DGM_STR_MAX, dgm_str, &diff);
    if (!diff) return AMVP_KAS_FFC_FFDHE8192;

    return 0;
}
/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static AMVP_RESULT amvp_kas_ffc_output_ssc_tc(AMVP_CTX *ctx,
                                               AMVP_KAS_FFC_TC *stc,
                                               JSON_Object *tc_rsp) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    char *tmp = NULL;

    tmp = calloc(AMVP_KAS_FFC_STR_MAX + 1, sizeof(char));
    if (!tmp) {
        AMVP_LOG_ERR("Unable to malloc in amvp_aes_output_mct_tc");
        return AMVP_MALLOC_FAIL;
    }

    if (stc->test_type == AMVP_KAS_FFC_TT_VAL) {
        int diff = 1;

        memcmp_s(stc->chash, AMVP_KAS_FFC_BYTE_MAX,
                 stc->z, stc->zlen, &diff);
        if (!diff) {
            json_object_set_boolean(tc_rsp, "testPassed", 1);
        } else {
            json_object_set_boolean(tc_rsp, "testPassed", 0);
        }
        goto end;
    } else {
        memzero_s(tmp, AMVP_KAS_FFC_STR_MAX);
        rv = amvp_bin_to_hexstr(stc->piut, stc->piutlen, tmp, AMVP_KAS_FFC_STR_MAX);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("hex conversion failure (Z)");
            goto end;
        }
        json_object_set_string(tc_rsp, "ephemeralPublicIut", tmp);

        memzero_s(tmp, AMVP_KAS_FFC_STR_MAX);
        rv = amvp_bin_to_hexstr(stc->chash, stc->chashlen, tmp, AMVP_KAS_FFC_STR_MAX);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("hex conversion failure (Z)");
            goto end;
        }
        if(stc->md == AMVP_NO_SHA) {
            json_object_set_string(tc_rsp, "Z", tmp);
        } else {
            json_object_set_string(tc_rsp, "hashZ", tmp);
        }
    }
end:
    if (tmp) free(tmp);

    return rv;
}

static AMVP_RESULT amvp_kas_ffc_output_comp_tc(AMVP_CTX *ctx,
                                               AMVP_KAS_FFC_TC *stc,
                                               JSON_Object *tc_rsp) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    char *tmp = NULL;

    tmp = calloc(AMVP_KAS_FFC_STR_MAX + 1, sizeof(char));
    if (!tmp) {
        AMVP_LOG_ERR("Unable to malloc in amvp_aes_output_mct_tc");
        return AMVP_MALLOC_FAIL;
    }

    if (stc->test_type == AMVP_KAS_FFC_TT_VAL) {
        int diff = 1;

        memcmp_s(stc->chash, AMVP_KAS_FFC_BYTE_MAX,
                 stc->z, stc->zlen, &diff);
        if (!diff) {
            json_object_set_boolean(tc_rsp, "testPassed", 1);
        } else {
            json_object_set_boolean(tc_rsp, "testPassed", 0);
        }
        goto end;
    }

    memzero_s(tmp, AMVP_KAS_FFC_STR_MAX);
    rv = amvp_bin_to_hexstr(stc->piut, stc->piutlen, tmp, AMVP_KAS_FFC_STR_MAX);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("hex conversion failure (Z)");
        goto end;
    }
    json_object_set_string(tc_rsp, "ephemeralPublicIut", tmp);

    memzero_s(tmp, AMVP_KAS_FFC_STR_MAX);
    rv = amvp_bin_to_hexstr(stc->chash, stc->chashlen, tmp, AMVP_KAS_FFC_STR_MAX);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("hex conversion failure (Z)");
        goto end;
    }
    json_object_set_string(tc_rsp, "hashZIut", tmp);

end:
    if (tmp) free(tmp);

    return rv;
}

static AMVP_RESULT amvp_kas_ffc_init_comp_tc(AMVP_CTX *ctx,
                                             AMVP_KAS_FFC_TC *stc,
                                             AMVP_HASH_ALG hash_alg,
                                             AMVP_KAS_FFC_PARAM dgm,
                                             const char *p,
                                             const char *q,
                                             const char *g,
                                             const char *eps,
                                             const char *epri,
                                             const char *epui,
                                             const char *z,
                                             AMVP_KAS_FFC_TEST_TYPE test_type) {
    AMVP_RESULT rv;

    stc->mode = AMVP_KAS_FFC_MODE_COMPONENT;
    stc->md = hash_alg;
    stc->test_type = test_type;

    if ((dgm == AMVP_KAS_FFC_FB) || (dgm == AMVP_KAS_FFC_FC)) {
        stc->p = calloc(1, AMVP_KAS_FFC_BYTE_MAX);
        if (!stc->p) { return AMVP_MALLOC_FAIL; }
        rv = amvp_hexstr_to_bin(p, stc->p, AMVP_KAS_FFC_BYTE_MAX, &(stc->plen));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (p)");
            return rv;
        }

        stc->q = calloc(1, AMVP_KAS_FFC_BYTE_MAX);
        if (!stc->q) { return AMVP_MALLOC_FAIL; }
        rv = amvp_hexstr_to_bin(q, stc->q, AMVP_KAS_FFC_BYTE_MAX, &(stc->qlen));
        if (rv != AMVP_SUCCESS) {
           AMVP_LOG_ERR("Hex conversion failure (q)");
           return rv;
        }

        stc->g = calloc(1, AMVP_KAS_FFC_BYTE_MAX);
        if (!stc->g) { return AMVP_MALLOC_FAIL; }
        rv = amvp_hexstr_to_bin(g, stc->g, AMVP_KAS_FFC_BYTE_MAX, &(stc->glen));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (g)");
            return rv;
        }
    }
    stc->eps = calloc(1, AMVP_KAS_FFC_BYTE_MAX);
    if (!stc->eps) { return AMVP_MALLOC_FAIL; }
    rv = amvp_hexstr_to_bin(eps, stc->eps, AMVP_KAS_FFC_BYTE_MAX, &(stc->epslen));
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (eps)");
        return rv;
    }

    stc->epri = calloc(1, AMVP_KAS_FFC_BYTE_MAX);
    if (!stc->epri) { return AMVP_MALLOC_FAIL; }
    stc->epui = calloc(1, AMVP_KAS_FFC_BYTE_MAX);
    if (!stc->epui) { return AMVP_MALLOC_FAIL; }
    stc->chash = calloc(1, AMVP_KAS_FFC_BYTE_MAX);
    if (!stc->chash) { return AMVP_MALLOC_FAIL; }
    stc->piut = calloc(1, AMVP_KAS_FFC_BYTE_MAX);
    if (!stc->piut) { return AMVP_MALLOC_FAIL; }

    stc->z = calloc(1, AMVP_KAS_FFC_BYTE_MAX);
    if (!stc->z) { return AMVP_MALLOC_FAIL; }

    if (stc->test_type == AMVP_KAS_FFC_TT_VAL) {
        rv = amvp_hexstr_to_bin(z, stc->z, AMVP_KAS_FFC_BYTE_MAX, &(stc->zlen));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (z)");
            return rv;
        }
        rv = amvp_hexstr_to_bin(epri, stc->epri, AMVP_KAS_FFC_BYTE_MAX, &(stc->eprilen));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (epri)");
            return rv;
        }
        rv = amvp_hexstr_to_bin(epui, stc->epui, AMVP_KAS_FFC_BYTE_MAX, &(stc->epuilen));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (epui)");
            return rv;
        }
    }

    stc->dgm = dgm;
    return AMVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static AMVP_RESULT amvp_kas_ffc_release_tc(AMVP_KAS_FFC_TC *stc) {
    if (stc->piut) free(stc->piut);
    if (stc->epri) free(stc->epri);
    if (stc->epui) free(stc->epui);
    if (stc->eps) free(stc->eps);
    if (stc->z) free(stc->z);
    if (stc->chash) free(stc->chash);
    if (stc->p) free(stc->p);
    if (stc->q) free(stc->q);
    if (stc->g) free(stc->g);
    memzero_s(stc, sizeof(AMVP_KAS_FFC_TC));
    return AMVP_SUCCESS;
}

static AMVP_KAS_FFC_TEST_TYPE read_test_type(const char *str) {
    int diff = 1;

    strcmp_s("AFT", 3, str, &diff);
    if (!diff) return AMVP_KAS_FFC_TT_AFT;

    strcmp_s("VAL", 3, str, &diff);
    if (!diff) return AMVP_KAS_FFC_TT_VAL;

    return 0;
}

static AMVP_RESULT amvp_kas_ffc_comp(AMVP_CTX *ctx,
                                     AMVP_CAPS_LIST *cap,
                                     AMVP_TEST_CASE *tc,
                                     AMVP_KAS_FFC_TC *stc,
                                     JSON_Object *obj,
                                     JSON_Array *r_garr) {
    JSON_Value *groupval;
    JSON_Object *groupobj = NULL;
    JSON_Array *groups;
    JSON_Value *testval;
    JSON_Object *testobj = NULL;
    JSON_Array *tests, *r_tarr = NULL;
    JSON_Value *r_tval = NULL, *r_gval = NULL;  /* Response testval, groupval */
    JSON_Object *r_tobj = NULL, *r_gobj = NULL; /* Response testobj, groupobj */
    const char *hash_str = NULL;
    AMVP_HASH_ALG hash_alg = 0;
    const char *p = NULL, *q = NULL, *g = NULL, *pms_str = NULL;
    unsigned int i, g_cnt;
    int j, t_cnt, tc_id;
    AMVP_RESULT rv;
    const char *test_type_str;
    AMVP_KAS_FFC_TEST_TYPE test_type;
    AMVP_KAS_FFC_PARAM pms;

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

        hash_str = json_object_get_string(groupobj, "hashAlg");
        if (!hash_str) {
            AMVP_LOG_ERR("Server JSON missing 'hashAlg'");
            rv = AMVP_MISSING_ARG;
            goto err;
        }
        hash_alg = amvp_lookup_hash_alg(hash_str);
        if (hash_alg != AMVP_SHA224 && hash_alg != AMVP_SHA256 &&
            hash_alg != AMVP_SHA384 && hash_alg != AMVP_SHA512) {
            AMVP_LOG_ERR("Server JSON invalid 'hashAlg'");
            rv = AMVP_INVALID_ARG;
            goto err;
        }

        pms_str = json_object_get_string(groupobj, "parmSet");
        if (!pms_str) {
            AMVP_LOG_ERR("Missing parmSet from server JSON groub obj");
            rv = AMVP_MISSING_ARG;
            goto err;
        }

        pms = amvp_convert_dgm_string(pms_str);
        if (!pms) {
            AMVP_LOG_ERR("Missing parmSet from server JSON groub obj");
            rv = AMVP_MALFORMED_JSON;
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

        p = json_object_get_string(groupobj, "p");
        if (!p) {
            AMVP_LOG_ERR("Server JSON missing 'p'");
            rv = AMVP_MISSING_ARG;
            goto err;
        }
        if (strnlen_s(p, AMVP_KAS_FFC_STR_MAX + 1) > AMVP_KAS_FFC_STR_MAX) {
            AMVP_LOG_ERR("p too long, max allowed=(%d)",
                         AMVP_KAS_FFC_STR_MAX);
            rv = AMVP_INVALID_ARG;
            goto err;
        }

        q = json_object_get_string(groupobj, "q");
        if (!q) {
            AMVP_LOG_ERR("Server JSON missing 'q'");
            rv = AMVP_MISSING_ARG;
            goto err;
        }
        if (strnlen_s(q, AMVP_KAS_FFC_STR_MAX + 1) > AMVP_KAS_FFC_STR_MAX) {
            AMVP_LOG_ERR("q too long, max allowed=(%d)",
                         AMVP_KAS_FFC_STR_MAX);
            rv = AMVP_INVALID_ARG;
            goto err;
        }

        g = json_object_get_string(groupobj, "g");
        if (!g) {
            AMVP_LOG_ERR("Server JSON missing 'g'");
            rv = AMVP_MISSING_ARG;
            goto err;
        }
        if (strnlen_s(g, AMVP_KAS_FFC_STR_MAX + 1) > AMVP_KAS_FFC_STR_MAX) {
            AMVP_LOG_ERR("g too long, max allowed=(%d)",
                         AMVP_KAS_FFC_STR_MAX);
            rv = AMVP_INVALID_ARG;
            goto err;
        }

        AMVP_LOG_VERBOSE("    Test group: %d", i);
        AMVP_LOG_VERBOSE("      test type: %s", test_type_str);
        AMVP_LOG_VERBOSE("           hash: %s", hash_str);
        AMVP_LOG_VERBOSE("              p: %s", p);
        AMVP_LOG_VERBOSE("              q: %s", q);
        AMVP_LOG_VERBOSE("              g: %s", g);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);

        for (j = 0; j < t_cnt; j++) {
            const char *eps = NULL, *z = NULL, *epri = NULL, *epui = NULL;

            AMVP_LOG_VERBOSE("Found new KAS-FFC Component test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);
            tc_id = json_object_get_number(testobj, "tcId");

            eps = json_object_get_string(testobj, "ephemeralPublicServer");
            if (!eps) {
                AMVP_LOG_ERR("Server JSON missing 'ephemeralPublicServer'");
                rv = AMVP_MISSING_ARG;
                goto err;
            }
            if (strnlen_s(eps, AMVP_KAS_FFC_STR_MAX + 1)
                > AMVP_KAS_FFC_STR_MAX) {
                AMVP_LOG_ERR("ephemeralPublicServer too long, max allowed=(%d)",
                             AMVP_KAS_FFC_STR_MAX);
                rv = AMVP_INVALID_ARG;
                goto err;
            }

            if (test_type == AMVP_KAS_FFC_TT_VAL) {
                /*
                 * Validate
                 */
                epri = json_object_get_string(testobj, "ephemeralPrivateIut");
                if (!epri) {
                    AMVP_LOG_ERR("Server JSON missing 'ephemeralPrivateIut'");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(epri, AMVP_KAS_FFC_STR_MAX + 1)
                    > AMVP_KAS_FFC_STR_MAX) {
                    AMVP_LOG_ERR("ephemeralPrivateIut too long, max allowed=(%d)",
                                 AMVP_KAS_FFC_STR_MAX);
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }

                epui = json_object_get_string(testobj, "ephemeralPublicIut");
                if (!epui) {
                    AMVP_LOG_ERR("Server JSON missing 'ephemeralPublicIut'");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(epui, AMVP_KAS_FFC_STR_MAX + 1)
                    > AMVP_KAS_FFC_STR_MAX) {
                    AMVP_LOG_ERR("ephemeralPublicIut too long, max allowed=(%d)",
                                 AMVP_KAS_FFC_STR_MAX);
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }

                z = json_object_get_string(testobj, "hashZIut");
                if (!z) {
                    AMVP_LOG_ERR("Server JSON missing 'hashZIut'");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(z, AMVP_KAS_FFC_STR_MAX + 1)
                    > AMVP_KAS_FFC_STR_MAX) {
                    AMVP_LOG_ERR("hashZIut too long, max allowed=(%d)",
                                 AMVP_KAS_FFC_STR_MAX);
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }
            }

            AMVP_LOG_VERBOSE("            eps: %s", eps);
            AMVP_LOG_VERBOSE("              z: %s", z);
            AMVP_LOG_VERBOSE("           epri: %s", epri);
            AMVP_LOG_VERBOSE("           epui: %s", epui);

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
            rv = amvp_kas_ffc_init_comp_tc(ctx, stc, hash_alg, pms, 
                                           p, q, g, eps, epri, epui, z, test_type);
            if (rv != AMVP_SUCCESS) {
                amvp_kas_ffc_release_tc(stc);
                json_value_free(r_tval);
                goto err;
            }

            /* Process the current KAT test vector... */
            if ((cap->crypto_handler)(tc)) {
                amvp_kas_ffc_release_tc(stc);
                AMVP_LOG_ERR("crypto module failed the operation");
                rv = AMVP_CRYPTO_MODULE_FAIL;
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Output the test case results using JSON
             */
            rv = amvp_kas_ffc_output_comp_tc(ctx, stc, r_tobj);
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("JSON output failure in KAS-FFC module");
                amvp_kas_ffc_release_tc(stc);
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Release all the memory associated with the test case
             */
            amvp_kas_ffc_release_tc(stc);

            /* Append the test response value to array */
            json_array_append_value(r_tarr, r_tval);
        }
        json_array_append_value(r_garr, r_gval);
    }
    rv = AMVP_SUCCESS;

err:
    if (rv != AMVP_SUCCESS) {
        json_value_free(r_gval);
    }
    return rv;
}

AMVP_RESULT amvp_kas_ffc_kat_handler(AMVP_CTX *ctx, JSON_Object *obj) {
    JSON_Value *r_vs_val = NULL;
    JSON_Object *r_vs = NULL;
    JSON_Array *r_garr = NULL; /* Response testarray */
    JSON_Value *reg_arry_val = NULL;
    JSON_Array *reg_arry = NULL;
    JSON_Object *reg_obj = NULL;
    AMVP_CAPS_LIST *cap;
    AMVP_TEST_CASE tc;
    AMVP_KAS_FFC_TC stc;
    AMVP_RESULT rv = AMVP_SUCCESS;
    const char *alg_str = NULL;
    char *json_result = NULL;
    const char *mode_str = NULL;
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

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.kas_ffc = &stc;
    memzero_s(&stc, sizeof(AMVP_KAS_FFC_TC));

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
    mode_str = json_object_get_string(obj, "mode");
    json_object_set_string(r_vs, "mode", mode_str);

    if (mode_str) {
        stc.cipher = amvp_lookup_cipher_w_mode_index(alg_str, mode_str);
        if (stc.cipher != AMVP_KAS_FFC_COMP) {
            AMVP_LOG_ERR("Server JSON invalid 'algorithm' or 'mode'");
            rv = AMVP_INVALID_ARG;
            goto err;
        }
    } else {
        stc.cipher = AMVP_KAS_FFC_NOCOMP;
    }

    alg = amvp_get_kas_alg(stc.cipher);
    if (alg == 0) {
        AMVP_LOG_ERR("Invalid cipher value");
        rv = AMVP_INVALID_ARG;
        goto err;
    }
    
    switch (alg) {
    case AMVP_SUB_KAS_FFC_COMP:
        cap = amvp_locate_cap_entry(ctx, AMVP_KAS_FFC_COMP);
        if (!cap) {
            AMVP_LOG_ERR("AMVP server requesting unsupported capability");
            rv = AMVP_UNSUPPORTED_OP;
            goto err;
        }
        rv = amvp_kas_ffc_comp(ctx, cap, &tc, &stc, obj, r_garr);
        if (rv != AMVP_SUCCESS) {
            goto err;
        }

        break;

    case AMVP_SUB_KAS_ECC_CDH:
    case AMVP_SUB_KAS_ECC_COMP:
    case AMVP_SUB_KAS_ECC_NOCOMP:
    case AMVP_SUB_KAS_ECC_SSC:
    case AMVP_SUB_KAS_FFC_NOCOMP:
    case AMVP_SUB_KAS_FFC_SSC:
    case AMVP_SUB_KAS_IFC_SSC:
    case AMVP_SUB_KTS_IFC:
    case AMVP_SUB_KDA_ONESTEP:
    case AMVP_SUB_KDA_TWOSTEP:
    case AMVP_SUB_KDA_HKDF:
    case AMVP_SUB_SAFE_PRIMES_KEYGEN:
    case AMVP_SUB_SAFE_PRIMES_KEYVER:
    default:
        AMVP_LOG_ERR("AMVP server requesting unsupported KAS-FFC mode");
        rv = AMVP_UNSUPPORTED_OP;
        goto err;
    }
    json_array_append_value(reg_arry, r_vs_val);

    json_result = json_serialize_to_string_pretty(ctx->kat_resp, NULL);
    AMVP_LOG_VERBOSE("\n\n%s\n\n", json_result);
    json_free_serialized_string(json_result);
    rv = AMVP_SUCCESS;

err:
    if (rv != AMVP_SUCCESS) {
        amvp_kas_ffc_release_tc(&stc);
        json_value_free(r_vs_val);
    }
    return rv;
}

static AMVP_RESULT amvp_kas_ffc_ssc(AMVP_CTX *ctx,
                                    AMVP_CAPS_LIST *cap,
                                    AMVP_TEST_CASE *tc,
                                    AMVP_KAS_FFC_TC *stc,
                                    JSON_Object *obj,
                                    JSON_Array *r_garr) {
    JSON_Value *groupval;
    JSON_Object *groupobj = NULL;
    JSON_Array *groups;
    JSON_Value *testval;
    JSON_Object *testobj = NULL;
    JSON_Array *tests, *r_tarr = NULL;
    JSON_Value *r_tval = NULL, *r_gval = NULL;  /* Response testval, groupval */
    JSON_Object *r_tobj = NULL, *r_gobj = NULL; /* Response testobj, groupobj */
    AMVP_KAS_FFC_CAP_MODE *kas_ffc_mode = NULL;
    const char *hash_str = NULL, *dgm_str = NULL;
    AMVP_HASH_ALG hash_alg = 0;
    const char *p = NULL, *q = NULL, *g = NULL;
    unsigned int i, g_cnt;
    int j, t_cnt, tc_id;
    AMVP_RESULT rv;
    const char *test_type_str;
    AMVP_KAS_FFC_TEST_TYPE test_type;
    AMVP_KAS_FFC_PARAM dgm;
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
        dgm_str = json_object_get_string(groupobj, "domainParameterGenerationMode");
        if (!dgm_str) {
            AMVP_LOG_ERR("Missing domain generation method from server JSON groub obj");
            rv = AMVP_MISSING_ARG;
            goto err;
        }

        dgm = amvp_convert_dgm_string(dgm_str);
        if (!dgm) {
            AMVP_LOG_ERR("Missing domain generation method from server JSON groub obj");
            rv = AMVP_MALFORMED_JSON;
            goto err;
        }

        json_object_set_number(r_gobj, "tgId", tgId);
        json_object_set_value(r_gobj, "tests", json_value_init_array());
        r_tarr = json_object_get_array(r_gobj, "tests");

        //If the user doesn't specify a hash function, neither does the server
        if (cap && cap->cap.kas_ffc_cap) {
            kas_ffc_mode = &cap->cap.kas_ffc_cap->kas_ffc_mode[AMVP_KAS_FFC_MODE_NONE - 1];
            if (kas_ffc_mode && kas_ffc_mode->hash != AMVP_NO_SHA) {
                hash_str = json_object_get_string(groupobj, "hashFunctionZ");
                if (!hash_str) {
                    AMVP_LOG_ERR("Server JSON missing 'hashFunctionZ'");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }
                hash_alg = amvp_lookup_hash_alg(hash_str);
                switch (hash_alg) {
                case AMVP_SHA224:
                case AMVP_SHA256:
                case AMVP_SHA384:
                case AMVP_SHA512:
                case AMVP_SHA512_224:
                case AMVP_SHA512_256:
                case AMVP_SHA3_224:
                case AMVP_SHA3_256:
                case AMVP_SHA3_384:
                case AMVP_SHA3_512:
                    break;
                case AMVP_SHA1:
                case AMVP_NO_SHA:
                case AMVP_HASH_ALG_MAX:
                default:
                    AMVP_LOG_ERR("Server JSON invalid 'hashAlg'");
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }
            }
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
        if ((dgm == AMVP_KAS_FFC_FB) || (dgm == AMVP_KAS_FFC_FC)) {
            p = json_object_get_string(groupobj, "p");
            if (!p) {
                AMVP_LOG_ERR("Server JSON missing 'p'");
                rv = AMVP_MISSING_ARG;
                goto err;
            }
            if (strnlen_s(p, AMVP_KAS_FFC_STR_MAX + 1) > AMVP_KAS_FFC_STR_MAX) {
                AMVP_LOG_ERR("p too long, max allowed=(%d)",
                              AMVP_KAS_FFC_STR_MAX);
                rv = AMVP_INVALID_ARG;
                goto err;
            }

            q = json_object_get_string(groupobj, "q");
            if (!q) {
                AMVP_LOG_ERR("Server JSON missing 'q'");
                rv = AMVP_MISSING_ARG;
                goto err;
            }
            if (strnlen_s(q, AMVP_KAS_FFC_STR_MAX + 1) > AMVP_KAS_FFC_STR_MAX) {
                AMVP_LOG_ERR("q too long, max allowed=(%d)",
                             AMVP_KAS_FFC_STR_MAX);
                rv = AMVP_INVALID_ARG;
                goto err;
            }

            g = json_object_get_string(groupobj, "g");
            if (!g) {
                AMVP_LOG_ERR("Server JSON missing 'g'");
                rv = AMVP_MISSING_ARG;
                goto err;
            }
            if (strnlen_s(g, AMVP_KAS_FFC_STR_MAX + 1) > AMVP_KAS_FFC_STR_MAX) {
                AMVP_LOG_ERR("g too long, max allowed=(%d)",
                             AMVP_KAS_FFC_STR_MAX);
                rv = AMVP_INVALID_ARG;
                goto err;
            }
        }
        AMVP_LOG_VERBOSE("    Test group: %d", i);
        AMVP_LOG_VERBOSE("      test type: %s", test_type_str);
        AMVP_LOG_VERBOSE("           hash: %s", hash_str);
        AMVP_LOG_VERBOSE("              p: %s", p);
        AMVP_LOG_VERBOSE("              q: %s", q);
        AMVP_LOG_VERBOSE("              g: %s", g);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);

        for (j = 0; j < t_cnt; j++) {
            const char *eps = NULL, *z = NULL, *epri = NULL, *epui = NULL;

            AMVP_LOG_VERBOSE("Found new KAS-FFC Component test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);
            tc_id = json_object_get_number(testobj, "tcId");

            eps = json_object_get_string(testobj, "ephemeralPublicServer");
            if (!eps) {
                AMVP_LOG_ERR("Server JSON missing 'ephemeralPublicServer'");
                rv = AMVP_MISSING_ARG;
                goto err;
            }
            if (strnlen_s(eps, AMVP_KAS_FFC_STR_MAX + 1)
                > AMVP_KAS_FFC_STR_MAX) {
                AMVP_LOG_ERR("ephemeralPublicServer too long, max allowed=(%d)",
                             AMVP_KAS_FFC_STR_MAX);
                rv = AMVP_INVALID_ARG;
                goto err;
            }

            if (test_type == AMVP_KAS_FFC_TT_VAL) {
                /*
                 * Validate
                 */
                epri = json_object_get_string(testobj, "ephemeralPrivateIut");
                if (!epri) {
                    AMVP_LOG_ERR("Server JSON missing 'ephemeralPrivateIut'");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(epri, AMVP_KAS_FFC_STR_MAX + 1)
                    > AMVP_KAS_FFC_STR_MAX) {
                    AMVP_LOG_ERR("ephemeralPrivateIut too long, max allowed=(%d)",
                                 AMVP_KAS_FFC_STR_MAX);
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }

                epui = json_object_get_string(testobj, "ephemeralPublicIut");
                if (!epui) {
                    AMVP_LOG_ERR("Server JSON missing 'ephemeralPublicIut'");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(epui, AMVP_KAS_FFC_STR_MAX + 1)
                    > AMVP_KAS_FFC_STR_MAX) {
                    AMVP_LOG_ERR("ephemeralPublicIut too long, max allowed=(%d)",
                                 AMVP_KAS_FFC_STR_MAX);
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }

                z = json_object_get_string(testobj, "hashZ");
                if (!z) {
                    //Assume user did not specify hash function if we don't have capability info for some reason
                    if (!cap || !cap->cap.kas_ffc_cap || !cap->cap.kas_ffc_cap->kas_ffc_mode || 
                            cap->cap.kas_ffc_cap->kas_ffc_mode->hash == AMVP_NO_SHA) {
                        z = json_object_get_string(testobj, "z");
                        if (!z) {
                            AMVP_LOG_ERR("Server JSON missing 'z'");
                            rv = AMVP_MISSING_ARG;
                            goto err;
                        }
                    } else {
                        AMVP_LOG_ERR("Server JSON missing 'hashZ'");
                        rv = AMVP_MISSING_ARG;
                        goto err;
                    }
                }

                if (strnlen_s(z, AMVP_KAS_FFC_STR_MAX + 1)
                    > AMVP_KAS_FFC_STR_MAX) {
                    AMVP_LOG_ERR("hashZ or z too long, max allowed=(%d)",
                                 AMVP_KAS_FFC_STR_MAX);
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }
            }

            AMVP_LOG_VERBOSE("            eps: %s", eps);
            AMVP_LOG_VERBOSE("              z: %s", z);
            AMVP_LOG_VERBOSE("           epri: %s", epri);
            AMVP_LOG_VERBOSE("           epui: %s", epui);

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
            rv = amvp_kas_ffc_init_comp_tc(ctx, stc, hash_alg, dgm,
                                           p, q, g, eps, epri, epui, z, test_type);
            if (rv != AMVP_SUCCESS) {
                amvp_kas_ffc_release_tc(stc);
                json_value_free(r_tval);
                goto err;
            }

            /* Process the current KAT test vector... */
            if ((cap->crypto_handler)(tc)) {
                amvp_kas_ffc_release_tc(stc);
                AMVP_LOG_ERR("crypto module failed the operation");
                rv = AMVP_CRYPTO_MODULE_FAIL;
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Output the test case results using JSON
             */
            rv = amvp_kas_ffc_output_ssc_tc(ctx, stc, r_tobj);
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("JSON output failure in KAS-FFC module");
                amvp_kas_ffc_release_tc(stc);
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Release all the memory associated with the test case
             */
            amvp_kas_ffc_release_tc(stc);

            /* Append the test response value to array */
            json_array_append_value(r_tarr, r_tval);
        }
        json_array_append_value(r_garr, r_gval);
    }
    rv = AMVP_SUCCESS;

err:
    if (rv != AMVP_SUCCESS) {
        json_value_free(r_gval);
    }
    return rv;
}

AMVP_RESULT amvp_kas_ffc_ssc_kat_handler(AMVP_CTX *ctx, JSON_Object *obj) {
    JSON_Value *r_vs_val = NULL;
    JSON_Object *r_vs = NULL;
    JSON_Array *r_garr = NULL; /* Response testarray */
    JSON_Value *reg_arry_val = NULL;
    JSON_Array *reg_arry = NULL;
    JSON_Object *reg_obj = NULL;
    AMVP_CAPS_LIST *cap;
    AMVP_TEST_CASE tc;
    AMVP_KAS_FFC_TC stc;
    AMVP_RESULT rv = AMVP_SUCCESS;
    const char *alg_str = NULL;
    char *json_result = NULL;

    if (!ctx) {
        AMVP_LOG_ERR("No ctx for handler operation");
        return AMVP_NO_CTX;
    }

    alg_str = json_object_get_string(obj, "algorithm");
    if (!alg_str) {
        AMVP_LOG_ERR("unable to parse 'algorithm' from JSON");
        return AMVP_MALFORMED_JSON;
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.kas_ffc = &stc;
    memzero_s(&stc, sizeof(AMVP_KAS_FFC_TC));

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
    cap = amvp_locate_cap_entry(ctx, AMVP_KAS_FFC_SSC);
    if (!cap) {
        AMVP_LOG_ERR("AMVP server requesting unsupported capability");
        rv = AMVP_UNSUPPORTED_OP;
        goto err;
    }
    rv = amvp_kas_ffc_ssc(ctx, cap, &tc, &stc, obj, r_garr);
    if (rv != AMVP_SUCCESS) {
        goto err;
    }
    json_array_append_value(reg_arry, r_vs_val);

    json_result = json_serialize_to_string_pretty(ctx->kat_resp, NULL);
    AMVP_LOG_VERBOSE("\n\n%s\n\n", json_result);
    json_free_serialized_string(json_result);
    rv = AMVP_SUCCESS;

err:
    if (rv != AMVP_SUCCESS) {
        amvp_kas_ffc_release_tc(&stc);
        json_value_free(r_vs_val);
    }
    return rv;
}
