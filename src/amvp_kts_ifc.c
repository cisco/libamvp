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
static AMVP_RESULT amvp_kts_ifc_output_tc(AMVP_CTX *ctx,
                                              AMVP_KTS_IFC_TC *stc,
                                              JSON_Object *tc_rsp) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    char *tmp = NULL;

    tmp = calloc(AMVP_KTS_IFC_STR_MAX + 1, sizeof(char));
    if (!tmp) {
        AMVP_LOG_ERR("Unable to malloc in amvp_aes_output_mct_tc");
        return AMVP_MALLOC_FAIL;
    }

    if (stc->kts_role == AMVP_KTS_IFC_INITIATOR) {
        memzero_s(tmp, AMVP_KTS_IFC_STR_MAX);
        rv = amvp_bin_to_hexstr(stc->ct, stc->ct_len, tmp, AMVP_KTS_IFC_STR_MAX);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("hex conversion failure (iutC)");
            goto end;
        }

        json_object_set_string(tc_rsp, "iutC", tmp);
    }

    memzero_s(tmp, AMVP_KTS_IFC_STR_MAX);
    rv = amvp_bin_to_hexstr(stc->pt, stc->pt_len, tmp, AMVP_KTS_IFC_STR_MAX);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("hex conversion failure (dkm)");
        goto end;
    }

    json_object_set_string(tc_rsp, "dkm", tmp);

end:
    if (tmp) free(tmp);

    return rv;
}

static AMVP_RESULT amvp_kts_ifc_init_tc(AMVP_CTX *ctx,
                                            AMVP_KTS_IFC_TC *stc,
                                            AMVP_KTS_IFC_KEYGEN key_gen,
                                            AMVP_HASH_ALG hash_alg,
                                            AMVP_KTS_IFC_ROLES role,
                                            const char *ct,
                                            const char *p,
                                            const char *q,
                                            const char *d,
                                            const char *n,
                                            const char *e,
                                            const char *dmp1,
                                            const char *dmq1,
                                            const char *iqmp,
                                            int modulo, 
                                            int llen, 
                                            AMVP_KTS_IFC_TEST_TYPE test_type) {
    AMVP_RESULT rv;

    stc->llen = llen / 8;
    stc->modulo = modulo;
    stc->test_type = test_type;
    stc->md = hash_alg;
    stc->kts_role = role;
    stc->key_gen = key_gen;

    stc->ct = calloc(1, AMVP_KTS_IFC_BYTE_MAX);
    if (!stc->ct) { return AMVP_MALLOC_FAIL; }

    stc->pt = calloc(1, AMVP_KTS_IFC_BYTE_MAX);
    if (!stc->pt) { return AMVP_MALLOC_FAIL; }

    /* Both test types responder needs these */
    if (stc->kts_role == AMVP_KTS_IFC_RESPONDER) {
        rv = amvp_hexstr_to_bin(ct, stc->ct, AMVP_KTS_IFC_BYTE_MAX, &(stc->ct_len));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (p)");
            return rv;
        }

        stc->p = calloc(1, AMVP_KTS_IFC_BYTE_MAX);
        if (!stc->p) { return AMVP_MALLOC_FAIL; }
        rv = amvp_hexstr_to_bin(p, stc->p, AMVP_KTS_IFC_BYTE_MAX, &(stc->plen));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (p)");
            return rv;
        }

        stc->q = calloc(1, AMVP_KTS_IFC_BYTE_MAX);
        if (!stc->q) { return AMVP_MALLOC_FAIL; }
        rv = amvp_hexstr_to_bin(q, stc->q, AMVP_KTS_IFC_BYTE_MAX, &(stc->qlen));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (q)");
            return rv;
        }

        if (d) {
            stc->d = calloc(1, AMVP_KTS_IFC_BYTE_MAX);
            if (!stc->d) { return AMVP_MALLOC_FAIL; }
            rv = amvp_hexstr_to_bin(d, stc->d, AMVP_KTS_IFC_BYTE_MAX, &(stc->dlen));
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("Hex conversion failure (d)");
                return rv;
            }
        }

        if (key_gen == AMVP_KTS_IFC_RSAKPG1_CRT || key_gen == AMVP_KTS_IFC_RSAKPG2_CRT) {
            stc->dmp1 = calloc(1, AMVP_KTS_IFC_BYTE_MAX);
            if (!stc->dmp1) { return AMVP_MALLOC_FAIL; }
            rv = amvp_hexstr_to_bin(dmp1, stc->dmp1, AMVP_KTS_IFC_BYTE_MAX, &(stc->dmp1_len));
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("Hex conversion failure (dmp1)");
                return rv;
            }

            stc->dmq1 = calloc(1, AMVP_KTS_IFC_BYTE_MAX);
            if (!stc->dmq1) { return AMVP_MALLOC_FAIL; }
            rv = amvp_hexstr_to_bin(dmq1, stc->dmq1, AMVP_KTS_IFC_BYTE_MAX, &(stc->dmq1_len));
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("Hex conversion failure (dmq1)");
                return rv;
            }

            stc->iqmp = calloc(1, AMVP_KTS_IFC_BYTE_MAX);
            if (!stc->iqmp) { return AMVP_MALLOC_FAIL; }
            rv = amvp_hexstr_to_bin(iqmp, stc->iqmp, AMVP_KTS_IFC_BYTE_MAX, &(stc->iqmp_len));
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("Hex conversion failure (iqmp)");
                return rv;
            }
        }
    }

    /* Both test types both roles needs these */
    stc->n = calloc(1, AMVP_KTS_IFC_BYTE_MAX);
    if (!stc->n) { return AMVP_MALLOC_FAIL; }
    rv = amvp_hexstr_to_bin(n, stc->n, AMVP_KTS_IFC_BYTE_MAX, &(stc->nlen));
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (n)");
        return rv;
    }

    stc->e = calloc(1, AMVP_RSA_EXP_LEN_MAX);
    if (!stc->e) { return AMVP_MALLOC_FAIL; }
    rv = amvp_hexstr_to_bin(e, stc->e, AMVP_RSA_EXP_LEN_MAX, &(stc->elen));
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (e)");
        return rv;
    }

    return AMVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static AMVP_RESULT amvp_kts_ifc_release_tc(AMVP_KTS_IFC_TC *stc) {
    if (stc->p) free(stc->p);
    if (stc->q) free(stc->q);
    if (stc->d) free(stc->d);
    if (stc->e) free(stc->e);
    if (stc->n) free(stc->n);
    if (stc->dmp1) free(stc->dmp1);
    if (stc->dmq1) free(stc->dmq1);
    if (stc->iqmp) free(stc->iqmp);
    if (stc->ct) free(stc->ct);
    if (stc->pt) free(stc->pt);
    memzero_s(stc, sizeof(AMVP_KTS_IFC_TC));
    return AMVP_SUCCESS;
}

static AMVP_KTS_IFC_TEST_TYPE read_test_type(const char *str) {
    int diff = 1;

    strcmp_s("AFT", 3, str, &diff);
    if (!diff) return AMVP_KTS_IFC_TT_AFT;

    strcmp_s("VAL", 3, str, &diff);
    if (!diff) return AMVP_KTS_IFC_TT_VAL;

    return 0;
}

static AMVP_RSA_KEY_FORMAT read_key_gen(const char *str){
    int diff;

    strcmp_s("rsakpg1-basic", 13, str, &diff);
    if (!diff) return AMVP_KAS_IFC_RSAKPG1_BASIC;
    strcmp_s("rsakpg1-crt", 11, str, &diff);
    if (!diff) return AMVP_KAS_IFC_RSAKPG1_CRT;
    strcmp_s("rsakpg1-prime-factor", 20, str, &diff);
    if (!diff) return AMVP_KAS_IFC_RSAKPG1_PRIME_FACTOR;
    strcmp_s("rsakpg2-basic", 13, str, &diff);
    if (!diff) return AMVP_KAS_IFC_RSAKPG2_BASIC;
    strcmp_s("rsakpg2-crt", 11, str, &diff);
    if (!diff) return AMVP_KAS_IFC_RSAKPG2_CRT;
    strcmp_s("rsakpg2-prime-factor", 20, str, &diff);
    if (!diff) return AMVP_KAS_IFC_RSAKPG2_PRIME_FACTOR;

    return 0;
}

static AMVP_RESULT amvp_kts_ifc(AMVP_CTX *ctx,
                                    AMVP_CAPS_LIST *cap,
                                    AMVP_TEST_CASE *tc,
                                    AMVP_KTS_IFC_TC *stc,
                                    JSON_Object *obj,
                                    JSON_Array *r_garr) {
    JSON_Value *groupval;
    JSON_Object *groupobj = NULL;
    JSON_Array *groups;
    JSON_Object *ktsobj = NULL;
    JSON_Value *testval;
    JSON_Object *testobj = NULL;
    JSON_Array *tests, *r_tarr = NULL;
    JSON_Value *r_tval = NULL, *r_gval = NULL;  /* Response testval, groupval */
    JSON_Object *r_tobj = NULL, *r_gobj = NULL; /* Response testobj, groupobj */
    const char *p = NULL, *q = NULL, *n = NULL, *d = NULL, *e = NULL, *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
    const char *kts_role = NULL, *scheme = NULL, *hash = NULL;
    const char *ct = NULL;
    AMVP_HASH_ALG hash_alg;
    unsigned int modulo;
    unsigned int i, g_cnt;
    int j, t_cnt, tc_id, diff, llen;
    AMVP_RESULT rv;
    const char *test_type_str, *key_gen_str = NULL, *kc_dir = NULL, *kc_role = NULL;
    const char *iut_id = NULL, *server_id = NULL, *encoding = NULL, *assoc_data = NULL;
    AMVP_KTS_IFC_TEST_TYPE test_type;
    AMVP_KTS_IFC_ROLES role = 0;
    AMVP_KTS_IFC_KEYGEN key_gen = 0;

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
        } else if (test_type != AMVP_KTS_IFC_TT_AFT) {
            AMVP_LOG_ERR("Server JSON invalid testType - only AFT tests are supported for KTS-IFC");
            rv = AMVP_INVALID_ARG;
            goto err;
        }

        key_gen_str = json_object_get_string(groupobj, "keyGenerationMethod");
        if (!key_gen_str) {
            AMVP_LOG_ERR("Server JSON missing 'keyGenerationMethod'");
            rv = AMVP_MISSING_ARG;
            goto err;
        }

        key_gen = read_key_gen(key_gen_str);
        if (!key_gen) {
            AMVP_LOG_ERR("Server JSON invalid 'key_gen'");
            rv = AMVP_INVALID_ARG;
            goto err;
        }

        scheme = json_object_get_string(groupobj, "scheme");
        if (!scheme) {
            AMVP_LOG_ERR("Server JSON missing 'scheme'");
            rv = AMVP_MISSING_ARG;
            goto err;
        }
        kts_role = json_object_get_string(groupobj, "kasRole");
        if (!kts_role) {
            AMVP_LOG_ERR("Server JSON missing 'kasRole'");
            rv = AMVP_MISSING_ARG;
            goto err;
        }

        strcmp_s("initiator", 9, kts_role, &diff);
        if (!diff) role = AMVP_KTS_IFC_INITIATOR;
        strcmp_s("responder", 9, kts_role, &diff);
        if (!diff) role = AMVP_KTS_IFC_RESPONDER;

        iut_id = json_object_get_string(groupobj, "iutId");
        if (!iut_id) {
            AMVP_LOG_ERR("Server JSON missing 'iutId'");
            rv = AMVP_MISSING_ARG;
            goto err;
        }

        server_id = json_object_get_string(groupobj, "serverId");
        if (!server_id) {
            AMVP_LOG_ERR("Server JSON missing 'serverId'");
            rv = AMVP_MISSING_ARG;
            goto err;
        }

        modulo = json_object_get_number(groupobj, "modulo");
        if (!modulo) {
            AMVP_LOG_ERR("Server JSON missing 'modulo'");
            rv = AMVP_MISSING_ARG;
            goto err;
        }

        llen = json_object_get_number(groupobj, "l");
        if (!llen) {
            AMVP_LOG_ERR("Server JSON missing 'l'");
            rv = AMVP_MISSING_ARG;
            goto err;
        }

        kc_dir = json_object_get_string(groupobj, "keyConfirmationDirection");
        if (!kc_dir) {
            AMVP_LOG_ERR("Server JSON invalid 'keyConfirmationDirection'");
            rv = AMVP_MISSING_ARG;
            goto err;
        }

        kc_role = json_object_get_string(groupobj, "keyConfirmationRole");
        if (!kc_role) {
            AMVP_LOG_ERR("Server JSON invalid 'keyConfirmationRole'");
            rv = AMVP_MISSING_ARG;
            goto err;
        }


        ktsobj = json_object_get_object(groupobj, "ktsConfiguration");
        hash = json_object_get_string(ktsobj, "hashAlg");
        if (!hash) {
            AMVP_LOG_ERR("Server JSON missing 'hashAlg'");
            rv = AMVP_MISSING_ARG;
            goto err;
        }

        hash_alg = amvp_lookup_hash_alg(hash);
        if (!hash_alg) {
            AMVP_LOG_ERR("Server JSON invalid 'hashAlg'");
            rv = AMVP_INVALID_ARG;
            goto err;
        }

        assoc_data = json_object_get_string(ktsobj, "associatedDataPattern");
        if (!assoc_data) {
            AMVP_LOG_ERR("Server JSON invalid 'associatedDataPattern'");
            rv = AMVP_MISSING_ARG;
            goto err;
        }

        encoding = json_object_get_string(ktsobj, "encoding");
        if (!encoding) {
            AMVP_LOG_ERR("Server JSON invalid 'encoding'");
            rv = AMVP_MISSING_ARG;
            goto err;
        }

        AMVP_LOG_VERBOSE("    Test group: %d", i);
        AMVP_LOG_VERBOSE("      test type: %s", test_type_str);
        AMVP_LOG_VERBOSE("         scheme: %s", scheme);
        AMVP_LOG_VERBOSE("       kts role: %s", kts_role);
        AMVP_LOG_VERBOSE("        pub exp: %s", e);
        AMVP_LOG_VERBOSE("        key gen: %s", key_gen_str);
        AMVP_LOG_VERBOSE("           hash: %s", hash);
        AMVP_LOG_VERBOSE("         modulo: %d", modulo);
        AMVP_LOG_VERBOSE("           role: %d", role);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);

        for (j = 0; j < t_cnt; j++) {

            AMVP_LOG_VERBOSE("Found new KTS-IFC Component test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);
            tc_id = json_object_get_number(testobj, "tcId");

            if (role == AMVP_KTS_IFC_RESPONDER) {
                ct = json_object_get_string(testobj, "serverC");
                if (!ct) {
                    AMVP_LOG_ERR("Server JSON missing 'serverC'");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(ct, AMVP_KTS_IFC_STR_MAX + 1) > AMVP_KTS_IFC_STR_MAX) {
                    AMVP_LOG_ERR("ct too long, max allowed=(%d)",
                                  AMVP_KTS_IFC_STR_MAX);
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }

                p = json_object_get_string(testobj, "iutP");
                if (!p) {
                    AMVP_LOG_ERR("Server JSON missing 'iutP'");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(p, AMVP_KTS_IFC_STR_MAX + 1) > AMVP_KTS_IFC_STR_MAX) {
                    AMVP_LOG_ERR("p too long, max allowed=(%d)",
                                  AMVP_KTS_IFC_STR_MAX);
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }

                q = json_object_get_string(testobj, "iutQ");
                if (!q) {
                    AMVP_LOG_ERR("Server JSON missing 'iutQ'");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(q, AMVP_KTS_IFC_STR_MAX + 1) > AMVP_KTS_IFC_STR_MAX) {
                    AMVP_LOG_ERR("q too long, max allowed=(%d)",
                                  AMVP_KTS_IFC_STR_MAX);
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }

                n = json_object_get_string(testobj, "iutN");
                if (!n) {
                    AMVP_LOG_ERR("Server JSON missing 'iutN'");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(n, AMVP_KTS_IFC_STR_MAX + 1) > AMVP_KTS_IFC_STR_MAX) {
                    AMVP_LOG_ERR("n too long, max allowed=(%d)",
                                  AMVP_KTS_IFC_STR_MAX);
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }
                e = json_object_get_string(testobj, "iutE");
                if (!e) {
                    AMVP_LOG_ERR("Server JSON missing 'iutE'");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(e, AMVP_KTS_IFC_STR_MAX + 1) > AMVP_RSA_EXP_LEN_MAX) {
                    AMVP_LOG_ERR("e too long, max allowed=(%d)",
                                  AMVP_KTS_IFC_STR_MAX);
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }
                if (key_gen == AMVP_KTS_IFC_RSAKPG1_CRT || key_gen == AMVP_KTS_IFC_RSAKPG2_CRT) {
                    dmp1 = json_object_get_string(testobj, "iutDmp1");
                    if (!dmp1) {
                        AMVP_LOG_ERR("Server JSON missing 'iutDmp1'");
                        rv = AMVP_MISSING_ARG;
                        goto err;
                    }
                    if (strnlen_s(dmp1, AMVP_KTS_IFC_STR_MAX + 1) > AMVP_RSA_EXP_LEN_MAX) {
                        AMVP_LOG_ERR("dmp1 too long, max allowed=(%d)",
                                    AMVP_KTS_IFC_STR_MAX);
                        rv = AMVP_INVALID_ARG;
                        goto err;
                    }

                    dmq1 = json_object_get_string(testobj, "iutDmq1");
                    if (!dmq1) {
                        AMVP_LOG_ERR("Server JSON missing 'iutDmq1'");
                        rv = AMVP_MISSING_ARG;
                        goto err;
                    }
                    if (strnlen_s(dmq1, AMVP_KTS_IFC_STR_MAX + 1) > AMVP_RSA_EXP_LEN_MAX) {
                        AMVP_LOG_ERR("dmq1 too long, max allowed=(%d)",
                                    AMVP_KTS_IFC_STR_MAX);
                        rv = AMVP_INVALID_ARG;
                        goto err;
                    }

                    iqmp = json_object_get_string(testobj, "iutIqmp");
                    if (!iqmp) {
                        AMVP_LOG_ERR("Server JSON missing 'iutIqmp'");
                        rv = AMVP_MISSING_ARG;
                        goto err;
                    }
                    if (strnlen_s(iqmp, AMVP_KTS_IFC_STR_MAX + 1) > AMVP_RSA_EXP_LEN_MAX) {
                        AMVP_LOG_ERR("iqmp too long, max allowed=(%d)",
                                    AMVP_KTS_IFC_STR_MAX);
                        rv = AMVP_INVALID_ARG;
                        goto err;
                    }
                } else {
                    d = json_object_get_string(testobj, "iutD");
                    if (!d) {
                        AMVP_LOG_ERR("Server JSON missing 'iutD'");
                        rv = AMVP_MISSING_ARG;
                        goto err;
                    }
                    if (strnlen_s(d, AMVP_KTS_IFC_STR_MAX + 1) > AMVP_KTS_IFC_STR_MAX) {
                        AMVP_LOG_ERR("d too long, max allowed=(%d)",
                                    AMVP_KTS_IFC_STR_MAX);
                        rv = AMVP_INVALID_ARG;
                        goto err;
                }
                }
            } else {
                n = json_object_get_string(testobj, "serverN");
                if (!n) {
                    AMVP_LOG_ERR("Server JSON missing 'serverN'");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(n, AMVP_KTS_IFC_STR_MAX + 1) > AMVP_KTS_IFC_STR_MAX) {
                    AMVP_LOG_ERR("n too long, max allowed=(%d)",
                                  AMVP_KTS_IFC_STR_MAX);
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }

                e = json_object_get_string(testobj, "serverE");
                if (!e) {
                    AMVP_LOG_ERR("Server JSON missing 'serverE'");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(e, AMVP_KTS_IFC_STR_MAX + 1) > AMVP_KTS_IFC_STR_MAX) {
                    AMVP_LOG_ERR("e too long, max allowed=(%d)",
                                  AMVP_KTS_IFC_STR_MAX);
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }

            }
            
            AMVP_LOG_VERBOSE("           tcId: %d", tc_id);
            AMVP_LOG_VERBOSE("              p: %s", p);
            AMVP_LOG_VERBOSE("              q: %s", q);
            AMVP_LOG_VERBOSE("              n: %s", n);
            AMVP_LOG_VERBOSE("              d: %s", d);
            AMVP_LOG_VERBOSE("              e: %s", e);


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
            rv = amvp_kts_ifc_init_tc(ctx, stc, key_gen, hash_alg, role, ct, 
                                      p, q, d, n, e, dmp1, dmq1, iqmp, modulo, llen, test_type);
            if (rv != AMVP_SUCCESS) {
                amvp_kts_ifc_release_tc(stc);
                json_value_free(r_tval);
                goto err;
            }

            /* Process the current KAT test vector... */
            if ((cap->crypto_handler)(tc)) {
                amvp_kts_ifc_release_tc(stc);
                AMVP_LOG_ERR("crypto module failed the operation");
                rv = AMVP_CRYPTO_MODULE_FAIL;
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Output the test case results using JSON
             */
            rv = amvp_kts_ifc_output_tc(ctx, stc, r_tobj);
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("JSON output failure in KTS-IFC module");
                amvp_kts_ifc_release_tc(stc);
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Release all the memory associated with the test case
             */
            amvp_kts_ifc_release_tc(stc);

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

AMVP_RESULT amvp_kts_ifc_kat_handler(AMVP_CTX *ctx, JSON_Object *obj) {
    JSON_Value *r_vs_val = NULL;
    JSON_Object *r_vs = NULL;
    JSON_Array *r_garr = NULL; /* Response testarray */
    JSON_Value *reg_arry_val = NULL;
    JSON_Array *reg_arry = NULL;
    JSON_Object *reg_obj = NULL;
    AMVP_CAPS_LIST *cap;
    AMVP_TEST_CASE tc;
    AMVP_KTS_IFC_TC stc;
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
    tc.tc.kts_ifc = &stc;
    memzero_s(&stc, sizeof(AMVP_KTS_IFC_TC));

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
    cap = amvp_locate_cap_entry(ctx, AMVP_KTS_IFC);
    if (!cap) {
        AMVP_LOG_ERR("AMVP server requesting unsupported capability");
        rv = AMVP_UNSUPPORTED_OP;
        goto err;
    }
    rv = amvp_kts_ifc(ctx, cap, &tc, &stc, obj, r_garr);
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
        amvp_kts_ifc_release_tc(&stc);
        json_value_free(r_vs_val);
    }
    return rv;
}
