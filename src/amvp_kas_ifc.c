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
static AMVP_RESULT amvp_kas_ifc_ssc_output_tc(AMVP_CTX *ctx,
                                              AMVP_KAS_IFC_TC *stc,
                                              JSON_Object *tc_rsp) {
    AMVP_RESULT rv = AMVP_INVALID_ARG;
    char *tmp = NULL;
    unsigned char *merge = NULL;
    int z_len = 0;

    tmp = calloc(AMVP_KAS_IFC_STR_MAX + 1, sizeof(char));
    if (!tmp) {
        AMVP_LOG_ERR("Unable to malloc in amvp_aes_output_mct_tc");
        return AMVP_MALLOC_FAIL;
    }

    if (stc->kas_role == AMVP_KAS_IFC_INITIATOR) {
        rv = amvp_bin_to_hexstr(stc->iut_ct_z, stc->iut_ct_z_len, tmp, AMVP_KAS_IFC_STR_MAX);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("hex conversion failure (iut_ct_z)");
            goto end;
        }
        json_object_set_string(tc_rsp, "iutC", tmp);

        rv = amvp_bin_to_hexstr(stc->iut_pt_z, stc->iut_pt_z_len, tmp, AMVP_KAS_IFC_STR_MAX);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("hex conversion failure (iut_pt_z)");
            goto end;
        }
        if (stc->md == AMVP_NO_SHA) {
            json_object_set_string(tc_rsp, "iutZ", tmp);
        } else {
            json_object_set_string(tc_rsp, "iutHashZ", tmp);
        }
        /* for KAS1, z is just iutZ. For KAS2, its the combined z. */
        if (stc->md == AMVP_NO_SHA) {
            json_object_set_string(tc_rsp, "z", tmp);
        } else {
            json_object_set_string(tc_rsp, "hashZ", tmp);
        }
    } else { /* if role = responder */
        if (stc->scheme == AMVP_KAS_IFC_KAS2) {
            rv = amvp_bin_to_hexstr(stc->iut_ct_z, stc->iut_ct_z_len, tmp, AMVP_KAS_IFC_STR_MAX);
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("hex conversion failure (iut_ct_z)");
                goto end;
            }
            json_object_set_string(tc_rsp, "iutC", tmp);

            rv = amvp_bin_to_hexstr(stc->iut_pt_z, stc->iut_pt_z_len, tmp, AMVP_KAS_IFC_STR_MAX);
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("hex conversion failure (iut_pt_z)");
                goto end;
            }
            if (stc->md == AMVP_NO_SHA) {
                json_object_set_string(tc_rsp, "iutZ", tmp);
            } else {
                json_object_set_string(tc_rsp, "iutHashZ", tmp);
            }
        } else {
            rv = amvp_bin_to_hexstr(stc->server_pt_z, stc->server_pt_z_len, tmp, AMVP_KAS_IFC_STR_MAX);
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("hex conversion failure (server_pt_z)");
                goto end;
            }
            if (stc->md == AMVP_NO_SHA) {
                json_object_set_string(tc_rsp, "z", tmp);
            } else {
                json_object_set_string(tc_rsp, "hashZ", tmp);
            }
        }
    }

    if (stc->scheme == AMVP_KAS_IFC_KAS2) {
        memzero_s(tmp, AMVP_KAS_IFC_STR_MAX);

        z_len = stc->iut_pt_z_len + stc->server_pt_z_len;
        merge = calloc(z_len, sizeof(unsigned char));
        if (!merge) {
            AMVP_LOG_ERR("Error allocating memory for z combination in KAS-IFC output");
            goto end;
        }
        if (stc->kas_role == AMVP_KAS_IFC_INITIATOR) {
            memcpy_s(merge, z_len, stc->iut_pt_z, stc->iut_pt_z_len);
            memcpy_s(merge + stc->iut_pt_z_len, z_len - stc->iut_pt_z_len,
                        stc->server_pt_z, stc->server_pt_z_len);
        } else {
            memcpy_s(merge, z_len, stc->server_pt_z, stc->server_pt_z_len);
            memcpy_s(merge + stc->server_pt_z_len, z_len - stc->server_pt_z_len,
                        stc->iut_pt_z, stc->iut_pt_z_len);
        }
        rv = amvp_bin_to_hexstr((const unsigned char *)merge, z_len, tmp, AMVP_KAS_IFC_STR_MAX);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("hex conversion failure (KAS2 combined Z)");
            goto end;
        }
        json_object_set_string(tc_rsp, "z", tmp);

    }

end:
    if (tmp) free(tmp);
    if (merge) free(merge);
    return rv;
}

static AMVP_RESULT amvp_kas_ifc_ssc_val_output_tc(AMVP_KAS_IFC_TC *stc,
                                                  JSON_Object *tc_rsp) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    rv = 0;
    int diff = 1, len = 0;
    unsigned char *merge = NULL;
    /* For initiator tests, check the encapsulated Z. For responder tests, check the decapsulated Z. */
    if (stc->kas_role == AMVP_KAS_IFC_INITIATOR) {
        if (stc->iut_ct_z_len == stc->provided_ct_z_len) {
            memcmp_s(stc->iut_ct_z, stc->iut_ct_z_len, stc->provided_ct_z, stc->provided_ct_z_len, &diff);
            rv += diff;
        } else {
            rv++;
        }
    } else if (stc->scheme != AMVP_KAS_IFC_KAS2) {
        if (stc->server_pt_z_len == stc->provided_pt_z_len) {
            memcmp_s(stc->server_pt_z, stc->server_pt_z_len, stc->provided_pt_z, stc->provided_pt_z_len, &diff);
            rv += diff;
        } else {
            rv++;
        }
    }

    /* For KAS2 tests, also check the combined Z. We ideally could check serverZ, but sometimes NIST provides incorrect
    combined Z in VAL tests. */
    if (stc->scheme == AMVP_KAS_IFC_KAS2) {
        len = stc->iut_pt_z_len + stc->server_pt_z_len;

        if (len == stc->provided_kas2_z_len) {
            merge = calloc(len, sizeof(unsigned char));
            if (!merge) {
                return AMVP_MALLOC_FAIL;
            }
            if (stc->kas_role == AMVP_KAS_IFC_INITIATOR) {
                memcpy_s(merge, len, stc->iut_pt_z, stc->iut_pt_z_len);
                memcpy_s(merge + stc->iut_pt_z_len, len - stc->iut_pt_z_len,
                            stc->server_pt_z, stc->server_pt_z_len);
            } else {
                memcpy_s(merge, len, stc->server_pt_z, stc->server_pt_z_len);
                memcpy_s(merge + stc->server_pt_z_len, len - stc->server_pt_z_len,
                            stc->iut_pt_z, stc->iut_pt_z_len);
            }
            memcmp_s(merge, len, stc->provided_kas2_z, stc->provided_kas2_z_len, &diff);
            rv += diff;
        } else {
            rv++;
        }
    }

    if (!rv) {
        json_object_set_boolean(tc_rsp, "testPassed", 1);
    } else {
        json_object_set_boolean(tc_rsp, "testPassed", 0);
    }

    if (merge) free(merge);
    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_kas_ifc_ssc_init_tc(AMVP_CTX *ctx,
                                            AMVP_KAS_IFC_TC *stc,
                                            AMVP_KAS_IFC_KEYGEN key_gen,
                                            AMVP_HASH_ALG hash_alg,
                                            AMVP_KAS_IFC_PARAM scheme,
                                            AMVP_KAS_IFC_ROLES role,
                                            const char *pt_z,
                                            const char *ct_z,
                                            const char *server_ct_z,
                                            const char *kas2_z,
                                            const char *server_n,
                                            const char *server_e,
                                            const char *p,
                                            const char *q,
                                            const char *d,
                                            const char *n,
                                            const char *e,
                                            const char *dmp1,
                                            const char *dmq1,
                                            const char *iqmp,
                                            unsigned int modulo,
                                            AMVP_KAS_IFC_TEST_TYPE test_type) {
    AMVP_RESULT rv;

    stc->test_type = test_type;
    stc->md = hash_alg;
    stc->scheme = scheme;
    stc->kas_role = role;
    stc->key_gen = key_gen;
    stc->modulo = modulo;

    if (p) {
        stc->p = calloc(1, AMVP_KAS_IFC_BYTE_MAX);
        if (!stc->p) { return AMVP_MALLOC_FAIL; }
        rv = amvp_hexstr_to_bin(p, stc->p, AMVP_KAS_IFC_BYTE_MAX, &(stc->plen));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (p)");
            return rv;
        }
    }

    if (q) {
        stc->q = calloc(1, AMVP_KAS_IFC_BYTE_MAX);
        if (!stc->q) { return AMVP_MALLOC_FAIL; }
        rv = amvp_hexstr_to_bin(q, stc->q, AMVP_KAS_IFC_BYTE_MAX, &(stc->qlen));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (q)");
            return rv;
        }
    }

    if (d) {
        stc->d = calloc(1, AMVP_KAS_IFC_BYTE_MAX);
        if (!stc->d) { return AMVP_MALLOC_FAIL; }
        rv = amvp_hexstr_to_bin(d, stc->d, AMVP_KAS_IFC_BYTE_MAX, &(stc->dlen));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (d)");
            return rv;
        }
    }

    if (n) {
        stc->n = calloc(1, AMVP_KAS_IFC_BYTE_MAX);
        if (!stc->n) { return AMVP_MALLOC_FAIL; }
        rv = amvp_hexstr_to_bin(n, stc->n, AMVP_KAS_IFC_BYTE_MAX, &(stc->nlen));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (n)");
            return rv;
        }
    }

    if (e) {
        stc->e = calloc(1, AMVP_RSA_EXP_LEN_MAX);
        if (!stc->e) { return AMVP_MALLOC_FAIL; }
        rv = amvp_hexstr_to_bin(e, stc->e, AMVP_RSA_EXP_LEN_MAX, &(stc->elen));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (e)");
            return rv;
        }
    }

    if (dmp1) {
        stc->dmp1 = calloc(1, AMVP_KAS_IFC_BYTE_MAX);
        if (!stc->dmp1) { return AMVP_MALLOC_FAIL; }
        rv = amvp_hexstr_to_bin(dmp1, stc->dmp1, AMVP_KAS_IFC_BYTE_MAX, &(stc->dmp1_len));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (dmp1)");
            return rv;
        }
    }

    if (dmq1) {
        stc->dmq1 = calloc(1, AMVP_KAS_IFC_BYTE_MAX);
        if (!stc->dmq1) { return AMVP_MALLOC_FAIL; }
        rv = amvp_hexstr_to_bin(dmq1, stc->dmq1, AMVP_KAS_IFC_BYTE_MAX, &(stc->dmq1_len));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (dmq1)");
            return rv;
        }
    }

    if (iqmp) {
        stc->iqmp = calloc(1, AMVP_KAS_IFC_BYTE_MAX);
        if (!stc->iqmp) { return AMVP_MALLOC_FAIL; }
        rv = amvp_hexstr_to_bin(iqmp, stc->iqmp, AMVP_KAS_IFC_BYTE_MAX, &(stc->iqmp_len));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (iqmp)");
            return rv;
        }
    }

    if (server_ct_z) {
        stc->server_ct_z = calloc(1, AMVP_KAS_IFC_BYTE_MAX);
        if (!stc->server_ct_z) { return AMVP_MALLOC_FAIL; }
        rv = amvp_hexstr_to_bin(server_ct_z, stc->server_ct_z, AMVP_KAS_IFC_BYTE_MAX, &(stc->server_ct_z_len));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (server_ct_z)");
            return rv;
        }
    }

    if (kas2_z) {
        stc->provided_kas2_z = calloc(1, AMVP_KAS_IFC_BYTE_MAX);
        if (!stc->provided_kas2_z) { return AMVP_MALLOC_FAIL; }
        rv = amvp_hexstr_to_bin(kas2_z, stc->provided_kas2_z, AMVP_KAS_IFC_BYTE_MAX, &(stc->provided_kas2_z_len));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (kas2_z)");
            return rv;
        }
    }

    if (server_n) {
        stc->server_n = calloc(1, AMVP_KAS_IFC_BYTE_MAX);
        if (!stc->server_n) { return AMVP_MALLOC_FAIL; }
        rv = amvp_hexstr_to_bin(server_n, stc->server_n, AMVP_KAS_IFC_BYTE_MAX, &(stc->server_nlen));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (server_n)");
            return rv;
        }
    }

    if (server_e) {
        stc->server_e = calloc(1, AMVP_KAS_IFC_BYTE_MAX);
        if (!stc->server_e) { return AMVP_MALLOC_FAIL; }
        rv = amvp_hexstr_to_bin(server_e, stc->server_e, AMVP_RSA_EXP_LEN_MAX, &(stc->server_elen));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (server_e)");
            return rv;
        }
    }

    stc->iut_ct_z = calloc(1, AMVP_KAS_IFC_BYTE_MAX);
    if (!stc->iut_ct_z) { return AMVP_MALLOC_FAIL; }
    if (ct_z) {
        rv = amvp_hexstr_to_bin(ct_z, stc->iut_ct_z, AMVP_KAS_IFC_BYTE_MAX, &(stc->iut_ct_z_len));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (ct_z)");
            return rv;
        }
    }
    stc->iut_pt_z = calloc(1, AMVP_KAS_IFC_BYTE_MAX);
    if (!stc->iut_pt_z) { return AMVP_MALLOC_FAIL; }
    if (pt_z) {
        rv = amvp_hexstr_to_bin(pt_z, stc->iut_pt_z, AMVP_KAS_IFC_BYTE_MAX, &(stc->iut_pt_z_len));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (pt_z)");
            return rv;
        }
    }
    stc->server_pt_z = calloc(1, AMVP_KAS_IFC_BYTE_MAX + 1);
    if (!stc->server_pt_z) { return AMVP_MALLOC_FAIL; }

    if (stc->test_type == AMVP_KAS_IFC_TT_VAL) {
        if (stc->kas_role == AMVP_KAS_IFC_INITIATOR) {
            stc->provided_ct_z = calloc(1, AMVP_KAS_IFC_BYTE_MAX);
            if (!stc->provided_ct_z) { return AMVP_MALLOC_FAIL; }
            rv = amvp_hexstr_to_bin(ct_z, stc->provided_ct_z, AMVP_KAS_IFC_BYTE_MAX, &(stc->provided_ct_z_len));
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("Hex conversion failure (provided_iut_ct_z)");
                return rv;
            }
        } else {
            stc->provided_pt_z = calloc(1, AMVP_KAS_IFC_BYTE_MAX);
            if (!stc->provided_pt_z) { return AMVP_MALLOC_FAIL; }
            rv = amvp_hexstr_to_bin(pt_z, stc->provided_pt_z, AMVP_KAS_IFC_BYTE_MAX, &(stc->provided_pt_z_len));
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("Hex conversion failure (provided_iut_pt_z)");
                return rv;
            }
        }
    }

    return AMVP_SUCCESS;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static AMVP_RESULT amvp_kas_ifc_release_tc(AMVP_KAS_IFC_TC *stc) {
    if (stc->server_n) free(stc->server_n);
    if (stc->server_e) free(stc->server_e);
    if (stc->p) free(stc->p);
    if (stc->q) free(stc->q);
    if (stc->d) free(stc->d);
    if (stc->e) free(stc->e);
    if (stc->n) free(stc->n);
    if (stc->dmp1) free(stc->dmp1);
    if (stc->dmq1) free(stc->dmq1);
    if (stc->iqmp) free(stc->iqmp);
    if (stc->iut_ct_z) free(stc->iut_ct_z);
    if (stc->iut_pt_z) free(stc->iut_pt_z);
    if (stc->provided_ct_z) free(stc->provided_ct_z);
    if (stc->provided_pt_z) free(stc->provided_pt_z);
    if (stc->server_pt_z) free(stc->server_pt_z);
    if (stc->server_ct_z) free(stc->server_ct_z);
    if (stc->provided_kas2_z) free(stc->provided_kas2_z);
    memzero_s(stc, sizeof(AMVP_KAS_IFC_TC));
    return AMVP_SUCCESS;
}

static AMVP_KAS_IFC_TEST_TYPE read_test_type(const char *str) {
    int diff = 1;

    strcmp_s("AFT", 3, str, &diff);
    if (!diff) return AMVP_KAS_IFC_TT_AFT;

    strcmp_s("VAL", 3, str, &diff);
    if (!diff) return AMVP_KAS_IFC_TT_VAL;

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

static AMVP_RESULT amvp_kas_ifc_ssc(AMVP_CTX *ctx,
                                    AMVP_CAPS_LIST *cap,
                                    AMVP_TEST_CASE *tc,
                                    AMVP_KAS_IFC_TC *stc,
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
    /* KAS key vals */
    const char *p = NULL, *q = NULL, *n = NULL, *d = NULL, *e = NULL, *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
    const char *server_n = NULL, *server_e = NULL;
    const char *pub_exp = NULL, *kas_role = NULL, *scheme_str = NULL, *hash = NULL;
    const char *ct_z = NULL, *pt_z = NULL, *kas2_z = NULL;
    const char *server_ct_z = NULL;
    AMVP_HASH_ALG hash_alg = 0;
    unsigned int modulo;
    unsigned int i, g_cnt;
    int j, t_cnt, tc_id, diff;
    AMVP_RESULT rv;
    const char *test_type_str, *key_gen_str = NULL;
    AMVP_KAS_IFC_TEST_TYPE test_type;
    AMVP_KAS_IFC_ROLES role = 0;
    AMVP_KAS_IFC_PARAM scheme = AMVP_KAS_IFC_KAS1;
    AMVP_KAS_IFC_KEYGEN key_gen = 0;

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

        scheme_str = json_object_get_string(groupobj, "scheme");
        if (!scheme_str) {
            AMVP_LOG_ERR("Server JSON missing 'scheme'");
            rv = AMVP_MISSING_ARG;
            goto err;
        }
        strcmp_s("KAS1", 4, scheme_str, &diff);
        if (!diff) scheme = AMVP_KAS_IFC_KAS1;
        strcmp_s("KAS2", 4, scheme_str, &diff);
        if (!diff) scheme = AMVP_KAS_IFC_KAS2;


        //If the user doesn't specify a hash function, neither does the server
        if (cap && cap->cap.kas_ifc_cap && cap->cap.kas_ifc_cap->hash != AMVP_NO_SHA) {
            hash = json_object_get_string(groupobj, "hashFunctionZ");
            if (!hash) {
                AMVP_LOG_ERR("Server JSON missing 'hashFunctionZ'");
                rv = AMVP_MISSING_ARG;
                goto err;
            }

            hash_alg = amvp_lookup_hash_alg(hash);
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
                    AMVP_LOG_ERR("Server JSON invalid 'hashFunctionZ'");
                    rv = AMVP_INVALID_ARG;
                    goto err;
            }
        }

        kas_role = json_object_get_string(groupobj, "kasRole");
        if (!kas_role) {
            AMVP_LOG_ERR("Server JSON missing 'kasRole'");
            rv = AMVP_MISSING_ARG;
            goto err;
        }

        strcmp_s("initiator", 9, kas_role, &diff);
        if (!diff) role = AMVP_KAS_IFC_INITIATOR;
        strcmp_s("responder", 9, kas_role, &diff);
        if (!diff) role = AMVP_KAS_IFC_RESPONDER;

        pub_exp = json_object_get_string(groupobj, "fixedPubExp");
        if (!pub_exp) {
            AMVP_LOG_ERR("Server JSON missing 'fixedPubExp'");
            rv = AMVP_MISSING_ARG;
            goto err;
        }

        modulo = json_object_get_number(groupobj, "modulo");
        if (!modulo) {
            AMVP_LOG_ERR("Server JSON missing 'modulo'");
            rv = AMVP_MISSING_ARG;
            goto err;
        }


        AMVP_LOG_VERBOSE("    Test group: %d", i);
        AMVP_LOG_VERBOSE("      test type: %s", test_type_str);
        AMVP_LOG_VERBOSE("         scheme: %s", scheme_str);
        AMVP_LOG_VERBOSE("       kas role: %s", kas_role);
        AMVP_LOG_VERBOSE("        pub exp: %s", pub_exp);
        AMVP_LOG_VERBOSE("        key gen: %s", key_gen_str);
        AMVP_LOG_VERBOSE("           hash: %s", hash);
        AMVP_LOG_VERBOSE("         modulo: %d", modulo);
        AMVP_LOG_VERBOSE("           role: %d", role);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);

        for (j = 0; j < t_cnt; j++) {

            AMVP_LOG_VERBOSE("Found new KAS-IFC Component test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);
            tc_id = json_object_get_number(testobj, "tcId");

            if (role == AMVP_KAS_IFC_RESPONDER || scheme == AMVP_KAS_IFC_KAS2) {
                p = json_object_get_string(testobj, "iutP");
                if (!p) {
                    AMVP_LOG_ERR("Server JSON missing 'iutP'");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(p, AMVP_KAS_IFC_STR_MAX + 1) > AMVP_KAS_IFC_STR_MAX) {
                    AMVP_LOG_ERR("p too long, max allowed=(%d)",
                                  AMVP_KAS_IFC_STR_MAX);
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }

                q = json_object_get_string(testobj, "iutQ");
                if (!q) {
                    AMVP_LOG_ERR("Server JSON missing 'iutQ'");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(q, AMVP_KAS_IFC_STR_MAX + 1) > AMVP_KAS_IFC_STR_MAX) {
                    AMVP_LOG_ERR("q too long, max allowed=(%d)",
                                  AMVP_KAS_IFC_STR_MAX);
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }

                if (strnlen_s(d, AMVP_KAS_IFC_STR_MAX + 1) > AMVP_KAS_IFC_STR_MAX) {
                    AMVP_LOG_ERR("d too long, max allowed=(%d)",
                                  AMVP_KAS_IFC_STR_MAX);
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }

                n = json_object_get_string(testobj, "iutN");
                if (!n) {
                    AMVP_LOG_ERR("Server JSON missing 'iutN'");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(n, AMVP_KAS_IFC_STR_MAX + 1) > AMVP_KAS_IFC_STR_MAX) {
                    AMVP_LOG_ERR("n too long, max allowed=(%d)",
                                  AMVP_KAS_IFC_STR_MAX);
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }

                e = json_object_get_string(testobj, "iutE");
                if (!e) {
                    AMVP_LOG_ERR("Server JSON missing 'iutE'");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(e, AMVP_KAS_IFC_STR_MAX + 1) > AMVP_RSA_EXP_LEN_MAX) {
                    AMVP_LOG_ERR("e too long, max allowed=(%d)",
                                  AMVP_KAS_IFC_STR_MAX);
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }

                if (key_gen == AMVP_KAS_IFC_RSAKPG1_CRT || key_gen == AMVP_KAS_IFC_RSAKPG2_CRT) {
                    dmp1 = json_object_get_string(testobj, "iutDmp1");
                    if (!dmp1) {
                        AMVP_LOG_ERR("Server JSON missing 'iutDmp1'");
                        rv = AMVP_MISSING_ARG;
                        goto err;
                    }
                    if (strnlen_s(dmp1, AMVP_KAS_IFC_STR_MAX + 1) > AMVP_KAS_IFC_STR_MAX) {
                        AMVP_LOG_ERR("dmp1 too long, max allowed=(%d)",
                                    AMVP_KAS_IFC_STR_MAX);
                        rv = AMVP_INVALID_ARG;
                        goto err;
                    }
                    dmq1 = json_object_get_string(testobj, "iutDmq1");
                    if (!dmq1) {
                        AMVP_LOG_ERR("Server JSON missing 'iutDmq1'");
                        rv = AMVP_MISSING_ARG;
                        goto err;
                    }
                    if (strnlen_s(dmq1, AMVP_KAS_IFC_STR_MAX + 1) > AMVP_KAS_IFC_STR_MAX) {
                        AMVP_LOG_ERR("dmq1 too long, max allowed=(%d)",
                                    AMVP_KAS_IFC_STR_MAX);
                        rv = AMVP_INVALID_ARG;
                        goto err;
                    }
                    iqmp = json_object_get_string(testobj, "iutIqmp");
                    if (!iqmp) {
                        AMVP_LOG_ERR("Server JSON missing 'iutIqmp'");
                        rv = AMVP_MISSING_ARG;
                        goto err;
                    }
                    if (strnlen_s(iqmp, AMVP_KAS_IFC_STR_MAX + 1) > AMVP_KAS_IFC_STR_MAX) {
                        AMVP_LOG_ERR("iqmp too long, max allowed=(%d)",
                                    AMVP_KAS_IFC_STR_MAX);
                        rv = AMVP_INVALID_ARG;
                        goto err;
                    }
                }

                if (key_gen != AMVP_KAS_IFC_RSAKPG1_CRT && key_gen != AMVP_KAS_IFC_RSAKPG2_CRT) {
                    d = json_object_get_string(testobj, "iutD");
                    if (!d) {
                        AMVP_LOG_ERR("Server JSON missing 'iutD'");
                        rv = AMVP_MISSING_ARG;
                        goto err;
                    }
                }
            }

            if (role == AMVP_KAS_IFC_INITIATOR || scheme == AMVP_KAS_IFC_KAS2) {
                server_n = json_object_get_string(testobj, "serverN");
                if (!server_n) {
                    AMVP_LOG_ERR("Server JSON missing 'serverN'");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(server_n, AMVP_KAS_IFC_STR_MAX + 1) > AMVP_KAS_IFC_STR_MAX) {
                    AMVP_LOG_ERR("serverN too long, max allowed=(%d)",
                                  AMVP_KAS_IFC_STR_MAX);
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }

                server_e = json_object_get_string(testobj, "serverE");
                if (!server_e) {
                    AMVP_LOG_ERR("Server JSON missing 'serverE'");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(server_e, AMVP_KAS_IFC_STR_MAX + 1) > AMVP_KAS_IFC_STR_MAX) {
                    AMVP_LOG_ERR("serverE too long, max allowed=(%d)",
                                  AMVP_KAS_IFC_STR_MAX);
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }
            }

            if (role == AMVP_KAS_IFC_RESPONDER || scheme == AMVP_KAS_IFC_KAS2) {
                server_ct_z = json_object_get_string(testobj, "serverC");
                if (!server_ct_z) {
                    AMVP_LOG_ERR("Server JSON missing 'serverC'");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(server_ct_z, AMVP_KAS_IFC_STR_MAX + 1) > AMVP_KAS_IFC_STR_MAX) {
                    AMVP_LOG_ERR("serverC too long, max allowed=(%d)",
                                  AMVP_KAS_IFC_STR_MAX);
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }
            }

            if (scheme == AMVP_KAS_IFC_KAS2) {
                server_n = json_object_get_string(testobj, "serverN");
                if (!server_n) {
                    AMVP_LOG_ERR("Server JSON missing 'serverN'");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(server_n, AMVP_KAS_IFC_STR_MAX + 1) > AMVP_KAS_IFC_STR_MAX) {
                    AMVP_LOG_ERR("n too long, max allowed=(%d)",
                                AMVP_KAS_IFC_STR_MAX);
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }
                server_e = json_object_get_string(testobj, "serverE");
                if (!server_e) {
                    AMVP_LOG_ERR("Server JSON missing 'serverE'");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }
                if (strnlen_s(server_e, AMVP_KAS_IFC_STR_MAX + 1) > AMVP_RSA_EXP_LEN_MAX) {
                    AMVP_LOG_ERR("e too long, max allowed=(%d)",
                                AMVP_KAS_IFC_STR_MAX);
                    rv = AMVP_INVALID_ARG;
                    goto err;
                }
            }

            /**
             * Z values can get messy. iutZ and z are the same for KAS1 cases, but for KAS2,
             * z is serverZ || iutZ. Ideally, serverZ would be specified separately in these cases
             * for SSC since SSC should not really cover how the z values are combined in KAS2; handle 
             * concatenation ourselves in library for convenience. 
             */
            if (test_type == AMVP_KAS_IFC_TT_VAL) {
                if (scheme == AMVP_KAS_IFC_KAS1) {
                    if (role == AMVP_KAS_IFC_INITIATOR) {
                        pt_z = json_object_get_string(testobj, "iutZ");
                    } else {
                        pt_z = json_object_get_string(testobj, "z");
                    }
                } else {
                    pt_z = json_object_get_string(testobj, "iutZ");
                }
                if (!pt_z) {
                    AMVP_LOG_ERR("Server JSON missing 'z' or 'iutZ''");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }

                if (role == AMVP_KAS_IFC_INITIATOR  || scheme == AMVP_KAS_IFC_KAS2) {
                    ct_z = json_object_get_string(testobj, "iutC");
                    if (!ct_z) {
                        AMVP_LOG_ERR("Server JSON missing 'iutC'");
                        rv = AMVP_MISSING_ARG;
                        goto err;
                    }
                    if (strnlen_s(ct_z, AMVP_KAS_IFC_STR_MAX + 1) > AMVP_KAS_IFC_STR_MAX) {
                        AMVP_LOG_ERR("c too long, max allowed=(%d)",
                                      AMVP_KAS_IFC_STR_MAX);
                        rv = AMVP_INVALID_ARG;
                        goto err;
                    }
                }
            }

            if (scheme == AMVP_KAS_IFC_KAS2 && test_type == AMVP_KAS_IFC_TT_VAL) {
                if (hash) {
                    kas2_z = json_object_get_string(testobj, "hashZ");
                } else {
                    kas2_z = json_object_get_string(testobj, "z");
                }
                if (!kas2_z) {
                    AMVP_LOG_ERR("Server JSON missing 'z'");
                    rv = AMVP_MISSING_ARG;
                    goto err;
                }
            }

            AMVP_LOG_VERBOSE("           tcId: %d", tc_id);
            AMVP_LOG_VERBOSE("              p: %s", p);
            AMVP_LOG_VERBOSE("              q: %s", q);
            AMVP_LOG_VERBOSE("              n: %s", n);
            AMVP_LOG_VERBOSE("              d: %s", d);
            AMVP_LOG_VERBOSE("              e: %s", e);
            if (key_gen == AMVP_KAS_IFC_RSAKPG1_CRT || key_gen == AMVP_KAS_IFC_RSAKPG2_CRT) {
                AMVP_LOG_VERBOSE("           dmp1: %s", dmp1);
                AMVP_LOG_VERBOSE("           dmq1: %s", dmq1);
                AMVP_LOG_VERBOSE("           iqmp: %s", iqmp);
            }
            if (hash) {
                AMVP_LOG_VERBOSE("          hashZ: %s", pt_z);
            } else {
                AMVP_LOG_VERBOSE("              z: %s", pt_z);
            }
            AMVP_LOG_VERBOSE("              c: %s", ct_z);

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
            rv = amvp_kas_ifc_ssc_init_tc(ctx, stc, key_gen, hash_alg, scheme, role, pt_z, ct_z,
                                          server_ct_z, kas2_z, server_n, server_e, p, q, d, n,
                                          e, dmp1, dmq1, iqmp, modulo, test_type);
            if (rv != AMVP_SUCCESS) {
                amvp_kas_ifc_release_tc(stc);
                json_value_free(r_tval);
                goto err;
            }

            /* Process the current KAT test vector... */
            if ((cap->crypto_handler)(tc)) {
                amvp_kas_ifc_release_tc(stc);
                AMVP_LOG_ERR("crypto module failed the operation");
                rv = AMVP_CRYPTO_MODULE_FAIL;
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Output the test case results using JSON
             */
            if (stc->test_type == AMVP_KAS_IFC_TT_VAL) {
                rv = amvp_kas_ifc_ssc_val_output_tc(stc, r_tobj);
            } else {
                rv = amvp_kas_ifc_ssc_output_tc(ctx, stc, r_tobj);
            }
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("JSON output failure in KAS-IFC module");
                amvp_kas_ifc_release_tc(stc);
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Release all the memory associated with the test case
             */
            amvp_kas_ifc_release_tc(stc);

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

AMVP_RESULT amvp_kas_ifc_ssc_kat_handler(AMVP_CTX *ctx, JSON_Object *obj) {
    JSON_Value *r_vs_val = NULL;
    JSON_Object *r_vs = NULL;
    JSON_Array *r_garr = NULL; /* Response testarray */
    JSON_Value *reg_arry_val = NULL;
    JSON_Array *reg_arry = NULL;
    JSON_Object *reg_obj = NULL;
    AMVP_CAPS_LIST *cap;
    AMVP_TEST_CASE tc;
    AMVP_KAS_IFC_TC stc;
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
    tc.tc.kas_ifc = &stc;
    memzero_s(&stc, sizeof(AMVP_KAS_IFC_TC));

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
    cap = amvp_locate_cap_entry(ctx, AMVP_KAS_IFC_SSC);
    if (!cap) {
        AMVP_LOG_ERR("AMVP server requesting unsupported capability");
        rv = AMVP_UNSUPPORTED_OP;
        goto err;
    }
    rv = amvp_kas_ifc_ssc(ctx, cap, &tc, &stc, obj, r_garr);
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
        amvp_kas_ifc_release_tc(&stc);
        json_value_free(r_vs_val);
    }
    return rv;
}
