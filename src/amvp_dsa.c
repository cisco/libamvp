/** @file */
/*
 * Copyright (c) 2020, Cisco Systems, Inc.
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

static AMVP_RESULT amvp_dsa_keygen_init_tc(AMVP_DSA_TC *stc,
                                           int tg_id,
                                           unsigned int tc_id,
                                           int l,
                                           int n) {
    stc->l = l;
    stc->n = n;
    stc->tc_id = tc_id;
    stc->tg_id = tg_id;

    if (stc->l == 0) {
        return AMVP_INVALID_ARG;
    }
    if (stc->n == 0) {
        return AMVP_INVALID_ARG;
    }

    stc->p = calloc(1, AMVP_DSA_MAX_STRING);
    if (!stc->p) { return AMVP_MALLOC_FAIL; }
    stc->q = calloc(1, AMVP_DSA_MAX_STRING);
    if (!stc->q) { return AMVP_MALLOC_FAIL; }
    stc->g = calloc(1, AMVP_DSA_MAX_STRING);
    if (!stc->g) { return AMVP_MALLOC_FAIL; }
    stc->x = calloc(1, AMVP_DSA_MAX_STRING);
    if (!stc->x) { return AMVP_MALLOC_FAIL; }
    stc->y = calloc(1, AMVP_DSA_MAX_STRING);
    if (!stc->y) { return AMVP_MALLOC_FAIL; }

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_dsa_siggen_init_tc(AMVP_CTX *ctx,
                                           AMVP_DSA_TC *stc,
                                           int tg_id,
                                           unsigned int tc_id,
                                           int l,
                                           int n,
                                           AMVP_HASH_ALG sha,
                                           const char *msg) {
    AMVP_RESULT rv;

    stc->tg_id = tg_id;
    stc->tc_id = tc_id;

    stc->l = l;
    stc->n = n;
    stc->sha = sha;

    stc->p = calloc(1, AMVP_DSA_MAX_STRING);
    if (!stc->p) { return AMVP_MALLOC_FAIL; }
    stc->q = calloc(1, AMVP_DSA_MAX_STRING);
    if (!stc->q) { return AMVP_MALLOC_FAIL; }
    stc->g = calloc(1, AMVP_DSA_MAX_STRING);
    if (!stc->g) { return AMVP_MALLOC_FAIL; }
    stc->r = calloc(1, AMVP_DSA_MAX_STRING);
    if (!stc->r) { return AMVP_MALLOC_FAIL; }
    stc->s = calloc(1, AMVP_DSA_MAX_STRING);
    if (!stc->s) { return AMVP_MALLOC_FAIL; }
    stc->y = calloc(1, AMVP_DSA_MAX_STRING);
    if (!stc->y) { return AMVP_MALLOC_FAIL; }

    if (stc->l == 0) {
        return AMVP_INVALID_ARG;
    }
    if (stc->n == 0) {
        return AMVP_INVALID_ARG;
    }

    stc->msg = calloc(1, AMVP_DSA_PQG_MAX);
    if (!stc->msg) { return AMVP_MALLOC_FAIL; }

    rv = amvp_hexstr_to_bin(msg, stc->msg, AMVP_DSA_PQG_MAX, &(stc->msglen));
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (msg)");
        return rv;
    }
    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_dsa_sigver_init_tc(AMVP_CTX *ctx,
                                           AMVP_DSA_TC *stc,
                                           int l,
                                           int n,
                                           AMVP_HASH_ALG sha,
                                           const char *p,
                                           const char *q,
                                           const char *g,
                                           const char *r,
                                           const char *s,
                                           const char *y,
                                           const char *msg) {
    AMVP_RESULT rv;

    stc->l = l;
    stc->n = n;
    stc->sha = sha;

    if (stc->l == 0) {
        return AMVP_INVALID_ARG;
    }
    if (stc->n == 0) {
        return AMVP_INVALID_ARG;
    }

    stc->msg = calloc(1, AMVP_DSA_MAX_STRING);
    if (!stc->msg) { return AMVP_MALLOC_FAIL; }

    stc->p = calloc(1, AMVP_DSA_MAX_STRING);
    if (!stc->p) { return AMVP_MALLOC_FAIL; }
    stc->q = calloc(1, AMVP_DSA_MAX_STRING);
    if (!stc->q) { return AMVP_MALLOC_FAIL; }
    stc->g = calloc(1, AMVP_DSA_MAX_STRING);
    if (!stc->g) { return AMVP_MALLOC_FAIL; }
    stc->r = calloc(1, AMVP_DSA_MAX_STRING);
    if (!stc->r) { return AMVP_MALLOC_FAIL; }
    stc->s = calloc(1, AMVP_DSA_MAX_STRING);
    if (!stc->s) { return AMVP_MALLOC_FAIL; }
    stc->y = calloc(1, AMVP_DSA_MAX_STRING);
    if (!stc->y) { return AMVP_MALLOC_FAIL; }

    rv = amvp_hexstr_to_bin(msg, stc->msg, AMVP_DSA_MAX_STRING, &(stc->msglen));
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (msg)");
        return rv;
    }
    rv = amvp_hexstr_to_bin(p, stc->p, AMVP_DSA_MAX_STRING, &(stc->p_len));
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (p)");
        return rv;
    }
    rv = amvp_hexstr_to_bin(q, stc->q, AMVP_DSA_MAX_STRING, &(stc->q_len));
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (q)");
        return rv;
    }
    rv = amvp_hexstr_to_bin(g, stc->g, AMVP_DSA_MAX_STRING, &(stc->g_len));
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (g)");
        return rv;
    }
    rv = amvp_hexstr_to_bin(r, stc->r, AMVP_DSA_MAX_STRING, &(stc->r_len));
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (r)");
        return rv;
    }
    rv = amvp_hexstr_to_bin(s, stc->s, AMVP_DSA_MAX_STRING, &(stc->s_len));
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (s)");
        return rv;
    }
    rv = amvp_hexstr_to_bin(y, stc->y, AMVP_DSA_MAX_STRING, &(stc->y_len));
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (y)");
        return rv;
    }

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_dsa_pqgver_init_tc(AMVP_CTX *ctx,
                                           AMVP_DSA_TC *stc,
                                           int l,
                                           int n,
                                           int c,
                                           const char *idx,
                                           AMVP_HASH_ALG sha,
                                           const char *p,
                                           const char *q,
                                           const char *g,
                                           const char *h,
                                           const char *seed,
                                           unsigned int pqg) {
    AMVP_RESULT rv;

    stc->l = l;
    stc->n = n;
    stc->c = c;
    stc->pqg = pqg;
    stc->sha = sha;

    if (stc->l == 0) {
        return AMVP_INVALID_ARG;
    }
    if (stc->n == 0) {
        return AMVP_INVALID_ARG;
    }

    stc->seed = calloc(1, AMVP_DSA_MAX_STRING);
    if (!stc->seed) { return AMVP_MALLOC_FAIL; }

    stc->p = calloc(1, AMVP_DSA_MAX_STRING);
    if (!stc->p) { return AMVP_MALLOC_FAIL; }
    stc->q = calloc(1, AMVP_DSA_MAX_STRING);
    if (!stc->q) { return AMVP_MALLOC_FAIL; }
    stc->g = calloc(1, AMVP_DSA_MAX_STRING);
    if (!stc->g) { return AMVP_MALLOC_FAIL; }

    stc->r = calloc(1, AMVP_DSA_MAX_STRING);
    if (!stc->r) { return AMVP_MALLOC_FAIL; }
    stc->s = calloc(1, AMVP_DSA_MAX_STRING);
    if (!stc->s) { return AMVP_MALLOC_FAIL; }
    stc->y = calloc(1, AMVP_DSA_MAX_STRING);
    if (!stc->y) { return AMVP_MALLOC_FAIL; }

    stc->index = -1;
    if (idx) {
        stc->index = strtol(idx, NULL, 16);
    }
    stc->h = -1;
    if (h) {
        stc->h = strtol(h, NULL, 16);
    }

    if (seed) {
        rv = amvp_hexstr_to_bin(seed, stc->seed, AMVP_DSA_MAX_STRING, &(stc->seedlen));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (seed)");
            return rv;
        }
    }

    rv = amvp_hexstr_to_bin(p, stc->p, AMVP_DSA_MAX_STRING, &(stc->p_len));
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (p)");
        return rv;
    }
    rv = amvp_hexstr_to_bin(q, stc->q, AMVP_DSA_MAX_STRING, &(stc->q_len));
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (q)");
        return rv;
    }

    if (g) {
        rv = amvp_hexstr_to_bin(g, stc->g, AMVP_DSA_MAX_STRING, &(stc->g_len));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (g)");
            return rv;
        }
    }
    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_dsa_pqggen_init_tc(AMVP_CTX *ctx,
                                           AMVP_DSA_TC *stc,
                                           unsigned int gpq,
                                           const char *idx,
                                           int l,
                                           int n,
                                           AMVP_HASH_ALG sha,
                                           const char *p,
                                           const char *q,
                                           const char *seed) {
    AMVP_RESULT rv;

    stc->l = l;
    stc->n = n;
    stc->sha = sha;

    if (stc->l == 0) {
        return AMVP_INVALID_ARG;
    }
    if (stc->n == 0) {
        return AMVP_INVALID_ARG;
    }

    stc->p = calloc(1, AMVP_DSA_PQG_MAX);
    if (!stc->p) { return AMVP_MALLOC_FAIL; }
    stc->q = calloc(1, AMVP_DSA_PQG_MAX);
    if (!stc->q) { return AMVP_MALLOC_FAIL; }
    stc->g = calloc(1, AMVP_DSA_PQG_MAX);
    if (!stc->g) { return AMVP_MALLOC_FAIL; }
    stc->seed = calloc(1, AMVP_DSA_SEED_MAX);
    if (!stc->seed) { return AMVP_MALLOC_FAIL; }

    stc->gen_pq = gpq;
    stc->pqg = gpq;

    switch (gpq) {
    case AMVP_DSA_CANONICAL:
        stc->index = -1;
        stc->index = strtol(idx, NULL, 16);
        rv = amvp_hexstr_to_bin(seed, stc->seed, AMVP_DSA_SEED_MAX, &(stc->seedlen));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (seed)");
            return rv;
        }
        rv = amvp_hexstr_to_bin(p, stc->p, AMVP_DSA_MAX_STRING, &(stc->p_len));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (p)");
            return rv;
        }
        rv = amvp_hexstr_to_bin(q, stc->q, AMVP_DSA_MAX_STRING, &(stc->q_len));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (q)");
            return rv;
        }
        break;
    case AMVP_DSA_UNVERIFIABLE:
        rv = amvp_hexstr_to_bin(p, stc->p, AMVP_DSA_MAX_STRING, &(stc->p_len));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (p)");
            return rv;
        }
        rv = amvp_hexstr_to_bin(q, stc->q, AMVP_DSA_MAX_STRING, &(stc->q_len));
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Hex conversion failure (q)");
            return rv;
        }
        break;
    case AMVP_DSA_PROBABLE:
    case AMVP_DSA_PROVABLE:
        break;
    default:
        AMVP_LOG_ERR("Invalid GPQ argument %d", gpq);
        return AMVP_INVALID_ARG;

        break;
    }
    return AMVP_SUCCESS;
}

/*
 * After the test case has been processed by the DUT, the results
 * need to be JSON formated to be included in the vector set results
 * file that will be uploaded to the server.  This routine handles
 * the JSON processing for a single test case.
 */
static AMVP_RESULT amvp_dsa_output_tc(AMVP_CTX *ctx, AMVP_DSA_TC *stc, JSON_Object *r_tobj) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    char *tmp = NULL;

    switch (stc->mode) {
    case AMVP_DSA_MODE_PQGGEN:
        switch (stc->gen_pq) {
        case AMVP_DSA_CANONICAL:
        case AMVP_DSA_UNVERIFIABLE:
            tmp = calloc(AMVP_DSA_PQG_MAX + 1, sizeof(char));
            if (!tmp) {
                AMVP_LOG_ERR("Unable to malloc in amvp_dsa_output_tc");
                return AMVP_MALLOC_FAIL;
            }
            rv = amvp_bin_to_hexstr(stc->g, stc->g_len, tmp, AMVP_DSA_PQG_MAX);
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("hex conversion failure (g)");
                goto err;
            }
            json_object_set_string(r_tobj, "g", (const char *)tmp);
            memzero_s(tmp, AMVP_DSA_PQG_MAX + 1);
            break;
        case AMVP_DSA_PROBABLE:
        case AMVP_DSA_PROVABLE:
            tmp = calloc(AMVP_DSA_PQG_MAX + 1, sizeof(char));
            if (!tmp) {
                AMVP_LOG_ERR("Unable to malloc in amvp_dsa_output_tc");
                return AMVP_MALLOC_FAIL;
            }
            rv = amvp_bin_to_hexstr(stc->p, stc->p_len, tmp, AMVP_DSA_PQG_MAX);
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("hex conversion failure (p)");
                goto err;
            }
            json_object_set_string(r_tobj, "p", (const char *)tmp);
            memzero_s(tmp, AMVP_DSA_PQG_MAX + 1);

            rv = amvp_bin_to_hexstr(stc->q, stc->q_len, tmp, AMVP_DSA_PQG_MAX);
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("hex conversion failure (q)");
                goto err;
            }
            json_object_set_string(r_tobj, "q", (const char *)tmp);

            memzero_s(tmp, AMVP_DSA_SEED_MAX);
            rv = amvp_bin_to_hexstr(stc->seed, stc->seedlen, tmp, AMVP_DSA_SEED_MAX);
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("hex conversion failure (p)");
                goto err;
            }
            json_object_set_string(r_tobj, "domainSeed", tmp);
            json_object_set_number(r_tobj, "counter", stc->counter);
            break;
        default:
            AMVP_LOG_ERR("Invalid mode argument %d", stc->mode);
            return AMVP_INVALID_ARG;

            break;
        }
        break;
    case AMVP_DSA_MODE_SIGGEN:
        tmp = calloc(AMVP_DSA_PQG_MAX + 1, sizeof(char));
        if (!tmp) {
            AMVP_LOG_ERR("Unable to malloc in amvp_dsa_output_tc");
            return AMVP_MALLOC_FAIL;
        }
        rv = amvp_bin_to_hexstr(stc->r, stc->r_len, tmp, AMVP_DSA_PQG_MAX);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("hex conversion failure (r)");
            goto err;
        }
        json_object_set_string(r_tobj, "r", (const char *)tmp);
        memzero_s(tmp, AMVP_DSA_PQG_MAX);

        rv = amvp_bin_to_hexstr(stc->s, stc->s_len, tmp, AMVP_DSA_PQG_MAX);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("hex conversion failure (s)");
            goto err;
        }
        json_object_set_string(r_tobj, "s", (const char *)tmp);
        memzero_s(tmp, AMVP_DSA_PQG_MAX);

        break;
    case AMVP_DSA_MODE_SIGVER:
        json_object_set_boolean(r_tobj, "testPassed", stc->result);
        break;
    case AMVP_DSA_MODE_KEYGEN:
        tmp = calloc(AMVP_DSA_PQG_MAX + 1, sizeof(char));
        if (!tmp) {
            AMVP_LOG_ERR("Unable to malloc in amvp_dsa_output_tc");
            return AMVP_MALLOC_FAIL;
        }

        rv = amvp_bin_to_hexstr(stc->y, stc->y_len, tmp, AMVP_DSA_PQG_MAX);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("hex conversion failure (y)");
            goto err;
        }
        json_object_set_string(r_tobj, "y", (const char *)tmp);
        memzero_s(tmp, AMVP_DSA_PQG_MAX);

        rv = amvp_bin_to_hexstr(stc->x, stc->x_len, tmp, AMVP_DSA_PQG_MAX);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("hex conversion failure (x)");
            goto err;
        }
        json_object_set_string(r_tobj, "x", (const char *)tmp);
        memzero_s(tmp, AMVP_DSA_PQG_MAX);

        break;
    case AMVP_DSA_MODE_PQGVER:
        json_object_set_boolean(r_tobj, "testPassed", stc->result);
        break;
    default:
        break;
    }

err:
    if (tmp) free(tmp);

    return rv;
}

/*
 * This function simply releases the data associated with
 * a test case.
 */
static AMVP_RESULT amvp_dsa_release_tc(AMVP_DSA_TC *stc) {
    if (stc->p) free(stc->p);
    if (stc->q) free(stc->q);
    if (stc->g) free(stc->g);
    if (stc->x) free(stc->x);
    if (stc->y) free(stc->y);
    if (stc->r) free(stc->r);
    if (stc->s) free(stc->s);
    if (stc->seed) free(stc->seed);
    if (stc->msg) free(stc->msg);

    memzero_s(stc, sizeof(AMVP_DSA_TC));

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_dsa_keygen_handler(AMVP_CTX *ctx,
                                    AMVP_TEST_CASE tc,
                                    AMVP_CAPS_LIST *cap,
                                    JSON_Array *r_tarr,
                                    JSON_Object *groupobj,
                                    int tg_id,
                                    JSON_Object *r_gobj) {
    JSON_Array *tests;
    JSON_Value *testval;
    JSON_Object *testobj = NULL;
    JSON_Value *r_tval = NULL; /* Response testval */
    int j, t_cnt, tc_id, l, n;
    AMVP_RESULT rv = AMVP_SUCCESS;
    JSON_Value *mval;
    JSON_Object *mobj = NULL;
    AMVP_DSA_TC *stc;

    l = json_object_get_number(groupobj, "l");
    if (!l) {
        AMVP_LOG_ERR("Failed to include l. ");
        return AMVP_MISSING_ARG;
    }

    n = json_object_get_number(groupobj, "n");
    if (!n) {
        AMVP_LOG_ERR("Failed to include n. ");
        return AMVP_MISSING_ARG;
    }

    AMVP_LOG_VERBOSE("             l: %d", l);
    AMVP_LOG_VERBOSE("             n: %d", n);

    tests = json_object_get_array(groupobj, "tests");
    if (!tests) {
        AMVP_LOG_ERR("Failed to include tests. ");
        return AMVP_MISSING_ARG;
    }

    t_cnt = json_array_get_count(tests);
    if (!t_cnt) {
        AMVP_LOG_ERR("Failed to include tests in array. ");
        return AMVP_MISSING_ARG;
    }

    stc = tc.tc.dsa;

    for (j = 0; j < t_cnt; j++) {
        AMVP_LOG_VERBOSE("Found new DSA KeyGen test vector...");
        stc->mode = AMVP_DSA_MODE_KEYGEN;

        testval = json_array_get_value(tests, j);
        testobj = json_value_get_object(testval);

        tc_id = json_object_get_number(testobj, "tcId");
        if (!tc_id) {
            AMVP_LOG_ERR("Failed to include tc_id. ");
            return AMVP_MISSING_ARG;
        }

        AMVP_LOG_VERBOSE("       Test case: %d", j);
        AMVP_LOG_VERBOSE("            tcId: %d", tc_id);

        /*
         * Setup the test case data that will be passed down to
         * the crypto module.
         */
        rv = amvp_dsa_keygen_init_tc(stc, tg_id, tc_id, l, n);
        if (rv != AMVP_SUCCESS) {
            goto err;
        }

        /* Process the current DSA test vector... */
        if ((cap->crypto_handler)(&tc)) {
            AMVP_LOG_ERR("crypto module failed the operation");
            rv = AMVP_CRYPTO_MODULE_FAIL;
            goto err;
        }

        mval = json_value_init_object();
        mobj = json_value_get_object(mval);
        json_object_set_number(mobj, "tcId", tc_id);

        /*
         * Set the values for the group (p,q,g)
         */
        char *tmp = calloc(AMVP_DSA_PQG_MAX + 1, sizeof(char));
        if (!tmp) {
            AMVP_LOG_ERR("Unable to malloc in amvp_dsa_output_tc");
            return AMVP_MALLOC_FAIL;
        }
        rv = amvp_bin_to_hexstr(stc->p, stc->p_len, tmp, AMVP_DSA_PQG_MAX);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("hex conversion failure (p)");
            free(tmp);
            goto err;
        }
        json_object_set_string(r_gobj, "p", (const char *)tmp);
        memzero_s(tmp, AMVP_DSA_PQG_MAX);

        rv = amvp_bin_to_hexstr(stc->q, stc->q_len, tmp, AMVP_DSA_PQG_MAX);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("hex conversion failure (q)");
            free(tmp);
            goto err;
        }
        json_object_set_string(r_gobj, "q", (const char *)tmp);
        memzero_s(tmp, AMVP_DSA_PQG_MAX);

        rv = amvp_bin_to_hexstr(stc->g, stc->g_len, tmp, AMVP_DSA_PQG_MAX);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("hex conversion failure (g)");
            free(tmp);
            goto err;
        }
        json_object_set_string(r_gobj, "g", (const char *)tmp);
        memzero_s(tmp, AMVP_DSA_PQG_MAX);
        free(tmp);

        /*
         * Output the test case results using JSON
         */
        rv = amvp_dsa_output_tc(ctx, stc, mobj);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("JSON output failure in DSA module");
            goto err;
        }

        /* Append the test response value to array */
        json_array_append_value(r_tarr, mval);
        amvp_dsa_release_tc(stc);
    }
    /* Append the test response value to array */
    json_array_append_value(r_tarr, r_tval);
    return AMVP_SUCCESS;

err:
    amvp_dsa_release_tc(stc);
    return rv;
}

static AMVP_DSA_GEN_PARM read_gen_g(const char *str) {
    int diff = 0;

    strcmp_s("canonical", 9, str, &diff);
    if (!diff) {
        return AMVP_DSA_CANONICAL;
    }

    strcmp_s("unverifiable", 12, str, &diff);
    if (!diff) {
        return AMVP_DSA_UNVERIFIABLE;
    }

    return 0;
}

static AMVP_DSA_GEN_PARM read_gen_pq(const char *str) {
    int diff = 0;

    strcmp_s("probable", 8, str, &diff);
    if (!diff) {
        return AMVP_DSA_PROBABLE;
    }

    strcmp_s("provable", 8, str, &diff);
    if (!diff) {
        return AMVP_DSA_PROVABLE;
    }

    return 0;
}

static 
AMVP_RESULT amvp_dsa_pqggen_handler(AMVP_CTX *ctx,
                                    AMVP_TEST_CASE tc,
                                    AMVP_CAPS_LIST *cap,
                                    JSON_Array *r_tarr,
                                    JSON_Object *groupobj) {
    const char *idx = NULL;
    JSON_Array *tests;
    JSON_Value *testval;
    JSON_Object *testobj = NULL;
    JSON_Value *r_tval = NULL;  /* Response testval */
    JSON_Object *r_tobj = NULL; /* Response testobj */
    int j, t_cnt, tc_id;
    AMVP_RESULT rv = AMVP_SUCCESS;
    unsigned gpq = 0, n, l;
    const char *p = NULL, *q = NULL, *seed = NULL;
    AMVP_DSA_TC *stc;
    AMVP_HASH_ALG sha = 0;
    const char *sha_str = NULL, *gen_g = NULL, *gen_pq = NULL;

    gen_pq = json_object_get_string(groupobj, "pqMode");
    gen_g = json_object_get_string(groupobj, "gMode");
    if (!gen_pq && !gen_g) {
        AMVP_LOG_ERR("Failed to include either gen_pq or gen_g. ");
        return AMVP_MISSING_ARG;
    }
    if (gen_pq && gen_g) {
        AMVP_LOG_ERR("Server included both gen_pq and gen_g. ");
        return AMVP_INVALID_ARG;
    }

    l = json_object_get_number(groupobj, "l");
    if (!l) {
        AMVP_LOG_ERR("Failed to include l. ");
        return AMVP_MISSING_ARG;
    }

    n = json_object_get_number(groupobj, "n");
    if (!n) {
        AMVP_LOG_ERR("Failed to include n. ");
        return AMVP_MISSING_ARG;
    }

    sha_str = json_object_get_string(groupobj, "hashAlg");
    if (!sha_str) {
        AMVP_LOG_ERR("Failed to include hashAlg. ");
        return AMVP_MISSING_ARG;
    }
    sha = amvp_lookup_hash_alg(sha_str);
    if (!sha) {
        AMVP_LOG_ERR("Server JSON invalid 'hashAlg'");
        return AMVP_INVALID_ARG;
    }

    if (gen_pq) {
        AMVP_LOG_VERBOSE("         genPQ: %s", gen_pq);
    }
    if (gen_g) {
        AMVP_LOG_VERBOSE("          genG: %s", gen_g);
    }
    AMVP_LOG_VERBOSE("             l: %d", l);
    AMVP_LOG_VERBOSE("             n: %d", n);
    AMVP_LOG_VERBOSE("           sha: %s", sha_str);

    tests = json_object_get_array(groupobj, "tests");
    if (!tests) {
        AMVP_LOG_ERR("Failed to include tests. ");
        return AMVP_MISSING_ARG;
    }

    t_cnt = json_array_get_count(tests);
    if (!t_cnt) {
        AMVP_LOG_ERR("Failed to include tests in array. ");
        return AMVP_MISSING_ARG;
    }

    stc = tc.tc.dsa;

    for (j = 0; j < t_cnt; j++) {
        AMVP_LOG_VERBOSE("Found new DSA PQGGen test vector...");
        stc->mode = AMVP_DSA_MODE_PQGGEN;

        testval = json_array_get_value(tests, j);
        testobj = json_value_get_object(testval);

        tc_id = json_object_get_number(testobj, "tcId");
        if (!tc_id) {
            AMVP_LOG_ERR("Failed to include tc_id. ");
            return AMVP_MISSING_ARG;
        }

        AMVP_LOG_VERBOSE("       Test case: %d", j);
        AMVP_LOG_VERBOSE("            tcId: %d", tc_id);
        if (gen_g) {
            gpq = read_gen_g(gen_g);

            if (!gpq) {
                AMVP_LOG_ERR("Server JSON invalid 'genG'");
                return AMVP_INVALID_ARG;
            }

            if (gpq == AMVP_DSA_CANONICAL) {
                seed = json_object_get_string(testobj, "domainSeed");
                if (!seed) {
                    AMVP_LOG_ERR("Failed to include domainSeed. ");
                    return AMVP_MISSING_ARG;
                }

                idx = json_object_get_string(testobj, "index");
                if (!idx) {
                    AMVP_LOG_ERR("Failed to include idx. ");
                    return AMVP_MISSING_ARG;
                }

                gpq = AMVP_DSA_CANONICAL;

                AMVP_LOG_VERBOSE("            seed: %s", seed);
                AMVP_LOG_VERBOSE("           idx: %s", idx);
            }

            p = json_object_get_string(testobj, "p");
            if (!p) {
                AMVP_LOG_ERR("Failed to include p. ");
                return AMVP_MISSING_ARG;
            }

            q = json_object_get_string(testobj, "q");
            if (!q) {
                AMVP_LOG_ERR("Failed to include q. ");
                return AMVP_MISSING_ARG;
            }

            AMVP_LOG_VERBOSE("               p: %s", p);
            AMVP_LOG_VERBOSE("               q: %s", q);

        } else if (gen_pq) {
            gpq = read_gen_pq(gen_pq);
            if (!gpq) {
                AMVP_LOG_ERR("Server JSON invalid 'genPQ'");
                return AMVP_INVALID_ARG;
            }
        }

        /*
         * Setup the test case data that will be passed down to
         * the crypto module.
         */

        switch (gpq) {
        case AMVP_DSA_PROBABLE:
        case AMVP_DSA_PROVABLE:
            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);
            json_object_set_number(r_tobj, "tcId", tc_id);

            rv = amvp_dsa_pqggen_init_tc(ctx, stc, gpq, idx, l, n, sha, p, q, seed);
            if (rv != AMVP_SUCCESS) {
                amvp_dsa_release_tc(stc);
                json_value_free(r_tval);
                return rv;
            }

            /* Process the current DSA test vector... */
            if ((cap->crypto_handler)(&tc)) {
                AMVP_LOG_ERR("crypto module failed the operation");
                amvp_dsa_release_tc(stc);
                json_value_free(r_tval);
                return AMVP_CRYPTO_MODULE_FAIL;
            }

            /*
             * Output the test case results using JSON
             */
            rv = amvp_dsa_output_tc(ctx, stc, r_tobj);
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("JSON output failure in DSA module");
                json_value_free(r_tval);
                amvp_dsa_release_tc(stc);
                return rv;
            }

            stc->seedlen = 0;
            stc->counter = 0;
            if (stc->seed) free(stc->seed);
            stc->seed = 0;
            break;

        case AMVP_DSA_CANONICAL:
        case AMVP_DSA_UNVERIFIABLE:
            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);
            json_object_set_number(r_tobj, "tcId", tc_id);

            /* Process the current DSA test vector... */
            rv = amvp_dsa_pqggen_init_tc(ctx, stc, gpq, idx, l, n, sha, p, q, seed);
            if (rv != AMVP_SUCCESS) {
                amvp_dsa_release_tc(stc);
                json_value_free(r_tval);
                return rv;
            }

            if ((cap->crypto_handler)(&tc)) {
                AMVP_LOG_ERR("crypto module failed the operation");
                amvp_dsa_release_tc(stc);
                json_value_free(r_tval);
                return AMVP_CRYPTO_MODULE_FAIL;
            }

            /*
             * Output the test case results using JSON
             */
            rv = amvp_dsa_output_tc(ctx, stc, r_tobj);
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("JSON output failure in DSA module");
                amvp_dsa_release_tc(stc);
                json_value_free(r_tval);
                return rv;
            }
            break;
        default:
            AMVP_LOG_ERR("Invalid DSA PQGGen mode");
            json_value_free(r_tval);
            rv = AMVP_INVALID_ARG;
            break;
        }
        json_array_append_value(r_tarr, r_tval);
        amvp_dsa_release_tc(stc);
    }
    return rv;
}

static AMVP_RESULT amvp_dsa_siggen_handler(AMVP_CTX *ctx,
                                    AMVP_TEST_CASE tc,
                                    AMVP_CAPS_LIST *cap,
                                    JSON_Array *r_tarr,
                                    JSON_Object *groupobj,
                                    int tg_id,
                                    JSON_Object *r_gobj) {
    const char *msg = NULL;
    JSON_Array *tests;
    JSON_Value *testval;
    JSON_Object *testobj = NULL;
    JSON_Value *r_tval = NULL; /* Response testval */
    int j, t_cnt, tc_id, l, n;
    AMVP_RESULT rv = AMVP_SUCCESS;
    JSON_Value *mval;
    JSON_Object *mobj = NULL;
    AMVP_DSA_TC *stc;
    AMVP_HASH_ALG sha = 0;
    const char *sha_str = NULL;

    l = json_object_get_number(groupobj, "l");
    if (!l) {
        AMVP_LOG_ERR("Failed to include l. ");
        return AMVP_MISSING_ARG;
    }

    n = json_object_get_number(groupobj, "n");
    if (!n) {
        AMVP_LOG_ERR("Failed to include n. ");
        return AMVP_MISSING_ARG;
    }

    sha_str = json_object_get_string(groupobj, "hashAlg");
    if (!sha_str) {
        AMVP_LOG_ERR("Failed to include hashAlg. ");
        return AMVP_MISSING_ARG;
    }
    sha = amvp_lookup_hash_alg(sha_str);
    if (!sha) {
        AMVP_LOG_ERR("Server JSON invalid 'hashAlg'");
        return AMVP_INVALID_ARG;
    }

    AMVP_LOG_VERBOSE("             l: %d", l);
    AMVP_LOG_VERBOSE("             n: %d", n);
    AMVP_LOG_VERBOSE("           sha: %s", sha_str);

    tests = json_object_get_array(groupobj, "tests");
    if (!tests) {
        AMVP_LOG_ERR("Failed to include tests. ");
        return AMVP_MISSING_ARG;
    }

    t_cnt = json_array_get_count(tests);
    if (!t_cnt) {
        AMVP_LOG_ERR("Failed to include tests in array. ");
        return AMVP_MISSING_ARG;
    }

    stc = tc.tc.dsa;

    for (j = 0; j < t_cnt; j++) {
        AMVP_LOG_VERBOSE("Found new DSA SigGen test vector...");
        stc->mode = AMVP_DSA_MODE_SIGGEN;

        testval = json_array_get_value(tests, j);
        testobj = json_value_get_object(testval);

        tc_id = json_object_get_number(testobj, "tcId");
        if (!tc_id) {
            AMVP_LOG_ERR("Failed to include tc_id. ");
            return AMVP_MISSING_ARG;
        }

        msg = json_object_get_string(testobj, "message");
        if (!msg) {
            AMVP_LOG_ERR("Failed to include message. ");
            return AMVP_MISSING_ARG;
        }

        AMVP_LOG_VERBOSE("       Test case: %d", j);
        AMVP_LOG_VERBOSE("            tcId: %d", tc_id);
        AMVP_LOG_VERBOSE("             msg: %s", msg);

        /*
         * Setup the test case data that will be passed down to
         * the crypto module.
         */
        rv = amvp_dsa_siggen_init_tc(ctx, stc, tg_id, tc_id, l, n, sha, msg);
        if (rv != AMVP_SUCCESS) {
            goto err;
        }

        /* Process the current DSA test vector... */
        if ((cap->crypto_handler)(&tc)) {
            AMVP_LOG_ERR("crypto module failed the operation");
            rv = AMVP_CRYPTO_MODULE_FAIL;
            goto err;
        }

        mval = json_value_init_object();
        mobj = json_value_get_object(mval);
        json_object_set_number(mobj, "tcId", tc_id);

        /*
         * Set the p,q,g,y values in the group obj
         */
        char *tmp = calloc(AMVP_DSA_PQG_MAX + 1, sizeof(char));
        if (!tmp) {
            AMVP_LOG_ERR("Unable to malloc in amvp_dsa_siggen_handler");
            return AMVP_MALLOC_FAIL;
        }

        rv = amvp_bin_to_hexstr(stc->p, stc->p_len, tmp, AMVP_DSA_PQG_MAX);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("hex conversion failure (p)");
            free(tmp);
            goto err;
        }
        json_object_set_string(r_gobj, "p", (const char *)tmp);
        memzero_s(tmp, AMVP_DSA_PQG_MAX);

        rv = amvp_bin_to_hexstr(stc->q, stc->q_len, tmp, AMVP_DSA_PQG_MAX);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("hex conversion failure (q)");
            free(tmp);
            goto err;
        }
        json_object_set_string(r_gobj, "q", (const char *)tmp);
        memzero_s(tmp, AMVP_DSA_PQG_MAX);

        rv = amvp_bin_to_hexstr(stc->g, stc->g_len, tmp, AMVP_DSA_PQG_MAX);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("hex conversion failure (g)");
            free(tmp);
            goto err;
        }
        json_object_set_string(r_gobj, "g", (const char *)tmp);
        memzero_s(tmp, AMVP_DSA_PQG_MAX);

        rv = amvp_bin_to_hexstr(stc->y, stc->y_len, tmp, AMVP_DSA_PQG_MAX);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("hex conversion failure (y)");
            free(tmp);
            goto err;
        }
        json_object_set_string(r_gobj, "y", (const char *)tmp);
        memzero_s(tmp, AMVP_DSA_PQG_MAX);
        free(tmp);

        /*
         * Output the test case results using JSON
         */
        rv = amvp_dsa_output_tc(ctx, stc, mobj);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("JSON output failure in DSA module");
            goto err;
        }
        amvp_dsa_release_tc(stc);
        /* Append the test response value to array */
        json_array_append_value(r_tarr, mval);
    }
    /* Append the test response value to array */
    json_array_append_value(r_tarr, r_tval);
    return AMVP_SUCCESS;

err:
    amvp_dsa_release_tc(stc);
    return rv;
}

static AMVP_RESULT amvp_dsa_pqgver_handler(AMVP_CTX *ctx,
                                    AMVP_TEST_CASE tc,
                                    AMVP_CAPS_LIST *cap,
                                    JSON_Array *r_tarr,
                                    JSON_Object *groupobj) {
    const char *idx = NULL;
    const char *g = NULL, *pqmode = NULL, *gmode = NULL, *seed = NULL;
    JSON_Array *tests;
    JSON_Value *testval;
    JSON_Object *testobj = NULL;
    JSON_Value *r_tval = NULL; /* Response testval */
    int j, t_cnt, tc_id, l, n, c, gpq = 0;
    AMVP_RESULT rv = AMVP_SUCCESS;
    JSON_Value *mval;
    JSON_Object *mobj = NULL;
    const char *p = NULL, *q = NULL, *h = NULL;
    AMVP_DSA_TC *stc;
    AMVP_HASH_ALG sha = 0;
    const char *sha_str = NULL;

    l = json_object_get_number(groupobj, "l");
    if (!l) {
        AMVP_LOG_ERR("Failed to include l. ");
        return AMVP_MISSING_ARG;
    }

    n = json_object_get_number(groupobj, "n");
    if (!n) {
        AMVP_LOG_ERR("Failed to include n. ");
        return AMVP_MISSING_ARG;
    }

    sha_str = json_object_get_string(groupobj, "hashAlg");
    if (!sha_str) {
        AMVP_LOG_ERR("Failed to include hashAlg. ");
        return AMVP_MISSING_ARG;
    }
    sha = amvp_lookup_hash_alg(sha_str);
    if (!sha) {
        AMVP_LOG_ERR("Server JSON invalid 'hashAlg'");
        return AMVP_INVALID_ARG;
    }

    gmode = json_object_get_string(groupobj, "gMode");
    pqmode = json_object_get_string(groupobj, "pqMode");
    if (!pqmode && !gmode) {
        AMVP_LOG_ERR("Failed to include either pqMode or gMode.");
        return AMVP_MISSING_ARG;
    }
    if (pqmode && gmode) {
        AMVP_LOG_ERR("Server included both pqMode and gMode.");
        return AMVP_INVALID_ARG;
    }

    AMVP_LOG_VERBOSE("             l: %d", l);
    AMVP_LOG_VERBOSE("             n: %d", n);
    AMVP_LOG_VERBOSE("           sha: %s", sha_str);
    AMVP_LOG_VERBOSE("         gmode: %s", gmode);
    AMVP_LOG_VERBOSE("        pqmode: %s", pqmode);

    tests = json_object_get_array(groupobj, "tests");
    if (!tests) {
        AMVP_LOG_ERR("Failed to include tests. ");
        return AMVP_MISSING_ARG;
    }

    t_cnt = json_array_get_count(tests);
    if (!t_cnt) {
        AMVP_LOG_ERR("Failed to include tests in array. ");
        return AMVP_MISSING_ARG;
    }

    stc = tc.tc.dsa;

    for (j = 0; j < t_cnt; j++) {
        AMVP_LOG_VERBOSE("Found new DSA PQGVer test vector...");
        stc->mode = AMVP_DSA_MODE_PQGVER;

        testval = json_array_get_value(tests, j);
        testobj = json_value_get_object(testval);

        tc_id = json_object_get_number(testobj, "tcId");
        if (!tc_id) {
            AMVP_LOG_ERR("Failed to include tc_id. ");
            return AMVP_MISSING_ARG;
        }

        seed = json_object_get_string(testobj, "domainSeed");
        c = json_object_get_number(testobj, "counter");
        idx = json_object_get_string(testobj, "index");

        p = json_object_get_string(testobj, "p");
        if (!p) {
            AMVP_LOG_ERR("Failed to include p. ");
            return AMVP_MISSING_ARG;
        }

        q = json_object_get_string(testobj, "q");
        if (!q) {
            AMVP_LOG_ERR("Failed to include q. ");
            return AMVP_MISSING_ARG;
        }

        g = json_object_get_string(testobj, "g");
        h = json_object_get_string(testobj, "h");

        AMVP_LOG_VERBOSE("       Test case: %d", j);
        AMVP_LOG_VERBOSE("            tcId: %d", tc_id);
        AMVP_LOG_VERBOSE("            seed: %s", seed);
        AMVP_LOG_VERBOSE("               p: %s", p);
        AMVP_LOG_VERBOSE("               q: %s", q);
        AMVP_LOG_VERBOSE("               g: %s", g);
        AMVP_LOG_VERBOSE("          pqMode: %s", pqmode);
        AMVP_LOG_VERBOSE("           gMode: %s", gmode);
        AMVP_LOG_VERBOSE("               c: %d", c);
        AMVP_LOG_VERBOSE("           idx: %s", idx);

        /* find the mode */
        if (gmode) {
            gpq = read_gen_g(gmode);
        } else if (pqmode) {
            gpq = read_gen_pq(pqmode);
        }

        switch (gpq) {
        case AMVP_DSA_PROVABLE:
            AMVP_LOG_ERR("libamvp does not fully support \"provable\" method for pqgVer at this time");
            return AMVP_UNSUPPORTED_OP;
        case AMVP_DSA_PROBABLE:
            if (!seed) {
                AMVP_LOG_ERR("Failed to include seed. ");
                return AMVP_MISSING_ARG;
            }
            break;
        case AMVP_DSA_CANONICAL:
            if (!idx) {
                AMVP_LOG_ERR("Failed to include idx. ");
                return AMVP_MISSING_ARG;
            }
            if (!g) {
                AMVP_LOG_ERR("Failed to include q. ");
                return AMVP_MISSING_ARG;
            }
            break;
        case AMVP_DSA_UNVERIFIABLE:
            if (!seed) {
                AMVP_LOG_ERR("Failed to include seed. ");
                return AMVP_MISSING_ARG;
            }
            if (!h) {
                AMVP_LOG_ERR("Failed to include h. ");
                return AMVP_MISSING_ARG;
            }
            break;
        default:
            AMVP_LOG_ERR("Failed to include valid gen_pq. ");
            return AMVP_UNSUPPORTED_OP;
        }

        /*
         * Setup the test case data that will be passed down to
         * the crypto module.
         */
        rv = amvp_dsa_pqgver_init_tc(ctx, stc, l, n, c, idx, sha, p, q, g, h, seed, gpq);
        if (rv != AMVP_SUCCESS) {
            amvp_dsa_release_tc(stc);
            return rv;
        }

        /* Process the current DSA test vector... */
        if ((cap->crypto_handler)(&tc)) {
            AMVP_LOG_ERR("crypto module failed the operation");
            amvp_dsa_release_tc(stc);
            return AMVP_CRYPTO_MODULE_FAIL;
        }

        mval = json_value_init_object();
        mobj = json_value_get_object(mval);
        json_object_set_number(mobj, "tcId", tc_id);
        /*
         * Output the test case results using JSON
         */
        rv = amvp_dsa_output_tc(ctx, stc, mobj);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("JSON output failure in DSA module");
            amvp_dsa_release_tc(stc);
            return rv;
        }
        amvp_dsa_release_tc(stc);

        /* Append the test response value to array */
        json_array_append_value(r_tarr, mval);
    }
    /* Append the test response value to array */
    json_array_append_value(r_tarr, r_tval);
    return rv;
}

static AMVP_RESULT amvp_dsa_sigver_handler(AMVP_CTX *ctx,
                                    AMVP_TEST_CASE tc,
                                    AMVP_CAPS_LIST *cap,
                                    JSON_Array *r_tarr,
                                    JSON_Object *groupobj) {
    const char *msg = NULL, *r = NULL, *s = NULL, *y = NULL, *g = NULL;
    JSON_Array *tests;
    JSON_Value *testval;
    JSON_Object *testobj = NULL;
    JSON_Value *r_tval = NULL; /* Response testval */
    int j, t_cnt, tc_id, l, n;
    AMVP_RESULT rv = AMVP_SUCCESS;
    JSON_Value *mval;
    JSON_Object *mobj = NULL;
    const char *p = NULL, *q = NULL;
    AMVP_DSA_TC *stc;
    AMVP_HASH_ALG sha = 0;
    const char *sha_str = NULL;

    l = json_object_get_number(groupobj, "l");
    if (!l) {
        AMVP_LOG_ERR("Failed to include l. ");
        return AMVP_MISSING_ARG;
    }

    n = json_object_get_number(groupobj, "n");
    if (!n) {
        AMVP_LOG_ERR("Failed to include n. ");
        return AMVP_MISSING_ARG;
    }

    sha_str = json_object_get_string(groupobj, "hashAlg");
    if (!sha_str) {
        AMVP_LOG_ERR("Failed to include hashAlg. ");
        return AMVP_MISSING_ARG;
    }
    sha = amvp_lookup_hash_alg(sha_str);
    if (!sha) {
        AMVP_LOG_ERR("Server JSON invalid 'hashAlg'");
        return AMVP_INVALID_ARG;
    }

    AMVP_LOG_VERBOSE("             l: %d", l);
    AMVP_LOG_VERBOSE("             n: %d", n);
    AMVP_LOG_VERBOSE("           sha: %s", sha_str);

    tests = json_object_get_array(groupobj, "tests");
    if (!tests) {
        AMVP_LOG_ERR("Failed to include tests. ");
        return AMVP_MISSING_ARG;
    }

    t_cnt = json_array_get_count(tests);
    if (!t_cnt) {
        AMVP_LOG_ERR("Failed to include tests in array. ");
        return AMVP_MISSING_ARG;
    }

    stc = tc.tc.dsa;

    p = json_object_get_string(groupobj, "p");
    if (!p) {
        AMVP_LOG_ERR("Failed to include p. ");
        return AMVP_MISSING_ARG;
    }

    q = json_object_get_string(groupobj, "q");
    if (!q) {
        AMVP_LOG_ERR("Failed to include q. ");
        return AMVP_MISSING_ARG;
    }

    g = json_object_get_string(groupobj, "g");
    if (!g) {
        AMVP_LOG_ERR("Failed to include g. ");
        return AMVP_MISSING_ARG;
    }

    for (j = 0; j < t_cnt; j++) {
        AMVP_LOG_VERBOSE("Found new DSA SigVer test vector...");
        stc->mode = AMVP_DSA_MODE_SIGVER;

        testval = json_array_get_value(tests, j);
        testobj = json_value_get_object(testval);

        tc_id = json_object_get_number(testobj, "tcId");
        if (!tc_id) {
            AMVP_LOG_ERR("Failed to include tc_id. ");
            return AMVP_MISSING_ARG;
        }

        msg = json_object_get_string(testobj, "message");
        if (!msg) {
            AMVP_LOG_ERR("Failed to include message. ");
            return AMVP_MISSING_ARG;
        }
        r = json_object_get_string(testobj, "r");
        if (!r) {
            AMVP_LOG_ERR("Failed to include r. ");
            return AMVP_MISSING_ARG;
        }
        s = json_object_get_string(testobj, "s");
        if (!s) {
            AMVP_LOG_ERR("Failed to include s. ");
            return AMVP_MISSING_ARG;
        }
        y = json_object_get_string(testobj, "y");
        if (!y) {
            AMVP_LOG_ERR("Failed to include y. ");
            return AMVP_MISSING_ARG;
        }

        AMVP_LOG_VERBOSE("       Test case: %d", j);
        AMVP_LOG_VERBOSE("            tcId: %d", tc_id);
        AMVP_LOG_VERBOSE("             msg: %s", msg);
        AMVP_LOG_VERBOSE("               p: %s", p);
        AMVP_LOG_VERBOSE("               q: %s", q);
        AMVP_LOG_VERBOSE("               g: %s", g);
        AMVP_LOG_VERBOSE("               r: %s", r);
        AMVP_LOG_VERBOSE("               s: %s", s);
        AMVP_LOG_VERBOSE("               y: %s", y);

        /*
         * Setup the test case data that will be passed down to
         * the crypto module.
         */
        rv = amvp_dsa_sigver_init_tc(ctx, stc, l, n, sha, p, q, g, r, s, y, msg);
        if (rv != AMVP_SUCCESS) {
            amvp_dsa_release_tc(stc);
            return rv;
        }

        /* Process the current DSA test vector... */
        if ((cap->crypto_handler)(&tc)) {
            AMVP_LOG_ERR("crypto module failed the operation");
            amvp_dsa_release_tc(stc);
            return AMVP_CRYPTO_MODULE_FAIL;
        }

        mval = json_value_init_object();
        mobj = json_value_get_object(mval);
        json_object_set_number(mobj, "tcId", tc_id);
        /*
         * Output the test case results using JSON
         */
        rv = amvp_dsa_output_tc(ctx, stc, mobj);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("JSON output failure in DSA module");
            amvp_dsa_release_tc(stc);
            return rv;
        }
        amvp_dsa_release_tc(stc);

        /* Append the test response value to array */
        json_array_append_value(r_tarr, mval);
    }
    /* Append the test response value to array */
    json_array_append_value(r_tarr, r_tval);
    return rv;
}

static AMVP_RESULT amvp_dsa_pqgver_kat_handler(AMVP_CTX *ctx, JSON_Object *obj) {
    JSON_Value *groupval;
    JSON_Object *groupobj = NULL;
    JSON_Value *r_vs_val = NULL;
    JSON_Object *r_vs = NULL;
    JSON_Array *r_tarr = NULL; /* Response testarray */
    JSON_Value *reg_arry_val = NULL, *r_gval = NULL;
    JSON_Array *reg_arry = NULL, *r_garr = NULL;
    JSON_Object *reg_obj = NULL, *r_gobj = NULL;
    JSON_Array *groups;
    AMVP_CAPS_LIST *cap;
    AMVP_DSA_TC stc;
    AMVP_TEST_CASE tc;
    AMVP_RESULT rv;
    const char *alg_str = json_object_get_string(obj, "algorithm");
    AMVP_CIPHER alg_id;
    char *json_result;
    unsigned int g_cnt, i;

    if (!alg_str) {
        AMVP_LOG_ERR("unable to parse 'algorithm' from JSON");
        return AMVP_MALFORMED_JSON;
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.dsa = &stc;
    memzero_s(&stc, sizeof(AMVP_DSA_TC));

    /*
     * Get the crypto module handler for DSA mode
     */
    alg_id = AMVP_DSA_PQGVER;
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
    if (!groups) {
        AMVP_LOG_ERR("Failed to include testGroups. ");
        rv = AMVP_MISSING_ARG;
        goto err;
    }

    g_cnt = json_array_get_count(groups);

    stc.cipher = alg_id;
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

        stc.mode = AMVP_DSA_MODE_PQGVER;

        AMVP_LOG_VERBOSE("    Test group: %d", i);

        rv = amvp_dsa_pqgver_handler(ctx, tc, cap, r_tarr, groupobj);
        if (rv != AMVP_SUCCESS) {
            goto err;
        }
        json_array_append_value(r_garr, r_gval);
        amvp_dsa_release_tc(&stc);
    }
    memzero_s(&stc, sizeof(AMVP_DSA_TC));
    json_array_append_value(reg_arry, r_vs_val);
    json_result = json_serialize_to_string_pretty(ctx->kat_resp, NULL);
    if (!json_result) {
        AMVP_LOG_ERR("JSON unable to be serialized");
        rv = AMVP_JSON_ERR;
        goto err;
    }

    AMVP_LOG_VERBOSE("\n\n%s\n\n", json_result);

    json_free_serialized_string(json_result);
    rv = AMVP_SUCCESS;

err:
    if (rv != AMVP_SUCCESS) {
        amvp_dsa_release_tc(&stc);
        amvp_release_json(r_vs_val, r_gval);
    }
    return rv;
}

static AMVP_RESULT amvp_dsa_pqggen_kat_handler(AMVP_CTX *ctx, JSON_Object *obj) {
    JSON_Value *groupval;
    JSON_Object *groupobj = NULL;
    JSON_Value *r_vs_val = NULL;
    JSON_Object *r_vs = NULL;
    JSON_Array *r_tarr = NULL, *r_garr = NULL; /* Response testarray, grouparray */
    JSON_Value *reg_arry_val = NULL, *r_gval = NULL;
    JSON_Array *reg_arry = NULL;
    JSON_Object *reg_obj = NULL, *r_gobj = NULL;
    JSON_Array *groups;
    AMVP_CAPS_LIST *cap;
    AMVP_DSA_TC stc;
    AMVP_TEST_CASE tc;
    AMVP_RESULT rv;
    const char *alg_str = json_object_get_string(obj, "algorithm");
    AMVP_CIPHER alg_id;
    char *json_result;
    unsigned int g_cnt, i;

    if (!alg_str) {
        AMVP_LOG_ERR("unable to parse 'algorithm' from JSON");
        return AMVP_MALFORMED_JSON;
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.dsa = &stc;
    memzero_s(&stc, sizeof(AMVP_DSA_TC));

    /*
     * Get the crypto module handler for DSA mode
     */
    alg_id = AMVP_DSA_PQGGEN;
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
    if (!groups) {
        AMVP_LOG_ERR("Failed to include testGroups. ");
        rv = AMVP_MISSING_ARG;
        goto err;
    }
    g_cnt = json_array_get_count(groups);

    stc.cipher = alg_id;
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

        stc.mode = AMVP_DSA_MODE_PQGGEN;

        AMVP_LOG_VERBOSE("    Test group: %d", i);

        rv = amvp_dsa_pqggen_handler(ctx, tc, cap, r_tarr, groupobj);
        if (rv != AMVP_SUCCESS) {
            goto err;
        }
        json_array_append_value(r_garr, r_gval);
        amvp_dsa_release_tc(&stc);
    }

    memzero_s(&stc, sizeof(AMVP_DSA_TC));
    json_array_append_value(reg_arry, r_vs_val);
    json_result = json_serialize_to_string_pretty(ctx->kat_resp, NULL);
    AMVP_LOG_VERBOSE("\n\n%s\n\n", json_result);
    json_free_serialized_string(json_result);
    rv = AMVP_SUCCESS;

err:
    if (rv != AMVP_SUCCESS) {
        amvp_dsa_release_tc(&stc);
        amvp_release_json(r_vs_val, r_gval);
    }
    return rv;
}

static AMVP_RESULT amvp_dsa_siggen_kat_handler(AMVP_CTX *ctx, JSON_Object *obj) {
    JSON_Value *groupval;
    JSON_Object *groupobj = NULL;
    JSON_Value *r_vs_val = NULL;
    JSON_Object *r_vs = NULL;
    JSON_Array *r_tarr = NULL, *r_garr = NULL; /* Response testarray, grouparray */
    JSON_Value *reg_arry_val = NULL, *r_gval = NULL;
    JSON_Array *reg_arry = NULL;
    JSON_Object *reg_obj = NULL, *r_gobj = NULL;
    JSON_Array *groups;
    AMVP_CAPS_LIST *cap;
    AMVP_DSA_TC stc;
    AMVP_TEST_CASE tc;
    AMVP_RESULT rv;
    const char *alg_str = json_object_get_string(obj, "algorithm");
    AMVP_CIPHER alg_id;
    char *json_result;
    unsigned int g_cnt, i;

    if (!alg_str) {
        AMVP_LOG_ERR("unable to parse 'algorithm' from JSON");
        return AMVP_MALFORMED_JSON;
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.dsa = &stc;
    memzero_s(&stc, sizeof(AMVP_DSA_TC));

    /*
     * Get the crypto module handler for DSA mode
     */
    alg_id = AMVP_DSA_SIGGEN;
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
    if (!groups) {
        AMVP_LOG_ERR("Failed to include testGroups. ");
        rv = AMVP_MISSING_ARG;
        goto err;
    }
    g_cnt = json_array_get_count(groups);

    stc.cipher = alg_id;
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

        stc.mode = AMVP_DSA_MODE_SIGGEN;

        AMVP_LOG_VERBOSE("    Test group: %d", i);

        rv = amvp_dsa_siggen_handler(ctx, tc, cap, r_tarr, groupobj, tgId, r_gobj);
        if (rv != AMVP_SUCCESS) {
            goto err;

        }
        json_array_append_value(r_garr, r_gval);
        amvp_dsa_release_tc(&stc);
    }

    memzero_s(&stc, sizeof(AMVP_DSA_TC));
    json_array_append_value(reg_arry, r_vs_val);
    json_result = json_serialize_to_string_pretty(ctx->kat_resp, NULL);

    AMVP_LOG_VERBOSE("\n\n%s\n\n", json_result);
    json_free_serialized_string(json_result);
    rv = AMVP_SUCCESS;

err:
    if (rv != AMVP_SUCCESS) {
        amvp_dsa_release_tc(&stc);
        amvp_release_json(r_vs_val, r_gval);
    }
    return rv;
}

static AMVP_RESULT amvp_dsa_keygen_kat_handler(AMVP_CTX *ctx, JSON_Object *obj) {
    JSON_Value *groupval;
    JSON_Object *groupobj = NULL;
    JSON_Value *r_vs_val = NULL;
    JSON_Object *r_vs = NULL;
    JSON_Array *r_tarr = NULL, *r_garr = NULL; /* Response testarray, grouparray */
    JSON_Value *reg_arry_val = NULL, *r_gval = NULL;
    JSON_Array *reg_arry = NULL;
    JSON_Object *reg_obj = NULL, *r_gobj = NULL;
    JSON_Array *groups;
    AMVP_CAPS_LIST *cap;
    AMVP_DSA_TC stc;
    AMVP_TEST_CASE tc;
    AMVP_RESULT rv;
    const char *alg_str = json_object_get_string(obj, "algorithm");
    AMVP_CIPHER alg_id;
    char *json_result;
    unsigned int g_cnt, i;

    if (!alg_str) {
        AMVP_LOG_ERR("unable to parse 'algorithm' from JSON");
        return AMVP_MALFORMED_JSON;
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.dsa = &stc;
    memzero_s(&stc, sizeof(AMVP_DSA_TC));

    /*
     * Get the crypto module handler for DSA mode
     */
    alg_id = AMVP_DSA_KEYGEN;
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
    if (!groups) {
        AMVP_LOG_ERR("Failed to include testGroups. ");
        rv = AMVP_MISSING_ARG;
        goto err;
    }
    g_cnt = json_array_get_count(groups);

    stc.cipher = alg_id;
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

        stc.mode = AMVP_DSA_MODE_KEYGEN;

        AMVP_LOG_VERBOSE("    Test group: %d", i);

        rv = amvp_dsa_keygen_handler(ctx, tc, cap, r_tarr, groupobj, tgId, r_gobj);
        if (rv != AMVP_SUCCESS) {
            goto err;
        }
        json_array_append_value(r_garr, r_gval);
        amvp_dsa_release_tc(&stc);
    }

    memzero_s(&stc, sizeof(AMVP_DSA_TC));
    json_array_append_value(reg_arry, r_vs_val);
    json_result = json_serialize_to_string_pretty(ctx->kat_resp, NULL);

    AMVP_LOG_VERBOSE("\n\n%s\n\n", json_result);
    json_free_serialized_string(json_result);
    rv = AMVP_SUCCESS;

err:
    if (rv != AMVP_SUCCESS) {
        amvp_dsa_release_tc(&stc);
        amvp_release_json(r_vs_val, r_gval);
    }
    return rv;
}

static AMVP_RESULT amvp_dsa_sigver_kat_handler(AMVP_CTX *ctx, JSON_Object *obj) {
    JSON_Value *groupval;
    JSON_Object *groupobj = NULL;
    JSON_Value *r_vs_val = NULL;
    JSON_Object *r_vs = NULL;
    JSON_Array *r_tarr = NULL, *r_garr = NULL; /* Response testarray, grouparray */
    JSON_Value *reg_arry_val = NULL, *r_gval = NULL;
    JSON_Array *reg_arry = NULL;
    JSON_Object *reg_obj = NULL, *r_gobj = NULL;
    JSON_Array *groups;
    AMVP_CAPS_LIST *cap;
    AMVP_DSA_TC stc;
    AMVP_TEST_CASE tc;
    AMVP_RESULT rv;
    const char *alg_str = json_object_get_string(obj, "algorithm");
    AMVP_CIPHER alg_id;
    char *json_result;
    unsigned int g_cnt, i;

    if (!alg_str) {
        AMVP_LOG_ERR("unable to parse 'algorithm' from JSON");
        return AMVP_MALFORMED_JSON;
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.dsa = &stc;
    memzero_s(&stc, sizeof(AMVP_DSA_TC));

    /*
     * Get the crypto module handler for DSA mode
     */
    alg_id = AMVP_DSA_SIGVER;
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
    if (!groups) {
        AMVP_LOG_ERR("Failed to include testGroups. ");
        rv = AMVP_MISSING_ARG;
        goto err;
    }
    g_cnt = json_array_get_count(groups);

    stc.cipher = alg_id;
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

        stc.mode = AMVP_DSA_MODE_SIGVER;

        AMVP_LOG_VERBOSE("    Test group: %d", i);

        rv = amvp_dsa_sigver_handler(ctx, tc, cap, r_tarr, groupobj);
        if (rv != AMVP_SUCCESS) {
            goto err;
        }
        json_array_append_value(r_garr, r_gval);
        amvp_dsa_release_tc(&stc);
    }

    memzero_s(&stc, sizeof(AMVP_DSA_TC));
    json_array_append_value(reg_arry, r_vs_val);
    json_result = json_serialize_to_string_pretty(ctx->kat_resp, NULL);
    if (!json_result) {
        AMVP_LOG_ERR("JSON unable to be serialized");
        rv = AMVP_JSON_ERR;
        goto err;
    }

    AMVP_LOG_VERBOSE("\n\n%s\n\n", json_result);
    json_free_serialized_string(json_result);
    rv = AMVP_SUCCESS;

err:
    if (rv != AMVP_SUCCESS) {
        amvp_dsa_release_tc(&stc);
        amvp_release_json(r_vs_val, r_gval);
    }
    return rv;
}

#define DSA_MODE_STR_MAX 6

AMVP_RESULT amvp_dsa_kat_handler(AMVP_CTX *ctx, JSON_Object *obj) {
    const char *mode = json_object_get_string(obj, "mode");
    int diff = 0;

    if (!ctx) {
        AMVP_LOG_ERR("CTX is NULL. ");
        return AMVP_NO_CTX;
    }

    if (!obj) {
        AMVP_LOG_ERR("OBJ is NULL. ");
        return AMVP_MALFORMED_JSON;
    }

    if (!mode) {
        AMVP_LOG_ERR("Failed to include mode. ");
        return AMVP_MISSING_ARG;
    }

    strcmp_s(AMVP_ALG_DSA_PQGGEN, DSA_MODE_STR_MAX, mode, &diff);
    if (!diff) return amvp_dsa_pqggen_kat_handler(ctx, obj);

    strcmp_s(AMVP_ALG_DSA_PQGVER, DSA_MODE_STR_MAX, mode, &diff);
    if (!diff) return amvp_dsa_pqgver_kat_handler(ctx, obj);

    strcmp_s(AMVP_ALG_DSA_SIGGEN, DSA_MODE_STR_MAX, mode, &diff);
    if (!diff) return amvp_dsa_siggen_kat_handler(ctx, obj);

    strcmp_s(AMVP_ALG_DSA_SIGVER, DSA_MODE_STR_MAX, mode, &diff);
    if (!diff) return amvp_dsa_sigver_kat_handler(ctx, obj);

    strcmp_s(AMVP_ALG_DSA_KEYGEN, DSA_MODE_STR_MAX, mode, &diff);
    if (!diff) return amvp_dsa_keygen_kat_handler(ctx, obj);

    return AMVP_INVALID_ARG;
}
