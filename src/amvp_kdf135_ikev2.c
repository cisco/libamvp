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
static AMVP_RESULT amvp_kdf135_ikev2_output_tc(AMVP_CTX *ctx, AMVP_KDF135_IKEV2_TC *stc, JSON_Object *tc_rsp) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    char *tmp = NULL;

    tmp = calloc(AMVP_KDF135_IKEV2_SKEY_SEED_STR_MAX + 1, sizeof(char));
    if (!tmp) { return AMVP_MALLOC_FAIL; }

    rv = amvp_bin_to_hexstr(stc->s_key_seed, stc->key_out_len, tmp, AMVP_KDF135_IKEV2_SKEY_SEED_STR_MAX);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("hex conversion failure (s_key_seed)");
        goto err;
    }
    json_object_set_string(tc_rsp, "sKeySeed", (const char *)tmp);
    memzero_s(tmp, AMVP_KDF135_IKEV2_SKEY_SEED_STR_MAX);

    rv = amvp_bin_to_hexstr(stc->s_key_seed_rekey, stc->key_out_len, tmp, AMVP_KDF135_IKEV2_SKEY_SEED_STR_MAX);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("hex conversion failure (s_key_seed_rekey)");
        goto err;
    }
    json_object_set_string(tc_rsp, "sKeySeedReKey", (const char *)tmp);
    memzero_s(tmp, AMVP_KDF135_IKEV2_SKEY_SEED_STR_MAX);
    free(tmp);


    tmp = calloc(AMVP_KDF135_IKEV2_DKEY_MATERIAL_STR_MAX, sizeof(char));
    rv = amvp_bin_to_hexstr(stc->derived_keying_material, stc->keying_material_len, tmp, AMVP_KDF135_IKEV2_DKEY_MATERIAL_STR_MAX);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("hex conversion failure (derived_keying_material)");
        goto err;
    }
    json_object_set_string(tc_rsp, "derivedKeyingMaterial", (const char *)tmp);
    memzero_s(tmp, AMVP_KDF135_IKEV2_DKEY_MATERIAL_STR_MAX);

    rv = amvp_bin_to_hexstr(stc->derived_keying_material_child, stc->keying_material_len, tmp, AMVP_KDF135_IKEV2_DKEY_MATERIAL_STR_MAX);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("hex conversion failure (derived_keying_material)");
        goto err;
    }
    json_object_set_string(tc_rsp, "derivedKeyingMaterialChild", (const char *)tmp);
    memzero_s(tmp, AMVP_KDF135_IKEV2_DKEY_MATERIAL_STR_MAX);

    rv = amvp_bin_to_hexstr(stc->derived_keying_material_child_dh, stc->keying_material_len, tmp, AMVP_KDF135_IKEV2_DKEY_MATERIAL_STR_MAX);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("hex conversion failure (derived_keying_material)");
        goto err;
    }
    json_object_set_string(tc_rsp, "derivedKeyingMaterialDh", (const char *)tmp);
    memzero_s(tmp, AMVP_KDF135_IKEV2_DKEY_MATERIAL_STR_MAX);

err:
    free(tmp);
    return rv;
}

static AMVP_RESULT amvp_kdf135_ikev2_init_tc(AMVP_CTX *ctx,
                                             AMVP_KDF135_IKEV2_TC *stc,
                                             unsigned int tc_id,
                                             AMVP_HASH_ALG hash_alg,
                                             int init_nonce_len,
                                             int resp_nonce_len,
                                             int dh_secret_len,
                                             int keying_material_len,
                                             const char *init_nonce,
                                             const char *resp_nonce,
                                             const char *init_spi,
                                             const char *resp_spi,
                                             const char *gir,
                                             const char *gir_new) {
    AMVP_RESULT rv = AMVP_SUCCESS;

    memzero_s(stc, sizeof(AMVP_KDF135_IKEV2_TC));

    stc->tc_id = tc_id;

    stc->hash_alg = hash_alg;
    stc->init_nonce_len = init_nonce_len;
    stc->resp_nonce_len = resp_nonce_len;

    stc->dh_secret_len = dh_secret_len;
    stc->keying_material_len = AMVP_BIT2BYTE(keying_material_len);

    stc->init_nonce = calloc(AMVP_KDF135_IKEV2_INIT_NONCE_BYTE_MAX,
                             sizeof(unsigned char));
    if (!stc->init_nonce) { return AMVP_MALLOC_FAIL; }
    rv = amvp_hexstr_to_bin(init_nonce, stc->init_nonce, AMVP_KDF135_IKEV2_INIT_NONCE_BYTE_MAX, &(stc->init_nonce_len));
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (init_nonce)");
        return rv;
    }

    stc->resp_nonce = calloc(AMVP_KDF135_IKEV2_RESP_NONCE_BYTE_MAX,
                             sizeof(unsigned char));
    if (!stc->resp_nonce) { return AMVP_MALLOC_FAIL; }
    rv = amvp_hexstr_to_bin(resp_nonce, stc->resp_nonce, AMVP_KDF135_IKEV2_RESP_NONCE_BYTE_MAX, &(stc->resp_nonce_len));
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (resp_nonce)");
        return rv;
    }

    stc->init_spi = calloc(AMVP_KDF135_IKEV2_SPI_BYTE_MAX,
                           sizeof(unsigned char));
    if (!stc->init_spi) { return AMVP_MALLOC_FAIL; }
    rv = amvp_hexstr_to_bin(init_spi, stc->init_spi, AMVP_KDF135_IKEV2_SPI_BYTE_MAX, &(stc->init_spi_len));
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (init_spi)");
        return rv;
    }

    stc->resp_spi = calloc(AMVP_KDF135_IKEV2_SPI_BYTE_MAX,
                           sizeof(unsigned char));
    if (!stc->resp_spi) { return AMVP_MALLOC_FAIL; }
    rv = amvp_hexstr_to_bin(resp_spi, stc->resp_spi, AMVP_KDF135_IKEV2_SPI_BYTE_MAX, &(stc->resp_spi_len));
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (resp_spi)");
        return rv;
    }

    stc->gir = calloc(AMVP_KDF135_IKEV2_DH_SHARED_SECRET_BYTE_MAX,
                      sizeof(unsigned char));
    if (!stc->gir) { return AMVP_MALLOC_FAIL; }
    rv = amvp_hexstr_to_bin(gir, stc->gir, AMVP_KDF135_IKEV2_DH_SHARED_SECRET_BYTE_MAX, &(stc->gir_len));
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (gir)");
        return rv;
    }

    stc->gir_new = calloc(AMVP_KDF135_IKEV2_DH_SHARED_SECRET_BYTE_MAX,
                          sizeof(unsigned char));
    if (!stc->gir_new) { return AMVP_MALLOC_FAIL; }
    rv = amvp_hexstr_to_bin(gir_new, stc->gir_new, AMVP_KDF135_IKEV2_DH_SHARED_SECRET_BYTE_MAX, &(stc->gir_new_len));
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Hex conversion failure (gir_new)");
        return rv;
    }

    /* allocate memory for answers so app doesn't have to touch library memory */
    stc->s_key_seed = calloc(AMVP_KDF135_IKEV2_SKEY_SEED_BYTE_MAX,
                             sizeof(unsigned char));
    if (!stc->s_key_seed) { return AMVP_MALLOC_FAIL; }

    stc->s_key_seed_rekey = calloc(AMVP_KDF135_IKEV2_SKEY_SEED_BYTE_MAX,
                                   sizeof(unsigned char));
    if (!stc->s_key_seed_rekey) { return AMVP_MALLOC_FAIL; }

    stc->derived_keying_material = calloc(AMVP_KDF135_IKEV2_DKEY_MATERIAL_BYTE_MAX,
                                          sizeof(unsigned char));
    if (!stc->derived_keying_material) { return AMVP_MALLOC_FAIL; }

    stc->derived_keying_material_child_dh = calloc(AMVP_KDF135_IKEV2_DKEY_MATERIAL_BYTE_MAX,
                                                   sizeof(unsigned char));
    if (!stc->derived_keying_material_child_dh) { return AMVP_MALLOC_FAIL; }

    stc->derived_keying_material_child = calloc(AMVP_KDF135_IKEV2_DKEY_MATERIAL_BYTE_MAX,
                                                sizeof(unsigned char));
    if (!stc->derived_keying_material_child) { return AMVP_MALLOC_FAIL; }

    return rv;
}

static AMVP_RESULT amvp_kdf135_ikev2_release_tc(AMVP_KDF135_IKEV2_TC *stc) {
    if (stc->init_nonce) { free(stc->init_nonce); }
    if (stc->resp_nonce) { free(stc->resp_nonce); }
    if (stc->init_spi) { free(stc->init_spi); }
    if (stc->resp_spi) { free(stc->resp_spi); }
    if (stc->gir) { free(stc->gir); }
    if (stc->gir_new) { free(stc->gir_new); }
    if (stc->s_key_seed) { free(stc->s_key_seed); }
    if (stc->s_key_seed_rekey) { free(stc->s_key_seed_rekey); }
    if (stc->derived_keying_material) { free(stc->derived_keying_material); }
    if (stc->derived_keying_material_child) { free(stc->derived_keying_material_child); }
    if (stc->derived_keying_material_child_dh) { free(stc->derived_keying_material_child_dh); }
    memzero_s(stc, sizeof(AMVP_KDF135_IKEV2_TC));
    return AMVP_SUCCESS;
}

AMVP_RESULT amvp_kdf135_ikev2_kat_handler(AMVP_CTX *ctx, JSON_Object *obj) {
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
    AMVP_KDF135_IKEV2_TC stc;
    AMVP_TEST_CASE tc;
    AMVP_RESULT rv;
    const char *alg_str = json_object_get_string(obj, "algorithm");
    const char *mode_str = NULL;
    AMVP_CIPHER alg_id;
    char *json_result;

    AMVP_HASH_ALG hash_alg;
    const char *hash_alg_str = NULL;
    const char *init_nonce = NULL, *resp_nonce = NULL, *init_spi = NULL;
    const char *resp_spi = NULL, *gir = NULL, *gir_new = NULL;
    unsigned int init_nonce_len = 0, resp_nonce_len = 0;
    int  dh_secret_len = 0, keying_material_len = 0;

    if (!ctx) {
        AMVP_LOG_ERR("No ctx for handler operation");
        return AMVP_NO_CTX;
    }

    if (!alg_str) {
        AMVP_LOG_ERR("unable to parse 'algorithm' from JSON");
        return AMVP_MALFORMED_JSON;
    }

    mode_str = json_object_get_string(obj, "mode");
    if (!mode_str) {
        AMVP_LOG_ERR("unable to parse 'mode' from JSON");
        return AMVP_MALFORMED_JSON;
    }

    alg_id = amvp_lookup_cipher_w_mode_index(alg_str, mode_str);
    if (alg_id != AMVP_KDF135_IKEV2) {
        AMVP_LOG_ERR("Server JSON invalid 'algorithm' or 'mode'");
        return AMVP_INVALID_ARG;
    }

    /*
     * Get a reference to the abstracted test case
     */
    tc.tc.kdf135_ikev2 = &stc;
    stc.cipher = alg_id;

    cap = amvp_locate_cap_entry(ctx, alg_id);
    if (!cap) {
        AMVP_LOG_ERR("AMVP server requesting unsupported capability %s : %d.", alg_str, alg_id);
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

        hash_alg_str = json_object_get_string(groupobj, "hashAlg");
        if (!hash_alg_str) {
            AMVP_LOG_ERR("Failed to include hashAlg");
            rv = AMVP_MISSING_ARG;
            goto err;
        }
        hash_alg = amvp_lookup_hash_alg(hash_alg_str);
        if (hash_alg != AMVP_SHA1 && hash_alg != AMVP_SHA224 &&
            hash_alg != AMVP_SHA256 && hash_alg != AMVP_SHA384 &&
            hash_alg != AMVP_SHA512) {
            AMVP_LOG_ERR("AMVP server requesting invalid hash alg");
            rv = AMVP_INVALID_ARG;
            goto err;
        }

        init_nonce_len = json_object_get_number(groupobj, "nInitLength");
        if (!(init_nonce_len >= AMVP_KDF135_IKEV2_INIT_NONCE_BIT_MIN &&
              init_nonce_len <= AMVP_KDF135_IKEV2_INIT_NONCE_BIT_MAX)) {
            AMVP_LOG_ERR("nInitLength incorrect, %d", init_nonce_len);
            rv = AMVP_INVALID_ARG;
            goto err;
        }

        resp_nonce_len = json_object_get_number(groupobj, "nRespLength");
        if (!(resp_nonce_len >= AMVP_KDF135_IKEV2_RESP_NONCE_BIT_MIN &&
              resp_nonce_len <= AMVP_KDF135_IKEV2_RESP_NONCE_BIT_MAX)) {
            AMVP_LOG_ERR("nRespLength incorrect, %d", resp_nonce_len);
            rv = AMVP_INVALID_ARG;
            goto err;
        }

        dh_secret_len = json_object_get_number(groupobj, "dhLength");
        if (!(dh_secret_len >= AMVP_KDF135_IKEV2_DH_SHARED_SECRET_BIT_MIN &&
              dh_secret_len <= AMVP_KDF135_IKEV2_DH_SHARED_SECRET_BIT_MAX)) {
            AMVP_LOG_ERR("dhLength incorrect, %d", dh_secret_len);
            rv = AMVP_INVALID_ARG;
            goto err;
        }

        keying_material_len = json_object_get_number(groupobj, "derivedKeyingMaterialLength");
        if (!(keying_material_len >= AMVP_KDF135_IKEV2_DKEY_MATERIAL_BIT_MIN &&
              keying_material_len <= AMVP_KDF135_IKEV2_DKEY_MATERIAL_BIT_MAX)) {
            AMVP_LOG_ERR("derivedKeyingMaterialLength incorrect, %d", keying_material_len);
            rv = AMVP_INVALID_ARG;
            goto err;
        }

        AMVP_LOG_VERBOSE("\n    Test group: %d", i);
        AMVP_LOG_VERBOSE("        hash alg: %s", hash_alg_str);
        AMVP_LOG_VERBOSE("  init nonce len: %d", init_nonce_len);
        AMVP_LOG_VERBOSE("  resp nonce len: %d", resp_nonce_len);
        AMVP_LOG_VERBOSE("   dh secret len: %d", dh_secret_len);
        AMVP_LOG_VERBOSE("derived key material: %d", keying_material_len);

        tests = json_object_get_array(groupobj, "tests");
        t_cnt = json_array_get_count(tests);

        for (j = 0; j < t_cnt; j++) {
            AMVP_LOG_VERBOSE("Found new KDF IKEv2 test vector...");
            testval = json_array_get_value(tests, j);
            testobj = json_value_get_object(testval);

            tc_id = json_object_get_number(testobj, "tcId");

            init_nonce = json_object_get_string(testobj, "nInit");
            if (!init_nonce) {
                AMVP_LOG_ERR("Failed to include nInit");
                rv = AMVP_MISSING_ARG;
                goto err;
            }
            if (strnlen_s(init_nonce, init_nonce_len) != init_nonce_len / 4) {
                AMVP_LOG_ERR("nInit length(%d) incorrect, expected(%d)",
                             (int)strnlen_s(init_nonce, AMVP_KDF135_IKEV2_INIT_NONCE_STR_MAX),
                             init_nonce_len / 4);
                rv = AMVP_INVALID_ARG;
                goto err;
            }

            resp_nonce = json_object_get_string(testobj, "nResp");
            if (!resp_nonce) {
                AMVP_LOG_ERR("Failed to include nResp");
                rv = AMVP_MISSING_ARG;
                goto err;
            }
            if (strnlen_s(resp_nonce, resp_nonce_len) != resp_nonce_len / 4) {
                AMVP_LOG_ERR("nResp length(%d) incorrect, expected(%d)",
                             (int)strnlen_s(resp_nonce, AMVP_KDF135_IKEV2_RESP_NONCE_STR_MAX),
                             resp_nonce_len / 4);
                rv = AMVP_INVALID_ARG;
                goto err;
            }

            init_spi = json_object_get_string(testobj, "spiInit");
            if (!init_spi) {
                AMVP_LOG_ERR("Failed to include spiInit");
                rv = AMVP_MISSING_ARG;
                goto err;
            }
            if (strnlen_s(init_spi, AMVP_KDF135_IKEV2_SPI_STR_MAX + 1)
                > AMVP_KDF135_IKEV2_SPI_STR_MAX) {
                AMVP_LOG_ERR("spiInit too long, max allowed=(%d)",
                             AMVP_KDF135_IKEV2_SPI_STR_MAX);
                rv = AMVP_INVALID_ARG;
                goto err;
            }

            resp_spi = json_object_get_string(testobj, "spiResp");
            if (!resp_spi) {
                AMVP_LOG_ERR("Failed to include spiResp");
                rv = AMVP_MISSING_ARG;
                goto err;
            }
            if (strnlen_s(resp_spi, AMVP_KDF135_IKEV2_SPI_STR_MAX + 1)
                > AMVP_KDF135_IKEV2_SPI_STR_MAX) {
                AMVP_LOG_ERR("spiResp too long, max allowed=(%d)",
                             AMVP_KDF135_IKEV2_SPI_STR_MAX);
                rv = AMVP_INVALID_ARG;
                goto err;
            }

            gir = json_object_get_string(testobj, "gir");
            if (!gir) {
                AMVP_LOG_ERR("Failed to include gir");
                rv = AMVP_MISSING_ARG;
                goto err;
            }
            if (strnlen_s(gir, AMVP_KDF135_IKEV2_DH_SHARED_SECRET_STR_MAX + 1)
                > AMVP_KDF135_IKEV2_DH_SHARED_SECRET_STR_MAX) {
                AMVP_LOG_ERR("gir too long, max allowed=(%d)",
                             AMVP_KDF135_IKEV2_DH_SHARED_SECRET_STR_MAX);
                rv = AMVP_INVALID_ARG;
                goto err;
            }

            gir_new = json_object_get_string(testobj, "girNew");
            if (!gir_new) {
                AMVP_LOG_ERR("Failed to include girNew");
                rv = AMVP_MISSING_ARG;
                goto err;
            }
            if (strnlen_s(gir_new, AMVP_KDF135_IKEV2_DH_SHARED_SECRET_STR_MAX + 1)
                > AMVP_KDF135_IKEV2_DH_SHARED_SECRET_STR_MAX) {
                AMVP_LOG_ERR("girNew too long, max allowed=(%d)",
                             AMVP_KDF135_IKEV2_DH_SHARED_SECRET_STR_MAX);
                rv = AMVP_INVALID_ARG;
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
             * Setup the test case data that will be passed down to
             * the crypto module.
             */
            rv = amvp_kdf135_ikev2_init_tc(ctx, &stc, tc_id, hash_alg,
                                           init_nonce_len, resp_nonce_len,
                                           dh_secret_len, keying_material_len,
                                           init_nonce, resp_nonce,
                                           init_spi, resp_spi,
                                           gir, gir_new);
            if (rv != AMVP_SUCCESS) {
                amvp_kdf135_ikev2_release_tc(&stc);
                json_value_free(r_tval);
                goto err;
            }

            /* Process the current test vector... */
            if ((cap->crypto_handler)(&tc)) {
                AMVP_LOG_ERR("crypto module failed");
                amvp_kdf135_ikev2_release_tc(&stc);
                rv = AMVP_CRYPTO_MODULE_FAIL;
                json_value_free(r_tval);
                goto err;
            }

            /*
             * Output the test case results using JSON
             */
            rv = amvp_kdf135_ikev2_output_tc(ctx, &stc, r_tobj);
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("JSON output failure");
                amvp_kdf135_ikev2_release_tc(&stc);
                json_value_free(r_tval);
                goto err;
            }
            /*
             * Release all the memory associated with the test case
             */
            amvp_kdf135_ikev2_release_tc(&stc);

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
