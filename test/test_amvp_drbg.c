/** @file */
/*
 * Copyright (c) 2019, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libamvp/LICENSE
 */


#include "ut_common.h"
#include "amvp/amvp_lcl.h"

static AMVP_CTX *ctx = NULL;
static AMVP_RESULT rv = 0;
static JSON_Object *obj = NULL;
static JSON_Value *val = NULL;
static char cvalue[] = "same";

static void setup(void) {
    setup_empty_ctx(&ctx);

    rv = amvp_cap_drbg_enable(ctx, AMVP_HASHDRBG, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0,
                                    AMVP_DRBG_DER_FUNC_ENABLED, 0);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_set_prereq(ctx, AMVP_HASHDRBG, 
            AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0,
            AMVP_DRBG_PRED_RESIST_ENABLED, 1);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0,
            AMVP_DRBG_RESEED_ENABLED, 1);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0,
            AMVP_DRBG_ENTROPY_LEN, (int)128, (int)64,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0,
            AMVP_DRBG_NONCE_LEN, (int)96, (int)32,(int) 128);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0,
            AMVP_DRBG_PERSO_LEN, (int)0, (int)128,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0,
            AMVP_DRBG_ADD_IN_LEN, (int)0, (int)128,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0,
            AMVP_DRBG_RET_BITS_LEN, 160);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_enable(ctx, AMVP_HMACDRBG, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_set_prereq(ctx, AMVP_HMACDRBG, 
            AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_HMACDRBG, 
            AMVP_PREREQ_HMAC, cvalue);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0,
                                    AMVP_DRBG_DER_FUNC_ENABLED, 1);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0,
            AMVP_DRBG_PRED_RESIST_ENABLED, 1);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0,
            AMVP_DRBG_RESEED_ENABLED, 1);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0,
            AMVP_DRBG_RET_BITS_LEN, 224);
    cr_assert(rv == AMVP_SUCCESS);

    //Add length range
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0,
            AMVP_DRBG_ENTROPY_LEN, (int)192, (int)64,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0,
            AMVP_DRBG_NONCE_LEN, (int)192, (int)64,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0,
            AMVP_DRBG_PERSO_LEN, (int)0, (int)128,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0,
            AMVP_DRBG_ADD_IN_LEN, (int)0, (int)128,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);

    // AMVP_CTRDRBG
    rv = amvp_cap_drbg_enable(ctx, AMVP_CTRDRBG, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);

    //Add length range
    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0,
            AMVP_DRBG_ENTROPY_LEN, (int)128, (int)128, (int) 256);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0,
            AMVP_DRBG_NONCE_LEN, (int)64, (int)64,(int) 128);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0,
            AMVP_DRBG_PERSO_LEN, (int)0, (int)256,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0,
            AMVP_DRBG_ADD_IN_LEN, (int)0, (int)256,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0,
                                    AMVP_DRBG_DER_FUNC_ENABLED, 1);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0,
            AMVP_DRBG_PRED_RESIST_ENABLED, 1);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0,
            AMVP_DRBG_RESEED_ENABLED, 0);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0,
            AMVP_DRBG_RET_BITS_LEN, 256);
    cr_assert(rv == AMVP_SUCCESS);
}

static void setup_fail(void) {
    setup_empty_ctx(&ctx);

    rv = amvp_cap_drbg_enable(ctx, AMVP_HASHDRBG, &dummy_handler_failure);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0,
                                    AMVP_DRBG_DER_FUNC_ENABLED, 0);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_set_prereq(ctx, AMVP_HASHDRBG, 
            AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0,
            AMVP_DRBG_PRED_RESIST_ENABLED, 1);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0,
            AMVP_DRBG_RESEED_ENABLED, 1);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0,
            AMVP_DRBG_ENTROPY_LEN, (int)128, (int)64,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0,
            AMVP_DRBG_NONCE_LEN, (int)96, (int)32,(int) 128);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0,
            AMVP_DRBG_PERSO_LEN, (int)0, (int)128,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0,
            AMVP_DRBG_ADD_IN_LEN, (int)0, (int)128,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0,
            AMVP_DRBG_RET_BITS_LEN, 160);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_enable(ctx, AMVP_HMACDRBG, &dummy_handler_failure);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_set_prereq(ctx, AMVP_HMACDRBG, 
            AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_HMACDRBG, 
            AMVP_PREREQ_HMAC, cvalue);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0,
                                    AMVP_DRBG_DER_FUNC_ENABLED, 1);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0,
            AMVP_DRBG_PRED_RESIST_ENABLED, 1);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0,
            AMVP_DRBG_RESEED_ENABLED, 1);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0,
            AMVP_DRBG_RET_BITS_LEN, 224);
    cr_assert(rv == AMVP_SUCCESS);

    //Add length range
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0,
            AMVP_DRBG_ENTROPY_LEN, (int)192, (int)64,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0,
            AMVP_DRBG_NONCE_LEN, (int)192, (int)64,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0,
            AMVP_DRBG_PERSO_LEN, (int)0, (int)128,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0,
            AMVP_DRBG_ADD_IN_LEN, (int)0, (int)128,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);

    // AMVP_CTRDRBG
    rv = amvp_cap_drbg_enable(ctx, AMVP_CTRDRBG, &dummy_handler_failure);
    cr_assert(rv == AMVP_SUCCESS);

    //Add length range
    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0,
            AMVP_DRBG_ENTROPY_LEN, (int)128, (int)128, (int) 256);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0,
            AMVP_DRBG_NONCE_LEN, (int)64, (int)64,(int) 128);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0,
            AMVP_DRBG_PERSO_LEN, (int)0, (int)256,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0,
            AMVP_DRBG_ADD_IN_LEN, (int)0, (int)256,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0,
                                    AMVP_DRBG_DER_FUNC_ENABLED, 1);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0,
            AMVP_DRBG_PRED_RESIST_ENABLED, 1);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0,
            AMVP_DRBG_RESEED_ENABLED, 0);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0,
            AMVP_DRBG_RET_BITS_LEN, 256);
    cr_assert(rv == AMVP_SUCCESS);
}

static void teardown(void) {
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test capabilites API.
 */
Test(DRBG_CAPABILITY, good) {
    setup_empty_ctx(&ctx);

    rv = amvp_cap_drbg_enable(ctx, AMVP_HASHDRBG, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0,
                                    AMVP_DRBG_DER_FUNC_ENABLED, 0);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_set_prereq(ctx, AMVP_HASHDRBG, 
            AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0,
            AMVP_DRBG_PRED_RESIST_ENABLED, 1);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0,
            AMVP_DRBG_RESEED_ENABLED, 1);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0,
            AMVP_DRBG_ENTROPY_LEN, (int)128, (int)64,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0,
            AMVP_DRBG_NONCE_LEN, (int)96, (int)32,(int) 128);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0,
            AMVP_DRBG_PERSO_LEN, (int)0, (int)128,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0,
            AMVP_DRBG_ADD_IN_LEN, (int)0, (int)128,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0,
            AMVP_DRBG_RET_BITS_LEN, 160);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_enable(ctx, AMVP_HMACDRBG, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_set_prereq(ctx, AMVP_HMACDRBG, 
            AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_HMACDRBG, 
            AMVP_PREREQ_HMAC, cvalue);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0,
                                    AMVP_DRBG_DER_FUNC_ENABLED, 1);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0,
            AMVP_DRBG_PRED_RESIST_ENABLED, 1);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0,
            AMVP_DRBG_RESEED_ENABLED, 1);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0,
            AMVP_DRBG_RET_BITS_LEN, 224);
    cr_assert(rv == AMVP_SUCCESS);

    //Add length range
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0,
            AMVP_DRBG_ENTROPY_LEN, (int)192, (int)64,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0,
            AMVP_DRBG_NONCE_LEN, (int)192, (int)64,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0,
            AMVP_DRBG_PERSO_LEN, (int)0, (int)128,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0,
            AMVP_DRBG_ADD_IN_LEN, (int)0, (int)128,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);

    // AMVP_CTRDRBG
    rv = amvp_cap_drbg_enable(ctx, AMVP_CTRDRBG, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);

    //Add length range
    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0,
            AMVP_DRBG_ENTROPY_LEN, (int)128, (int)128, (int) 256);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0,
            AMVP_DRBG_NONCE_LEN, (int)64, (int)64,(int) 128);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0,
            AMVP_DRBG_PERSO_LEN, (int)0, (int)256,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0,
            AMVP_DRBG_ADD_IN_LEN, (int)0, (int)256,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0,
                                    AMVP_DRBG_DER_FUNC_ENABLED, 1);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0,
            AMVP_DRBG_PRED_RESIST_ENABLED, 1);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0,
            AMVP_DRBG_RESEED_ENABLED, 0);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0,
            AMVP_DRBG_RET_BITS_LEN, 256);
    cr_assert(rv == AMVP_SUCCESS);

    teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 */
Test(DRBG_API, empty_ctx) {
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/drbg/drbg.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_UNSUPPORTED_OP);

end:
    if (ctx) teardown_ctx(&ctx);
    json_value_free(val);
}

/*
 * Test KAT handler API.
 * The ctx is NULL, expecting failure.
 */
Test(DRBG_API, null_ctx) {
    val = json_parse_file("json/drbg/drbg.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with NULL JSON object */
    rv  = amvp_drbg_kat_handler(NULL, obj);
    cr_assert(rv == AMVP_NO_CTX);
    json_value_free(val);

}

/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 */
Test(DRBG_API, null_json_obj, .init = setup, .fini = teardown) {
    rv  = amvp_drbg_kat_handler(ctx, NULL);
    cr_assert(rv == AMVP_MALFORMED_JSON);
}

/*
 * This is a good JSON.
 * Expecting success.
 */
Test(DRBG_HANDLER, good, .init = setup, .fini = teardown) {
    val = json_parse_file("json/drbg/drbg.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_SUCCESS);
    json_value_free(val);

}

/*
 * The key:"algorithm" is missing.
 */
Test(DRBG_HANDLER, missing_algorithm, .init = setup, .fini = teardown) {
    val = json_parse_file("json/drbg/drbg_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * The value for key:"algorithm" is wrong.
 */
Test(DRBG_HANDLER, wrong_algorithm, .init = setup, .fini = teardown) {
    val = json_parse_file("json/drbg/drbg_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_UNSUPPORTED_OP);
    json_value_free(val);
}

/*
 * The key:"mode" is missing.
 */
Test(DRBG_HANDLER, missing_mode, .init = setup, .fini = teardown) {
    val = json_parse_file("json/drbg/drbg_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * The value for key:"mode" is wrong.
 */
Test(DRBG_HANDLER, wrong_mode, .init = setup, .fini = teardown) {
    val = json_parse_file("json/drbg/drbg_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_UNSUPPORTED_OP);
    json_value_free(val);
}

/*
 * The key:"predResistance" is missing.
 */
Test(DRBG_HANDLER, missing_predResistance, .init = setup, .fini = teardown) {
    val = json_parse_file("json/drbg/drbg_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"derFunc" is missing.
 */
Test(DRBG_HANDLER, missing_derFunc, .init = setup, .fini = teardown) {
    val = json_parse_file("json/drbg/drbg_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"entropyInputLen" is missing.
 */
Test(DRBG_HANDLER, missing_entropyInputLen, .init = setup, .fini = teardown) {
    val = json_parse_file("json/drbg/drbg_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The value for key:"entropyInputLen" is too small.
 */
Test(DRBG_HANDLER, small_entropyInputLen, .init = setup, .fini = teardown) {
    val = json_parse_file("json/drbg/drbg_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The value for key:"entropyInputLen" is too big.
 */
Test(DRBG_HANDLER, big_entropyInputLen, .init = setup, .fini = teardown) {
    val = json_parse_file("json/drbg/drbg_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"nonceLen" is missing.
 */
Test(DRBG_HANDLER, missing_nonceLen, .init = setup, .fini = teardown) {
    val = json_parse_file("json/drbg/drbg_10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The value for key:"nonceLen" is too small.
 */
Test(DRBG_HANDLER, small_nonceLen, .init = setup, .fini = teardown) {
    val = json_parse_file("json/drbg/drbg_11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The value for key:"nonceLen" is too big.
 */
Test(DRBG_HANDLER, big_nonceLen, .init = setup, .fini = teardown) {
    val = json_parse_file("json/drbg/drbg_12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The value for key:"persoStringLen" is too big.
 */
Test(DRBG_HANDLER, big_persoStringLen, .init = setup, .fini = teardown) {
    val = json_parse_file("json/drbg/drbg_13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"returnedBitsLen" is missing.
 */
Test(DRBG_HANDLER, missing_returnedBitsLen, .init = setup, .fini = teardown) {
    val = json_parse_file("json/drbg/drbg_14.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The value for key:"returnedBitsLen" is too big.
 */
Test(DRBG_HANDLER, big_returnedBitsLen, .init = setup, .fini = teardown) {
    val = json_parse_file("json/drbg/drbg_15.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The value for key:"additionalInputLen" is too big.
 */
Test(DRBG_HANDLER, big_additionalInputLen, .init = setup, .fini = teardown) {
    val = json_parse_file("json/drbg/drbg_16.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"persoString" is missing.
 */
Test(DRBG_HANDLER, missing_persoString, .init = setup, .fini = teardown) {
    val = json_parse_file("json/drbg/drbg_17.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"persoString" string is too long.
 */
Test(DRBG_HANDLER, long_persoString, .init = setup, .fini = teardown) {
    val = json_parse_file("json/drbg/drbg_18.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"entropyInput" is missing.
 */
Test(DRBG_HANDLER, missing_entropyInput, .init = setup, .fini = teardown) {
    val = json_parse_file("json/drbg/drbg_19.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"entropyInput" string is too long.
 */
Test(DRBG_HANDLER, long_entropyInput, .init = setup, .fini = teardown) {
    val = json_parse_file("json/drbg/drbg_20.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"nonce" is missing.
 */
Test(DRBG_HANDLER, missing_nonce, .init = setup, .fini = teardown) {
    val = json_parse_file("json/drbg/drbg_21.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"nonce" string is too long.
 */
Test(DRBG_HANDLER, long_nonce, .init = setup, .fini = teardown) {
    val = json_parse_file("json/drbg/drbg_22.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"otherInput" is missing.
 */
Test(DRBG_HANDLER, missing_otherInput, .init = setup, .fini = teardown) {
    val = json_parse_file("json/drbg/drbg_23.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"otherInput" array is empty.
 */
Test(DRBG_HANDLER, empty_otherInput, .init = setup, .fini = teardown) {
    val = json_parse_file("json/drbg/drbg_24.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"additionalInput" for otherInput[0] is missing.
 */
Test(DRBG_HANDLER, missing_additionalInput_oi0, .init = setup, .fini = teardown) {
    val = json_parse_file("json/drbg/drbg_25.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"additionalInput" for otherInput[0] string is too long.
 */
Test(DRBG_HANDLER, long_additionalInput_oi0, .init = setup, .fini = teardown) {
    val = json_parse_file("json/drbg/drbg_26.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"entropyInput" for otherInput[0] is missing.
 */
Test(DRBG_HANDLER, missing_entropyInput_oi0, .init = setup, .fini = teardown) {
    val = json_parse_file("json/drbg/drbg_27.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"entropyInput" for otherInput[0] string is too long.
 */
Test(DRBG_HANDLER, long_entropyInput_oi0, .init = setup, .fini = teardown) {
    val = json_parse_file("json/drbg/drbg_28.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"additionalInput" for otherInput[1] is missing.
 */
Test(DRBG_HANDLER, missing_additionalInput_oi1, .init = setup, .fini = teardown) {
    val = json_parse_file("json/drbg/drbg_29.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"additionalInput" for otherInput[1] string is too long.
 */
Test(DRBG_HANDLER, long_additionalInput_oi1, .init = setup, .fini = teardown) {
    val = json_parse_file("json/drbg/drbg_30.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"entropyInput" for otherInput[1] is missing.
 */
Test(DRBG_HANDLER, missing_entropyInput_oi1, .init = setup, .fini = teardown) {
    val = json_parse_file("json/drbg/drbg_31.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"entropyInput" for otherInput[1] string is too long.
 */
Test(DRBG_HANDLER, long_entropyInput_oi1, .init = setup, .fini = teardown) {
    val = json_parse_file("json/drbg/drbg_32.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(DRBG_HANDDLER, cryptoFail1, .init = setup_fail, .fini = teardown) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/drbg/drbg.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration */
    rv  = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(DRBG_HANDDLER, cryptoFail2, .init = setup_fail, .fini = teardown) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/drbg/drbg.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 809; /* fail on last iteration */
    rv  = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * The key:"mode" is missing in last tg
 */
Test(DRBG_HANDDLER, tgFail1, .init = setup, .fini = teardown) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/drbg/drbg_33.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * The key:"nonce" is missing in last tc
 */
Test(DRBG_HANDDLER, tcFail1, .init = setup, .fini = teardown) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/drbg/drbg_34.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_drbg_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}

