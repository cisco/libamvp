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
    
    /*
     * Enable ECDSA keygen
     */
    rv = amvp_cap_ecdsa_enable(ctx, AMVP_ECDSA_KEYGEN, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_ECDSA_KEYGEN, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_ECDSA_KEYGEN, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B571);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYGEN, AMVP_ECDSA_SECRET_GEN, AMVP_ECDSA_SECRET_GEN_TEST_CAND);
    cr_assert(rv == AMVP_SUCCESS);
    
    /*
     * Enable ECDSA keyVer...
     */
    rv = amvp_cap_ecdsa_enable(ctx, AMVP_ECDSA_KEYVER, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_ECDSA_KEYVER, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_ECDSA_KEYVER, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B409);
    cr_assert(rv == AMVP_SUCCESS);
    
    /*
     * Enable ECDSA sigGen...
     */
    rv = amvp_cap_ecdsa_enable(ctx, AMVP_ECDSA_SIGGEN, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_ECDSA_SIGGEN, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_ECDSA_SIGGEN, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B283);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_HASH_ALG, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    
    /*
     * Enable ECDSA sigVer...
     */
    rv = amvp_cap_ecdsa_enable(ctx, AMVP_ECDSA_SIGVER, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_ECDSA_SIGVER, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_ECDSA_SIGVER, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P521);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K233);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K283);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_HASH_ALG, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);

}

static void setup_fail(void) {
    setup_empty_ctx(&ctx);
    
    /*
     * Enable ECDSA keygen
     */
    rv = amvp_cap_ecdsa_enable(ctx, AMVP_ECDSA_KEYGEN, &dummy_handler_failure);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_ECDSA_KEYGEN, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_ECDSA_KEYGEN, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B571);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYGEN, AMVP_ECDSA_SECRET_GEN, AMVP_ECDSA_SECRET_GEN_TEST_CAND);
    cr_assert(rv == AMVP_SUCCESS);
    
    /*
     * Enable ECDSA keyVer...
     */
    rv = amvp_cap_ecdsa_enable(ctx, AMVP_ECDSA_KEYVER, &dummy_handler_failure);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_ECDSA_KEYVER, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_ECDSA_KEYVER, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B409);
    cr_assert(rv == AMVP_SUCCESS);
    
    /*
     * Enable ECDSA sigGen...
     */
    rv = amvp_cap_ecdsa_enable(ctx, AMVP_ECDSA_SIGGEN, &dummy_handler_failure);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_ECDSA_SIGGEN, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_ECDSA_SIGGEN, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B283);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_HASH_ALG, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    
    /*
     * Enable ECDSA sigVer...
     */
    rv = amvp_cap_ecdsa_enable(ctx, AMVP_ECDSA_SIGVER, &dummy_handler_failure);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_ECDSA_SIGVER, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_ECDSA_SIGVER, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P521);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K233);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K283);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_HASH_ALG, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);

}

static void teardown(void) {
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test capabilites API.
 */
Test(ECDSA_CAPABILITY, good) {
    setup_empty_ctx(&ctx);

    rv = amvp_cap_ecdsa_enable(ctx, AMVP_ECDSA_KEYGEN, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_ECDSA_KEYGEN, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_ECDSA_KEYGEN, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B571);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYGEN, AMVP_ECDSA_SECRET_GEN, AMVP_ECDSA_SECRET_GEN_TEST_CAND);
    cr_assert(rv == AMVP_SUCCESS);

    teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 */
Test(ECDSA_API, empty_ctx) {
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/ecdsa/ecdsa_keygen.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    /* All four APIs point to the same internal code... */
    rv  = amvp_ecdsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_UNSUPPORTED_OP);
    json_value_free(val);

    val = json_parse_file("json/ecdsa/ecdsa_keyver.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = amvp_ecdsa_keyver_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_UNSUPPORTED_OP);
    json_value_free(val);
    
    val = json_parse_file("json/ecdsa/ecdsa_siggen.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = amvp_ecdsa_siggen_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_UNSUPPORTED_OP);
    json_value_free(val);
    
    val = json_parse_file("json/ecdsa/ecdsa_sigver.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = amvp_ecdsa_sigver_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_UNSUPPORTED_OP);
    json_value_free(val);

end:
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test KAT handler API.
 * The ctx is NULL, expecting failure.
 */
Test(ECDSA_API, null_ctx) {
    val = json_parse_file("json/ecdsa/ecdsa_keygen.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* All four APIs point to the same internal code... */
    rv  = amvp_ecdsa_keygen_kat_handler(NULL, obj);
    cr_assert(rv == AMVP_NO_CTX);
    json_value_free(val);
}

/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 * All four APIs point to the same internal method so
 * this is just a sanity check...
 */
Test(ECDSA_API, null_json_obj, .init = setup, .fini = teardown) {
    rv  = amvp_ecdsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MALFORMED_JSON);
    
    rv  = amvp_ecdsa_keyver_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MALFORMED_JSON);
    
    rv  = amvp_ecdsa_siggen_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MALFORMED_JSON);
    
    rv  = amvp_ecdsa_sigver_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * This is a good JSON.
 * Expecting success.
 */
Test(ECDSA_HANDLER, good_sv, .init = setup, .fini = teardown) {
    val = json_parse_file("json/ecdsa/ecdsa_sigver.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_ecdsa_sigver_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_SUCCESS);
    json_value_free(val);
}

/*
 * This is a good JSON.
 * Expecting success.
 */
Test(ECDSA_HANDLER, good_kg, .init = setup, .fini = teardown) {
    val = json_parse_file("json/ecdsa/ecdsa_keygen.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_ecdsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_SUCCESS);
    json_value_free(val);
}

/*
 * This is a good JSON.
 * Expecting success.
 */
Test(ECDSA_HANDLER, good_kv, .init = setup, .fini = teardown) {
    val = json_parse_file("json/ecdsa/ecdsa_keyver.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_ecdsa_keyver_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_SUCCESS);
    json_value_free(val);
}

/*
 * This is a good JSON.
 * Expecting success.
 */
Test(ECDSA_HANDLER, good_sg, .init = setup, .fini = teardown) {
    val = json_parse_file("json/ecdsa/ecdsa_siggen.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_ecdsa_siggen_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_SUCCESS);
    json_value_free(val);
}

/*
 * The value for key:"algorithm" is wrong.
 */
Test(ECDSA_HANDLER, wrong_algorithm, .init = setup, .fini = teardown) {
    val = json_parse_file("json/ecdsa/ecdsa_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_ecdsa_siggen_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"mode" is missing.
 */
Test(ECDSA_HANDLER, missing_mode, .init = setup, .fini = teardown) {
    val = json_parse_file("json/ecdsa/ecdsa_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_ecdsa_sigver_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * The value for key:"mode" is wrong.
 */
Test(ECDSA_HANDLER, wrong_mode, .init = setup, .fini = teardown) {
    val = json_parse_file("json/ecdsa/ecdsa_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_ecdsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"testGroups" is missing.
 */
Test(ECDSA_HANDLER, missing_testgroups, .init = setup, .fini = teardown) {
    val = json_parse_file("json/ecdsa/ecdsa_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_ecdsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * The key:"curve" is missing.
 */
Test(ECDSA_HANDLER, missing_curve, .init = setup, .fini = teardown) {
    val = json_parse_file("json/ecdsa/ecdsa_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_ecdsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"curve" string is wrong.
 */
Test(ECDSA_HANDLER, wrong_curve, .init = setup, .fini = teardown) {
    val = json_parse_file("json/ecdsa/ecdsa_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_ecdsa_keyver_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"tgId" is missing.
 */
Test(ECDSA_HANDLER, missing_tgid, .init = setup, .fini = teardown) {
    val = json_parse_file("json/ecdsa/ecdsa_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_ecdsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"hashAlg" is missing. (siggen, sigver only)
 */
Test(ECDSA_HANDLER, missing_hashalg_sg, .init = setup, .fini = teardown) {
    val = json_parse_file("json/ecdsa/ecdsa_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_ecdsa_sigver_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"hashAlg" is wrong. (siggen, sigver only)
 */
Test(ECDSA_HANDLER, wrong_hashalg, .init = setup, .fini = teardown) {
    val = json_parse_file("json/ecdsa/ecdsa_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_ecdsa_siggen_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"message" is missing. (siggen, sigver only)
 */
Test(ECDSA_HANDLER, missing_message, .init = setup, .fini = teardown) {
    val = json_parse_file("json/ecdsa/ecdsa_10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_ecdsa_siggen_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"message" is too long. (siggen, sigver only)
 */
Test(ECDSA_HANDLER, too_long_message, .init = setup, .fini = teardown) {
    val = json_parse_file("json/ecdsa/ecdsa_11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_ecdsa_sigver_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"qx" is missing. (keyver, sigver only)
 */
Test(ECDSA_HANDLER, missing_qx, .init = setup, .fini = teardown) {
    val = json_parse_file("json/ecdsa/ecdsa_12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_ecdsa_keyver_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"qy" is missing. (keyver, sigver only)
 */
Test(ECDSA_HANDLER, missing_qy, .init = setup, .fini = teardown) {
    val = json_parse_file("json/ecdsa/ecdsa_13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_ecdsa_sigver_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"qx" is too long. (keyver, sigver only)
 */
Test(ECDSA_HANDLER, too_long_qx, .init = setup, .fini = teardown) {
    val = json_parse_file("json/ecdsa/ecdsa_14.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_ecdsa_sigver_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The value for key:"qy" is too long. (keyver, sigver only)
 */
Test(ECDSA_HANDLER, too_long_qy, .init = setup, .fini = teardown) {
    val = json_parse_file("json/ecdsa/ecdsa_15.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_ecdsa_keyver_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"r" is missing. (sigver only)
 */
Test(ECDSA_HANDLER, missing_r, .init = setup, .fini = teardown) {
    val = json_parse_file("json/ecdsa/ecdsa_16.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_ecdsa_sigver_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"s" is missing. (sigver only)
 */
Test(ECDSA_HANDLER, missing_s, .init = setup, .fini = teardown) {
    val = json_parse_file("json/ecdsa/ecdsa_17.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_ecdsa_sigver_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The value for key:"r" is too long. (sigver only)
 */
Test(ECDSA_HANDLER, too_long_r, .init = setup, .fini = teardown) {
    val = json_parse_file("json/ecdsa/ecdsa_18.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_ecdsa_sigver_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The value for key:"s" is too long. (sigver only)
 */
Test(ECDSA_HANDLER, too_long_s, .init = setup, .fini = teardown) {
    val = json_parse_file("json/ecdsa/ecdsa_19.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_ecdsa_sigver_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(ECDSA_HANDLER, cryptoFail1, .init = setup_fail, .fini = teardown) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/ecdsa/ecdsa_keygen.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration */
    rv  = amvp_ecdsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(ECDSA_HANDLER, cryptoFail2, .init = setup_fail, .fini = teardown) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/ecdsa/ecdsa_keygen.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 1; /* fail on last iteration */
    rv  = amvp_ecdsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(ECDSA_HANDLER, cryptoFail3, .init = setup_fail, .fini = teardown) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/ecdsa/ecdsa_keyver.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration */
    rv  = amvp_ecdsa_keyver_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(ECDSA_HANDLER, cryptoFail4, .init = setup_fail, .fini = teardown) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/ecdsa/ecdsa_keyver.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 1; /* fail on last iteration */
    rv  = amvp_ecdsa_keyver_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(ECDSA_HANDLER, cryptoFail5, .init = setup_fail, .fini = teardown) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/ecdsa/ecdsa_siggen.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration */
    rv  = amvp_ecdsa_siggen_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(ECDSA_HANDLER, cryptoFail6, .init = setup_fail, .fini = teardown) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/ecdsa/ecdsa_siggen.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 1; /* fail on last iteration */
    rv  = amvp_ecdsa_siggen_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(ECDSA_HANDLER, cryptoFail7, .init = setup_fail, .fini = teardown) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/ecdsa/ecdsa_sigver.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration */
    rv  = amvp_ecdsa_sigver_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(ECDSA_HANDLER, cryptoFail8, .init = setup_fail, .fini = teardown) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/ecdsa/ecdsa_sigver.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 1; /* fail on last iteration */
    rv  = amvp_ecdsa_sigver_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * The key:"curve" is missing in last tg
 */
Test(ECDSA_HANDLER, tgFail1, .init = setup, .fini = teardown) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/ecdsa/ecdsa_keygen_1.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_ecdsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"tests" is missing in last tc
 */
Test(ECDSA_HANDLER, tcFail1, .init = setup, .fini = teardown) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/ecdsa/ecdsa_keygen_2.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_ecdsa_keygen_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The key:"curve" is missing in last tg
 */
Test(ECDSA_HANDLER, tgFail2, .init = setup, .fini = teardown) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/ecdsa/ecdsa_keyver_1.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_ecdsa_keyver_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"qx" is missing in last tc
 */
Test(ECDSA_HANDLER, tcFail2, .init = setup, .fini = teardown) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/ecdsa/ecdsa_keyver_2.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_ecdsa_keyver_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The key:"curve" is missing in last tg
 */
Test(ECDSA_HANDLER, tgFail3, .init = setup, .fini = teardown) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/ecdsa/ecdsa_siggen_1.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_ecdsa_siggen_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"message" is missing in last tc
 */
Test(ECDSA_HANDLER, tcFail3, .init = setup, .fini = teardown) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/ecdsa/ecdsa_siggen_2.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_ecdsa_siggen_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The key:"curve" is missing in last tg
 */
Test(ECDSA_HANDLER, tgFail4, .init = setup, .fini = teardown) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/ecdsa/ecdsa_sigver_1.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_ecdsa_sigver_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}

/*
 * The key:"message" is missing in last tc
 */
Test(ECDSA_HANDLER, tcFail4, .init = setup, .fini = teardown) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/ecdsa/ecdsa_sigver_2.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_ecdsa_sigver_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}


