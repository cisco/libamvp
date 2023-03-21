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

    rv = amvp_cap_kdf135_ikev1_enable(ctx, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_IKEV1, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_IKEV1, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev1_set_domain(ctx, AMVP_KDF_IKEv1_INIT_NONCE_LEN, 64, 2048, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev1_set_domain(ctx, AMVP_KDF_IKEv1_RESPOND_NONCE_LEN, 64, 2048, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev1_set_domain(ctx, AMVP_KDF_IKEv1_DH_SECRET_LEN, 224, 8192, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev1_set_domain(ctx, AMVP_KDF_IKEv1_PSK_LEN, 8, 8192, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev1_set_parm(ctx, AMVP_KDF_IKEv1_HASH_ALG, AMVP_SHA1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev1_set_parm(ctx, AMVP_KDF_IKEv1_AUTH_METHOD, AMVP_KDF135_IKEV1_AMETH_PSK);
    cr_assert(rv == AMVP_SUCCESS);
}

static void setup_fail(void) {
    setup_empty_ctx(&ctx);

    rv = amvp_cap_kdf135_ikev1_enable(ctx, &dummy_handler_failure);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_IKEV1, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_IKEV1, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev1_set_domain(ctx, AMVP_KDF_IKEv1_INIT_NONCE_LEN, 64, 2048, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev1_set_domain(ctx, AMVP_KDF_IKEv1_RESPOND_NONCE_LEN, 64, 2048, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev1_set_domain(ctx, AMVP_KDF_IKEv1_DH_SECRET_LEN, 224, 8192, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev1_set_domain(ctx, AMVP_KDF_IKEv1_PSK_LEN, 8, 8192, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev1_set_parm(ctx, AMVP_KDF_IKEv1_HASH_ALG, AMVP_SHA1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev1_set_parm(ctx, AMVP_KDF_IKEv1_AUTH_METHOD, AMVP_KDF135_IKEV1_AMETH_PSK);
    cr_assert(rv == AMVP_SUCCESS);
}

static void teardown(void) {
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test capabilites API.
 */
Test(KDF135_IKEV1_CAPABILITY, good) {
    setup_empty_ctx(&ctx);

    rv = amvp_cap_kdf135_ikev1_enable(ctx, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_IKEV1, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_IKEV1, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev1_set_domain(ctx, AMVP_KDF_IKEv1_INIT_NONCE_LEN, 64, 2048, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev1_set_domain(ctx, AMVP_KDF_IKEv1_RESPOND_NONCE_LEN, 64, 2048, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev1_set_domain(ctx, AMVP_KDF_IKEv1_DH_SECRET_LEN, 224, 8192, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev1_set_domain(ctx, AMVP_KDF_IKEv1_PSK_LEN, 8, 8192, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev1_set_parm(ctx, AMVP_KDF_IKEv1_HASH_ALG, AMVP_SHA1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev1_set_parm(ctx, AMVP_KDF_IKEv1_AUTH_METHOD, AMVP_KDF135_IKEV1_AMETH_PSK);
    cr_assert(rv == AMVP_SUCCESS);

    teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 */
Test(KDF135_IKEV1_API, empty_ctx) {
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_UNSUPPORTED_OP);
    json_value_free(val);

end:
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test KAT handler API.
 * The ctx is NULL, expecting failure.
 */
Test(KDF135_IKEV1_API, null_ctx) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with NULL JSON object */
    rv  = amvp_kdf135_ikev1_kat_handler(NULL, obj);
    cr_assert(rv == AMVP_NO_CTX);
    json_value_free(val);
}

/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 */
Test(KDF135_IKEV1_API, null_json_obj, .init = setup, .fini = teardown) {
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, NULL);
    cr_assert(rv == AMVP_MALFORMED_JSON);
}

/*
 * This is a good JSON.
 * Expecting success.
 */
Test(KDF135_IKEV1_HANDLER, good, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_SUCCESS);
    json_value_free(val);
}


/*
 * The value for key:"algorithm" is wrong.
 */
Test(KDF135_IKEV1_HANDLER, wrong_algorithm, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The key:"hashAlg" is missing.
 */
Test(KDF135_IKEV1_HANDLER, missing_hashAlg, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The value for key:"hashAlg" is wrong.
 */
Test(KDF135_IKEV1_HANDLER, wrong_hashAlg, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The key:"authenticationMethod" is missing.
 */
Test(KDF135_IKEV1_HANDLER, missing_authenticationMethod, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The value for key:"authenticationMethod" is wrong.
 */
Test(KDF135_IKEV1_HANDLER, wrong_authenticationMethod, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The key:"nInitLength" is missing.
 */
Test(KDF135_IKEV1_HANDLER, missing_nInitLength, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The value for key:"nInitLength" is too small.
 */
Test(KDF135_IKEV1_HANDLER, small_nInitLength, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The value for key:"nInitLength" is too big.
 */
Test(KDF135_IKEV1_HANDLER, big_nInitLength, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The key:"nRespLength" is missing.
 */
Test(KDF135_IKEV1_HANDLER, missing_nRespLength, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The value for key:"nRespLength" is too small.
 */
Test(KDF135_IKEV1_HANDLER, small_nRespLength, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The value for key:"nRespLength" is too big.
 */
Test(KDF135_IKEV1_HANDLER, big_nRespLength, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The key:"dhLength" is missing.
 */
Test(KDF135_IKEV1_HANDLER, missing_dhLength, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The value for key:"dhLength" is too small.
 */
Test(KDF135_IKEV1_HANDLER, small_dhLength, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The value for key:"dhLength" is too big.
 */
Test(KDF135_IKEV1_HANDLER, big_dhLength, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_14.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The key:"preSharedKeyLength" is missing.
 */
Test(KDF135_IKEV1_HANDLER, missing_preSharedKeyLength, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_15.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The value for key:"preSharedKeyLength" is too small.
 */
Test(KDF135_IKEV1_HANDLER, small_preSharedKeyLength, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_16.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The value for key:"preSharedKeyLength" is too big.
 */
Test(KDF135_IKEV1_HANDLER, big_preSharedKeyLength, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_17.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The key:"nInit" is missing.
 */
Test(KDF135_IKEV1_HANDLER, missing_nInit, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_18.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The value for key:"nInit" has wrong string length.
 */
Test(KDF135_IKEV1_HANDLER, wrong_nInit, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_19.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The key:"nResp" is missing.
 */
Test(KDF135_IKEV1_HANDLER, missing_nResp, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_20.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The value for key:"nResp" has wrong string length.
 */
Test(KDF135_IKEV1_HANDLER, wrong_nResp, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_21.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The key:"ckyInit" is missing.
 */
Test(KDF135_IKEV1_HANDLER, missing_ckyInit, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_22.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The value for key:"ckyInit" string is too long.
 */
Test(KDF135_IKEV1_HANDLER, long_ckyInit, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_23.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The key:"ckyResp" is missing.
 */
Test(KDF135_IKEV1_HANDLER, missing_ckyResp, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_24.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The value for key:"ckyResp" string is too long.
 */
Test(KDF135_IKEV1_HANDLER, long_ckyResp, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_25.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The key:"gxy" is missing.
 */
Test(KDF135_IKEV1_HANDLER, missing_gxy, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_26.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The value for key:"gxy" string is too long.
 */
Test(KDF135_IKEV1_HANDLER, long_gxy, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_27.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The key:"preSharedKey" is missing.
 */
Test(KDF135_IKEV1_HANDLER, missing_preSharedKey, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_28.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}


/*
 * The value for key:"preSharedKey" string is too long.
 */
Test(KDF135_IKEV1_HANDLER, long_preSharedKey, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_29.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}


/*
 * The key:"tgId" is missing.
 */
Test(KDF135_IKEV1_HANDLER, missing_tgId, .init = setup, .fini = teardown) {
    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_30.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MALFORMED_JSON);
    json_value_free(val);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(Kdf135ikeV1Fail, cryptoFail1, .init = setup_fail, .fini = teardown) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration */
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(Kdf135ikeV1Fail, cryptoFail2, .init = setup_fail, .fini = teardown) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 9; /* fail on tenth iteration */
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * The key:"nInitLength" is missing in last tg
 */
Test(Kdf135ikeV1Fail, tgFail, .init = setup, .fini = teardown) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_31.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
}

/*
 * The key:"nInit" is missing in last tc
 */
Test(Kdf135ikeV1Fail, tcFail, .init = setup, .fini = teardown) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    val = json_parse_file("json/kdf135_ikev1/kdf135_ikev1_32.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ikev1_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
}

