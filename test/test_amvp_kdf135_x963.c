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

AMVP_CTX *ctx;
static char cvalue[] = "same";

/*
 * Test kdf135 x963 handler API inputs
 */
Test(Kdf135x963Func, null_ctx) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);
      
    val = json_parse_file("json/kdf135_x963/kdf135_x963_1.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    
    /* Test with unregistered ctx */
    rv  = amvp_kdf135_x963_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_UNSUPPORTED_OP);

    teardown_ctx(&ctx);
    json_value_free(val);
}
/*
 * Test kdf135 x963 handler functionally
 */
Test(Kdf135x963Func1, null_ctx) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);
    
    val = json_parse_file("json/kdf135_x963/kdf135_x963_1.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    
    /* Enable capabilites */
    rv = amvp_cap_kdf135_x963_enable(ctx, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_X963, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_HASH_ALG, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_HASH_ALG, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_HASH_ALG, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_HASH_ALG, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_KEY_DATA_LEN, 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_KEY_DATA_LEN, 1024);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_FIELD_SIZE, 224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_FIELD_SIZE, 521);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_SHARED_INFO_LEN, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_SHARED_INFO_LEN, 1024);
    cr_assert(rv == AMVP_SUCCESS);

    /* Test with NULL ctx */
    rv  = amvp_kdf135_x963_kat_handler(NULL, obj);
    cr_assert(rv == AMVP_NO_CTX);

    teardown_ctx(&ctx);
    json_value_free(val);
}
/*
 * Test kdf135 x963 handler functionally
 */
Test(Kdf135x963Func2, null_obj) {
    AMVP_RESULT rv;
    //JSON_Object *obj;
    //JSON_Value *val;

    setup_empty_ctx(&ctx);
    
    /* Enable capabilites */
    rv = amvp_cap_kdf135_x963_enable(ctx, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_X963, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_HASH_ALG, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    
    /* Test with NULL JSON object */
    rv  = amvp_kdf135_ssh_kat_handler(ctx, NULL);
    cr_assert(rv == AMVP_MALFORMED_JSON);
    
    teardown_ctx(&ctx);
}

/*
 * Test kdf135 x963 handler functionally
 */
Test(Kdf135x963Func3, properly) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);

    /* Enable capabilites */
    rv = amvp_cap_kdf135_x963_enable(ctx, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_X963, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_HASH_ALG, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);

    /* This is a proper JSON */
    val = json_parse_file("json/kdf135_x963/kdf135_x963_1.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_x963_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_SUCCESS);
    
    teardown_ctx(&ctx);
    json_value_free(val);
}
/*
 * Test kdf135 x963 handler functionally
 */
Test(Kdf135x963Func4, missing) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);
    
    /* Enable capabilites */
    rv = amvp_cap_kdf135_x963_enable(ctx, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_X963, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_HASH_ALG, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    
    /* This is a corrupt JSON, missing field size */
    val = json_parse_file("json/kdf135_x963/kdf135_x963_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_x963_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    
    teardown_ctx(&ctx);
    json_value_free(val);
}

/*
 * Test kdf135 x963 handler functionally
 */
Test(Kdf135x963Func5, missing) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);
    
    /* Enable capabilites */
    rv = amvp_cap_kdf135_x963_enable(ctx, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_X963, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_HASH_ALG, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    
    /* This is a corrupt JSON, missing key data length */
    val = json_parse_file("json/kdf135_x963/kdf135_x963_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_x963_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    
    teardown_ctx(&ctx);
    json_value_free(val);
}
/*
 * Test kdf135 x963 handler functionally
 */
Test(Kdf135x963Func6, missing) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);
    
    /* Enable capabilites */
    rv = amvp_cap_kdf135_x963_enable(ctx, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_X963, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_HASH_ALG, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    
    /* This is a corrupt JSON, missing hash alg */
    val = json_parse_file("json/kdf135_x963/kdf135_x963_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_x963_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    
    teardown_ctx(&ctx);
    json_value_free(val);
}
/*
 * Test kdf135 x963 handler functionally
 */
Test(Kdf135x963Func7, invalid) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);
    
    /* Enable capabilites */
    rv = amvp_cap_kdf135_x963_enable(ctx, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_X963, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_HASH_ALG, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    
    /* This is a corrupt JSON, corrupt algorithm */
    val = json_parse_file("json/kdf135_x963/kdf135_x963_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_x963_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    
    teardown_ctx(&ctx);
    json_value_free(val);
}
/*
 * Test kdf135 x963 handler functionally
 */
Test(Kdf135x963Func8, missing) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);
    
    /* Enable capabilites */
    rv = amvp_cap_kdf135_x963_enable(ctx, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_X963, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_HASH_ALG, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    
    /* Test failing case, failed to include test array */
    val = json_parse_file("json/kdf135_x963/kdf135_x963_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_x963_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    
    teardown_ctx(&ctx);
    json_value_free(val);
}
/*
 * Test kdf135 x963 handler functionally
 */
Test(Kdf135x963Func9, missing) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);
    
    /* Enable capabilites */
    rv = amvp_cap_kdf135_x963_enable(ctx, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_X963, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_HASH_ALG, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    
    /* Test failing case, failed to include tests */
    val = json_parse_file("json/kdf135_x963/kdf135_x963_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_x963_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    
    teardown_ctx(&ctx);
    json_value_free(val);
}
/*
 * Test kdf135 x963 handler functionally
 */
Test(Kdf135x963Func10, missing) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);
    
    /* Enable capabilites */
    rv = amvp_cap_kdf135_x963_enable(ctx, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_X963, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_HASH_ALG, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    
    /* Test failing case, failed to include testGroups */
    val = json_parse_file("json/kdf135_x963/kdf135_x963_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_x963_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    
    teardown_ctx(&ctx);
    json_value_free(val);
}

/*
 * Test kdf135 x963 handler functionally
 */
Test(Kdf135x963Func11, missing) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);
    
    /* Enable capabilites */
    rv = amvp_cap_kdf135_x963_enable(ctx, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_X963, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_HASH_ALG, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    
    /* Test failing case, failed to include tcId */
    val = json_parse_file("json/kdf135_x963/kdf135_x963_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_x963_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    
    teardown_ctx(&ctx);
    json_value_free(val);
}

/*
 * Test kdf135 x963 handler functionally
 */
Test(Kdf135x963Func11, missing_tgid) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;
    
    setup_empty_ctx(&ctx);
    
    /* Enable capabilites */
    rv = amvp_cap_kdf135_x963_enable(ctx, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_X963, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_HASH_ALG, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    
    /* Test failing case, failed to include tcId */
    val = json_parse_file("json/kdf135_x963/kdf135_x963_10.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_x963_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MALFORMED_JSON);

    teardown_ctx(&ctx);
    json_value_free(val);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(Kdf135x963Fail, cryptoFail1) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);

    /* Enable capabilites */
    rv = amvp_cap_kdf135_x963_enable(ctx, &dummy_handler_failure);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_X963, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_HASH_ALG, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);

    val = json_parse_file("json/kdf135_x963/kdf135_x963_1.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration */
    rv  = amvp_kdf135_x963_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
    teardown_ctx(&ctx);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(Kdf135x963Fail, cryptoFail2) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);

    /* Enable capabilites */
    rv = amvp_cap_kdf135_x963_enable(ctx, &dummy_handler_failure);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_X963, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_HASH_ALG, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);

    val = json_parse_file("json/kdf135_x963/kdf135_x963_1.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 9; /* fail on tenth iteration */
    rv  = amvp_kdf135_x963_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
    teardown_ctx(&ctx);
}

/*
 * The key:"hashAlg" is missing in secong tg
 */
Test(Kdf135x963Fail, tgFail) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);

    /* Enable capabilites */
    rv = amvp_cap_kdf135_x963_enable(ctx, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_X963, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_HASH_ALG, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);

    val = json_parse_file("json/kdf135_x963/kdf135_x963_11.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_x963_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
    teardown_ctx(&ctx);
}

/*
 * The key:"z" is missing in last tc
 */
Test(Kdf135x963Fail, tcFail) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);

    /* Enable capabilites */
    rv = amvp_cap_kdf135_x963_enable(ctx, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_X963, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_HASH_ALG, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);

    val = json_parse_file("json/kdf135_x963/kdf135_x963_12.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_x963_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
    teardown_ctx(&ctx);
}

