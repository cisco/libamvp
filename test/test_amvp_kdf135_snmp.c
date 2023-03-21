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
 * Test kdf135 SNMP handler API inputs
 */
Test(Kdf135SnmpApi, null_ctx) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);

    val = json_parse_file("json/kdf135_snmp/kdf135_snmp1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with unregistered ctx */
    rv  = amvp_kdf135_snmp_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_UNSUPPORTED_OP);

    /* Enable capabilites */
    rv = amvp_cap_kdf135_snmp_enable(ctx, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_SNMP, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_snmp_set_parm(ctx, AMVP_KDF135_SNMP, AMVP_KDF135_SNMP_PASS_LEN, 64);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_snmp_set_engid(ctx, AMVP_KDF135_SNMP, "AB37BDE5657AB");
    cr_assert(rv == AMVP_SUCCESS);


    /* Test with NULL ctx */
    rv  = amvp_kdf135_snmp_kat_handler(NULL, obj);
    cr_assert(rv == AMVP_NO_CTX);

    /* Test with NULL JSON object */
    rv  = amvp_kdf135_snmp_kat_handler(ctx, NULL);
    cr_assert(rv == AMVP_MALFORMED_JSON);

    teardown_ctx(&ctx);
    json_value_free(val);
}

/*
 * Test kdf135 SNMP handler functionally
 */
Test(Kdf135SnmpFunc, null_ctx) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);

    /* Enable capabilites */
    rv = amvp_cap_kdf135_snmp_enable(ctx, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_SNMP, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_snmp_set_parm(ctx, AMVP_KDF135_SNMP, AMVP_KDF135_SNMP_PASS_LEN, 64);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_snmp_set_engid(ctx, AMVP_KDF135_SNMP, "AB37BDE5657AB");
    cr_assert(rv == AMVP_SUCCESS);

    /* This is a proper JSON, positive test */
    val = json_parse_file("json/kdf135_snmp/kdf135_snmp1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_snmp_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_SUCCESS);
    json_value_free(val);


    /* This is a corrupt JSON, missing engineId */
    val = json_parse_file("json/kdf135_snmp/kdf135_snmp2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_snmp_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
    

    /* This is a corrupt JSON, missing passwordLength */
    val = json_parse_file("json/kdf135_snmp/kdf135_snmp3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_snmp_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
    
    /* This is a corrupt JSON, password does not match passwordLength */
    val = json_parse_file("json/kdf135_snmp/kdf135_snmp4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_snmp_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);
    
    /* This is a corrupt JSON, password not in test case */
    val = json_parse_file("json/kdf135_snmp/kdf135_snmp5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_snmp_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
    
    /* This is a corrupt JSON, no tests */
    val = json_parse_file("json/kdf135_snmp/kdf135_snmp6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_snmp_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
    
    /* This is a corrupt JSON, no testGroups */
    val = json_parse_file("json/kdf135_snmp/kdf135_snmp7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_snmp_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
    
    /* This is a corrupt JSON, no tcId */
    val = json_parse_file("json/kdf135_snmp/kdf135_snmp8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_snmp_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
    
    /* This is a corrupt JSON, corrupt algorithm */
    val = json_parse_file("json/kdf135_snmp/kdf135_snmp9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_snmp_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);

    /* This is a corrupt JSON, no tgId */
    val = json_parse_file("json/kdf135_snmp/kdf135_snmp_10.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_snmp_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MALFORMED_JSON);
    json_value_free(val);

    teardown_ctx(&ctx);

}

/*
 * The key: crypto handler operation fails on first call
 */
Test(Kdf135SnmpFail, cryptoFail1) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);

    /* Enable capabilites */
    rv = amvp_cap_kdf135_snmp_enable(ctx, &dummy_handler_failure);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_SNMP, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_snmp_set_parm(ctx, AMVP_KDF135_SNMP, AMVP_KDF135_SNMP_PASS_LEN, 64);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_snmp_set_engid(ctx, AMVP_KDF135_SNMP, "AB37BDE5657AB");
    cr_assert(rv == AMVP_SUCCESS);

    val = json_parse_file("json/kdf135_snmp/kdf135_snmp1.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration */
    rv  = amvp_kdf135_snmp_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
    teardown_ctx(&ctx);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(Kdf135SnmpFail, cryptoFail2) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);

    /* Enable capabilites */
    rv = amvp_cap_kdf135_snmp_enable(ctx, &dummy_handler_failure);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_SNMP, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_snmp_set_parm(ctx, AMVP_KDF135_SNMP, AMVP_KDF135_SNMP_PASS_LEN, 64);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_snmp_set_engid(ctx, AMVP_KDF135_SNMP, "AB37BDE5657AB");
    cr_assert(rv == AMVP_SUCCESS);

    val = json_parse_file("json/kdf135_snmp/kdf135_snmp1.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 9; /* fail on tenth iteration */
    rv  = amvp_kdf135_snmp_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
    teardown_ctx(&ctx);
}

/*
 * The key:"engineId" is missing in secong tg
 */
Test(Kdf135SnmpFail, tcidFail) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);

    /* Enable capabilites */
    rv = amvp_cap_kdf135_snmp_enable(ctx, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_SNMP, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_snmp_set_parm(ctx, AMVP_KDF135_SNMP, AMVP_KDF135_SNMP_PASS_LEN, 64);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_snmp_set_engid(ctx, AMVP_KDF135_SNMP, "AB37BDE5657AB");
    cr_assert(rv == AMVP_SUCCESS);

    val = json_parse_file("json/kdf135_snmp/kdf135_snmp11.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_snmp_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
    teardown_ctx(&ctx);
}

/*
 * The key:"password" is missing in eighth tc
 */
Test(Kdf135SnmpFail, tcFail) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);

    /* Enable capabilites */
    rv = amvp_cap_kdf135_snmp_enable(ctx, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_SNMP, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_snmp_set_parm(ctx, AMVP_KDF135_SNMP, AMVP_KDF135_SNMP_PASS_LEN, 64);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_snmp_set_engid(ctx, AMVP_KDF135_SNMP, "AB37BDE5657AB");
    cr_assert(rv == AMVP_SUCCESS);

    val = json_parse_file("json/kdf135_snmp/kdf135_snmp12.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_snmp_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
    teardown_ctx(&ctx);
}

