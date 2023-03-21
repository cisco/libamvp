/** @file */
/*
 * Copyright (c) 2020, Cisco Systems, Inc.
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

static void setup_pqggen(void)
{
    AMVP_RESULT rv;

    rv = amvp_cap_set_prereq(ctx, AMVP_DSA_PQGGEN, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_DSA_PQGGEN, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_GENPQ, AMVP_DSA_PROBABLE);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_GENG, AMVP_DSA_CANONICAL);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_LN2048_224, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_LN2048_224, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_LN2048_224, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_LN2048_224, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_LN2048_256, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_LN2048_256, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_LN2048_256, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_LN3072_256, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_LN3072_256, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_LN3072_256, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);
}

static void setup_keygen(void)
{
    AMVP_RESULT rv;

    rv = amvp_cap_set_prereq(ctx, AMVP_DSA_KEYGEN, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_DSA_KEYGEN, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_KEYGEN, AMVP_DSA_MODE_KEYGEN, AMVP_DSA_LN2048_224, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_KEYGEN, AMVP_DSA_MODE_KEYGEN, AMVP_DSA_LN2048_224, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_KEYGEN, AMVP_DSA_MODE_KEYGEN, AMVP_DSA_LN2048_224, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_KEYGEN, AMVP_DSA_MODE_KEYGEN, AMVP_DSA_LN2048_224, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_KEYGEN, AMVP_DSA_MODE_KEYGEN, AMVP_DSA_LN2048_256, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_KEYGEN, AMVP_DSA_MODE_KEYGEN, AMVP_DSA_LN2048_256, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_KEYGEN, AMVP_DSA_MODE_KEYGEN, AMVP_DSA_LN2048_256, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_KEYGEN, AMVP_DSA_MODE_KEYGEN, AMVP_DSA_LN2048_256, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_KEYGEN, AMVP_DSA_MODE_KEYGEN, AMVP_DSA_LN3072_256, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_KEYGEN, AMVP_DSA_MODE_KEYGEN, AMVP_DSA_LN3072_256, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_KEYGEN, AMVP_DSA_MODE_KEYGEN, AMVP_DSA_LN3072_256, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_KEYGEN, AMVP_DSA_MODE_KEYGEN, AMVP_DSA_LN3072_256, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);
}

static void setup_siggen(void)
{
    AMVP_RESULT rv;

    rv = amvp_cap_set_prereq(ctx, AMVP_DSA_SIGGEN, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_DSA_SIGGEN, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN2048_224, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN2048_224, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN2048_224, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN2048_224, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN2048_256, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN2048_256, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN2048_256, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN2048_256, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN3072_256, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN3072_256, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN3072_256, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN3072_256, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);
}


/*
 * Test DSA PQGGEN handler API inputs
 */
Test(DsaPqgGenApi, null_ctx) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);

    val = json_parse_file("json/dsa/dsa_pqggen1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with unregistered ctx */
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_UNSUPPORTED_OP);

    /* Enable capabilites */
    rv = amvp_cap_dsa_enable(ctx, AMVP_DSA_PQGGEN, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    setup_pqggen();

    /* Test with NULL ctx */
    rv  = amvp_dsa_kat_handler(NULL, obj);
    cr_assert(rv == AMVP_NO_CTX);

    /* Test with NULL JSON object */
    rv  = amvp_dsa_kat_handler(ctx, NULL);
    cr_assert(rv == AMVP_MALFORMED_JSON);
    json_value_free(val);

    teardown_ctx(&ctx);
}

/*
 * Test DSA PQGGEN handler functionally
 */
Test(DsaPqgGenFunc, null_ctx) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);

    /* Enable capabilites */
    rv = amvp_cap_dsa_enable(ctx, AMVP_DSA_PQGGEN, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    setup_pqggen();

    /* This is a proper JSON, positive test */
    val = json_parse_file("json/dsa/dsa_pqggen1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }

    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_SUCCESS);
    json_value_free(val);

    /* Test failing case, failed to include mode */
    val = json_parse_file("json/dsa/dsa_pqggen2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include l */
    val = json_parse_file("json/dsa/dsa_pqggen3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include n */
    val = json_parse_file("json/dsa/dsa_pqggen4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include hashAlg */
    val = json_parse_file("json/dsa/dsa_pqggen5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include pqMode */
    val = json_parse_file("json/dsa/dsa_pqggen6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include gmode */
    val = json_parse_file("json/dsa/dsa_pqggen7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);


    /* Test failing case, failed to include p */
    val = json_parse_file("json/dsa/dsa_pqggen8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include q */
    val = json_parse_file("json/dsa/dsa_pqggen9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include domainSeed */
    val = json_parse_file("json/dsa/dsa_pqggen10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include index */
    val = json_parse_file("json/dsa/dsa_pqggen11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Positive test case for coverage */
    val = json_parse_file("json/dsa/dsa_pqggen12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_SUCCESS);
    json_value_free(val);

    /* Missing tgId */
    val = json_parse_file("json/dsa/dsa_pqggen13.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MALFORMED_JSON);
    json_value_free(val);

    /* Missing tgId */
    val = json_parse_file("json/dsa/dsa_pqggen14.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Missing tgId */
    val = json_parse_file("json/dsa/dsa_pqggen15.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    teardown_ctx(&ctx);

}


/*
 * Test DSA KEYGEN handler API inputs
 */
Test(DsaKeyGenApi, null_ctx) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);

    val = json_parse_file("json/dsa/dsa_keygen1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with unregistered ctx */
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_UNSUPPORTED_OP);

    /* Enable capabilites */
    rv = amvp_cap_dsa_enable(ctx, AMVP_DSA_KEYGEN, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    setup_keygen();

    /* Test with NULL ctx */
    rv  = amvp_dsa_kat_handler(NULL, obj);
    cr_assert(rv == AMVP_NO_CTX);

    /* Test with NULL JSON object */
    rv  = amvp_dsa_kat_handler(ctx, NULL);
    cr_assert(rv == AMVP_MALFORMED_JSON);
    json_value_free(val);
    teardown_ctx(&ctx);
}

/*
 * Test DSA KEYGEN handler functionally
 */
Test(DsaKeyGenFunc, null_ctx) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);

    /* Enable capabilites */
    rv = amvp_cap_dsa_enable(ctx, AMVP_DSA_KEYGEN, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    setup_keygen();

    /* This is a proper JSON, positive test */
    val = json_parse_file("json/dsa/dsa_keygen1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }

    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_SUCCESS);
    json_value_free(val);

    /* Test failing case, failed to include mode */
    val = json_parse_file("json/dsa/dsa_keygen2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include l */
    val = json_parse_file("json/dsa/dsa_keygen3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include n */
    val = json_parse_file("json/dsa/dsa_keygen4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Positive test case for coverage */
    val = json_parse_file("json/dsa/dsa_keygen5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_SUCCESS);
    json_value_free(val);

    /* Positive test case for coverage */
    val = json_parse_file("json/dsa/dsa_keygen6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_SUCCESS);
    json_value_free(val);

    /* missing tgId */
    val = json_parse_file("json/dsa/dsa_keygen7.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MALFORMED_JSON);

    json_value_free(val);

    /* missing field in last tgId */
    val = json_parse_file("json/dsa/dsa_keygen8.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);

    json_value_free(val);

    /* missing field in last tcId */
    val = json_parse_file("json/dsa/dsa_keygen9.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    teardown_ctx(&ctx);

}


/*
 * Test DSA SIGGEN handler API inputs
 */
Test(DsaSigGenApi, null_ctx) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);

    val = json_parse_file("json/dsa/dsa_siggen1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with unregistered ctx */
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_UNSUPPORTED_OP);

    /* Enable capabilites */
    rv = amvp_cap_dsa_enable(ctx, AMVP_DSA_SIGGEN, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    setup_siggen();

    /* Test with NULL ctx */
    rv  = amvp_dsa_kat_handler(NULL, obj);
    cr_assert(rv == AMVP_NO_CTX);

    /* Test with NULL JSON object */
    rv  = amvp_dsa_kat_handler(ctx, NULL);
    cr_assert(rv == AMVP_MALFORMED_JSON);
    json_value_free(val);

    teardown_ctx(&ctx);
}

/*
 * Test DSA SIGGEN handler functionally
 */
Test(DsaSigGenFunc, null_ctx) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);

    /* Enable capabilites */
    rv = amvp_cap_dsa_enable(ctx, AMVP_DSA_SIGGEN, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    setup_siggen();

    /* This is a proper JSON, positive test */
    val = json_parse_file("json/dsa/dsa_siggen1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }

    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_SUCCESS);
    json_value_free(val);

    /* Test failing case, failed to include mode */
    val = json_parse_file("json/dsa/dsa_siggen2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include l */
    val = json_parse_file("json/dsa/dsa_siggen3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include n */
    val = json_parse_file("json/dsa/dsa_siggen4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include hashAlg */
    val = json_parse_file("json/dsa/dsa_siggen5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include message */
    val = json_parse_file("json/dsa/dsa_siggen6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);


    /* Test failing case, failed to include tests */
    val = json_parse_file("json/dsa/dsa_siggen7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include testGroup */
    val = json_parse_file("json/dsa/dsa_siggen8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include tcId */
    val = json_parse_file("json/dsa/dsa_siggen9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include tgId */
    val = json_parse_file("json/dsa/dsa_siggen10.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MALFORMED_JSON);
    json_value_free(val);

    /* Test failing case, missing field in last tgId */
    val = json_parse_file("json/dsa/dsa_siggen11.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, missing field in last tcId */
    val = json_parse_file("json/dsa/dsa_siggen12.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    teardown_ctx(&ctx);

}


/*
 * Test DSA SIGVER handler API inputs
 */
Test(DsaSigVerApi, null_ctx) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);

    val = json_parse_file("json/dsa/dsa_sigver1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with unregistered ctx */
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_UNSUPPORTED_OP);

    /* Enable capabilites */
    rv = amvp_cap_dsa_enable(ctx, AMVP_DSA_SIGVER, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_DSA_SIGVER, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_DSA_SIGVER, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_224, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_224, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_224, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_224, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_256, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_256, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_256, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_256, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN3072_256, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN3072_256, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN3072_256, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN3072_256, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);

    /* Test with NULL ctx */
    rv  = amvp_dsa_kat_handler(NULL, obj);
    cr_assert(rv == AMVP_NO_CTX);

    /* Test with NULL JSON object */
    rv  = amvp_dsa_kat_handler(ctx, NULL);
    cr_assert(rv == AMVP_MALFORMED_JSON);
    json_value_free(val);

    teardown_ctx(&ctx);
}

/*
 * Test DSA SIGVER handler functionally
 */
Test(DsaSigVerFunc, null_ctx) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);

    /* Enable capabilites */
    rv = amvp_cap_dsa_enable(ctx, AMVP_DSA_SIGVER, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_DSA_SIGVER, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_DSA_SIGVER, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_224, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_224, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_224, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_224, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_256, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_256, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_256, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_256, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN3072_256, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN3072_256, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN3072_256, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN3072_256, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);

    /* This is a proper JSON, positive test */
    val = json_parse_file("json/dsa/dsa_sigver1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }

    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_SUCCESS);
    json_value_free(val);

    /* Test failing case, failed to include mode */
    val = json_parse_file("json/dsa/dsa_sigver2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include l */
    val = json_parse_file("json/dsa/dsa_sigver3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include n */
    val = json_parse_file("json/dsa/dsa_sigver4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include hashAlg */
    val = json_parse_file("json/dsa/dsa_sigver5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include message */
    val = json_parse_file("json/dsa/dsa_sigver6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);


    /* Test failing case, failed to include tests */
    val = json_parse_file("json/dsa/dsa_sigver7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include testGroup */
    val = json_parse_file("json/dsa/dsa_sigver8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include tcId */
    val = json_parse_file("json/dsa/dsa_sigver9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include tcId */
    val = json_parse_file("json/dsa/dsa_sigver10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include tcId */
    val = json_parse_file("json/dsa/dsa_sigver11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include tcId */
    val = json_parse_file("json/dsa/dsa_sigver12.json");

    obj = ut_get_obj_from_rsp(val);
    cr_assert(obj != NULL);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include tcId */
    val = json_parse_file("json/dsa/dsa_sigver13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include tcId */
    val = json_parse_file("json/dsa/dsa_sigver14.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include tcId */
    val = json_parse_file("json/dsa/dsa_sigver15.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include tgId */
    val = json_parse_file("json/dsa/dsa_sigver16.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
    AMVP_LOG_ERR("JSON obj parse error");
    return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MALFORMED_JSON);
    json_value_free(val);

    /* Test failing case, missing field in last tgId */
    val = json_parse_file("json/dsa/dsa_sigver17.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, missing field in last tcId */
    val = json_parse_file("json/dsa/dsa_sigver18.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
    teardown_ctx(&ctx);

}

/*
 * Test DSA PQGVER handler API inputs
 */
Test(DsaPqgVerApi, null_ctx) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);

    val = json_parse_file("json/dsa/dsa_pqgver1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with unregistered ctx */
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_UNSUPPORTED_OP);

    /* Enable capabilites */
    rv = amvp_cap_dsa_enable(ctx, AMVP_DSA_PQGVER, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_DSA_PQGVER, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_DSA_PQGVER, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_GENPQ, AMVP_DSA_PROBABLE);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_GENG, AMVP_DSA_CANONICAL);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN2048_224, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN2048_224, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN2048_224, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN2048_224, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN2048_256, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN2048_256, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN2048_256, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN3072_256, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN3072_256, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN3072_256, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);

    /* Test with NULL ctx */
    rv  = amvp_dsa_kat_handler(NULL, obj);
    cr_assert(rv == AMVP_NO_CTX);

    /* Test with NULL JSON object */
    rv  = amvp_dsa_kat_handler(ctx, NULL);
    cr_assert(rv == AMVP_MALFORMED_JSON);
    json_value_free(val);

    teardown_ctx(&ctx);
}

/*
 * Test DSA PQGVER handler functionally
 */
Test(DsaPqgVerFunc, null_ctx) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);

    /* Enable capabilites */
    rv = amvp_cap_dsa_enable(ctx, AMVP_DSA_PQGVER, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_DSA_PQGVER, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_DSA_PQGVER, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_GENPQ, AMVP_DSA_PROBABLE);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_GENG, AMVP_DSA_CANONICAL);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN2048_224, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN2048_224, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN2048_224, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN2048_224, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN2048_256, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN2048_256, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN2048_256, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN3072_256, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN3072_256, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN3072_256, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);

    /* This is a proper JSON, positive test */
    val = json_parse_file("json/dsa/dsa_pqgver1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }

    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_SUCCESS);
    json_value_free(val);

    /* Test failing case, failed to include mode */
    val = json_parse_file("json/dsa/dsa_pqgver2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include l */
    val = json_parse_file("json/dsa/dsa_pqgver3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include n */
    val = json_parse_file("json/dsa/dsa_pqgver4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include hashAlg */
    val = json_parse_file("json/dsa/dsa_pqgver5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include message */
    val = json_parse_file("json/dsa/dsa_pqgver6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);


    /* Test failing case, failed to include tests */
    val = json_parse_file("json/dsa/dsa_pqgver7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include testGroup */
    val = json_parse_file("json/dsa/dsa_pqgver8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include tcId */
    val = json_parse_file("json/dsa/dsa_pqgver9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

#if 0
    /* Test failing case, failed to include counter */
    val = json_parse_file("json/dsa/dsa_pqgver10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
#endif

    /* Test failing case, failed to include tcId */
    val = json_parse_file("json/dsa/dsa_pqgver11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include tcId */
    val = json_parse_file("json/dsa/dsa_pqgver12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include tcId */
    val = json_parse_file("json/dsa/dsa_pqgver13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* Test failing case, failed to include tgId */
    val = json_parse_file("json/dsa/dsa_pqgver14.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MALFORMED_JSON);

    json_value_free(val);

    /* Test failing case, missing SHA in last tgId */
    val = json_parse_file("json/dsa/dsa_pqgver15.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);

    json_value_free(val);

    /* Test failing case, missing field in last tcId */
    val = json_parse_file("json/dsa/dsa_pqgver16.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    teardown_ctx(&ctx);

}

/*
 * This is a good JSON.
 * Will fail as defined by the counter values.
 */
Test(DsaPqgVer_HANDLER, cryptoFail1) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);
    /* Enable capabilites */
    rv = amvp_cap_dsa_enable(ctx, AMVP_DSA_PQGGEN, &dummy_handler_failure);
    cr_assert(rv == AMVP_SUCCESS);

    setup_pqggen();
    /* This is a proper JSON, positive test */
    val = json_parse_file("json/dsa/dsa_pqggen1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration of AFT */

    rv = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);

    teardown_ctx(&ctx);
}

/*
 * This is a good JSON.
 * Will fail as defined by the counter values.
 */
Test(DsaPqgVer_HANDLER, cryptoFail2) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);

    /* Enable capabilites */
    rv = amvp_cap_dsa_enable(ctx, AMVP_DSA_PQGGEN, &dummy_handler_failure);
    cr_assert(rv == AMVP_SUCCESS);

    setup_pqggen();
    /* This is a proper JSON, positive test */
    val = json_parse_file("json/dsa/dsa_pqggen1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 20;  /* fail on 21st(last) iteration of AFT */

    rv = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);

    teardown_ctx(&ctx);
}

/*
 * This is a good JSON.
 * Will fail as defined by the counter values.
 */
Test(DsaKeyGen_HANDLER, cryptoFail1) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);
    /* Enable capabilites */

    rv = amvp_cap_dsa_enable(ctx, AMVP_DSA_KEYGEN, &dummy_handler_failure);
    cr_assert(rv == AMVP_SUCCESS);

    setup_keygen();
    /* This is a proper JSON, positive test */
    val = json_parse_file("json/dsa/dsa_keygen1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration of AFT */

    rv = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);

    teardown_ctx(&ctx);
}

/*
 * This is a good JSON.
 * Will fail as defined by the counter values.
 */
Test(DsaKeyGen_HANDLER, cryptoFail2) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);

    /* Enable capabilites */
    rv = amvp_cap_dsa_enable(ctx, AMVP_DSA_KEYGEN, &dummy_handler_failure);
    cr_assert(rv == AMVP_SUCCESS);

    setup_keygen();
    /* This is a proper JSON, positive test */
    val = json_parse_file("json/dsa/dsa_keygen1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 9;  /* fail on 10th(last) iteration of AFT */

    rv = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);

    teardown_ctx(&ctx);
}

/*
 * This is a good JSON.
 * Will fail as defined by the counter values.
 */
Test(SigGen_HANDLER, cryptoFail1) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);
    /* Enable capabilites */

    rv = amvp_cap_dsa_enable(ctx, AMVP_DSA_SIGGEN, &dummy_handler_failure);
    cr_assert(rv == AMVP_SUCCESS);

    setup_siggen();
    /* This is a proper JSON, positive test */
    val = json_parse_file("json/dsa/dsa_siggen1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration of AFT */

    rv = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);

    teardown_ctx(&ctx);
}

/*
 * This is a good JSON.
 * Will fail as defined by the counter values.
 */
Test(SigGen_HANDLER, cryptoFail2) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;

    setup_empty_ctx(&ctx);

    /* Enable capabilites */
    rv = amvp_cap_dsa_enable(ctx, AMVP_DSA_SIGGEN, &dummy_handler_failure);
    cr_assert(rv == AMVP_SUCCESS);

    setup_siggen();
    /* This is a proper JSON, positive test */
    val = json_parse_file("json/dsa/dsa_siggen1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 2;  /* fail on 3rd(last) iteration of AFT */

    rv = amvp_dsa_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);

    teardown_ctx(&ctx);
}
