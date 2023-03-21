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
 * Test kdf135 SSH handler API inputs
 */
Test(Kdf135SshApi, null_ctx) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;
    int flags = 0;

    setup_empty_ctx(&ctx);

    val = json_parse_file("json/kdf135_ssh/kdf135_ssh1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with unregistered ctx */
    rv  = amvp_kdf135_ssh_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_UNSUPPORTED_OP);

    /* Enable capabilites */
    rv = amvp_cap_kdf135_ssh_enable(ctx, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_SSH, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_SSH, AMVP_PREREQ_TDES, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_SSH, AMVP_PREREQ_AES, cvalue);
    cr_assert(rv == AMVP_SUCCESS);

    //Bit flags for kdf135_ssh sha capabilities
    flags = AMVP_SHA1 | AMVP_SHA224 |AMVP_SHA256
    | AMVP_SHA384 | AMVP_SHA512;

    rv = amvp_cap_kdf135_ssh_set_parm(ctx, AMVP_KDF135_SSH, AMVP_SSH_METH_TDES_CBC, flags);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ssh_set_parm(ctx, AMVP_KDF135_SSH, AMVP_SSH_METH_AES_128_CBC, flags);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ssh_set_parm(ctx, AMVP_KDF135_SSH, AMVP_SSH_METH_AES_192_CBC, flags);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ssh_set_parm(ctx, AMVP_KDF135_SSH, AMVP_SSH_METH_AES_256_CBC, flags);
    cr_assert(rv == AMVP_SUCCESS);

    /* Test with NULL ctx */
    rv  = amvp_kdf135_ssh_kat_handler(NULL, obj);
    cr_assert(rv == AMVP_NO_CTX);

    /* Test with NULL JSON object */
    rv  = amvp_kdf135_ssh_kat_handler(ctx, NULL);
    cr_assert(rv == AMVP_MALFORMED_JSON);

    teardown_ctx(&ctx);
    json_value_free(val);
}

/*
 * Test kdf135 SSH handler functionally
 */
Test(Kdf135SshFunc, null_ctx) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;
    int flags = 0;

    setup_empty_ctx(&ctx);

    /* Enable capabilites */
    rv = amvp_cap_kdf135_ssh_enable(ctx, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_SSH, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_SSH, AMVP_PREREQ_TDES, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_SSH, AMVP_PREREQ_AES, cvalue);
    cr_assert(rv == AMVP_SUCCESS);

    //Bit flags for kdf135_ssh sha capabilities
    flags = AMVP_SHA1 | AMVP_SHA224 |AMVP_SHA256
    | AMVP_SHA384 | AMVP_SHA512;

    rv = amvp_cap_kdf135_ssh_set_parm(ctx, AMVP_KDF135_SSH, AMVP_SSH_METH_TDES_CBC, flags);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ssh_set_parm(ctx, AMVP_KDF135_SSH, AMVP_SSH_METH_AES_128_CBC, flags);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ssh_set_parm(ctx, AMVP_KDF135_SSH, AMVP_SSH_METH_AES_192_CBC, flags);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ssh_set_parm(ctx, AMVP_KDF135_SSH, AMVP_SSH_METH_AES_256_CBC, flags);
    cr_assert(rv == AMVP_SUCCESS);


    /* This is a proper JSON, positive test TDES SHA-1 */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ssh_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_SUCCESS);
    json_value_free(val);

    /* This is a corrupt JSON, missing cipher */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ssh_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
    
    /* This is a corrupt JSON, missing hashAlg */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ssh_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
    
    /* This is a corrupt JSON, failed to include k */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ssh_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
    
    /* This is a corrupt JSON, failed to include h */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ssh_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
    
    /* This is a corrupt JSON, failed to include session_id */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ssh_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* This is a corrupt JSON, corrupt algorithm */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ssh_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_INVALID_ARG);
    json_value_free(val);

    /* This is a corrupt JSON, failed to include tests */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ssh_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* This is a corrupt JSON, failed to include testGroups */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ssh_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* This is a corrupt JSON, failed to include tc_id */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ssh_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);

    /* This is a proper JSON, positive test AES-128 thru 256 SHA-224 thru SHA-512 */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ssh_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_SUCCESS);
    json_value_free(val);

    /* This is a corrupt JSON, failed to include tgid */
    val = json_parse_file("json/kdf135_ssh/kdf135_ssh12.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ssh_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MALFORMED_JSON);
    json_value_free(val);

    teardown_ctx(&ctx);

}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(Kdf135SshFail, cryptoFail1) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;
    int flags = 0;

    setup_empty_ctx(&ctx);

    /* Enable capabilites */
    rv = amvp_cap_kdf135_ssh_enable(ctx, &dummy_handler_failure);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_SSH, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_SSH, AMVP_PREREQ_TDES, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_SSH, AMVP_PREREQ_AES, cvalue);
    cr_assert(rv == AMVP_SUCCESS);

    //Bit flags for kdf135_ssh sha capabilities
    flags = AMVP_SHA1 | AMVP_SHA224 |AMVP_SHA256
    | AMVP_SHA384 | AMVP_SHA512;

    rv = amvp_cap_kdf135_ssh_set_parm(ctx, AMVP_KDF135_SSH, AMVP_SSH_METH_TDES_CBC, flags);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ssh_set_parm(ctx, AMVP_KDF135_SSH, AMVP_SSH_METH_AES_128_CBC, flags);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ssh_set_parm(ctx, AMVP_KDF135_SSH, AMVP_SSH_METH_AES_192_CBC, flags);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ssh_set_parm(ctx, AMVP_KDF135_SSH, AMVP_SSH_METH_AES_256_CBC, flags);
    cr_assert(rv == AMVP_SUCCESS);

    val = json_parse_file("json/kdf135_ssh/kdf135_ssh1.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 9; /* fail on first iteration */
    rv  = amvp_kdf135_ssh_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
    teardown_ctx(&ctx);
}

/*
 * The key: crypto handler operation fails on last crypto call
 */
Test(Kdf135SshFail, cryptoFail2) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;
    int flags = 0;

    setup_empty_ctx(&ctx);

    /* Enable capabilites */
    rv = amvp_cap_kdf135_ssh_enable(ctx, &dummy_handler_failure);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_SSH, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_SSH, AMVP_PREREQ_TDES, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_SSH, AMVP_PREREQ_AES, cvalue);
    cr_assert(rv == AMVP_SUCCESS);

    //Bit flags for kdf135_ssh sha capabilities
    flags = AMVP_SHA1 | AMVP_SHA224 |AMVP_SHA256
    | AMVP_SHA384 | AMVP_SHA512;

    rv = amvp_cap_kdf135_ssh_set_parm(ctx, AMVP_KDF135_SSH, AMVP_SSH_METH_TDES_CBC, flags);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ssh_set_parm(ctx, AMVP_KDF135_SSH, AMVP_SSH_METH_AES_128_CBC, flags);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ssh_set_parm(ctx, AMVP_KDF135_SSH, AMVP_SSH_METH_AES_192_CBC, flags);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ssh_set_parm(ctx, AMVP_KDF135_SSH, AMVP_SSH_METH_AES_256_CBC, flags);
    cr_assert(rv == AMVP_SUCCESS);


    val = json_parse_file("json/kdf135_ssh/kdf135_ssh1.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 9; /* fail on last iteration */
    rv  = amvp_kdf135_ssh_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
    teardown_ctx(&ctx);
}

/*
 * The key:"cipher" is missing in secong tg
 */
Test(Kdf135SshFail, tcidFail) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;
    int flags = 0;

    setup_empty_ctx(&ctx);

    /* Enable capabilites */
    rv = amvp_cap_kdf135_ssh_enable(ctx, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_SSH, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_SSH, AMVP_PREREQ_TDES, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_SSH, AMVP_PREREQ_AES, cvalue);
    cr_assert(rv == AMVP_SUCCESS);

    //Bit flags for kdf135_ssh sha capabilities
    flags = AMVP_SHA1 | AMVP_SHA224 |AMVP_SHA256
    | AMVP_SHA384 | AMVP_SHA512;

    rv = amvp_cap_kdf135_ssh_set_parm(ctx, AMVP_KDF135_SSH, AMVP_SSH_METH_TDES_CBC, flags);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ssh_set_parm(ctx, AMVP_KDF135_SSH, AMVP_SSH_METH_AES_128_CBC, flags);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ssh_set_parm(ctx, AMVP_KDF135_SSH, AMVP_SSH_METH_AES_192_CBC, flags);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ssh_set_parm(ctx, AMVP_KDF135_SSH, AMVP_SSH_METH_AES_256_CBC, flags);
    cr_assert(rv == AMVP_SUCCESS);

    val = json_parse_file("json/kdf135_ssh/kdf135_ssh13.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ssh_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
    teardown_ctx(&ctx);
}

/*
 * The key:"h" is missing in last tc
 */
Test(Kdf135SshFail, tcFail) {
    AMVP_RESULT rv;
    JSON_Object *obj;
    JSON_Value *val;
    int flags = 0;

    setup_empty_ctx(&ctx);

    /* Enable capabilites */
    rv = amvp_cap_kdf135_ssh_enable(ctx, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_SSH, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_SSH, AMVP_PREREQ_TDES, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_SSH, AMVP_PREREQ_AES, cvalue);
    cr_assert(rv == AMVP_SUCCESS);

    //Bit flags for kdf135_ssh sha capabilities
    flags = AMVP_SHA1 | AMVP_SHA224 |AMVP_SHA256
    | AMVP_SHA384 | AMVP_SHA512;

    rv = amvp_cap_kdf135_ssh_set_parm(ctx, AMVP_KDF135_SSH, AMVP_SSH_METH_TDES_CBC, flags);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ssh_set_parm(ctx, AMVP_KDF135_SSH, AMVP_SSH_METH_AES_128_CBC, flags);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ssh_set_parm(ctx, AMVP_KDF135_SSH, AMVP_SSH_METH_AES_192_CBC, flags);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ssh_set_parm(ctx, AMVP_KDF135_SSH, AMVP_SSH_METH_AES_256_CBC, flags);
    cr_assert(rv == AMVP_SUCCESS);

    val = json_parse_file("json/kdf135_ssh/kdf135_ssh14.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_kdf135_ssh_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_MISSING_ARG);
    json_value_free(val);
    teardown_ctx(&ctx);
}

