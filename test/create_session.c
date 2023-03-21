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

AMVP_CTX *ctx;

Test(CreateSession, properly) {
    AMVP_RESULT rv;
    AMVP_LOG_LVL level = AMVP_LOG_LVL_STATUS;

    rv = amvp_create_test_session(&ctx, &progress, level);
    cr_assert(rv == AMVP_SUCCESS);

    teardown_ctx(&ctx);
}

Test(CreateSession, null_ctx) {
    AMVP_RESULT rv;
    AMVP_LOG_LVL level = AMVP_LOG_LVL_STATUS;

    rv = amvp_create_test_session(NULL, &progress, level);
    cr_assert(rv == AMVP_INVALID_ARG);

    teardown_ctx(&ctx);
}

Test(SetupSessionParams, proper_ctx_params) {
    AMVP_RESULT rv;
    AMVP_LOG_LVL level = AMVP_LOG_LVL_STATUS;
    char *server = "127.0.0.1";
    int port = 443;

    rv = amvp_create_test_session(&ctx, &progress, level);
    cr_assert(rv == AMVP_SUCCESS);

    /*
     * Next we setup ctx params
     */
    rv = amvp_set_server(ctx, server, port);
    cr_assert(rv == AMVP_SUCCESS);
#if 0
    rv = amvp_set_vendor_info(ctx, "Cisco", "www.cisco.com", "Unit Tests", "ut@123.com");
    cr_assert(rv == AMVP_SUCCESS);
#endif

    teardown_ctx(&ctx);
}

Test(SetupSessionParams, null_server_param) {
    AMVP_RESULT rv;
    AMVP_LOG_LVL level = AMVP_LOG_LVL_STATUS;
    char *server = NULL;
    int port = 443;

    rv = amvp_create_test_session(&ctx, &progress, level);
    cr_assert(rv == AMVP_SUCCESS);

    /*
     * Next we setup ctx params
     */
    rv = amvp_set_server(ctx, server, port);
    cr_assert(rv == AMVP_INVALID_ARG);

    teardown_ctx(&ctx);
}

#if 0
Test(SetupSessionParams, null_vendor_info_params) {
    AMVP_RESULT rv;
    setup_empty_ctx(&ctx);
    
    rv = amvp_set_vendor_info(ctx, NULL, "www.cisco.com", "Unit Tests", "ut@123.com");
    cr_assert(rv == AMVP_INVALID_ARG);
    rv = amvp_set_vendor_info(ctx, "Cisco", NULL, "Unit Tests", "ut@123.com");
    cr_assert(rv == AMVP_INVALID_ARG);
    rv = amvp_set_vendor_info(ctx, "Cisco", "www.cisco.com", NULL, "ut@123.com");
    cr_assert(rv == AMVP_INVALID_ARG);
    rv = amvp_set_vendor_info(ctx, "Cisco", "www.cisco.com", "Unit Tests", NULL);
    cr_assert(rv == AMVP_INVALID_ARG);
    
    teardown_ctx(&ctx);
}
#endif
