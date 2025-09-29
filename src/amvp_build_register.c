/** @file */
/*
 * Copyright (c) 2025, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libamvp/LICENSE
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif
#include "amvp.h"
#include "amvp_lcl.h"
#include "parson.h"
#include "safe_str_lib.h"
#include "safe_mem_lib.h"

/*
 * This builds a cert req
 */
AMVP_RESULT amvp_build_registration_json(AMVP_CTX *ctx, JSON_Value **reg) {
    JSON_Value *val = NULL, *module_val = NULL;
    JSON_Array *req_arr = NULL;
    JSON_Object *cap_obj = NULL;

    int i = 0;
    if (!ctx) {
        AMVP_LOG_ERR("No ctx for build_test_session");
        return AMVP_NO_CTX;
    }
    if (ctx->cert_req_info.tester_count <= 0 && ctx->cert_req_info.reviewer_count <= 0) {
        AMVP_LOG_ERR("Cannot build cert req without any contact IDs");
        return AMVP_MISSING_ARG;
    }

    val = json_value_init_object();
    cap_obj = json_value_get_object(val);

    json_object_set_number(cap_obj, "vendorId", ctx->cert_req_info.vendor_id);

    /* Add testers array if we have any testers */
    if (ctx->cert_req_info.tester_count > 0) {
        json_object_set_value(cap_obj, "testers", json_value_init_array());
        req_arr = json_object_get_array(cap_obj, "testers");
        for (i = 0; i < ctx->cert_req_info.tester_count; i++) {
            json_array_append_string(req_arr, ctx->cert_req_info.tester_id[i]);
        }
    }

    /* Add reviewers array if we have any reviewers */
    if (ctx->cert_req_info.reviewer_count > 0) {
        json_object_set_value(cap_obj, "reviewers", json_value_init_array());
        req_arr = json_object_get_array(cap_obj, "reviewers");
        for (i = 0; i < ctx->cert_req_info.reviewer_count; i++) {
            json_array_append_string(req_arr, ctx->cert_req_info.reviewer_id[i]);
        }
    }

    /* Add ACV certificates if we have any */
    if (ctx->cert_req_info.acv_cert_count > 0) {
        json_object_set_value(cap_obj, "algorithmCertificates", json_value_init_array());
        req_arr = json_object_get_array(cap_obj, "algorithmCertificates");
        for (i = 0; i < ctx->cert_req_info.acv_cert_count; i++) {
            json_array_append_string(req_arr, ctx->cert_req_info.acv_cert[i]);
        }
    }

    /* Add ESV certificates if we have any */
    if (ctx->cert_req_info.esv_cert_count > 0) {
        json_object_set_value(cap_obj, "entropyCertificates", json_value_init_array());
        req_arr = json_object_get_array(cap_obj, "entropyCertificates");
        for (i = 0; i < ctx->cert_req_info.esv_cert_count; i++) {
            json_array_append_string(req_arr, ctx->cert_req_info.esv_cert[i]);
        }
    }
    module_val = json_parse_file(ctx->cert_req_info.module_file);
    if (!module_val) {
        AMVP_LOG_ERR("Provided module file is invalid or does not exist");
        json_value_free(val);
        return AMVP_INVALID_ARG;
    }

    json_object_set_value(cap_obj, "module", module_val);

    *reg = val;

    return AMVP_SUCCESS;
}
