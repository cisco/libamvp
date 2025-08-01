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
#include "amvp.h"
#include "amvp_lcl.h"
#include "amvp_error.h"
#include "safe_lib.h"

/* URI path segments for different endpoints */
#define AMVP_TEST_SESSIONS_URI "testSessions"
#define AMVP_FT_EVIDENCE_URI "evidence"
#define AMVP_SC_EVIDENCE_URI "sourceCode"
#define AMVP_SP_URI "securityPolicy"
#define AMVP_LOGIN_URI "login"

/* Helper function declarations */
static char* generate_sp_url(const char *url);
static char* build_endpoint_url(const char *base_url, const char *endpoint);
static AMVP_RESULT amvp_send_with_path_seg(AMVP_CTX *ctx,
                                           AMVP_NET_ACTION action,
                                           const char *uri,
                                           char *data,
                                           int data_len);

/*
 * Local sanity check function for context validation
 */
static AMVP_RESULT sanity_check_ctx(AMVP_CTX *ctx) {
    if (!ctx) {
        AMVP_LOG_ERR("Missing ctx");
        return AMVP_NO_CTX;
    }

    if (!ctx->server_port || !ctx->server_name) {
        AMVP_LOG_ERR("Call amvp_set_server to fill in server name and port");
        return AMVP_MISSING_ARG;
    }

    return AMVP_SUCCESS;
}

/*
 * Generic helper function to build endpoint URLs
 * Returns allocated string that caller must free, or NULL on error
 */
static char* build_endpoint_url(const char *base_url, const char *endpoint) {
    char *full_url = NULL;
    size_t endpoint_len;
    int url_len;

    if (!base_url || !endpoint) {
        return NULL;
    }

    endpoint_len = strnlen_s(endpoint, AMVP_ATTR_URL_MAX);
    url_len = strnlen_s(base_url, AMVP_ATTR_URL_MAX + 1);
    if (url_len > AMVP_ATTR_URL_MAX - endpoint_len - 1) { /* -1 for '/' separator */
        return NULL;
    }

    full_url = calloc(AMVP_ATTR_URL_MAX + 1, sizeof(char));
    if (!full_url) {
        return NULL;
    }
    snprintf(full_url, AMVP_ATTR_URL_MAX, "%s/%s", base_url, endpoint);
    return full_url;
}

/*
 * Helper function to send data with path segment
 */
static AMVP_RESULT amvp_send_with_path_seg(AMVP_CTX *ctx,
                                           AMVP_NET_ACTION action,
                                           const char *uri,
                                           char *data,
                                           int data_len) {
    AMVP_RESULT rv = 0;
    char url[AMVP_ATTR_URL_MAX] = {0};

    rv = sanity_check_ctx(ctx);
    if (AMVP_SUCCESS != rv) return rv;

    if (!ctx->path_segment) {
        AMVP_LOG_ERR("No path segment, need to call amvp_set_path_segment first");
        return AMVP_MISSING_ARG;
    }

    snprintf(url, AMVP_ATTR_URL_MAX - 1, "https://%s:%d%s%s", ctx->server_name,
             ctx->server_port, ctx->path_segment, uri);

    return amvp_network_action(ctx, action, url, data, data_len);
}

/*
 * This is the transport function used within libamvp to register
 * the DUT attributes with the AMVP server.
 *
 * The reg parameter is the JSON encoded registration message that
 * will be sent to the server.
 */
AMVP_RESULT amvp_send_test_session_registration(AMVP_CTX *ctx,
                                                char *reg,
                                                int len) {
    return amvp_send_with_path_seg(ctx, AMVP_NET_POST,
                                   AMVP_TEST_SESSIONS_URI, reg, len);
}

/*
 * Send evidence (functional test or source code) to the server
 */
AMVP_RESULT amvp_send_evidence(AMVP_CTX *ctx,
                               AMVP_EVIDENCE_TYPE type,
                               const char *url,
                               char *ev,
                               int ev_len) {
    char *full_url = NULL;
    const char *type_endpoint = NULL;
    AMVP_RESULT rv;

    switch (type) {
    case AMVP_EVIDENCE_TYPE_FUNCTIONAL_TEST:
        type_endpoint = AMVP_FT_EVIDENCE_URI;
        break;
    case AMVP_EVIDENCE_TYPE_SOURCE_CODE:
        type_endpoint = AMVP_SC_EVIDENCE_URI;
        break;
    case AMVP_EVIDENCE_TYPE_NA:
    case AMVP_EVIDENCE_TYPE_MAX:
    default:
        AMVP_LOG_ERR("Cannot create evidence URL with given type");
        return AMVP_INVALID_ARG;
    }

    full_url = build_endpoint_url(url, type_endpoint);
    if (!full_url) {
        AMVP_LOG_ERR("Failed to build URL for submitting evidence");
        return AMVP_TRANSPORT_FAIL;
    }

    rv = amvp_transport_post(ctx, full_url, ev, ev_len);
    free(full_url);
    return rv;
}

/*
 * Helper function to generate security policy URL
 */
static char* generate_sp_url(const char *url) {
    return build_endpoint_url(url, AMVP_SP_URI);
}

/*
 * Send security policy to the server
 */
AMVP_RESULT amvp_send_security_policy(AMVP_CTX *ctx,
                                      const char *url,
                                      char *sp,
                                      int sp_len) {
    char *full_url = NULL;
    AMVP_RESULT rv;

    full_url = generate_sp_url(url);
    if (!full_url) {
        AMVP_LOG_ERR("Failed to build URL for security policy operation");
        return AMVP_TRANSPORT_FAIL;
    }

    rv = amvp_transport_post(ctx, full_url, sp, sp_len);
    free(full_url);
    return rv;
}

/*
 * Request security policy generation from the server
 */
AMVP_RESULT amvp_request_security_policy_generation(AMVP_CTX *ctx,
                                                    const char *url,
                                                    char *data) {
    char *full_url = NULL;
    AMVP_RESULT rv;

    full_url = generate_sp_url(url);
    if (!full_url) {
        AMVP_LOG_ERR("Failed to build URL for security policy operation");
        return AMVP_TRANSPORT_FAIL;
    }

    rv = amvp_transport_put(ctx, full_url, (const char*)data, strnlen_s(data, AMVP_CURL_BUF_MAX));
    free(full_url);
    return rv;
}

/*
 * Get security policy JSON from the server
 */
AMVP_RESULT amvp_get_security_policy_json(AMVP_CTX *ctx,
                                          const char *url) {
    char *full_url = NULL;
    AMVP_RESULT rv;
    full_url = build_endpoint_url(url, AMVP_SP_URI);
    if (!full_url) {
        AMVP_LOG_ERR("Failed to build URL for getting security policy");
        return AMVP_TRANSPORT_FAIL;
    }

    rv = amvp_transport_get(ctx, full_url, NULL);
    free(full_url);
    return rv;
}

/*
 * This is the transport function used within libamvp to login before
 * it is able to register parameters with the server
 *
 * The login parameter is the JSON encoded login message that
 * will be sent to the server.
 */
AMVP_RESULT amvp_send_login(AMVP_CTX *ctx,
                            char *login,
                            int len) {
    return amvp_send_with_path_seg(ctx, AMVP_NET_POST,
                                   AMVP_LOGIN_URI, login, len);
}
