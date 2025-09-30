/** @file */
/*
 * Copyright (c) 2025, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libamvp/LICENSE
 */

/*
 * Transport utility functions shared between networking implementations
 * These functions handle HTTP status analysis, logging, context validation,
 * URL encoding, and user agent generation - all networking-agnostic.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "amvp.h"
#include "amvp_lcl.h"
#include "amvp_error.h"
#include "safe_lib.h"

/*
 * Constants used by transport utility functions
 */
#define HTTP_OK    200
#define HTTP_UNAUTH    401
#define HTTP_BAD_REQ 400

#define AMVP_URL_ENCODE_BUFFER_SIZE     4
#define AMVP_HTTP_SUCCESS_MIN           200
#define AMVP_HTTP_SUCCESS_MAX           300

#define JWT_EXPIRED_STR "JWT expired"
#define JWT_EXPIRED_STR_LEN 11
#define JWT_INVALID_STR "JWT signature does not match"
#define JWT_INVALID_STR_LEN 28

/*
 * Context sanity check - ensures server name and port are set
 */
AMVP_RESULT sanity_check_ctx(AMVP_CTX *ctx) {
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
 * HTTP status code inspection - handles JWT validation and error parsing
 */
AMVP_RESULT inspect_http_code(AMVP_CTX *ctx, int code) {
    AMVP_RESULT result = AMVP_TRANSPORT_FAIL; /* Generic failure */
    JSON_Value *root_value = NULL;
    const JSON_Object *obj = NULL;
    const char *err_str = NULL;
    char *tmp_err_str = NULL;

    if (code == HTTP_OK) {
        /* 200 */
        return AMVP_SUCCESS;
    } else if (amvp_is_protocol_error_message(ctx->curl_buf)) {
        /* If anything can be handled by the transport layer here, do it, otherwise return to sender */
        /* Check if JWT expired, and try to refresh if so */
        if (ctx->error) {
            /* Assume we are trying to handle an existing error and have failed yet again */
            return AMVP_TRANSPORT_FAIL;
        }
        ctx->error = amvp_parse_protocol_error(ctx->curl_buf);
        return AMVP_PROTOCOL_RSP_ERR; /* Let the caller handle the error */
    }

    if (code == HTTP_BAD_REQ) {
        return AMVP_UNSUPPORTED_OP;
    }

    if (code == HTTP_UNAUTH) {
        char *diff = NULL;

        root_value = json_parse_string(ctx->curl_buf);
        obj = json_value_get_object(root_value);
        if (!obj) {
            AMVP_LOG_ERR("HTTP body doesn't contain expected top-level object");
            goto end;
        }
        err_str = json_object_get_string(obj, "error");
        if (!err_str) {
            AMVP_LOG_ERR("JSON object doesn't contain 'error'");
            goto end;
        }

        int err_str_len = strnlen_s(err_str, AMVP_CURL_BUF_MAX);
        tmp_err_str = calloc(sizeof(char), err_str_len + 1);
        if (!tmp_err_str) {
        AMVP_LOG_WARN("Issue while allocating memory to check message from server, trying to continue...");
            goto end;
        }

        if (strncpy_s(tmp_err_str, err_str_len + 1, err_str, err_str_len)) {
        AMVP_LOG_WARN("Issue while checking message from server, trying to continue...");
            goto end;
        }

        strstr_s(tmp_err_str, AMVP_CURL_BUF_MAX, JWT_EXPIRED_STR, JWT_EXPIRED_STR_LEN, &diff);

        if (diff) {
            result = AMVP_JWT_EXPIRED;
            goto end;
        }

        strstr_s(tmp_err_str, AMVP_CURL_BUF_MAX, JWT_INVALID_STR, JWT_INVALID_STR_LEN, &diff);
        if (diff) {
            result = AMVP_JWT_INVALID;
            goto end;
        }
    }

end:
    if (root_value) json_value_free(root_value);
    if (tmp_err_str) free(tmp_err_str);
    return result;
}

/*
 * Log network status - logs HTTP requests and responses
 */
void log_network_status(AMVP_CTX *ctx,
                        AMVP_NET_ACTION action,
                        int http_code,
                        const char *url) {

    switch(action) {
    case AMVP_NET_GET:
        AMVP_LOG_VERBOSE("GET...\n\tStatus: %d\n\tUrl: %s\n\tResp:\n%s\n",
                      http_code, url, ctx->curl_buf);
        break;

    case AMVP_NET_POST:
        AMVP_LOG_VERBOSE("POST...\n\tStatus: %d\n\tUrl: %s\n\tResp: %s\n",
                        http_code, url, ctx->curl_buf);
        break;

    case AMVP_NET_POST_MULTIPART:
    AMVP_LOG_VERBOSE("POST multipart...\n\tStatus: %d\n\tUrl: %s\n\tResp: %s\n",
                    http_code, url, ctx->curl_buf);
    break;

    case AMVP_NET_PUT:
        AMVP_LOG_VERBOSE("PUT...\n\tStatus: %d\n\tUrl: %s\n\tResp: %s\n",
                        http_code, url, ctx->curl_buf);
        break;

    case AMVP_NET_DELETE:
        AMVP_LOG_VERBOSE("DELETE...\n\tStatus: %d\n\tUrl: %s\n\tResp:\n%s\n",
                       http_code, url, ctx->curl_buf);
        break;
    default:
        AMVP_LOG_ERR("We should never be here!");
        break;
    }

    if (http_code == 0) {
        AMVP_LOG_ERR("Received no response from server.");
    } else if (http_code < AMVP_HTTP_SUCCESS_MIN || http_code >= AMVP_HTTP_SUCCESS_MAX) {
        /* Check if this might be a protocol error that can be handled automatically. */
        if (ctx && amvp_is_protocol_error_message(ctx->curl_buf)) {
            /* This is likely a protocol error - let the handler log appropriately */
            AMVP_LOG_VERBOSE("HTTP %d response contains protocol error message", http_code);
        } else {
            /* This is a non-protocol error that should be logged */
            AMVP_LOG_ERR("%d error received from server. Message:", http_code);
            AMVP_LOG_ERR("%s", ctx->curl_buf);
        }
    }
}
