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
 * Implementation-agnostic HTTP transport layer.
 * Provides common network logic and delegates platform-specific calls.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "amvp.h"
#include "amvp_lcl.h"
#include "amvp_error.h"
#include "safe_lib.h"

/*
 * Implementation-agnostic network action dispatcher
 * Builds full URLs and handles validation, JWT logic, retry logic, and delegates HTTP calls
 */
AMVP_RESULT amvp_network_action(AMVP_CTX *ctx, AMVP_NET_ACTION action,
                               const char *endpoint_path, const char *data, int data_len) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    AMVP_RESULT result = 0;
    AMVP_NET_ACTION generic_action = 0;
    int check_data = 0;
    int response_code = 0;
    char *full_url = NULL;

    /* Input validation */
    if (!ctx) {
        AMVP_LOG_ERR("Missing ctx");
        return AMVP_NO_CTX;
    }

    if (!endpoint_path) {
        AMVP_LOG_ERR("Endpoint path required for transmission");
        return AMVP_MISSING_ARG;
    }

    if (!ctx->server_name) {
        AMVP_LOG_ERR("Missing server configuration");
        return AMVP_MISSING_ARG;
    }

    /* Build full URL: https://server:port{endpoint_path} */
    /* Note: endpoint_path should be a complete path from root */
    full_url = calloc(AMVP_ATTR_URL_MAX + 1, sizeof(char));
    if (!full_url) {
        AMVP_LOG_ERR("Failed to allocate memory for URL");
        return AMVP_MALLOC_FAIL;
    }

    snprintf(full_url, AMVP_ATTR_URL_MAX, "https://%s:%d%s", 
             ctx->server_name, ctx->server_port, endpoint_path);

    /* Action validation and setup */
    switch (action) {
    case AMVP_NET_GET:
        generic_action = AMVP_NET_GET;
        break;

    case AMVP_NET_POST:
        check_data = 1;
        generic_action = AMVP_NET_POST;
        break;

    case AMVP_NET_PUT:
        check_data = 1;
        generic_action = AMVP_NET_PUT;
        break;

    case AMVP_NET_POST_MULTIPART:
        check_data = 1;
        generic_action = AMVP_NET_POST_MULTIPART;
        break;
        
    case AMVP_NET_DELETE:
        generic_action = AMVP_NET_DELETE;
        break;
        
    default:
        AMVP_LOG_ERR("We should never be here!");
        return AMVP_INVALID_ARG;
    }

    /* Data validation for POST/PUT/MULTIPART */
    if (check_data && (!data || !data_len)) {
        AMVP_LOG_ERR("POST/PUT/MULTIPART action requires non-zero data/data_len");
        return AMVP_NO_DATA;
    }

    /* Execute the HTTP call */
    rv = execute_network_action(ctx, generic_action, full_url, data, data_len, &response_code);
    if (rv != AMVP_SUCCESS) {
        goto end;
    }

    /* Inspect HTTP code for protocol-level errors */
    result = inspect_http_code(ctx, response_code);
    if (result == AMVP_PROTOCOL_RSP_ERR) {
        rv = result;
        goto end;
    }

    if (result != AMVP_SUCCESS) {
        if (result == AMVP_JWT_EXPIRED) {
            /*
             * Expired JWT - refresh session and retry
             */
            AMVP_LOG_WARN("JWT authorization has timed out, response code=%d. Refreshing session...", response_code);
            result = amvp_refresh(ctx);
            if (result != AMVP_SUCCESS) {
                AMVP_LOG_ERR("JWT refresh failed.");
                rv = result;
                goto end;
            } else {
                AMVP_LOG_STATUS("Refresh successful, attempting to continue...");
            }

            /* Retry the HTTP call after refresh */
            rv = execute_network_action(ctx, generic_action, full_url, data, data_len, &response_code);
            if (rv != AMVP_SUCCESS) {
                goto end;
            }

            /* Re-inspect HTTP code after retry */
            result = inspect_http_code(ctx, response_code);
            if (result != AMVP_SUCCESS) {
                AMVP_LOG_ERR("Refreshed + retried, HTTP transport fails. Response code=%d", response_code);
                rv = result;
                goto end;
            }
        } else if (result == AMVP_JWT_INVALID) {
            /*
             * Invalid JWT
             */
            AMVP_LOG_ERR("JWT invalid. Response code=%d.", response_code);
            rv = result;
            goto end;
        } else {
            /* Generic error */
            rv = result;
            goto end;
        }
    }

    /* Success */
    rv = AMVP_SUCCESS;

end:
    /* Log network status */
    if (full_url) {
        log_network_status(ctx, action, response_code, full_url);
    }
    
    /* Cleanup */
    if (full_url) {
        free(full_url);
    }
    
    return rv;
}

/*
 * Thin wrapper functions for better ergonomics
 * All delegate to amvp_network_action for consistent behavior
 */

AMVP_RESULT amvp_transport_get(AMVP_CTX *ctx, const char *endpoint_path) {
    return amvp_network_action(ctx, AMVP_NET_GET, endpoint_path, NULL, 0);
}

AMVP_RESULT amvp_transport_post(AMVP_CTX *ctx, const char *endpoint_path, const char *data, int data_len) {
    return amvp_network_action(ctx, AMVP_NET_POST, endpoint_path, data, data_len);
}

AMVP_RESULT amvp_transport_put(AMVP_CTX *ctx, const char *endpoint_path, const char *data, int data_len) {
    return amvp_network_action(ctx, AMVP_NET_PUT, endpoint_path, data, data_len);
}

AMVP_RESULT amvp_transport_delete(AMVP_CTX *ctx, const char *endpoint_path) {
    return amvp_network_action(ctx, AMVP_NET_DELETE, endpoint_path, NULL, 0);
}

AMVP_RESULT amvp_transport_post_multipart_form(AMVP_CTX *ctx, const char *endpoint_path, const char *file_path) {
    /* For multipart uploads, pass file path as data */
    return amvp_network_action(ctx, AMVP_NET_POST_MULTIPART, endpoint_path, file_path, strlen(file_path));
}

