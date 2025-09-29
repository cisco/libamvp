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

/* Endpoint paths after /amvp/v1/ */
#define AMVP_FT_EVIDENCE_PATH "evidence"
#define AMVP_SC_EVIDENCE_PATH "sourceCode"
#define AMVP_OD_EVIDENCE_PATH "otherDocumentation"
#define AMVP_SP_PATH "securityPolicy"
#define AMVP_LOGIN_PATH "login"
#define AMVP_CERT_REQUESTS_PATH "certRequests"
#define AMVP_MODULES_PATH "modules"
#define AMVP_SP_TEMPLATE_PATH "securityPolicy/template"

/* Helper function declarations */
static char* build_evidence_path(const char *base_path, const char *evidence_type);
static char* build_api_path(AMVP_CTX *ctx, const char *relative_path);
static AMVP_RESULT parse_response_json(AMVP_CTX *ctx, JSON_Value **result);

/*
 * Build evidence submission path by appending evidence type
 * Returns allocated string that caller must free, or NULL on error
 */
static char* build_evidence_path(const char *base_path, const char *evidence_type) {
    char *path = NULL;

    if (!base_path || !evidence_type) {
        return NULL;
    }

    path = calloc(AMVP_ATTR_URL_MAX + 1, sizeof(char));
    if (!path) {
        return NULL;
    }

    snprintf(path, AMVP_ATTR_URL_MAX, "%s/%s", base_path, evidence_type);
    return path;
}

/*
 * Build API path by prepending path segment to relative endpoint
 * For use with relative paths like "login", "certRequests", "modules/123"
 * Returns allocated string that caller must free, or NULL on error
 */
static char* build_api_path(AMVP_CTX *ctx, const char *relative_path) {
    char *full_path = NULL;

    if (!ctx || !relative_path) {
        return NULL;
    }

    full_path = calloc(AMVP_ATTR_URL_MAX + 1, sizeof(char));
    if (!full_path) {
        return NULL;
    }

    snprintf(full_path, AMVP_ATTR_URL_MAX, "%s/%s", AMVP_DEFAULT_PATH_SEGMENT, relative_path);
    return full_path;
}

/*
 * Parse JSON from response buffer, return deep copy, and clear buffer
 * Returns allocated JSON_Value that caller must free, or NULL on error
 */
static AMVP_RESULT parse_response_json(AMVP_CTX *ctx, JSON_Value **result) {
    JSON_Value *parsed_json = NULL;

    if (!ctx || !result) {
        return AMVP_INVALID_ARG;
    }

    *result = NULL;

    /* Parse JSON from response buffer */
    if (ctx->curl_buf && ctx->curl_read_ctr > 0) {
        parsed_json = json_parse_string(ctx->curl_buf);
        if (!parsed_json) {
            AMVP_LOG_ERR("Failed to parse JSON response");
            return AMVP_JSON_ERR;
        }

        *result = json_value_deep_copy(parsed_json);
        json_value_free(parsed_json);
        if (!*result) {
            AMVP_LOG_ERR("Failed to copy JSON response");
            return AMVP_MALLOC_FAIL;
        }

        /* Clear the response buffer */
        memzero_s(ctx->curl_buf, ctx->curl_read_ctr);
        ctx->curl_read_ctr = 0;

        return AMVP_SUCCESS;
    } else {
        AMVP_LOG_ERR("No response data received");
        return AMVP_NO_DATA;
    }
}

/*
 * Send evidence (functional test or source code) to the server
 */
AMVP_RESULT amvp_send_evidence(AMVP_CTX *ctx,
                               AMVP_EVIDENCE_TYPE type,
                               const char *url,
                               char *ev,
                               int ev_len) {
    char *evidence_path = NULL;
    const char *type_path = NULL;
    AMVP_RESULT rv;

    switch (type) {
    case AMVP_EVIDENCE_TYPE_FUNCTIONAL_TEST:
        type_path = AMVP_FT_EVIDENCE_PATH;
        break;
    case AMVP_EVIDENCE_TYPE_SOURCE_CODE:
        type_path = AMVP_SC_EVIDENCE_PATH;
        break;
    case AMVP_EVIDENCE_TYPE_OTHER_DOC:
        type_path = AMVP_OD_EVIDENCE_PATH;
        break;
    case AMVP_EVIDENCE_TYPE_NA:
    case AMVP_EVIDENCE_TYPE_MAX:
    default:
        AMVP_LOG_ERR("Cannot create evidence URL with given type");
        return AMVP_INVALID_ARG;
    }

    evidence_path = build_evidence_path(url, type_path);
    if (!evidence_path) {
        AMVP_LOG_ERR("Failed to build evidence path");
        return AMVP_TRANSPORT_FAIL;
    }

    rv = amvp_transport_post(ctx, evidence_path, ev, ev_len);
    free(evidence_path);
    return rv;
}


/*
 * Send security policy to the server
 */
AMVP_RESULT amvp_send_security_policy(AMVP_CTX *ctx,
                                      const char *url,
                                      char *sp,
                                      int sp_len) {
    char *sp_path = NULL;
    AMVP_RESULT rv;

    sp_path = build_evidence_path(url, AMVP_SP_PATH);
    if (!sp_path) {
        AMVP_LOG_ERR("Failed to build security policy path");
        return AMVP_TRANSPORT_FAIL;
    }

    rv = amvp_transport_post(ctx, sp_path, sp, sp_len);
    free(sp_path);
    return rv;
}

/*
 * Request security policy generation from the server
 */
AMVP_RESULT amvp_request_security_policy_generation(AMVP_CTX *ctx,
                                                    const char *url,
                                                    char *data) {
    char *sp_path = NULL;
    AMVP_RESULT rv;

    sp_path = build_evidence_path(url, AMVP_SP_PATH);
    if (!sp_path) {
        AMVP_LOG_ERR("Failed to build security policy path");
        return AMVP_TRANSPORT_FAIL;
    }

    rv = amvp_transport_put(ctx, sp_path, (const char*)data, strnlen_s(data, AMVP_CURL_BUF_MAX));
    free(sp_path);
    return rv;
}

/*
 * Get security policy JSON from the server
 */
AMVP_RESULT amvp_get_security_policy_json(AMVP_CTX *ctx,
                                          const char *url,
                                          JSON_Value **result) {
    char *sp_path = NULL;
    AMVP_RESULT rv;

    if (!result) {
        AMVP_LOG_ERR("Result parameter is required");
        return AMVP_INVALID_ARG;
    }
    *result = NULL;

    sp_path = build_evidence_path(url, AMVP_SP_PATH);
    if (!sp_path) {
        AMVP_LOG_ERR("Failed to build security policy path");
        return AMVP_TRANSPORT_FAIL;
    }

    rv = amvp_transport_get(ctx, sp_path);
    free(sp_path);

    if (rv != AMVP_SUCCESS) {
        return rv;
    }

    return parse_response_json(ctx, result);
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
    AMVP_RESULT rv;
    char *login_path = NULL;

    rv = sanity_check_ctx(ctx);
    if (AMVP_SUCCESS != rv) return rv;

    login_path = build_api_path(ctx, AMVP_LOGIN_PATH);
    if (!login_path) {
        AMVP_LOG_ERR("Failed to build login path");
        return AMVP_TRANSPORT_FAIL;
    }

    /* Make network call */
    rv = amvp_network_action(ctx, AMVP_NET_POST, login_path, login, len);
    free(login_path);
    return rv;
}

/*
 * Send security policy template using multipart form-data
 */
AMVP_RESULT amvp_send_sp_template(AMVP_CTX *ctx,
                                  const char *url,
                                  const char *file_path) {
    char *template_path = NULL;
    AMVP_RESULT rv;

    if (!ctx || !url || !file_path) {
        AMVP_LOG_ERR("Missing required parameters");
        return AMVP_MISSING_ARG;
    }

    template_path = build_evidence_path(url, AMVP_SP_TEMPLATE_PATH);
    if (!template_path) {
        AMVP_LOG_ERR("Failed to build security policy template path");
        return AMVP_TRANSPORT_FAIL;
    }

    rv = amvp_transport_post_multipart_form(ctx, template_path, file_path);
    free(template_path);
    return rv;
}

/*
 * Session status retrieval
 */
AMVP_RESULT amvp_get_session_status(AMVP_CTX *ctx, JSON_Value **result) {
    AMVP_RESULT rv;

    if (!ctx) return AMVP_NO_CTX;
    if (!result) {
        AMVP_LOG_ERR("Result parameter is required");
        return AMVP_INVALID_ARG;
    }
    *result = NULL;

    if (!ctx->session_url) {
        AMVP_LOG_ERR("No session URL available");
        return AMVP_MISSING_ARG;
    }

    rv = amvp_transport_get(ctx, ctx->session_url);
    if (rv != AMVP_SUCCESS) {
        return rv;
    }

    return parse_response_json(ctx, result);
}

/*
 * Certificate request submission
 */
AMVP_RESULT amvp_submit_cert_request(AMVP_CTX *ctx, const char *request_data, int data_len) {
    char *cert_path = NULL;
    AMVP_RESULT rv;

    if (!ctx) return AMVP_NO_CTX;
    if (!request_data || data_len <= 0) {
        AMVP_LOG_ERR("Invalid request data");
        return AMVP_MISSING_ARG;
    }

    cert_path = build_api_path(ctx, AMVP_CERT_REQUESTS_PATH);
    if (!cert_path) {
        AMVP_LOG_ERR("Failed to build cert request path");
        return AMVP_TRANSPORT_FAIL;
    }

    rv = amvp_transport_post(ctx, cert_path, request_data, data_len);
    free(cert_path);
    return rv;
}


/*
 * Certificate finalization - internal endpoint function
 */
AMVP_RESULT amvp_send_cert_finalization(AMVP_CTX *ctx) {
    char *certify_path = NULL;
    char *finalize_payload = NULL;
    JSON_Value *finalize_val = NULL;
    JSON_Object *finalize_obj = NULL;
    AMVP_RESULT rv;
    int payload_len = 0;

    if (!ctx) return AMVP_NO_CTX;
    if (!ctx->session_url) {
        AMVP_LOG_ERR("No session URL available");
        return AMVP_MISSING_ARG;
    }

    /* Create JSON payload with proper amvVersion */
    finalize_val = json_value_init_object();
    if (!finalize_val) {
        AMVP_LOG_ERR("Error creating JSON object for cert finalization");
        return AMVP_JSON_ERR;
    }

    finalize_obj = json_value_get_object(finalize_val);
    rv = amvp_add_version_to_obj(finalize_obj);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Unable to add amvVersion to cert finalization");
        json_value_free(finalize_val);
        return rv;
    }

    finalize_payload = json_serialize_to_string(finalize_val, &payload_len);
    if (!finalize_payload) {
        AMVP_LOG_ERR("Error serializing cert finalization JSON");
        json_value_free(finalize_val);
        return AMVP_JSON_ERR;
    }

    certify_path = build_evidence_path(ctx->session_url, AMVP_CERTIFY_ENDPOINT);
    if (!certify_path) {
        AMVP_LOG_ERR("Unable to build path for cert finalization");
        json_free_serialized_string(finalize_payload);
        json_value_free(finalize_val);
        return AMVP_TRANSPORT_FAIL;
    }

    rv = amvp_transport_post(ctx, certify_path, finalize_payload, payload_len);

    /* Cleanup */
    free(certify_path);
    json_free_serialized_string(finalize_payload);
    json_value_free(finalize_val);

    return rv;
}

/*
 * Module information retrieval
 */
AMVP_RESULT amvp_get_module_info(AMVP_CTX *ctx, int module_id, JSON_Value **result) {
    char *module_relative_path = NULL;
    char *module_path = NULL;
    AMVP_RESULT rv;

    if (!ctx) return AMVP_NO_CTX;
    if (!result) {
        AMVP_LOG_ERR("Result parameter is required");
        return AMVP_INVALID_ARG;
    }
    *result = NULL;

    module_relative_path = calloc(AMVP_ATTR_URL_MAX + 1, sizeof(char));
    if (!module_relative_path) {
        AMVP_LOG_ERR("Memory allocation error for module relative path");
        return AMVP_MALLOC_FAIL;
    }

    snprintf(module_relative_path, AMVP_ATTR_URL_MAX, "%s/%d", AMVP_MODULES_PATH, module_id);

    module_path = build_api_path(ctx, module_relative_path);
    if (!module_path) {
        AMVP_LOG_ERR("Failed to build module info path");
        free(module_relative_path);
        return AMVP_TRANSPORT_FAIL;
    }

    rv = amvp_transport_get(ctx, module_path);
    free(module_path);
    free(module_relative_path);

    if (rv != AMVP_SUCCESS) {
        return rv;
    }

    return parse_response_json(ctx, result);
}

/*
 * Generic GET request to any endpoint
 */
AMVP_RESULT amvp_send_get_request(AMVP_CTX *ctx, const char *endpoint_path) {
    AMVP_RESULT rv;

    if (!ctx) return AMVP_NO_CTX;
    if (!endpoint_path) {
        AMVP_LOG_ERR("Endpoint path is required");
        return AMVP_MISSING_ARG;
    }

    rv = amvp_transport_get(ctx, endpoint_path);
    return rv;
}
