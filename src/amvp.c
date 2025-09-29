/** @file */
/*
 * Copyright (c) 2025, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libamvp/LICENSE
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#ifdef _WIN32
#include <io.h>
#include <Windows.h>
#else
#include <unistd.h>
#endif
#include <math.h>
#include "amvp.h"
#include "amvp_lcl.h"
#include "amvp_error.h"
#include "parson.h"
#include "safe_lib.h"

/*
 * Forward prototypes for local functions
 */
static AMVP_RESULT amvp_login(AMVP_CTX *ctx, int refresh);

static AMVP_RESULT amvp_parse_login(AMVP_CTX *ctx);

static AMVP_RESULT amvp_update_session_file_jwt(AMVP_CTX *ctx);

/*
 * This is the first function the user should invoke to allocate
 * a new context to be used for the test session.
 */
AMVP_RESULT amvp_init_cert_request(AMVP_CTX **ctx,
                                     AMVP_RESULT (*progress_cb)(char *msg, AMVP_LOG_LVL level),
                                     AMVP_LOG_LVL level) {
    if (!ctx) {
        return AMVP_INVALID_ARG;
    }
    if (*ctx) {
        return AMVP_CTX_NOT_EMPTY;
    }
    *ctx = calloc(1, sizeof(AMVP_CTX));
    if (!*ctx) {
        return AMVP_MALLOC_FAIL;
    }

    if (progress_cb) {
        (*ctx)->test_progress_cb = progress_cb;
    }

    (*ctx)->log_lvl= level;
    if (level >= AMVP_LOG_LVL_DEBUG) {
        (*ctx)->debug = 1;
    }

    return AMVP_SUCCESS;
}

AMVP_RESULT amvp_set_2fa_callback(AMVP_CTX *ctx, AMVP_RESULT (*totp_cb)(char **token, int token_max)) {
    if (totp_cb == NULL) {
        return AMVP_MISSING_ARG;
    }
    if (ctx == NULL) {
        return AMVP_NO_CTX;
    }
    ctx->totp_cb = totp_cb;
    return AMVP_SUCCESS;
}

/*
 * The application will invoke this to free the AMVP context
 * when the test session is finished.
 */
AMVP_RESULT amvp_free_test_session(AMVP_CTX *ctx) {
    int i = 0;

    if (!ctx) {
        AMVP_LOG_STATUS("No ctx to free");
        return AMVP_SUCCESS;
    }

    if (ctx->kat_resp) { json_value_free(ctx->kat_resp); }
    if (ctx->curl_buf) { free(ctx->curl_buf); }
    if (ctx->server_name) { free(ctx->server_name); }
    if (ctx->cacerts_file) { free(ctx->cacerts_file); }
    if (ctx->tls_cert) { free(ctx->tls_cert); }
    if (ctx->tls_key) { free(ctx->tls_key); }
    if (ctx->http_user_agent) { free(ctx->http_user_agent); }
    if (ctx->session_file_path) { free(ctx->session_file_path); }
    if (ctx->session_url) { free(ctx->session_url); }
    if (ctx->get_string) { free(ctx->get_string); }
    if (ctx->delete_string) { free(ctx->delete_string); }
    if (ctx->save_filename) { free(ctx->save_filename); }
    if (ctx->mod_cert_req_file) { free(ctx->mod_cert_req_file); }
    if (ctx->jwt_token) { free(ctx->jwt_token); }
    if (ctx->tmp_jwt) { free(ctx->tmp_jwt); }
    if (ctx->error) { amvp_free_protocol_err(ctx->error); ctx->error = NULL; }
    if (ctx->vsid_url_list) {
        amvp_free_str_list(&ctx->vsid_url_list);
    }
    if (ctx->registration) {
            json_value_free(ctx->registration);
    }
    if (ctx->cert_req_info.tester_count > 0) {
        for (i = 0; i < ctx->cert_req_info.tester_count; i++) {
            free(ctx->cert_req_info.tester_id[i]);
        }
    }
    if (ctx->cert_req_info.reviewer_count > 0) {
        for (i = 0; i < ctx->cert_req_info.reviewer_count; i++) {
            free(ctx->cert_req_info.reviewer_id[i]);
        }
    }
    if (ctx->cert_req_info.acv_cert_count > 0) {
        for (i = 0; i < ctx->cert_req_info.acv_cert_count; i++) {
            free(ctx->cert_req_info.acv_cert[i]);
        }
    }
    if (ctx->cert_req_info.esv_cert_count > 0) {
        for (i = 0; i < ctx->cert_req_info.esv_cert_count; i++) {
            free(ctx->cert_req_info.esv_cert[i]);
        }
    }

    /* Free the AMVP_CTX struct */
    free(ctx);

    return AMVP_SUCCESS;
}

/*
 * This function is used by the application to specify the
 * AMVP server address and TCP port#.
 */
AMVP_RESULT amvp_set_server(AMVP_CTX *ctx, const char *server_name, int port) {
    if (!ctx) {
        return AMVP_NO_CTX;
    }
    if (!server_name || port < 1) {
        return AMVP_INVALID_ARG;
    }
    if (strnlen_s(server_name, AMVP_SESSION_PARAMS_STR_LEN_MAX + 1) > AMVP_SESSION_PARAMS_STR_LEN_MAX) {
        AMVP_LOG_ERR("Server name string(s) too long");
        return AMVP_INVALID_ARG;
    }
    if (ctx->server_name) {
        free(ctx->server_name);
    }
    ctx->server_name = calloc(AMVP_SESSION_PARAMS_STR_LEN_MAX + 1, sizeof(char));
    if (!ctx->server_name) {
        return AMVP_MALLOC_FAIL;
    }
    strcpy_s(ctx->server_name, AMVP_SESSION_PARAMS_STR_LEN_MAX + 1, server_name);

    ctx->server_port = port;

    if (!ctx->http_user_agent) {
        //generate user-agent string to send with HTTP requests
        amvp_http_user_agent_handler(ctx);
    }

    return AMVP_SUCCESS;
}

/*
 * This function allows the client to specify the location of the
 * PEM encoded CA certificates that will be used by Curl to verify
 * the AMVP server during the TLS handshake.  If this function is
 * not called by the application, then peer verification is not
 * enabled, which is not recommended (but provided as an operational
 * mode for testing).
 */
AMVP_RESULT amvp_set_cacerts(AMVP_CTX *ctx, const char *ca_file) {
    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (!ca_file) {
        return AMVP_MISSING_ARG;
    }

    if (strnlen_s(ca_file, AMVP_SESSION_PARAMS_STR_LEN_MAX + 1) > AMVP_SESSION_PARAMS_STR_LEN_MAX) {
        AMVP_LOG_ERR("CA filename is suspiciously long...");
        return AMVP_INVALID_ARG;
    }

    if (ctx->cacerts_file) { free(ctx->cacerts_file); }
    ctx->cacerts_file = calloc(AMVP_SESSION_PARAMS_STR_LEN_MAX + 1, sizeof(char));
    if (!ctx->cacerts_file) {
        return AMVP_MALLOC_FAIL;
    }
    strcpy_s(ctx->cacerts_file, AMVP_SESSION_PARAMS_STR_LEN_MAX + 1, ca_file);

    return AMVP_SUCCESS;
}

/*
 * This function is used to set the X509 certificate and private
 * key that will be used by libamvp during the TLS handshake to
 * identify itself to the server.  Some servers require TLS client
 * authentication, others do not.  This function is optional and
 * should only be used when the AMVP server supports TLS client
 * authentication.
 */
AMVP_RESULT amvp_set_certkey(AMVP_CTX *ctx, char *cert_file, char *key_file) {
    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (!cert_file || !key_file) {
        return AMVP_MISSING_ARG;
    }
    if (strnlen_s(cert_file, AMVP_SESSION_PARAMS_STR_LEN_MAX + 1) > AMVP_SESSION_PARAMS_STR_LEN_MAX ||
        strnlen_s(key_file, AMVP_SESSION_PARAMS_STR_LEN_MAX + 1) > AMVP_SESSION_PARAMS_STR_LEN_MAX) {
        AMVP_LOG_ERR("CA filename is suspiciously long...");
        return AMVP_INVALID_ARG;
    }
    if (ctx->tls_cert) { free(ctx->tls_cert); }
    ctx->tls_cert = calloc(AMVP_SESSION_PARAMS_STR_LEN_MAX + 1, sizeof(char));
    if (!ctx->tls_cert) {
        return AMVP_MALLOC_FAIL;
    }
    strcpy_s(ctx->tls_cert, AMVP_SESSION_PARAMS_STR_LEN_MAX + 1, cert_file);

    if (ctx->tls_key) { free(ctx->tls_key); }
    ctx->tls_key = calloc(AMVP_SESSION_PARAMS_STR_LEN_MAX + 1, sizeof(char));
    if (!ctx->tls_key) {
        free(ctx->tls_cert);
        ctx->tls_cert = NULL;
        return AMVP_MALLOC_FAIL;
    }
    strcpy_s(ctx->tls_key, AMVP_SESSION_PARAMS_STR_LEN_MAX + 1, key_file);

    return AMVP_SUCCESS;
}

AMVP_RESULT amvp_get(AMVP_CTX *ctx, const char *endpoint_path) {
    AMVP_RESULT rv = AMVP_SUCCESS;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (!endpoint_path) {
        return AMVP_MISSING_ARG;
    }

    if (strnlen_s(endpoint_path, AMVP_REQUEST_STR_LEN_MAX + 1) > AMVP_REQUEST_STR_LEN_MAX) {
        AMVP_LOG_ERR("Request endpoint path is suspiciously long...");
        return AMVP_INVALID_ARG;
    }

    /* Check if we have authentication - either from cert req info file or need to login */
    if (!ctx->jwt_token) {
        rv = amvp_login(ctx, 0);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Failed to login for GET request");
            return rv;
        }
    }

    /* Perform the GET request through endpoints abstraction */
    AMVP_LOG_STATUS("Performing GET request to: %s", endpoint_path);
    rv = amvp_send_get_request(ctx, endpoint_path);
    if (rv == AMVP_PROTOCOL_RSP_ERR) {
        rv = amvp_handle_protocol_error(ctx, ctx->error);
        if (rv == AMVP_RETRY_OPERATION) {
            rv = amvp_send_get_request(ctx, endpoint_path);
        }
    }
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("GET request failed");
        return rv;
    }

    /* Check if we have response data */
    if (!ctx->curl_buf || strlen(ctx->curl_buf) == 0) {
        AMVP_LOG_WARN("No response data received");
        return AMVP_SUCCESS;
    }

    /* Use existing get save file mechanism - ctx->save_filename is set via amvp_set_get_save_file() */
    if (ctx->save_filename) {
        FILE *fp = fopen(ctx->save_filename, "w");
        if (!fp) {
            AMVP_LOG_ERR("Failed to open save file: %s", ctx->save_filename);
            return AMVP_INTERNAL_ERR;
        }

        if (fwrite(ctx->curl_buf, 1, strlen(ctx->curl_buf), fp) != strlen(ctx->curl_buf)) {
            AMVP_LOG_ERR("Failed to write response to file: %s", ctx->save_filename);
            fclose(fp);
            return AMVP_INTERNAL_ERR;
        }
        AMVP_LOG_STATUS("Response saved to file: %s", ctx->save_filename);
        fclose(fp);
    } else {
        AMVP_LOG_STATUS("Response:\n%s", ctx->curl_buf);
    }

    return AMVP_SUCCESS;
}

AMVP_RESULT amvp_set_get_save_file(AMVP_CTX *ctx, char *filename) {
    if (!ctx) {
        AMVP_LOG_ERR("No CTX given");
        return AMVP_NO_CTX;
    }
    if (!filename) {
        AMVP_LOG_ERR("No filename given");
        return AMVP_MISSING_ARG;
    }
    int filenameLen = 0;
    filenameLen = strnlen_s(filename, AMVP_JSON_FILENAME_MAX + 1);
    if (filenameLen > AMVP_JSON_FILENAME_MAX || filenameLen <= 0) {
        AMVP_LOG_ERR("Provided filename invalid");
        return AMVP_INVALID_ARG;
    }
    if (ctx->save_filename) { free(ctx->save_filename); }
    ctx->save_filename = calloc(filenameLen + 1, sizeof(char));
    if (!ctx->save_filename) {
        return AMVP_MALLOC_FAIL;
    }
    strncpy_s(ctx->save_filename, filenameLen + 1, filename, filenameLen);
    return AMVP_SUCCESS;
}

AMVP_RESULT amvp_mark_as_cert_req(AMVP_CTX *ctx, const char *module_file, int vendor_id) {
    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (!module_file || !vendor_id) {
        AMVP_LOG_ERR("Missing module or vendor ID");
        return AMVP_INVALID_ARG;
    }
    if (strnlen_s(module_file, AMVP_JSON_FILENAME_MAX + 1) > AMVP_JSON_FILENAME_MAX) {
        AMVP_LOG_ERR("Module file name is suspiciously long...");
        return AMVP_INVALID_ARG;
    }

    strcpy_s(ctx->cert_req_info.module_file, AMVP_JSON_FILENAME_MAX + 1, module_file);
    ctx->cert_req_info.vendor_id = vendor_id;
    ctx->action = AMVP_ACTION_CERT_REQ;
    return AMVP_SUCCESS;
}

AMVP_RESULT amvp_cert_req_add_contact(AMVP_CTX *ctx, const char *contact_id, AMVP_CONTACT_TYPE contact_type) {
    int len = 0;
    int *count_ptr = NULL;
    char **contact_array = NULL;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (!contact_id) {
        return AMVP_MISSING_ARG;
    }

    /* Validate contact ID format */
    if (amvp_validate_contact_id(contact_id) != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Invalid contact ID format: %s (must be CVP-XXXXXX)", contact_id);
        return AMVP_INVALID_ARG;
    }

    if (contact_type >= AMVP_CONTACT_TYPE_MAX) {
        AMVP_LOG_ERR("Invalid contact type provided");
        return AMVP_INVALID_ARG;
    }

    if (ctx->action != AMVP_ACTION_CERT_REQ) {
        AMVP_LOG_ERR("Session must be marked as a certify request to add contact info");
        return AMVP_UNSUPPORTED_OP;
    }

    /* Set the appropriate count pointer and contact array based on contact type */
    switch (contact_type) {
        case AMVP_CONTACT_TYPE_TESTER:
            count_ptr = &ctx->cert_req_info.tester_count;
            contact_array = ctx->cert_req_info.tester_id;
            break;
        case AMVP_CONTACT_TYPE_REVIEWER:
            count_ptr = &ctx->cert_req_info.reviewer_count;
            contact_array = ctx->cert_req_info.reviewer_id;
            break;
        case AMVP_CONTACT_TYPE_MAX:
        default:
            AMVP_LOG_ERR("Unsupported contact type");
            return AMVP_INVALID_ARG;
    }

    if (*count_ptr >= AMVP_MAX_CONTACTS_PER_CERT_REQ) {
        AMVP_LOG_ERR("Already at maximum number of contacts per cert request for this contact type");
        return AMVP_UNSUPPORTED_OP;
    }

    len = strnlen_s(contact_id, AMVP_CONTACT_STR_MAX_LEN + 1);
    if (!len || len > AMVP_CONTACT_STR_MAX_LEN) {
        AMVP_LOG_ERR("Provided contact ID string is too long or empty");
        return AMVP_INVALID_ARG;
    }

    contact_array[*count_ptr] = calloc(len + 1, sizeof(char));
    if (!contact_array[*count_ptr]) {
        AMVP_LOG_ERR("Error allocating memory for contact ID in cert request");
        return AMVP_MALLOC_FAIL;
    }

    if (strncpy_s(contact_array[*count_ptr], len + 1, contact_id, len)) {
        AMVP_LOG_ERR("Error copying contact ID string into cert request");
        free(contact_array[*count_ptr]);
        return AMVP_INTERNAL_ERR;
    }

    (*count_ptr)++;
    return AMVP_SUCCESS;
}

AMVP_RESULT amvp_cert_req_add_sub_cert(AMVP_CTX *ctx, const char *cert_id, AMVP_CERT_TYPE type) {
    int len = 0;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (!cert_id) {
        return AMVP_MISSING_ARG;
    }

    /* Validate certificate ID format based on type */
    if (type == AMVP_CERT_TYPE_ACV) {
        if (amvp_validate_acv_cert_id(cert_id) != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Invalid ACV certificate ID format: %s (must be A<number>)", cert_id);
            return AMVP_INVALID_ARG;
        }
    } else if (type == AMVP_CERT_TYPE_ESV) {
        if (amvp_validate_esv_cert_id(cert_id) != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Invalid ESV certificate ID format: %s (must be E<number>)", cert_id);
            return AMVP_INVALID_ARG;
        }
    }

    len = strnlen_s(cert_id, AMVP_CERT_STR_MAX_LEN + 1);
    if (!len || len > AMVP_CONTACT_STR_MAX_LEN) {
        AMVP_LOG_ERR("Provided cert ID string is too long or empty");
        return AMVP_INVALID_ARG;
    }

    if (ctx->action != AMVP_ACTION_CERT_REQ) {
        AMVP_LOG_ERR("Session must be marked as a certify request to add contact info");
        return AMVP_UNSUPPORTED_OP;
    }

    switch (type) {
        case AMVP_CERT_TYPE_ACV:
            if (ctx->cert_req_info.acv_cert_count >= AMVP_MAX_ACV_CERTS_PER_CERT_REQ) {
                AMVP_LOG_ERR("Already at maximum number of alg certs per cert request");
                return AMVP_UNSUPPORTED_OP;
            }

            ctx->cert_req_info.acv_cert[ctx->cert_req_info.acv_cert_count] = calloc(len + 1, sizeof(char));
            if (!ctx->cert_req_info.acv_cert[ctx->cert_req_info.acv_cert_count]) {
                AMVP_LOG_ERR("Error allocating memory for contact ID in cert request");
                return AMVP_MALLOC_FAIL;
            }

            if (strncpy_s(ctx->cert_req_info.acv_cert[ctx->cert_req_info.acv_cert_count], len + 1, cert_id, len)) {
                AMVP_LOG_ERR("Error copying contact ID string into cert request");
                free(ctx->cert_req_info.acv_cert[ctx->cert_req_info.acv_cert_count]);
                return AMVP_INTERNAL_ERR;
            }

            ctx->cert_req_info.acv_cert_count++;
            break;
        case AMVP_CERT_TYPE_ESV:
            if (ctx->cert_req_info.esv_cert_count >= AMVP_MAX_ESV_CERTS_PER_CERT_REQ) {
                AMVP_LOG_ERR("Already at maximum number of esv certs per cert request");
                return AMVP_UNSUPPORTED_OP;
            }
            ctx->cert_req_info.esv_cert[ctx->cert_req_info.esv_cert_count] = calloc(len + 1, sizeof(char));
            if (!ctx->cert_req_info.esv_cert[ctx->cert_req_info.esv_cert_count]) {
                AMVP_LOG_ERR("Error allocating memory for contact ID in cert request");
                return AMVP_MALLOC_FAIL;
            }

            if (strncpy_s(ctx->cert_req_info.esv_cert[ctx->cert_req_info.esv_cert_count], len + 1, cert_id, len)) {
                AMVP_LOG_ERR("Error copying contact ID string into cert request");
                free(ctx->cert_req_info.esv_cert[ctx->cert_req_info.esv_cert_count]);
                return AMVP_INTERNAL_ERR;
            }

            ctx->cert_req_info.esv_cert_count++;
            break;
        case AMVP_CERT_TYPE_AMV:
        case AMVP_CERT_TYPE_NONE:
        case AMVP_CERT_TYPE_MAX:
        default:
            AMVP_LOG_ERR("Sub certs can only be set for ACV or ESV certs");
            return AMVP_INVALID_ARG;
    }

    return AMVP_SUCCESS;
}

AMVP_RESULT amvp_mark_as_delete_only(AMVP_CTX *ctx, char *request_url) {
    if (!ctx) {
        return AMVP_NO_CTX;
    }
    if (!request_url) {
        return AMVP_MISSING_ARG;
    }
    int requestLen = strnlen_s(request_url, AMVP_REQUEST_STR_LEN_MAX + 1);
    if (requestLen > AMVP_REQUEST_STR_LEN_MAX || requestLen <= 0) {
        AMVP_LOG_ERR("Request URL is too long or too short");
        return AMVP_INVALID_ARG;
    }

    ctx->delete_string = calloc(AMVP_REQUEST_STR_LEN_MAX + 1, sizeof(char));
    if (!ctx->delete_string) {
        return AMVP_MALLOC_FAIL;
    }

    strcpy_s(ctx->delete_string, AMVP_REQUEST_STR_LEN_MAX + 1, request_url);
    ctx->action = AMVP_ACTION_DELETE;
    return AMVP_SUCCESS;
}

/*
 * This function builds the JSON login message that
 * will be sent to the AMVP server. If enabled,
 * it will perform the second of the two-factor
 * authentications using a TOTP.
 */
static AMVP_RESULT amvp_build_login(AMVP_CTX *ctx, char **login, int *login_len, int refresh) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    JSON_Value *val = NULL;
    JSON_Object *obj = NULL;
    char *token = NULL;

    if (!login_len) return AMVP_INVALID_ARG;

    val = json_value_init_object();
    obj = json_value_get_object(val);

    json_object_set_string(obj, AMVP_PROTOCOL_VERSION_STR, AMVP_VERSION);

    if (ctx->totp_cb) {
        token = calloc(AMVP_TOTP_TOKEN_MAX + 1, sizeof(char));
        if (!token) return AMVP_MALLOC_FAIL;

        rv = ctx->totp_cb(&token, AMVP_TOTP_TOKEN_MAX);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Error occurred in application callback while generating TOTP");
            rv = AMVP_TOTP_FAIL;
            goto err;
        }
        if (strnlen_s(token, AMVP_TOTP_TOKEN_MAX + 1) > AMVP_TOTP_TOKEN_MAX) {
            AMVP_LOG_ERR("totp cb generated a token that is too long");
            json_value_free(val);
            val = NULL;
            rv = AMVP_TOTP_FAIL;
            goto err;
        }
        json_object_set_string(obj, "passcode", token);
    }

    if (refresh) {
        json_object_set_string(obj, "accessToken", ctx->jwt_token);
    }

err:
    *login = json_serialize_to_string(val, login_len);
    if (val) json_value_free(val);
    if (token) free(token);
    return rv;
}

AMVP_RESULT amvp_read_cert_req_info_file(AMVP_CTX *ctx, const char *filename) {
    AMVP_RESULT rv = AMVP_INTERNAL_ERR;
    JSON_Value *val = NULL;
    JSON_Object *obj = NULL;
    const char *url = NULL, *access_token = NULL, *status = NULL;
    AMVP_CERT_REQ_STATUS cert_req_status = AMVP_CERT_REQ_STATUS_UNKNOWN;

    if (!ctx) {
        AMVP_LOG_ERR("No CTX given");
        return AMVP_NO_CTX;
    }
    if (!filename) {
        AMVP_LOG_ERR("Must provide value for JSON filename");
        return AMVP_MISSING_ARG;
    }

    if (ctx->session_url || ctx->jwt_token) {
        AMVP_LOG_WARN("Warning: Cert Req URL or JWT were already set, erasing old info...");
        if (ctx->session_url) free(ctx->session_url);
        if (ctx->jwt_token) free(ctx->jwt_token);
        ctx->session_url = NULL;
        ctx->jwt_token = NULL;
    }

    if (strnlen_s(filename, AMVP_JSON_FILENAME_MAX + 1) > AMVP_JSON_FILENAME_MAX) {
        AMVP_LOG_ERR("Provided filename length > max(%d)", AMVP_JSON_FILENAME_MAX);
        return AMVP_INVALID_ARG;
    }

    /* Store the session file path for later updating */
    if (ctx->session_file_path) {
        free(ctx->session_file_path);
        ctx->session_file_path = NULL;
    }
    ctx->session_file_path = calloc(AMVP_JSON_FILENAME_MAX + 1, sizeof(char));
    if (!ctx->session_file_path) {
        AMVP_LOG_ERR("Unable to allocate memory for session file path");
        return AMVP_MALLOC_FAIL;
    }
    strcpy_s(ctx->session_file_path, AMVP_JSON_FILENAME_MAX + 1, filename);

    /*
     * Send the capabilities to the AMVP server and get the response,
     * which should be a list of vector set ID urls
     */
    val = json_parse_file(filename);
    obj = json_value_get_object(val);
    if (!obj) {
        AMVP_LOG_ERR("Provided cert request info file is invalid");
        goto end;
    }

    url = json_object_get_string(obj, "url");
    if (!url) {
        AMVP_LOG_ERR("URL missing from cert session info file");
        goto end;
    }
    if (strnlen_s(url, AMVP_ATTR_URL_MAX + 1) > AMVP_ATTR_URL_MAX) {
        AMVP_LOG_ERR("Provided url length > max(%d)", AMVP_ATTR_URL_MAX);
        return AMVP_INVALID_ARG;
    }

    ctx->session_url = calloc(AMVP_ATTR_URL_MAX + 1, sizeof(char));
    strcpy_s(ctx->session_url, AMVP_ATTR_URL_MAX + 1, url);

    /*
     * The accessToken needed for this specific test session.
     */
    access_token = json_object_get_string(obj, "accessToken");
    if (!access_token) {
        AMVP_LOG_ERR("accessToken missing from cert session info file");
        return AMVP_JSON_ERR;
    }
    if (strnlen_s(access_token, AMVP_JWT_TOKEN_MAX + 1) > AMVP_JWT_TOKEN_MAX) {
        AMVP_LOG_ERR("access_token too large");
        return AMVP_JWT_INVALID;
    }
    ctx->jwt_token = calloc(AMVP_JWT_TOKEN_MAX + 1, sizeof(char));
    if (!ctx->jwt_token) {
        AMVP_LOG_ERR("Unable to allocate memory for JWT");
        return AMVP_MALLOC_FAIL;
    }
    strcpy_s(ctx->jwt_token, AMVP_JWT_TOKEN_MAX + 1, access_token);

    /* Determine if this session has already retrieved its expected TE list */
    status = json_object_get_string(obj, "status");
    if (status) {
        cert_req_status = amvp_parse_cert_req_status_str(obj);
        if (cert_req_status != AMVP_CERT_REQ_STATUS_INITIAL &&
                json_object_has_value(obj, "securityPolicyStatus") &&
                json_object_has_value(obj, "evidenceStatus")) {
            ctx->session_file_has_te_list = 1;
        }
    }

    rv = AMVP_SUCCESS;
end:
    if (val) json_value_free(val);
    return rv;
}

static AMVP_RESULT amvp_update_session_file_jwt(AMVP_CTX *ctx) {
    AMVP_RESULT rv = AMVP_INTERNAL_ERR;
    JSON_Value *val = NULL;
    JSON_Object *obj = NULL;
    char *serialized_string = NULL;
    FILE *file = NULL;

    if (!ctx) {
        AMVP_LOG_ERR("No CTX given");
        return AMVP_NO_CTX;
    }

    if (!ctx->session_file_path) {
        AMVP_LOG_WARN("No session file path available to update");
        return AMVP_SUCCESS; /* Not an error if no file to update */
    }

    if (!ctx->jwt_token) {
        AMVP_LOG_ERR("No JWT token available to update file with");
        return AMVP_MISSING_ARG;
    }

    /* Parse the existing session file */
    val = json_parse_file(ctx->session_file_path);
    if (!val) {
        AMVP_LOG_ERR("Failed to parse existing session file: %s", ctx->session_file_path);
        return AMVP_JSON_ERR;
    }

    obj = json_value_get_object(val);
    if (!obj) {
        AMVP_LOG_ERR("Session file does not contain valid JSON object");
        goto end;
    }

    /* Update the accessToken field with the new JWT */
    if (json_object_set_string(obj, "accessToken", ctx->jwt_token) != JSONSuccess) {
        AMVP_LOG_ERR("Failed to update accessToken in JSON object");
        goto end;
    }

    /* Serialize the updated JSON */
    serialized_string = json_serialize_to_string_pretty(val, NULL);
    if (!serialized_string) {
        AMVP_LOG_ERR("Failed to serialize updated JSON");
        goto end;
    }

    /* Write the updated content back to the file */
    file = fopen(ctx->session_file_path, "w");
    if (!file) {
        AMVP_LOG_ERR("Failed to open session file for writing: %s", ctx->session_file_path);
        goto end;
    }

    if (fwrite(serialized_string, 1, strlen(serialized_string), file) != strlen(serialized_string)) {
        AMVP_LOG_ERR("Failed to write updated content to session file");
        goto end;
    }

    AMVP_LOG_STATUS("Successfully updated JWT in session file: %s", ctx->session_file_path);
    rv = AMVP_SUCCESS;

end:
    if (file) fclose(file);
    if (serialized_string) json_free_serialized_string(serialized_string);
    if (val) json_value_free(val);
    return rv;
}

AMVP_RESULT amvp_check_cert_req_status(AMVP_CTX *ctx) {
    AMVP_RESULT rv = AMVP_INTERNAL_ERR;
    JSON_Value *val = NULL;
    JSON_Object *obj = NULL;
    AMVP_CERT_REQ_STATUS status = AMVP_CERT_REQ_STATUS_UNKNOWN;
    int retry = 0, retry_period = 30;
    unsigned int time_waited_so_far = 0;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (!ctx->jwt_token || !ctx->session_url) {
        AMVP_LOG_ERR("Must ingest cert session file in order to check session status");
        return AMVP_MISSING_ARG;
    }

    do {
        retry = 0;

        rv = amvp_get_session_status(ctx, &val);
        if (rv == AMVP_PROTOCOL_RSP_ERR) {
            rv = amvp_handle_protocol_error(ctx, ctx->error);
            if (rv == AMVP_RETRY_OPERATION) {
                if (val) json_value_free(val);  /* Free first response before retry */
                rv = amvp_get_session_status(ctx, &val);
            }
        }

        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Unable to get session status from server");
            goto end;
        }

        if (!val) {
            AMVP_LOG_ERR("No JSON data received when getting cert req status");
            rv = AMVP_NO_DATA;
            goto end;
        }

        obj = amvp_get_obj_from_rsp(ctx, val);
        if (!obj) {
            AMVP_LOG_ERR("Unrecognized JSON format found when getting cert req status");
            rv = AMVP_JSON_ERR;
            goto end;
        }

        status = amvp_parse_cert_req_status_str(obj);
        switch (status) {
        case AMVP_CERT_REQ_STATUS_INITIAL:
            AMVP_LOG_STATUS("Certification request is still initializing...");
            rv = amvp_retry_handler(ctx, &retry_period, &time_waited_so_far, 1, AMVP_WAITING_FOR_TESTS);
            retry = 1;
            if (val) json_value_free(val);
            val = NULL;
            continue;
        case AMVP_CERT_REQ_STATUS_READY:
            if (!ctx->session_file_has_te_list) {
                AMVP_LOG_STATUS("Adding requirements to cert request file...");
                rv = amvp_save_cert_req_info_file(ctx, obj);
                if (rv != AMVP_SUCCESS) {
                    AMVP_LOG_ERR("Error saving cert request info file");
                    goto end;
                }
            }
            rv = amvp_output_cert_request_status(ctx, obj);
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("Error outputting cert request status");
                goto end;
            }
            break;
        case AMVP_CERT_REQ_STATUS_SUBMITTED:
        case AMVP_CERT_REQ_STATUS_IN_REVIEW:
        case AMVP_CERT_REQ_STATUS_APPROVED:
        case AMVP_CERT_REQ_STATUS_REJECTED:
            rv = amvp_output_cert_request_status(ctx, obj);
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("Error outputting cert request status");
                goto end;
            }
            break;
        case AMVP_CERT_REQ_STATUS_ERROR:
        case AMVP_CERT_REQ_STATUS_UNKNOWN:
        default:
            AMVP_LOG_ERR("An error occurred while parsing the cert request status");
            rv = AMVP_JSON_ERR;
            goto end;
        }

    } while (retry);

end:
    if (val) json_value_free(val);
    return rv;
}

/*
 * This function is used to register the DUT with the server.
 * Registration allows the DUT to advertise it's capabilities to
 * the server.  The server will respond with a set of vector set
 * identifiers that the client will need to process.
 */
AMVP_RESULT amvp_mod_cert_req(AMVP_CTX *ctx) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    char *reg = NULL, *file = NULL;
    int reg_len = 0, i = 0;
    JSON_Value *cert_submission_val = NULL, *cert_rsp_val = NULL, *cert_info_val = NULL,
               *output_file_val = NULL, *module_file_val = NULL;
    JSON_Object *tmp_obj = NULL, *module_file_obj = NULL, *module_info_obj = NULL;
    const char *url = NULL, *token = NULL, *module_name = NULL;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (ctx->cert_req_info.module_file[0] == '\0') {
        AMVP_LOG_ERR("Must provide module file name before certifying");
        return AMVP_MISSING_ARG;
    }

    module_file_val = json_parse_file(ctx->cert_req_info.module_file);
    if (!module_file_val) {
        AMVP_LOG_ERR("Provided module file is invalid or does not exist");
        return AMVP_INVALID_ARG;
    }
    module_file_obj = json_value_get_object(module_file_val);
    if (!module_file_obj) {
        AMVP_LOG_ERR("Provided module file is invalid or does not contain a JSON object");
        json_value_free(module_file_val);
        return AMVP_INVALID_ARG;
    }

    rv = amvp_login(ctx, 0);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Failed to login to AMVP server when creating cert request");
        goto end;
    }

    module_info_obj = json_object_get_object(module_file_obj, "moduleInfo");
    if (!module_info_obj) {
        AMVP_LOG_ERR("Module file does not contain moduleInfo object");
        rv = AMVP_JSON_ERR;
        goto end;
    }

    module_name = json_object_get_string(module_info_obj, "name");
    if (!module_name) {
        AMVP_LOG_ERR("Module file does not contain name field");
        rv = AMVP_JSON_ERR;
        goto end;
    }

    AMVP_LOG_STATUS("    Module: %s", module_name);
    if (ctx->cert_req_info.vendor_id) {
        AMVP_LOG_STATUS("    Vendor: %d", ctx->cert_req_info.vendor_id);
    }
    if (ctx->cert_req_info.tester_count > 0) {
        AMVP_LOG_STATUS("    Testers:");
        for (i = 0; i < ctx->cert_req_info.tester_count; i++) {
            AMVP_LOG_STATUS("        %s", ctx->cert_req_info.tester_id[i]);
        }
    }
    if (ctx->cert_req_info.reviewer_count > 0) {
        AMVP_LOG_STATUS("    Reviewers:");
        for (i = 0; i < ctx->cert_req_info.reviewer_count; i++) {
            AMVP_LOG_STATUS("        %s", ctx->cert_req_info.reviewer_id[i]);
        }
    }

    /* Create the module cert request value */
    AMVP_LOG_STATUS("Creating module cert request...");
    if (amvp_build_registration_json(ctx, &cert_submission_val) != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Error building cert request JSON");
        rv = AMVP_JSON_ERR;
        goto end;
    }
    /* create an array with amvVersion header, append request as the second object in the array */
    amvp_add_version_to_obj(json_value_get_object(cert_submission_val));
    reg = json_serialize_to_string(cert_submission_val, &reg_len);

    AMVP_LOG_VERBOSE("Cert request payload:\n%s", reg);

    /* Send it */
    AMVP_LOG_STATUS("Sending module cert request...");
    rv = amvp_submit_cert_request(ctx, reg, reg_len);
    if (rv == AMVP_PROTOCOL_RSP_ERR) {
        rv = amvp_handle_protocol_error(ctx, ctx->error);
        if (rv == AMVP_RETRY_OPERATION) {
            rv = amvp_submit_cert_request(ctx, reg, reg_len);
        }
    }
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Failed to send certify request");
        goto end;
    }


    cert_rsp_val = json_parse_string(ctx->curl_buf);
    tmp_obj = amvp_get_obj_from_rsp(ctx, cert_rsp_val);
    if (!tmp_obj) {
        AMVP_LOG_ERR("Error parsing response to certify request");
        rv = AMVP_JSON_ERR;
        goto end;
    }

    url = json_object_get_string(tmp_obj, "url");
    if (!url) {
        AMVP_LOG_ERR("Server response missing URL for cert request session.");
        rv = AMVP_JSON_ERR;
        goto end;
    }
    if (!ctx->session_url) {
        ctx->session_url = calloc(AMVP_ATTR_URL_MAX + 1, sizeof(char));
        if (!ctx->session_url) {
            AMVP_LOG_ERR("Unable to allocate memory for cert session URL");
            return AMVP_MALLOC_FAIL;
        }
    } else {
        memzero_s(ctx->session_url, AMVP_ATTR_URL_MAX + 1);
    }
    strcpy_s(ctx->session_url, AMVP_ATTR_URL_MAX + 1, url);

    token = json_object_get_string(tmp_obj, "accessToken");
    if (!ctx->jwt_token) {
        ctx->jwt_token = calloc(AMVP_JWT_TOKEN_MAX + 1, sizeof(char));
        if (!ctx->jwt_token) {
            AMVP_LOG_ERR("Unable to allocate memory for JWT");
            return AMVP_MALLOC_FAIL;
        }
    } else {
        memzero_s(ctx->jwt_token, AMVP_JWT_TOKEN_MAX + 1);
    }
    strcpy_s(ctx->jwt_token, AMVP_JWT_TOKEN_MAX + 1, token);

    AMVP_LOG_STATUS("Successfully sent certify request...");

    rv = amvp_save_cert_req_info_file(ctx, tmp_obj);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Error saving cert request info file");
        goto end;
    }

    rv = amvp_check_cert_req_status(ctx);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Error checking cert request status");
        goto end;
    }

end:
    if (reg) json_free_serialized_string(reg);
    if (file) free(file);
    if (module_file_val) json_value_free(module_file_val);
    if (output_file_val) json_value_free(output_file_val); //Also frees the header and body vals
    if (cert_info_val) json_value_free(cert_info_val);
    if (cert_rsp_val) json_value_free(cert_rsp_val);
    if (cert_submission_val) json_value_free(cert_submission_val);
    return rv;
}

AMVP_RESULT amvp_submit_security_policy_template(AMVP_CTX *ctx, const char *filename) {
    AMVP_RESULT rv = AMVP_INTERNAL_ERR;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (!filename) {
        AMVP_LOG_ERR("Must provide value for security policy template filename");
        return AMVP_MISSING_ARG;
    }

    if (strnlen_s(filename, AMVP_JSON_FILENAME_MAX + 1) > AMVP_JSON_FILENAME_MAX) {
        AMVP_LOG_ERR("Provided filename length > max(%d)", AMVP_JSON_FILENAME_MAX);
        return AMVP_INVALID_ARG;
    }

    AMVP_LOG_STATUS("Submitting security policy template file...");
    rv = amvp_send_sp_template(ctx, ctx->session_url, filename);
    if (rv == AMVP_PROTOCOL_RSP_ERR) {
        rv = amvp_handle_protocol_error(ctx, ctx->error);
        if (rv == AMVP_RETRY_OPERATION) {
            rv = amvp_send_sp_template(ctx, ctx->session_url, filename);
        }
    }

    if (rv == AMVP_SUCCESS) {
        AMVP_LOG_STATUS("Security policy template successfully submitted!");
    } else {
        AMVP_LOG_ERR("Error sending security policy template for cert request session");
        return rv;
    }

    rv = amvp_check_cert_req_status(ctx);
    return rv;
}

AMVP_RESULT amvp_submit_security_policy(AMVP_CTX *ctx, const char *filename) {
    AMVP_RESULT rv = AMVP_INTERNAL_ERR;
    char *reg = NULL, *file = NULL, *sp = NULL;
    int sp_len = 0;

    JSON_Value *val = NULL, *tmp = NULL, *submission = NULL;
    JSON_Object *obj = NULL, *submission_obj = NULL;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (!filename) {
        AMVP_LOG_ERR("Must provide value for JSON filename");
        return AMVP_MISSING_ARG;
    }

    if (strnlen_s(filename, AMVP_JSON_FILENAME_MAX + 1) > AMVP_JSON_FILENAME_MAX) {
        AMVP_LOG_ERR("Provided filename length > max(%d)", AMVP_JSON_FILENAME_MAX);
        return AMVP_INVALID_ARG;
    }

    val = json_parse_file(filename);
    obj = json_value_get_object(val);
    if (!obj) {
        AMVP_LOG_ERR("Provided security policy file is invalid");
        goto end;
    }

    submission = val;
    submission_obj = json_value_get_object(submission);
    rv = amvp_add_version_to_obj(submission_obj);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Unable to add amvVersion to SP submission");
        goto end;
    }

    sp = json_serialize_to_string_pretty(submission, &sp_len);

    AMVP_LOG_STATUS("Successfully read security policy file. Submitting...");
    rv = amvp_send_security_policy(ctx, ctx->session_url, sp, sp_len);
    if (rv == AMVP_PROTOCOL_RSP_ERR) {
        rv = amvp_handle_protocol_error(ctx, ctx->error);
        if (rv == AMVP_RETRY_OPERATION) {
            rv = amvp_send_security_policy(ctx, ctx->session_url, sp, sp_len);
        }
    }

    if (rv == AMVP_SUCCESS) {
        AMVP_LOG_STATUS( "Security policy successfully submitted!");
    } else {
        AMVP_LOG_ERR("Error sending security policy for cert request session");
        goto end;
    }

    rv = amvp_check_cert_req_status(ctx);
end:
    if (reg) json_free_serialized_string(reg);
    if (val) json_value_free(val);
    if (tmp) json_value_free(tmp);
    if (file) free(file);
    if (sp) free(sp);
    return rv;
}

static AMVP_SP_STATUS amvp_get_sp_request_status(const char *str) {
    int diff = 1;
    size_t len = 0;

    len = strnlen_s(str, AMVP_CERT_REQ_STATUS_MAX_LEN + 1);
    if (len > AMVP_CERT_REQ_STATUS_MAX_LEN) {
        return AMVP_SP_STATUS_UNKNOWN;
    }

    strncmp_s(AMVP_SP_STATUS_STR_UNSUBMITTED, sizeof(AMVP_SP_STATUS_STR_UNSUBMITTED) - 1, str, len, &diff);
    if (!diff) return AMVP_SP_STATUS_UNSUBMITTED;
    strncmp_s(AMVP_SP_STATUS_STR_PROCESSING, sizeof(AMVP_SP_STATUS_STR_PROCESSING) - 1, str, len, &diff);
    if (!diff) return AMVP_SP_STATUS_PROCESSING;
    strncmp_s(AMVP_SP_STATUS_STR_WAITING_GENERATION, sizeof(AMVP_SP_STATUS_STR_WAITING_GENERATION) - 1, str, len, &diff);
    if (!diff) return AMVP_SP_STATUS_WAITING_GENERATION;
    strncmp_s(AMVP_SP_STATUS_STR_GENERATING, sizeof(AMVP_SP_STATUS_STR_GENERATING) - 1, str, len, &diff);
    if (!diff) return AMVP_SP_STATUS_GENERATING;
    strncmp_s(AMVP_SP_STATUS_STR_SUCCESS, sizeof(AMVP_SP_STATUS_STR_SUCCESS) - 1, str, len, &diff);
    if (!diff) return AMVP_SP_STATUS_SUCCESS;
    strncmp_s(AMVP_SP_STATUS_STR_ERROR, sizeof(AMVP_SP_STATUS_STR_ERROR) - 1, str, len, &diff);
    if (!diff) return AMVP_SP_STATUS_ERROR;

    return AMVP_SP_STATUS_UNKNOWN;
}

AMVP_RESULT amvp_get_security_policy(AMVP_CTX *ctx) {
    AMVP_RESULT rv = AMVP_INTERNAL_ERR;
    AMVP_SP_STATUS status = AMVP_SP_STATUS_UNKNOWN;
    JSON_Value *val = NULL, *req_val = NULL;
    JSON_Object *obj = NULL, *req_obj = NULL;
    const char *status_str = NULL, *sp_str = NULL;
    unsigned char *sp_buffer = NULL;
    char *req_str = NULL;
    unsigned int sp_buffer_len = 0;
    size_t sp_str_len = 0;
    FILE *fp = NULL;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (!ctx->save_filename) {
        AMVP_LOG_ERR("Save file location must be set to get security policy");
        return AMVP_MISSING_ARG;
    }

    if (!ctx->jwt_token || !ctx->session_url) {
        AMVP_LOG_ERR("Must ingest cert session file in order to get security policy");
        return AMVP_MISSING_ARG;
    }

    rv = amvp_get_security_policy_json(ctx, ctx->session_url, &val);
    if (rv == AMVP_PROTOCOL_RSP_ERR) {
        rv = amvp_handle_protocol_error(ctx, ctx->error);
        if (rv == AMVP_RETRY_OPERATION) {
            if (val) json_value_free(val);
            rv = amvp_get_security_policy_json(ctx, ctx->session_url, &val);
        }
    }
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Failed to get SP JSON payload from server");
        return AMVP_TRANSPORT_FAIL;
    }

    if (!val) {
        AMVP_LOG_ERR("No JSON data received when getting security policy");
        goto err;
    }

    obj = amvp_get_obj_from_rsp(ctx, val);
    if (!obj) {
        AMVP_LOG_ERR("Error parsing response from server when checking certify session status");
        goto err;
    }

    status_str = json_object_get_string(obj, "status");
    if (!status_str) {
        AMVP_LOG_ERR("No status value found when getting security policy status\n");
        return AMVP_JSON_ERR;
    }
    status = amvp_get_sp_request_status(status_str);
    switch (status) {
    case AMVP_SP_STATUS_UNSUBMITTED:
        AMVP_LOG_ERR("Security policy information has not yet been submitted.");
        goto err;
    case AMVP_SP_STATUS_PROCESSING:
        AMVP_LOG_STATUS("Security policy information is still being processed. Please try again later.");
        goto err;
    case AMVP_SP_STATUS_GENERATING:
        AMVP_LOG_STATUS("Security policy generation in progress. Try again shortly.");
        goto err;
    case AMVP_SP_STATUS_WAITING_GENERATION:
        AMVP_LOG_STATUS("Security policy not yet generated. Attempting to request security policy generation...");
        if (amvp_create_response_obj(&req_obj, &req_val) != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Error occurred while creating SP generation request body");
            return AMVP_INTERNAL_ERR;
        }
        req_str = json_serialize_to_string(req_val, NULL);

        if (amvp_request_security_policy_generation(ctx, ctx->session_url, req_str) != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Error requesting security policy generation");
            goto err;
        }
        AMVP_LOG_STATUS("Succesfully requested generation of security policy PDF. Check back shortly.");
        break;
    case AMVP_SP_STATUS_SUCCESS:
        AMVP_LOG_STATUS("Security policy ready. Saving...");
        sp_str = json_object_get_string(obj, "content");
        if (!sp_str) {
            AMVP_LOG_ERR("Server indicated security policy was ready, but content is missing!");
            goto err;
        }

        sp_str_len = strnlen_s(sp_str, AMVP_MAX_FILE_PAYLOAD_SIZE + 1);
        if (sp_str_len % 2 != 0 || (sp_str_len / 2) > AMVP_MAX_FILE_PAYLOAD_SIZE) {
            AMVP_LOG_ERR("Security policy data is suspiciously large, stopping...");
            goto err;
        }

        sp_buffer = amvp_decode_base64(sp_str, &sp_buffer_len);
        if (!sp_buffer) {
            AMVP_LOG_ERR("Error decoding base64 while getting security policy");
            goto err;
        }

        fp = fopen(ctx->save_filename, "w");
        if (fp == NULL) {
            AMVP_LOG_ERR("Failed to intialize file output for security policy");
            goto err;
        }

        if (fwrite((const void *)sp_buffer, sp_buffer_len, 1, fp) != 1) {
            AMVP_LOG_ERR("Failure writing security policy to file");
            goto err;
        }

        if (fclose(fp) == EOF) {
            AMVP_LOG_ERR("Failed to finalize security policy file - cannot confirm integrity");
        }

        AMVP_LOG_STATUS("Security policy saved to file %s", ctx->save_filename);
        break;
    case AMVP_SP_STATUS_UNKNOWN:
    case AMVP_SP_STATUS_ERROR:
    default:
        AMVP_LOG_ERR("Error occurred while getting security policy");
        goto err;
    }

    rv = AMVP_SUCCESS;
err:
    if (val) json_value_free(val);
    if (req_val) json_value_free(req_val);
    if (sp_buffer) free(sp_buffer);
    if (req_str) free(req_str);
    return rv;
}

/*
 * Static helper function to auto-detect evidence type from JSON structure
 * by checking the top-level keys in the evidence payload
 */
static AMVP_EVIDENCE_TYPE amvp_detect_evidence_type(JSON_Object *obj) {
    if (!obj) {
        return AMVP_EVIDENCE_TYPE_NA;
    }

    /* Check for functional test evidence - has "functionalTest" top-level key */
    if (json_object_has_value(obj, "functionalTest")) {
        return AMVP_EVIDENCE_TYPE_FUNCTIONAL_TEST;
    }

    /* Check for source code evidence - has "sourceCode" top-level key */
    if (json_object_has_value(obj, "sourceCode")) {
        return AMVP_EVIDENCE_TYPE_SOURCE_CODE;
    }

    /* Check for other documentation evidence - has "otherDocumentation" top-level key */
    if (json_object_has_value(obj, "otherDocumentation")) {
        return AMVP_EVIDENCE_TYPE_OTHER_DOC;
    }

    /* If none of the expected keys are found, return unknown/invalid type */
    return AMVP_EVIDENCE_TYPE_NA;
}

AMVP_RESULT amvp_submit_evidence(AMVP_CTX *ctx, const char *filename) {
    AMVP_RESULT rv = AMVP_INTERNAL_ERR;
    char *reg = NULL, *file = NULL, *ev = NULL;
    int ev_len = 0;
    AMVP_EVIDENCE_TYPE type = AMVP_EVIDENCE_TYPE_NA;

    JSON_Value *val = NULL, *tmp = NULL, *submission = NULL;
    JSON_Object *obj = NULL, *submission_obj = NULL;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (!filename) {
        AMVP_LOG_ERR("Must provide value for JSON filename");
        return AMVP_MISSING_ARG;
    }

    if (strnlen_s(filename, AMVP_JSON_FILENAME_MAX + 1) > AMVP_JSON_FILENAME_MAX) {
        AMVP_LOG_ERR("Provided filename length > max(%d)", AMVP_JSON_FILENAME_MAX);
        return AMVP_INVALID_ARG;
    }

    val = json_parse_file(filename);
    obj = json_value_get_object(val);
    if (!obj) {
        AMVP_LOG_ERR("Provided evidence file is invalid");
        goto end;
    }

    /* Auto-detect evidence type from JSON structure */
    type = amvp_detect_evidence_type(obj);
    if (type <= AMVP_EVIDENCE_TYPE_NA || type >= AMVP_EVIDENCE_TYPE_MAX) {
        AMVP_LOG_ERR("Unable to determine evidence type from file structure. Expected top-level keys: 'functionalTest', 'sourceCode', or 'otherDocumentation'");
        rv = AMVP_INVALID_ARG;
        goto end;
    }

    submission = val;
    submission_obj = json_value_get_object(submission);
    rv = amvp_add_version_to_obj(submission_obj);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Unable to add amvVersion to SP submission");
        goto end;
    }

    ev = json_serialize_to_string_pretty(submission, &ev_len);

    AMVP_LOG_STATUS("Successfully read %s evidence file. Submitting...", amvp_lookup_evidence_type_string(type));
    rv = amvp_send_evidence(ctx, type, ctx->session_url, ev, ev_len);
    if (rv == AMVP_PROTOCOL_RSP_ERR) {
        rv = amvp_handle_protocol_error(ctx, ctx->error);
        if (rv == AMVP_RETRY_OPERATION) {
            rv = amvp_send_evidence(ctx, type, ctx->session_url, ev, ev_len);
        }
    }

    if (rv == AMVP_SUCCESS) {
        AMVP_LOG_STATUS("Evidence successfully submitted!");
    } else {
        AMVP_LOG_ERR("Error sending evidence for cert request session");
        goto end;
    }

    if (val) json_value_free(val);
    val = NULL;
    val = json_parse_string(ctx->curl_buf);
    if (!val) {
        AMVP_LOG_ERR("Error parsing response from server when checking certify session status");
        goto end;
    }

    obj = amvp_get_obj_from_rsp(ctx, val);
    if (!obj) {
        AMVP_LOG_ERR("Error parsing response from server when checking certify session status");
        goto end;
    }

    rv = amvp_check_cert_req_status(ctx);

end:
    if (reg) json_free_serialized_string(reg);
    if (val) json_value_free(val);
    if (tmp) json_value_free(tmp);
    if (file) free(file);
    if (ev) free(ev);
    return rv;
}

AMVP_RESULT amvp_finalize_cert_request(AMVP_CTX *ctx) {
    AMVP_RESULT rv = AMVP_INTERNAL_ERR;
    JSON_Value *val = NULL;
    JSON_Object *obj = NULL;
    AMVP_CERT_REQ_STATUS status = AMVP_CERT_REQ_STATUS_UNKNOWN;

    rv = amvp_get_session_status(ctx, &val);
    if (rv == AMVP_PROTOCOL_RSP_ERR) {
        rv = amvp_handle_protocol_error(ctx, ctx->error);
        if (rv == AMVP_RETRY_OPERATION) {
            if (val) json_value_free(val);  /* Free first response before retry */
            rv = amvp_get_session_status(ctx, &val);
        }
    }

    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Failure attempting to get cert request status while waiting for approval");
        goto end;
    }

    if (!val) {
        AMVP_LOG_ERR("No JSON data received when getting cert request status");
        rv = AMVP_NO_DATA;
        goto end;
    }

    obj = amvp_get_obj_from_rsp(ctx, val);
    if (!obj) {
        AMVP_LOG_ERR("Error parsing info about certify request while waiting for approval");
        rv = AMVP_JSON_ERR;
        goto end;
    }

    status = amvp_parse_cert_req_status_str(obj);
    if (status != AMVP_CERT_REQ_STATUS_SUBMITTED) {
       // AMVP_LOG_ERR("Unable to complete final submission on cert request; it has not yet had all requirements completed.");
      //  goto end;
    }

    rv = amvp_send_cert_finalization(ctx);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Error occurred when requesting final submission of cert request");
        goto end;
    }

    AMVP_LOG_STATUS("Successfully submitted certification request!");
    rv = amvp_check_cert_req_status(ctx);
end:
    if (val) json_value_free(val);
    return rv;
}

/*
 * This routine performs the JSON parsing of the login response
 * from the AMVP server.  The response should contain an initial
 * jwt which will be used once during registration.
 */
static AMVP_RESULT amvp_parse_login(AMVP_CTX *ctx) {
    JSON_Value *val;
    JSON_Object *obj = NULL;
    char *json_buf = ctx->curl_buf;
    const char *jwt;
    AMVP_RESULT rv = AMVP_SUCCESS;

    /*
     * Parse the JSON
     */
    val = json_parse_string(json_buf);
    if (!val) {
        AMVP_LOG_ERR("JSON parse error");
        return AMVP_JSON_ERR;
    }

    obj = amvp_get_obj_from_rsp(ctx, val);

    /*
     * Get the JWT assigned to this session by the server.  This will need
     * to be included when sending the vector responses back to the server
     * later.
     */
    jwt = json_object_get_string(obj, "accessToken");
    if (!jwt) {
        AMVP_LOG_ERR("No access_token provided in registration response");
        rv = AMVP_JWT_MISSING;
        goto end;
    } else {
        if (strnlen_s(jwt, AMVP_JWT_TOKEN_MAX + 1) > AMVP_JWT_TOKEN_MAX) {
            AMVP_LOG_ERR("access_token too large");
            rv = AMVP_JWT_INVALID;
            goto end;
        }

        ctx->jwt_token = calloc(AMVP_JWT_TOKEN_MAX + 1, sizeof(char));
        strcpy_s(ctx->jwt_token, AMVP_JWT_TOKEN_MAX + 1, jwt);
    }
end:
    json_value_free(val);
    return rv;
}

static AMVP_RESULT amvp_login(AMVP_CTX *ctx, int refresh) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    char *login = NULL;
    int login_len = 0;

    AMVP_LOG_STATUS("Logging in...");
    rv = amvp_build_login(ctx, &login, &login_len, refresh);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Unable to build login message");
        goto end;
    }

    /*
     * Send the login to the AMVP server and get the response,
     */
     if (refresh && ctx->jwt_token) {
        free(ctx->jwt_token);
        ctx->jwt_token = NULL;
    }
    rv = amvp_send_login(ctx, login, login_len);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Login Send Failed");
        goto end;
    }

    rv = amvp_parse_login(ctx);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_STATUS("Login Response Failed, %d", rv);
    } else {
        AMVP_LOG_STATUS("Login successful");

        /* If this was a refresh and we have a session file, update it with the new JWT */
        if (refresh && ctx->session_file_path) {
            AMVP_RESULT update_rv = amvp_update_session_file_jwt(ctx);
            if (update_rv != AMVP_SUCCESS) {
                AMVP_LOG_WARN("Failed to update session file with new JWT, but continuing...");
            }
        }
    }
end:
    if (login) free(login);
    return rv;
}

AMVP_RESULT amvp_refresh(AMVP_CTX *ctx) {
    if (!ctx) {
        return AMVP_NO_CTX;
    }

    return amvp_login(ctx, 1);
}

const char *amvp_version(void) {
    return AMVP_LIBRARY_VERSION;
}

const char *amvp_protocol_version(void) {
    return AMVP_VERSION;
}
