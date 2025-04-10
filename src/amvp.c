/** @file */
/*
 * Copyright (c) 2021, Cisco Systems, Inc.
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

static AMVP_CERT_REQ_STATUS amvp_parse_cert_req_status_str(JSON_Object *json);

#define MODULES "modules/"
#define REQUESTS "requests/"
#define AMVP_CERTIFY_ENDPOINT "certify"

typedef enum amvp_sp_status {
    AMVP_SP_STATUS_UNKNOWN = 0,
    AMVP_SP_STATUS_UNSUBMITTED,
    AMVP_SP_STATUS_PROCESSING,
    AMVP_SP_STATUS_WAITING_GENERATION,
    AMVP_SP_STATUS_GENERATING,
    AMVP_SP_STATUS_SUCCESS,
    AMVP_SP_STATUS_ERROR
} AMVP_SP_STATUS;


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
    AMVP_VS_LIST *vs_entry, *vs_e2;
    int i = 0;

    if (!ctx) {
        AMVP_LOG_STATUS("No ctx to free");
        return AMVP_SUCCESS;
    }

    if (ctx->kat_resp) { json_value_free(ctx->kat_resp); }
    if (ctx->curl_buf) { free(ctx->curl_buf); }
    if (ctx->server_name) { free(ctx->server_name); }
    if (ctx->path_segment) { free(ctx->path_segment); }
    if (ctx->cacerts_file) { free(ctx->cacerts_file); }
    if (ctx->tls_cert) { free(ctx->tls_cert); }
    if (ctx->tls_key) { free(ctx->tls_key); }
    if (ctx->http_user_agent) { free(ctx->http_user_agent); }
    if (ctx->session_file_path) { free(ctx->session_file_path); }
    if (ctx->json_filename) { free(ctx->json_filename); }
    if (ctx->session_url) { free(ctx->session_url); }
    if (ctx->vector_req_file) { free(ctx->vector_req_file); }
    if (ctx->get_string) { free(ctx->get_string); }
    if (ctx->delete_string) { free(ctx->delete_string); }
    if (ctx->save_filename) { free(ctx->save_filename); }
    if (ctx->post_filename) { free(ctx->post_filename); }
    if (ctx->put_filename) { free(ctx->put_filename); }
    if (ctx->mod_cert_req_file) { free(ctx->mod_cert_req_file); }
    if (ctx->jwt_token) { free(ctx->jwt_token); }
    if (ctx->tmp_jwt) { free(ctx->tmp_jwt); }
    if (ctx->error) { amvp_free_protocol_err(ctx->error); ctx->error = NULL; }
    if (ctx->vs_list) {
        vs_entry = ctx->vs_list;
        while (vs_entry) {
            vs_e2 = vs_entry->next;
            free(vs_entry);
            vs_entry = vs_e2;
        }
    }
    if (ctx->vsid_url_list) {
        amvp_free_str_list(&ctx->vsid_url_list);
    }
    if (ctx->registration) {
            json_value_free(ctx->registration);
    }
    if (ctx->cert_req_info.contact_count > 0) {
        for (i = 0; i < ctx->cert_req_info.contact_count; i++) {
            free(ctx->cert_req_info.contact_id[i]);
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

    /*
     * Free everything in the Operating Environment structs
     */
    amvp_oe_free_operating_env(ctx);

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
 * This function is used by the application to specify the
 * AMVP server URI path segment prefix.
 */
AMVP_RESULT amvp_set_path_segment(AMVP_CTX *ctx, const char *path_segment) {
    if (!ctx) {
        return AMVP_NO_CTX;
    }
    if (!path_segment) {
        return AMVP_INVALID_ARG;
    }
    if (strnlen_s(path_segment, AMVP_SESSION_PARAMS_STR_LEN_MAX + 1) > AMVP_SESSION_PARAMS_STR_LEN_MAX) {
        AMVP_LOG_ERR("Path segment string(s) too long");
        return AMVP_INVALID_ARG;
    }
    if (ctx->path_segment) { free(ctx->path_segment); }
    ctx->path_segment = calloc(AMVP_SESSION_PARAMS_STR_LEN_MAX + 1, sizeof(char));
    if (!ctx->path_segment) {
        return AMVP_MALLOC_FAIL;
    }
    strcpy_s(ctx->path_segment, AMVP_SESSION_PARAMS_STR_LEN_MAX + 1, path_segment);

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

AMVP_RESULT amvp_mark_as_get_only(AMVP_CTX *ctx, char *string) {
    if (!ctx) {
        return AMVP_NO_CTX;
    } 
    if (!string) {
        return AMVP_MISSING_ARG;
    }
    if (strnlen_s(string, AMVP_REQUEST_STR_LEN_MAX + 1) > AMVP_REQUEST_STR_LEN_MAX) {
         AMVP_LOG_ERR("Request string is suspiciously long...");
        return AMVP_INVALID_ARG;
    }

    if (ctx->get_string) { free(ctx->get_string); }
    ctx->get_string = calloc(AMVP_REQUEST_STR_LEN_MAX + 1, sizeof(char));
    if (!ctx->get_string) {
        return AMVP_MALLOC_FAIL;
    }

    strcpy_s(ctx->get_string, AMVP_REQUEST_STR_LEN_MAX + 1, string);
    ctx->action = AMVP_ACTION_GET;
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

AMVP_RESULT amvp_mark_as_cert_req(AMVP_CTX *ctx, int module_id, int vendor_id) {
    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (!module_id || !vendor_id) {
        AMVP_LOG_ERR("Missing module or vendor ID");
        return AMVP_INVALID_ARG;
    }
    ctx->cert_req_info.module_id = module_id;
    ctx->cert_req_info.vendor_id = vendor_id;
    ctx->action = AMVP_ACTION_CERT_REQ;
    return AMVP_SUCCESS;
}

AMVP_RESULT amvp_cert_req_add_contact(AMVP_CTX *ctx, const char *contact_id) {
    int len = 0;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (!contact_id) {
        return AMVP_MISSING_ARG;
    }

    if (ctx->action != AMVP_ACTION_CERT_REQ) {
        AMVP_LOG_ERR("Session must be marked as a certify request to add contact info");
        return AMVP_UNSUPPORTED_OP;
    }
    if (ctx->cert_req_info.contact_count >= AMVP_MAX_CONTACTS_PER_CERT_REQ) {
        AMVP_LOG_ERR("Already at maximum number of contacts per cert request");
        return AMVP_UNSUPPORTED_OP;
    }

    len = strnlen_s(contact_id, AMVP_CONTACT_STR_MAX_LEN + 1);
    if (!len || len > AMVP_CONTACT_STR_MAX_LEN) {
        AMVP_LOG_ERR("Provided contact ID string is too long or empty");
        return AMVP_INVALID_ARG;
    }

    ctx->cert_req_info.contact_id[ctx->cert_req_info.contact_count] = calloc(len + 1, sizeof(char));
    if (!ctx->cert_req_info.contact_id[ctx->cert_req_info.contact_count]) {
        AMVP_LOG_ERR("Error allocating memory for contact ID in cert request");
        return AMVP_MALLOC_FAIL;
    }

    if (strncpy_s(ctx->cert_req_info.contact_id[ctx->cert_req_info.contact_count], len + 1, contact_id, len)) {
        AMVP_LOG_ERR("Error copying contact ID string into cert request");
        free(ctx->cert_req_info.contact_id[ctx->cert_req_info.contact_count]);
        return AMVP_INTERNAL_ERR;
    }

    ctx->cert_req_info.contact_count++;
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
    if (token) free(token);
    return rv;
}

AMVP_RESULT amvp_create_module(AMVP_CTX *ctx, char *filename) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    char *reg = NULL, *file = NULL;
    const char *url = NULL, *id = NULL, *tmp = NULL;
    int reg_len = 0, diff = 0, level = 0;
    JSON_Value *tmp_json = NULL, *val = NULL;
    JSON_Object *obj = NULL, *obj2 = NULL;
    if (!ctx) {
        return AMVP_NO_CTX;
    }

    /*
     * Send the capabilities to the AMVP server and get the response,
     * which should be a list of vector set ID urls
     */
    AMVP_LOG_STATUS("Reading module file...\n");
    tmp_json = json_parse_file(filename);
    if (!tmp_json) {
        AMVP_LOG_ERR("Error reading module file");
        rv = AMVP_JSON_ERR;
        goto end;
    }

    /* Sanity check format, Log some info about the module */
    obj = amvp_get_obj_from_rsp(ctx, tmp_json);
    if (!obj) {
        AMVP_LOG_ERR("Module file in incorrect format");
        rv = AMVP_JSON_ERR;
        goto end;
    }
    obj2 = json_object_get_object(obj, "moduleInfo");
    if (!obj2) {
        AMVP_LOG_ERR("Module file missing required info");
        rv = AMVP_JSON_ERR;
        goto end;
    }
    tmp = json_object_get_string(obj2, "name");
    if (!tmp) {
        AMVP_LOG_ERR("Module file missing required info (name)");
        rv = AMVP_JSON_ERR;
        goto end;
    }
    AMVP_LOG_STATUS("Module Name: %s", tmp);

    tmp = json_object_get_string(obj2, "description");
    if (!tmp) {
        AMVP_LOG_ERR("Module file missing required info (description)");
        rv = AMVP_JSON_ERR;
        goto end;
    }
    AMVP_LOG_STATUS("Description: %s", tmp);

    tmp = json_object_get_string(obj2, "type");
    if (!tmp) {
        AMVP_LOG_ERR("Module file missing required info (type)");
        rv = AMVP_JSON_ERR;
        goto end;
    }
    AMVP_LOG_STATUS("Type: %s", tmp);

    level = json_object_get_number(obj2, "overallSecurityLevel");
    if (!level) {
        AMVP_LOG_ERR("Module file missing required info (level)");
        rv = AMVP_JSON_ERR;
        goto end;
    }
    AMVP_LOG_STATUS("Overall Security Level: %d\n", level);

    reg = json_serialize_to_string(tmp_json, &reg_len);

    rv = amvp_login(ctx, 0);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Error logging in with AMVP server while trying to create module");
        goto end;
    }

    AMVP_LOG_STATUS("Sending module create request...");
    rv = amvp_send_module_creation(ctx, reg, reg_len);
    if (rv == AMVP_SUCCESS) {
        val = json_parse_string(ctx->curl_buf);
        if (!val) {
            AMVP_LOG_ERR("Error while parsing json from server!");
            rv = AMVP_JSON_ERR;
            goto end;
        }
        obj = amvp_get_obj_from_rsp(ctx, val);
        if (!obj) {
            AMVP_LOG_ERR("Error while parsing json from server!");
            rv = AMVP_JSON_ERR;
            goto end;
        }
        url = json_object_get_string(obj, "url");

        file = calloc(AMVP_REQ_FILENAME_MAX_LEN + 1, sizeof(char));
        if (!file) {
            AMVP_LOG_ERR("Unable to allocate memory for storing module file");
            goto end;
        }

        id = url;
        while(*id != 0) {
            memcmp_s(id, strlen(REQUESTS), REQUESTS, strlen(REQUESTS), &diff);
            if (!diff) {
                break;
            }
            id++;
        }
        id += strnlen_s(REQUESTS, AMVP_ATTR_URL_MAX);

        AMVP_LOG_STATUS("Module Request URL: %s", url);

        snprintf(file, AMVP_REQ_FILENAME_MAX_LEN + 1, "%s_%s_%s.json", AMVP_MODULE_FILENAME_DEFAULT, AMVP_REQ_FILENAME_DEFAULT, id);
        rv = amvp_json_serialize_to_file_pretty_w(json_object_get_wrapping_value(obj), file);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Failed to write module creation response to file.");
        } else {
            amvp_json_serialize_to_file_pretty_a(NULL, file);
            AMVP_LOG_STATUS("Successfully created module request and saved request info to file %s", file);
        }
    }

end:
    if (reg) free(reg);
    if (file) free (file);
    if (val) json_value_free(val);
    if (tmp_json) json_value_free(tmp_json);
    return rv;
}

AMVP_RESULT amvp_get_module_request(AMVP_CTX *ctx, char *filename) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    AMVP_REQUEST_STATUS status = 0;
    JSON_Value *val = NULL;
    JSON_Array *arr = NULL;
    JSON_Object *obj = NULL;
    const char *url = NULL;
    char *approved = NULL, *substr = NULL, *file = NULL;
    int len = 0;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    /*
     * Send the capabilities to the AMVP server and get the response,
     * which should be a list of vector set ID urls
     */
    val = json_parse_file(filename);
    arr = json_value_get_array(val);
    obj = json_array_get_object(arr, 0);
    if (!obj) {
        AMVP_LOG_ERR("Invalid request file provided when getting module request");
        goto end;
    }
    url = json_object_get_string(obj, "url");
    if (!url) {
        AMVP_LOG_ERR("Request file missing URL");
        goto end;
    }

    rv = amvp_login(ctx, 0);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Error logging in with AMVP server while trying to get module request status");
        goto end;
    }

    rv = amvp_transport_get(ctx, url, NULL);

    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Failed to get status of request from server");
        goto end;
    }

    status = amvp_get_request_status(ctx, &approved);
    switch (status) {
    case AMVP_REQUEST_STATUS_INITIAL:
        AMVP_LOG_STATUS("Module request still in initial status");
        break;
    case AMVP_REQUEST_STATUS_APPROVED:
        /* Check and make sure the approved Url is a module before storing it as a module */
        len = strnlen_s(approved, AMVP_REQUEST_STR_LEN_MAX + 1);
        strstr_s(approved, len, AMVP_MODULE_ENDPOINT, sizeof(AMVP_MODULE_ENDPOINT) - 1, &substr);
        if (!substr) {
            AMVP_LOG_ERR("Request approved, but not saving to file as it is not a module. URL: %s", approved);
            goto end;
        }
        AMVP_LOG_STATUS("Module request approved! URL: %s", approved);
        AMVP_LOG_STATUS("Saving module info to file...");

        rv = amvp_transport_get(ctx, approved, NULL);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Failure getting approved module info");
            goto end;
        }

        /* substr is set to beginning of "modules" - set it to whatever comes after "modules/" */
        substr += sizeof(AMVP_MODULE_ENDPOINT);

        file = calloc(AMVP_REQ_FILENAME_MAX_LEN + 1, sizeof(char));
        if (!file) {
            AMVP_LOG_ERR("Unable to allocate memory for storing module file");
            goto end;
        }

        if (val) json_value_free(val);
        val = json_parse_string(ctx->curl_buf);
        obj = amvp_get_obj_from_rsp(ctx, val);
        if (!obj) {
            AMVP_LOG_ERR("Failure getting approved module info");
            goto end;
        }
        json_object_set_string(obj, "url", approved);

        snprintf(file, AMVP_REQ_FILENAME_MAX_LEN + 1, "%s_%s.json", AMVP_MODULE_FILENAME_DEFAULT, substr);
        rv = amvp_json_serialize_to_file_pretty_w(json_object_get_wrapping_value(obj), file);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Failed to write module info to file.");
        } else {
            amvp_json_serialize_to_file_pretty_a(NULL, file);
            AMVP_LOG_STATUS("Successfully saved module info to file %s", file);
        }
        break;
    case AMVP_REQUEST_STATUS_REJECTED:
        AMVP_LOG_STATUS("Module request was rejected");
        break;
    default:
        AMVP_LOG_ERR("Unable to determine request status");
        break;
    }

end:
    if (approved) free(approved);
    if (file) free(file);
    if (val) json_value_free(val);
    return rv;
}

static char* amvp_get_module_name_from_id(AMVP_CTX *ctx, int id) {
    char *url = NULL, *module_name = NULL;
    AMVP_RESULT rv = AMVP_SUCCESS;
    JSON_Value *val = NULL;
    JSON_Object *obj = NULL;

    url = calloc(AMVP_ATTR_URL_MAX + 1, sizeof(char));
    if (!url) {
        AMVP_LOG_ERR("Memory allocation error while fetching module name");
        goto end;
    }
    snprintf(url, AMVP_ATTR_URL_MAX + 1, "/amvp/v1/modules/%d", id);
    rv = amvp_transport_get(ctx, url, NULL);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Error fetching module name");
        goto end;
    }

    val = json_parse_string(ctx->curl_buf);
    if (!val) {
        AMVP_LOG_ERR("Error reading response when getting module name");
        goto end;
    }
    obj = amvp_get_obj_from_rsp(ctx, val);
    if (json_object_has_value(obj, "name")) {
        module_name = calloc(AMVP_MAX_MODULE_NAME_LEN + 1, sizeof(char));
        if (!module_name) {
            AMVP_LOG_ERR("Error allocating memory for module name");
            goto end;
        }
        strncpy_s(module_name, AMVP_MAX_MODULE_NAME_LEN + 1, json_object_get_string(obj, "name"), json_object_get_string_len(obj, "name"));
    }

end:
    if (val) json_value_free(val);
    if (url) free(url);
    return module_name;

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

    /* Determine if this session has already retreived its expected TE list */
    status = json_object_get_string(obj, "status");
    if (status) {
        cert_req_status = amvp_parse_cert_req_status_str(obj);
        if (cert_req_status != AMVP_CERT_REQ_STATUS_INITIAL &&
                json_object_has_value(obj, "securityPolicyStatus") &&
                json_object_has_value(obj, "functionalTestStatus") &&
                json_object_has_value(obj, "sourceCodeStatus")) {
            ctx->session_file_has_te_list = 1;
        }
    }

    rv = AMVP_SUCCESS;
end:
    if (val) json_value_free(val);
    return rv;
}

static AMVP_CERT_REQ_STATUS amvp_parse_cert_req_status_str(JSON_Object *json) {
    const char *status = NULL;
    int diff = 1;
    size_t len = 0;

    if (!json || !json_object_has_value_of_type(json, "status", JSONString)) {
        return AMVP_CERT_REQ_STATUS_UNKNOWN;
    }

    status = json_object_get_string(json, "status");
    len = strnlen_s(status, AMVP_CERT_REQ_STATUS_MAX_LEN + 1);
    if (len > AMVP_CERT_REQ_STATUS_MAX_LEN) {
        return AMVP_CERT_REQ_STATUS_UNKNOWN;
    }

    strncmp_s(AMVP_CERT_REQ_STATUS_STR_INITIAL, sizeof(AMVP_CERT_REQ_STATUS_STR_INITIAL) - 1, status, len, &diff);
    if (!diff) return AMVP_CERT_REQ_STATUS_INITIAL;
    strncmp_s(AMVP_CERT_REQ_STATUS_STR_READY, sizeof(AMVP_CERT_REQ_STATUS_STR_READY) - 1, status, len, &diff);
    if (!diff) return AMVP_CERT_REQ_STATUS_READY;
    strncmp_s(AMVP_CERT_REQ_STATUS_STR_SUBMITTED, sizeof(AMVP_CERT_REQ_STATUS_STR_SUBMITTED) - 1, status, len, &diff);
    if (!diff) return AMVP_CERT_REQ_STATUS_SUBMITTED;
    strncmp_s(AMVP_CERT_REQ_STATUS_STR_IN_REVIEW, sizeof(AMVP_CERT_REQ_STATUS_STR_IN_REVIEW) - 1, status, len, &diff);
    if (!diff) return AMVP_CERT_REQ_STATUS_IN_REVIEW;
    strncmp_s(AMVP_CERT_REQ_STATUS_STR_APPROVED, sizeof(AMVP_CERT_REQ_STATUS_STR_APPROVED) - 1, status, len, &diff);
    if (!diff) return AMVP_CERT_REQ_STATUS_APPROVED;
    strncmp_s(AMVP_CERT_REQ_STATUS_STR_REJECTED, sizeof(AMVP_CERT_REQ_STATUS_STR_REJECTED) - 1, status, len, &diff);
    if (!diff) return AMVP_CERT_REQ_STATUS_REJECTED;
    strncmp_s(AMVP_CERT_REQ_STATUS_STR_ERROR, sizeof(AMVP_CERT_REQ_STATUS_STR_ERROR) - 1, status, len, &diff);
    if (!diff) return AMVP_CERT_REQ_STATUS_ERROR;

    return AMVP_CERT_REQ_STATUS_UNKNOWN;
}

/* Output prettified cert request status to log */
static AMVP_RESULT amvp_output_cert_request_status(AMVP_CTX *ctx, JSON_Object *status_json) {
    JSON_Object *tmp_obj = NULL;
    JSON_Array *arr = NULL;
    char *module_name = NULL;
    int req_id = 0, module_id = 0, vendor_id = 0, i = 0;
    size_t arr_size = 0;
    AMVP_RESULT rv = AMVP_SUCCESS;
    AMVP_NAME_LIST *fte_list = NULL, *fte_iter = NULL, *sce_list = NULL, *sce_iter = NULL;
    AMVP_SL_LIST *sp_list = NULL, *sp_iter = NULL;
    AMVP_CERT_REQ_STATUS cert_req_status = AMVP_CERT_REQ_STATUS_UNKNOWN;
    const char *feedback = NULL, *cert_id = NULL;
    if (!ctx || !status_json) {
        return AMVP_INTERNAL_ERR;
    }
    cert_req_status = amvp_parse_cert_req_status_str(status_json);

    /* We want to collect all the information from JSON first, then output all at once so we have better control over output */
    if (json_object_has_value_of_type(status_json, "url", JSONString)) {
        sscanf(json_object_get_string(status_json, "url"), "/amvp/v1/certRequests/%d", &req_id);
    } else if (json_object_has_value_of_type(status_json, "certRequestId", JSONNumber)) {
        req_id = (int) json_object_get_number(status_json, "certRequestId");
    }

    module_id = (int)json_object_get_number(status_json, "moduleId");
    module_name = amvp_get_module_name_from_id(ctx, module_id);
    if (!module_name) {
        AMVP_LOG_ERR("Error getting module name from cert request info");
        goto end;
    }

    if (json_object_has_value_of_type(status_json, "vendorId", JSONNumber)) {
        vendor_id = (int)json_object_get_number(status_json, "vendorId");
    }

    /* Begin prettified logging of data */
    AMVP_LOG_STATUS("");
    AMVP_LOG_STATUS("Current status of module certification request:");
    AMVP_LOG_STATUS(AMVP_ANSI_COLOR_GREEN "    Certification Request %d" AMVP_ANSI_COLOR_RESET, req_id);
    AMVP_LOG_STATUS(AMVP_ANSI_COLOR_GREEN "    Module ID: %d (%s)" AMVP_ANSI_COLOR_RESET, module_id, module_name);
    if (vendor_id) {
        AMVP_LOG_STATUS(AMVP_ANSI_COLOR_GREEN "    Vendor ID: %d" AMVP_ANSI_COLOR_RESET, vendor_id);
    }
    AMVP_LOG_STATUS("    Status:");
    switch (cert_req_status) {
    case AMVP_CERT_REQ_STATUS_INITIAL:
        AMVP_LOG_STATUS("        " AMVP_ANSI_COLOR_YELLOW "The cert request has not yet finished initializing." AMVP_ANSI_COLOR_RESET);
        goto end;
    case AMVP_CERT_REQ_STATUS_READY:
        AMVP_LOG_STATUS("        " AMVP_ANSI_COLOR_GREEN "The cert request is ready for data submissions!" AMVP_ANSI_COLOR_RESET);
        break;
    case AMVP_CERT_REQ_STATUS_SUBMITTED:
        AMVP_LOG_STATUS("        " AMVP_ANSI_COLOR_GREEN "All required data has been submitted!" AMVP_ANSI_COLOR_RESET);
        break;
    case AMVP_CERT_REQ_STATUS_IN_REVIEW:
        AMVP_LOG_STATUS("        " AMVP_ANSI_COLOR_YELLOW "The cert request is currently being reviewed." AMVP_ANSI_COLOR_RESET);
        goto end;
    case AMVP_CERT_REQ_STATUS_APPROVED:
        cert_id = json_object_get_string(status_json, "validationCertificate");
        if (!cert_id) {
            AMVP_LOG_ERR("Server marked request as approved, but failed to provide a certificate number");
            goto end;
        }
        AMVP_LOG_STATUS("        " AMVP_ANSI_COLOR_GREEN "The cert request has been approved!" AMVP_ANSI_COLOR_RESET);
        AMVP_LOG_STATUS("        " AMVP_ANSI_COLOR_GREEN "Certificate ID: %s" AMVP_ANSI_COLOR_RESET, cert_id);
        goto end;
    case AMVP_CERT_REQ_STATUS_REJECTED:
        AMVP_LOG_STATUS("        " AMVP_ANSI_COLOR_RED "The cert request has been rejected." AMVP_ANSI_COLOR_RESET);
        feedback = json_object_get_string(status_json, "ruleFeedback");
        AMVP_LOG_STATUS("        " AMVP_ANSI_COLOR_RED "Reasoning: %s\n" AMVP_ANSI_COLOR_RESET, feedback);
        break;
    case AMVP_CERT_REQ_STATUS_ERROR:
        AMVP_LOG_ERR("        " AMVP_ANSI_COLOR_RED "The cert request has encountered an error." AMVP_ANSI_COLOR_RESET);
        goto end;
    case AMVP_CERT_REQ_STATUS_UNKNOWN:
    default:
        AMVP_LOG_ERR("        " AMVP_ANSI_COLOR_RED "The cert request status is unknown." AMVP_ANSI_COLOR_RESET);
        goto end;
    }

    /* Get the expected functional test evidence list, or the list of not submitted yet TEs */
    arr = json_object_get_array(status_json, "expectedFunctionalTestEvidence");
    if (!arr) {
        arr_size = 0;
    } else {
        arr_size = json_array_get_count(arr);
        for (i = 0; i < (int)arr_size; i++) {
            tmp_obj = json_array_get_object(arr, i);
            amvp_append_name_list(&fte_list, json_object_get_string(tmp_obj, "testRequirement"));
        }
    }

    /* Get the expected source code evidence list, or the list of not submitted yet TEs */
    arr = json_object_get_array(status_json, "expectedSourceCodeEvidence");
    if (!arr) {
        arr_size = 0;
    } else {
        arr_size = json_array_get_count(arr);
        for (i = 0; i < (int)arr_size; i++) {
            tmp_obj = json_array_get_object(arr, i);
            amvp_append_name_list(&sce_list, json_object_get_string(tmp_obj, "testRequirement"));
        }
    }

    /* Get the list of missing security policy sections */
    arr = json_object_get_array(status_json, "missingSecurityPolicySection");
    if (!arr) {
        arr_size = 0;
    } else {
        arr_size = json_array_get_count(arr);
        for (i = 0; i < (int)arr_size; i++) {
            tmp_obj = json_array_get_object(arr, i);
            amvp_append_sl_list(&sp_list, json_array_get_number(arr, i));
        }
    }

    AMVP_LOG_STATUS("    List of remaining required functional test evidence submissions:");
    if (fte_list) {
        fte_iter = fte_list;
        while (fte_iter) {
            AMVP_LOG_STATUS(AMVP_ANSI_COLOR_YELLOW "        %s" AMVP_ANSI_COLOR_RESET, fte_iter->name);
            fte_iter = fte_iter->next;
        }
    } else {
        AMVP_LOG_STATUS(AMVP_ANSI_COLOR_GREEN "        All expected functional test evidence has been submitted!" AMVP_ANSI_COLOR_RESET);
    }

    AMVP_LOG_STATUS("    List of remaining required source code evidence submissions:");
    if (sce_list) {
        sce_iter = sce_list;
        while (sce_iter) {
            AMVP_LOG_STATUS(AMVP_ANSI_COLOR_YELLOW "        %s" AMVP_ANSI_COLOR_RESET, sce_iter->name);
            sce_iter = sce_iter->next;
        }
    } else {
        AMVP_LOG_STATUS(AMVP_ANSI_COLOR_GREEN "        All expected source code evidence has been submitted!" AMVP_ANSI_COLOR_RESET);
    }

    AMVP_LOG_STATUS("    List of unsubmitted security policy sections:");
    if (sp_list) {
        sp_iter = sp_list;
        while (sp_iter) {
            AMVP_LOG_STATUS(AMVP_ANSI_COLOR_YELLOW "        %d" AMVP_ANSI_COLOR_RESET, sp_iter->length);
            sp_iter = sp_iter->next;
        }
    } else {
        AMVP_LOG_STATUS(AMVP_ANSI_COLOR_GREEN "        All expected SP sections have been submitted!" AMVP_ANSI_COLOR_RESET);
    }
    AMVP_LOG_STATUS("");

end:
    if (fte_list) amvp_free_nl(fte_list);
    if (sce_list) amvp_free_nl(sce_list);
    if (sp_list) amvp_free_sl(sp_list);
    if (module_name) free(module_name);
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
 
        rv = amvp_transport_get(ctx, ctx->session_url, NULL);
        if (rv == AMVP_PROTOCOL_RSP_ERR) {
            rv = amvp_handle_protocol_error(ctx, ctx->error);
            if (rv == AMVP_RETRY_OPERATION) {
                rv = amvp_transport_get(ctx, ctx->session_url, NULL);
            }
        }

        val = json_parse_string(ctx->curl_buf);
        if (!val) {
            AMVP_LOG_ERR("Unable to parse JSON from server response when getting cert req status");
            return AMVP_JSON_ERR;
        }

        obj = amvp_get_obj_from_rsp(ctx, val);
        if (!obj) {
            AMVP_LOG_ERR("Unrecognized JSON format found when getting cert req status");
            return AMVP_JSON_ERR;
        }

        status = amvp_parse_cert_req_status_str(obj);
        switch (status) {
        case AMVP_CERT_REQ_STATUS_INITIAL:
            AMVP_LOG_STATUS("Certification request is still initializing...");
            rv = amvp_retry_handler(ctx, &retry_period, &time_waited_so_far, 1, AMVP_WAITING_FOR_TESTS);
            retry = 1;
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
        default:
            AMVP_LOG_ERR("An error occurred while parsing the cert request status");
            rv = AMVP_JSON_ERR;
            goto end;
        }

    } while (retry);

end:
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
    char *module_name = NULL, *reg = NULL, *file = NULL;
    int reg_len = 0, i = 0;
    JSON_Value *cert_submission_val = NULL, *cert_rsp_val = NULL, *cert_info_val = NULL,
               *output_file_val = NULL;
    JSON_Object *tmp_obj = NULL;
    const char *url = NULL, *token = NULL;

    if (!ctx) {
        return AMVP_NO_CTX;
    }
    rv = amvp_login(ctx, 0);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Failed to login to AMVP server when creating cert request");
        goto end;
    }

    /* do a get on the module ID provided and show its basic info in logs */
    AMVP_LOG_STATUS("Fetching info about cert req...");

    module_name = amvp_get_module_name_from_id(ctx, ctx->cert_req_info.module_id);

    AMVP_LOG_STATUS("    Module: %s", module_name);
    if (ctx->cert_req_info.vendor_id) {
        AMVP_LOG_STATUS("    Vendor: %d", ctx->cert_req_info.vendor_id);
    }
    if (ctx->cert_req_info.contact_count > 0) {
        AMVP_LOG_STATUS("    Contacts:");
    }
    for (i = 0; i < ctx->cert_req_info.contact_count; i++) {
        AMVP_LOG_STATUS("        %s", ctx->cert_req_info.contact_id[i]);
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
    rv = amvp_transport_post(ctx, "/amvp/v1/certRequests", reg, reg_len);
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

    AMVP_LOG_STATUS("Successfully sent certify request. Saving details and proceeding...");

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
    if (module_name) free(module_name);
    if (output_file_val) json_value_free(output_file_val); //Also frees the header and body vals
    if (cert_info_val) json_value_free(cert_info_val);
    if (cert_rsp_val) json_value_free(cert_rsp_val);
    if (cert_submission_val) json_value_free(cert_submission_val);
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

    rv = amvp_get_security_policy_json(ctx, ctx->session_url);
    if (rv == AMVP_PROTOCOL_RSP_ERR) {
        rv = amvp_handle_protocol_error(ctx, ctx->error);
        if (rv == AMVP_RETRY_OPERATION) {
            rv = amvp_get_security_policy_json(ctx, ctx->session_url);
        }
    }
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Failed to get SP JSON payload from server");
        return AMVP_TRANSPORT_FAIL;
    }

    val = json_parse_string(ctx->curl_buf);
    if (!val) {
        AMVP_LOG_ERR("Error parsing response from server when checking certify session status");
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

        if (fwrite((const void *)sp_buffer, sp_buffer_len, 1, fp) == EOF) {
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
    if (sp_buffer) free(sp_buffer);
    return rv;
}

AMVP_RESULT amvp_submit_evidence(AMVP_CTX *ctx, const char *filename, AMVP_EVIDENCE_TYPE type) {
    AMVP_RESULT rv = AMVP_INTERNAL_ERR;
    char *reg = NULL, *file = NULL, *ev = NULL;
    int ev_len = 0;

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

    if (type <= AMVP_EVIDENCE_TYPE_NA || type >= AMVP_EVIDENCE_TYPE_MAX) {
        AMVP_LOG_ERR("Invalid evidence type indicated, unable to submit");
        return AMVP_INVALID_ARG;
    }

    val = json_parse_file(filename);
    obj = json_value_get_object(val);
    if (!obj) {
        AMVP_LOG_ERR("Provided evidence file is invalid");
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

    AMVP_LOG_STATUS("Successfully read evidence file. Submitting...");
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
    return rv;
}

AMVP_RESULT amvp_finalize_cert_request(AMVP_CTX *ctx) {
    AMVP_RESULT rv = AMVP_INTERNAL_ERR;
    JSON_Value *val = NULL;
    JSON_Object *obj = NULL;
    AMVP_CERT_REQ_STATUS status = AMVP_CERT_REQ_STATUS_UNKNOWN;
    char *url = NULL;

    rv = amvp_transport_get(ctx, ctx->session_url, NULL);
    if (rv == AMVP_PROTOCOL_RSP_ERR) {
        rv = amvp_handle_protocol_error(ctx, ctx->error);
        if (rv == AMVP_RETRY_OPERATION) {
            rv = amvp_transport_get(ctx, ctx->session_url, NULL);
        }
    }

    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Failure attempting to get cert request status while waiting for approval");
        goto end;
    }

    if (val) json_value_free(val);
    val = json_parse_string(ctx->curl_buf);
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

    url = calloc(AMVP_ATTR_URL_MAX, sizeof(char));
    if (!url) {
        AMVP_LOG_ERR("Unable to allocate URL for finalizing submission of cert request");
        goto end;
    }
    snprintf(url, AMVP_ATTR_URL_MAX, "%s/%s", ctx->session_url, AMVP_CERTIFY_ENDPOINT);
    rv = amvp_transport_post(ctx, url, "{\"amvVersion\": 0.1}", 20);
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
