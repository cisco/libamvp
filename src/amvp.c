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

static AMVP_RESULT amvp_cert_req(AMVP_CTX *ctx);
/*
 * Forward prototypes for local functions
 */
static AMVP_RESULT amvp_login(AMVP_CTX *ctx, int refresh);

static AMVP_RESULT amvp_append_vsid_url(AMVP_CTX *ctx, const char *vsid_url);

static AMVP_RESULT amvp_parse_login(AMVP_CTX *ctx);

static AMVP_RESULT amvp_parse_session_info_file(AMVP_CTX *ctx, const char *filename);

static void amvp_cap_free_sl(AMVP_SL_LIST *list);

static void amvp_cap_free_nl(AMVP_NAME_LIST *list);

static void amvp_cap_free_pl(AMVP_PARAM_LIST *list);

static void amvp_cap_free_domain(AMVP_JSON_DOMAIN_OBJ *domain);

static AMVP_RESULT amvp_retry_handler(AMVP_CTX *ctx, int *retry_period, unsigned int *waited_so_far, int modifier, AMVP_WAITING_STATUS situation);

static AMVP_RESULT amvp_handle_protocol_error(AMVP_CTX *ctx, AMVP_PROTOCOL_ERR *err);

static AMVP_RESULT amvp_write_session_info(AMVP_CTX *ctx);

/*
 * This is the first function the user should invoke to allocate
 * a new context to be used for the test session.
 */
AMVP_RESULT amvp_create_test_session(AMVP_CTX **ctx,
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
    if (ctx->post_resources_filename) { free(ctx->post_resources_filename); }
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
 * Simple utility function to free a supported length
 * list from the capabilities structure.
 */
static void amvp_cap_free_sl(AMVP_SL_LIST *list) {
    AMVP_SL_LIST *top = list;
    AMVP_SL_LIST *tmp;

    while (top) {
        tmp = top;
        top = top->next;
        free(tmp);
    }
}

/*
 * Simple utility function to free a supported param
 * list from the capabilities structure.
 */
static void amvp_cap_free_pl(AMVP_PARAM_LIST *list) {
    AMVP_PARAM_LIST *top = list;
    AMVP_PARAM_LIST *tmp;

    while (top) {
        tmp = top;
        top = top->next;
        free(tmp);
    }
}

/*
 * Simple utility function to free a name
 * list from the capabilities structure.
 */
static void amvp_cap_free_nl(AMVP_NAME_LIST *list) {
    AMVP_NAME_LIST *top = list;
    AMVP_NAME_LIST *tmp;

    while (top) {
        tmp = top;
        top = top->next;
        free(tmp);
    }
}

static void amvp_cap_free_domain(AMVP_JSON_DOMAIN_OBJ *domain) {
    if (!domain) {
        return;
    }
    amvp_cap_free_sl(domain->values);
    return;
}

/**
 * Allows application (with proper authentication) to connect to server and request
 * it cancel the session, halting processing and deleting related data
 */
AMVP_RESULT amvp_cancel_test_session(AMVP_CTX *ctx, const char *request_filename, const char *save_filename) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    JSON_Value *val = NULL;
    int len = 0;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (save_filename) {
        len = strnlen_s(save_filename, AMVP_JSON_FILENAME_MAX + 1);
        if (len > AMVP_JSON_FILENAME_MAX || len <= 0) {
            AMVP_LOG_ERR("Provided save filename too long or too short");
            rv = AMVP_INVALID_ARG;
            goto end;
        }
    }

    rv = amvp_parse_session_info_file(ctx, request_filename);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Error reading session info file, unable to cancel session");
        goto end;
    }

    rv = amvp_refresh(ctx);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Failed to refresh login with AMVP server");
        goto end;
    }

    rv = amvp_transport_delete(ctx, ctx->session_url);

    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Unable to cancel test session");
        goto end;
    }
    if (save_filename) {
        AMVP_LOG_STATUS("Saving cancel request response to specified file...");
        val = json_parse_string(ctx->curl_buf);
        if (!val) {
            AMVP_LOG_ERR("Unable to parse JSON. printing output instead...");
        } else {
            rv = amvp_json_serialize_to_file_pretty_w(val, save_filename);
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("Failed to write file, printing instead...");
            } else {
                rv = amvp_json_serialize_to_file_pretty_a(NULL, save_filename);
                if (rv != AMVP_SUCCESS)
                    AMVP_LOG_WARN("Unable to append ending ] to write file");
                goto end;
            }
        }
    }
    AMVP_LOG_STATUS("DELETE Response:\n\n%s\n", ctx->curl_buf);

end:
    if (val) json_value_free(val);
    return rv;
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

AMVP_RESULT amvp_mark_as_request_only(AMVP_CTX *ctx, char *filename) {
    if (!ctx) {
        return AMVP_NO_CTX;
    } 
    if (!filename) {
        return AMVP_MISSING_ARG;
    }
    if (strnlen_s(filename, AMVP_SESSION_PARAMS_STR_LEN_MAX + 1) > AMVP_SESSION_PARAMS_STR_LEN_MAX) {
         AMVP_LOG_ERR("Vector filename is suspiciously long...");
        return AMVP_INVALID_ARG;
    }

    if (ctx->vector_req_file) { free(ctx->vector_req_file); }
    ctx->vector_req_file = calloc(AMVP_SESSION_PARAMS_STR_LEN_MAX + 1, sizeof(char));
    if (!ctx->vector_req_file) {
        return AMVP_MALLOC_FAIL;
    }
    strcpy_s(ctx->vector_req_file, AMVP_SESSION_PARAMS_STR_LEN_MAX + 1, filename);
    ctx->vector_req = 1;
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

AMVP_RESULT amvp_mark_as_post_resources(AMVP_CTX *ctx, char *filename) {

    if (!ctx) {
        return AMVP_NO_CTX;
    } 
    if (!filename) {
        return AMVP_MISSING_ARG;
    }
    if (strnlen_s(filename, AMVP_SESSION_PARAMS_STR_LEN_MAX + 1) > AMVP_SESSION_PARAMS_STR_LEN_MAX) {
         AMVP_LOG_ERR("Request filename is suspiciously long...");
        return AMVP_INVALID_ARG;
    }

    if (ctx->post_resources_filename) { free(ctx->post_resources_filename); }
    ctx->post_resources_filename = calloc(AMVP_SESSION_PARAMS_STR_LEN_MAX + 1, sizeof(char));
    if (!ctx->post_resources_filename) {
        return AMVP_MALLOC_FAIL;
    }

    strcpy_s(ctx->post_resources_filename, AMVP_SESSION_PARAMS_STR_LEN_MAX + 1, filename);
    ctx->post_resources = 1;
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
#ifdef AMVP_OLD_JSON_FORMAT
    AMVP_RESULT rv = AMVP_SUCCESS;
    JSON_Value *reg_arry_val = NULL;
    JSON_Value *ver_val = NULL;
    JSON_Object *ver_obj = NULL;
    JSON_Value *pw_val = NULL;
    JSON_Object *pw_obj = NULL;
    JSON_Array *reg_arry = NULL;
    char *token = NULL;

    if (!login_len) return AMVP_INVALID_ARG;

    /*
     * Start the login array
     */
    reg_arry_val = json_value_init_array();
    reg_arry = json_array((const JSON_Value *)reg_arry_val);
    ver_val = json_value_init_object();
    ver_obj = json_value_get_object(ver_val);

    json_object_set_string(ver_obj, AMVP_PROTOCOL_VERSION_STR, AMVP_VERSION);
    json_array_append_value(reg_arry, ver_val);

    if (ctx->totp_cb || refresh) {
        pw_val = json_value_init_object();
        pw_obj = json_value_get_object(pw_val);
    }

    if (ctx->totp_cb) {
        token = calloc(AMVP_TOTP_TOKEN_MAX + 1, sizeof(char));
        if (!token) return AMVP_MALLOC_FAIL;

        rv = ctx->totp_cb(&token, AMVP_TOTP_TOKEN_MAX);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Error occured in application callback while generating TOTP");
            rv = AMVP_TOTP_FAIL;
            goto err;
        }
        if (strnlen_s(token, AMVP_TOTP_TOKEN_MAX + 1) > AMVP_TOTP_TOKEN_MAX) {
            AMVP_LOG_ERR("totp cb generated a token that is too long");
            json_value_free(pw_val);
            rv = AMVP_TOTP_FAIL;
            goto err;
        }
        json_object_set_string(pw_obj, "passcode", token);
    }

    if (refresh) {
        json_object_set_string(pw_obj, "accessToken", ctx->jwt_token);
    }
    if (pw_val) json_array_append_value(reg_arry, pw_val);

err:
    *login = json_serialize_to_string(reg_arry_val, login_len);
    if (token) free(token);
    if (reg_arry_val) json_value_free(reg_arry_val);
    return rv;
#else
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
            AMVP_LOG_ERR("Error occured in application callback while generating TOTP");
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
#endif
}

/*
 * This routine performs the JSON parsing of the mod cert rq
 * from the server. It should contain a list of URLs for vector sets that
 * can be queried to get the test parameters.
 */
static AMVP_RESULT amvp_parse_mod_cert_req(AMVP_CTX *ctx) {
    JSON_Value *val = NULL;
    JSON_Object *obj = NULL;
    JSON_Array *te_sets = NULL;
    const char *test_session_url = NULL, *access_token = NULL;
    int i = 0, te_cnt = 0;
    AMVP_RESULT rv = 0;

    /*
     * Parse the JSON
     */
    val = json_parse_string(ctx->curl_buf);
    if (!val) {
        AMVP_LOG_ERR("JSON parse error");
        return AMVP_JSON_ERR;
    }
    obj = amvp_get_obj_from_rsp(ctx, val);

    /*
     * This is the identifiers provided by the server
     * for this specific test session!
     */
    test_session_url = json_object_get_string(obj, "url");
    if (!test_session_url) {
        AMVP_LOG_ERR("JSON parse error");
        return AMVP_JSON_ERR;
    }

    ctx->session_url = calloc(AMVP_ATTR_URL_MAX + 1, sizeof(char));
    strcpy_s(ctx->session_url, AMVP_ATTR_URL_MAX + 1, test_session_url);

    /*
     * The accessToken needed for this specific test session.
     */
    access_token = json_object_get_string(obj, "accessToken");
    if (!access_token) {
        AMVP_LOG_ERR("JSON parse error");
        return AMVP_JSON_ERR;
    }
    if (strnlen_s(access_token, AMVP_JWT_TOKEN_MAX + 1) > AMVP_JWT_TOKEN_MAX) {
        AMVP_LOG_ERR("access_token too large");
        return AMVP_JWT_INVALID;
    }
    memzero_s(ctx->jwt_token, AMVP_JWT_TOKEN_MAX + 1);
    strcpy_s(ctx->jwt_token, AMVP_JWT_TOKEN_MAX + 1, access_token);

    /*
     * Identify the TE identifiers provided by the server, save them for
     * processing later.
     */
    te_sets = json_object_get_array(obj, "crUrls");
    te_cnt = json_array_get_count(te_sets);
    for (i = 0; i < te_cnt; i++) {
        const char *teid_url = json_array_get_string(te_sets, i);

        if (!teid_url) {
            AMVP_LOG_ERR("No teid_url");
            goto end;
        }

        rv = amvp_append_vsid_url(ctx, teid_url);
        if (rv != AMVP_SUCCESS) goto end;
        AMVP_LOG_INFO("Received teid_url=%s", teid_url);
    }

end:
    if (val) json_value_free(val);
    return rv;
}

#define REQUESTS "requests/"
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

#define MODULES "modules/"
AMVP_RESULT amvp_get_module_request(AMVP_CTX *ctx, char *filename) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    AMVP_REQUEST_STATUS status = 0;
    JSON_Value *val = NULL;
    JSON_Array *arr = NULL;
    JSON_Object *obj = NULL;
    const char *url = NULL;
    char *approved = NULL, *substr = NULL, *file = NULL;
    int len = 0;
#ifndef AMVP_DISABLE_WORKAROUND
    #define WORKAROUND_STR "amvp"
    //Server returns acvp url currently, replace with amvp
    char *tmp_url = NULL, *ptr = NULL;
    int tmp_len = 0;
#endif
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

#ifndef AMVP_DISABLE_WORKAROUND 
        //Server returns acvp url currently, replace with amvp
        tmp_len = strnlen_s(url, AMVP_ATTR_URL_MAX + 1);
        tmp_url = calloc(tmp_len + 1, sizeof(char));
        strcpy_s(tmp_url, tmp_len + 1, url);
        strstr_s(tmp_url, tmp_len, "acvp", 4, &ptr);
        memcpy_s(ptr, 4, WORKAROUND_STR, 4);
        rv = amvp_transport_get(ctx, tmp_url, NULL);
        free(tmp_url);
#else
    rv = amvp_transport_get(ctx, url, NULL);
#endif
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
    JSON_Array *arr = NULL;
    const char *url = NULL, *access_token = NULL;

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
    arr = json_value_get_array(val);
    obj = json_array_get_object(arr, 0);
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

    rv = AMVP_SUCCESS;
end:
    if (val) json_value_free(val);
    return rv;
}

static AMVP_CERT_REQ_STATUS amvp_get_cert_req_status(JSON_Object *json) {
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
    strncmp_s(AMVP_CERT_REQ_STATUS_STR_APPROVED, sizeof(AMVP_CERT_REQ_STATUS_STR_APPROVED) - 1, status, len, &diff);
    if (!diff) return AMVP_CERT_REQ_STATUS_APPROVED;
    strncmp_s(AMVP_CERT_REQ_STATUS_STR_ERROR, sizeof(AMVP_CERT_REQ_STATUS_STR_ERROR) - 1, status, len, &diff);
    if (!diff) return AMVP_CERT_REQ_STATUS_ERROR;

    return AMVP_CERT_REQ_STATUS_UNKNOWN;
}

/* Output prettified cert request status to log; if filename is provided, generate template file for response (not yet implemented) */
static AMVP_RESULT amvp_output_cert_request_status(AMVP_CTX *ctx, JSON_Object *status_json, char *filename) {
    JSON_Object *tmp_obj = NULL;
    JSON_Array *arr = NULL;
    char *module_name = NULL;
    int req_id = 0, module_id = 0, vendor_id = 0, diff = 0, i = 0;
    size_t arr_size = 0;
    AMVP_RESULT rv = AMVP_INTERNAL_ERR;
    AMVP_NAME_LIST *fte_list = NULL, *fte_iter = NULL, *sce_list = NULL, *sce_iter = NULL;
    AMVP_SL_LIST *sp_list = NULL, *sp_iter = NULL;

    if (!ctx || !status_json) {
        return AMVP_INTERNAL_ERR;
    }

    strncmp_s("ready", 5, json_object_get_string(status_json, "status"), json_object_get_string_len(status_json, "status"), &diff);
    if (diff) {
        AMVP_LOG_ERR("Cert request not in \"Ready\" status");
        return AMVP_INTERNAL_ERR;
    }

    /* We want to collect all the information from JSON first, then output all at once so we have better control over output */
    sscanf(json_object_get_string(status_json, "url"), "\\/amvp\\/v1\\/certRequests\\/%d", &req_id);

    module_id = (int)json_object_get_number(status_json, "moduleId");
    module_name = amvp_get_module_name_from_id(ctx, module_id);
    if (!module_name) {
        AMVP_LOG_ERR("Error getting module name from cert request info");
        goto err;
    }
    vendor_id = (int)json_object_get_number(status_json, "vendorId");

    /* Get the expected functional test evidence list, or the list of not submitted yet TEs */
    arr = json_object_get_array(status_json, "expectedFunctionalTestEvidence");
    if (!arr) {
        AMVP_LOG_ERR("Cert request status missing expected functional test evidence array");
        goto err;
    }
    arr_size = json_array_get_count(arr);
    for (i = 0; i < (int)arr_size; i++) {
        tmp_obj = json_array_get_object(arr, i);
        amvp_append_name_list(&fte_list, json_object_get_string(tmp_obj, "testRequirement"));
    }

    /* Get the expected source code evidence list, or the list of not submitted yet TEs */
    arr = json_object_get_array(status_json, "expectedSourceCodeEvidence");
    if (!arr) {
        AMVP_LOG_ERR("Cert request status missing expected source code evidence array");
        goto err;
    }
    arr_size = json_array_get_count(arr);
    for (i = 0; i < (int)arr_size; i++) {
        tmp_obj = json_array_get_object(arr, i);
        amvp_append_name_list(&sce_list, json_object_get_string(tmp_obj, "testRequirement"));
    }

    /* Get the list of missing security policy sections */
    arr = json_object_get_array(status_json, "missingSecurityPolicySection");
    if (!arr) {
        AMVP_LOG_ERR("Cert request status missing security policy section array");
        goto err;
    }
    arr_size = json_array_get_count(arr);
    for (i = 0; i < (int)arr_size; i++) {
        tmp_obj = json_array_get_object(arr, i);
        amvp_append_sl_list(&sp_list, json_array_get_number(arr, i));
    }

    /* Begin prettified logging of data */
    AMVP_LOG_STATUS("");
    AMVP_LOG_STATUS("Current status of module certification request:");
    AMVP_LOG_STATUS(AMVP_ANSI_COLOR_GREEN "    Certification Request %d" AMVP_ANSI_COLOR_RESET, req_id);
    AMVP_LOG_STATUS(AMVP_ANSI_COLOR_GREEN "    Module ID: %d"AMVP_ANSI_COLOR_RESET, module_id);
    AMVP_LOG_STATUS(AMVP_ANSI_COLOR_GREEN "    Module Name: %s" AMVP_ANSI_COLOR_RESET, module_name);
    AMVP_LOG_STATUS(AMVP_ANSI_COLOR_GREEN "    Vendor ID: %d" AMVP_ANSI_COLOR_RESET, vendor_id);

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

    rv = AMVP_SUCCESS;
err:
    if (fte_list) amvp_cap_free_nl(fte_list);
    if (sce_list) amvp_cap_free_nl(sce_list);
    if (sp_list) amvp_cap_free_sl(sp_list);
    if (module_name) free(module_name);
    return rv;
}

/* This should be called when a cert request is approved */
static AMVP_RESULT amvp_handle_cert_request_approval(AMVP_CTX *ctx, JSON_Object *json) {
    AMVP_RESULT rv = AMVP_INTERNAL_ERR;
    const char *cert_id = NULL;

    cert_id = json_object_get_string(json, "validationCertificate");
    if (!cert_id) {
        AMVP_LOG_ERR("Cert request in approved state, but missing certificate number. Contact service provider.");
        goto err;
    }

    AMVP_LOG_STATUS(AMVP_ANSI_COLOR_GREEN "Certification request has been approved! Congratulations!" AMVP_ANSI_COLOR_RESET);
    AMVP_LOG_STATUS("Certificate identifier: %s", cert_id);

    rv = AMVP_SUCCESS;
err:
    return rv;
}

/* Use this if we hit the requirementsSubmitted state; wait 30 seconds + retry to see approval */
static AMVP_RESULT amvp_wait_for_submitted_req_approval(AMVP_CTX *ctx) {
    int retry_period = 30, approved = 0;
    unsigned int time_waited_so_far = 0;
    AMVP_RESULT rv = AMVP_INTERNAL_ERR;
    JSON_Value *val = NULL;
    JSON_Object *obj = NULL;
    AMVP_CERT_REQ_STATUS status = AMVP_CERT_REQ_STATUS_UNKNOWN;

    AMVP_LOG_STATUS("All required data submitted. Checking for approval...");

    while (!approved) {
        rv = amvp_transport_get(ctx, ctx->session_url, NULL);
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

        status = amvp_get_cert_req_status(obj);

        if (status == AMVP_CERT_REQ_STATUS_SUBMITTED) {
            /*  Wait and try again to retrieve the cert session information */
            if (amvp_retry_handler(ctx, &retry_period, &time_waited_so_far, 1, AMVP_WAITING_FOR_TESTS) != AMVP_KAT_DOWNLOAD_RETRY) {
                AMVP_LOG_STATUS("Maximum wait time with server reached! (Max: %d seconds)", AMVP_MAX_WAIT_TIME);
                rv = AMVP_TRANSPORT_FAIL;
                goto end;
            };
        } else if (status == AMVP_CERT_REQ_STATUS_APPROVED) {
            rv = amvp_handle_cert_request_approval(ctx, obj);
            approved = 1;
        } else {
            AMVP_LOG_ERR("Unexpected cert request status change while waiting for approval");
            goto end;
        }
    }

    rv = AMVP_SUCCESS;
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
    char *module_name = NULL, *reg = NULL, *file = NULL;
    const char *token = NULL, *url = NULL;
    int reg_len = 0, id = 0, i = 0, retry_period = 0, retry = 1;
    unsigned int time_waited_so_far = 0;
    JSON_Value *cert_submission_val = NULL, *cert_rsp_val = NULL, *cert_info_val = NULL,
               *output_file_val = NULL, *output_file_header_val = NULL, *output_file_body_val = NULL;
    JSON_Array *output_file_arr = NULL;
    JSON_Object *tmp_obj = NULL;
    AMVP_CERT_REQ_STATUS status = AMVP_CERT_REQ_STATUS_UNKNOWN;
#ifdef AMVP_OLD_JSON_FORMAT
    JSON_Array *submission_arr = NULL;
    JSON_Value *arr_val = NULL;
#endif

    if (!ctx) {
        return AMVP_NO_CTX;
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
#ifdef AMVP_OLD_JSON_FORMAT
    amvp_create_array(&tmp_obj, &arr_val, &submission_arr);
    json_array_append_value(submission_arr, cert_submission_val);
    reg = json_serialize_to_string(arr_val, &reg_len);
#else
    amvp_add_version_to_obj(json_value_get_object(cert_submission_val));
    reg = json_serialize_to_string(cert_submission_val, &reg_len);
#endif

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
    sscanf(url, "/amvp/v1/certRequests/%d", &id);

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

    AMVP_LOG_STATUS("Cert request %d successfully created. Checking status...", id);

    while (retry) {
        rv = amvp_transport_get(ctx, url, NULL);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Failed to get info about created certify request");
            goto end;
        }

        if (cert_info_val) json_value_free(cert_info_val);
        cert_info_val = json_parse_string(ctx->curl_buf);
        tmp_obj = amvp_get_obj_from_rsp(ctx, cert_info_val);
        if (!tmp_obj) {
            AMVP_LOG_ERR("Error parsing info about certify request");
            rv = AMVP_JSON_ERR;
            goto end;
        }

        status = amvp_get_cert_req_status(tmp_obj);
        if (status == AMVP_CERT_REQ_STATUS_INITIAL) {
            /* Check if we received a retry response */
            retry_period = json_object_get_number(tmp_obj, "retry");
            if (retry_period) {
                /*  Wait and try again to retrieve the cert session information */
                if (amvp_retry_handler(ctx, &retry_period, &time_waited_so_far, 1, AMVP_WAITING_FOR_TESTS) != AMVP_KAT_DOWNLOAD_RETRY) {
                    AMVP_LOG_STATUS("Maximum wait time with server reached! (Max: %d seconds)", AMVP_MAX_WAIT_TIME);
                    rv = AMVP_TRANSPORT_FAIL;
                    goto end;
                };
            }
        } else if (status == AMVP_CERT_REQ_STATUS_READY) {
            retry = 0;
            AMVP_LOG_STATUS("Module Certification Session created and ready for data submission!");
            amvp_output_cert_request_status(ctx, amvp_get_obj_from_rsp(ctx, cert_info_val), NULL);

            AMVP_LOG_STATUS("Saving session info to file...");
            /* Create the name of the file we are saving info to */
            file = calloc(AMVP_CERT_REQUEST_FILENAME_MAX_LEN + 1, sizeof(char));
            if (!file) {
                AMVP_LOG_ERR("Error allocating memory for certify request filename");
                rv = AMVP_MALLOC_FAIL;
                goto end;
            }
            snprintf(file, AMVP_CERT_REQUEST_FILENAME_MAX_LEN + 1, "%s_%d.json", AMVP_CERT_REQUEST_FILENAME_DEFAULT, id);

            /* Create a JSON file that contains the intial info from the creation response (ID, accessToken, etc), as well as the list of requirements */
            output_file_val = json_value_init_array();
            output_file_arr = json_value_get_array(output_file_val);
            if (!output_file_arr) {
                AMVP_LOG_ERR("Error occured while trying to generate output file");
                goto end;
            }
            /* Get the certRequest URL and the access token into an object, make that the first array element */
            output_file_header_val = json_value_init_object();
            tmp_obj = json_value_get_object(output_file_header_val);
            if (!tmp_obj) {
                AMVP_LOG_ERR("Error occured while trying to generate output file header");
                goto end;
            }
            json_object_set_string(tmp_obj, "url", url);
            json_object_set_string(tmp_obj, "accessToken", token);
            json_array_append_value(output_file_arr, output_file_header_val);

            /* Make a duplicate of the current status JSON we just got and make it the second element */
            output_file_body_val = json_value_deep_copy(json_object_get_wrapping_value(amvp_get_obj_from_rsp(ctx, cert_info_val)));
            json_array_append_value(output_file_arr, output_file_body_val);

            /* Take this array and save it to the cert request file */
            rv = (json_serialize_to_file_pretty(output_file_val, file) == JSONSuccess ? AMVP_SUCCESS : AMVP_INTERNAL_ERR);
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("Failed to write module creation response to file!");
            } else {
                AMVP_LOG_STATUS("Successfully created cert request file %s", file);
            }
        } else {
            AMVP_LOG_ERR("Error determining status of cert request");
            goto end;
        }
    }

end:
    if (reg) json_free_serialized_string(reg);
    if (file) free(file);
    if (module_name) free(module_name);
    if (output_file_val) json_value_free(output_file_val); //Also frees the header and body vals
    if (cert_info_val) json_value_free(cert_info_val);
    if (cert_rsp_val) json_value_free(cert_rsp_val);
#ifdef AMVP_OLD_JSON_FORMAT
    if (arr_val) json_value_free(arr_val); //Also frees submission_val
#else
    if (cert_submission_val) json_value_free(cert_submission_val);
#endif
    return rv;
}

AMVP_RESULT amvp_submit_security_policy(AMVP_CTX *ctx, const char *filename) {
    AMVP_RESULT rv = AMVP_INTERNAL_ERR;
    char *reg = NULL, *file = NULL, *sp = NULL;
    int sp_len = 0;

    JSON_Value *val = NULL, *tmp = NULL, *submission = NULL;
#ifdef AMVP_OLD_JSON_FORMAT
    JSON_Array *submission_arr = NULL;
#endif
    JSON_Object *obj = NULL, *submission_obj = NULL;
    AMVP_CERT_REQ_STATUS status = AMVP_CERT_REQ_STATUS_UNKNOWN;

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

#ifdef AMVP_OLD_JSON_FORMAT
    rv = amvp_create_array(&submission_obj, &submission, &submission_arr);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Error preparing security policy for submission");
        goto end;
    }
    json_array_append_value(submission_arr, val);

#else
    submission = val;
    submission_obj = json_value_get_object(submission);
    rv = amvp_add_version_to_obj(submission_obj);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Unable to add amvVersion to SP submission");
        goto end;
    }
#endif

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

    status = amvp_get_cert_req_status(obj);
    if (status == AMVP_CERT_REQ_STATUS_READY) {
        amvp_output_cert_request_status(ctx, obj, NULL);
    } else if (status == AMVP_CERT_REQ_STATUS_SUBMITTED) {
        AMVP_LOG_STATUS(AMVP_ANSI_COLOR_GREEN "All required data submitted. You may proceed " \
                        "with requesting final submission of cert request." AMVP_ANSI_COLOR_RESET);
        goto end;
    } else if (status == AMVP_CERT_REQ_STATUS_APPROVED) {
        amvp_handle_cert_request_approval(ctx, obj);
    } else {
        AMVP_LOG_ERR("Unable to handle current status of cert req currently");
        goto end;
    }

end:
    if (reg) json_free_serialized_string(reg);
    if (val) json_value_free(val);
    if (tmp) json_value_free(tmp);
    if (file) free(file);
    return rv;
}

typedef enum amvp_sp_status {
    AMVP_SP_STATUS_UNKNOWN = 0,
    AMVP_SP_STATUS_PENDING,
    AMVP_SP_STATUS_PROCESSING,
    AMVP_SP_STATUS_WAITING_GENERATION,
    AMVP_SP_STATUS_SUBMITTED,
    AMVP_SP_STATUS_SUCCESS,
    AMVP_SP_STATUS_ERROR
} AMVP_SP_STATUS;

static AMVP_SP_STATUS amvp_get_sp_request_status(const char *str) {
    int diff = 1;
    size_t len = 0;

    len = strnlen_s(str, AMVP_CERT_REQ_STATUS_MAX_LEN + 1);
    if (len > AMVP_CERT_REQ_STATUS_MAX_LEN) {
        return AMVP_SP_STATUS_UNKNOWN;
    }

    strncmp_s(AMVP_SP_STATUS_STR_PENDING, sizeof(AMVP_SP_STATUS_STR_PENDING) - 1, str, len, &diff);
    if (!diff) return AMVP_SP_STATUS_PENDING;
    strncmp_s(AMVP_SP_STATUS_STR_PROCESSING, sizeof(AMVP_SP_STATUS_STR_PROCESSING) - 1, str, len, &diff);
    if (!diff) return AMVP_SP_STATUS_PROCESSING;
    strncmp_s(AMVP_SP_STATUS_STR_WAITING_GENERATION, sizeof(AMVP_SP_STATUS_STR_WAITING_GENERATION) - 1, str, len, &diff);
    if (!diff) return AMVP_SP_STATUS_WAITING_GENERATION;
    strncmp_s(AMVP_SP_STATUS_STR_SUBMITTED, sizeof(AMVP_SP_STATUS_STR_SUBMITTED) - 1, str, len, &diff);
    if (!diff) return AMVP_SP_STATUS_SUBMITTED;
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

    rv = amvp_transport_get(ctx, ctx->session_url, NULL);
    if (rv == AMVP_PROTOCOL_RSP_ERR) {
        rv = amvp_handle_protocol_error(ctx, ctx->error);
        if (rv == AMVP_RETRY_OPERATION) {
            rv = amvp_transport_get(ctx, ctx->session_url, NULL);
        }
    }
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Failed to get session status for security policy");
        return AMVP_TRANSPORT_FAIL;
    }

    val = json_parse_string(ctx->curl_buf);
    if (!val) {
        AMVP_LOG_ERR("Unable to parse JSON from server response when getting security policy");
        return AMVP_JSON_ERR;
    }

    obj = amvp_get_obj_from_rsp(ctx, val);
    if (!obj) {
        AMVP_LOG_ERR("Unrecognized JSON format found when getting security policy");
        return AMVP_JSON_ERR;
    }
 //   amvp_output_cert_request_status(ctx, obj, NULL);

    status_str = json_object_get_string(obj, "securityPolicyStatus");
    if (!status_str) {
        AMVP_LOG_ERR("No status value found when getting security policy status\n");
        return AMVP_JSON_ERR;
    }
    status = amvp_get_sp_request_status(status_str);
    switch (status) {
    case AMVP_SP_STATUS_PENDING:
        AMVP_LOG_ERR("Security policy in \"pending\" state. Please try again later.");
        goto err;
    case AMVP_SP_STATUS_PROCESSING:
    case AMVP_SP_STATUS_WAITING_GENERATION:
        AMVP_LOG_STATUS("Security policy not yet generated. Attempting to request security policy generation...");
        if (amvp_create_response_obj(&req_obj, &req_val) != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Error occured while creating SP generation request body");
            return AMVP_INTERNAL_ERR;
        }
        req_str = json_serialize_to_string(req_val, NULL);
        if (amvp_request_security_policy_generation(ctx, ctx->session_url, req_str) != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Error requesting security policy generation");
            goto err;
        }
        AMVP_LOG_STATUS("Succesfully requested generation of security policy PDF. Check back later.");
        break;
    case AMVP_SP_STATUS_SUCCESS:
        AMVP_LOG_STATUS("Security policy ready. Saving...");
        sp_str = json_object_get_string(obj, "content");
        if (!sp_str) {
            AMVP_LOG_ERR("Server indicated security policy was ready, but content is missing!");
            goto err;
        }

        sp_buffer = amvp_decode_base64(sp_str, &sp_buffer_len);
        if (!sp_buffer) {
            AMVP_LOG_ERR("Error decoding base64 while getting security policy");
            goto err;
        }
#if 0
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
        AMVP_LOG_ERR("Unable to parse JSON from server response when getting security policy");
        return AMVP_JSON_ERR;
    }

    obj = amvp_get_obj_from_rsp(ctx, val);
    if (!obj) {
        AMVP_LOG_ERR("Unrecognized JSON format found when getting security policy");
        return AMVP_JSON_ERR;
    }

    status_str = json_object_get_string(obj, "status");
    if (!status_str) {
        AMVP_LOG_ERR("No status value found when getting security policy\n");
        return AMVP_JSON_ERR;
    }

    status = amvp_get_sp_request_status(status_str);
    switch (status) {
    case AMVP_SP_STATUS_PENDING:
        AMVP_LOG_ERR("Security policy in \"pending\" state. Please try again later.");
        goto err;
    case AMVP_SP_STATUS_WAITING_GENERATION:
        AMVP_LOG_STATUS("Security policy not yet generated. Attempting to request security policy generation...");
        if (amvp_create_response_obj(&req_obj, &req_val) != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Error occured while creating SP generation request body");
            return AMVP_INTERNAL_ERR;
        }
        req_str = json_serialize_to_string(req_val, NULL);
        if (amvp_request_security_policy_generation(ctx, ctx->session_url, req_str) != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Error requesting security policy generation");
            goto err;
        }
        AMVP_LOG_STATUS("Succesfully requested generation of security policy PDF. Check back later.");
        break;
    case AMVP_SP_STATUS_SUCCESS:
        AMVP_LOG_STATUS("Security policy ready. Saving...");
        sp_str = json_object_get_string(obj, "content");
        if (!sp_str) {
            AMVP_LOG_ERR("Server indicated security policy was ready, but content is missing!");
            goto err;
        }

        sp_buffer = amvp_decode_base64(sp_str, &sp_buffer_len);
        if (!sp_buffer) {
            AMVP_LOG_ERR("Error decoding base64 while getting security policy");
            goto err;
        }
#endif

#if 0 // Realistically, eventually should set a max length for SP file 
        if (sp_buffer_len > 100000000) { //100,000,000b = 100MB
            AMVP_LOG_ERR("Security policy is suspiciously large");
            goto err;
        }
#endif

        fp = fopen(ctx->save_filename, "w");
        if (fp == NULL) {
            AMVP_LOG_ERR("Failed to intialize file output for security policy");
            goto err;
        }

        if (fwrite((const void *)sp_buffer, sp_buffer_len, 1, fp) == EOF) {
            AMVP_LOG_ERR("Failiure writing security policy to file");
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
        AMVP_LOG_ERR("Error occured while getting security policy");
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
#ifdef AMVP_OLD_JSON_FORMAT
    JSON_Array *submission_arr = NULL;
#endif
    JSON_Object *obj = NULL, *submission_obj = NULL;
    AMVP_CERT_REQ_STATUS status = AMVP_CERT_REQ_STATUS_UNKNOWN;

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

#ifdef AMVP_OLD_JSON_FORMAT
    rv = amvp_create_array(&submission_obj, &submission, &submission_arr);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Error preparing evidence for submission");
        goto end;
    }
    json_array_append_value(submission_arr, val);
#else
    submission = val;
    submission_obj = json_value_get_object(submission);
    rv = amvp_add_version_to_obj(submission_obj);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Unable to add amvVersion to SP submission");
        goto end;
    }
#endif

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

    status = amvp_get_cert_req_status(obj);
    if (status == AMVP_CERT_REQ_STATUS_READY) {
        amvp_output_cert_request_status(ctx, obj, NULL);
    } else if (status == AMVP_CERT_REQ_STATUS_SUBMITTED) {
        amvp_wait_for_submitted_req_approval(ctx);
    } else if (status == AMVP_CERT_REQ_STATUS_APPROVED) {
        amvp_handle_cert_request_approval(ctx, obj);
    } else {
        AMVP_LOG_ERR("Unable to handle current status of cert req currently");
        goto end;
    }

end:
    if (reg) json_free_serialized_string(reg);
    if (val) json_value_free(val);
    if (tmp) json_value_free(tmp);
    if (file) free(file);
    return rv;
}

#define AMVP_CERTIFY_ENDPOINT "certify"
AMVP_RESULT amvp_finalize_cert_request(AMVP_CTX *ctx) {
    int retry_period = 30, approved = 0;
    unsigned int time_waited_so_far = 0;
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

    amvp_output_cert_request_status(ctx, obj, NULL);
    return AMVP_SUCCESS;

    status = amvp_get_cert_req_status(obj);
    if (status != AMVP_CERT_REQ_STATUS_SUBMITTED) {
        AMVP_LOG_ERR("Unable to complete final submission on cert request; it has not yet had all requirements completed.");
        goto end;
    }

    url = calloc(AMVP_ATTR_URL_MAX, sizeof(char));
    if (!url) {
        AMVP_LOG_ERR("Unable to allocate URL for finalizing submission of cert request");
        goto end;
    }
    snprintf(url, AMVP_ATTR_URL_MAX, "%s/%s", ctx->session_url, AMVP_CERTIFY_ENDPOINT);
    rv = amvp_transport_post(ctx, url, "{\"amvVersion\": 1.0}", 20);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Error occured when requesting final submission of cert request");
        goto end;
    }
    #if 0
    while (!approved) {
        rv = amvp_transport_get(ctx, ctx->session_url, NULL);
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

        status = amvp_get_cert_req_status(obj);

        if (status == AMVP_CERT_REQ_STATUS_SUBMITTED) {

            /*  Wait and try again to retrieve the cert session information */
            if (amvp_retry_handler(ctx, &retry_period, &time_waited_so_far, 1, AMVP_WAITING_FOR_TESTS) != AMVP_KAT_DOWNLOAD_RETRY) {
                AMVP_LOG_STATUS("Maximum wait time with server reached! (Max: %d seconds)", AMVP_MAX_WAIT_TIME);
                rv = AMVP_TRANSPORT_FAIL;
                goto end;
            };
        } else if (status == AMVP_CERT_REQ_STATUS_APPROVED) {
            rv = amvp_handle_cert_request_approval(ctx, obj);
            approved = 1;
        } else {
            AMVP_LOG_ERR("Unexpected cert request status change while waiting for approval");
            goto end;
        }
    }
#endif
    rv = AMVP_SUCCESS;
end:
    if (val) json_value_free(val);
    return rv;
}

/*
 * Append a VS identifier to the list of VS identifiers
 * that will need to be downloaded and processed later.
 */
static AMVP_RESULT amvp_append_vsid_url(AMVP_CTX *ctx, const char *vsid_url) {
    AMVP_STRING_LIST *vs_entry, *vs_e2;


    if (!ctx || !vsid_url) {
        return AMVP_MISSING_ARG;
    }
    vs_entry = calloc(1, sizeof(AMVP_STRING_LIST));
    if (!vs_entry) {
        return AMVP_MALLOC_FAIL;
    }
    vs_entry->string = calloc(AMVP_ATTR_URL_MAX + 1, sizeof(char));
    if (!vs_entry->string) {
        free(vs_entry);
        return AMVP_MALLOC_FAIL;
    }
    strcpy_s(vs_entry->string, AMVP_ATTR_URL_MAX + 1, vsid_url);

    if (!ctx->vsid_url_list) {
        ctx->vsid_url_list = vs_entry;
    } else {
        vs_e2 = ctx->vsid_url_list;
        while (vs_e2->next) {
            vs_e2 = vs_e2->next;
        }
        vs_e2->next = vs_entry;
    }
    return AMVP_SUCCESS;
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

static AMVP_RESULT amvp_parse_validation(AMVP_CTX *ctx) {
    JSON_Value *val = NULL, *ts_val = NULL, *new_ts = NULL;
    JSON_Object *obj = NULL, *ts_obj = NULL;
    JSON_Array *ts_arr = NULL;
    const char *url = NULL, *status = NULL;
    AMVP_RESULT rv = AMVP_SUCCESS;

    /*
     * Parse the JSON
     */
    val = json_parse_string(ctx->curl_buf);
    if (!val) {
        AMVP_LOG_ERR("JSON parse error");
        return AMVP_JSON_ERR;
    }

    obj = amvp_get_obj_from_rsp(ctx, val);

    /*
     * Get the url of the 'request' status sent by server.
     */
    url = json_object_get_string(obj, "url");
    if (!url) {
        AMVP_LOG_ERR("Validation response JSON missing 'url'");
        rv = AMVP_JSON_ERR;
        goto end;
    }

    status = json_object_get_string(obj, "status");
    if (!status) {
        AMVP_LOG_ERR("Validation response JSON missing 'status'");
        rv = AMVP_JSON_ERR;
        goto end;
    }

    /* Print the request info to screen */
    AMVP_LOG_STATUS("Validation requested -- status %s -- url: %s", status, url);
    /* save the request URL to the test session info file, if it is saved in the CTX. */
    if (ctx->session_file_path) {
        ts_val = json_parse_file(ctx->session_file_path);
        if (!ts_val) {
            AMVP_LOG_WARN("Failed to save request URL to test session file. Make sure you save it from output!");
            goto end;
        }
        ts_arr = json_value_get_array(ts_val);
        if (!ts_arr) {
            AMVP_LOG_WARN("Failed to save request URL to test session file. Make sure you save it from output!");
            goto end;
        }
        ts_obj = json_array_get_object(ts_arr, 0);
        if (!ts_obj) {
            AMVP_LOG_WARN("Failed to save request URL to test session file. Make sure you save it from output!");
            goto end;
        }
        //Sanity check the object to make sure its valid
        if (!json_object_get_string(ts_obj, "url")) {
            AMVP_LOG_WARN("Saved testSession file seems invalid. Make sure you save request URL from output!");
            goto end;
        }
        json_object_set_string(ts_obj, "validationRequestUrl", url);
        new_ts = json_object_get_wrapping_value(ts_obj);
        if (!new_ts) {
            AMVP_LOG_WARN("Failed to save request URL to test session file. Make sure you save it from output!");
            goto end;  
        }
        rv = amvp_json_serialize_to_file_pretty_w(new_ts, ctx->session_file_path);
        if (rv) {
            AMVP_LOG_WARN("Failed to save request URL to test session file. Make sure you save it from output!");
            goto end;
        } else {
            amvp_json_serialize_to_file_pretty_a(NULL, ctx->session_file_path);
        }
    }


end:
    if (val) json_value_free(val);
    if (ts_val) json_value_free(ts_val);
    return rv;
}

/**
 * Loads all of the data we need to process or view test session information
 * from the given file. used for non-continuous sessions.
 */
static AMVP_RESULT amvp_parse_session_info_file(AMVP_CTX *ctx, const char *filename) {
    JSON_Value *val = NULL;
    JSON_Array *reg_array;
    JSON_Object *obj = NULL;
    const char *test_session_url = NULL;
    const char *jwt = NULL;
    int isSample = 0;
    AMVP_RESULT rv = AMVP_SUCCESS;

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
    if (!val) {
        AMVP_LOG_ERR("JSON val parse error");
        return AMVP_MALFORMED_JSON;
    }
    reg_array = json_value_get_array(val);
    obj = json_array_get_object(reg_array, 0);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        rv = AMVP_MALFORMED_JSON;
        goto end;
    }

    test_session_url = json_object_get_string(obj, "url");
    if (!test_session_url) {
        AMVP_LOG_ERR("Missing session URL");
        rv = AMVP_MALFORMED_JSON;
        goto end;
    }

    ctx->session_url = calloc(AMVP_ATTR_URL_MAX + 1, sizeof(char));
    if (!ctx->session_url) {
        rv = AMVP_MALLOC_FAIL;
        goto end;
    }
    strcpy_s(ctx->session_url, AMVP_ATTR_URL_MAX + 1, test_session_url);

    jwt = json_object_get_string(obj, "jwt");
    if (!jwt) {
        rv = AMVP_MALFORMED_JSON;
        goto end;
    }
    ctx->jwt_token = calloc(AMVP_JWT_TOKEN_MAX + 1, sizeof(char));
    if (!ctx->jwt_token) {
        rv = AMVP_MALLOC_FAIL;
        goto end;
    }
    strcpy_s(ctx->jwt_token, AMVP_JWT_TOKEN_MAX + 1, jwt);

    isSample = json_object_get_boolean(obj, "isSample");
    if (json_object_has_value(obj, "isSample")) {
        ctx->is_sample = isSample;
    } else {
        AMVP_LOG_WARN("Missing indication of whether tests are sample in file, continuing");
    }

end:
    if (val) json_value_free(val);
    return rv;
}

/*
 * This is a retry handler, which pauses for a specific time.
 * This allows the server time to generate the vectors on behalf of
 * the client and to process the vector responses. The caller of this function
 * can choose to implement a retry backoff using 'modifier'. Additionally, this
 * function will ensure that retry periods will sum to no longer than AMVP_MAX_WAIT_TIME.
 */
static AMVP_RESULT amvp_retry_handler(AMVP_CTX *ctx, int *retry_period, unsigned int *waited_so_far, int modifier, AMVP_WAITING_STATUS situation) {
    /* perform check at beginning of function call, so library can check one more time when max
     * time is reached to see if server status has changed */
    if (*waited_so_far >= AMVP_MAX_WAIT_TIME) {
        return AMVP_TRANSPORT_FAIL;
    }

    if (*waited_so_far + *retry_period > AMVP_MAX_WAIT_TIME) {
        *retry_period = AMVP_MAX_WAIT_TIME - *waited_so_far;
    }
    if (*retry_period <= AMVP_RETRY_TIME_MIN || *retry_period > AMVP_RETRY_TIME_MAX) {
        *retry_period = AMVP_RETRY_TIME_MAX;
        AMVP_LOG_WARN("retry_period not found, using max retry period!");
    }
    if (situation == AMVP_WAITING_FOR_TESTS) {
        AMVP_LOG_STATUS("Certification request session not yet ready, server requests we wait %u seconds and try again...", *retry_period);
    } else if (situation == AMVP_WAITING_FOR_RESULTS) {
        AMVP_LOG_STATUS("Results not ready, waiting %u seconds and trying again...", *retry_period);
    } else {
        AMVP_LOG_STATUS("Waiting %u seconds and trying again...", *retry_period);
    }

    #ifdef _WIN32
    /*
     * Windows uses milliseconds
     */
    Sleep(*retry_period * 1000);
    #else
    sleep(*retry_period);
    #endif

    /* ensure that all parameters are valid and that we do not wait longer than AMVP_MAX_WAIT_TIME */
    if (modifier < 1 || modifier > AMVP_RETRY_MODIFIER_MAX) {
        AMVP_LOG_WARN("retry modifier not valid, defaulting to 1 (no change)");
        modifier = 1;
    }
    if ((*retry_period *= modifier) > AMVP_RETRY_TIME_MAX) {
        *retry_period = AMVP_RETRY_TIME_MAX;
    }

    *waited_so_far += *retry_period;

    return AMVP_KAT_DOWNLOAD_RETRY;
}


/***************************************************************************************************************
* Begin vector processing logic
***************************************************************************************************************/

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

typedef struct amvp_evidence_t AMVP_EVIDENCE;
struct amvp_evidence_t {
    const char *evidence_name;
    const char *evidence;
};

AMVP_EVIDENCE amvp_evidence_tbl[9] = {
       {"TE02.20.01", "/acvp/v1/validations/41763"},
       {"TE02.20.02", "none"},
       {"TE11.16.01", "Version X.Y.Z of the module meets the assertion" },
       {"TE04.11.01", "<BASE64(table of services.pdf) compliant with SP800-140Br>" },
       {"TE04.11.02", "/wwwin.cisco.com/cryptomod/log_te041102_04172023.txt" },
       {"TE10.10.01", "Degraded mode not supported, no algorithms can be used...goes directly into SP." },
       {"TE10.10.02", "/wwwin.cisco.com/cryptomod/log_te041102_04172023.txt" },
       {"TE11.08.01", "/wwwin.cisco.com/cryptomod/FSM.pdf" },
       {"TE11.08.02", "See TE11.08.01"}
};

AMVP_RESULT amvp_post_resources(AMVP_CTX *ctx, const char *resource_file) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    JSON_Array *vendor_array = NULL;
    JSON_Object *obj = NULL;
    JSON_Value *val = NULL;
    JSON_Value *post_val = NULL;
    JSON_Value *raw_val = NULL;
    char *json_result = NULL;
    int len;


    if (!ctx) return AMVP_NO_CTX;
    if (!resource_file) {
        AMVP_LOG_ERR("Must provide string value for 'resource_file'");
        return AMVP_MISSING_ARG;
    }

    if (strnlen_s(resource_file, AMVP_JSON_FILENAME_MAX + 1) > AMVP_JSON_FILENAME_MAX) {
        AMVP_LOG_ERR("Provided 'resource_file' string length > max(%d)", AMVP_JSON_FILENAME_MAX);
        return AMVP_INVALID_ARG;
    }

    val = json_parse_file(resource_file);
    if (!val) {
        AMVP_LOG_ERR("Failed to parse JSON in metadata file");
        return AMVP_JSON_ERR;
    }
    obj = json_value_get_object(val);
    if (!obj) {
        AMVP_LOG_ERR("Failed to parse JSON object in metadata file");
        return AMVP_JSON_ERR;
    }

    /* POST obj to labs */

    vendor_array = json_object_get_array(obj, "lab");
    if (!vendor_array) {
        AMVP_LOG_ERR("Unable to resolve the 'lab' array");
        return AMVP_JSON_ERR;
    }

    raw_val = json_array_get_value(vendor_array, 0);
    json_result = json_serialize_to_string_pretty(raw_val, &len);
    post_val = json_parse_string(json_result);


    AMVP_LOG_INFO("\nPOST Data: %s, %s\n\n", "/amv/v1/labs", json_result);
    rv = amvp_transport_post(ctx, "/amv/v1/labs", json_result, len);
    AMVP_LOG_STATUS("POST response:\n\n%s\n", ctx->curl_buf);
    json_free_serialized_string(json_result);
    json_value_free(post_val);

    /* POST obj to vendors */

    vendor_array = json_object_get_array(obj, "vendor");
    if (!vendor_array) {
        AMVP_LOG_ERR("Unable to resolve the 'vendor' array");
        return AMVP_JSON_ERR;
    }

    raw_val = json_array_get_value(vendor_array, 0);
    json_result = json_serialize_to_string_pretty(raw_val, &len);
    post_val = json_parse_string(json_result);

    AMVP_LOG_INFO("\nPOST Data: %s, %s\n\n", "/amv/v1/vendors", json_result);
    rv = amvp_transport_post(ctx, "/amv/v1/vendors", json_result, len);
    AMVP_LOG_STATUS("POST response:\n\n%s\n", ctx->curl_buf);
    json_free_serialized_string(json_result);
    json_value_free(post_val);

    /* POST obj to modules */

    vendor_array = json_object_get_array(obj, "module");
    if (!vendor_array) {
        AMVP_LOG_ERR("Unable to resolve the 'module' array");
        return AMVP_JSON_ERR;
    }

    raw_val = json_array_get_value(vendor_array, 0);
    json_result = json_serialize_to_string_pretty(raw_val, &len);
    post_val = json_parse_string(json_result);


    AMVP_LOG_INFO("\nPOST Data: %s, %s\n\n", "/amv/v1/modules", json_result);
    rv = amvp_transport_post(ctx, "/amv/v1/modules", json_result, len);
    AMVP_LOG_STATUS("POST response:\n\n%s\n", ctx->curl_buf);
    json_free_serialized_string(json_result);
    json_value_free(post_val);

    json_value_free(val);

    /* Success */

    return rv;
}



#define TEST_SESSION "testSessions/"

/**
 * Creates a file with the test session info, which can be used to access the test session
 * in the future.
 *
 * This function should not modify the ctx, only read it.
 */
static AMVP_RESULT amvp_write_session_info(AMVP_CTX *ctx) {
    AMVP_RESULT rv = AMVP_INTERNAL_ERR;
    JSON_Value *ts_val = NULL;
    JSON_Object *ts_obj = NULL;
    char *filename = NULL, *ptr = NULL, *path = NULL, *prefix = NULL;
    int diff;
    int pathLen = 0, allocedPrefix = 0;

    filename = calloc(AMVP_JSON_FILENAME_MAX + 1, sizeof(char));
    if (!filename) {
        return AMVP_MALLOC_FAIL;
    }

    ts_val = json_value_init_object();
    ts_obj = json_value_get_object(ts_val);
    if (!ts_obj) {
        goto end;
    }

    json_object_set_string(ts_obj, "url", ctx->session_url);
    json_object_set_string(ts_obj, "jwt", ctx->jwt_token);

    /* pull test session ID out of URL */
    ptr = ctx->session_url;
    while(*ptr != 0) {
        memcmp_s(ptr, strlen(TEST_SESSION), TEST_SESSION, strlen(TEST_SESSION), &diff);
        if (!diff) {
            break;
        }
        ptr++;
    }

    ptr+= strnlen_s(TEST_SESSION, AMVP_ATTR_URL_MAX);

    path = getenv("ACV_SESSION_SAVE_PATH");
    prefix = getenv("ACV_SESSION_SAVE_PREFIX");

    /*
     * Check the total length of our path, prefix, and total concatenated filename. 
     * Add 6 to checks for .json and the _ beteween prefix and session ID
     * If any lengths are too long, just use default prefix and location
     */
    if (path) {
        pathLen += strnlen_s(path, AMVP_JSON_FILENAME_MAX + 1);
    }
    if (prefix) {
        pathLen += strnlen_s(prefix, AMVP_JSON_FILENAME_MAX + 1);
    }
    pathLen += strnlen_s(ptr, AMVP_JSON_FILENAME_MAX + 1);

    if (pathLen > AMVP_JSON_FILENAME_MAX - 6) {
        AMVP_LOG_WARN("Provided ACV_SESSION_SAVE information too long (current max path len: %d). Using defaults", \
                      AMVP_JSON_FILENAME_MAX);
        path = NULL;
        prefix = NULL;
    }
    if (!prefix) {
        int len = strnlen_s(AMVP_SAVE_DEFAULT_PREFIX, AMVP_JSON_FILENAME_MAX);
        prefix = calloc(len + 1, sizeof(char));
        if (!prefix) {
            rv = AMVP_MALLOC_FAIL;
            goto end;
        }
        strncpy_s(prefix, len + 1, AMVP_SAVE_DEFAULT_PREFIX, len);
        allocedPrefix = 1;
    }

    //if we have a path, use it, otherwise use default (usually directory of parent application)
    if (path) {
        diff = snprintf(filename, AMVP_JSON_FILENAME_MAX, "%s/%s_%s.json", path, prefix, ptr);
    } else {
        diff = snprintf(filename, AMVP_JSON_FILENAME_MAX, "%s_%s.json", prefix, ptr);
    }
    if (diff < 0) {
        rv = AMVP_UNSUPPORTED_OP;
        goto end;
    }
    rv = amvp_json_serialize_to_file_pretty_w(ts_val, filename);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("File write error. Check that directory exists and allows writes.");
        goto end;
    }

    rv = amvp_json_serialize_to_file_pretty_a(NULL, filename);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("File write error. Check that directory exists and allows writes.");
        goto end;
    }

    if (ctx->session_file_path) {
        free(ctx->session_file_path);
    }
    ctx->session_file_path = calloc(AMVP_JSON_FILENAME_MAX + 1, sizeof(char));
    if (strncpy_s(ctx->session_file_path, AMVP_JSON_FILENAME_MAX + 1, filename, 
                  AMVP_JSON_FILENAME_MAX)) {
        AMVP_LOG_ERR("Buffer write error while trying to save session file path to CTX");
        rv = AMVP_UNSUPPORTED_OP;
        goto end;
    }

    rv = AMVP_SUCCESS;
end:
    if (allocedPrefix && prefix) free(prefix);
    if (ts_obj) json_object_soft_remove(ts_obj, "registration");
    if (ts_val) json_value_free(ts_val);
    free(filename);
    return rv;
}

static AMVP_RESULT amvp_cert_req(AMVP_CTX *ctx)
{
    AMVP_RESULT rv = AMVP_SUCCESS;
    JSON_Object *obj = NULL;
    JSON_Value *val = NULL;
    JSON_Array *doc_array = NULL;
    const char *sp = NULL, *dc = NULL;

    /*
     * Retrieve the SP and DC and write to file
     */
    AMVP_LOG_STATUS("Tests complete, request SP and DC...");
    rv = amvp_retrieve_docs(ctx, ctx->session_url);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Unable to retrieve docs");
        goto end;
    }
    val = json_parse_string(ctx->curl_buf);
    if (!val) {
        AMVP_LOG_ERR("JSON parse error");
        rv = AMVP_JSON_ERR;
        goto end;
    }
    if (!val) {
        AMVP_LOG_ERR("JSON val parse error");
        return AMVP_MALFORMED_JSON;
    }
    doc_array = json_value_get_array(val);
    obj = json_array_get_object(doc_array, 0);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        rv = AMVP_MALFORMED_JSON;
        goto end;
    }

    sp = json_object_get_string(obj, "secPolicyUrl");
    AMVP_LOG_STATUS("Security Policy url: %s", sp);

    dc = json_object_get_string(obj, "draftCertUrl");
    AMVP_LOG_STATUS("Draft Certificate url: %s", dc);


    if (ctx->action == AMVP_ACTION_CERT_REQ) {
        static char validation[] = "[{ \"implementationUrls\": [\"/acvp/v1/1234\", \"/esv/v1/5678\", \"amv/v1/13780\" ] }]";
        int validation_len = sizeof(validation);
        /*
         * PUT the validation with the AMVP server and get the response,
         */
        rv = amvp_transport_put_validation(ctx, validation, validation_len);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_STATUS("Validation send failed");
            goto end;
        }

        rv = amvp_parse_validation(ctx);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_STATUS("Failed to parse Validation response");
        }
    }
end:
    if (val) json_value_free(val);
    return rv;
}

AMVP_RESULT amvp_run(AMVP_CTX *ctx, int fips_validation) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    JSON_Value *val = NULL;
    if (ctx == NULL) return AMVP_NO_CTX;



    if (!getenv("AMVP_NO_LOGIN")) {
        rv = amvp_login(ctx, 0);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Failed to login with AMVP server");
            goto end;
        }
    }

    if (ctx->action == AMVP_ACTION_CERT_REQ) {
        rv = amvp_mod_cert_req(ctx);
        goto end;
        //goto check;
    }

    if (ctx->action == AMVP_ACTION_DELETE) {
        rv = amvp_transport_delete(ctx, ctx->delete_string);
        if (ctx->save_filename) {
            AMVP_LOG_STATUS("Saving DELETE response to specified file...");
            val = json_parse_string(ctx->curl_buf);
            if (!val) {
                AMVP_LOG_ERR("Unable to parse JSON. printing output instead...");
            } else {
                rv = amvp_json_serialize_to_file_pretty_w(val, ctx->save_filename);
                if (rv != AMVP_SUCCESS) {
                    AMVP_LOG_ERR("Failed to write file, printing instead...");
                } else {
                    rv = amvp_json_serialize_to_file_pretty_a(NULL, ctx->save_filename);
                    if (rv != AMVP_SUCCESS)
                        AMVP_LOG_WARN("Unable to append ending ] to write file");
                    goto end;
                }
            }
        }
        if (ctx->log_lvl == AMVP_LOG_LVL_VERBOSE) {
            printf("\n\n%s\n\n", ctx->curl_buf);
        } else {
            AMVP_LOG_STATUS("DELETE Response:\n\n%s\n", ctx->curl_buf);
        }
        goto end;
    }

end:
    if (val) json_value_free(val);
    return rv;
}

const char *amvp_version(void) {
    return AMVP_LIBRARY_VERSION;
}

const char *amvp_protocol_version(void) {
    return AMVP_VERSION;
}

static void amvp_generic_error_log(AMVP_CTX *ctx, AMVP_PROTOCOL_ERR *err) {
    AMVP_PROTOCOL_ERR_LIST *list = NULL;
    int i = 0;

    AMVP_LOG_ERR("Error(s) reported by server while attempting task.");
    AMVP_LOG_ERR("Category: %s", err->category_desc);
    AMVP_LOG_ERR("Error(s):");

    list = err->errors;
    while (list) {
        AMVP_LOG_ERR("    Code: %d");
        AMVP_LOG_ERR("    Messages:");
        for (i = 0; i < list->desc_count; i++) {
            AMVP_LOG_ERR("        %s", list->desc[i]);
        }
    }
}

/* Return AMVP_RETRY_OPERATION if we want the caller to try whatever task again */
static AMVP_RESULT amvp_handle_protocol_error(AMVP_CTX *ctx, AMVP_PROTOCOL_ERR *err) {
    AMVP_PROTOCOL_ERR_LIST *list = NULL;
    AMVP_RESULT rv = AMVP_INTERNAL_ERR;

    if (!err) {
        return AMVP_MISSING_ARG;
    }
    list = err->errors;
    switch (err->category) {
    case AMVP_PROTOCOL_ERR_AUTH:
        while (list) {
            switch(list->code) {
            case AMVP_ERR_CODE_AUTH_MISSING_PW:
                AMVP_LOG_ERR("TOTP was expected but not provided");
                rv = AMVP_MISSING_ARG;
                break;
            case AMVP_ERR_CODE_AUTH_INVALID_JWT:
                AMVP_LOG_ERR("Provided JWT is invalid");
                rv = AMVP_INVALID_ARG;
                break;
            case AMVP_ERR_CODE_AUTH_EXPIRED_JWT:
                AMVP_LOG_STATUS("Attempting to refresh JWT and continue...");
                if (amvp_refresh(ctx) == AMVP_SUCCESS) {
                    AMVP_LOG_STATUS("JWT succesfully refreshed. Trying again...");
                    rv = AMVP_RETRY_OPERATION;
                } else {
                    AMVP_LOG_ERR("Attempted to refresh JWT but failed");
                    rv = AMVP_TRANSPORT_FAIL;
                }
                break;
            case AMVP_ERR_CODE_AUTH_INVALID_PW:
                AMVP_LOG_ERR("Provided TOTP invalid; check generator, seed, and system clock");
                rv = AMVP_INVALID_ARG;
                break;
            default:
                break;
            }
            list = list->next;
        }
        break;
    case AMVP_PROTOCOL_ERR_GENERAL:
    case AMVP_PROTOCOL_ERR_MALFORMED_PAYLOAD:
    case AMVP_PROTOCOL_ERR_INVALID_REQUEST:
    case AMVP_PROTOCOL_ERR_ON_SERVER:
        amvp_generic_error_log(ctx, err);
        break;
    case AMVP_PROTOCOL_ERR_CAT_MAX:
    default:
        return AMVP_INVALID_ARG;
    }

    amvp_free_protocol_err(ctx->error);
    ctx->error = NULL;
    return rv;
}
