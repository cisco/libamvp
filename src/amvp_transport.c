/** @file */
/*
 * Copyright (c) 2021, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libamvp/LICENSE
 */

#include <curl/curl.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "amvp.h"
#include "amvp_lcl.h"
#include "amvp_error.h"
#include "safe_lib.h"

#ifdef _WIN32
#include <Windows.h>
#include <intrin.h>

#elif defined __linux__
#if defined __x86_64__ || defined __i386__
#include <cpuid.h>
#endif
#include <sys/utsname.h>

#elif defined __APPLE__
#include <TargetConditionals.h>
//TARGET_OS_MAC is set to 1 on both iOS and Mac OS
#if TARGET_OS_MAC == 1 && TARGET_OS_IPHONE == 0 && !defined(__aarch64__)
#include <cpuid.h>
#endif
#include <sys/utsname.h>
#endif

/*
 * Macros
 */
#define HTTP_OK    200
#define HTTP_UNAUTH    401
#define HTTP_BAD_REQ 400

//Used for knowing which environment variable is being looked for in case of HTTP user-agent.
typedef enum amvp_user_agent_env_type {
    AMVP_USER_AGENT_OSNAME = 1,
    AMVP_USER_AGENT_OSVER,
    AMVP_USER_AGENT_ARCH,
    AMVP_USER_AGENT_PROC,
    AMVP_USER_AGENT_COMP,
    AMVP_USER_AGENT_NONE,
} AMVP_OE_ENV_VAR;

#define AMVP_AUTH_BEARER_TITLE_LEN 23

/*
 * Prototypes
 */
AMVP_RESULT amvp_network_action(AMVP_CTX *ctx, AMVP_NET_ACTION action,
                                       const char *url, const char *data, int data_len);

static void log_network_status(AMVP_CTX *ctx,
                               AMVP_NET_ACTION action,
                               int curl_code,
                               const char *url);

static AMVP_RESULT inspect_http_code(AMVP_CTX *ctx, int code);

static struct curl_slist *amvp_add_auth_hdr(AMVP_CTX *ctx, struct curl_slist *slist) {
    char *bearer = NULL;
    char bearer_title[] = "Authorization: Bearer ";
    int bearer_title_size = (int)sizeof(bearer_title) - 1;
    int bearer_size = 0;

    if (!ctx->jwt_token && !(ctx->tmp_jwt && ctx->use_tmp_jwt)) {
        /*
         * We don't have a token to embed
         */
        return slist;
    }

    if (ctx->use_tmp_jwt && !ctx->tmp_jwt) {
        AMVP_LOG_ERR("Trying to use tmp_jwt, but it is NULL");
        return slist;
    }

    if (ctx->use_tmp_jwt) {
        bearer_size = strnlen_s(ctx->tmp_jwt, AMVP_JWT_TOKEN_MAX) + bearer_title_size;
    } else {
        bearer_size = strnlen_s(ctx->jwt_token, AMVP_JWT_TOKEN_MAX) + bearer_title_size;
    }

    bearer = calloc(bearer_size + 1, sizeof(char));
    if (!bearer) {
        AMVP_LOG_ERR("unable to allocate memory.");
        goto end;
    }

    if (ctx->use_tmp_jwt) {
        snprintf(bearer, bearer_size + 1, "%s%s", bearer_title, ctx->tmp_jwt);
    } else {
        snprintf(bearer, bearer_size + 1, "%s%s", bearer_title, ctx->jwt_token);
    }
    slist = curl_slist_append(slist, bearer);

    free(bearer);

end:
    if (ctx->use_tmp_jwt) {
        /*
         * This was a single-use token.
         * Turn it off now... the library might turn it back on later.
         */
        ctx->use_tmp_jwt = 0;
    }

    return slist;
}

/*
 * This is a callback used by curl to send the HTTP body
 * to the application (us).  We will store the HTTP body
 * in the AMVP_CTX curl_buf field.
 */
static size_t amvp_curl_write_callback(void *ptr, size_t size, size_t nmemb, void *userdata) {
    AMVP_CTX *ctx = (AMVP_CTX *)userdata;

    if (size != 1) {
        fprintf(stderr, "\ncurl size not 1\n");
        return 0;
    }

    if (!ctx->curl_buf) {
        ctx->curl_buf = calloc(AMVP_CURL_BUF_MAX, sizeof(char));
        if (!ctx->curl_buf) {
            fprintf(stderr, "\nmalloc failed in curl write reg func\n");
            return 0;
        }
    }

    if ((ctx->curl_read_ctr + nmemb) > AMVP_CURL_BUF_MAX) {
        fprintf(stderr, "\nServer response is too large\n");
        return 0;
    }

    memcpy_s(&ctx->curl_buf[ctx->curl_read_ctr], (AMVP_CURL_BUF_MAX - ctx->curl_read_ctr), ptr, nmemb);
    ctx->curl_buf[ctx->curl_read_ctr + nmemb] = 0;
    ctx->curl_read_ctr += nmemb;

    return nmemb;
}

/*
 * This function uses libcurl to send a simple HTTP GET
 * request with no Content-Type header.
 * TLS peer verification is enabled, but not HTTP authentication.
 * The parameters are:
 *
 * ctx: Ptr to AMVP_CTX, which contains the server name
 * url: URL to use for the GET request
 *
 * Return value is the HTTP status value from the server
 * (e.g. 200 for HTTP OK)
 */
static long amvp_curl_http_get(AMVP_CTX *ctx, const char *url) {
    long http_code = 0;
    CURL *hnd = NULL;
    struct curl_slist *slist = NULL;
    CURLcode crv = CURLE_OK;

    /*
     * Create the Authorzation header if needed
     */
    slist = amvp_add_auth_hdr(ctx, slist);

    ctx->curl_read_ctr = 0;

    //Setup Curl
    hnd = curl_easy_init();
    if (!hnd) { AMVP_LOG_ERR("Error initializing Curl structure, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_URL, url);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_URL, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 1L);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_NOPROGRESS, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_USERAGENT, ctx->http_user_agent);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_USERAGENT, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, 1L);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_TCP_KEEPALIVE, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSLVERSION, stopping"); goto end; }
    if (slist) {
        crv = curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, slist);
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_HTTPHEADER, stopping"); goto end; }
    }
    //Always verify the server
    crv = curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 0);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSL_VERIFYPEER, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYHOST, 0);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSL_VERIFYHOST, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_HTTP_VERSION, stopping"); goto end; }
    if (ctx->cacerts_file) {
        crv = curl_easy_setopt(hnd, CURLOPT_CAINFO, ctx->cacerts_file);
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_CAINFO, stopping"); goto end; }
        crv = curl_easy_setopt(hnd, CURLOPT_CERTINFO, 1L);
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_CERTINFO, stopping"); goto end; }
    }
    //Mutual-auth
    if (ctx->tls_cert && ctx->tls_key) {
        crv = curl_easy_setopt(hnd, CURLOPT_SSLCERTTYPE, "PEM");
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSLCERTTYPE, stopping"); goto end; }
        crv = curl_easy_setopt(hnd, CURLOPT_SSLCERT, ctx->tls_cert);
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSLCERT, stopping"); goto end; }
        crv = curl_easy_setopt(hnd, CURLOPT_SSLKEYTYPE, "PEM");
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSLKEYTYPE, stopping"); goto end; }
        crv = curl_easy_setopt(hnd, CURLOPT_SSLKEY, ctx->tls_key);
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSLKEY, stopping"); goto end; }
    }

    //To record the HTTP data recieved from the server, set the callback function.
    crv = curl_easy_setopt(hnd, CURLOPT_WRITEDATA, ctx);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_WRITEDATA, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, amvp_curl_write_callback);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_WRITEFUNCTION, stopping"); goto end; }

    if (ctx->curl_buf) {
        /* Clear the HTTP buffer for next server response */
        memzero_s(ctx->curl_buf, AMVP_CURL_BUF_MAX);
    }

    /*
     * Send the HTTP GET request
     */
    curl_easy_perform(hnd);

    if (ctx->log_lvl == AMVP_LOG_LVL_DEBUG) {
        printf("\nHTTP GET RSP:\n\n%s\n", ctx->curl_buf);
    }
    /*
     * Get the HTTP reponse status code from the server
     */
    curl_easy_getinfo(hnd, CURLINFO_RESPONSE_CODE, &http_code);

end:
    if (hnd) curl_easy_cleanup(hnd);
    hnd = NULL;
    if (slist) curl_slist_free_all(slist);
    slist = NULL;

    return http_code;
}

/*
 * This function uses libcurl to send a simple HTTP POST
 * request with no Content-Type header.
 * TLS peer verification is enabled, but not HTTP authentication.
 * The parameters are:
 *
 * ctx: Ptr to AMVP_CTX, which contains the server name
 * url: URL to use for the GET request
 * data: data to POST to the server
 * writefunc: Function pointer to handle writing the data
 *            from the HTTP body received from the server.
 *
 * Return value is the HTTP status value from the server
 * (e.g. 200 for HTTP OK)
 */
static long amvp_curl_http_post(AMVP_CTX *ctx, const char *url, const char *data, int data_len) {
    long http_code = 0;
    CURL *hnd = NULL;
    CURLcode crv = CURLE_OK;
    struct curl_slist *slist = NULL;

    /*
     * Set the Content-Type header in the HTTP request
     */
    slist = curl_slist_append(slist, "Content-Type:application/json");
    /*
     * Create the Authorzation header if needed
     */
    slist = amvp_add_auth_hdr(ctx, slist);

    ctx->curl_read_ctr = 0;

   //Setup Curl
    hnd = curl_easy_init();
    if (!hnd) { AMVP_LOG_ERR("Error initializing Curl structure, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_URL, url);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_URL, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 1L);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_NOPROGRESS, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_USERAGENT, ctx->http_user_agent);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_USERAGENT, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, slist);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_HTTPHEADER, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "POST");
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_CUSTOMREQUEST, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_POST, 1L);
    if (crv) { AMVP_LOG_ERR("fError setting curl option CURLOPT_POST, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, data);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_POSTFIELDS, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)data_len);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_POSTFIELDSIZE_LARGE, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, 1L);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_TCP_KEEPALIVE, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSL_VERSION, stopping"); goto end; }
    //Always verify the server
    crv = curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 0);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSL_VERIFYPEER, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYHOST, 0);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSL_VERIFYHOST, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_HTTP_VERSION, stopping"); goto end; }

    if (ctx->cacerts_file) {
        crv = curl_easy_setopt(hnd, CURLOPT_CAINFO, ctx->cacerts_file);
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_CAINFO, stopping"); goto end; }
        crv = curl_easy_setopt(hnd, CURLOPT_CERTINFO, 1L);
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_CERTINFO, stopping"); goto end; }
    }

    //Mutual-auth
    if (ctx->tls_cert && ctx->tls_key) {
        crv = curl_easy_setopt(hnd, CURLOPT_SSLCERTTYPE, "PEM");
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSLCERTTYPE, stopping"); goto end; }
        crv = curl_easy_setopt(hnd, CURLOPT_SSLCERT, ctx->tls_cert);
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSLCERT, stopping"); goto end; }
        crv = curl_easy_setopt(hnd, CURLOPT_SSLKEYTYPE, "PEM");
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSLKEYTYPE stopping"); goto end; }
        crv = curl_easy_setopt(hnd, CURLOPT_SSLKEY, ctx->tls_key);
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSLKEY, stopping"); goto end; }
    }
    // To record the HTTP data recieved from the server, set the callback function.
    crv = curl_easy_setopt(hnd, CURLOPT_WRITEDATA, ctx);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_WRITEDATA, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, amvp_curl_write_callback);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_WRITEFUNCTION, stopping"); goto end; }

    if (ctx->curl_buf) {
        /* Clear the HTTP buffer for next server response */
        memzero_s(ctx->curl_buf, AMVP_CURL_BUF_MAX);
    }

    /*
     * Send the HTTP POST request
     */
    crv = curl_easy_perform(hnd);
    if (crv != CURLE_OK) {
        AMVP_LOG_ERR("Curl failed with code %d (%s)", crv, curl_easy_strerror(crv));
    }
    if (ctx->log_lvl == AMVP_LOG_LVL_DEBUG) {
        printf("\nHTTP POST RSP:\n\n%s\n", ctx->curl_buf);
    }

    /*
     * Get the HTTP reponse status code from the server
     */
    curl_easy_getinfo(hnd, CURLINFO_RESPONSE_CODE, &http_code);

end:
    if (hnd) curl_easy_cleanup(hnd);
    hnd = NULL;
    if (slist) curl_slist_free_all(slist);
    slist = NULL;

    return http_code;
}

/**
 * @brief Uses libcurl to send a simple HTTP PUT.
 *
 * TLS peer verification is enabled, but not mutual authentication.
 *
 * @param ctx Ptr to AMVP_CTX, which contains the server name
 * @param url URL to use for the PUT operation
 * @param data: data to PUT to the server
 * @param data_len: Length of \p data (in bytes)
 *
 * @return HTTP status value from the server
 * (e.g. 200 for HTTP OK)
 */
static long amvp_curl_http_put(AMVP_CTX *ctx, const char *url, const char *data, int data_len) {
    long http_code = 0;
    CURL *hnd = NULL;
    CURLcode crv = CURLE_OK;
    struct curl_slist *slist = NULL;


    ctx->curl_read_ctr = 0;
    /*
     * Set the Content-Type header in the HTTP request
     */
    slist = curl_slist_append(slist, "Content-Type:application/json");

    /*
     * Create the Authorzation header if needed
     */
    slist = amvp_add_auth_hdr(ctx, slist);

    //Setup Curl
    hnd = curl_easy_init();
    if (!hnd) { AMVP_LOG_ERR("Error initializing Curl structure, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_URL, url);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_URL, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 1L);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_NOPROGRESS, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_USERAGENT, ctx->http_user_agent);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_USERAGENT, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, slist);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_HTTPHEADER, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "PUT");
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_CUSTOMREQUEST, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, data);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_POSTFIELDS, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)data_len);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_POSTFIELDSIZE_LARGE, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, 1L);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_TCP_KEEPALIVE, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSLVERSION, stopping"); goto end; }
    //Always verify the server
    crv = curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 0);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSL_VERIFYPEER, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYHOST, 0);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSL_VERIFYHOST, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_HTTP_VERSION, stopping"); goto end; }
    if (ctx->cacerts_file) {
        crv = curl_easy_setopt(hnd, CURLOPT_CAINFO, ctx->cacerts_file);
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_CAINFO, stopping"); goto end; }
        crv = curl_easy_setopt(hnd, CURLOPT_CERTINFO, 1L);
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_CERTINFO, stopping"); goto end; }
    }
    //Mutual-auth
    if (ctx->tls_cert && ctx->tls_key) {
        crv = curl_easy_setopt(hnd, CURLOPT_SSLCERTTYPE, "PEM");
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSLCERTTYPE, stopping"); goto end; }
        crv = curl_easy_setopt(hnd, CURLOPT_SSLCERT, ctx->tls_cert);
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSLCERT, stopping"); goto end; }
        crv = curl_easy_setopt(hnd, CURLOPT_SSLKEYTYPE, "PEM");
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSLKEYTYPE, stopping"); goto end; }
        crv = curl_easy_setopt(hnd, CURLOPT_SSLKEY, ctx->tls_key);
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSLKEY, stopping"); goto end; }
    }
    //To record the HTTP data recieved from the server, set the callback function.
    crv = curl_easy_setopt(hnd, CURLOPT_WRITEDATA, ctx);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_WRITEDATA, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, amvp_curl_write_callback);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_WRITEFUNCTION, stopping"); goto end; }

    if (ctx->curl_buf) {
        /* Clear the HTTP buffer for next server response */
        memzero_s(ctx->curl_buf, AMVP_CURL_BUF_MAX);
    }

    if (ctx->log_lvl == AMVP_LOG_LVL_DEBUG) {
        printf("\nHTTP PUT:\n\n%s\n", data);
    }

    /*
     * Send the HTTP PUT request
     */
    crv = curl_easy_perform(hnd);
    if (crv != CURLE_OK) {
        AMVP_LOG_ERR("Curl failed with code %d (%s)", crv, curl_easy_strerror(crv));
    }

    if (ctx->log_lvl == AMVP_LOG_LVL_DEBUG) {
        printf("\nHTTP PUT RSP:\n\n%s\n", ctx->curl_buf);
    }

    /*
     * Get the HTTP reponse status code from the server
     */
    curl_easy_getinfo(hnd, CURLINFO_RESPONSE_CODE, &http_code);

end:
    if (hnd) curl_easy_cleanup(hnd);
    hnd = NULL;
    if (slist) curl_slist_free_all(slist);
    slist = NULL;

    return http_code;
}

/**
 * @brief Uses libcurl to send a simple HTTP PUT.
 *
 * TLS peer verification is enabled, but not mutual authentication.
 *
 * @param ctx Ptr to AMVP_CTX, which contains the server name
 * @param url URL to use for the PUT operation
 * @param data: data to PUT to the server
 * @param data_len: Length of \p data (in bytes)
 *
 * @return HTTP status value from the server
 * (e.g. 200 for HTTP OK)
 */
static long amvp_curl_http_delete(AMVP_CTX *ctx, const char *url) {
    long http_code = 0;
    CURL *hnd = NULL;
    CURLcode crv = CURLE_OK;
    struct curl_slist *slist = NULL;


    ctx->curl_read_ctr = 0;
    /*
     * Set the Content-Type header in the HTTP request
     */
    slist = curl_slist_append(slist, "Content-Type:application/json");

    /*
     * Create the Authorzation header if needed
     */
    slist = amvp_add_auth_hdr(ctx, slist);

    //Setup Curl
    hnd = curl_easy_init();
    if (!hnd) { AMVP_LOG_ERR("Error initializing Curl structure, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_URL, url);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_URL, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 1L);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_NOPROGRESS, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_USERAGENT, ctx->http_user_agent);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_USERAGENT, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, slist);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_HTTPHEADER, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "DELETE");
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_CUSTOMREQUEST, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, 1L);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_TCP_KEEPALIVE, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSLVERSION, stopping"); goto end; }
    //Always verify the server
    crv = curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 0);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSL_VERIFYPEER, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYHOST, 0);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSL_VERIFYHOST, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_HTTP_VERSION, stopping"); goto end; }
    if (ctx->cacerts_file) {
        crv = curl_easy_setopt(hnd, CURLOPT_CAINFO, ctx->cacerts_file);
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_CAINFO, stopping"); goto end; }
        crv = curl_easy_setopt(hnd, CURLOPT_CERTINFO, 1L);
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_CERTINFO, stopping"); goto end; }
    }
    //Mutual-auth
    if (ctx->tls_cert && ctx->tls_key) {
        crv = curl_easy_setopt(hnd, CURLOPT_SSLCERTTYPE, "PEM");
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSLCERTTYPE, stopping"); goto end; }
        crv = curl_easy_setopt(hnd, CURLOPT_SSLCERT, ctx->tls_cert);
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSLCERT, stopping"); goto end; }
        crv = curl_easy_setopt(hnd, CURLOPT_SSLKEYTYPE, "PEM");
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSLKEYTYPE, stopping"); goto end; }
        crv = curl_easy_setopt(hnd, CURLOPT_SSLKEY, ctx->tls_key);
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSLKEY, stopping"); goto end; }
    }
    //To record the HTTP data recieved from the server, set the callback function.
    crv = curl_easy_setopt(hnd, CURLOPT_WRITEDATA, ctx);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_WRITEDATA, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, amvp_curl_write_callback);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_WRITEFUNCTION, stopping"); goto end; }

    if (ctx->curl_buf) {
        /* Clear the HTTP buffer for next server response */
        memzero_s(ctx->curl_buf, AMVP_CURL_BUF_MAX);
    }

    if (ctx->log_lvl == AMVP_LOG_LVL_DEBUG) {
        printf("\nHTTP DELETE: %s\n", url);
    }

    /*
     * Send the HTTP PUT request
     */
    crv = curl_easy_perform(hnd);
    if (crv != CURLE_OK) {
        AMVP_LOG_ERR("Curl failed with code %d (%s) ", crv, curl_easy_strerror(crv));
    }

    /*
     * Get the HTTP reponse status code from the server
     */
    curl_easy_getinfo(hnd, CURLINFO_RESPONSE_CODE, &http_code);

end:
    if (hnd) curl_easy_cleanup(hnd);
    hnd = NULL;
    if (slist) curl_slist_free_all(slist);
    slist = NULL;

    return http_code;
}

/*
 * Build a curl_mime structure for security policy document template requests
 * Returns allocated mime structure that caller must free with curl_mime_free()
 */
static curl_mime *build_sp_template_request(CURL *curl_handle, const char *file_path) {
    curl_mime *mime = NULL;
    curl_mimepart *part = NULL;
    CURLcode crv = CURLE_OK;

    mime = curl_mime_init(curl_handle);
    if (!mime) {
        fprintf(stderr, "Error initializing curl mime structure\n");
        return NULL;
    }

    /* Add amvVersion field */
    part = curl_mime_addpart(mime);
    if (!part) {
        fprintf(stderr, "Error adding mime part for amvVersion\n");
        curl_mime_free(mime);
        return NULL;
    }
    crv = curl_mime_name(part, "amvVersion");
    if (crv) {
        fprintf(stderr, "Error setting mime field name for amvVersion\n");
        curl_mime_free(mime);
        return NULL;
    }
    crv = curl_mime_data(part, AMVP_VERSION, CURL_ZERO_TERMINATED);
    if (crv) {
        fprintf(stderr, "Error setting mime data for amvVersion\n");
        curl_mime_free(mime);
        return NULL;
    }

    /* Add documentTemplate file field */
    part = curl_mime_addpart(mime);
    if (!part) {
        fprintf(stderr, "Error adding mime part for documentTemplate\n");
        curl_mime_free(mime);
        return NULL;
    }
    crv = curl_mime_name(part, "documentTemplate");
    if (crv) {
        fprintf(stderr, "Error setting mime field name for documentTemplate\n");
        curl_mime_free(mime);
        return NULL;
    }
    crv = curl_mime_filedata(part, file_path);
    if (crv) {
        fprintf(stderr, "Error setting mime filedata for documentTemplate\n");
        curl_mime_free(mime);
        return NULL;
    }

    return mime;
}

/**
 * @brief Uses libcurl to send a simple HTTP POST with multipart form-data.
 *
 * TLS peer verification is enabled, but not mutual authentication.
 *
 * @param ctx Ptr to AMVP_CTX, which contains the server name
 * @param url URL to use for the POST operation
 * @param mime Pre-built curl_mime structure containing the multipart data
 *
 * @return HTTP status value from the server
 * (e.g. 200 for HTTP OK)
 */
static long amvp_curl_http_post_multipart(AMVP_CTX *ctx, const char *url, curl_mime *mime) {
    long http_code = 0;
    CURL *hnd = NULL;
    CURLcode crv = CURLE_OK;
    struct curl_slist *slist = NULL;

    ctx->curl_read_ctr = 0;

    /*
     * Create the Authorization header if needed
     */
    slist = amvp_add_auth_hdr(ctx, slist);

    //Setup Curl
    hnd = curl_easy_init();
    if (!hnd) { AMVP_LOG_ERR("Error initializing Curl structure, stopping"); goto end; }

    /* Set curl options */
    crv = curl_easy_setopt(hnd, CURLOPT_URL, url);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_URL, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 1L);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_NOPROGRESS, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_USERAGENT, ctx->http_user_agent);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_USERAGENT, stopping"); goto end; }
    if (slist) {
        crv = curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, slist);
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_HTTPHEADER, stopping"); goto end; }
    }
    crv = curl_easy_setopt(hnd, CURLOPT_MIMEPOST, mime);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_MIMEPOST, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, 1L);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_TCP_KEEPALIVE, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSLVERSION, stopping"); goto end; }
    //Always verify the server
    crv = curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 0);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSL_VERIFYPEER, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYHOST, 0);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSL_VERIFYHOST, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_HTTP_VERSION, stopping"); goto end; }

    if (ctx->cacerts_file) {
        crv = curl_easy_setopt(hnd, CURLOPT_CAINFO, ctx->cacerts_file);
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_CAINFO, stopping"); goto end; }
        crv = curl_easy_setopt(hnd, CURLOPT_CERTINFO, 1L);
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_CERTINFO, stopping"); goto end; }
    }
    //Mutual-auth
    if (ctx->tls_cert && ctx->tls_key) {
        crv = curl_easy_setopt(hnd, CURLOPT_SSLCERTTYPE, "PEM");
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSLCERTTYPE, stopping"); goto end; }
        crv = curl_easy_setopt(hnd, CURLOPT_SSLCERT, ctx->tls_cert);
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSLCERT, stopping"); goto end; }
        crv = curl_easy_setopt(hnd, CURLOPT_SSLKEYTYPE, "PEM");
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSLKEYTYPE, stopping"); goto end; }
        crv = curl_easy_setopt(hnd, CURLOPT_SSLKEY, ctx->tls_key);
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSLKEY, stopping"); goto end; }
    }
    //To record the HTTP data received from the server, set the callback function.
    crv = curl_easy_setopt(hnd, CURLOPT_WRITEDATA, ctx);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_WRITEDATA, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, amvp_curl_write_callback);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_WRITEFUNCTION, stopping"); goto end; }

    if (ctx->curl_buf) {
        /* Clear the HTTP buffer for next server response */
        memzero_s(ctx->curl_buf, AMVP_CURL_BUF_MAX);
    }

    if (ctx->log_lvl == AMVP_LOG_LVL_DEBUG) {
        printf("\nHTTP POST MULTIPART:\n\tURL: %s\n", url);
    }

    /*
     * Send the HTTP POST request
     */
    crv = curl_easy_perform(hnd);
    if (crv != CURLE_OK) {
        AMVP_LOG_ERR("Curl failed with code %d (%s)", crv, curl_easy_strerror(crv));
    }

    if (ctx->log_lvl == AMVP_LOG_LVL_DEBUG) {
        printf("\nHTTP POST MULTIPART RSP:\n\n%s\n", ctx->curl_buf);
    }

    /*
     * Get the HTTP response status code from the server
     */
    curl_easy_getinfo(hnd, CURLINFO_RESPONSE_CODE, &http_code);

end:
    if (hnd) curl_easy_cleanup(hnd);
    hnd = NULL;
    if (slist) curl_slist_free_all(slist);
    slist = NULL;

    return http_code;
}

/**
 * @brief Uses libcurl to send a simple HTTP PUT with multipart form-data.
 *
 * TLS peer verification is enabled, but not mutual authentication.
 *
 * @param ctx Ptr to AMVP_CTX, which contains the server name
 * @param url URL to use for the PUT operation
 * @param mime Pre-built curl_mime structure containing the multipart data
 *
 * @return HTTP status value from the server
 * (e.g. 200 for HTTP OK)
 */
static long amvp_curl_http_put_multipart(AMVP_CTX *ctx, const char *url, curl_mime *mime) {
    long http_code = 0;
    CURL *hnd = NULL;
    CURLcode crv = CURLE_OK;
    struct curl_slist *slist = NULL;

    ctx->curl_read_ctr = 0;

    /*
     * Create the Authorization header if needed
     */
    slist = amvp_add_auth_hdr(ctx, slist);

    //Setup Curl
    hnd = curl_easy_init();
    if (!hnd) { AMVP_LOG_ERR("Error initializing Curl structure, stopping"); goto end; }

    /* Set curl options */
    crv = curl_easy_setopt(hnd, CURLOPT_URL, url);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_URL, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 1L);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_NOPROGRESS, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_USERAGENT, ctx->http_user_agent);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_USERAGENT, stopping"); goto end; }
    if (slist) {
        crv = curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, slist);
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_HTTPHEADER, stopping"); goto end; }
    }
    crv = curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "PUT");
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_CUSTOMREQUEST, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_MIMEPOST, mime);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_MIMEPOST, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, 1L);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_TCP_KEEPALIVE, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSLVERSION, stopping"); goto end; }
    //Always verify the server
    crv = curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 0);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSL_VERIFYPEER, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYHOST, 0);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSL_VERIFYHOST, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_HTTP_VERSION, stopping"); goto end; }

    if (ctx->cacerts_file) {
        crv = curl_easy_setopt(hnd, CURLOPT_CAINFO, ctx->cacerts_file);
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_CAINFO, stopping"); goto end; }
        crv = curl_easy_setopt(hnd, CURLOPT_CERTINFO, 1L);
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_CERTINFO, stopping"); goto end; }
    }
    //Mutual-auth
    if (ctx->tls_cert && ctx->tls_key) {
        crv = curl_easy_setopt(hnd, CURLOPT_SSLCERTTYPE, "PEM");
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSLCERTTYPE, stopping"); goto end; }
        crv = curl_easy_setopt(hnd, CURLOPT_SSLCERT, ctx->tls_cert);
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSLCERT, stopping"); goto end; }
        crv = curl_easy_setopt(hnd, CURLOPT_SSLKEYTYPE, "PEM");
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSLKEYTYPE, stopping"); goto end; }
        crv = curl_easy_setopt(hnd, CURLOPT_SSLKEY, ctx->tls_key);
        if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_SSLKEY, stopping"); goto end; }
    }
    //To record the HTTP data received from the server, set the callback function.
    crv = curl_easy_setopt(hnd, CURLOPT_WRITEDATA, ctx);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_WRITEDATA, stopping"); goto end; }
    crv = curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, amvp_curl_write_callback);
    if (crv) { AMVP_LOG_ERR("Error setting curl option CURLOPT_WRITEFUNCTION, stopping"); goto end; }

    if (ctx->curl_buf) {
        /* Clear the HTTP buffer for next server response */
        memzero_s(ctx->curl_buf, AMVP_CURL_BUF_MAX);
    }

    if (ctx->log_lvl == AMVP_LOG_LVL_DEBUG) {
        printf("\nHTTP PUT MULTIPART:\n\tURL: %s\n", url);
    }

    /*
     * Send the HTTP PUT request
     */
    crv = curl_easy_perform(hnd);
    if (crv != CURLE_OK) {
        AMVP_LOG_ERR("Curl failed with code %d (%s)", crv, curl_easy_strerror(crv));
    }

    if (ctx->log_lvl == AMVP_LOG_LVL_DEBUG) {
        printf("\nHTTP PUT MULTIPART RSP:\n\n%s\n", ctx->curl_buf);
    }

    /*
     * Get the HTTP response status code from the server
     */
    curl_easy_getinfo(hnd, CURLINFO_RESPONSE_CODE, &http_code);

end:
    if (hnd) curl_easy_cleanup(hnd);
    hnd = NULL;
    if (slist) curl_slist_free_all(slist);
    slist = NULL;

    return http_code;
}


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

AMVP_RESULT amvp_transport_post(AMVP_CTX *ctx,
                                const char *uri,
                                char *data,
                                int data_len) {
    AMVP_RESULT rv = 0;
    char url[AMVP_ATTR_URL_MAX] = {0};

    rv = sanity_check_ctx(ctx);
    if (AMVP_SUCCESS != rv) return rv;

    if (!uri) {
        AMVP_LOG_ERR("Missing endpoint");
        return AMVP_MISSING_ARG;
    }

    snprintf(url, AMVP_ATTR_URL_MAX - 1,
            "https://%s:%d%s",
            ctx->server_name, ctx->server_port, uri);

    return amvp_network_action(ctx, AMVP_NET_POST, url, data, data_len);
}

/*
 * This is the top level function used within libamvp to retrieve
 * documentation package
 */
AMVP_RESULT amvp_retrieve_docs(AMVP_CTX *ctx, char *vsid_url) {
    AMVP_RESULT rv = 0;
    char url[AMVP_ATTR_URL_MAX] = {0};

    rv = sanity_check_ctx(ctx);
    if (AMVP_SUCCESS != rv) return rv;

    if (!vsid_url) {
        AMVP_LOG_ERR("Missing vsid_url");
        return AMVP_MISSING_ARG;
    }

    snprintf(url, AMVP_ATTR_URL_MAX - 1,
            "https://%s:%d%s/docs",
            ctx->server_name, ctx->server_port, vsid_url);


    return amvp_network_action(ctx, AMVP_NET_GET, url, NULL, 0);
}

AMVP_RESULT amvp_transport_put(AMVP_CTX *ctx,
                               const char *endpoint,
                               const char *data,
                               int data_len) {
    AMVP_RESULT rv = 0;
    char url[AMVP_ATTR_URL_MAX] = {0};

    rv = sanity_check_ctx(ctx);
    if (AMVP_SUCCESS != rv) return rv;

    if (!endpoint) {
        AMVP_LOG_ERR("Missing endpoint");
        return AMVP_MISSING_ARG;
    }

    snprintf(url, AMVP_ATTR_URL_MAX - 1,
            "https://%s:%d%s",
            ctx->server_name, ctx->server_port, endpoint);

    return amvp_network_action(ctx, AMVP_NET_PUT, url, data, data_len);
}

AMVP_RESULT amvp_transport_delete(AMVP_CTX *ctx,
                               const char *endpoint) {
    AMVP_RESULT rv = 0;
    char url[AMVP_ATTR_URL_MAX] = {0};

    rv = sanity_check_ctx(ctx);
    if (AMVP_SUCCESS != rv) return rv;

    if (!endpoint) {
        AMVP_LOG_ERR("Missing endpoint");
        return AMVP_MISSING_ARG;
    }

    snprintf(url, AMVP_ATTR_URL_MAX - 1,
            "https://%s:%d%s",
            ctx->server_name, ctx->server_port, endpoint);

    return amvp_network_action(ctx, AMVP_NET_DELETE, url, NULL, 0);
}

AMVP_RESULT amvp_transport_put_validation(AMVP_CTX *ctx,
                                          const char *validation,
                                          int validation_len) {
    if (!ctx) return AMVP_NO_CTX;
    if (validation == NULL) return AMVP_INVALID_ARG;

    return amvp_transport_put(ctx, ctx->session_url, validation, validation_len);
}

static AMVP_RESULT amvp_transport_post_multipart(AMVP_CTX *ctx,
                                          const char *endpoint,
                                          curl_mime *mime) {
    AMVP_RESULT rv = 0;
    char url[AMVP_ATTR_URL_MAX] = {0};
    long http_code = 0;

    rv = sanity_check_ctx(ctx);
    if (AMVP_SUCCESS != rv) return rv;

    if (!endpoint) {
        AMVP_LOG_ERR("Missing endpoint");
        return AMVP_MISSING_ARG;
    }

    if (!mime) {
        AMVP_LOG_ERR("Missing MIME structure");
        return AMVP_MISSING_ARG;
    }

    snprintf(url, AMVP_ATTR_URL_MAX - 1,
            "https://%s:%d%s",
            ctx->server_name, ctx->server_port, endpoint);

    http_code = amvp_curl_http_post_multipart(ctx, url, mime);

    /* Log to the console */
    log_network_status(ctx, AMVP_NET_POST, http_code, url);

    /* Use proper protocol error handling */
    rv = inspect_http_code(ctx, http_code);
    if (rv != AMVP_SUCCESS) {
        return rv;
    }

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_transport_put_multipart(AMVP_CTX *ctx,
                                          const char *endpoint,
                                          curl_mime *mime) {
    AMVP_RESULT rv = 0;
    char url[AMVP_ATTR_URL_MAX] = {0};
    long http_code = 0;

    rv = sanity_check_ctx(ctx);
    if (AMVP_SUCCESS != rv) return rv;

    if (!endpoint) {
        AMVP_LOG_ERR("Missing endpoint");
        return AMVP_MISSING_ARG;
    }

    if (!mime) {
        AMVP_LOG_ERR("Missing MIME structure");
        return AMVP_MISSING_ARG;
    }

    snprintf(url, AMVP_ATTR_URL_MAX - 1,
            "https://%s:%d%s",
            ctx->server_name, ctx->server_port, endpoint);

    http_code = amvp_curl_http_put_multipart(ctx, url, mime);

    /* Log to the console */
    log_network_status(ctx, AMVP_NET_PUT, http_code, url);

    /* Use proper protocol error handling */
    rv = inspect_http_code(ctx, http_code);
    if (rv != AMVP_SUCCESS) {
        return rv;
    }

    return AMVP_SUCCESS;
}

AMVP_RESULT amvp_transport_post_sp_template(AMVP_CTX *ctx,
                                            const char *endpoint,
                                            const char *file_path) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    CURL *temp_curl = NULL;
    curl_mime *mime = NULL;

    if (!ctx || !endpoint || !file_path) {
        AMVP_LOG_ERR("Missing required parameters");
        return AMVP_MISSING_ARG;
    }

    /* Create temporary curl handle for MIME building */
    temp_curl = curl_easy_init();
    if (!temp_curl) {
        AMVP_LOG_ERR("Failed to initialize temporary curl handle");
        return AMVP_TRANSPORT_FAIL;
    }

    /* Build MIME structure with specific fields for SP template */
    mime = build_sp_template_request(temp_curl, file_path);
    if (!mime) {
        AMVP_LOG_ERR("Failed to build MIME structure");
        curl_easy_cleanup(temp_curl);
        return AMVP_TRANSPORT_FAIL;
    }

    /* Send the multipart request */
    rv = amvp_transport_post_multipart(ctx, endpoint, mime);

    /* Cleanup */
    curl_mime_free(mime);
    curl_easy_cleanup(temp_curl);

    return rv;
}

AMVP_RESULT amvp_transport_put_sp_template(AMVP_CTX *ctx,
                                           const char *endpoint,
                                           const char *file_path) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    CURL *temp_curl = NULL;
    curl_mime *mime = NULL;

    if (!ctx || !endpoint || !file_path) {
        AMVP_LOG_ERR("Missing required parameters");
        return AMVP_MISSING_ARG;
    }

    /* Create temporary curl handle for MIME building */
    temp_curl = curl_easy_init();
    if (!temp_curl) {
        AMVP_LOG_ERR("Failed to initialize temporary curl handle");
        return AMVP_TRANSPORT_FAIL;
    }

    /* Build MIME structure with specific fields for SP template */
    mime = build_sp_template_request(temp_curl, file_path);
    if (!mime) {
        AMVP_LOG_ERR("Failed to build MIME structure");
        curl_easy_cleanup(temp_curl);
        return AMVP_TRANSPORT_FAIL;
    }

    /* Send the multipart request */
    rv = amvp_transport_put_multipart(ctx, endpoint, mime);

    /* Cleanup */
    curl_mime_free(mime);
    curl_easy_cleanup(temp_curl);

    return rv;
}

AMVP_RESULT amvp_transport_get(AMVP_CTX *ctx,
                               const char *url,
                               const AMVP_KV_LIST *parameters) {
    AMVP_RESULT rv = 0;
    CURL *curl_hnd = NULL;
    char *full_url = NULL, *escaped_value = NULL;
    int max_url = AMVP_ATTR_URL_MAX;
    int rem_space = 0;
    int join = 0;
    int len = 0;

    rv = sanity_check_ctx(ctx);
    if (AMVP_SUCCESS != rv) return rv;

    if (!url) {
        AMVP_LOG_ERR("Missing url");
        return AMVP_MISSING_ARG;
    }

    full_url = calloc(AMVP_ATTR_URL_MAX + 1, sizeof(char));
    if (full_url == NULL) {
        AMVP_LOG_ERR("Failed to malloc");
        rv = AMVP_TRANSPORT_FAIL;
        goto end;
    }

    len = snprintf(full_url, max_url, "https://%s:%d%s",
                   ctx->server_name, ctx->server_port, url);
    rem_space = max_url - len;

    if (parameters) {
        curl_hnd = curl_easy_init();
        if (curl_hnd == NULL) {
            AMVP_LOG_ERR("Failed to intialize curl handle");
            rv = AMVP_TRANSPORT_FAIL;
            goto end;
        }
        const AMVP_KV_LIST *param = parameters;
        while (1) {
            if (join) {
                len += snprintf(full_url+len, rem_space, "&%s", param->key);
                rem_space = max_url - len;
            } else {
                len += snprintf(full_url+len, rem_space, "%s", param->key);
                rem_space = max_url - len;
                join = 1;
            }

            escaped_value = curl_easy_escape(curl_hnd, param->value, strnlen_s(param->value, rem_space));
            if (escaped_value == NULL) {
                AMVP_LOG_ERR("Failed curl_easy_escape()");
                rv = AMVP_TRANSPORT_FAIL;
                goto end;
            }

            len += snprintf(full_url+len, rem_space, "%s", escaped_value);
            rem_space = max_url - len;

            curl_free(escaped_value); escaped_value = NULL;
            if (param->next == NULL || rem_space <= 0) break;
            param = param->next;
        }
        /* Don't need these anymore */
        curl_easy_cleanup(curl_hnd); curl_hnd = NULL;
    }

    rv = amvp_network_action(ctx, AMVP_NET_GET, full_url, NULL, 0);

end:
    if (curl_hnd) curl_easy_cleanup(curl_hnd);
    if (full_url) free(full_url);
    return rv;
}

#define JWT_EXPIRED_STR "JWT expired"
#define JWT_EXPIRED_STR_LEN 11
#define JWT_INVALID_STR "JWT signature does not match"
#define JWT_INVALID_STR_LEN 28
static AMVP_RESULT inspect_http_code(AMVP_CTX *ctx, int code) {
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

static AMVP_RESULT execute_network_action(AMVP_CTX *ctx,
                                          AMVP_NET_ACTION action,
                                          const char *url,
                                          const char *data,
                                          int data_len,
                                          int *curl_code) {
    AMVP_RESULT result = 0;
    char *resp = NULL;
    int rc = 0;

    switch(action) {
    case AMVP_NET_GET:
        rc = amvp_curl_http_get(ctx, url);
        break;

    case AMVP_NET_POST:
        rc = amvp_curl_http_post(ctx, url, data, data_len);
        break;

    case AMVP_NET_PUT:
        rc = amvp_curl_http_put(ctx, url, data, data_len);
        break;

    case AMVP_NET_DELETE:
        rc = amvp_curl_http_delete(ctx, url);
        break;

    default:
        AMVP_LOG_ERR("Unknown AMVP_NET_ACTION");
        return AMVP_INVALID_ARG;
    }

    /* Peek at the HTTP code */
    result = inspect_http_code(ctx, rc);
    if (result == AMVP_PROTOCOL_RSP_ERR) {
        goto end;
    }

    if (result != AMVP_SUCCESS) {
        if (result == AMVP_JWT_EXPIRED) {
            /*
             * Expired JWT
             * We are going to refresh the session
             * and try to obtain a new JWT!
             * This should not ever happen during "login"...
             * and we need to avoid an infinite loop (via amvp_refesh).
             */
            AMVP_LOG_WARN("JWT authorization has timed out, curl rc=%d. Refreshing session...", rc);
            result = amvp_refresh(ctx);
            if (result != AMVP_SUCCESS) {
                AMVP_LOG_ERR("JWT refresh failed.");
                goto end;
            } else {
                AMVP_LOG_STATUS("Refresh successful, attempting to continue...");
            }

            /* Try action again after the refresh */
            switch(action) {
            case AMVP_NET_GET:
                rc = amvp_curl_http_get(ctx, url);
                break;

            case AMVP_NET_POST:
                rc = amvp_curl_http_post(ctx, url, data, data_len);
                break;

            case AMVP_NET_PUT:
                rc = amvp_curl_http_put(ctx, url, data, data_len);
                break;

            case AMVP_NET_DELETE:
                amvp_curl_http_delete(ctx, url);
                break;

            default:
                AMVP_LOG_ERR("We should never be here!");
                break;
            }

            result = inspect_http_code(ctx, rc);
            if (result != AMVP_SUCCESS) {
                AMVP_LOG_ERR("Refreshed + retried, HTTP transport fails. curl rc=%d\n", rc);
                goto end;
            }
        } else if (result == AMVP_JWT_INVALID) {
            /*
             * Invalid JWT
             */
            AMVP_LOG_ERR("JWT invalid. curl rc=%d.\n", rc);
            goto end;
        }

        /* Generic error */
        goto end;
    }

    result = AMVP_SUCCESS;

end:
    if (resp) json_free_serialized_string(resp);

    *curl_code = rc;

    return result;
}

static void log_network_status(AMVP_CTX *ctx,
                               AMVP_NET_ACTION action,
                               int curl_code,
                               const char *url) {

    switch(action) {
    case AMVP_NET_GET:
        AMVP_LOG_VERBOSE("GET...\n\tStatus: %d\n\tUrl: %s\n\tResp:\n%s\n",
                      curl_code, url, ctx->curl_buf);
        break;

    case AMVP_NET_POST:
        AMVP_LOG_VERBOSE("POST...\n\tStatus: %d\n\tUrl: %s\n\tResp: %s\n",
                        curl_code, url, ctx->curl_buf);
        break;

    case AMVP_NET_PUT:
        AMVP_LOG_VERBOSE("PUT...\n\tStatus: %d\n\tUrl: %s\n\tResp: %s\n",
                        curl_code, url, ctx->curl_buf);
        break;

    case AMVP_NET_DELETE:
        AMVP_LOG_VERBOSE("DELETE...\n\tStatus: %d\n\tUrl: %s\n\tResp:\n%s\n",
                       curl_code, url, ctx->curl_buf);
        break;
    default:
        AMVP_LOG_ERR("We should never be here!");
        break;
    }


    if (curl_code == 0) {
        AMVP_LOG_ERR("Received no response from server.");
    } else if (curl_code < 200 || curl_code >= 300) {
        /* Check if this might be a protocol error that can be handled automatically.
         * If so, suppress the error log to avoid confusing users when the error
         * is successfully handled by the protocol error system. */
        if (ctx && amvp_is_protocol_error_message(ctx->curl_buf)) {
            /* This is likely a protocol error - let the handler log appropriately */
            AMVP_LOG_VERBOSE("HTTP %d response contains protocol error message", curl_code);
        } else {
            /* This is a non-protocol error that should be logged */
            AMVP_LOG_ERR("%d error received from server. Message:", curl_code);
            AMVP_LOG_ERR("%s", ctx->curl_buf);
        }
    }

}

/*
 * This is the internal send function that takes the URI as an extra
 * parameter. This removes repeated code without having to change the
 * API that the library uses to send registrations
 */
AMVP_RESULT amvp_network_action(AMVP_CTX *ctx,
                                       AMVP_NET_ACTION action,
                                       const char *url,
                                       const char *data,
                                       int data_len) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    AMVP_NET_ACTION generic_action = 0;
    int check_data = 0;
    int curl_code = 0;

    if (!ctx) {
        AMVP_LOG_ERR("Missing ctx");
        return AMVP_NO_CTX;
    }

    if (!url) {
        AMVP_LOG_ERR("URL required for transmission");
        return AMVP_MISSING_ARG;
    }

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
    case AMVP_NET_DELETE:
        generic_action = AMVP_NET_DELETE;
        break;
    default:
        AMVP_LOG_ERR("We should never be here!");
        break;
    }

    if (check_data && (!data || !data_len)) {
        AMVP_LOG_ERR("POST action requires non-zero data/data_len");
        return AMVP_NO_DATA;
    }

    rv = execute_network_action(ctx, generic_action, url,
                                data, data_len, &curl_code);

    /* Log to the console */
    log_network_status(ctx, action, curl_code, url);

    return rv;
}

/**
 * This function is called to look for operating enivronment info in the environment
 * for the HTTP user-agent string when the library cannot automatically find it
 */
static void amvp_http_user_agent_check_env_for_var(AMVP_CTX *ctx, char *var_string, AMVP_OE_ENV_VAR var_to_check) {
    unsigned int maxLength = 0;
    const char *var;

    switch(var_to_check) {
    case AMVP_USER_AGENT_OSNAME:
        var = AMVP_USER_AGENT_OSNAME_ENV;
        maxLength = AMVP_USER_AGENT_OSNAME_STR_MAX;
        break;
    case AMVP_USER_AGENT_OSVER:
        var = AMVP_USER_AGENT_OSVER_ENV;
        maxLength = AMVP_USER_AGENT_OSVER_STR_MAX;
        break;
    case AMVP_USER_AGENT_ARCH:
        var = AMVP_USER_AGENT_ARCH_ENV;
        maxLength = AMVP_USER_AGENT_ARCH_STR_MAX;
        break;
    case AMVP_USER_AGENT_PROC:
        var = AMVP_USER_AGENT_PROC_ENV;
        maxLength = AMVP_USER_AGENT_PROC_STR_MAX;
        break;
    case AMVP_USER_AGENT_COMP:
        var = AMVP_USER_AGENT_COMP_ENV;
        maxLength = AMVP_USER_AGENT_COMP_STR_MAX;
        break;
    case AMVP_USER_AGENT_NONE:
    default:
        return;
    }

    //Check presence and length of variable's value, concatenate if valid, warn and ignore if not
    char *envVal = getenv(var);
    if (envVal) {
        if (strnlen_s(envVal, maxLength + 1) > maxLength) {
            AMVP_LOG_WARN("Environment-provided %s string too long! (%d char max.) Omitting...\n", var, maxLength);
        } else {
            strncpy_s(var_string, maxLength + 1, envVal, maxLength);
        }
    } else {
        AMVP_LOG_INFO("Unable to collect info for HTTP user-agent - consider defining %s (%d char max.) This is optional and will not affect testing.", var, maxLength);
    }
}

static void amvp_http_user_agent_check_compiler_ver(char *comp_string) {
    char versionBuffer[16];

#ifdef __GNUC__
    strncpy_s(comp_string, AMVP_USER_AGENT_COMP_STR_MAX + 1, "GCC/", AMVP_USER_AGENT_COMP_STR_MAX);

    snprintf(versionBuffer, sizeof(versionBuffer), "%d", __GNUC__);
    strncat_s(comp_string, AMVP_USER_AGENT_COMP_STR_MAX + 1, versionBuffer, AMVP_USER_AGENT_COMP_STR_MAX);

#ifdef __GNUC_MINOR__
    snprintf(versionBuffer, sizeof(versionBuffer), "%d", __GNUC_MINOR__);
    strncat_s(comp_string, AMVP_USER_AGENT_COMP_STR_MAX + 1, ".", AMVP_USER_AGENT_COMP_STR_MAX);
    strncat_s(comp_string, AMVP_USER_AGENT_COMP_STR_MAX + 1, versionBuffer, AMVP_USER_AGENT_COMP_STR_MAX);
#endif

#ifdef __GNUC_PATCHLEVEL__
    snprintf(versionBuffer, sizeof(versionBuffer), "%d", __GNUC_PATCHLEVEL__);
    strncat_s(comp_string, AMVP_USER_AGENT_COMP_STR_MAX + 1, ".", AMVP_USER_AGENT_COMP_STR_MAX);
    strncat_s(comp_string, AMVP_USER_AGENT_COMP_STR_MAX + 1, versionBuffer, AMVP_USER_AGENT_COMP_STR_MAX);
#endif

#elif defined _MSC_FULL_VER
    strncpy_s(comp_string, AMVP_USER_AGENT_COMP_STR_MAX + 1, "MSVC/", AMVP_USER_AGENT_COMP_STR_MAX);

    snprintf(versionBuffer, sizeof(versionBuffer), "%d", _MSC_FULL_VER);
    strncat_s(comp_string, AMVP_USER_AGENT_COMP_STR_MAX + 1, versionBuffer, AMVP_USER_AGENT_COMP_STR_MAX);
#else
    amvp_http_user_agent_check_env_for_var(ctx, comp_string, AMVP_USER_AGENT_COMP);
#endif
}

/*
 * remove delimiter characters, check for leading and trailing whitespace
 */
static void amvp_http_user_agent_string_clean(char *str) {
    int i = 0;
    if (!str) {
        return;
    }
    int len = strnlen_s(str, AMVP_USER_AGENT_STR_MAX);
    if (len <= 0) {
        return;
    }
    //remove any leading or trailing whitespace
    strremovews_s(str, len);
    len = strnlen_s(str, AMVP_USER_AGENT_STR_MAX);

    for (i = 0; i < len; i++) {
        if (str[i] == AMVP_USER_AGENT_DELIMITER) {
            str[i] = AMVP_USER_AGENT_CHAR_REPLACEMENT;
        }
    }
}

void amvp_http_user_agent_handler(AMVP_CTX *ctx) {
    if (!ctx || ctx->http_user_agent) {
        AMVP_LOG_WARN("Error generating HTTP user-agent - no CTX or string already exists\n");
        return;
    } else {
        ctx->http_user_agent = calloc(AMVP_USER_AGENT_STR_MAX + 1, sizeof(char));
        if (!ctx->http_user_agent) {
            AMVP_LOG_ERR("Unable to allocate memory for user agent, skipping...");
            return;
        }
    }

    char *libver = calloc(AMVP_USER_AGENT_AMVP_STR_MAX + 1, sizeof(char));
    char *osname = calloc(AMVP_USER_AGENT_OSNAME_STR_MAX + 1, sizeof(char));
    char *osver = calloc(AMVP_USER_AGENT_OSVER_STR_MAX + 1, sizeof(char));
    char *arch = calloc(AMVP_USER_AGENT_ARCH_STR_MAX + 1, sizeof(char));
    char *proc = calloc(AMVP_USER_AGENT_PROC_STR_MAX + 1, sizeof(char));
    char *comp = calloc(AMVP_USER_AGENT_COMP_STR_MAX + 1, sizeof(char));

    if (!libver || !osname || !osver || !arch || !proc || !comp) {
        AMVP_LOG_ERR("Unable to allocate memory for HTTP user-agent, skipping...\n");
        goto end;
    }

    snprintf(libver, AMVP_USER_AGENT_AMVP_STR_MAX, "libamvp/%s", AMVP_LIBRARY_VERSION_NUMBER);


#if defined __linux__ || defined __APPLE__

    //collects basic OS/hardware info
    struct utsname info;
    if (uname(&info) != 0) {
        amvp_http_user_agent_check_env_for_var(ctx, osname, AMVP_USER_AGENT_OSNAME);
        amvp_http_user_agent_check_env_for_var(ctx, osver, AMVP_USER_AGENT_OSVER);
        amvp_http_user_agent_check_env_for_var(ctx, arch, AMVP_USER_AGENT_ARCH);
    } else {
        //usually Linux/Darwin
        strncpy_s(osname, AMVP_USER_AGENT_OSNAME_STR_MAX + 1, info.sysname, AMVP_USER_AGENT_OSNAME_STR_MAX);

        //usually linux kernel version/darwin version
        strncpy_s(osver, AMVP_USER_AGENT_OSVER_STR_MAX + 1, info.release, AMVP_USER_AGENT_OSVER_STR_MAX);

        //hardware architecture
        strncpy_s(arch, AMVP_USER_AGENT_ARCH_STR_MAX + 1, info.machine, AMVP_USER_AGENT_ARCH_STR_MAX);
    }

#if defined __x86_64__ || defined __i386__
    /* 48 byte CPU brand string, obtained via CPUID opcode in x86/amd64 processors.
    The 0x8000000X values are specifically for that opcode.
    Each __get_cpuid call gets 16 bytes, or 1/3 of the brand string */
    unsigned int registers[4];
    char brandString[48];

    if (!__get_cpuid(0x80000002, &registers[0], &registers[1], &registers[2], &registers[3])) {
        amvp_http_user_agent_check_env_for_var(ctx, proc, AMVP_USER_AGENT_PROC);
    } else {
        memcpy_s(brandString, 16, &registers, 16);
    }
    if (!__get_cpuid(0x80000003, &registers[0], &registers[1], &registers[2], &registers[3])) {
        amvp_http_user_agent_check_env_for_var(ctx, proc, AMVP_USER_AGENT_PROC);
    } else {
        memcpy_s(brandString + 16, 16, &registers, 16);
    }
    if (!__get_cpuid(0x80000004, &registers[0], &registers[1], &registers[2], &registers[3])) {
        amvp_http_user_agent_check_env_for_var(ctx, proc, AMVP_USER_AGENT_PROC);
    } else {
        memcpy_s(brandString + 32, 16, &registers, 16);
        strncpy_s(proc, AMVP_USER_AGENT_PROC_STR_MAX + 1, brandString, AMVP_USER_AGENT_PROC_STR_MAX);
    }
#else
    amvp_http_user_agent_check_env_for_var(ctx, proc, AMVP_USER_AGENT_PROC);
#endif

    //gets compiler version, or checks environment for it
    amvp_http_user_agent_check_compiler_ver(comp);

#elif defined WIN32

    HKEY key;
    long status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0,
                  KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key);
    if (status != ERROR_SUCCESS) {
        amvp_http_user_agent_check_env_for_var(ctx, osname, AMVP_USER_AGENT_OSNAME);
        amvp_http_user_agent_check_env_for_var(ctx, osver, AMVP_USER_AGENT_OSVER);
    } else {
        //product name string, containing general version of windows
        DWORD bufferLength;
        if (RegQueryValueExW(key, L"ProductName", NULL, NULL, NULL, &bufferLength) != ERROR_SUCCESS) {
            AMVP_LOG_WARN("Unable to access Windows OS name, checking environment or omitting from HTTP user-agent...\n");
            amvp_http_user_agent_check_env_for_var(ctx, osname, AMVP_USER_AGENT_OSNAME);
        } else {
            //get string - registry strings not garuanteed to be null terminated
            wchar_t *productNameBuffer = calloc(bufferLength + 1, sizeof(wchar_t));
            if (!productNameBuffer) {
                AMVP_LOG_ERR("Unable to allocate memory while generating windows OS name, skipping...\n");
            } else if (RegQueryValueExW(key, L"ProductName", NULL, NULL, productNameBuffer, &bufferLength) != ERROR_SUCCESS) {
                AMVP_LOG_WARN("Unable to access Windows OS name, checking environment or omitting from HTTP user-agent...\n");
                free(productNameBuffer);
                amvp_http_user_agent_check_env_for_var(ctx, osname, AMVP_USER_AGENT_OSNAME);
            } else {
                //Windows uses UTF16, and everyone else uses UTF8
                char *utf8String = calloc(bufferLength + 1, sizeof(char));
                if (!utf8String || !WideCharToMultiByte(CP_UTF8, 0, productNameBuffer, -1, utf8String, bufferLength + 1, NULL, NULL)) {
                    AMVP_LOG_ERR("Error converting Windows version to UTF8, checking environment or omitting from HTTP user-agent...\n");
                    amvp_http_user_agent_check_env_for_var(ctx, osver, AMVP_USER_AGENT_OSVER);
                } else {
                    strncpy_s(osname, AMVP_USER_AGENT_OSNAME_STR_MAX + 1, utf8String, AMVP_USER_AGENT_OSNAME_STR_MAX);
                }
                free(utf8String);
                free(productNameBuffer);
            }

        }

        //get the "BuildLab" string, which contains more specific windows build information
        if (RegQueryValueExW(key, L"BuildLab", NULL, NULL, NULL, &bufferLength) != ERROR_SUCCESS) {
            AMVP_LOG_WARN("Unable to access Windows version, checking environment or omitting from HTTP user-agent...\n");
            amvp_http_user_agent_check_env_for_var(ctx, osver, AMVP_USER_AGENT_OSVER);
        } else {
            //get string - registry strings not garuanteed to be null terminated
            wchar_t *buildLabBuffer = calloc(bufferLength + 1, sizeof(wchar_t));
            if (!buildLabBuffer) {
                AMVP_LOG_ERR("Unable to allocate memory while generating windows OS version, skipping...\n");
            } else if (RegQueryValueExW(key, L"BuildLab", NULL, NULL, buildLabBuffer, &bufferLength) != ERROR_SUCCESS) {
                AMVP_LOG_WARN("Unable to access Windows version, checking environment or omitting from HTTP user-agent...\n");
                amvp_http_user_agent_check_env_for_var(ctx, osver, AMVP_USER_AGENT_OSVER);
                free(buildLabBuffer);
            } else {
                //Windows uses UTF16, and everyone else uses UTF8
                char *utf8String = calloc(bufferLength + 1, sizeof(char));
                if (!utf8String || !WideCharToMultiByte(CP_UTF8, 0, buildLabBuffer, -1, utf8String, bufferLength + 1, NULL, NULL)) {
                    AMVP_LOG_ERR("Error converting Windows build info to UTF8, checking environment or omitting from HTTP user-agent...\n");
                    amvp_http_user_agent_check_env_for_var(ctx, osver, AMVP_USER_AGENT_OSVER);
                } else {
                    strncpy_s(osver, AMVP_USER_AGENT_OSVER_STR_MAX + 1, utf8String, AMVP_USER_AGENT_OSVER_STR_MAX);
                }
                free(utf8String);
                free(buildLabBuffer);
            }
        }
    }

    SYSTEM_INFO sysInfo;
    GetNativeSystemInfo(&sysInfo);
    if (!sysInfo.dwOemId) {
        amvp_http_user_agent_check_env_for_var(ctx, arch, AMVP_USER_AGENT_ARCH);
        amvp_http_user_agent_check_env_for_var(ctx, proc, AMVP_USER_AGENT_PROC);
    } else {
        char brandString[48];
        int brandString_resp[4];
        switch(sysInfo.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64:
            strncpy_s(arch, AMVP_USER_AGENT_ARCH_STR_MAX + 1, "x86_64", AMVP_USER_AGENT_ARCH_STR_MAX);
             //get CPU model string
            __cpuid(brandString_resp, 0x80000002);
            memcpy_s(brandString, 16, &brandString_resp, 16);
            __cpuid(brandString_resp, 0x80000003);
            memcpy_s(brandString + 16, 16, &brandString_resp, 16);
            __cpuid(brandString_resp, 0x80000004);
            memcpy_s(brandString + 32, 16, &brandString_resp, 16);
            strncpy_s(proc, AMVP_USER_AGENT_PROC_STR_MAX + 1, brandString, AMVP_USER_AGENT_PROC_STR_MAX);
            break;
        case PROCESSOR_ARCHITECTURE_INTEL:
            strncpy_s(arch, AMVP_USER_AGENT_ARCH_STR_MAX + 1, "x86", AMVP_USER_AGENT_ARCH_STR_MAX);
            //get CPU model string
            __cpuid(brandString_resp, 0x80000002);
            memcpy_s(brandString, 16, &brandString_resp, 16);
            __cpuid(brandString_resp, 0x80000003);
            memcpy_s(brandString + 16, 16, &brandString_resp, 16);
            __cpuid(brandString_resp, 0x80000004);
            memcpy_s(brandString + 32, 16, &brandString_resp, 16);
            strncpy_s(proc, AMVP_USER_AGENT_PROC_STR_MAX + 1, brandString, AMVP_USER_AGENT_PROC_STR_MAX);
            break;
        case PROCESSOR_ARCHITECTURE_ARM64:
            strncpy_s(arch, AMVP_USER_AGENT_ARCH_STR_MAX + 1, "aarch64", AMVP_USER_AGENT_ARCH_STR_MAX);
            amvp_http_user_agent_check_env_for_var(ctx, proc, AMVP_USER_AGENT_PROC);
            break;
        case PROCESSOR_ARCHITECTURE_ARM:
            strncpy_s(arch, AMVP_USER_AGENT_ARCH_STR_MAX + 1, "arm", AMVP_USER_AGENT_ARCH_STR_MAX);
            amvp_http_user_agent_check_env_for_var(ctx, proc, AMVP_USER_AGENT_PROC);
            break;
        case PROCESSOR_ARCHITECTURE_PPC:
            strncpy_s(arch, AMVP_USER_AGENT_ARCH_STR_MAX + 1, "ppc", AMVP_USER_AGENT_ARCH_STR_MAX);
            amvp_http_user_agent_check_env_for_var(ctx, proc, AMVP_USER_AGENT_PROC);
            break;
        case PROCESSOR_ARCHITECTURE_MIPS:
            strncpy_s(arch, AMVP_USER_AGENT_ARCH_STR_MAX + 1, "mips", AMVP_USER_AGENT_ARCH_STR_MAX);
            amvp_http_user_agent_check_env_for_var(ctx, proc, AMVP_USER_AGENT_PROC);
            break;
        default:
            amvp_http_user_agent_check_env_for_var(ctx, arch, AMVP_USER_AGENT_ARCH);
            amvp_http_user_agent_check_env_for_var(ctx, proc, AMVP_USER_AGENT_PROC);
            break;
        }
    }

    //gets compiler version
    amvp_http_user_agent_check_compiler_ver(comp);

#else
    /*******************************************************
     * Code for getting OE information on platforms that   *
     * are not Windows, Linux, or Mac OS can be added here *
     *******************************************************/
    amvp_http_user_agent_check_env_for_var(ctx, osname, AMVP_USER_AGENT_OSNAME);
    amvp_http_user_agent_check_env_for_var(ctx, osver, AMVP_USER_AGENT_OSVER);
    amvp_http_user_agent_check_env_for_var(ctx, arch, AMVP_USER_AGENT_ARCH);
    amvp_http_user_agent_check_env_for_var(ctx, proc, AMVP_USER_AGENT_PROC);
    amvp_http_user_agent_check_compiler_ver(comp);
#endif

    amvp_http_user_agent_string_clean(osname);
    amvp_http_user_agent_string_clean(osver);
    amvp_http_user_agent_string_clean(arch);
    amvp_http_user_agent_string_clean(proc);
    amvp_http_user_agent_string_clean(comp);

    snprintf(ctx->http_user_agent, AMVP_USER_AGENT_STR_MAX, "%s;%s;%s;%s;%s;%s", libver, osname, osver, arch, proc, comp);
    AMVP_LOG_INFO("HTTP User-Agent: %s\n", ctx->http_user_agent);

end:
    free(libver);
    free(osname);
    free(osver);
    free(arch);
    free(proc);
    free(comp);
}
