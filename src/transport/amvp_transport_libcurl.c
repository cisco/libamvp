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
 * HTTP transport implementation using libcurl
 * This file provides HTTP/HTTPS networking capabilities for the AMVP client
 * using the libcurl library for cross-platform networking.
 */

#include <curl/curl.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "amvp.h"
#include "amvp_lcl.h"
#include "amvp_error.h"
#include "safe_lib.h"

/*
 * Macros
 */
#define HTTP_OK    200
#define HTTP_UNAUTH    401
#define HTTP_BAD_REQ 400

#define AMVP_AUTH_BEARER_TITLE_LEN 23

/*
 * Prototypes
 */
AMVP_RESULT amvp_network_action(AMVP_CTX *ctx, AMVP_NET_ACTION action,
                                       const char *url, const char *data, int data_len);


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

    AMVP_LOG_DEBUG("\nHTTP GET RSP:\n\n%s\n", ctx->curl_buf);
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
    AMVP_LOG_DEBUG("\nHTTP POST RSP:\n\n%s\n", ctx->curl_buf);

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

    AMVP_LOG_DEBUG("\nHTTP PUT:\n\n%s\n", data);

    /*
     * Send the HTTP PUT request
     */
    crv = curl_easy_perform(hnd);
    if (crv != CURLE_OK) {
        AMVP_LOG_ERR("Curl failed with code %d (%s)", crv, curl_easy_strerror(crv));
    }

    AMVP_LOG_DEBUG("\nHTTP PUT RSP:\n\n%s\n", ctx->curl_buf);

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

    AMVP_LOG_DEBUG("\nHTTP DELETE: %s\n", url);

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

    AMVP_LOG_DEBUG("\nHTTP POST MULTIPART:\n\tURL: %s\n", url);

    /*
     * Send the HTTP POST request
     */
    crv = curl_easy_perform(hnd);
    if (crv != CURLE_OK) {
        AMVP_LOG_ERR("Curl failed with code %d (%s)", crv, curl_easy_strerror(crv));
    }

    AMVP_LOG_DEBUG("\nHTTP POST MULTIPART RSP:\n\n%s\n", ctx->curl_buf);

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

/* Helper functions for multipart file uploads via execute_network_action */
static long amvp_curl_http_post_multipart_file(AMVP_CTX *ctx, const char *url, const char *file_path) {
    CURL *temp_curl = NULL;
    curl_mime *mime = NULL;
    long http_code = 0;
    
    temp_curl = curl_easy_init();
    if (!temp_curl) return 0;
    
    mime = build_sp_template_request(temp_curl, file_path);
    if (!mime) {
        curl_easy_cleanup(temp_curl);
        return 0;
    }
    
    http_code = amvp_curl_http_post_multipart(ctx, url, mime);
    
    curl_mime_free(mime);
    curl_easy_cleanup(temp_curl);
    return http_code;
}

AMVP_RESULT execute_network_action(AMVP_CTX *ctx,
                                          AMVP_NET_ACTION action,
                                          const char *url,
                                          const char *data,
                                          int data_len,
                                          int *curl_code) {
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

    case AMVP_NET_POST_MULTIPART:
        /* For multipart, data contains the file path */
        rc = amvp_curl_http_post_multipart_file(ctx, url, data);
        break;

    default:
        AMVP_LOG_ERR("Unknown AMVP_NET_ACTION");
        return AMVP_INVALID_ARG;
    }

    *curl_code = rc;
    return AMVP_SUCCESS;
}
