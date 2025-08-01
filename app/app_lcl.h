/*
 * Copyright (c) 2023, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libamvp/LICENSE
 */

#ifndef LIBAMVP_APP_LCL_H
#define LIBAMVP_APP_LCL_H

#ifdef __cplusplus
extern "C"
{
#endif
#include <openssl/evp.h>
#include "amvp/amvp.h"

/* MACROS */
#define DEFAULT_SERVER "127.0.0.1"
#define DEFAULT_SERVER_LEN 9
#define DEFAULT_PORT 443
#define DEFAULT_URI_PREFIX "/amvp/v1/"
#define JSON_FILENAME_LENGTH 128
#define JSON_STRING_LENGTH 32
#define JSON_REQUEST_LENGTH 128
#define ALG_STR_MAX_LEN 256 /* arbitrary */

#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_RESET "\x1b[0m"

typedef struct app_config {
    AMVP_LOG_LVL level;
    int get;
    int post;
    int put;
    int delete;
    int fips_validation;
    int save_to;
    char get_string[JSON_REQUEST_LENGTH + 1];
    char post_filename[JSON_FILENAME_LENGTH + 1];
    char put_filename[JSON_FILENAME_LENGTH + 1];
    char delete_url[JSON_REQUEST_LENGTH + 1];
    char validation_metadata_file[JSON_FILENAME_LENGTH + 1];
    char save_file[JSON_FILENAME_LENGTH + 1];
    char mod_cert_req_file[JSON_FILENAME_LENGTH + 1];
    char create_module_file[JSON_FILENAME_LENGTH + 1];
    char ev_file[JSON_FILENAME_LENGTH + 1];
    char sp_file[JSON_FILENAME_LENGTH + 1];
    char contact_ids[AMVP_MAX_CONTACTS_PER_CERT_REQ][AMVP_CONTACT_STR_MAX_LEN + 1];
    char acv_certs[AMVP_MAX_ACV_CERTS_PER_CERT_REQ][AMVP_CERT_STR_MAX_LEN + 1];
    char esv_certs[AMVP_MAX_ESV_CERTS_PER_CERT_REQ][AMVP_CERT_STR_MAX_LEN + 1];

    int num_contacts;
    int num_acv_certs;
    int num_esv_certs;
    int mod_cert_req;
    int ingest_cert_info;
    int submit_ft_ev;
    int submit_sc_ev;
    int submit_sp;
    int get_sp;
    int finalize;
    int check_status;
    int vendor_id;
} APP_CONFIG;


int ingest_cli(APP_CONFIG *cfg, int argc, char **argv);
int app_setup_two_factor_auth(AMVP_CTX *ctx);

#ifdef __cplusplus
}
#endif

#endif // LIBAMVP_APP_LCL_H

