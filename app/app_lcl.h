/*
 * Copyright (c) 2025, Cisco Systems, Inc.
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
#include "amvp/amvp.h"

/* MACROS */
#define DEFAULT_SERVER "127.0.0.1"
#define DEFAULT_SERVER_LEN 9
#define DEFAULT_PORT 443
#define JSON_FILENAME_LENGTH 128
#define JSON_REQUEST_LENGTH 128

#define AMVP_CONFIG_CERT_REQUEST_ENV "AMVP_CONFIG_CERT_REQUEST"

#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_RESET "\x1b[0m"

typedef struct app_config {
    AMVP_LOG_LVL level;
    int get;
    int delete;
    int save_to;
    char get_string[JSON_REQUEST_LENGTH + 1];
    char delete_url[JSON_REQUEST_LENGTH + 1];
    char validation_metadata_file[JSON_FILENAME_LENGTH + 1];
    char save_file[JSON_FILENAME_LENGTH + 1];
    char mod_cert_req_file[JSON_FILENAME_LENGTH + 1];
    char create_module_file[JSON_FILENAME_LENGTH + 1];
    char ev_file[JSON_FILENAME_LENGTH + 1];
    char sp_file[JSON_FILENAME_LENGTH + 1];
    char sp_template_file[JSON_FILENAME_LENGTH + 1];
    char config_file[JSON_FILENAME_LENGTH + 1];
    char tester_ids[AMVP_MAX_CONTACTS_PER_CERT_REQ][AMVP_CONTACT_STR_MAX_LEN + 1];
    char reviewer_ids[AMVP_MAX_CONTACTS_PER_CERT_REQ][AMVP_CONTACT_STR_MAX_LEN + 1];
    char acv_certs[AMVP_MAX_ACV_CERTS_PER_CERT_REQ][AMVP_CERT_STR_MAX_LEN + 1];
    char esv_certs[AMVP_MAX_ESV_CERTS_PER_CERT_REQ][AMVP_CERT_STR_MAX_LEN + 1];

    int num_testers;
    int num_reviewers;
    int num_acv_certs;
    int num_esv_certs;
    int mod_cert_req;
    int ingest_cert_info;
    int submit_ev;
    int submit_sp;
    int submit_sp_template;
    int get_sp;
    int finalize;
    int check_status;
    int vendor_id;
} APP_CONFIG;


int ingest_cli(APP_CONFIG *cfg, int argc, char **argv);
AMVP_RESULT load_cert_config(APP_CONFIG *cfg);
AMVP_RESULT app_logger(char *msg, AMVP_LOG_LVL level);
AMVP_RESULT totp(char **token, int token_max);



#ifdef __cplusplus
}
#endif

#endif // LIBAMVP_APP_LCL_H

