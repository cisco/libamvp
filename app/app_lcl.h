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

#define APP_SCHEMA_VERSION_MAX_LEN 32

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
    char save_file[JSON_FILENAME_LENGTH + 1];
    char mod_cert_req_file[JSON_FILENAME_LENGTH + 1];
    char create_module_file[JSON_FILENAME_LENGTH + 1];
    char ev_file[JSON_FILENAME_LENGTH + 1];
    char sp_file[JSON_FILENAME_LENGTH + 1];
    char sp_template_file[JSON_FILENAME_LENGTH + 1];

    int mod_cert_req;
    int ingest_cert_info;
    int submit_ev;
    int submit_sp;
    int submit_sp_template;
    int get_sp;
    int finalize;
    int check_status;
    int get_schema;
    AMVP_SCHEMA_TYPE schema_type;
    char schema_version[APP_SCHEMA_VERSION_MAX_LEN + 1];
} APP_CONFIG;

int ingest_cli(APP_CONFIG *cfg, int argc, char **argv);
AMVP_RESULT totp(char **token, int token_max);

#ifdef __cplusplus
}
#endif

#endif // LIBAMVP_APP_LCL_H

