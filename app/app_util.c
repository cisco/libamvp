/*
 * Copyright (c) 2025, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libamvp/LICENSE
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "app_lcl.h"
#include "amvp/amvp.h"
#include "amvp/parson.h"
#include "safe_lib.h"



/*
 * Load certification configuration from JSON file
 * The config file path is determined by CLI argument (takes precedence) or environment variable
 */
AMVP_RESULT load_cert_config(APP_CONFIG *cfg) {
    JSON_Value *val = NULL;
    JSON_Object *obj = NULL;
    JSON_Array *array = NULL;
    const char *config_path = NULL;
    const char *tester = NULL;
    const char *reviewer = NULL;
    const char *cert = NULL;
    double vendor_num = 0.0;
    int vendor_id = 0;
    size_t i, count;
    AMVP_RESULT rv = AMVP_SUCCESS;

    /* Determine config file path: CLI argument takes precedence over env var */
    if (cfg->config_file[0] != '\0') {
        config_path = cfg->config_file;
    } else {
        config_path = getenv(AMVP_CONFIG_CERT_REQUEST_ENV);
        if (!config_path) {
            /* No config file specified - this is not an error if using pure CLI mode */
            return AMVP_SUCCESS;
        }
    }

    /* Load and parse the config file */
    val = json_parse_file(config_path);
    if (!val) {
        printf("Failed to load certification configuration file: %s\n", config_path);
        return AMVP_JSON_ERR;
    }

    obj = json_value_get_object(val);
    if (!obj) {
        printf("Invalid JSON format in certification configuration file: %s\n", config_path);
        rv = AMVP_JSON_ERR;
        goto cleanup;
    }

    /* Load vendor ID (only if not already set via CLI) */
    if (cfg->vendor_id == 0) {
        vendor_num = json_object_get_number(obj, "vendor");
        vendor_id = (int)vendor_num;
        if (vendor_id > 0) {
            cfg->vendor_id = vendor_id;
        }
    }

    /* Load testers */
    array = json_object_get_array(obj, "testers");
    if (array) {
        count = json_array_get_count(array);
        for (i = 0; i < count && cfg->num_testers < AMVP_MAX_CONTACTS_PER_CERT_REQ; i++) {
            tester = json_array_get_string(array, i);
            if (tester) {
                if (strnlen_s(tester, AMVP_CONTACT_STR_MAX_LEN + 1) > AMVP_CONTACT_STR_MAX_LEN) {
                    printf("Tester ID too long in config file\n");
                    rv = AMVP_INVALID_ARG;
                    goto cleanup;
                }

                strcpy_s(cfg->tester_ids[cfg->num_testers], AMVP_CONTACT_STR_MAX_LEN + 1, tester);
                cfg->num_testers++;
            }
        }
    }

    /* Load reviewers */
    array = json_object_get_array(obj, "reviewers");
    if (array) {
        count = json_array_get_count(array);
        for (i = 0; i < count && cfg->num_reviewers < AMVP_MAX_CONTACTS_PER_CERT_REQ; i++) {
            reviewer = json_array_get_string(array, i);
            if (reviewer) {
                if (strnlen_s(reviewer, AMVP_CONTACT_STR_MAX_LEN + 1) > AMVP_CONTACT_STR_MAX_LEN) {
                    printf("Reviewer ID too long in config file\n");
                    rv = AMVP_INVALID_ARG;
                    goto cleanup;
                }

                strcpy_s(cfg->reviewer_ids[cfg->num_reviewers], AMVP_CONTACT_STR_MAX_LEN + 1, reviewer);
                cfg->num_reviewers++;
            }
        }
    }

    /* Load ACV certificates */
    array = json_object_get_array(obj, "acvCerts");
    if (array) {
        count = json_array_get_count(array);
        for (i = 0; i < count && cfg->num_acv_certs < AMVP_MAX_ACV_CERTS_PER_CERT_REQ; i++) {
            cert = json_array_get_string(array, i);
            if (cert) {
                if (strnlen_s(cert, AMVP_CERT_STR_MAX_LEN + 1) > AMVP_CERT_STR_MAX_LEN) {
                    printf("ACV certificate ID too long in config file\n");
                    rv = AMVP_INVALID_ARG;
                    goto cleanup;
                }

                strcpy_s(cfg->acv_certs[cfg->num_acv_certs], AMVP_CERT_STR_MAX_LEN + 1, cert);
                cfg->num_acv_certs++;
            }
        }
    }

    /* Load ESV certificates */
    array = json_object_get_array(obj, "esvCerts");
    if (array) {
        count = json_array_get_count(array);
        for (i = 0; i < count && cfg->num_esv_certs < AMVP_MAX_ESV_CERTS_PER_CERT_REQ; i++) {
            cert = json_array_get_string(array, i);
            if (cert) {
                if (strnlen_s(cert, AMVP_CERT_STR_MAX_LEN + 1) > AMVP_CERT_STR_MAX_LEN) {
                    printf("ESV certificate ID too long in config file\n");
                    rv = AMVP_INVALID_ARG;
                    goto cleanup;
                }

                strcpy_s(cfg->esv_certs[cfg->num_esv_certs], AMVP_CERT_STR_MAX_LEN + 1, cert);
                cfg->num_esv_certs++;
            }
        }
    }

    printf("Loaded certification configuration from: %s\n", config_path);

cleanup:
    if (val) json_value_free(val);
    return rv;
}

/* App logging function - mirrors progress() but with amvp_app prefix */
AMVP_RESULT app_logger(char *msg, AMVP_LOG_LVL level) {

    printf("[AMVP_APP]");

    switch (level) {
    case AMVP_LOG_LVL_ERR:
        printf(ANSI_COLOR_RED "[ERROR]" ANSI_COLOR_RESET);
        break;
    case AMVP_LOG_LVL_WARN:
        printf(ANSI_COLOR_YELLOW "[WARNING]" ANSI_COLOR_RESET);
        break;
    case AMVP_LOG_LVL_STATUS:
    case AMVP_LOG_LVL_INFO:
    case AMVP_LOG_LVL_VERBOSE:
    case AMVP_LOG_LVL_DEBUG:
    case AMVP_LOG_LVL_NONE:
    case AMVP_LOG_LVL_MAX:
    default:
        break;
    }

    printf(": %s\n", msg);

    return AMVP_SUCCESS;
}
