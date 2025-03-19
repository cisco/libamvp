/*
 * Copyright (c) 2023, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libamvp/LICENSE
 */

/*
 * This module is not part of libamvp.  Rather, it's a simple app that
 * demonstrates how to use libamvp. Software that use libamvp
 * will need to implement a similar module.
 *
 * It will default to 127.0.0.1 port 443 if no arguments are given.
 */
#include <stdio.h>

#include "app_lcl.h"

#include "safe_mem_lib.h"
#include "safe_str_lib.h"

//static int enable_hash(AMVP_CTX *ctx);

const char *server;
int port;
const char *ca_chain_file;
char *cert_file;
char *key_file;
const char *path_segment;
char value[JSON_STRING_LENGTH] = "same";

#define CHECK_ENABLE_CAP_RV(rv) \
    if (rv != AMVP_SUCCESS) { \
        printf("Failed to register capability with libamvp (rv=%d: %s)\n", rv, amvp_lookup_error_string(rv)); \
        goto end; \
    }

/*
 * Read the operational parameters from the various environment
 * variables.
 */
static void setup_session_parameters(void) {
    char *tmp;

    server = getenv("AMV_SERVER");
    if (!server) {
         server = DEFAULT_SERVER;
     }

    tmp = getenv("AMV_PORT");
    if (tmp) port = atoi(tmp);
    if (!port) port = DEFAULT_PORT;

    path_segment = getenv("AMV_URI_PREFIX");
    if (!path_segment) path_segment = DEFAULT_URI_PREFIX;

    ca_chain_file = getenv("AMV_CA_FILE");
    cert_file = getenv("AMV_CERT_FILE");
    key_file = getenv("AMV_KEY_FILE");

    printf("Using the following parameters:\n\n");
  //  printf("    AMV_SERVER:     %s\n", server);
    printf("    AMV_SERVER:     [Redacted for demo]\n");
    printf("    AMV_PORT:       %d\n", port);
    printf("    AMV_URI_PREFIX: %s\n", path_segment);
    if (ca_chain_file) printf("    AMV_CA_FILE:    [Redacted for demo]\n");
    if (cert_file) printf("    AMV_CERT_FILE:  [Redacted for demo]\n");
    if (key_file) printf("    AMV_KEY_FILE:   [Redacted for demo]\n");
    printf("\n");
}

/* libamvp calls this function for status updates, debugs, warnings, and errors. */
static AMVP_RESULT progress(char *msg, AMVP_LOG_LVL level) {

    printf("[AMVP]");

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

static void app_cleanup(AMVP_CTX *ctx) {
    // Routines for libamvp
    amvp_cleanup(ctx);
}


int main(int argc, char **argv) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    AMVP_CTX *ctx = NULL;
    APP_CONFIG cfg;
    int diff = 0;

    memset_s(&cfg, sizeof(APP_CONFIG), 0, sizeof(APP_CONFIG));
    if (ingest_cli(&cfg, argc, argv)) {
        return 1;
    }


     setup_session_parameters();

    /*
     * We begin the libamvp usage flow here.
     * First, we create a test session context.
     */
    rv = amvp_create_test_session(&ctx, &progress, cfg.level);
    if (rv != AMVP_SUCCESS) {
        printf("Failed to create AMVP context: %s\n", amvp_lookup_error_string(rv));
        goto end;
    }

    /* Next we specify the AMVP server address */
    rv = amvp_set_server(ctx, server, port);
    if (rv != AMVP_SUCCESS) {
        printf("Failed to set server/port\n");
        goto end;
    }

    /* Set the path segment prefix if needed */
    rv = amvp_set_path_segment(ctx, path_segment);
    if (rv != AMVP_SUCCESS) {
        printf("Failed to set URI prefix\n");
        goto end;
    }

    if (ca_chain_file) {
        /*
         * Next we provide the CA certs to be used by libamvp
         * to verify the AMVP TLS certificate.
         */
        rv = amvp_set_cacerts(ctx, ca_chain_file);
        if (rv != AMVP_SUCCESS) {
            printf("Failed to set CA certs\n");
            goto end;
        }
    }

    if (cert_file && key_file) {
        /*
         * Specify the certificate and private key the client should used
         * for TLS client auth.
         */
        rv = amvp_set_certkey(ctx, cert_file, key_file);
        if (rv != AMVP_SUCCESS) {
            printf("Failed to set TLS cert/key\n");
            goto end;
        }
    }

    /*
     * Setup the Two-factor authentication
     * This may or may not be turned on...
     */
    if (app_setup_two_factor_auth(ctx)) {
        printf("Error setting  up two factor auth\n");
        goto end;
    }

    if (cfg.get) {
        rv = amvp_mark_as_get_only(ctx, cfg.get_string);
        if (rv != AMVP_SUCCESS) {
            printf("Failed to mark as get only.\n");
            goto end;
        } else if (cfg.save_to) {
            rv = amvp_set_get_save_file(ctx, cfg.save_file);
            if (rv != AMVP_SUCCESS) {
                printf("Failed to set save file for get request, continuing anyway...\n");
            }
        }
    }

    if (cfg.delete) {
        amvp_mark_as_delete_only(ctx, cfg.delete_url);
    }

    if (cfg.vector_req && !cfg.vector_rsp) {
        amvp_mark_as_request_only(ctx, cfg.vector_req_file);
    }

    if (!cfg.vector_req && cfg.vector_rsp) {
        printf("Offline vector processing requires both options, --vector_req and --vector_rsp\n");
        goto end;
    }

    strncmp_s(DEFAULT_SERVER, DEFAULT_SERVER_LEN, server, DEFAULT_SERVER_LEN, &diff);
    if (!diff) {
         printf("Warning: No server set, using default. Please define AMV_SERVER in your environment.\n");
         printf("Run amvp_app --help for more information on this and other environment variables.\n\n");
    }

    if (cfg.fips_validation) {
        unsigned int module_id = 1, oe_id = 1;

        /* Provide the metadata needed for a FIPS validation. */
        rv = amvp_oe_ingest_metadata(ctx, cfg.validation_metadata_file);
        if (rv != AMVP_SUCCESS) {
            printf("Failed to read validation_metadata_file\n");
            goto end;
        }

        /*
         * Tell the library which Module and Operating Environment to use
         * when doing the FIPS validation.
         */
        rv = amvp_oe_set_fips_validation_metadata(ctx, module_id, oe_id);
        if (rv != AMVP_SUCCESS) {
            printf("Failed to set metadata for FIPS validation\n");
            goto end;
        }
    }

    if (cfg.cancel_session) {
        if (cfg.save_to) {
            rv = amvp_cancel_test_session(ctx, cfg.session_file, cfg.save_file);
        } else {
            rv = amvp_cancel_test_session(ctx, cfg.session_file, NULL);
        }
        goto end;
    }

    if (cfg.post_resources) {
        rv = amvp_mark_as_post_resources(ctx, cfg.post_resources_filename);
    }

    if (cfg.mod_cert_req) {
        rv = amvp_mark_as_cert_req(ctx, cfg.module_id, cfg.vendor_id);
        for (diff = 0; diff < cfg.num_contacts; diff++) {
            amvp_cert_req_add_contact(ctx, cfg.contact_ids[diff]);
        }

        for (diff = 0; diff < cfg.num_acv_certs; diff++) {
            amvp_cert_req_add_sub_cert(ctx, cfg.acv_certs[diff], AMVP_CERT_TYPE_ACV);
        }

        for (diff = 0; diff < cfg.num_esv_certs; diff++) {
            amvp_cert_req_add_sub_cert(ctx, cfg.esv_certs[diff], AMVP_CERT_TYPE_ESV);
        }
    }

    if (cfg.create_module) {
        rv = amvp_create_module(ctx, cfg.create_module_file);
        goto end;
    }

    if (cfg.get_module) {
        rv = amvp_get_module_request(ctx, cfg.get_module_file);
        goto end;
    }

    if (cfg.ingest_cert_info) {
        rv = amvp_read_cert_req_info_file(ctx, cfg.mod_cert_req_file);
        if (rv != AMVP_SUCCESS) {
            printf("Error reading cert request info file; ensure it exists and is properly formatted\n");
            goto end;
        }
        if (cfg.submit_ft_ev) {
            rv = amvp_submit_evidence(ctx, cfg.ev_file, AMVP_EVIDENCE_TYPE_FUNCTIONAL_TEST);
            if (rv != AMVP_SUCCESS) {
                printf("Error submitting functional evidence for module cert request\n");
                goto end;
            }
        }
        if (cfg.submit_sc_ev) {
            rv = amvp_submit_evidence(ctx, cfg.ev_file, AMVP_EVIDENCE_TYPE_SOURCE_CODE);
            if (rv != AMVP_SUCCESS) {
                printf("Error submitting source code evidence for module cert request\n");
                goto end;
            }
        }
        if (cfg.submit_sp) {
            rv = amvp_submit_security_policy(ctx, cfg.sp_file);
            if (rv != AMVP_SUCCESS) {
                printf("Error submitting security policy for module cert request\n");
                goto end;
            }
        }
        if (cfg.get_sp) {
            if (!cfg.save_to) {
                printf("Error: Must use --save_to <file> to get security policy\n");
            } else {
                rv = amvp_set_get_save_file(ctx, cfg.save_file);
                if (rv != AMVP_SUCCESS) {
                    printf("Failed to set save file for getting security policy\n");
                    goto end;
                }
                rv = amvp_get_security_policy(ctx);
                if (rv != AMVP_SUCCESS) {
                    printf("Unable to retrieve generated security policy\n");
                    goto end;
                }
            }
        }
        if (cfg.finalize) {
            amvp_finalize_cert_request(ctx);
            goto end;
        }
        goto end;
    }

    /*
     * Run the test session.
     * Perform a FIPS validation on this test session if specified.
     */
    amvp_run(ctx, cfg.fips_validation);

end:
    /*
     * Free all memory associated with
     * both the application and libamvp.
     */
    app_cleanup(ctx);

    return rv;
}
