/*
 * Copyright (c) 2021, Cisco Systems, Inc.
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
#include <openssl/rsa.h>
#include <openssl/bn.h>

#include "app_lcl.h"

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#include <openssl/evp.h>
#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif
#endif

#include "safe_mem_lib.h"
#include "safe_str_lib.h"

#if !defined OPENSSL_NO_DSA && OPENSSL_VERSION_NUMBER >= 0x30000000L
static int enable_dsa(AMVP_CTX *ctx);
static int enable_kas_ffc(AMVP_CTX *ctx);
static int enable_safe_primes(AMVP_CTX *ctx);
#endif
static int enable_aes(AMVP_CTX *ctx);
static int enable_tdes(AMVP_CTX *ctx);
static int enable_hash(AMVP_CTX *ctx);
static int enable_cmac(AMVP_CTX *ctx);
static int enable_hmac(AMVP_CTX *ctx);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static int enable_kmac(AMVP_CTX *ctx);
static int enable_rsa(AMVP_CTX *ctx);
static int enable_ecdsa(AMVP_CTX *ctx);
static int enable_drbg(AMVP_CTX *ctx);
static int enable_kas_ecc(AMVP_CTX *ctx);
static int enable_kas_ifc(AMVP_CTX *ctx);
static int enable_kda(AMVP_CTX *ctx);
static int enable_kts_ifc(AMVP_CTX *ctx);
static int enable_kdf(AMVP_CTX *ctx);
#endif

const char *server;
int port;
const char *ca_chain_file;
char *cert_file;
char *key_file;
const char *path_segment;
const char *api_context;
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

    server = getenv("ACV_SERVER");
    if (!server) {
         server = DEFAULT_SERVER;
     }

    tmp = getenv("ACV_PORT");
    if (tmp) port = atoi(tmp);
    if (!port) port = DEFAULT_PORT;

    path_segment = getenv("ACV_URI_PREFIX");
    if (!path_segment) path_segment = DEFAULT_URI_PREFIX;

    api_context = getenv("ACV_API_CONTEXT");
    if (!api_context) api_context = "";

    ca_chain_file = getenv("ACV_CA_FILE");
    cert_file = getenv("ACV_CERT_FILE");
    key_file = getenv("ACV_KEY_FILE");

    printf("Using the following parameters:\n\n");
    printf("    ACV_SERVER:     %s\n", server);
    printf("    ACV_PORT:       %d\n", port);
    printf("    ACV_URI_PREFIX: %s\n", path_segment);
    if (ca_chain_file) printf("    ACV_CA_FILE:    %s\n", ca_chain_file);
    if (cert_file) printf("    ACV_CERT_FILE:  %s\n", cert_file);
    if (key_file) printf("    ACV_KEY_FILE:   %s\n", key_file);
    printf("\n");
}

#define CHECK_NON_ALLOWED_ALG(enabled, str) \
    if (enabled != 0) { \
        printf("%s\n", str); \
        rv = 0; \
    }

static int verify_algorithms(APP_CONFIG *cfg) {
    int rv = 1;

    if (!cfg) {
        return 0;
    }

    /* If we are testing "all" then we don't need to tell the user they can't test algs */
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    if (!cfg->testall) {
        CHECK_NON_ALLOWED_ALG(cfg->dsa, "This version of OpenSSL does not support DSA testing");
        CHECK_NON_ALLOWED_ALG(cfg->rsa, "This version of OpenSSL does not support RSA testing");
        CHECK_NON_ALLOWED_ALG(cfg->drbg, "This version of OpenSSL does not support DRBG testing");
        CHECK_NON_ALLOWED_ALG(cfg->ecdsa, "This version of OpenSSL does not support ECDSA testing");
        CHECK_NON_ALLOWED_ALG(cfg->kas_ecc, "This version of OpenSSL does not support KAS-ECC testing");
        CHECK_NON_ALLOWED_ALG(cfg->kas_ffc, "This version of OpenSSL does not support KAS-FFC testing");
        CHECK_NON_ALLOWED_ALG(cfg->kas_ifc, "This version of OpenSSL does not support KAS-IFC testing");
        CHECK_NON_ALLOWED_ALG(cfg->kda, "This version of OpenSSL does not support KDA testing");
        CHECK_NON_ALLOWED_ALG(cfg->kts_ifc, "This version of OpenSSL does not support KTS-IFC testing");
        CHECK_NON_ALLOWED_ALG(cfg->kdf, "This version of OpenSSL does not support KDF testing");
        CHECK_NON_ALLOWED_ALG(cfg->safe_primes, "This version of OpenSSL does not support safe primes testing");
    }
#endif
#ifdef OPENSSL_NO_DSA
    if (!cfg->testall) {
        CHECK_NON_ALLOWED_ALG(cfg->dsa, "This version of OpenSSL does not support DSA testing (DSA disabled)");
        CHECK_NON_ALLOWED_ALG(cfg->kas_ffc, "This version of OpenSSL does not support KAS-FFC testing (DSA disabled)");
        CHECK_NON_ALLOWED_ALG(cfg->safe_primes, "This version of OpenSSL does not support safe primes testing");
    }
#endif

    return rv;
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

    // Routines for this application
    app_aes_cleanup();
    app_des_cleanup();
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#ifndef OPENSSL_NO_DSA
    app_dsa_cleanup();
#endif
    app_rsa_cleanup();
    app_ecdsa_cleanup();
#endif
}

#ifndef AMVP_APP_LIB_WRAPPER
int main(int argc, char **argv) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    AMVP_CTX *ctx = NULL;
    APP_CONFIG cfg;
    int diff = 0;

    memset_s(&cfg, sizeof(APP_CONFIG), 0, sizeof(APP_CONFIG));
    if (ingest_cli(&cfg, argc, argv)) {
        return 1;
    }

    if (!verify_algorithms(&cfg)) {
        printf("\nAlgorithm tests not supported by this crypto module have been requested. Please \n");
        printf("verify your testing capablities and try again.\n");
        return 1;
    }

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (!cfg.disable_fips) {
        /* sets the property "fips=yes" to be included implicitly in cipher fetches */
        EVP_default_properties_enable_fips(NULL, 1);
        if (!EVP_default_properties_is_fips_enabled(NULL)) {
            printf("Error setting FIPS property at startup\n\n");
            return 1;
        }
        /* Run a quick sanity check to determine that the FIPS provider is functioning properly */
        rv = fips_sanity_check();
        if (rv != AMVP_SUCCESS) {
            printf("Error occured when testing FIPS at startup (rv = %d). Please verify the FIPS provider is\n", rv);
            printf("properly installed and configured. Exiting...\n\n");
            return 1;
        }
    } else {
        printf("***********************************************************************************\n");
        printf("* WARNING: You have chosen to not fetch the FIPS provider for this run. Any tests *\n");
        printf("* created or performed during this run MUST NOT have any validation requested     *\n");
        printf("* on it unless the FIPS provider is exclusively loaded or enabled by default in   *\n");
        printf("* your configuration. Proceed at your own risk. Continuing in 5 seconds...        *\n");
        printf("***********************************************************************************\n");
        printf("\n");
        #ifdef _WIN32
            Sleep(5 * 1000);
        #else
            sleep(5);
        #endif
    }
#endif

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

    /* Set the api context prefix if needed */
    rv = amvp_set_api_context(ctx, api_context);
    if (rv != AMVP_SUCCESS) {
        printf("Failed to set URI prefix\n");
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
        goto end;
    }

    if (cfg.sample) {
        amvp_mark_as_sample(ctx);
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

    if (cfg.post) {
        amvp_mark_as_post_only(ctx, cfg.post_filename);
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

    if (cfg.manual_reg) {
        /*
         * Using a JSON to register allows us to skip the
         * "amvp_enable_*" API calls... could reduce the
         * size of this file if you choose to use this capability.
         */
        rv = amvp_set_json_filename(ctx, cfg.reg_file);
        if (rv != AMVP_SUCCESS) {
            printf("Failed to set json file within AMVP ctx (rv=%d)\n", rv);
            goto end;
        }
    } else {
        /*
         * We need to register all the crypto module capabilities that will be
         * validated. Each has their own method for readability.
         */
        if (cfg.aes) { if (enable_aes(ctx)) goto end; }
        if (cfg.tdes) { if (enable_tdes(ctx)) goto end; }
        if (cfg.hash) { if (enable_hash(ctx)) goto end; }
        if (cfg.cmac) { if (enable_cmac(ctx)) goto end; }
        if (cfg.hmac) { if (enable_hmac(ctx)) goto end; }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        if (cfg.kmac) { if (enable_kmac(ctx)) goto end; }
        if (cfg.kdf) { if (enable_kdf(ctx)) goto end; }
        if (cfg.rsa) { if (enable_rsa(ctx)) goto end; }
        if (cfg.ecdsa) { if (enable_ecdsa(ctx)) goto end; }
        if (cfg.drbg) { if (enable_drbg(ctx)) goto end; }
        if (cfg.kas_ecc) { if (enable_kas_ecc(ctx)) goto end; }
        if (cfg.kas_ifc) { if (enable_kas_ifc(ctx)) goto end; }
        if (cfg.kts_ifc) { if (enable_kts_ifc(ctx)) goto end; }
        if (cfg.kda) { if (enable_kda(ctx)) goto end; }
#ifndef OPENSSL_NO_DSA
        if (cfg.dsa) { if (enable_dsa(ctx)) goto end; }
        if (cfg.kas_ffc) { if (enable_kas_ffc(ctx)) goto end; }
        if (cfg.safe_primes) { if (enable_safe_primes(ctx)) goto end; }
#endif
#endif
    }

    if (cfg.get_cost) {
        diff = amvp_get_vector_set_count(ctx);
        if (diff < 0) {
            printf("Unable to get expected vector set count with given test session context.\n\n");
        } else {
            printf("The given test session context is expected to generate %d vector sets.\n\n", diff);
        }
        goto end;
    }

    if (cfg.get_reg) {
        char *reg = NULL;
        reg = amvp_get_current_registration(ctx, NULL);
        if (!reg) {
            printf("Error occured while getting current registration.\n");
            goto end;
        }
        if (cfg.save_to) {
            if (save_string_to_file((const char *)reg, (const char *)&cfg.save_file)) {
                printf("Error occured while saving registration to file. Exiting...\n");
            } else {
                printf("Succesfully saved registration to given file. Exiting...\n");
            }
        } else {
            printf("%s\n", reg);
            printf("Completed output of current registration. Exiting...\n");
        }
        if (reg) free(reg);
        goto end;
    }

    if (cfg.kat) {
       rv = amvp_load_kat_filename(ctx, cfg.kat_file);
       goto end;
    }

    if (cfg.vector_req && cfg.vector_rsp) {
       rv = amvp_run_vectors_from_file(ctx, cfg.vector_req_file, cfg.vector_rsp_file);
       goto end;
    }

    strncmp_s(DEFAULT_SERVER, DEFAULT_SERVER_LEN, server, DEFAULT_SERVER_LEN, &diff);
    if (!diff) {
         printf("Warning: No server set, using default. Please define ACV_SERVER in your environment.\n");
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

    if (cfg.vector_upload) {
       rv = amvp_upload_vectors_from_file(ctx, cfg.vector_upload_file, cfg.fips_validation);
       goto end;
    }

    /* PUT without algorithms submits put_filename for validation using save JWT and testSession ID */
    if (cfg.empty_alg && cfg.put) {
         rv = amvp_put_data_from_file(ctx, cfg.put_filename);
         goto end;
    }
    /* PUT with alg testing will submit put_filename with module/oe information */
    if (!cfg.empty_alg && cfg.put) {
        amvp_mark_as_put_after_test(ctx, cfg.put_filename);
    }
    
    if (cfg.get_results) {
        rv = amvp_get_results_from_server(ctx, cfg.session_file);
        goto end;
    }
    
    if (cfg.resume_session) {
        rv = amvp_resume_test_session(ctx, cfg.session_file, cfg.fips_validation);
        goto end;
    }

    if (cfg.cancel_session) {
        if (cfg.save_to) {
            rv = amvp_cancel_test_session(ctx, cfg.session_file, cfg.save_file);
        } else {
            rv = amvp_cancel_test_session(ctx, cfg.session_file, NULL);
        }
        goto end;
    }

    if (cfg.get_expected) {
        if (cfg.save_to) {
            rv = amvp_get_expected_results(ctx, cfg.session_file, cfg.save_file);
        } else {
            rv = amvp_get_expected_results(ctx, cfg.session_file, NULL);
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
#endif

static int enable_aes(AMVP_CTX *ctx) {
    AMVP_RESULT rv = AMVP_SUCCESS;

    /* Enable AES_GCM */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_GCM, &app_aes_handler_aead);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_AES_GCM, AMVP_PREREQ_AES, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_AES_GCM, AMVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_PARM_IVGEN_SRC, AMVP_SYM_CIPH_IVGEN_SRC_EITHER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_domain(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_DOMAIN_IVLEN, 96, 1024, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_TAGLEN, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_TAGLEN, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_TAGLEN, 96);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_TAGLEN, 104);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_TAGLEN, 112);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_TAGLEN, 120);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_domain(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_DOMAIN_PTLEN, 8, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_domain(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_DOMAIN_AADLEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);
#else
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_PARM_IVGEN_SRC, AMVP_SYM_CIPH_IVGEN_SRC_INT);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_IVLEN, 96);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_domain(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_DOMAIN_PTLEN, 0, 65536, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_domain(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_DOMAIN_AADLEN, 0, 65536, 256);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_TAGLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_PARM_IVGEN_MODE, AMVP_SYM_CIPH_IVGEN_MODE_821);
    CHECK_ENABLE_CAP_RV(rv);

    /* Enable AES-ECB 128,192,256 bit key */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_ECB, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_ECB, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_ECB, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_ECB, AMVP_SYM_CIPH_PARM_IVGEN_SRC, AMVP_SYM_CIPH_IVGEN_SRC_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_ECB, AMVP_SYM_CIPH_PARM_IVGEN_MODE, AMVP_SYM_CIPH_IVGEN_MODE_NA);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_ECB, AMVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_ECB, AMVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_ECB, AMVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);

    /* Enable AES-CBC 128 bit key */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_CBC, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC, AMVP_SYM_CIPH_PARM_IVGEN_SRC, AMVP_SYM_CIPH_IVGEN_SRC_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC, AMVP_SYM_CIPH_PARM_IVGEN_MODE, AMVP_SYM_CIPH_IVGEN_MODE_NA);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC, AMVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC, AMVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC, AMVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    /* Enable AES-CBC-CS1, CS2, and CS3 */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_CBC_CS1, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS1, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS1, AMVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS1, AMVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS1, AMVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_domain(ctx, AMVP_AES_CBC_CS1, AMVP_SYM_CIPH_DOMAIN_PTLEN, 128, 512, 8);
    CHECK_ENABLE_CAP_RV(rv);
    
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_CBC_CS2, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS2, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS2, AMVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS2, AMVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS2, AMVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_domain(ctx, AMVP_AES_CBC_CS2, AMVP_SYM_CIPH_DOMAIN_PTLEN, 128, 512, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_CBC_CS3, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS3, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS3, AMVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS3, AMVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS3, AMVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_domain(ctx, AMVP_AES_CBC_CS3, AMVP_SYM_CIPH_DOMAIN_PTLEN, 136, 512, 8);
    CHECK_ENABLE_CAP_RV(rv);
#endif

    /* Enable AES-CFB1 128,192,256 bit key */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_CFB1, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB1, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB1, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB1, AMVP_SYM_CIPH_PARM_IVGEN_SRC, AMVP_SYM_CIPH_IVGEN_SRC_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB1, AMVP_SYM_CIPH_PARM_IVGEN_MODE, AMVP_SYM_CIPH_IVGEN_MODE_NA);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB1, AMVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB1, AMVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB1, AMVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);

    /* Enable AES-CFB8 128,192,256 bit key */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_CFB8, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB8, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB8, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB8, AMVP_SYM_CIPH_PARM_IVGEN_SRC, AMVP_SYM_CIPH_IVGEN_SRC_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB8, AMVP_SYM_CIPH_PARM_IVGEN_MODE, AMVP_SYM_CIPH_IVGEN_MODE_NA);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB8, AMVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB8, AMVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB8, AMVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);

    /* Enable AES-CFB128 128,192,256 bit key */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_CFB128, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB128, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB128, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB128, AMVP_SYM_CIPH_PARM_IVGEN_SRC, AMVP_SYM_CIPH_IVGEN_SRC_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB128, AMVP_SYM_CIPH_PARM_IVGEN_MODE, AMVP_SYM_CIPH_IVGEN_MODE_NA);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB128, AMVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB128, AMVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB128, AMVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);

    /* Enable AES-OFB 128, 192, 256 bit key */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_OFB, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_OFB, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_OFB, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_OFB, AMVP_SYM_CIPH_PARM_IVGEN_SRC, AMVP_SYM_CIPH_IVGEN_SRC_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_OFB, AMVP_SYM_CIPH_PARM_IVGEN_MODE, AMVP_SYM_CIPH_IVGEN_MODE_NA);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_OFB, AMVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_OFB, AMVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_OFB, AMVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);

    /* Register AES CCM capabilities */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_CCM, &app_aes_handler_aead);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_AES_CCM, AMVP_PREREQ_AES, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CCM, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CCM, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CCM, AMVP_SYM_CIPH_PARM_IVGEN_SRC, AMVP_SYM_CIPH_IVGEN_SRC_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CCM, AMVP_SYM_CIPH_PARM_IVGEN_MODE, AMVP_SYM_CIPH_IVGEN_MODE_NA);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CCM, AMVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CCM, AMVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CCM, AMVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_domain(ctx, AMVP_AES_CCM, AMVP_SYM_CIPH_DOMAIN_PTLEN, 0, 256, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CCM, AMVP_SYM_CIPH_TAGLEN, 32);
    CHECK_ENABLE_CAP_RV(rv);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CCM, AMVP_SYM_CIPH_TAGLEN, 48);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CCM, AMVP_SYM_CIPH_TAGLEN, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CCM, AMVP_SYM_CIPH_TAGLEN, 80);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CCM, AMVP_SYM_CIPH_TAGLEN, 96);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CCM, AMVP_SYM_CIPH_TAGLEN, 112);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CCM, AMVP_SYM_CIPH_TAGLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_domain(ctx, AMVP_AES_CCM, AMVP_SYM_CIPH_DOMAIN_IVLEN, 56, 104, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_domain(ctx, AMVP_AES_CCM, AMVP_SYM_CIPH_DOMAIN_AADLEN, 0, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);

    /* AES-KW */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_KW, &app_aes_keywrap_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KW, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KW, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KW, AMVP_SYM_CIPH_PARM_IVGEN_SRC, AMVP_SYM_CIPH_IVGEN_SRC_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KW, AMVP_SYM_CIPH_PARM_IVGEN_MODE, AMVP_SYM_CIPH_IVGEN_MODE_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KW, AMVP_SYM_CIPH_KW_MODE, AMVP_SYM_KW_CIPHER);
    CHECK_ENABLE_CAP_RV(rv);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KW, AMVP_SYM_CIPH_KW_MODE, AMVP_SYM_KW_INVERSE);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_domain(ctx, AMVP_AES_KW, AMVP_SYM_CIPH_DOMAIN_PTLEN, 128, 524288, 128);
    CHECK_ENABLE_CAP_RV(rv);
#else
    rv = amvp_cap_sym_cipher_set_domain(ctx, AMVP_AES_KW, AMVP_SYM_CIPH_DOMAIN_PTLEN, 128, 65536, 64);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KW, AMVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KW, AMVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KW, AMVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L || defined OPENSSL_KWP
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_KWP, &app_aes_keywrap_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_KW_MODE, AMVP_SYM_KW_CIPHER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_KW_MODE, AMVP_SYM_KW_INVERSE);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_domain(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_DOMAIN_PTLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
#endif

    /* Enable AES-XTS 128 and 256 bit key */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_XTS, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XTS, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XTS, AMVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XTS, AMVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XTS, AMVP_SYM_CIPH_TWEAK, AMVP_SYM_CIPH_TWEAK_HEX);
    CHECK_ENABLE_CAP_RV(rv);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = amvp_cap_sym_cipher_set_domain(ctx, AMVP_AES_XTS, AMVP_SYM_CIPH_DOMAIN_PTLEN, 128, 65536, 128);
    CHECK_ENABLE_CAP_RV(rv);
#else
    rv = amvp_cap_sym_cipher_set_domain(ctx, AMVP_AES_XTS, AMVP_SYM_CIPH_DOMAIN_PTLEN, 256, 65536, 256);
    CHECK_ENABLE_CAP_RV(rv);
#endif
#if 0
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XTS, AMVP_SYM_CIPH_PARM_DULEN_MATCHES_PAYLOADLEN, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_domain(ctx, AMVP_AES_XTS, AMVP_SYM_CIPH_DOMAIN_DULEN, 256, 65536, 256);
    CHECK_ENABLE_CAP_RV(rv);
#endif

    /* Enable AES-CTR 128, 192, 256 bit key */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_CTR, &app_aes_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_NA);
    CHECK_ENABLE_CAP_RV(rv);

    //CTR_INCR and CTR_OVRFLW are ignored by server if PERFORM_CTR is false - can remove those calls if so
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_PARM_PERFORM_CTR, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_PARM_CTR_INCR, 1);
    CHECK_ENABLE_CAP_RV(rv);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_PARM_CTR_OVRFLW, 0);
    CHECK_ENABLE_CAP_RV(rv);
#else
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_PARM_CTR_OVRFLW, 1);
    CHECK_ENABLE_CAP_RV(rv);
#endif

#if 0 //Support for AES-CTR RFC3686 conformance
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_PARM_CONFORMANCE, AMVP_CONFORMANCE_RFC3686);
    CHECK_ENABLE_CAP_RV(rv);
    //if ivGen is internal, ensure generated IV's least significant 32 bits are 1
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_PARM_IVGEN_SRC, AMVP_SYM_CIPH_IVGEN_SRC_INT);
#endif
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_domain(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_DOMAIN_PTLEN, 8, 128, 8);
    CHECK_ENABLE_CAP_RV(rv);

    //GMAC
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_GMAC, &app_aes_handler_gmac);
#else
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_GMAC, &app_aes_handler_aead);
#endif
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_AES_GMAC, AMVP_PREREQ_AES, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_AES_GMAC, AMVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GMAC, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GMAC, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_NA);
    CHECK_ENABLE_CAP_RV(rv);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GMAC, AMVP_SYM_CIPH_PARM_IVGEN_SRC, AMVP_SYM_CIPH_IVGEN_SRC_EITHER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GMAC, AMVP_SYM_CIPH_TAGLEN, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GMAC, AMVP_SYM_CIPH_TAGLEN, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GMAC, AMVP_SYM_CIPH_TAGLEN, 96);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GMAC, AMVP_SYM_CIPH_TAGLEN, 104);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GMAC, AMVP_SYM_CIPH_TAGLEN, 112);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GMAC, AMVP_SYM_CIPH_TAGLEN, 120);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_domain(ctx, AMVP_AES_GMAC, AMVP_SYM_CIPH_DOMAIN_AADLEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);
#else
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GMAC, AMVP_SYM_CIPH_PARM_IVGEN_SRC, AMVP_SYM_CIPH_IVGEN_SRC_INT);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_domain(ctx, AMVP_AES_GMAC, AMVP_SYM_CIPH_DOMAIN_AADLEN, 256, 65536, 256);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GMAC, AMVP_SYM_CIPH_PARM_IVGEN_MODE, AMVP_SYM_CIPH_IVGEN_MODE_821);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GMAC, AMVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GMAC, AMVP_SYM_CIPH_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GMAC, AMVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GMAC, AMVP_SYM_CIPH_TAGLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GMAC, AMVP_SYM_CIPH_IVLEN, 96);
    CHECK_ENABLE_CAP_RV(rv);

#if 0 //not currently supported by openSSL
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_GCM_SIV, &app_aes_handler_aead);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_AES_GCM_SIV, AMVP_PREREQ_AES, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_AES_GCM_SIV, AMVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM_SIV, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM_SIV, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_NA);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM_SIV, AMVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM_SIV, AMVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_domain(ctx, AMVP_AES_GCM_SIV, AMVP_SYM_CIPH_DOMAIN_PTLEN, 0, 65536, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_domain(ctx, AMVP_AES_GCM_SIV, AMVP_SYM_CIPH_DOMAIN_AADLEN, 0, 65536, 256);
    CHECK_ENABLE_CAP_RV(rv);
#endif

#if 0 //AES-XPN not currently supported by openSSL
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_XPN, &app_aes_handler_aead);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_AES_XPN, AMVP_PREREQ_AES, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_AES_XPN, AMVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XPN, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XPN, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_NA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XPN, AMVP_SYM_CIPH_PARM_IVGEN_SRC, AMVP_SYM_CIPH_IVGEN_SRC_INT);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XPN, AMVP_SYM_CIPH_PARM_IVGEN_MODE, AMVP_SYM_CIPH_IVGEN_MODE_821);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XPN, AMVP_SYM_CIPH_PARM_SALT_SRC, AMVP_SYM_CIPH_SALT_SRC_EXT);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XPN, AMVP_SYM_CIPH_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XPN, AMVP_SYM_CIPH_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XPN, AMVP_SYM_CIPH_TAGLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_domain(ctx, AMVP_AES_XPN, AMVP_SYM_CIPH_DOMAIN_PTLEN, 0, 65536, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_domain(ctx, AMVP_AES_XPN, AMVP_SYM_CIPH_DOMAIN_AADLEN, 0, 65536, 256);
    CHECK_ENABLE_CAP_RV(rv);
#endif

end:

    return rv;
}

static int enable_tdes(AMVP_CTX *ctx) {
    AMVP_RESULT rv = AMVP_SUCCESS;

    /* Enable 3DES-ECB */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_TDES_ECB, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_TDES_ECB, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_TDES_ECB, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_ONE);
    CHECK_ENABLE_CAP_RV(rv);

    /* Enable 3DES-CBC */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_TDES_CBC, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_TDES_CBC, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_TDES_CBC, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_ONE);
    CHECK_ENABLE_CAP_RV(rv);

#if 0
    /* Enable 3DES-CBCI */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_TDES_CBCI, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_TDES_CBCI, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_TDES_CBCI, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_ONE);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_TDES_OFBI, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_TDES_OFBI, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_TDES_OFBI, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_ONE);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_TDES_CFBP1, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_TDES_CFBP1, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_TDES_CFBP1, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_ONE);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_TDES_CFBP8, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_TDES_CFBP8, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_TDES_CFBP8, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_ONE);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_TDES_CFBP64, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_TDES_CFBP64, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_TDES_CFBP64, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_ONE);
    CHECK_ENABLE_CAP_RV(rv);
#endif

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    /* Enable 3DES-OFB */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_TDES_OFB, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_TDES_OFB, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_TDES_OFB, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_ONE);
    CHECK_ENABLE_CAP_RV(rv);

    /* Enable 3DES-CFB64 */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_TDES_CFB64, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_TDES_CFB64, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_TDES_CFB64, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_ONE);
    CHECK_ENABLE_CAP_RV(rv);

    /* Enable 3DES-CFB8 */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_TDES_CFB8, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_TDES_CFB8, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_TDES_CFB8, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_ONE);
    CHECK_ENABLE_CAP_RV(rv);

    /* Enable 3DES-CFB1 */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_TDES_CFB1, &app_des_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_TDES_CFB1, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_TDES_CFB1, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_ONE);
    CHECK_ENABLE_CAP_RV(rv);
#endif

end:
    return rv;
}

static int enable_hash(AMVP_CTX *ctx) {
    AMVP_RESULT rv = AMVP_SUCCESS;

    /* Enable SHA-1 and SHA-2 */
    rv = amvp_cap_hash_enable(ctx, AMVP_HASH_SHA1, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hash_set_domain(ctx, AMVP_HASH_SHA1, AMVP_HASH_MESSAGE_LEN,
                                  0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_hash_enable(ctx, AMVP_HASH_SHA224, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hash_set_domain(ctx, AMVP_HASH_SHA224, AMVP_HASH_MESSAGE_LEN,
                                  0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_hash_enable(ctx, AMVP_HASH_SHA256, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hash_set_domain(ctx, AMVP_HASH_SHA256, AMVP_HASH_MESSAGE_LEN,
                                  0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_hash_enable(ctx, AMVP_HASH_SHA384, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hash_set_domain(ctx, AMVP_HASH_SHA384, AMVP_HASH_MESSAGE_LEN,
                                  0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_hash_enable(ctx, AMVP_HASH_SHA512, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hash_set_domain(ctx, AMVP_HASH_SHA512, AMVP_HASH_MESSAGE_LEN,
                                  0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    /* SHA2-512/224 and SHA2-512/256 */
    rv = amvp_cap_hash_enable(ctx, AMVP_HASH_SHA512_224, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hash_set_domain(ctx, AMVP_HASH_SHA512_224, AMVP_HASH_MESSAGE_LEN,
                                  0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_hash_enable(ctx, AMVP_HASH_SHA512_256, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hash_set_domain(ctx, AMVP_HASH_SHA512_256, AMVP_HASH_MESSAGE_LEN,
                                  0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    /* SHA3 and SHAKE */
    rv = amvp_cap_hash_enable(ctx, AMVP_HASH_SHA3_224, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hash_set_parm(ctx, AMVP_HASH_SHA3_224, AMVP_HASH_IN_BIT, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hash_set_parm(ctx, AMVP_HASH_SHA3_224, AMVP_HASH_IN_EMPTY, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hash_set_domain(ctx, AMVP_HASH_SHA3_224, AMVP_HASH_MESSAGE_LEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_hash_enable(ctx, AMVP_HASH_SHA3_256, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hash_set_parm(ctx, AMVP_HASH_SHA3_256, AMVP_HASH_IN_BIT, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hash_set_parm(ctx, AMVP_HASH_SHA3_256, AMVP_HASH_IN_EMPTY, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hash_set_domain(ctx, AMVP_HASH_SHA3_256, AMVP_HASH_MESSAGE_LEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_hash_enable(ctx, AMVP_HASH_SHA3_384, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hash_set_parm(ctx, AMVP_HASH_SHA3_384, AMVP_HASH_IN_BIT, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hash_set_parm(ctx, AMVP_HASH_SHA3_384, AMVP_HASH_IN_EMPTY, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hash_set_domain(ctx, AMVP_HASH_SHA3_384, AMVP_HASH_MESSAGE_LEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_hash_enable(ctx, AMVP_HASH_SHA3_512, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hash_set_parm(ctx, AMVP_HASH_SHA3_512, AMVP_HASH_IN_BIT, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hash_set_parm(ctx, AMVP_HASH_SHA3_512, AMVP_HASH_IN_EMPTY, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hash_set_domain(ctx, AMVP_HASH_SHA3_512, AMVP_HASH_MESSAGE_LEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_hash_enable(ctx, AMVP_HASH_SHAKE_128, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hash_set_parm(ctx, AMVP_HASH_SHAKE_128, AMVP_HASH_IN_BIT, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hash_set_parm(ctx, AMVP_HASH_SHAKE_128, AMVP_HASH_OUT_BIT, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hash_set_parm(ctx, AMVP_HASH_SHAKE_128, AMVP_HASH_IN_EMPTY, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hash_set_domain(ctx, AMVP_HASH_SHAKE_128, AMVP_HASH_OUT_LENGTH, 16, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);


    rv = amvp_cap_hash_enable(ctx, AMVP_HASH_SHAKE_256, &app_sha_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hash_set_parm(ctx, AMVP_HASH_SHAKE_256, AMVP_HASH_IN_BIT, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hash_set_parm(ctx, AMVP_HASH_SHAKE_256, AMVP_HASH_OUT_BIT, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hash_set_parm(ctx, AMVP_HASH_SHAKE_256, AMVP_HASH_IN_EMPTY, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hash_set_domain(ctx, AMVP_HASH_SHAKE_256, AMVP_HASH_OUT_LENGTH, 16, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);

end:
    return rv;
}

static int enable_cmac(AMVP_CTX *ctx) {
    AMVP_RESULT rv = AMVP_SUCCESS;

    /* Enable CMAC */
    rv = amvp_cap_cmac_enable(ctx, AMVP_CMAC_AES, &app_cmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_cmac_set_domain(ctx, AMVP_CMAC_AES, AMVP_CMAC_MSGLEN, 0, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_cmac_set_parm(ctx, AMVP_CMAC_AES, AMVP_CMAC_MACLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_CMAC_AES, AMVP_PREREQ_AES, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_cmac_set_parm(ctx, AMVP_CMAC_AES, AMVP_CMAC_DIRECTION_GEN, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_cmac_set_parm(ctx, AMVP_CMAC_AES, AMVP_CMAC_DIRECTION_VER, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_cmac_set_parm(ctx, AMVP_CMAC_AES, AMVP_CMAC_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_cmac_set_parm(ctx, AMVP_CMAC_AES, AMVP_CMAC_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_cmac_set_parm(ctx, AMVP_CMAC_AES, AMVP_CMAC_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    rv = amvp_cap_cmac_enable(ctx, AMVP_CMAC_TDES, &app_cmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_cmac_set_domain(ctx, AMVP_CMAC_TDES, AMVP_CMAC_MSGLEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_cmac_set_parm(ctx, AMVP_CMAC_TDES, AMVP_CMAC_MACLEN, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_cmac_set_parm(ctx, AMVP_CMAC_TDES, AMVP_CMAC_DIRECTION_GEN, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_cmac_set_parm(ctx, AMVP_CMAC_TDES, AMVP_CMAC_DIRECTION_VER, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_cmac_set_parm(ctx, AMVP_CMAC_TDES, AMVP_CMAC_KEYING_OPTION, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_CMAC_TDES, AMVP_PREREQ_TDES, value);
    CHECK_ENABLE_CAP_RV(rv);
#endif
end:

    return rv;
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static int enable_kmac(AMVP_CTX *ctx) {
    AMVP_RESULT rv = AMVP_SUCCESS;

    /* Enable KMAC */
    rv = amvp_cap_kmac_enable(ctx, AMVP_KMAC_128, &app_kmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kmac_set_domain(ctx, AMVP_KMAC_128, AMVP_KMAC_MSGLEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kmac_set_domain(ctx, AMVP_KMAC_128, AMVP_KMAC_MACLEN, 32, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kmac_set_domain(ctx, AMVP_KMAC_128, AMVP_KMAC_KEYLEN, 128, 1024, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kmac_set_parm(ctx, AMVP_KMAC_128, AMVP_KMAC_XOF_SUPPORT, AMVP_XOF_SUPPORT_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    /* OpenSSL 3.X supports hex customization strings, but they are not on the FIPS cert, so leaving disabled */
    rv = amvp_cap_kmac_set_parm(ctx, AMVP_KMAC_128, AMVP_KMAC_HEX_CUSTOM_SUPPORT, 0);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_kmac_enable(ctx, AMVP_KMAC_256, &app_kmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kmac_set_domain(ctx, AMVP_KMAC_256, AMVP_KMAC_MSGLEN, 0, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kmac_set_domain(ctx, AMVP_KMAC_256, AMVP_KMAC_MACLEN, 32, 65536, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kmac_set_domain(ctx, AMVP_KMAC_256, AMVP_KMAC_KEYLEN, 128, 1024, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kmac_set_parm(ctx, AMVP_KMAC_256, AMVP_KMAC_XOF_SUPPORT, AMVP_XOF_SUPPORT_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    /* OpenSSL 3.X supports hex customization strings, but they are not on the FIPS cert, so leaving disabled */
    rv = amvp_cap_kmac_set_parm(ctx, AMVP_KMAC_256, AMVP_KMAC_HEX_CUSTOM_SUPPORT, 0);
    CHECK_ENABLE_CAP_RV(rv);
end:
    return rv;
}
#endif

static int enable_hmac(AMVP_CTX *ctx) {
    AMVP_RESULT rv = AMVP_SUCCESS;

    rv = amvp_cap_hmac_enable(ctx, AMVP_HMAC_SHA1, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hmac_set_domain(ctx, AMVP_HMAC_SHA1, AMVP_HMAC_KEYLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hmac_set_domain(ctx, AMVP_HMAC_SHA1, AMVP_HMAC_MACLEN, 32, 160, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_HMAC_SHA1, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_hmac_enable(ctx, AMVP_HMAC_SHA2_224, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hmac_set_domain(ctx, AMVP_HMAC_SHA2_224, AMVP_HMAC_KEYLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hmac_set_domain(ctx, AMVP_HMAC_SHA2_224, AMVP_HMAC_MACLEN, 32, 224, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_HMAC_SHA2_224, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_hmac_enable(ctx, AMVP_HMAC_SHA2_256, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hmac_set_domain(ctx, AMVP_HMAC_SHA2_256, AMVP_HMAC_KEYLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hmac_set_domain(ctx, AMVP_HMAC_SHA2_256, AMVP_HMAC_MACLEN, 32, 256, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_HMAC_SHA2_256, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_hmac_enable(ctx, AMVP_HMAC_SHA2_384, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hmac_set_domain(ctx, AMVP_HMAC_SHA2_384, AMVP_HMAC_KEYLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hmac_set_domain(ctx, AMVP_HMAC_SHA2_384, AMVP_HMAC_MACLEN, 32, 384, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_HMAC_SHA2_384, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_hmac_enable(ctx, AMVP_HMAC_SHA2_512, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hmac_set_domain(ctx, AMVP_HMAC_SHA2_512, AMVP_HMAC_KEYLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hmac_set_domain(ctx, AMVP_HMAC_SHA2_512, AMVP_HMAC_MACLEN, 32, 512, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_HMAC_SHA2_512, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_hmac_enable(ctx, AMVP_HMAC_SHA2_512_224, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hmac_set_domain(ctx, AMVP_HMAC_SHA2_512_224, AMVP_HMAC_KEYLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hmac_set_domain(ctx, AMVP_HMAC_SHA2_512_224, AMVP_HMAC_MACLEN, 32, 224, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_HMAC_SHA2_512_224, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_hmac_enable(ctx, AMVP_HMAC_SHA2_512_256, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hmac_set_domain(ctx, AMVP_HMAC_SHA2_512_256, AMVP_HMAC_KEYLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hmac_set_domain(ctx, AMVP_HMAC_SHA2_512_256, AMVP_HMAC_MACLEN, 32, 256, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_HMAC_SHA2_512_256, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    
    rv = amvp_cap_hmac_enable(ctx, AMVP_HMAC_SHA3_224, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hmac_set_domain(ctx, AMVP_HMAC_SHA3_224, AMVP_HMAC_KEYLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hmac_set_domain(ctx, AMVP_HMAC_SHA3_224, AMVP_HMAC_MACLEN, 32, 224, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_HMAC_SHA3_224, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    
    rv = amvp_cap_hmac_enable(ctx, AMVP_HMAC_SHA3_256, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hmac_set_domain(ctx, AMVP_HMAC_SHA3_256, AMVP_HMAC_KEYLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hmac_set_domain(ctx, AMVP_HMAC_SHA3_256, AMVP_HMAC_MACLEN, 32, 256, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_HMAC_SHA3_256, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    
    rv = amvp_cap_hmac_enable(ctx, AMVP_HMAC_SHA3_384, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hmac_set_domain(ctx, AMVP_HMAC_SHA3_384, AMVP_HMAC_KEYLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hmac_set_domain(ctx, AMVP_HMAC_SHA3_384, AMVP_HMAC_MACLEN, 32, 384, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_HMAC_SHA3_384, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    
    rv = amvp_cap_hmac_enable(ctx, AMVP_HMAC_SHA3_512, &app_hmac_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hmac_set_domain(ctx, AMVP_HMAC_SHA3_512, AMVP_HMAC_KEYLEN, 8, 524288, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_hmac_set_domain(ctx, AMVP_HMAC_SHA3_512, AMVP_HMAC_MACLEN, 32, 512, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_HMAC_SHA3_512, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
end:

    return rv;
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static int enable_kdf(AMVP_CTX *ctx) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    int flags = 0;

    rv = amvp_cap_kdf_tls12_enable(ctx, &app_kdf_tls12_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF_TLS12, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF_TLS12, AMVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf_tls12_set_parm(ctx, AMVP_KDF_TLS12_HASH_ALG, AMVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf_tls12_set_parm(ctx, AMVP_KDF_TLS12_HASH_ALG, AMVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf_tls12_set_parm(ctx, AMVP_KDF_TLS12_HASH_ALG, AMVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);

#if 0
    rv = amvp_cap_kdf135_snmp_enable(ctx, &app_kdf135_snmp_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_SNMP, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_snmp_set_parm(ctx, AMVP_KDF135_SNMP, AMVP_KDF135_SNMP_PASS_LEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_snmp_set_parm(ctx, AMVP_KDF135_SNMP, AMVP_KDF135_SNMP_PASS_LEN, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_snmp_set_engid(ctx, AMVP_KDF135_SNMP, ENGID1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_snmp_set_engid(ctx, AMVP_KDF135_SNMP, ENGID2);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = amvp_cap_kdf135_ssh_enable(ctx, &app_kdf135_ssh_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_SSH, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_SSH, AMVP_PREREQ_TDES, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_SSH, AMVP_PREREQ_AES, value);
    CHECK_ENABLE_CAP_RV(rv);

    //Bit flags for kdf135_ssh sha capabilities
    flags = AMVP_SHA1 | AMVP_SHA224 | AMVP_SHA256
            | AMVP_SHA384 | AMVP_SHA512;

    rv = amvp_cap_kdf135_ssh_set_parm(ctx, AMVP_KDF135_SSH, AMVP_SSH_METH_TDES_CBC, flags);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_ssh_set_parm(ctx, AMVP_KDF135_SSH, AMVP_SSH_METH_AES_128_CBC, flags);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_ssh_set_parm(ctx, AMVP_KDF135_SSH, AMVP_SSH_METH_AES_192_CBC, flags);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_ssh_set_parm(ctx, AMVP_KDF135_SSH, AMVP_SSH_METH_AES_256_CBC, flags);
    CHECK_ENABLE_CAP_RV(rv);
#if 0
    rv = amvp_cap_kdf135_srtp_enable(ctx, &app_kdf135_srtp_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_SRTP, AMVP_PREREQ_AES, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_srtp_set_parm(ctx, AMVP_KDF135_SRTP, AMVP_SRTP_SUPPORT_ZERO_KDR, 0);
    CHECK_ENABLE_CAP_RV(rv);
    for (i = 0; i < 24; i++) {
        rv = amvp_cap_kdf135_srtp_set_parm(ctx, AMVP_KDF135_SRTP, AMVP_SRTP_KDF_EXPONENT, i + 1);
        CHECK_ENABLE_CAP_RV(rv);
    }
    rv = amvp_cap_kdf135_srtp_set_parm(ctx, AMVP_KDF135_SRTP, AMVP_SRTP_AES_KEYLEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_srtp_set_parm(ctx, AMVP_KDF135_SRTP, AMVP_SRTP_AES_KEYLEN, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_srtp_set_parm(ctx, AMVP_KDF135_SRTP, AMVP_SRTP_AES_KEYLEN, 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_kdf135_ikev2_enable(ctx, &app_kdf135_ikev2_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_IKEV2, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_IKEV2, AMVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    // can use len_param or domain_param for these attributes
    rv = amvp_cap_kdf135_ikev2_set_length(ctx, AMVP_INIT_NONCE_LEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_ikev2_set_length(ctx, AMVP_INIT_NONCE_LEN, 2048);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_ikev2_set_length(ctx, AMVP_RESPOND_NONCE_LEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_ikev2_set_length(ctx, AMVP_RESPOND_NONCE_LEN, 2048);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_ikev2_set_length(ctx, AMVP_DH_SECRET_LEN, 2048);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_ikev2_set_length(ctx, AMVP_KEY_MATERIAL_LEN, 1056);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_ikev2_set_length(ctx, AMVP_KEY_MATERIAL_LEN, 3072);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_ikev2_set_parm(ctx, AMVP_KDF_HASH_ALG, AMVP_SHA1);
    CHECK_ENABLE_CAP_RV(rv);
#endif
#if 0 // Disabled for now
    rv = amvp_cap_kdf135_ikev1_enable(ctx, &app_kdf135_ikev1_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_IKEV1, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_IKEV1, AMVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_ikev1_set_domain(ctx, AMVP_KDF_IKEv1_INIT_NONCE_LEN, 64, 2048, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_ikev1_set_domain(ctx, AMVP_KDF_IKEv1_RESPOND_NONCE_LEN, 64, 2048, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_ikev1_set_domain(ctx, AMVP_KDF_IKEv1_DH_SECRET_LEN, 224, 8192, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_ikev1_set_domain(ctx, AMVP_KDF_IKEv1_PSK_LEN, 8, 8192, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_ikev1_set_parm(ctx, AMVP_KDF_IKEv1_HASH_ALG, AMVP_SHA1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_ikev1_set_parm(ctx, AMVP_KDF_IKEv1_AUTH_METHOD, AMVP_KDF135_IKEV1_AMETH_PSK);
    CHECK_ENABLE_CAP_RV(rv);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = amvp_cap_kdf135_x942_enable(ctx, &app_kdf135_x942_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_X942, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_x942_set_parm(ctx, AMVP_KDF_X942_KDF_TYPE, AMVP_KDF_X942_KDF_TYPE_DER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_x942_set_parm(ctx, AMVP_KDF_X942_HASH_ALG, AMVP_SHA1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_x942_set_parm(ctx, AMVP_KDF_X942_HASH_ALG, AMVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_x942_set_parm(ctx, AMVP_KDF_X942_HASH_ALG, AMVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_x942_set_parm(ctx, AMVP_KDF_X942_HASH_ALG, AMVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_x942_set_parm(ctx, AMVP_KDF_X942_HASH_ALG, AMVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_x942_set_parm(ctx, AMVP_KDF_X942_HASH_ALG, AMVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_x942_set_parm(ctx, AMVP_KDF_X942_HASH_ALG, AMVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_x942_set_parm(ctx, AMVP_KDF_X942_HASH_ALG, AMVP_SHA3_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_x942_set_parm(ctx, AMVP_KDF_X942_HASH_ALG, AMVP_SHA3_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_x942_set_parm(ctx, AMVP_KDF_X942_HASH_ALG, AMVP_SHA3_384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_x942_set_parm(ctx, AMVP_KDF_X942_HASH_ALG, AMVP_SHA3_512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_x942_set_domain(ctx, AMVP_KDF_X942_KEY_LEN, 8, 4096, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_x942_set_domain(ctx, AMVP_KDF_X942_OTHER_INFO_LEN, 0, 4096, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_x942_set_domain(ctx, AMVP_KDF_X942_ZZ_LEN, 8, 4096, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_x942_set_domain(ctx, AMVP_KDF_X942_SUPP_INFO_LEN, 0, 120, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_x942_set_parm(ctx, AMVP_KDF_X942_OID, AMVP_KDF_X942_OID_AES128KW);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_x942_set_parm(ctx, AMVP_KDF_X942_OID, AMVP_KDF_X942_OID_AES192KW);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_x942_set_parm(ctx, AMVP_KDF_X942_OID, AMVP_KDF_X942_OID_AES256KW);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_kdf135_x963_enable(ctx, &app_kdf135_x963_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_X963, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_HASH_ALG, AMVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_HASH_ALG, AMVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_HASH_ALG, AMVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_HASH_ALG, AMVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_KEY_DATA_LEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_KEY_DATA_LEN, 4096);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_FIELD_SIZE, 224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_FIELD_SIZE, 571);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_SHARED_INFO_LEN, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_SHARED_INFO_LEN, 1024);
    CHECK_ENABLE_CAP_RV(rv);

    /* KDF108 Counter Mode */
    rv = amvp_cap_kdf108_enable(ctx, &app_kdf108_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF108, AMVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF108, AMVP_PREREQ_CMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_COUNTER, AMVP_KDF108_SUPPORTED_LEN, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_COUNTER, AMVP_KDF108_SUPPORTED_LEN, 72);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_COUNTER, AMVP_KDF108_SUPPORTED_LEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_COUNTER, AMVP_KDF108_SUPPORTED_LEN, 776);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_COUNTER, AMVP_KDF108_SUPPORTED_LEN, 3456);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_COUNTER, AMVP_KDF108_SUPPORTED_LEN, 4096);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_COUNTER, AMVP_KDF108_MAC_MODE, AMVP_KDF108_MAC_MODE_CMAC_AES128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_COUNTER, AMVP_KDF108_MAC_MODE, AMVP_KDF108_MAC_MODE_CMAC_AES192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_COUNTER, AMVP_KDF108_MAC_MODE, AMVP_KDF108_MAC_MODE_CMAC_AES256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_COUNTER, AMVP_KDF108_MAC_MODE, AMVP_KDF108_MAC_MODE_HMAC_SHA1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_COUNTER, AMVP_KDF108_MAC_MODE, AMVP_KDF108_MAC_MODE_HMAC_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_COUNTER, AMVP_KDF108_MAC_MODE, AMVP_KDF108_MAC_MODE_HMAC_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_COUNTER, AMVP_KDF108_MAC_MODE, AMVP_KDF108_MAC_MODE_HMAC_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_COUNTER, AMVP_KDF108_MAC_MODE, AMVP_KDF108_MAC_MODE_HMAC_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_COUNTER, AMVP_KDF108_COUNTER_LEN, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_COUNTER, AMVP_KDF108_FIXED_DATA_ORDER, AMVP_KDF108_FIXED_DATA_ORDER_BEFORE);
    CHECK_ENABLE_CAP_RV(rv);
    /* KDF108 Feedback Mode */
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_FEEDBACK, AMVP_KDF108_SUPPORTED_LEN, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_FEEDBACK, AMVP_KDF108_SUPPORTED_LEN, 72);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_FEEDBACK, AMVP_KDF108_SUPPORTED_LEN, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_FEEDBACK, AMVP_KDF108_SUPPORTED_LEN, 776);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_FEEDBACK, AMVP_KDF108_SUPPORTED_LEN, 3456);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_FEEDBACK, AMVP_KDF108_SUPPORTED_LEN, 4096);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_FEEDBACK, AMVP_KDF108_MAC_MODE, AMVP_KDF108_MAC_MODE_CMAC_AES128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_FEEDBACK, AMVP_KDF108_MAC_MODE, AMVP_KDF108_MAC_MODE_CMAC_AES192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_FEEDBACK, AMVP_KDF108_MAC_MODE, AMVP_KDF108_MAC_MODE_CMAC_AES256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_FEEDBACK, AMVP_KDF108_MAC_MODE, AMVP_KDF108_MAC_MODE_HMAC_SHA1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_FEEDBACK, AMVP_KDF108_MAC_MODE, AMVP_KDF108_MAC_MODE_HMAC_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_FEEDBACK, AMVP_KDF108_MAC_MODE, AMVP_KDF108_MAC_MODE_HMAC_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_FEEDBACK, AMVP_KDF108_MAC_MODE, AMVP_KDF108_MAC_MODE_HMAC_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_FEEDBACK, AMVP_KDF108_MAC_MODE, AMVP_KDF108_MAC_MODE_HMAC_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_FEEDBACK, AMVP_KDF108_SUPPORTS_EMPTY_IV, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_FEEDBACK, AMVP_KDF108_REQUIRES_EMPTY_IV, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_FEEDBACK, AMVP_KDF108_COUNTER_LEN, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_FEEDBACK, AMVP_KDF108_FIXED_DATA_ORDER, AMVP_KDF108_FIXED_DATA_ORDER_BEFORE);
    CHECK_ENABLE_CAP_RV(rv);

    /* PBKDF */
    rv = amvp_cap_pbkdf_enable(ctx, &app_pbkdf_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_PBKDF, AMVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_pbkdf_set_parm(ctx, AMVP_PBKDF_HMAC_ALG, AMVP_SHA1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_pbkdf_set_parm(ctx, AMVP_PBKDF_HMAC_ALG, AMVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_pbkdf_set_parm(ctx, AMVP_PBKDF_HMAC_ALG, AMVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_pbkdf_set_parm(ctx, AMVP_PBKDF_HMAC_ALG, AMVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_pbkdf_set_parm(ctx, AMVP_PBKDF_HMAC_ALG, AMVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_pbkdf_set_parm(ctx, AMVP_PBKDF_HMAC_ALG, AMVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_pbkdf_set_parm(ctx, AMVP_PBKDF_HMAC_ALG, AMVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_pbkdf_set_domain(ctx, AMVP_PBKDF_ITERATION_COUNT, 1, 10000, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_pbkdf_set_domain(ctx, AMVP_PBKDF_KEY_LEN, 112, 4096, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_pbkdf_set_domain(ctx, AMVP_PBKDF_PASSWORD_LEN, 8, 128, 8);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_pbkdf_set_domain(ctx, AMVP_PBKDF_SALT_LEN, 128, 4096, 8);
    CHECK_ENABLE_CAP_RV(rv);
#endif

    rv = amvp_cap_kdf_tls13_enable(ctx, &app_kdf_tls13_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF_TLS13, AMVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf_tls13_set_parm(ctx, AMVP_KDF_TLS13_HMAC_ALG, AMVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf_tls13_set_parm(ctx, AMVP_KDF_TLS13_HMAC_ALG, AMVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf_tls13_set_parm(ctx, AMVP_KDF_TLS13_RUNNING_MODE, AMVP_KDF_TLS13_RUN_MODE_PSK);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf_tls13_set_parm(ctx, AMVP_KDF_TLS13_RUNNING_MODE, AMVP_KDF_TLS13_RUN_MODE_DHE);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kdf_tls13_set_parm(ctx, AMVP_KDF_TLS13_RUNNING_MODE, AMVP_KDF_TLS13_RUN_MODE_PSK_DHE);
    CHECK_ENABLE_CAP_RV(rv);

end:

    return rv;
}
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static int enable_kas_ecc(AMVP_CTX *ctx) {
    AMVP_RESULT rv = AMVP_SUCCESS;

    /* Enable KAS-ECC.... */
    rv = amvp_cap_kas_ecc_enable(ctx, AMVP_KAS_ECC_CDH, &app_kas_ecc_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_prereq(ctx, AMVP_KAS_ECC_CDH, AMVP_KAS_ECC_MODE_CDH, AMVP_PREREQ_ECDSA, value);
    CHECK_ENABLE_CAP_RV(rv);
#ifdef AMVP_ENABLE_DEPRECATED_VERSION
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_CDH, AMVP_KAS_ECC_MODE_CDH, AMVP_KAS_ECC_FUNCTION, AMVP_KAS_ECC_FUNC_PARTIAL);
    CHECK_ENABLE_CAP_RV(rv);
#else
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_CDH, AMVP_KAS_ECC_MODE_CDH, AMVP_KAS_ECC_REVISION, AMVP_REVISION_SP800_56AR3);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_CDH, AMVP_KAS_ECC_MODE_CDH, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_P224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_CDH, AMVP_KAS_ECC_MODE_CDH, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_P256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_CDH, AMVP_KAS_ECC_MODE_CDH, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_P384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_CDH, AMVP_KAS_ECC_MODE_CDH, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_P521);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_CDH, AMVP_KAS_ECC_MODE_CDH, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_K233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_CDH, AMVP_KAS_ECC_MODE_CDH, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_K283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_CDH, AMVP_KAS_ECC_MODE_CDH, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_K409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_CDH, AMVP_KAS_ECC_MODE_CDH, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_K571);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_CDH, AMVP_KAS_ECC_MODE_CDH, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_B233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_CDH, AMVP_KAS_ECC_MODE_CDH, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_B283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_CDH, AMVP_KAS_ECC_MODE_CDH, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_B409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_CDH, AMVP_KAS_ECC_MODE_CDH, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_B571);
    CHECK_ENABLE_CAP_RV(rv);

#ifdef AMVP_ENABLE_DEPRECATED_VERSION
    rv = amvp_cap_kas_ecc_enable(ctx, AMVP_KAS_ECC_COMP, &app_kas_ecc_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_prereq(ctx, AMVP_KAS_ECC_COMP, AMVP_KAS_ECC_MODE_COMPONENT, AMVP_PREREQ_ECDSA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_prereq(ctx, AMVP_KAS_ECC_COMP, AMVP_KAS_ECC_MODE_COMPONENT, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_prereq(ctx, AMVP_KAS_ECC_COMP, AMVP_KAS_ECC_MODE_COMPONENT, AMVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_prereq(ctx, AMVP_KAS_ECC_COMP, AMVP_KAS_ECC_MODE_COMPONENT, AMVP_PREREQ_CCM, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_prereq(ctx, AMVP_KAS_ECC_COMP, AMVP_KAS_ECC_MODE_COMPONENT, AMVP_PREREQ_CMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_prereq(ctx, AMVP_KAS_ECC_COMP, AMVP_KAS_ECC_MODE_COMPONENT, AMVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_COMP, AMVP_KAS_ECC_MODE_COMPONENT, AMVP_KAS_ECC_FUNCTION, AMVP_KAS_ECC_FUNC_PARTIAL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_scheme(ctx, AMVP_KAS_ECC_COMP, AMVP_KAS_ECC_MODE_COMPONENT, AMVP_KAS_ECC_EPHEMERAL_UNIFIED, AMVP_KAS_ECC_ROLE, 0, AMVP_KAS_ECC_ROLE_INITIATOR);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_scheme(ctx, AMVP_KAS_ECC_COMP, AMVP_KAS_ECC_MODE_COMPONENT, AMVP_KAS_ECC_EPHEMERAL_UNIFIED, AMVP_KAS_ECC_ROLE, 0, AMVP_KAS_ECC_ROLE_RESPONDER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_scheme(ctx, AMVP_KAS_ECC_COMP, AMVP_KAS_ECC_MODE_COMPONENT, AMVP_KAS_ECC_EPHEMERAL_UNIFIED, AMVP_KAS_ECC_KDF, 0, AMVP_KAS_ECC_NOKDFNOKC);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_scheme(ctx, AMVP_KAS_ECC_COMP, AMVP_KAS_ECC_MODE_COMPONENT, AMVP_KAS_ECC_EPHEMERAL_UNIFIED, AMVP_KAS_ECC_EB, AMVP_EC_CURVE_P224, AMVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_scheme(ctx, AMVP_KAS_ECC_COMP, AMVP_KAS_ECC_MODE_COMPONENT, AMVP_KAS_ECC_EPHEMERAL_UNIFIED, AMVP_KAS_ECC_EC, AMVP_EC_CURVE_P256, AMVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_scheme(ctx, AMVP_KAS_ECC_COMP, AMVP_KAS_ECC_MODE_COMPONENT, AMVP_KAS_ECC_EPHEMERAL_UNIFIED, AMVP_KAS_ECC_ED, AMVP_EC_CURVE_P384, AMVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_scheme(ctx, AMVP_KAS_ECC_COMP, AMVP_KAS_ECC_MODE_COMPONENT, AMVP_KAS_ECC_EPHEMERAL_UNIFIED, AMVP_KAS_ECC_EE, AMVP_EC_CURVE_P521, AMVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
#endif

    rv = amvp_cap_kas_ecc_enable(ctx, AMVP_KAS_ECC_SSC, &app_kas_ecc_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_prereq(ctx, AMVP_KAS_ECC_SSC, AMVP_KAS_ECC_MODE_NONE, AMVP_PREREQ_ECDSA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_prereq(ctx, AMVP_KAS_ECC_SSC, AMVP_KAS_ECC_MODE_NONE, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_prereq(ctx, AMVP_KAS_ECC_SSC, AMVP_KAS_ECC_MODE_NONE, AMVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
#if 0
    rv = amvp_cap_kas_ecc_set_prereq(ctx, AMVP_KAS_ECC_SSC, AMVP_KAS_ECC_MODE_NONE, AMVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = amvp_cap_kas_ecc_set_scheme(ctx, AMVP_KAS_ECC_SSC, AMVP_KAS_ECC_MODE_NONE, AMVP_KAS_ECC_EPHEMERAL_UNIFIED, AMVP_KAS_ECC_ROLE, 0, AMVP_KAS_ECC_ROLE_INITIATOR);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_scheme(ctx, AMVP_KAS_ECC_SSC, AMVP_KAS_ECC_MODE_NONE, AMVP_KAS_ECC_EPHEMERAL_UNIFIED, AMVP_KAS_ECC_ROLE, 0, AMVP_KAS_ECC_ROLE_RESPONDER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_SSC, AMVP_KAS_ECC_MODE_NONE, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_P224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_SSC, AMVP_KAS_ECC_MODE_NONE, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_P256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_SSC, AMVP_KAS_ECC_MODE_NONE, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_P384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_SSC, AMVP_KAS_ECC_MODE_NONE, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_P521);
    CHECK_ENABLE_CAP_RV(rv);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_SSC, AMVP_KAS_ECC_MODE_NONE, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_B233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_SSC, AMVP_KAS_ECC_MODE_NONE, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_B283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_SSC, AMVP_KAS_ECC_MODE_NONE, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_B409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_SSC, AMVP_KAS_ECC_MODE_NONE, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_B571);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_SSC, AMVP_KAS_ECC_MODE_NONE, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_K233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_SSC, AMVP_KAS_ECC_MODE_NONE, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_K283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_SSC, AMVP_KAS_ECC_MODE_NONE, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_K409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_SSC, AMVP_KAS_ECC_MODE_NONE, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_K571);
    CHECK_ENABLE_CAP_RV(rv);
#else
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_SSC, AMVP_KAS_ECC_MODE_NONE, AMVP_KAS_ECC_HASH, AMVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
#endif

end:

    return rv;
}
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static int enable_kas_ifc(AMVP_CTX *ctx) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    BIGNUM *expo = NULL;
    char *expo_str = NULL;

    expo = BN_new();
    if (!expo || !BN_set_word(expo, RSA_F4)) {
        printf("oh no\n");
        return 1;
    }
    expo_str = BN_bn2hex(expo);
    BN_free(expo);

    rv = amvp_cap_kas_ifc_enable(ctx, AMVP_KAS_IFC_SSC, &app_kas_ifc_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_KAS_IFC_SSC, AMVP_PREREQ_RSA, value);
    CHECK_ENABLE_CAP_RV(rv);
#if 0 /* no longer used, left here for historical purposes */
    rv = amvp_cap_set_prereq(ctx, AMVP_KAS_IFC_SSC, AMVP_PREREQ_RSADP, value);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = amvp_cap_set_prereq(ctx, AMVP_KAS_IFC_SSC, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_KAS_IFC_SSC, AMVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ifc_set_parm(ctx, AMVP_KAS_IFC_SSC, AMVP_KAS_IFC_KAS1, AMVP_KAS_IFC_INITIATOR);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ifc_set_parm(ctx, AMVP_KAS_IFC_SSC, AMVP_KAS_IFC_KAS1, AMVP_KAS_IFC_RESPONDER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ifc_set_parm(ctx, AMVP_KAS_IFC_SSC, AMVP_KAS_IFC_MODULO, 2048);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ifc_set_parm(ctx, AMVP_KAS_IFC_SSC, AMVP_KAS_IFC_MODULO, 3072);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ifc_set_parm(ctx, AMVP_KAS_IFC_SSC, AMVP_KAS_IFC_MODULO, 4096);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ifc_set_exponent(ctx, AMVP_KAS_IFC_SSC, AMVP_KAS_IFC_FIXEDPUBEXP, expo_str);
    CHECK_ENABLE_CAP_RV(rv);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = amvp_cap_kas_ifc_set_parm(ctx, AMVP_KAS_IFC_SSC, AMVP_KAS_IFC_KAS2, AMVP_KAS_IFC_INITIATOR);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ifc_set_parm(ctx, AMVP_KAS_IFC_SSC, AMVP_KAS_IFC_KAS2, AMVP_KAS_IFC_RESPONDER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ifc_set_parm(ctx, AMVP_KAS_IFC_SSC, AMVP_KAS_IFC_MODULO, 6144);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ifc_set_parm(ctx, AMVP_KAS_IFC_SSC, AMVP_KAS_IFC_MODULO, 8192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ifc_set_parm(ctx, AMVP_KAS_IFC_SSC, AMVP_KAS_IFC_KEYGEN_METHOD, AMVP_KAS_IFC_RSAKPG1_BASIC);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ifc_set_parm(ctx, AMVP_KAS_IFC_SSC, AMVP_KAS_IFC_KEYGEN_METHOD, AMVP_KAS_IFC_RSAKPG2_BASIC);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ifc_set_parm(ctx, AMVP_KAS_IFC_SSC, AMVP_KAS_IFC_KEYGEN_METHOD, AMVP_KAS_IFC_RSAKPG1_PRIME_FACTOR);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ifc_set_parm(ctx, AMVP_KAS_IFC_SSC, AMVP_KAS_IFC_KEYGEN_METHOD, AMVP_KAS_IFC_RSAKPG2_PRIME_FACTOR);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ifc_set_parm(ctx, AMVP_KAS_IFC_SSC, AMVP_KAS_IFC_KEYGEN_METHOD, AMVP_KAS_IFC_RSAKPG1_CRT);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ifc_set_parm(ctx, AMVP_KAS_IFC_SSC, AMVP_KAS_IFC_KEYGEN_METHOD, AMVP_KAS_IFC_RSAKPG2_CRT);
    CHECK_ENABLE_CAP_RV(rv);
#else
    rv = amvp_cap_kas_ifc_set_parm(ctx, AMVP_KAS_IFC_SSC, AMVP_KAS_IFC_KEYGEN_METHOD, AMVP_KAS_IFC_RSAKPG1_BASIC);
    CHECK_ENABLE_CAP_RV(rv);
#if 0
    rv = amvp_cap_kas_ifc_set_parm(ctx, AMVP_KAS_IFC_SSC, AMVP_KAS_IFC_HASH, AMVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
#endif
#endif

end:
    if (expo_str) free(expo_str);
    return rv;
}
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static int enable_kts_ifc(AMVP_CTX *ctx) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    BIGNUM *expo = NULL;
    char *expo_str = NULL;
    char iut_id[] = "DEADDEAD";
    char concatenation[] = "concatenation";

    expo = BN_new();
    if (!expo || !BN_set_word(expo, RSA_F4)) {
        printf("oh no\n");
        return 1;
    }
    expo_str = BN_bn2hex(expo);
    BN_free(expo);

    rv = amvp_cap_kts_ifc_enable(ctx, AMVP_KTS_IFC, &app_kts_ifc_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_KTS_IFC, AMVP_PREREQ_RSA, value);
    CHECK_ENABLE_CAP_RV(rv);
#if 0 /* no longer used, left here for historical purposes */
    rv = amvp_cap_set_prereq(ctx, AMVP_KTS_IFC, AMVP_PREREQ_RSADP, value);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = amvp_cap_set_prereq(ctx, AMVP_KTS_IFC, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_KTS_IFC, AMVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kts_ifc_set_param_string(ctx, AMVP_KTS_IFC, AMVP_KTS_IFC_FIXEDPUBEXP, expo_str);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kts_ifc_set_param_string(ctx, AMVP_KTS_IFC, AMVP_KTS_IFC_IUT_ID, iut_id);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kts_ifc_set_parm(ctx, AMVP_KTS_IFC, AMVP_KTS_IFC_FUNCTION, AMVP_KTS_IFC_KEYPAIR_GEN);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kts_ifc_set_parm(ctx, AMVP_KTS_IFC, AMVP_KTS_IFC_FUNCTION, AMVP_KTS_IFC_PARTIAL_VAL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kts_ifc_set_parm(ctx, AMVP_KTS_IFC, AMVP_KTS_IFC_MODULO, 2048);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kts_ifc_set_parm(ctx, AMVP_KTS_IFC, AMVP_KTS_IFC_MODULO, 3072);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kts_ifc_set_parm(ctx, AMVP_KTS_IFC, AMVP_KTS_IFC_MODULO, 4096);
    CHECK_ENABLE_CAP_RV(rv);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = amvp_cap_kts_ifc_set_parm(ctx, AMVP_KTS_IFC, AMVP_KTS_IFC_MODULO, 6144);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kts_ifc_set_parm(ctx, AMVP_KTS_IFC, AMVP_KTS_IFC_KEYGEN_METHOD, AMVP_KTS_IFC_RSAKPG1_BASIC);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kts_ifc_set_parm(ctx, AMVP_KTS_IFC, AMVP_KTS_IFC_KEYGEN_METHOD, AMVP_KTS_IFC_RSAKPG2_BASIC);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kts_ifc_set_parm(ctx, AMVP_KTS_IFC, AMVP_KTS_IFC_KEYGEN_METHOD, AMVP_KTS_IFC_RSAKPG1_PRIME_FACTOR);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kts_ifc_set_parm(ctx, AMVP_KTS_IFC, AMVP_KTS_IFC_KEYGEN_METHOD, AMVP_KTS_IFC_RSAKPG2_PRIME_FACTOR);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kts_ifc_set_parm(ctx, AMVP_KTS_IFC, AMVP_KTS_IFC_KEYGEN_METHOD, AMVP_KTS_IFC_RSAKPG1_CRT);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kts_ifc_set_parm(ctx, AMVP_KTS_IFC, AMVP_KTS_IFC_KEYGEN_METHOD, AMVP_KTS_IFC_RSAKPG2_CRT);
    CHECK_ENABLE_CAP_RV(rv);
#else
    rv = amvp_cap_kts_ifc_set_parm(ctx, AMVP_KTS_IFC, AMVP_KTS_IFC_KEYGEN_METHOD, AMVP_KTS_IFC_RSAKPG1_BASIC);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = amvp_cap_kts_ifc_set_parm(ctx, AMVP_KTS_IFC, AMVP_KTS_IFC_SCHEME, AMVP_KTS_IFC_KAS1_BASIC);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kts_ifc_set_scheme_parm(ctx, AMVP_KTS_IFC, AMVP_KTS_IFC_KAS1_BASIC, AMVP_KTS_IFC_ROLE, AMVP_KTS_IFC_RESPONDER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kts_ifc_set_scheme_parm(ctx, AMVP_KTS_IFC, AMVP_KTS_IFC_KAS1_BASIC, AMVP_KTS_IFC_ROLE, AMVP_KTS_IFC_INITIATOR);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kts_ifc_set_scheme_parm(ctx, AMVP_KTS_IFC, AMVP_KTS_IFC_KAS1_BASIC, AMVP_KTS_IFC_HASH, AMVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = amvp_cap_kts_ifc_set_scheme_parm(ctx, AMVP_KTS_IFC, AMVP_KTS_IFC_KAS1_BASIC, AMVP_KTS_IFC_HASH, AMVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kts_ifc_set_scheme_parm(ctx, AMVP_KTS_IFC, AMVP_KTS_IFC_KAS1_BASIC, AMVP_KTS_IFC_HASH, AMVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kts_ifc_set_scheme_parm(ctx, AMVP_KTS_IFC, AMVP_KTS_IFC_KAS1_BASIC, AMVP_KTS_IFC_HASH, AMVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kts_ifc_set_scheme_parm(ctx, AMVP_KTS_IFC, AMVP_KTS_IFC_KAS1_BASIC, AMVP_KTS_IFC_HASH, AMVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kts_ifc_set_scheme_parm(ctx, AMVP_KTS_IFC, AMVP_KTS_IFC_KAS1_BASIC, AMVP_KTS_IFC_HASH, AMVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kts_ifc_set_scheme_parm(ctx, AMVP_KTS_IFC, AMVP_KTS_IFC_KAS1_BASIC, AMVP_KTS_IFC_HASH, AMVP_SHA3_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kts_ifc_set_scheme_parm(ctx, AMVP_KTS_IFC, AMVP_KTS_IFC_KAS1_BASIC, AMVP_KTS_IFC_HASH, AMVP_SHA3_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kts_ifc_set_scheme_parm(ctx, AMVP_KTS_IFC, AMVP_KTS_IFC_KAS1_BASIC, AMVP_KTS_IFC_HASH, AMVP_SHA3_384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kts_ifc_set_scheme_parm(ctx, AMVP_KTS_IFC, AMVP_KTS_IFC_KAS1_BASIC, AMVP_KTS_IFC_HASH, AMVP_SHA3_512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kts_ifc_set_scheme_parm(ctx, AMVP_KTS_IFC, AMVP_KTS_IFC_KAS1_BASIC, AMVP_KTS_IFC_L, 1024);
    CHECK_ENABLE_CAP_RV(rv);
#else
    rv = amvp_cap_kts_ifc_set_scheme_parm(ctx, AMVP_KTS_IFC, AMVP_KTS_IFC_KAS1_BASIC, AMVP_KTS_IFC_L, 512);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = amvp_cap_kts_ifc_set_scheme_parm(ctx, AMVP_KTS_IFC, AMVP_KTS_IFC_KAS1_BASIC, AMVP_KTS_IFC_NULL_ASSOC_DATA, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kts_ifc_set_scheme_string(ctx, AMVP_KTS_IFC, AMVP_KTS_IFC_KAS1_BASIC, AMVP_KTS_IFC_ENCODING, concatenation);
    CHECK_ENABLE_CAP_RV(rv);

end:
    if (expo_str) free(expo_str);
    return rv;
}
#endif

#if !defined OPENSSL_NO_DSA && OPENSSL_VERSION_NUMBER >= 0x30000000L
static int enable_kas_ffc(AMVP_CTX *ctx) {
    AMVP_RESULT rv = AMVP_SUCCESS;

#ifdef AMVP_ENABLE_DEPRECATED_VERSION
    /* Enable KAS-FFC.... */
    rv = amvp_cap_kas_ffc_enable(ctx, AMVP_KAS_FFC_COMP, &app_kas_ffc_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ffc_set_prereq(ctx, AMVP_KAS_FFC_COMP, AMVP_KAS_FFC_MODE_NONE, AMVP_PREREQ_SAFE_PRIMES, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ffc_set_prereq(ctx, AMVP_KAS_FFC_COMP, AMVP_KAS_FFC_MODE_COMPONENT, AMVP_PREREQ_DSA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ffc_set_prereq(ctx, AMVP_KAS_FFC_COMP, AMVP_KAS_FFC_MODE_COMPONENT, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ffc_set_prereq(ctx, AMVP_KAS_FFC_COMP, AMVP_KAS_FFC_MODE_COMPONENT, AMVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ffc_set_prereq(ctx, AMVP_KAS_FFC_COMP, AMVP_KAS_FFC_MODE_COMPONENT, AMVP_PREREQ_CCM, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ffc_set_prereq(ctx, AMVP_KAS_FFC_COMP, AMVP_KAS_FFC_MODE_COMPONENT, AMVP_PREREQ_CMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ffc_set_prereq(ctx, AMVP_KAS_FFC_COMP, AMVP_KAS_FFC_MODE_COMPONENT, AMVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ffc_set_parm(ctx, AMVP_KAS_FFC_COMP, AMVP_KAS_FFC_MODE_COMPONENT, AMVP_KAS_FFC_FUNCTION, AMVP_KAS_FFC_FUNC_DPGEN);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ffc_set_parm(ctx, AMVP_KAS_FFC_COMP, AMVP_KAS_FFC_MODE_COMPONENT, AMVP_KAS_FFC_FUNCTION, AMVP_KAS_FFC_FUNC_DPVAL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ffc_set_scheme(ctx, AMVP_KAS_FFC_COMP, AMVP_KAS_FFC_MODE_COMPONENT, AMVP_KAS_FFC_DH_EPHEMERAL, AMVP_KAS_FFC_ROLE, AMVP_KAS_FFC_ROLE_INITIATOR);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ffc_set_scheme(ctx, AMVP_KAS_FFC_COMP, AMVP_KAS_FFC_MODE_COMPONENT, AMVP_KAS_FFC_DH_EPHEMERAL, AMVP_KAS_FFC_ROLE, AMVP_KAS_FFC_ROLE_RESPONDER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ffc_set_scheme(ctx, AMVP_KAS_FFC_COMP, AMVP_KAS_FFC_MODE_COMPONENT, AMVP_KAS_FFC_DH_EPHEMERAL, AMVP_KAS_FFC_KDF, AMVP_KAS_FFC_NOKDFNOKC);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ffc_set_scheme(ctx, AMVP_KAS_FFC_COMP, AMVP_KAS_FFC_MODE_COMPONENT, AMVP_KAS_FFC_DH_EPHEMERAL, AMVP_KAS_FFC_FB, AMVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ffc_set_scheme(ctx, AMVP_KAS_FFC_COMP, AMVP_KAS_FFC_MODE_COMPONENT, AMVP_KAS_FFC_DH_EPHEMERAL, AMVP_KAS_FFC_FC, AMVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ffc_set_scheme(ctx, AMVP_KAS_FFC_COMP, AMVP_KAS_FFC_MODE_COMPONENT, AMVP_KAS_FFC_DH_EPHEMERAL, AMVP_KAS_FFC_FB, AMVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
#endif

    rv = amvp_cap_kas_ffc_enable(ctx, AMVP_KAS_FFC_SSC, &app_kas_ffc_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ffc_set_prereq(ctx, AMVP_KAS_FFC_SSC, AMVP_KAS_FFC_MODE_NONE, AMVP_PREREQ_SAFE_PRIMES, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ffc_set_prereq(ctx, AMVP_KAS_FFC_SSC, AMVP_KAS_FFC_MODE_NONE, AMVP_PREREQ_DSA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ffc_set_prereq(ctx, AMVP_KAS_FFC_SSC, AMVP_KAS_FFC_MODE_NONE, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ffc_set_prereq(ctx, AMVP_KAS_FFC_SSC, AMVP_KAS_FFC_MODE_NONE, AMVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
#if 0
    rv = amvp_cap_kas_ffc_set_prereq(ctx, AMVP_KAS_FFC_SSC, AMVP_KAS_FFC_MODE_NONE, AMVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = amvp_cap_kas_ffc_set_scheme(ctx, AMVP_KAS_FFC_SSC, AMVP_KAS_FFC_MODE_NONE, AMVP_KAS_FFC_DH_EPHEMERAL, AMVP_KAS_FFC_ROLE, AMVP_KAS_FFC_ROLE_INITIATOR);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ffc_set_scheme(ctx, AMVP_KAS_FFC_SSC, AMVP_KAS_FFC_MODE_NONE, AMVP_KAS_FFC_DH_EPHEMERAL, AMVP_KAS_FFC_ROLE, AMVP_KAS_FFC_ROLE_RESPONDER);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ffc_set_parm(ctx, AMVP_KAS_FFC_SSC, AMVP_KAS_FFC_MODE_NONE, AMVP_KAS_FFC_GEN_METH, AMVP_KAS_FFC_FC);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ffc_set_parm(ctx, AMVP_KAS_FFC_SSC, AMVP_KAS_FFC_MODE_NONE, AMVP_KAS_FFC_GEN_METH, AMVP_KAS_FFC_FB);
    CHECK_ENABLE_CAP_RV(rv);
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    rv = amvp_cap_kas_ffc_set_parm(ctx, AMVP_KAS_FFC_SSC, AMVP_KAS_FFC_MODE_NONE, AMVP_KAS_FFC_GEN_METH, AMVP_KAS_FFC_MODP2048);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ffc_set_parm(ctx, AMVP_KAS_FFC_SSC, AMVP_KAS_FFC_MODE_NONE, AMVP_KAS_FFC_GEN_METH, AMVP_KAS_FFC_MODP3072);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ffc_set_parm(ctx, AMVP_KAS_FFC_SSC, AMVP_KAS_FFC_MODE_NONE, AMVP_KAS_FFC_GEN_METH, AMVP_KAS_FFC_MODP4096);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ffc_set_parm(ctx, AMVP_KAS_FFC_SSC, AMVP_KAS_FFC_MODE_NONE, AMVP_KAS_FFC_GEN_METH, AMVP_KAS_FFC_MODP6144);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ffc_set_parm(ctx, AMVP_KAS_FFC_SSC, AMVP_KAS_FFC_MODE_NONE, AMVP_KAS_FFC_GEN_METH, AMVP_KAS_FFC_MODP8192);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = amvp_cap_kas_ffc_set_parm(ctx, AMVP_KAS_FFC_SSC, AMVP_KAS_FFC_MODE_NONE, AMVP_KAS_FFC_GEN_METH, AMVP_KAS_FFC_FFDHE2048);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ffc_set_parm(ctx, AMVP_KAS_FFC_SSC, AMVP_KAS_FFC_MODE_NONE, AMVP_KAS_FFC_GEN_METH, AMVP_KAS_FFC_FFDHE3072);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ffc_set_parm(ctx, AMVP_KAS_FFC_SSC, AMVP_KAS_FFC_MODE_NONE, AMVP_KAS_FFC_GEN_METH, AMVP_KAS_FFC_FFDHE4096);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ffc_set_parm(ctx, AMVP_KAS_FFC_SSC, AMVP_KAS_FFC_MODE_NONE, AMVP_KAS_FFC_GEN_METH, AMVP_KAS_FFC_FFDHE6144);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kas_ffc_set_parm(ctx, AMVP_KAS_FFC_SSC, AMVP_KAS_FFC_MODE_NONE, AMVP_KAS_FFC_GEN_METH, AMVP_KAS_FFC_FFDHE8192);
    CHECK_ENABLE_CAP_RV(rv);
end:

    return rv;
}
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static int enable_kda(AMVP_CTX *ctx) {
    AMVP_RESULT rv = AMVP_SUCCESS;

    rv = amvp_cap_kda_enable(ctx, AMVP_KDA_HKDF, &app_kda_hkdf_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDA_HKDF, AMVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
#if 0 /* example of how hybrid secret usage can be registered */
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_HKDF, AMVP_KDA_USE_HYBRID_SECRET, 512, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_HKDF, AMVP_KDA_USE_HYBRID_SECRET, 520, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_domain(ctx, AMVP_KDA_HKDF, AMVP_KDA_USE_HYBRID_SECRET, 1024, 4096, 8);
    CHECK_ENABLE_CAP_RV(rv);
#endif
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_HKDF, AMVP_KDA_PATTERN, AMVP_KDA_PATTERN_ALGID, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_HKDF, AMVP_KDA_PATTERN, AMVP_KDA_PATTERN_L, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_HKDF, AMVP_KDA_PATTERN, AMVP_KDA_PATTERN_UPARTYINFO, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_HKDF, AMVP_KDA_PATTERN, AMVP_KDA_PATTERN_VPARTYINFO, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_HKDF, AMVP_KDA_MAC_ALG, AMVP_SHA1, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_domain(ctx, AMVP_KDA_HKDF, AMVP_KDA_Z, 224, 8192, 8);
    CHECK_ENABLE_CAP_RV(rv);
#else
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_HKDF, AMVP_KDA_REVISION, AMVP_REVISION_SP800_56CR1, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_HKDF, AMVP_KDA_PATTERN, AMVP_KDA_PATTERN_LITERAL, "0123456789ABCDEF");
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_HKDF, AMVP_KDA_PATTERN, AMVP_KDA_PATTERN_UPARTYINFO, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_HKDF, AMVP_KDA_PATTERN, AMVP_KDA_PATTERN_VPARTYINFO, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_HKDF, AMVP_KDA_PATTERN, AMVP_KDA_PATTERN_CONTEXT, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_HKDF, AMVP_KDA_PATTERN, AMVP_KDA_PATTERN_ALGID, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_HKDF, AMVP_KDA_PATTERN, AMVP_KDA_PATTERN_LABEL, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_HKDF, AMVP_KDA_PATTERN, AMVP_KDA_PATTERN_L, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_domain(ctx, AMVP_KDA_HKDF, AMVP_KDA_Z, 224, 1024, 8);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_HKDF, AMVP_KDA_ENCODING_TYPE, AMVP_KDA_ENCODING_CONCAT, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_HKDF, AMVP_KDA_MAC_ALG, AMVP_SHA224, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_HKDF, AMVP_KDA_MAC_ALG, AMVP_SHA256, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_HKDF, AMVP_KDA_MAC_ALG, AMVP_SHA384, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_HKDF, AMVP_KDA_MAC_ALG, AMVP_SHA512, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_HKDF, AMVP_KDA_MAC_ALG, AMVP_SHA512_224, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_HKDF, AMVP_KDA_MAC_ALG, AMVP_SHA512_256, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_HKDF, AMVP_KDA_MAC_ALG, AMVP_SHA3_224, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_HKDF, AMVP_KDA_MAC_ALG, AMVP_SHA3_256, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_HKDF, AMVP_KDA_MAC_ALG, AMVP_SHA3_384, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_HKDF, AMVP_KDA_MAC_ALG, AMVP_SHA3_512, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_HKDF, AMVP_KDA_MAC_SALT, AMVP_KDA_MAC_SALT_METHOD_DEFAULT, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_HKDF, AMVP_KDA_MAC_SALT, AMVP_KDA_MAC_SALT_METHOD_RANDOM, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_HKDF, AMVP_KDA_L, 2048, NULL);
    CHECK_ENABLE_CAP_RV(rv);

    // kdf onestep
    rv = amvp_cap_kda_enable(ctx, AMVP_KDA_ONESTEP, &app_kda_onestep_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDA_ONESTEP, AMVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDA_ONESTEP, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDA_ONESTEP, AMVP_PREREQ_KMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_PATTERN, AMVP_KDA_PATTERN_ALGID, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_PATTERN, AMVP_KDA_PATTERN_L, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_PATTERN, AMVP_KDA_PATTERN_UPARTYINFO, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_PATTERN, AMVP_KDA_PATTERN_VPARTYINFO, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_ONESTEP_AUX_FUNCTION, AMVP_HASH_SHA512, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_ONESTEP_AUX_FUNCTION, AMVP_HMAC_SHA2_224, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_ONESTEP_AUX_FUNCTION, AMVP_KMAC_128, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_domain(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_Z, 224, 8192, 8);
    CHECK_ENABLE_CAP_RV(rv);
#else
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_REVISION, AMVP_REVISION_SP800_56CR1, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_PATTERN, AMVP_KDA_PATTERN_LITERAL, "0123456789ABCDEF");
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_PATTERN, AMVP_KDA_PATTERN_UPARTYINFO, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_PATTERN, AMVP_KDA_PATTERN_VPARTYINFO, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_PATTERN, AMVP_KDA_PATTERN_CONTEXT, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_PATTERN, AMVP_KDA_PATTERN_ALGID, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_PATTERN, AMVP_KDA_PATTERN_LABEL, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_PATTERN, AMVP_KDA_PATTERN_L, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_ONESTEP_AUX_FUNCTION, AMVP_HASH_SHA224, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_ONESTEP_AUX_FUNCTION, AMVP_HASH_SHA256, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_ONESTEP_AUX_FUNCTION, AMVP_HASH_SHA384, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_ONESTEP_AUX_FUNCTION, AMVP_HASH_SHA512, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_ONESTEP_AUX_FUNCTION, AMVP_HASH_SHA512_224, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_ONESTEP_AUX_FUNCTION, AMVP_HASH_SHA512_256, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_ONESTEP_AUX_FUNCTION, AMVP_HASH_SHA3_224, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_ONESTEP_AUX_FUNCTION, AMVP_HASH_SHA3_256, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_ONESTEP_AUX_FUNCTION, AMVP_HASH_SHA3_384, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_ONESTEP_AUX_FUNCTION, AMVP_HASH_SHA3_512, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_ONESTEP_AUX_FUNCTION, AMVP_HMAC_SHA2_224, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_ONESTEP_AUX_FUNCTION, AMVP_HMAC_SHA2_256, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_ONESTEP_AUX_FUNCTION, AMVP_HMAC_SHA2_384, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_ONESTEP_AUX_FUNCTION, AMVP_HMAC_SHA2_512, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_ONESTEP_AUX_FUNCTION, AMVP_HMAC_SHA2_512_224, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_ONESTEP_AUX_FUNCTION, AMVP_HMAC_SHA2_512_256, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_ONESTEP_AUX_FUNCTION, AMVP_HMAC_SHA3_224, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_ONESTEP_AUX_FUNCTION, AMVP_HMAC_SHA3_256, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_ONESTEP_AUX_FUNCTION, AMVP_HMAC_SHA3_384, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_ONESTEP_AUX_FUNCTION, AMVP_HMAC_SHA3_512, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_domain(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_Z, 224, 1024, 8);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_ENCODING_TYPE, AMVP_KDA_ENCODING_CONCAT, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_MAC_SALT, AMVP_KDA_MAC_SALT_METHOD_DEFAULT, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_MAC_SALT, AMVP_KDA_MAC_SALT_METHOD_RANDOM, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_set_parm(ctx, AMVP_KDA_ONESTEP, AMVP_KDA_L, 2048, NULL);
    CHECK_ENABLE_CAP_RV(rv);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = amvp_cap_kda_enable(ctx, AMVP_KDA_TWOSTEP, &app_kda_twostep_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDA_TWOSTEP, AMVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);
#if 0 /* example of how hybrid secret usage can be registered */
    rv = amvp_cap_kda_twostep_set_parm(ctx, AMVP_KDA_USE_HYBRID_SECRET, 512, 0, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_twostep_set_parm(ctx, AMVP_KDA_USE_HYBRID_SECRET, 520, 0, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_twostep_set_domain(ctx, AMVP_KDA_USE_HYBRID_SECRET, 1024, 4096, 8, 0);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = amvp_cap_kda_twostep_set_parm(ctx, AMVP_KDA_L, 2048, 0, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_twostep_set_domain(ctx, AMVP_KDA_Z, 224, 8192, 8, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_twostep_set_parm(ctx, AMVP_KDA_PATTERN, AMVP_KDA_PATTERN_ALGID, 0, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_twostep_set_parm(ctx, AMVP_KDA_PATTERN, AMVP_KDA_PATTERN_L, 0, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_twostep_set_parm(ctx, AMVP_KDA_PATTERN, AMVP_KDA_PATTERN_UPARTYINFO, 0, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_twostep_set_parm(ctx, AMVP_KDA_PATTERN, AMVP_KDA_PATTERN_VPARTYINFO, 0, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_twostep_set_parm(ctx, AMVP_KDA_ENCODING_TYPE, AMVP_KDA_ENCODING_CONCAT, AMVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_twostep_set_parm(ctx, AMVP_KDA_MAC_SALT, AMVP_KDA_MAC_SALT_METHOD_DEFAULT, AMVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_twostep_set_parm(ctx, AMVP_KDA_MAC_SALT, AMVP_KDA_MAC_SALT_METHOD_RANDOM, AMVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);

    /* Most parameters are set in groups based on the KDF108 mode */
    rv = amvp_cap_kda_twostep_set_parm(ctx, AMVP_KDA_MAC_ALG, AMVP_KDF108_MAC_MODE_HMAC_SHA1, AMVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_twostep_set_parm(ctx, AMVP_KDA_MAC_ALG, AMVP_KDF108_MAC_MODE_HMAC_SHA224, AMVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_twostep_set_parm(ctx, AMVP_KDA_MAC_ALG, AMVP_KDF108_MAC_MODE_HMAC_SHA256, AMVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_twostep_set_parm(ctx, AMVP_KDA_MAC_ALG, AMVP_KDF108_MAC_MODE_HMAC_SHA384, AMVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_twostep_set_parm(ctx, AMVP_KDA_MAC_ALG, AMVP_KDF108_MAC_MODE_HMAC_SHA512, AMVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_twostep_set_parm(ctx, AMVP_KDA_MAC_ALG, AMVP_KDF108_MAC_MODE_HMAC_SHA512_224, AMVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_twostep_set_parm(ctx, AMVP_KDA_MAC_ALG, AMVP_KDF108_MAC_MODE_HMAC_SHA512_256, AMVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_twostep_set_parm(ctx, AMVP_KDA_MAC_ALG, AMVP_KDF108_MAC_MODE_HMAC_SHA3_224, AMVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_twostep_set_parm(ctx, AMVP_KDA_MAC_ALG, AMVP_KDF108_MAC_MODE_HMAC_SHA3_256, AMVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_twostep_set_parm(ctx, AMVP_KDA_MAC_ALG, AMVP_KDF108_MAC_MODE_HMAC_SHA3_384, AMVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_twostep_set_parm(ctx, AMVP_KDA_MAC_ALG, AMVP_KDF108_MAC_MODE_HMAC_SHA3_512, AMVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_twostep_set_parm(ctx, AMVP_KDA_TWOSTEP_FIXED_DATA_ORDER, AMVP_KDF108_FIXED_DATA_ORDER_AFTER, AMVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_twostep_set_parm(ctx, AMVP_KDA_TWOSTEP_COUNTER_LEN, 8, AMVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_twostep_set_parm(ctx, AMVP_KDA_TWOSTEP_SUPPORTS_EMPTY_IV, 1, AMVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_twostep_set_parm(ctx, AMVP_KDA_TWOSTEP_REQUIRES_EMPTY_IV, 1, AMVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_kda_twostep_set_parm(ctx, AMVP_KDA_TWOSTEP_SUPPORTED_LEN, 2048, AMVP_KDF108_MODE_FEEDBACK, NULL);
    CHECK_ENABLE_CAP_RV(rv);
#endif

end:
   return rv;
}
#endif

#if !defined OPENSSL_NO_DSA && OPENSSL_VERSION_NUMBER >= 0x30000000L
static int enable_dsa(AMVP_CTX *ctx) {
    AMVP_RESULT rv = AMVP_SUCCESS;

    /* Enable DSA.... */
    rv = amvp_cap_dsa_enable(ctx, AMVP_DSA_PQGGEN, &app_dsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_DSA_PQGGEN, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_DSA_PQGGEN, AMVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_GENPQ, AMVP_DSA_PROBABLE);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_GENG, AMVP_DSA_CANONICAL);
    CHECK_ENABLE_CAP_RV(rv);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_GENG, AMVP_DSA_UNVERIFIABLE);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_LN2048_224, AMVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_LN2048_224, AMVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_LN2048_224, AMVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_LN2048_224, AMVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_LN2048_256, AMVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_LN2048_256, AMVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_LN2048_256, AMVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_LN3072_256, AMVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_LN3072_256, AMVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_LN3072_256, AMVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_LN2048_224, AMVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_LN2048_224, AMVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_LN2048_256, AMVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_LN3072_256, AMVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = amvp_cap_dsa_enable(ctx, AMVP_DSA_PQGVER, &app_dsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_DSA_PQGVER, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_DSA_PQGVER, AMVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_GENPQ, AMVP_DSA_PROBABLE);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_GENG, AMVP_DSA_CANONICAL);
    CHECK_ENABLE_CAP_RV(rv);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_GENG, AMVP_DSA_UNVERIFIABLE);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN1024_160, AMVP_SHA1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN1024_160, AMVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN1024_160, AMVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN1024_160, AMVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN1024_160, AMVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN1024_160, AMVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN1024_160, AMVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
#endif

    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN2048_224, AMVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN2048_224, AMVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN2048_224, AMVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN2048_224, AMVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN2048_256, AMVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN2048_256, AMVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN2048_256, AMVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN3072_256, AMVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN3072_256, AMVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN3072_256, AMVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN2048_224, AMVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN2048_224, AMVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN2048_256, AMVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN3072_256, AMVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = amvp_cap_dsa_enable(ctx, AMVP_DSA_KEYGEN, &app_dsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_DSA_KEYGEN, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_DSA_KEYGEN, AMVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_KEYGEN, AMVP_DSA_MODE_KEYGEN, AMVP_DSA_LN2048_224, AMVP_NO_SHA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_KEYGEN, AMVP_DSA_MODE_KEYGEN, AMVP_DSA_LN2048_256, AMVP_NO_SHA);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_KEYGEN, AMVP_DSA_MODE_KEYGEN, AMVP_DSA_LN3072_256, AMVP_NO_SHA);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_dsa_enable(ctx, AMVP_DSA_SIGGEN, &app_dsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_DSA_SIGGEN, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_DSA_SIGGEN, AMVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN2048_224, AMVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN2048_224, AMVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN2048_224, AMVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN2048_224, AMVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN2048_256, AMVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN2048_256, AMVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN2048_256, AMVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN2048_256, AMVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN3072_256, AMVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN3072_256, AMVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN3072_256, AMVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN3072_256, AMVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN2048_224, AMVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN2048_224, AMVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN2048_256, AMVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN2048_256, AMVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN3072_256, AMVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN3072_256, AMVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
#endif

    rv = amvp_cap_dsa_enable(ctx, AMVP_DSA_SIGVER, &app_dsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_DSA_SIGVER, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_DSA_SIGVER, AMVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN1024_160, AMVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN1024_160, AMVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN1024_160, AMVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN1024_160, AMVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_224, AMVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_224, AMVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_224, AMVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_224, AMVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_256, AMVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_256, AMVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_256, AMVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_256, AMVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN3072_256, AMVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN3072_256, AMVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN3072_256, AMVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN3072_256, AMVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN1024_160, AMVP_SHA1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN1024_160, AMVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN1024_160, AMVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_224, AMVP_SHA1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_224, AMVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_224, AMVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_256, AMVP_SHA1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_256, AMVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_256, AMVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN3072_256, AMVP_SHA1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN3072_256, AMVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN3072_256, AMVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);
#endif
end:

    return rv;
}
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static int enable_rsa(AMVP_CTX *ctx) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    BIGNUM *expo = NULL;
    char *expo_str = NULL;

    expo = BN_new();
    if (!expo || !BN_set_word(expo, RSA_F4)) {
        printf("oh no\n");
        return 1;
    }
    expo_str = BN_bn2hex(expo);
    BN_free(expo);

    /* Enable RSA keygen... */
    rv = amvp_cap_rsa_keygen_enable(ctx, AMVP_RSA_KEYGEN, &app_rsa_keygen_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_RSA_KEYGEN, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_RSA_KEYGEN, AMVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_keygen_set_parm(ctx, AMVP_RSA_PARM_INFO_GEN_BY_SERVER, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_keygen_set_parm(ctx, AMVP_RSA_PARM_KEY_FORMAT_CRT, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_keygen_set_parm(ctx, AMVP_RSA_PARM_PUB_EXP_MODE, AMVP_RSA_PUB_EXP_MODE_RANDOM);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_keygen_set_mode(ctx, AMVP_RSA_KEYGEN_B36);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_keygen_set_primes(ctx, AMVP_RSA_KEYGEN_B36, 2048,
                                        AMVP_RSA_PRIME_TEST, AMVP_RSA_PRIME_TEST_TBLC2);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_keygen_set_primes(ctx, AMVP_RSA_KEYGEN_B36, 3072,
                                        AMVP_RSA_PRIME_TEST, AMVP_RSA_PRIME_TEST_TBLC2);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_keygen_set_primes(ctx, AMVP_RSA_KEYGEN_B36, 4096,
                                        AMVP_RSA_PRIME_TEST, AMVP_RSA_PRIME_TEST_TBLC2);
    CHECK_ENABLE_CAP_RV(rv);

    /* Enable siggen */
    rv = amvp_cap_rsa_sig_enable(ctx, AMVP_RSA_SIGGEN, &app_rsa_sig_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_RSA_SIGGEN, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_RSA_SIGGEN, AMVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    // RSA w/ sigType: X9.31
    rv = amvp_cap_rsa_siggen_set_type(ctx, AMVP_RSA_SIG_TYPE_X931);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 2048, AMVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 2048, AMVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 2048, AMVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 3072, AMVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 3072, AMVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 3072, AMVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 4096, AMVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 4096, AMVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 4096, AMVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);

    // RSA w/ sigType: PKCS1v1.5
    rv = amvp_cap_rsa_siggen_set_type(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 2048, AMVP_SHA224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 2048, AMVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 2048, AMVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 2048, AMVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 3072, AMVP_SHA224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 3072, AMVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 3072, AMVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 3072, AMVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 4096, AMVP_SHA224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 4096, AMVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 4096, AMVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 4096, AMVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);

    // RSA w/ sigType: PKCS1PSS -- has salt
    rv = amvp_cap_rsa_siggen_set_type(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 2048, AMVP_SHA224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 2048, AMVP_SHA256, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 2048, AMVP_SHA384, 48);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 2048, AMVP_SHA512, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 3072, AMVP_SHA224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 3072, AMVP_SHA256, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 3072, AMVP_SHA384, 48);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 3072, AMVP_SHA512, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 4096, AMVP_SHA224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 4096, AMVP_SHA256, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 4096, AMVP_SHA384, 48);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 4096, AMVP_SHA512, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 2048, AMVP_SHA512_224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 2048, AMVP_SHA512_256, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 3072, AMVP_SHA512_224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 3072, AMVP_SHA512_256, 32);
    CHECK_ENABLE_CAP_RV(rv);

    /* Enable sigver */
    rv = amvp_cap_rsa_sig_enable(ctx, AMVP_RSA_SIGVER, &app_rsa_sig_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_RSA_SIGVER, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_RSA_SIGVER, AMVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_parm(ctx, AMVP_RSA_PARM_PUB_EXP_MODE, AMVP_RSA_PUB_EXP_MODE_RANDOM);
    CHECK_ENABLE_CAP_RV(rv);

    // RSA w/ sigType: X9.31
    rv = amvp_cap_rsa_sigver_set_type(ctx, AMVP_RSA_SIG_TYPE_X931);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 1024, AMVP_SHA1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 1024, AMVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 1024, AMVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 1024, AMVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 2048, AMVP_SHA1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 2048, AMVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 2048, AMVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 2048, AMVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 3072, AMVP_SHA1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 3072, AMVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 3072, AMVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 3072, AMVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 4096, AMVP_SHA1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 4096, AMVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 4096, AMVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 4096, AMVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);

    // RSA w/ sigType: PKCS1v1.5
    rv = amvp_cap_rsa_sigver_set_type(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 1024, AMVP_SHA1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 1024, AMVP_SHA224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 1024, AMVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 1024, AMVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 1024, AMVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 2048, AMVP_SHA1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 2048, AMVP_SHA224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 2048, AMVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 2048, AMVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 2048, AMVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 3072, AMVP_SHA1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 3072, AMVP_SHA224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 3072, AMVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 3072, AMVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 3072, AMVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 4096, AMVP_SHA1, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 4096, AMVP_SHA224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 4096, AMVP_SHA256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 4096, AMVP_SHA384, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 4096, AMVP_SHA512, 0);
    CHECK_ENABLE_CAP_RV(rv);

    // RSA w/ sigType: PKCS1PSS -- has salt
    rv = amvp_cap_rsa_sigver_set_type(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 1024, AMVP_SHA1, 20);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 1024, AMVP_SHA224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 1024, AMVP_SHA256, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 1024, AMVP_SHA384, 48);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 1024, AMVP_SHA512, 62);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 2048, AMVP_SHA1, 20);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 2048, AMVP_SHA224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 2048, AMVP_SHA256, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 2048, AMVP_SHA384, 48);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 2048, AMVP_SHA512, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 3072, AMVP_SHA1, 20);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 3072, AMVP_SHA224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 3072, AMVP_SHA256, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 3072, AMVP_SHA384, 48);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 3072, AMVP_SHA512, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 4096, AMVP_SHA1, 20);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 4096, AMVP_SHA224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 4096, AMVP_SHA256, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 4096, AMVP_SHA384, 48);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 4096, AMVP_SHA512, 64);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 1024, AMVP_SHA512_224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 1024, AMVP_SHA512_256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 2048, AMVP_SHA512_224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 2048, AMVP_SHA512_256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 3072, AMVP_SHA512_224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 3072, AMVP_SHA512_256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 4096, AMVP_SHA512_224, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 4096, AMVP_SHA512_256, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 1024, AMVP_SHA512_224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 1024, AMVP_SHA512_256, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 2048, AMVP_SHA512_224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 2048, AMVP_SHA512_256, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 3072, AMVP_SHA512_224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 3072, AMVP_SHA512_256, 32);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 4096, AMVP_SHA512_224, 24);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 4096, AMVP_SHA512_256, 32);
    CHECK_ENABLE_CAP_RV(rv);

#ifdef OPENSSL_RSA_PRIMITIVE /* only enable as needed, decrypt can take a long time */
    /* Enable Decryption Primitive */
    rv = amvp_cap_rsa_prim_enable(ctx, AMVP_RSA_DECPRIM, &app_rsa_decprim_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_RSA_DECPRIM, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_RSA_DECPRIM, AMVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
#endif
    /* Enable Signature Primitive */
    rv = amvp_cap_rsa_prim_enable(ctx, AMVP_RSA_SIGPRIM, &app_rsa_sigprim_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_RSA_SIGPRIM, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_RSA_SIGPRIM, AMVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_prim_set_parm(ctx, AMVP_RSA_PARM_KEY_FORMAT_CRT, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_prim_set_parm(ctx, AMVP_RSA_PARM_PUB_EXP_MODE, AMVP_RSA_PUB_EXP_MODE_FIXED);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_rsa_prim_set_exponent(ctx, AMVP_RSA_PARM_FIXED_PUB_EXP_VAL, expo_str);
    CHECK_ENABLE_CAP_RV(rv);
end:
    if (expo_str) free(expo_str);

    return rv;
}
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static int enable_ecdsa(AMVP_CTX *ctx) {
    AMVP_RESULT rv = AMVP_SUCCESS;

    /* Enable ECDSA keyGen... */
    rv = amvp_cap_ecdsa_enable(ctx, AMVP_ECDSA_KEYGEN, &app_ecdsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_ECDSA_KEYGEN, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_ECDSA_KEYGEN, AMVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P521);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K571);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B571);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYGEN, AMVP_ECDSA_SECRET_GEN, AMVP_ECDSA_SECRET_GEN_TEST_CAND);
    CHECK_ENABLE_CAP_RV(rv);

    /* Enable ECDSA keyVer... */
    rv = amvp_cap_ecdsa_enable(ctx, AMVP_ECDSA_KEYVER, &app_ecdsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_ECDSA_KEYVER, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_ECDSA_KEYVER, AMVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P521);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K571);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B571);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B163);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K163);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P192);
    CHECK_ENABLE_CAP_RV(rv);

    /* Enable ECDSA sigGen... */
    rv = amvp_cap_ecdsa_enable(ctx, AMVP_ECDSA_SIGGEN, &app_ecdsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_ECDSA_SIGGEN, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_ECDSA_SIGGEN, AMVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_COMPONENT_TEST, AMVP_ECDSA_COMPONENT_MODE_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P521);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K571);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B571);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_HASH_ALG, AMVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_HASH_ALG, AMVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_HASH_ALG, AMVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_HASH_ALG, AMVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_HASH_ALG, AMVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_HASH_ALG, AMVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);

    /* Enable ECDSA sigVer... */
    rv = amvp_cap_ecdsa_enable(ctx, AMVP_ECDSA_SIGVER, &app_ecdsa_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_ECDSA_SIGVER, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_ECDSA_SIGVER, AMVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_COMPONENT_TEST, AMVP_ECDSA_COMPONENT_MODE_BOTH);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P521);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K571);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B233);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B283);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B409);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B571);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_HASH_ALG, AMVP_SHA224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_HASH_ALG, AMVP_SHA256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_HASH_ALG, AMVP_SHA384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_HASH_ALG, AMVP_SHA512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B163);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K163);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_HASH_ALG, AMVP_SHA1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_HASH_ALG, AMVP_SHA512_224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_HASH_ALG, AMVP_SHA512_256);
    CHECK_ENABLE_CAP_RV(rv);

end:

    return rv;
}
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static int enable_drbg(AMVP_CTX *ctx) {
    AMVP_RESULT rv = AMVP_SUCCESS;

    /* Hash DRBG */
    rv = amvp_cap_drbg_enable(ctx, AMVP_HASHDRBG, &app_drbg_handler);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_set_prereq(ctx, AMVP_HASHDRBG, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);

    /* Group number for these should be 0 */
    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0, AMVP_DRBG_PRED_RESIST_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0, AMVP_DRBG_RESEED_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0, AMVP_DRBG_ENTROPY_LEN, 128, 64, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0, AMVP_DRBG_NONCE_LEN, 96, 32, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0, AMVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0, AMVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0, AMVP_DRBG_RET_BITS_LEN, 160);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_224, 0, AMVP_DRBG_ENTROPY_LEN, 192, 64, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_224, 0, AMVP_DRBG_NONCE_LEN, 128, 32, 160);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_224, 0, AMVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_224, 0, AMVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_224, 0, AMVP_DRBG_RET_BITS_LEN, 224);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_256, 0, AMVP_DRBG_ENTROPY_LEN, 256, 64, 320);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_256, 0, AMVP_DRBG_NONCE_LEN, 128, 32, 160);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_256, 0, AMVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_256, 0, AMVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_256, 0, AMVP_DRBG_RET_BITS_LEN, 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_384, 0, AMVP_DRBG_ENTROPY_LEN, 256, 64, 320);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_384, 0, AMVP_DRBG_NONCE_LEN, 128, 32, 160);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_384, 0, AMVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_384, 0, AMVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_384, 0, AMVP_DRBG_RET_BITS_LEN, 384);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_512, 0, AMVP_DRBG_ENTROPY_LEN, 256, 64, 320);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_512, 0, AMVP_DRBG_NONCE_LEN, 128, 32, 160);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_512, 0, AMVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_512, 0, AMVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_512, 0, AMVP_DRBG_RET_BITS_LEN, 512);
    CHECK_ENABLE_CAP_RV(rv);


    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_512_224, 0, AMVP_DRBG_ENTROPY_LEN, 256, 64, 320);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_512_224, 0, AMVP_DRBG_NONCE_LEN, 128, 32, 160);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_512_224, 0, AMVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_512_224, 0, AMVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_512_224, 0, AMVP_DRBG_RET_BITS_LEN, 224);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_512_256, 0, AMVP_DRBG_ENTROPY_LEN, 256, 64, 320);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_512_256, 0, AMVP_DRBG_NONCE_LEN, 128, 32, 160);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_512_256, 0, AMVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_512_256, 0, AMVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_512_256, 0, AMVP_DRBG_RET_BITS_LEN, 256);
    CHECK_ENABLE_CAP_RV(rv);

    /* HMAC DRBG */
    rv = amvp_cap_drbg_enable(ctx, AMVP_HMACDRBG, &app_drbg_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_HMACDRBG, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_HMACDRBG,AMVP_PREREQ_HMAC, value);
    CHECK_ENABLE_CAP_RV(rv);

    /* Group number for these should be 0 */
    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_1, 0, AMVP_DRBG_PRED_RESIST_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_1, 0, AMVP_DRBG_RESEED_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_1, 0, AMVP_DRBG_RET_BITS_LEN, 160);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_1, 0, AMVP_DRBG_ENTROPY_LEN, 160, 32, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_1, 0, AMVP_DRBG_NONCE_LEN, 0, 0, 64);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_1, 0, AMVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_1, 0, AMVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0, AMVP_DRBG_RET_BITS_LEN, 224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0, AMVP_DRBG_ENTROPY_LEN, 192, 64, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0, AMVP_DRBG_NONCE_LEN, 0, 0, 96);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0, AMVP_DRBG_PERSO_LEN, 0, 64, 192);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0, AMVP_DRBG_ADD_IN_LEN, 0, 0, 192);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_256, 0, AMVP_DRBG_RET_BITS_LEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_256, 0, AMVP_DRBG_ENTROPY_LEN, 256, 64, 512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_256, 0, AMVP_DRBG_NONCE_LEN, 0, 0, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_256, 0, AMVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_256, 0, AMVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_384, 0, AMVP_DRBG_RET_BITS_LEN, 384);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_384, 0, AMVP_DRBG_ENTROPY_LEN, 384, 64, 512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_384, 0, AMVP_DRBG_NONCE_LEN, 0, 0, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_384, 0, AMVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_384, 0, AMVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_512, 0, AMVP_DRBG_RET_BITS_LEN, 512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_512, 0, AMVP_DRBG_ENTROPY_LEN, 512, 64, 1024);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_512, 0, AMVP_DRBG_NONCE_LEN, 0, 0, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_512, 0, AMVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_512, 0, AMVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_512_224, 0, AMVP_DRBG_RET_BITS_LEN, 224);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_512_224, 0, AMVP_DRBG_ENTROPY_LEN, 512, 64, 1024);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_512_224, 0, AMVP_DRBG_NONCE_LEN, 0, 0, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_512_224, 0, AMVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_512_224, 0, AMVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_512_256, 0, AMVP_DRBG_RET_BITS_LEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_512_256, 0, AMVP_DRBG_ENTROPY_LEN, 512, 64, 1024);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_512_256, 0, AMVP_DRBG_NONCE_LEN, 0, 0, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_512_256, 0, AMVP_DRBG_PERSO_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_512_256, 0, AMVP_DRBG_ADD_IN_LEN, 0, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);

    /* CTR DRBG */
    rv = amvp_cap_drbg_enable(ctx, AMVP_CTRDRBG, &app_drbg_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_CTRDRBG, AMVP_PREREQ_AES, value);
    CHECK_ENABLE_CAP_RV(rv);

    /* Group number for these should be 0 */
    rv = amvp_cap_drbg_set_parm(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0, AMVP_DRBG_DER_FUNC_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_parm(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0, AMVP_DRBG_PRED_RESIST_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0, AMVP_DRBG_RESEED_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_parm(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0, AMVP_DRBG_RET_BITS_LEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0, AMVP_DRBG_ENTROPY_LEN, 128, 128, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0, AMVP_DRBG_NONCE_LEN, 0, 0, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0, AMVP_DRBG_PERSO_LEN, 0, 256, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0, AMVP_DRBG_ADD_IN_LEN, 0, 256, 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 1, AMVP_DRBG_DER_FUNC_ENABLED, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_parm(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 1, AMVP_DRBG_RET_BITS_LEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 1, AMVP_DRBG_ENTROPY_LEN, 256, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 1, AMVP_DRBG_NONCE_LEN, 0, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 1, AMVP_DRBG_PERSO_LEN, 256, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 1, AMVP_DRBG_ADD_IN_LEN, 256, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_192, 0, AMVP_DRBG_DER_FUNC_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_parm(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_192, 0, AMVP_DRBG_RET_BITS_LEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_192, 0, AMVP_DRBG_ENTROPY_LEN, 256, 128, 512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_192, 0, AMVP_DRBG_NONCE_LEN, 0, 0, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_192, 0, AMVP_DRBG_PERSO_LEN, 0, 256, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_192, 0, AMVP_DRBG_ADD_IN_LEN, 0, 256, 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_192, 1, AMVP_DRBG_DER_FUNC_ENABLED, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_parm(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_192, 1, AMVP_DRBG_RET_BITS_LEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_192, 1, AMVP_DRBG_ENTROPY_LEN, 320, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_192, 1, AMVP_DRBG_NONCE_LEN, 0, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_192, 1, AMVP_DRBG_PERSO_LEN, 320, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_192, 1, AMVP_DRBG_ADD_IN_LEN, 320, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_256, 0, AMVP_DRBG_DER_FUNC_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_parm(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_256, 0, AMVP_DRBG_PRED_RESIST_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_parm(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_256, 0, AMVP_DRBG_RESEED_ENABLED, 1);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_parm(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_256, 0, AMVP_DRBG_RET_BITS_LEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_256, 0, AMVP_DRBG_ENTROPY_LEN, 256, 128, 512);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_256, 0, AMVP_DRBG_NONCE_LEN, 0, 0, 128);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_256, 0, AMVP_DRBG_PERSO_LEN, 0, 256, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_256, 0, AMVP_DRBG_ADD_IN_LEN, 0, 256, 256);
    CHECK_ENABLE_CAP_RV(rv);

    rv = amvp_cap_drbg_set_parm(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_256, 1, AMVP_DRBG_DER_FUNC_ENABLED, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_parm(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_256, 1, AMVP_DRBG_RET_BITS_LEN, 256);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_256, 1, AMVP_DRBG_ENTROPY_LEN, 384, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_256, 1, AMVP_DRBG_NONCE_LEN, 0, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_256, 1, AMVP_DRBG_PERSO_LEN, 384, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_256, 1, AMVP_DRBG_ADD_IN_LEN, 384, 0, 0);
    CHECK_ENABLE_CAP_RV(rv);
end:
    return rv;
}
#endif

#if !defined OPENSSL_NO_DSA && OPENSSL_VERSION_NUMBER >= 0x30000000L
static int enable_safe_primes(AMVP_CTX *ctx) {
    AMVP_RESULT rv = AMVP_SUCCESS;

    /* Register Safe Prime Key Generation testing */
    rv = amvp_cap_safe_primes_enable(ctx, AMVP_SAFE_PRIMES_KEYGEN, &app_safe_primes_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_SAFE_PRIMES_KEYGEN, AMVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_SAFE_PRIMES_KEYGEN, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_safe_primes_set_parm(ctx, AMVP_SAFE_PRIMES_KEYGEN, AMVP_SAFE_PRIMES_GENMETH, AMVP_SAFE_PRIMES_FFDHE2048);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_safe_primes_set_parm(ctx, AMVP_SAFE_PRIMES_KEYGEN, AMVP_SAFE_PRIMES_GENMETH, AMVP_SAFE_PRIMES_FFDHE3072);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_safe_primes_set_parm(ctx, AMVP_SAFE_PRIMES_KEYGEN, AMVP_SAFE_PRIMES_GENMETH, AMVP_SAFE_PRIMES_FFDHE4096);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_safe_primes_set_parm(ctx, AMVP_SAFE_PRIMES_KEYGEN, AMVP_SAFE_PRIMES_GENMETH, AMVP_SAFE_PRIMES_FFDHE6144);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_safe_primes_set_parm(ctx, AMVP_SAFE_PRIMES_KEYGEN, AMVP_SAFE_PRIMES_GENMETH, AMVP_SAFE_PRIMES_FFDHE8192);
    CHECK_ENABLE_CAP_RV(rv);
#if 0 /* These should probably be enabled, but missing from OpenSSL cert */
    rv = amvp_cap_safe_primes_set_parm(ctx, AMVP_SAFE_PRIMES_KEYGEN, AMVP_SAFE_PRIMES_GENMETH, AMVP_SAFE_PRIMES_MODP2048);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_safe_primes_set_parm(ctx, AMVP_SAFE_PRIMES_KEYGEN, AMVP_SAFE_PRIMES_GENMETH, AMVP_SAFE_PRIMES_MODP3072);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_safe_primes_set_parm(ctx, AMVP_SAFE_PRIMES_KEYGEN, AMVP_SAFE_PRIMES_GENMETH, AMVP_SAFE_PRIMES_MODP4096);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_safe_primes_set_parm(ctx, AMVP_SAFE_PRIMES_KEYGEN, AMVP_SAFE_PRIMES_GENMETH, AMVP_SAFE_PRIMES_MODP6144);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_safe_primes_set_parm(ctx, AMVP_SAFE_PRIMES_KEYGEN, AMVP_SAFE_PRIMES_GENMETH, AMVP_SAFE_PRIMES_MODP8192);
    CHECK_ENABLE_CAP_RV(rv);
#endif

    /* Register Safe Prime Key Verify testing */
    rv = amvp_cap_safe_primes_enable(ctx, AMVP_SAFE_PRIMES_KEYVER, &app_safe_primes_handler);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_SAFE_PRIMES_KEYVER, AMVP_PREREQ_DRBG, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_set_prereq(ctx, AMVP_SAFE_PRIMES_KEYVER, AMVP_PREREQ_SHA, value);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_safe_primes_set_parm(ctx, AMVP_SAFE_PRIMES_KEYVER, AMVP_SAFE_PRIMES_GENMETH, AMVP_SAFE_PRIMES_FFDHE2048);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_safe_primes_set_parm(ctx, AMVP_SAFE_PRIMES_KEYVER, AMVP_SAFE_PRIMES_GENMETH, AMVP_SAFE_PRIMES_FFDHE3072);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_safe_primes_set_parm(ctx, AMVP_SAFE_PRIMES_KEYVER, AMVP_SAFE_PRIMES_GENMETH, AMVP_SAFE_PRIMES_FFDHE4096);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_safe_primes_set_parm(ctx, AMVP_SAFE_PRIMES_KEYVER, AMVP_SAFE_PRIMES_GENMETH, AMVP_SAFE_PRIMES_FFDHE6144);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_safe_primes_set_parm(ctx, AMVP_SAFE_PRIMES_KEYVER, AMVP_SAFE_PRIMES_GENMETH, AMVP_SAFE_PRIMES_FFDHE8192);
    CHECK_ENABLE_CAP_RV(rv);
#if 0 /* These should probably be enabled, but missing from OpenSSL cert */
    rv = amvp_cap_safe_primes_set_parm(ctx, AMVP_SAFE_PRIMES_KEYVER, AMVP_SAFE_PRIMES_GENMETH, AMVP_SAFE_PRIMES_MODP2048);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_safe_primes_set_parm(ctx, AMVP_SAFE_PRIMES_KEYVER, AMVP_SAFE_PRIMES_GENMETH, AMVP_SAFE_PRIMES_MODP3072);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_safe_primes_set_parm(ctx, AMVP_SAFE_PRIMES_KEYVER, AMVP_SAFE_PRIMES_GENMETH, AMVP_SAFE_PRIMES_MODP4096);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_safe_primes_set_parm(ctx, AMVP_SAFE_PRIMES_KEYVER, AMVP_SAFE_PRIMES_GENMETH, AMVP_SAFE_PRIMES_MODP6144);
    CHECK_ENABLE_CAP_RV(rv);
    rv = amvp_cap_safe_primes_set_parm(ctx, AMVP_SAFE_PRIMES_KEYVER, AMVP_SAFE_PRIMES_GENMETH, AMVP_SAFE_PRIMES_MODP8192);
    CHECK_ENABLE_CAP_RV(rv);
#endif
end:
    return rv;
}
#endif

#ifdef AMVP_APP_LIB_WRAPPER
AMVP_RESULT amvp_app_run_vector_test_file(const char *path, const char *output, AMVP_LOG_LVL lvl, AMVP_RESULT (*logger)(char *)) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    AMVP_CTX *ctx = NULL;

    /*
     * We begin the libamvp usage flow here.
     * First, we create a test session context.
     */
    rv = amvp_create_test_session(&ctx, logger, lvl);
    if (rv != AMVP_SUCCESS) {
        printf("Failed to create AMVP context: %s\n", amvp_lookup_error_string(rv));
        goto end;
    }

    /*
    * We need to register all possible crypto capabilities; since this code
    * just performs offline testing with already requested vectors
    */
    if (enable_aes(ctx)) goto end;
    if (enable_tdes(ctx)) goto end;
    if (enable_hash(ctx)) goto end;
    if (enable_cmac(ctx)) goto end;
    if (enable_hmac(ctx)) goto end;
    if (enable_kmac(ctx)) goto end;
    if (enable_kdf(ctx)) goto end;
    if (enable_dsa(ctx)) goto end;
    if (enable_rsa(ctx)) goto end;
    if (enable_ecdsa(ctx)) goto end;
    if (enable_drbg(ctx)) goto end;
    if (enable_kas_ecc(ctx)) goto end;
    if (enable_kas_ifc(ctx)) goto end;
    if (enable_kts_ifc(ctx)) goto end;
    if (enable_kas_ffc(ctx)) goto end;
    if (enable_kda(ctx)) goto end;
    if (enable_safe_primes(ctx)) goto end;

    rv = amvp_run_vectors_from_file(ctx, path, output);

end:
    /*
     * Free all memory associated with
     * both the application and libamvp.
     */
    app_cleanup(ctx);

    return rv;
   }
#endif
