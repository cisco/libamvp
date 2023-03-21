/*
 * Copyright (c) 2021, Cisco Systems, Inc.
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
extern char value[JSON_STRING_LENGTH];

#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_RESET "\x1b[0m"

typedef struct app_config {
    AMVP_LOG_LVL level;
    int sample;
    int manual_reg;
    int vector_req;
    int vector_rsp;
    int vector_upload;
    int get;
    int get_results;
    int resume_session;
    int cancel_session;
    int post;
    int put;
    int delete;
    int kat;
    int empty_alg;
    int fips_validation;
    int get_expected;
    int save_to;
    int get_cost;
    int get_reg;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    int disable_fips;
#endif
    char reg_file[JSON_FILENAME_LENGTH + 1];
    char vector_req_file[JSON_FILENAME_LENGTH + 1];
    char vector_rsp_file[JSON_FILENAME_LENGTH + 1];
    char vector_upload_file[JSON_FILENAME_LENGTH + 1];
    char get_string[JSON_REQUEST_LENGTH + 1];
    char session_file[JSON_FILENAME_LENGTH + 1];
    char post_filename[JSON_FILENAME_LENGTH + 1];
    char put_filename[JSON_FILENAME_LENGTH + 1];
    char delete_url[JSON_REQUEST_LENGTH + 1];
    char kat_file[JSON_FILENAME_LENGTH + 1];
    char validation_metadata_file[JSON_FILENAME_LENGTH + 1];
    char save_file[JSON_FILENAME_LENGTH + 1];

    /*
     * Algorithm Flags
     * 0 is off, 1 is on
     */
    int aes; int tdes;
    int hash; int cmac; int hmac; int kmac;
    int dsa; int rsa;
    int drbg; int ecdsa;
    int kas_ecc; int kas_ffc; int kas_ifc; int kda; int kts_ifc;
    int kdf;
    int safe_primes;
    int testall; /* So the app can check whether the user indicated to test all possible algorithms */
} APP_CONFIG;


int ingest_cli(APP_CONFIG *cfg, int argc, char **argv);
int app_setup_two_factor_auth(AMVP_CTX *ctx);
unsigned int swap_uint_endian(unsigned int i);
int check_is_little_endian(void);
char *remove_str_const(const char *str);
int save_string_to_file(const char *str, const char *path);
int get_nid_for_curve(AMVP_EC_CURVE curve);
const EVP_MD *get_md_for_hash_alg(AMVP_HASH_ALG alg);
const char *get_md_string_for_hash_alg(AMVP_HASH_ALG alg, int *md_size);
char *ec_point_to_pub_key(unsigned char *x, int x_len, unsigned char *y, int y_len, int *key_len);

void app_aes_cleanup(void);
void app_des_cleanup(void);

int app_aes_handler(AMVP_TEST_CASE *test_case);
int app_aes_handler_aead(AMVP_TEST_CASE *test_case);
int app_aes_keywrap_handler(AMVP_TEST_CASE *test_case);
int app_des_handler(AMVP_TEST_CASE *test_case);
int app_sha_handler(AMVP_TEST_CASE *test_case);
int app_hmac_handler(AMVP_TEST_CASE *test_case);
int app_cmac_handler(AMVP_TEST_CASE *test_case);
int app_kmac_handler(AMVP_TEST_CASE *test_case);

#define ENGID1 "800002B805123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456"
#define ENGID2 "000002b87766554433221100"

int app_kdf135_snmp_handler(AMVP_TEST_CASE *test_case);
int app_kdf135_ssh_handler(AMVP_TEST_CASE *test_case);
int app_kdf135_srtp_handler(AMVP_TEST_CASE *test_case);
int app_kdf135_ikev2_handler(AMVP_TEST_CASE *test_case);
int app_kdf108_handler(AMVP_TEST_CASE *test_case);
int app_kdf135_ikev1_handler(AMVP_TEST_CASE *test_case);
int app_kdf135_x942_handler(AMVP_TEST_CASE *test_case);
int app_kdf135_x963_handler(AMVP_TEST_CASE *test_case);
int app_pbkdf_handler(AMVP_TEST_CASE *test_case);
int app_kdf_tls12_handler(AMVP_TEST_CASE *test_case);
int app_kdf_tls13_handler(AMVP_TEST_CASE *test_case);

void app_dsa_cleanup(void);
void app_rsa_cleanup(void);
void app_ecdsa_cleanup(void);

int app_dsa_handler(AMVP_TEST_CASE *test_case);
int app_kas_ecc_handler(AMVP_TEST_CASE *test_case);
int app_kas_ffc_handler(AMVP_TEST_CASE *test_case);
int app_kas_ifc_handler(AMVP_TEST_CASE *test_case);
int app_kda_hkdf_handler(AMVP_TEST_CASE *test_case);
int app_kda_onestep_handler(AMVP_TEST_CASE *test_case);
int app_kda_twostep_handler(AMVP_TEST_CASE *test_case);
int app_kts_ifc_handler(AMVP_TEST_CASE *test_case);
int app_rsa_keygen_handler(AMVP_TEST_CASE *test_case);
int app_rsa_sig_handler(AMVP_TEST_CASE *test_case);
int app_rsa_decprim_handler(AMVP_TEST_CASE *test_case);
int app_rsa_sigprim_handler(AMVP_TEST_CASE *test_case);
int app_ecdsa_handler(AMVP_TEST_CASE *test_case);
int app_drbg_handler(AMVP_TEST_CASE *test_case);
int app_safe_primes_handler(AMVP_TEST_CASE *test_case);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
int app_aes_handler_gmac(AMVP_TEST_CASE *test_case);
AMVP_RESULT fips_sanity_check(void);
const char *get_string_from_oid(unsigned char *oid, int oid_len);
#endif

#ifdef __cplusplus
}
#endif

#endif // LIBAMVP_APP_LCL_H

