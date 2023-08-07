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

static AMVP_RESULT amvp_process_teid(AMVP_CTX *ctx, char *vsid_url, int count);

static AMVP_RESULT amvp_cert_req(AMVP_CTX *ctx);
/*
 * Forward prototypes for local functions
 */
static AMVP_RESULT amvp_login(AMVP_CTX *ctx, int refresh);

static AMVP_RESULT amvp_validate_test_session(AMVP_CTX *ctx);

static AMVP_RESULT amvp_append_vsid_url(AMVP_CTX *ctx, const char *vsid_url);

static AMVP_RESULT amvp_parse_login(AMVP_CTX *ctx);

static AMVP_RESULT amvp_parse_test_session_register(AMVP_CTX *ctx);

static AMVP_RESULT amvp_parse_session_info_file(AMVP_CTX *ctx, const char *filename);

static AMVP_RESULT amvp_process_vsid(AMVP_CTX *ctx, char *vsid_url, int count);

static AMVP_RESULT amvp_process_vector_set(AMVP_CTX *ctx, JSON_Object *obj);

static AMVP_RESULT amvp_process_ie_set(AMVP_CTX *ctx, JSON_Object *obj);

static AMVP_RESULT amvp_dispatch_vector_set(AMVP_CTX *ctx, JSON_Object *obj);

static void amvp_cap_free_sl(AMVP_SL_LIST *list);

static void amvp_cap_free_nl(AMVP_NAME_LIST *list);

static void amvp_cap_free_pl(AMVP_PARAM_LIST *list);

static void amvp_cap_free_domain(AMVP_JSON_DOMAIN_OBJ *domain);

static void amvp_cap_free_hash_pairs(AMVP_RSA_HASH_PAIR_LIST *list);

static AMVP_RESULT amvp_get_result_test_session(AMVP_CTX *ctx, char *session_url);

static AMVP_RESULT amvp_put_data_from_ctx(AMVP_CTX *ctx);

static AMVP_RESULT amvp_retry_handler(AMVP_CTX *ctx, int *retry_period, unsigned int *waited_so_far, int modifier, AMVP_WAITING_STATUS situation);

static AMVP_RESULT amvp_handle_protocol_error(AMVP_CTX *ctx, AMVP_PROTOCOL_ERR *err);

/*
 * This table maps AMVP operations to handlers within libamvp.
 * Each AMVP operation may have unique parameters.  For instance,
 * the parameters to test RSA are different than AES.  Therefore,
 * we allow for a unique handler to be registered for each
 * AMVP operation.
 *
 * WARNING:
 * This table is not sparse, it must contain AMVP_OP_MAX entries.
 */
AMVP_ALG_HANDLER alg_tbl[AMVP_ALG_MAX] = {
    { AMVP_AES_GCM,           NULL,             AMVP_ALG_AES_GCM,           NULL, AMVP_REV_AES_GCM, {AMVP_SUB_AES_GCM}},
    { AMVP_AES_GCM_SIV,       NULL,             AMVP_ALG_AES_GCM_SIV,       NULL, AMVP_REV_AES_GCM_SIV, {AMVP_SUB_AES_GCM_SIV}},
    { AMVP_AES_CCM,           NULL,             AMVP_ALG_AES_CCM,           NULL, AMVP_REV_AES_CCM, {AMVP_SUB_AES_CCM}},
    { AMVP_AES_ECB,           NULL,             AMVP_ALG_AES_ECB,           NULL, AMVP_REV_AES_ECB, {AMVP_SUB_AES_ECB}},
    { AMVP_AES_CBC,           NULL,             AMVP_ALG_AES_CBC,           NULL, AMVP_REV_AES_CBC, {AMVP_SUB_AES_CBC}},
    { AMVP_AES_CBC_CS1,       NULL,             AMVP_ALG_AES_CBC_CS1,       NULL, AMVP_REV_AES_CBC_CS1, {AMVP_SUB_AES_CBC_CS1}},
    { AMVP_AES_CBC_CS2,       NULL,             AMVP_ALG_AES_CBC_CS2,       NULL, AMVP_REV_AES_CBC_CS2, {AMVP_SUB_AES_CBC_CS2}},
    { AMVP_AES_CBC_CS3,       NULL,             AMVP_ALG_AES_CBC_CS3,       NULL, AMVP_REV_AES_CBC_CS3, {AMVP_SUB_AES_CBC_CS3}},
    { AMVP_AES_CFB1,          NULL,             AMVP_ALG_AES_CFB1,          NULL, AMVP_REV_AES_CFB1, {AMVP_SUB_AES_CFB1}},
    { AMVP_AES_CFB8,          NULL,             AMVP_ALG_AES_CFB8,          NULL, AMVP_REV_AES_CFB8, {AMVP_SUB_AES_CFB8}},
    { AMVP_AES_CFB128,        NULL,             AMVP_ALG_AES_CFB128,        NULL, AMVP_REV_AES_CFB128, {AMVP_SUB_AES_CFB128}},
    { AMVP_AES_OFB,           NULL,             AMVP_ALG_AES_OFB,           NULL, AMVP_REV_AES_OFB, {AMVP_SUB_AES_OFB}},
    { AMVP_AES_CTR,           NULL,             AMVP_ALG_AES_CTR,           NULL, AMVP_REV_AES_CTR, {AMVP_SUB_AES_CTR}},
    { AMVP_AES_XTS,           NULL,             AMVP_ALG_AES_XTS,           NULL, AMVP_REV_AES_XTS, {AMVP_SUB_AES_XTS}},
    { AMVP_AES_KW,            NULL,             AMVP_ALG_AES_KW,            NULL, AMVP_REV_AES_KW, {AMVP_SUB_AES_KW}},
    { AMVP_AES_KWP,           NULL,             AMVP_ALG_AES_KWP,           NULL, AMVP_REV_AES_KWP, {AMVP_SUB_AES_KWP}},
    { AMVP_AES_GMAC,          NULL,             AMVP_ALG_AES_GMAC,          NULL, AMVP_REV_AES_GMAC, {AMVP_SUB_AES_GMAC}},
    { AMVP_AES_XPN,           NULL,             AMVP_ALG_AES_XPN ,          NULL, AMVP_REV_AES_XPN, {AMVP_SUB_AES_XPN}},
    { AMVP_TDES_ECB,          NULL,             AMVP_ALG_TDES_ECB,          NULL, AMVP_REV_TDES_ECB, {AMVP_SUB_TDES_ECB}},
    { AMVP_TDES_CBC,          NULL,             AMVP_ALG_TDES_CBC,          NULL, AMVP_REV_TDES_CBC, {AMVP_SUB_TDES_CBC}},
    { AMVP_TDES_CBCI,         NULL,             AMVP_ALG_TDES_CBCI,         NULL, AMVP_REV_TDES_CBCI, {AMVP_SUB_TDES_CBCI}},
    { AMVP_TDES_OFB,          NULL,             AMVP_ALG_TDES_OFB,          NULL, AMVP_REV_TDES_OFB, {AMVP_SUB_TDES_OFB}},
    { AMVP_TDES_OFBI,         NULL,             AMVP_ALG_TDES_OFBI,         NULL, AMVP_REV_TDES_OFBI, {AMVP_SUB_TDES_OFBI}},
    { AMVP_TDES_CFB1,         NULL,             AMVP_ALG_TDES_CFB1,         NULL, AMVP_REV_TDES_CFB1, {AMVP_SUB_TDES_CFB1}},
    { AMVP_TDES_CFB8,         NULL,             AMVP_ALG_TDES_CFB8,         NULL, AMVP_REV_TDES_CFB8, {AMVP_SUB_TDES_CFB8}},
    { AMVP_TDES_CFB64,        NULL,             AMVP_ALG_TDES_CFB64,        NULL, AMVP_REV_TDES_CFB64, {AMVP_SUB_TDES_CFB64}},
    { AMVP_TDES_CFBP1,        NULL,             AMVP_ALG_TDES_CFBP1,        NULL, AMVP_REV_TDES_CFBP1, {AMVP_SUB_TDES_CFBP1}},
    { AMVP_TDES_CFBP8,        NULL,             AMVP_ALG_TDES_CFBP8,        NULL, AMVP_REV_TDES_CFBP8, {AMVP_SUB_TDES_CFBP8}},
    { AMVP_TDES_CFBP64,       NULL,             AMVP_ALG_TDES_CFBP64,       NULL, AMVP_REV_TDES_CFBP64, {AMVP_SUB_TDES_CFBP64}},
    { AMVP_TDES_CTR,          NULL,             AMVP_ALG_TDES_CTR,          NULL, AMVP_REV_TDES_CTR, {AMVP_SUB_TDES_CTR}},
    { AMVP_TDES_KW,           NULL,             AMVP_ALG_TDES_KW,           NULL, AMVP_REV_TDES_KW, {AMVP_SUB_TDES_KW}},
    { AMVP_HASH_SHA1,         NULL,            AMVP_ALG_SHA1,              NULL, AMVP_REV_HASH_SHA1, {AMVP_SUB_HASH_SHA1}},
    { AMVP_HASH_SHA224,       NULL,            AMVP_ALG_SHA224,            NULL, AMVP_REV_HASH_SHA224, {AMVP_SUB_HASH_SHA2_224}},
    { AMVP_HASH_SHA256,       NULL,            AMVP_ALG_SHA256,            NULL, AMVP_REV_HASH_SHA256, {AMVP_SUB_HASH_SHA2_256}},
    { AMVP_HASH_SHA384,       NULL,            AMVP_ALG_SHA384,            NULL, AMVP_REV_HASH_SHA384, {AMVP_SUB_HASH_SHA2_384}},
    { AMVP_HASH_SHA512,       NULL,            AMVP_ALG_SHA512,            NULL, AMVP_REV_HASH_SHA512, {AMVP_SUB_HASH_SHA2_512}},
    { AMVP_HASH_SHA512_224,   NULL,            AMVP_ALG_SHA512_224,        NULL, AMVP_REV_HASH_SHA512_224, {AMVP_SUB_HASH_SHA2_512_224}},
    { AMVP_HASH_SHA512_256,   NULL,            AMVP_ALG_SHA512_256,        NULL, AMVP_REV_HASH_SHA512_256, {AMVP_SUB_HASH_SHA2_512_256}},
    { AMVP_HASH_SHA3_224,     NULL,            AMVP_ALG_SHA3_224,          NULL, AMVP_REV_HASH_SHA3_224, {AMVP_SUB_HASH_SHA3_224}},
    { AMVP_HASH_SHA3_256,     NULL,            AMVP_ALG_SHA3_256,          NULL, AMVP_REV_HASH_SHA3_256, {AMVP_SUB_HASH_SHA3_256}},
    { AMVP_HASH_SHA3_384,     NULL,            AMVP_ALG_SHA3_384,          NULL, AMVP_REV_HASH_SHA3_384, {AMVP_SUB_HASH_SHA3_384}},
    { AMVP_HASH_SHA3_512,     NULL,            AMVP_ALG_SHA3_512,          NULL, AMVP_REV_HASH_SHA3_512, {AMVP_SUB_HASH_SHA3_512}},
    { AMVP_HASH_SHAKE_128,    NULL,            AMVP_ALG_SHAKE_128,         NULL, AMVP_REV_HASH_SHAKE_128, {AMVP_SUB_HASH_SHAKE_128}},
    { AMVP_HASH_SHAKE_256,    NULL,            AMVP_ALG_SHAKE_256,         NULL, AMVP_REV_HASH_SHAKE_256, {AMVP_SUB_HASH_SHAKE_256}},
    { AMVP_HASHDRBG,          NULL,            AMVP_ALG_HASHDRBG,          NULL, AMVP_REV_HASHDRBG, {AMVP_SUB_DRBG_HASH}},
    { AMVP_HMACDRBG,          NULL,            AMVP_ALG_HMACDRBG,          NULL, AMVP_REV_HMACDRBG, {AMVP_SUB_DRBG_HMAC}},
    { AMVP_CTRDRBG,           NULL,            AMVP_ALG_CTRDRBG,           NULL, AMVP_REV_CTRDRBG, {AMVP_SUB_DRBG_CTR}},
    { AMVP_HMAC_SHA1,         NULL,            AMVP_ALG_HMAC_SHA1,         NULL, AMVP_REV_HMAC_SHA1, {AMVP_SUB_HMAC_SHA1}},
    { AMVP_HMAC_SHA2_224,     NULL,            AMVP_ALG_HMAC_SHA2_224,     NULL, AMVP_REV_HMAC_SHA2_224, {AMVP_SUB_HMAC_SHA2_224}},
    { AMVP_HMAC_SHA2_256,     NULL,            AMVP_ALG_HMAC_SHA2_256,     NULL, AMVP_REV_HMAC_SHA2_256, {AMVP_SUB_HMAC_SHA2_256}},
    { AMVP_HMAC_SHA2_384,     NULL,            AMVP_ALG_HMAC_SHA2_384,     NULL, AMVP_REV_HMAC_SHA2_384, {AMVP_SUB_HMAC_SHA2_384}},
    { AMVP_HMAC_SHA2_512,     NULL,            AMVP_ALG_HMAC_SHA2_512,     NULL, AMVP_REV_HMAC_SHA2_512, {AMVP_SUB_HMAC_SHA2_512}},
    { AMVP_HMAC_SHA2_512_224, NULL,            AMVP_ALG_HMAC_SHA2_512_224, NULL, AMVP_REV_HMAC_SHA2_512_224, {AMVP_SUB_HMAC_SHA2_512_224}},
    { AMVP_HMAC_SHA2_512_256, NULL,            AMVP_ALG_HMAC_SHA2_512_256, NULL, AMVP_REV_HMAC_SHA2_512_256, {AMVP_SUB_HMAC_SHA2_512_256}},
    { AMVP_HMAC_SHA3_224,     NULL,            AMVP_ALG_HMAC_SHA3_224,     NULL, AMVP_REV_HMAC_SHA3_224, {AMVP_SUB_HMAC_SHA3_224}},
    { AMVP_HMAC_SHA3_256,     NULL,            AMVP_ALG_HMAC_SHA3_256,     NULL, AMVP_REV_HMAC_SHA3_256, {AMVP_SUB_HMAC_SHA3_256}},
    { AMVP_HMAC_SHA3_384,     NULL,            AMVP_ALG_HMAC_SHA3_384,     NULL, AMVP_REV_HMAC_SHA3_384, {AMVP_SUB_HMAC_SHA3_384}},
    { AMVP_HMAC_SHA3_512,     NULL,            AMVP_ALG_HMAC_SHA3_512,     NULL, AMVP_REV_HMAC_SHA3_512, {AMVP_SUB_HMAC_SHA3_512}},
    { AMVP_CMAC_AES,          NULL,            AMVP_ALG_CMAC_AES,          NULL, AMVP_REV_CMAC_AES, {AMVP_SUB_CMAC_AES}},
    { AMVP_CMAC_TDES,         NULL,            AMVP_ALG_CMAC_TDES,         NULL, AMVP_REV_CMAC_TDES, {AMVP_SUB_CMAC_TDES}},
    { AMVP_KMAC_128,          NULL,            AMVP_ALG_KMAC_128,          NULL, AMVP_REV_KMAC_128, {AMVP_SUB_KMAC_128}},
    { AMVP_KMAC_256,          NULL,            AMVP_ALG_KMAC_256,          NULL, AMVP_REV_KMAC_256, {AMVP_SUB_KMAC_256}},
    { AMVP_DSA_KEYGEN,        NULL,             AMVP_ALG_DSA,               AMVP_ALG_DSA_KEYGEN, AMVP_REV_DSA, {AMVP_SUB_DSA_KEYGEN}},
    { AMVP_DSA_PQGGEN,        NULL,             AMVP_ALG_DSA,               AMVP_ALG_DSA_PQGGEN, AMVP_REV_DSA, {AMVP_SUB_DSA_PQGGEN}},
    { AMVP_DSA_PQGVER,        NULL,             AMVP_ALG_DSA,               AMVP_ALG_DSA_PQGVER, AMVP_REV_DSA, {AMVP_SUB_DSA_PQGVER}},
    { AMVP_DSA_SIGGEN,        NULL,             AMVP_ALG_DSA,               AMVP_ALG_DSA_SIGGEN, AMVP_REV_DSA, {AMVP_SUB_DSA_SIGGEN}},
    { AMVP_DSA_SIGVER,        NULL,             AMVP_ALG_DSA,               AMVP_ALG_DSA_SIGVER, AMVP_REV_DSA, {AMVP_SUB_DSA_SIGVER}},
    { AMVP_RSA_KEYGEN,        NULL,      AMVP_ALG_RSA,               AMVP_MODE_KEYGEN, AMVP_REV_RSA, {AMVP_SUB_RSA_KEYGEN}},
    { AMVP_RSA_SIGGEN,        NULL,      AMVP_ALG_RSA,               AMVP_MODE_SIGGEN, AMVP_REV_RSA, {AMVP_SUB_RSA_SIGGEN}},
    { AMVP_RSA_SIGVER,        NULL,      AMVP_ALG_RSA,               AMVP_MODE_SIGVER, AMVP_REV_RSA, {AMVP_SUB_RSA_SIGVER}},
    { AMVP_RSA_DECPRIM,       NULL,     AMVP_ALG_RSA,               AMVP_MODE_DECPRIM, AMVP_REV_RSA_PRIM, {AMVP_SUB_RSA_DECPRIM}},
    { AMVP_RSA_SIGPRIM,       NULL,     AMVP_ALG_RSA,               AMVP_MODE_SIGPRIM, AMVP_REV_RSA_PRIM, {AMVP_SUB_RSA_SIGPRIM}},
    { AMVP_ECDSA_KEYGEN,      NULL,    AMVP_ALG_ECDSA,             AMVP_MODE_KEYGEN, AMVP_REV_ECDSA, {AMVP_SUB_ECDSA_KEYGEN}},
    { AMVP_ECDSA_KEYVER,      NULL,    AMVP_ALG_ECDSA,             AMVP_MODE_KEYVER, AMVP_REV_ECDSA, {AMVP_SUB_ECDSA_KEYVER}},
    { AMVP_ECDSA_SIGGEN,      NULL,    AMVP_ALG_ECDSA,             AMVP_MODE_SIGGEN, AMVP_REV_ECDSA, {AMVP_SUB_ECDSA_SIGGEN}},
    { AMVP_ECDSA_SIGVER,      NULL,    AMVP_ALG_ECDSA,             AMVP_MODE_SIGVER, AMVP_REV_ECDSA, {AMVP_SUB_ECDSA_SIGVER}},
    { AMVP_KDF135_SNMP,       NULL,     AMVP_KDF135_ALG_STR,        AMVP_ALG_KDF135_SNMP, AMVP_REV_KDF135_SNMP, {AMVP_SUB_KDF_SNMP}},
    { AMVP_KDF135_SSH,        NULL,      AMVP_KDF135_ALG_STR,        AMVP_ALG_KDF135_SSH, AMVP_REV_KDF135_SSH, {AMVP_SUB_KDF_SSH}},
    { AMVP_KDF135_SRTP,       NULL,     AMVP_KDF135_ALG_STR,        AMVP_ALG_KDF135_SRTP, AMVP_REV_KDF135_SRTP, {AMVP_SUB_KDF_SRTP}},
    { AMVP_KDF135_IKEV2,      NULL,    AMVP_KDF135_ALG_STR,        AMVP_ALG_KDF135_IKEV2, AMVP_REV_KDF135_IKEV2, {AMVP_SUB_KDF_IKEV2}},
    { AMVP_KDF135_IKEV1,      NULL,    AMVP_KDF135_ALG_STR,        AMVP_ALG_KDF135_IKEV1, AMVP_REV_KDF135_IKEV1, {AMVP_SUB_KDF_IKEV1}},
    { AMVP_KDF135_X942,       NULL,     AMVP_KDF135_ALG_STR,        AMVP_ALG_KDF135_X942, AMVP_REV_KDF135_X942, {AMVP_SUB_KDF_X942}},
    { AMVP_KDF135_X963,       NULL,     AMVP_KDF135_ALG_STR,        AMVP_ALG_KDF135_X963, AMVP_REV_KDF135_X963, {AMVP_SUB_KDF_X963}},
    { AMVP_KDF108,            NULL,          AMVP_ALG_KDF108,            NULL, AMVP_REV_KDF108, {AMVP_SUB_KDF_108}},
    { AMVP_PBKDF,             NULL,           AMVP_ALG_PBKDF,             NULL, AMVP_REV_PBKDF, {AMVP_SUB_KDF_PBKDF}},
    { AMVP_KDF_TLS12,         NULL,       AMVP_ALG_TLS12,             AMVP_ALG_KDF_TLS12, AMVP_REV_KDF_TLS12, {AMVP_SUB_KDF_TLS12}},
    { AMVP_KDF_TLS13,         NULL,       AMVP_ALG_TLS13,             AMVP_ALG_KDF_TLS13, AMVP_REV_KDF_TLS13, {AMVP_SUB_KDF_TLS13}},
    { AMVP_KAS_ECC_CDH,       NULL,         AMVP_ALG_KAS_ECC,           AMVP_ALG_KAS_ECC_CDH, AMVP_REV_KAS_ECC, {AMVP_SUB_KAS_ECC_CDH}},
    { AMVP_KAS_ECC_COMP,      NULL,         AMVP_ALG_KAS_ECC,           AMVP_ALG_KAS_ECC_COMP, AMVP_REV_KAS_ECC, {AMVP_SUB_KAS_ECC_COMP}},
    { AMVP_KAS_ECC_NOCOMP,    NULL,         AMVP_ALG_KAS_ECC,           AMVP_ALG_KAS_ECC_NOCOMP, AMVP_REV_KAS_ECC, {AMVP_SUB_KAS_ECC_NOCOMP}},
    { AMVP_KAS_ECC_SSC,       NULL,     AMVP_ALG_KAS_ECC_SSC,       AMVP_ALG_KAS_ECC_COMP, AMVP_REV_KAS_ECC_SSC, {AMVP_SUB_KAS_ECC_SSC}},
    { AMVP_KAS_FFC_COMP,      NULL,         AMVP_ALG_KAS_FFC,           AMVP_ALG_KAS_FFC_COMP, AMVP_REV_KAS_FFC, {AMVP_SUB_KAS_FFC_COMP}},
    { AMVP_KAS_FFC_NOCOMP,    NULL,         AMVP_ALG_KAS_FFC,           AMVP_ALG_KAS_FFC_NOCOMP, AMVP_REV_KAS_FFC, {AMVP_SUB_KAS_FFC_NOCOMP}},
    { AMVP_KAS_FFC_SSC,       NULL,     AMVP_ALG_KAS_FFC_SSC,       AMVP_ALG_KAS_FFC_COMP, AMVP_REV_KAS_FFC_SSC, {AMVP_SUB_KAS_FFC_SSC}},
    { AMVP_KAS_IFC_SSC,       NULL,     AMVP_ALG_KAS_IFC_SSC,       AMVP_ALG_KAS_IFC_COMP, AMVP_REV_KAS_IFC_SSC, {AMVP_SUB_KAS_IFC_SSC}},
    { AMVP_KDA_ONESTEP,       NULL,     AMVP_ALG_KDA_ALG_STR,       AMVP_ALG_KDA_ONESTEP, AMVP_REV_KDA_ONESTEP, {AMVP_SUB_KDA_ONESTEP}},
    { AMVP_KDA_TWOSTEP,       NULL,     AMVP_ALG_KDA_ALG_STR,       AMVP_ALG_KDA_TWOSTEP, AMVP_REV_KDA_TWOSTEP, {AMVP_SUB_KDA_TWOSTEP}},
    { AMVP_KDA_HKDF,          NULL,        AMVP_ALG_KDA_ALG_STR,       AMVP_ALG_KDA_HKDF, AMVP_REV_KDA_HKDF, {AMVP_SUB_KDA_HKDF}},
    { AMVP_KTS_IFC,           NULL,         AMVP_ALG_KTS_IFC,           AMVP_ALG_KTS_IFC_COMP, AMVP_REV_KTS_IFC, {AMVP_SUB_KTS_IFC}},
    { AMVP_SAFE_PRIMES_KEYGEN, NULL,    AMVP_ALG_SAFE_PRIMES_STR,   AMVP_ALG_SAFE_PRIMES_KEYGEN, AMVP_REV_SAFE_PRIMES, {AMVP_SUB_SAFE_PRIMES_KEYGEN}},
    { AMVP_SAFE_PRIMES_KEYVER, NULL,    AMVP_ALG_SAFE_PRIMES_STR,   AMVP_ALG_SAFE_PRIMES_KEYVER, AMVP_REV_SAFE_PRIMES, {AMVP_SUB_SAFE_PRIMES_KEYVER}}
};

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

static void amvp_free_prereqs(AMVP_CAPS_LIST *cap_list) {
    while (cap_list->prereq_vals) {
        AMVP_PREREQ_LIST *temp_ptr;
        temp_ptr = cap_list->prereq_vals;
        cap_list->prereq_vals = cap_list->prereq_vals->next;
        free(temp_ptr);
    }
}

/*
 * Free internal memory for EC curve/hash alg list
 */
static void amvp_cap_free_ec_alg_list(AMVP_CURVE_ALG_COMPAT_LIST *list) {
    AMVP_CURVE_ALG_COMPAT_LIST *tmp = NULL, *tmp2 = NULL;

    if (!list) {
        return;
    }

    tmp = list;
    while (tmp) {
        tmp2 = tmp;
        tmp = tmp->next;
        free(tmp2);
    }
}

/*
 * Free Internal memory for DSA operations. Since it supports
 * multiple modes, we have to free the whole list
 */
static void amvp_cap_free_dsa_attrs(AMVP_CAPS_LIST *cap_entry) {
    AMVP_DSA_ATTRS *attrs = NULL, *next = NULL;
    AMVP_DSA_CAP_MODE *dsa_cap_mode = NULL;
    int i;

    for (i = 0; i <= AMVP_DSA_MAX_MODES - 1; i++) {
        dsa_cap_mode = &cap_entry->cap.dsa_cap->dsa_cap_mode[i];
        if (dsa_cap_mode->defined) {
            next = dsa_cap_mode->dsa_attrs;
            while (next) {
                attrs = next;
                next = attrs->next;
                free(attrs);
            }
        }
    }
    dsa_cap_mode = cap_entry->cap.dsa_cap->dsa_cap_mode;
    free(dsa_cap_mode);
}

/*
 * Free Internal memory for keygen struct. Since it supports
 * multiple modes, we have to free the whole list
 */
static void amvp_cap_free_rsa_keygen_list(AMVP_CAPS_LIST *cap_list) {
    AMVP_RSA_KEYGEN_CAP *keygen_cap = cap_list->cap.rsa_keygen_cap;
    AMVP_RSA_KEYGEN_CAP *temp_keygen_cap;

    amvp_free_prereqs(cap_list);

    while (keygen_cap) {
        if (keygen_cap->fixed_pub_exp) {
            free(keygen_cap->fixed_pub_exp);
        }

        AMVP_RSA_MODE_CAPS_LIST *mode_list = keygen_cap->mode_capabilities;
        AMVP_RSA_MODE_CAPS_LIST *temp_mode_list;

        while (mode_list) {
            amvp_cap_free_nl(mode_list->hash_algs);
            amvp_cap_free_nl(mode_list->prime_tests);

            temp_mode_list = mode_list;
            mode_list = mode_list->next;
            free(temp_mode_list);
            temp_mode_list = NULL;
        }

        temp_keygen_cap = keygen_cap;
        keygen_cap = keygen_cap->next;
        free(temp_keygen_cap);
        temp_keygen_cap = NULL;
    }
}

/*
 * Free Internal memory for keygen struct. Since it supports
 * multiple modes, we have to free the whole list
 */
static void amvp_cap_free_rsa_sig_list(AMVP_CAPS_LIST *cap_list) {
    AMVP_RSA_SIG_CAP *sig_cap = NULL, *temp_sig_cap = NULL;

    if (cap_list->cipher == AMVP_RSA_SIGGEN) {
        sig_cap = cap_list->cap.rsa_siggen_cap;
    } else if (cap_list->cipher == AMVP_RSA_SIGVER) {
        sig_cap = cap_list->cap.rsa_sigver_cap;
    } else {
        return;
    }

    amvp_free_prereqs(cap_list);

    while (sig_cap) {
        AMVP_RSA_MODE_CAPS_LIST *mode_list = sig_cap->mode_capabilities;
        AMVP_RSA_MODE_CAPS_LIST *temp_mode_list;

        if (sig_cap->fixed_pub_exp) {
            free(sig_cap->fixed_pub_exp);
        }
        while (mode_list) {
            amvp_cap_free_hash_pairs(mode_list->hash_pair);

            temp_mode_list = mode_list;
            mode_list = mode_list->next;
            free(temp_mode_list);
            temp_mode_list = NULL;
        }

        temp_sig_cap = sig_cap;
        sig_cap = sig_cap->next;
        free(temp_sig_cap);
        temp_sig_cap = NULL;
    }
}

/*
 * Free Internal memory for KAS-ECC Data struct
 */
static void amvp_cap_free_kas_ecc_mode(AMVP_CAPS_LIST *cap_list) {
    AMVP_KAS_ECC_CAP *kas_ecc_cap = cap_list->cap.kas_ecc_cap;
    AMVP_KAS_ECC_CAP_MODE *mode;
    int i;

    if (kas_ecc_cap) {
        AMVP_PREREQ_LIST *current_pre_req_vals;
        AMVP_PREREQ_LIST *next_pre_req_vals;
        AMVP_KAS_ECC_PSET *current_pset;
        AMVP_KAS_ECC_PSET *next_pset;
        AMVP_KAS_ECC_SCHEME *current_scheme;
        AMVP_KAS_ECC_SCHEME *next_scheme;

        if (kas_ecc_cap->kas_ecc_mode) {
            for (i = 0; i < AMVP_KAS_ECC_MAX_MODES; i++) {
                mode = &kas_ecc_cap->kas_ecc_mode[i];
                current_pre_req_vals = mode->prereq_vals;
                /*
                 * Delete all pre_req
                 */
                if (current_pre_req_vals) {
                    do {
                        next_pre_req_vals = current_pre_req_vals->next;
                        free(current_pre_req_vals);
                        current_pre_req_vals = next_pre_req_vals;
                    } while (current_pre_req_vals);
                }
                /*
                 * Delete all function name lists
                 */
                amvp_cap_free_pl(mode->function);

                /*
                 * Delete all curve name lists
                 */
                amvp_cap_free_pl(mode->curve);

                /*
                 * Delete all schemes, psets and their param lists
                 */
                current_scheme = mode->scheme;
                if (current_scheme) {
                    do {
                        amvp_cap_free_pl(current_scheme->role);
                        current_pset = current_scheme->pset;
                        if (current_pset) {
                            do {
                                amvp_cap_free_pl(current_pset->sha);
                                next_pset = current_pset->next;
                                free(current_pset);
                                current_pset = next_pset;
                            } while (current_pset);
                        }
                        next_scheme = current_scheme->next;
                        free(current_scheme);
                        current_scheme = next_scheme;
                    } while (current_scheme);
                }
            }
        }
    }
    free(cap_list->cap.kas_ecc_cap->kas_ecc_mode);
    free(cap_list->cap.kas_ecc_cap);
}

/*
 * Free Internal memory for KAS-FFC Data struct
 */
static void amvp_cap_free_kas_ffc_mode(AMVP_CAPS_LIST *cap_list) {
    AMVP_KAS_FFC_CAP *kas_ffc_cap = cap_list->cap.kas_ffc_cap;
    AMVP_KAS_FFC_CAP_MODE *mode;
    int i;

    if (kas_ffc_cap) {
        AMVP_PREREQ_LIST *current_pre_req_vals;
        AMVP_PREREQ_LIST *next_pre_req_vals;
        AMVP_KAS_FFC_PSET *current_pset;
        AMVP_KAS_FFC_PSET *next_pset;
        AMVP_KAS_FFC_SCHEME *current_scheme;
        AMVP_KAS_FFC_SCHEME *next_scheme;

        if (kas_ffc_cap->kas_ffc_mode) {
            for (i = 0; i < AMVP_KAS_FFC_MAX_MODES; i++) {
                mode = &kas_ffc_cap->kas_ffc_mode[i];
                current_pre_req_vals = mode->prereq_vals;
                /*
                 * Delete all pre_req
                 */
                if (current_pre_req_vals) {
                    do {
                        next_pre_req_vals = current_pre_req_vals->next;
                        free(current_pre_req_vals);
                        current_pre_req_vals = next_pre_req_vals;
                    } while (current_pre_req_vals);
                }
                /*
                 * Delete all generation methods
                 */
                amvp_cap_free_pl(mode->genmeth);

                /*
                 * Delete all function name lists
                 */
                amvp_cap_free_pl(mode->function);

                /*
                 * Delete all schemes, psets and their param lists
                 */
                current_scheme = mode->scheme;
                if (current_scheme) {
                    do {
                        amvp_cap_free_pl(current_scheme->role);
                        current_pset = current_scheme->pset;
                        if (current_pset) {
                            do {
                                amvp_cap_free_pl(current_pset->sha);
                                next_pset = current_pset->next;
                                free(current_pset);
                                current_pset = next_pset;
                            } while (current_pset);
                        }
                        next_scheme = current_scheme->next;
                        free(current_scheme);
                        current_scheme = next_scheme;
                    } while (current_scheme);
                }
            }
        }
    }
    free(cap_list->cap.kas_ffc_cap->kas_ffc_mode);
    free(cap_list->cap.kas_ffc_cap);
}

/*
 * Free Internal memory for DRBG Data struct
 */
static void amvp_free_drbg_struct(AMVP_CAPS_LIST *cap_list) {
    AMVP_DRBG_CAP *drbg_cap = cap_list->cap.drbg_cap;

    if (drbg_cap) {
        AMVP_DRBG_MODE_LIST *mode_list = drbg_cap->drbg_cap_mode;
        AMVP_DRBG_MODE_LIST *next_mode_list;
        AMVP_DRBG_GROUP_LIST *group_list;
        AMVP_DRBG_GROUP_LIST *next_group_list;
        AMVP_PREREQ_LIST *current_pre_req_vals;
        AMVP_PREREQ_LIST *next_pre_req_vals;

        current_pre_req_vals = drbg_cap->prereq_vals;
        while (current_pre_req_vals) {
            next_pre_req_vals = current_pre_req_vals->next;
            free(current_pre_req_vals);
            current_pre_req_vals = next_pre_req_vals;
        }

        while (mode_list) {
            group_list = mode_list->groups;
            while (group_list) {
                next_group_list = group_list->next;
                if (group_list->group) {
                    free(group_list->group);
                }
                free(group_list);
                group_list = next_group_list;
            }
            next_mode_list = mode_list->next;
            free(mode_list);
            mode_list = next_mode_list;
        }
        free(drbg_cap);
        drbg_cap = NULL;
        cap_list->cap.drbg_cap = NULL;
    }
}

/*
 * Free Internal memory for KDF108 Cap struct
 */
static void amvp_cap_free_kdf108(AMVP_KDF108_CAP *cap) {
    AMVP_KDF108_MODE_PARAMS *mode_obj = NULL;

    if (cap) {
        if (cap->counter_mode.kdf_mode) {
            mode_obj = &cap->counter_mode;
            if (mode_obj->mac_mode) {
                amvp_cap_free_nl(mode_obj->mac_mode);
            }
            if (mode_obj->data_order) {
                amvp_cap_free_nl(mode_obj->data_order);
            }
            if (mode_obj->counter_lens) {
                amvp_cap_free_sl(mode_obj->counter_lens);
            }
            amvp_cap_free_domain(&mode_obj->supported_lens);
        }

        if (cap->feedback_mode.kdf_mode) {
            mode_obj = &cap->feedback_mode;
            if (mode_obj->mac_mode) {
                amvp_cap_free_nl(mode_obj->mac_mode);
            }
            if (mode_obj->data_order) {
                amvp_cap_free_nl(mode_obj->data_order);
            }
            if (mode_obj->counter_lens) {
                amvp_cap_free_sl(mode_obj->counter_lens);
            }
            amvp_cap_free_domain(&mode_obj->supported_lens);
        }

        if (cap->dpi_mode.kdf_mode) {
            mode_obj = &cap->dpi_mode;
            if (mode_obj->mac_mode) {
                amvp_cap_free_nl(mode_obj->mac_mode);
            }
            if (mode_obj->data_order) {
                amvp_cap_free_nl(mode_obj->data_order);
            }
            if (mode_obj->counter_lens) {
                amvp_cap_free_sl(mode_obj->counter_lens);
            }
            amvp_cap_free_domain(&mode_obj->supported_lens);
        }

        cap = NULL;
    }
}

static void amvp_cap_free_kts_ifc_schemes(AMVP_CAPS_LIST *cap_entry) {
    AMVP_KTS_IFC_SCHEMES *current_scheme;


    current_scheme = cap_entry->cap.kts_ifc_cap->schemes;
    while (current_scheme) {
        amvp_cap_free_pl(current_scheme->roles);
        amvp_cap_free_pl(current_scheme->hash);
        free(current_scheme->assoc_data_pattern);
        free(current_scheme->encodings);
        current_scheme = current_scheme->next;
    }
    free(cap_entry->cap.kts_ifc_cap->schemes);
}
/*
 * The application will invoke this to free the AMVP context
 * when the test session is finished.
 */
AMVP_RESULT amvp_free_test_session(AMVP_CTX *ctx) {
    AMVP_VS_LIST *vs_entry, *vs_e2;
    AMVP_CAPS_LIST *cap_entry, *cap_e2;

    if (!ctx) {
        AMVP_LOG_STATUS("No ctx to free");
        return AMVP_SUCCESS;
    }

    if (ctx->kat_resp) { json_value_free(ctx->kat_resp); }
    if (ctx->curl_buf) { free(ctx->curl_buf); }
    if (ctx->server_name) { free(ctx->server_name); }
    if (ctx->path_segment) { free(ctx->path_segment); }
    if (ctx->api_context) { free(ctx->api_context); }
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
    if (ctx->caps_list) {
        cap_entry = ctx->caps_list;
        while (cap_entry) {
            cap_e2 = cap_entry->next;
            if (cap_entry->prereq_vals) {
                amvp_free_prereqs(cap_entry);
            }
            switch (cap_entry->cap_type) {
            case AMVP_SYM_TYPE:
                amvp_cap_free_sl(cap_entry->cap.sym_cap->keylen);
                amvp_cap_free_sl(cap_entry->cap.sym_cap->ptlen);
                amvp_cap_free_sl(cap_entry->cap.sym_cap->ivlen);
                amvp_cap_free_sl(cap_entry->cap.sym_cap->aadlen);
                amvp_cap_free_sl(cap_entry->cap.sym_cap->taglen);
                amvp_cap_free_sl(cap_entry->cap.sym_cap->tweak);
                free(cap_entry->cap.sym_cap);
                break;
            case AMVP_HASH_TYPE:
                free(cap_entry->cap.hash_cap);
                break;
            case AMVP_DRBG_TYPE:
                amvp_free_drbg_struct(cap_entry);
                break;
            case AMVP_HMAC_TYPE:
                amvp_cap_free_domain(&cap_entry->cap.hmac_cap->key_len);
                amvp_cap_free_domain(&cap_entry->cap.hmac_cap->mac_len);
                free(cap_entry->cap.hmac_cap);
                break;
            case AMVP_CMAC_TYPE:
                amvp_cap_free_sl(cap_entry->cap.cmac_cap->key_len);
                amvp_cap_free_sl(cap_entry->cap.cmac_cap->keying_option);
                amvp_cap_free_domain(&cap_entry->cap.cmac_cap->msg_len);
                amvp_cap_free_domain(&cap_entry->cap.cmac_cap->mac_len);
                free(cap_entry->cap.cmac_cap);
                break;
            case AMVP_KMAC_TYPE:
                amvp_cap_free_domain(&cap_entry->cap.kmac_cap->key_len);
                amvp_cap_free_domain(&cap_entry->cap.kmac_cap->msg_len);
                amvp_cap_free_domain(&cap_entry->cap.kmac_cap->mac_len);
                free(cap_entry->cap.kmac_cap);
                break;
            case AMVP_DSA_TYPE:
                amvp_cap_free_dsa_attrs(cap_entry);
                free(cap_entry->cap.dsa_cap);
                break;
            case AMVP_KAS_ECC_CDH_TYPE:
            case AMVP_KAS_ECC_COMP_TYPE:
            case AMVP_KAS_ECC_NOCOMP_TYPE:
            case AMVP_KAS_ECC_SSC_TYPE:
                amvp_cap_free_kas_ecc_mode(cap_entry);
                break;
            case AMVP_KAS_FFC_SSC_TYPE:
            case AMVP_KAS_FFC_COMP_TYPE:
            case AMVP_KAS_FFC_NOCOMP_TYPE:
                amvp_cap_free_kas_ffc_mode(cap_entry);
                break;
            case AMVP_KAS_IFC_TYPE:
                amvp_cap_free_pl(cap_entry->cap.kas_ifc_cap->kas1_roles);
                amvp_cap_free_pl(cap_entry->cap.kas_ifc_cap->kas2_roles);
                amvp_cap_free_pl(cap_entry->cap.kas_ifc_cap->keygen_method);
                amvp_cap_free_sl(cap_entry->cap.kas_ifc_cap->modulo);
                free(cap_entry->cap.kas_ifc_cap->fixed_pub_exp);
                free(cap_entry->cap.kas_ifc_cap);
                break;
            case AMVP_KDA_ONESTEP_TYPE:
                if (cap_entry->cap.kda_onestep_cap->literal_pattern_candidate) {
                    free(cap_entry->cap.kda_onestep_cap->literal_pattern_candidate);
                }
                amvp_cap_free_pl(cap_entry->cap.kda_onestep_cap->patterns);
                amvp_cap_free_pl(cap_entry->cap.kda_onestep_cap->encodings);
                amvp_cap_free_nl(cap_entry->cap.kda_onestep_cap->aux_functions);
                amvp_cap_free_nl(cap_entry->cap.kda_onestep_cap->mac_salt_methods);
                free(cap_entry->cap.kda_onestep_cap);
                break;
            case AMVP_KDA_TWOSTEP_TYPE:
                if (cap_entry->cap.kda_twostep_cap->literal_pattern_candidate) {
                    free(cap_entry->cap.kda_twostep_cap->literal_pattern_candidate);
                }
                amvp_cap_free_nl(cap_entry->cap.kda_twostep_cap->mac_salt_methods);
                amvp_cap_free_pl(cap_entry->cap.kda_twostep_cap->patterns);
                amvp_cap_free_pl(cap_entry->cap.kda_twostep_cap->encodings);
                amvp_cap_free_domain(&cap_entry->cap.kda_twostep_cap->aux_secret_len);
                amvp_cap_free_kdf108(&cap_entry->cap.kda_twostep_cap->kdf_params);
                free(cap_entry->cap.kda_twostep_cap);
                break;
            case AMVP_KDA_HKDF_TYPE:
                if (cap_entry->cap.kda_hkdf_cap->literal_pattern_candidate) {
                    free(cap_entry->cap.kda_hkdf_cap->literal_pattern_candidate);
                }
                amvp_cap_free_pl(cap_entry->cap.kda_hkdf_cap->patterns);
                amvp_cap_free_pl(cap_entry->cap.kda_hkdf_cap->encodings);
                amvp_cap_free_nl(cap_entry->cap.kda_hkdf_cap->hmac_algs);
                amvp_cap_free_nl(cap_entry->cap.kda_hkdf_cap->mac_salt_methods);
                amvp_cap_free_domain(&cap_entry->cap.kda_hkdf_cap->aux_secret_len);
                free(cap_entry->cap.kda_hkdf_cap);
                break;
            case AMVP_KTS_IFC_TYPE:
                amvp_cap_free_pl(cap_entry->cap.kts_ifc_cap->keygen_method);
                amvp_cap_free_pl(cap_entry->cap.kts_ifc_cap->functions);
                amvp_cap_free_sl(cap_entry->cap.kts_ifc_cap->modulo);
                free(cap_entry->cap.kts_ifc_cap->fixed_pub_exp);
                free(cap_entry->cap.kts_ifc_cap->iut_id);
                amvp_cap_free_kts_ifc_schemes(cap_entry);
                free(cap_entry->cap.kts_ifc_cap);
                break;
            case AMVP_RSA_KEYGEN_TYPE:
                amvp_cap_free_rsa_keygen_list(cap_entry);
                break;
            case AMVP_RSA_SIGGEN_TYPE:
                amvp_cap_free_rsa_sig_list(cap_entry);
                break;
            case AMVP_RSA_SIGVER_TYPE:
                amvp_cap_free_rsa_sig_list(cap_entry);
                break;
            case AMVP_RSA_PRIM_TYPE:
                if (cap_entry->cap.rsa_prim_cap->fixed_pub_exp) {
                    free(cap_entry->cap.rsa_prim_cap->fixed_pub_exp);
                }
                free(cap_entry->cap.rsa_prim_cap);
                break;
            case AMVP_ECDSA_KEYGEN_TYPE:
                amvp_cap_free_ec_alg_list(cap_entry->cap.ecdsa_keygen_cap->curves);
                amvp_cap_free_nl(cap_entry->cap.ecdsa_keygen_cap->secret_gen_modes);
                free(cap_entry->cap.ecdsa_keygen_cap);
                break;
            case AMVP_ECDSA_KEYVER_TYPE:
                amvp_cap_free_ec_alg_list(cap_entry->cap.ecdsa_keyver_cap->curves);
                amvp_cap_free_nl(cap_entry->cap.ecdsa_keyver_cap->secret_gen_modes);
                free(cap_entry->cap.ecdsa_keyver_cap);
                break;
            case AMVP_ECDSA_SIGGEN_TYPE:
                amvp_cap_free_ec_alg_list(cap_entry->cap.ecdsa_siggen_cap->curves);
                free(cap_entry->cap.ecdsa_siggen_cap);
                break;
            case AMVP_ECDSA_SIGVER_TYPE:
                amvp_cap_free_ec_alg_list(cap_entry->cap.ecdsa_sigver_cap->curves);
                free(cap_entry->cap.ecdsa_sigver_cap);
                break;
            case AMVP_KDF135_SRTP_TYPE:
                amvp_cap_free_sl(cap_entry->cap.kdf135_srtp_cap->aes_keylens);
                free(cap_entry->cap.kdf135_srtp_cap);
                break;
            case AMVP_KDF108_TYPE:
                amvp_cap_free_kdf108(cap_entry->cap.kdf108_cap);
                free(cap_entry->cap.kdf108_cap);
                break;
            case AMVP_KDF135_SNMP_TYPE:
                amvp_cap_free_sl(cap_entry->cap.kdf135_snmp_cap->pass_lens);
                amvp_cap_free_nl(cap_entry->cap.kdf135_snmp_cap->eng_ids);
                free(cap_entry->cap.kdf135_snmp_cap);
                break;
            case AMVP_KDF135_SSH_TYPE:
                free(cap_entry->cap.kdf135_ssh_cap);
                break;
            case AMVP_KDF135_IKEV2_TYPE:
                amvp_cap_free_nl(cap_entry->cap.kdf135_ikev2_cap->hash_algs);
                amvp_cap_free_domain(&cap_entry->cap.kdf135_ikev2_cap->init_nonce_len_domain);
                amvp_cap_free_domain(&cap_entry->cap.kdf135_ikev2_cap->respond_nonce_len_domain);
                amvp_cap_free_domain(&cap_entry->cap.kdf135_ikev2_cap->dh_secret_len);
                amvp_cap_free_domain(&cap_entry->cap.kdf135_ikev2_cap->key_material_len);
                free(cap_entry->cap.kdf135_ikev2_cap);
                break;
            case AMVP_KDF135_IKEV1_TYPE:
                amvp_cap_free_nl(cap_entry->cap.kdf135_ikev1_cap->hash_algs);
                free(cap_entry->cap.kdf135_ikev1_cap);
                break;
            case AMVP_KDF135_X942_TYPE:
                amvp_cap_free_nl(cap_entry->cap.kdf135_x942_cap->hash_algs);
                amvp_cap_free_nl(cap_entry->cap.kdf135_x942_cap->oids);
                free(cap_entry->cap.kdf135_x942_cap);
                break;
            case AMVP_KDF135_X963_TYPE:
                amvp_cap_free_nl(cap_entry->cap.kdf135_x963_cap->hash_algs);
                amvp_cap_free_sl(cap_entry->cap.kdf135_x963_cap->shared_info_lengths);
                amvp_cap_free_sl(cap_entry->cap.kdf135_x963_cap->field_sizes);
                amvp_cap_free_sl(cap_entry->cap.kdf135_x963_cap->key_data_lengths);
                free(cap_entry->cap.kdf135_x963_cap);
                break;
            case AMVP_PBKDF_TYPE:
                amvp_cap_free_nl(cap_entry->cap.pbkdf_cap->hmac_algs);
                free(cap_entry->cap.pbkdf_cap);
                break;
            case AMVP_KDF_TLS13_TYPE:
                amvp_cap_free_nl(cap_entry->cap.kdf_tls13_cap->hmac_algs);
                amvp_cap_free_pl(cap_entry->cap.kdf_tls13_cap->running_mode);
                free(cap_entry->cap.kdf_tls13_cap);
                break;
            case AMVP_KDF_TLS12_TYPE:
                amvp_cap_free_nl(cap_entry->cap.kdf_tls12_cap->hash_algs);
                free(cap_entry->cap.kdf_tls12_cap);
                break;
            case AMVP_SAFE_PRIMES_KEYGEN_TYPE:
                if (cap_entry->cap.safe_primes_keygen_cap->mode->genmeth) {
                    amvp_cap_free_pl(cap_entry->cap.safe_primes_keygen_cap->mode->genmeth);
                }
                free(cap_entry->cap.safe_primes_keygen_cap->mode);
                free(cap_entry->cap.safe_primes_keygen_cap);
                break;
            case AMVP_SAFE_PRIMES_KEYVER_TYPE:
                if (cap_entry->cap.safe_primes_keyver_cap->mode->genmeth) {
                    amvp_cap_free_pl(cap_entry->cap.safe_primes_keyver_cap->mode->genmeth);
                }
                free(cap_entry->cap.safe_primes_keyver_cap->mode);
                free(cap_entry->cap.safe_primes_keyver_cap);
                break;
            case AMVP_KDF135_TPM_TYPE:
            default:
                return AMVP_INVALID_ARG;
            }
            free(cap_entry);
            cap_entry = cap_e2;
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

static void amvp_cap_free_hash_pairs(AMVP_RSA_HASH_PAIR_LIST *list) {
    AMVP_RSA_HASH_PAIR_LIST *top = list;
    AMVP_RSA_HASH_PAIR_LIST *tmp;

    while (top) {
        tmp = top;

        top = top->next;
        free(tmp);
    }
}

static void amvp_list_failing_algorithms(AMVP_CTX *ctx, AMVP_STRING_LIST **list, AMVP_STRING_LIST **modes) {
    if (!list || *list == NULL) {
        return;
    }
    AMVP_STRING_LIST *iterator = *list;
    AMVP_STRING_LIST *mode_iterator = *modes;
    if (!iterator || !iterator->string || !mode_iterator || !mode_iterator->string) {
        return;
    }
    AMVP_LOG_STATUS("Failing algorithms:");
    while (iterator && iterator->string && mode_iterator && mode_iterator->string) {
        if (strnlen_s(mode_iterator->string, AMVP_ALG_MODE_MAX) < 1) {
            AMVP_LOG_STATUS("    %s", iterator->string);
        } else {
            AMVP_LOG_STATUS("    %s, Mode: %s", iterator->string, mode_iterator->string);
        }
        iterator = iterator->next;
        mode_iterator = mode_iterator->next;
    }
}

/*
 * Allows application to load JSON kat vector file within context
 * to be read in and used for vector testing
 */
AMVP_RESULT amvp_load_kat_filename(AMVP_CTX *ctx, const char *kat_filename) {
    JSON_Object *obj = NULL;
    JSON_Value *val = NULL;
    AMVP_RESULT rv = AMVP_SUCCESS;
    JSON_Array *reg_array;

    if (!ctx) {
        return AMVP_NO_CTX;
    }
    if (!kat_filename) {
        AMVP_LOG_ERR("Must provide value for JSON filename");
        return AMVP_MISSING_ARG;
    }

    if (strnlen_s(kat_filename, AMVP_JSON_FILENAME_MAX + 1) > AMVP_JSON_FILENAME_MAX) {
        AMVP_LOG_ERR("Provided kat_filename length > max(%d)", AMVP_JSON_FILENAME_MAX);
        return AMVP_INVALID_ARG;
    }

    val = json_parse_file(kat_filename);

    reg_array = json_value_get_array(val);
    obj = json_array_get_object(reg_array, 1);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        json_value_free(val);
        return AMVP_INVALID_ARG;
    }

    /* Process the kat vector(s) */
    rv  = amvp_dispatch_vector_set(ctx, obj);
    json_value_free(val);
    return rv;
}

/*
 * Allows application to load JSON vector file(req_filename) within context
 * to be read in and used for vector testing. The results are
 * then saved in a response file(rsp_filename).
 */
AMVP_RESULT amvp_run_vectors_from_file(AMVP_CTX *ctx, const char *req_filename, const char *rsp_filename) {
    JSON_Object *obj = NULL;
    JSON_Value *val = NULL;
    JSON_Array *reg_array;
    JSON_Value *file_val = NULL;
    JSON_Value *kat_val = NULL;
    JSON_Array *kat_array;
    JSON_Value *rsp_val = NULL;
    AMVP_RESULT rv = AMVP_SUCCESS;
    int n, i;
    AMVP_STRING_LIST *vs_entry;
    JSON_Array *vect_sets = NULL;
    const char *test_session_url = NULL;
    int vs_cnt = 0, isSample = 0;
    const char *jwt = NULL;
    char *json_result = NULL;

    AMVP_LOG_STATUS("Beginning offline processing of vector sets...");

    if (!ctx) {
        return AMVP_NO_CTX;
    }
    if (!req_filename || !rsp_filename) {
        AMVP_LOG_ERR("Must provide value for JSON filename");
        return AMVP_MISSING_ARG;
    }

    if (strnlen_s(req_filename, AMVP_JSON_FILENAME_MAX + 1) > AMVP_JSON_FILENAME_MAX) {
        AMVP_LOG_ERR("Provided req_filename length > max(%d)", AMVP_JSON_FILENAME_MAX);
        return AMVP_INVALID_ARG;
    }

    val = json_parse_file(req_filename);

    n = 0;
    reg_array = json_value_get_array(val);
    obj = json_array_get_object(reg_array, n);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    /*
     * This is the identifiers provided by the server
     * for this specific test session!
     */
    test_session_url = json_object_get_string(obj, "url");
    if (test_session_url) {
        ctx->session_url = calloc(AMVP_ATTR_URL_MAX + 1, sizeof(char));
        strcpy_s(ctx->session_url, AMVP_ATTR_URL_MAX + 1, test_session_url);
    } else {
        AMVP_LOG_WARN("Missing session URL, results will not be POSTed to server");
        goto end;
    }

    jwt = json_object_get_string(obj, "jwt");
    if (jwt) {
        ctx->jwt_token = calloc(AMVP_JWT_TOKEN_MAX + 1, sizeof(char));
        strcpy_s(ctx->jwt_token, AMVP_JWT_TOKEN_MAX + 1, jwt);
    } else {
        AMVP_LOG_WARN("Missing JWT, results will not be POSTed to server");
        goto end;
    }

    isSample = json_object_get_boolean(obj, "isSample");
    if (json_object_has_value(obj, "isSample")) {
        ctx->is_sample = isSample;
    } else {
        AMVP_LOG_WARN("Missing indication of whether tests are sample in file, continuing");
    }

    vect_sets = json_object_get_array(obj, "vectorSetUrls");
    vs_cnt = json_array_get_count(vect_sets);
    for (i = 0; i < vs_cnt; i++) {
        const char *vsid_url = json_array_get_string(vect_sets, i);

        if (!vsid_url) {
            AMVP_LOG_WARN("No vsId URL, results will not be POSTed to server");
            goto end;
        }

        rv = amvp_append_vsid_url(ctx, vsid_url);
        if (rv != AMVP_SUCCESS) goto end;
        AMVP_LOG_INFO("Received vsid_url=%s", vsid_url);
    }

    n++;        /* bump past the version or url, jwt, url sets */
    obj = json_array_get_object(reg_array, n);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    vs_entry = ctx->vsid_url_list;
    if (!vs_entry) {
        goto end;
    }

    while (obj) {
        if (!vs_entry) {
            goto end;
        }
        /* Process the kat vector(s) */
        rv  = amvp_dispatch_vector_set(ctx, obj);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("KAT dispatch error");
            goto end;
        }
        AMVP_LOG_STATUS("Writing vector set responses for vector set %d...", ctx->vs_id);

        /* 
         * Convert the JSON from a fully qualified to a value that can be 
         * added to the file. Kind of klumsy, but it works.
         */
        kat_array = json_value_get_array(ctx->kat_resp);
        kat_val = json_array_get_value(kat_array, 1);
        if (!kat_val) {
            AMVP_LOG_ERR("JSON val parse error");
            goto end;
        }
        json_result = json_serialize_to_string_pretty(kat_val, NULL);
        file_val = json_parse_string(json_result);
        json_free_serialized_string(json_result);

        /* track first vector set with file count */
        if (n == 1) {

            rsp_val = json_array_get_value(reg_array, 0);
            /* start the file with the '[' and identifiers array */
            rv = amvp_json_serialize_to_file_pretty_w(rsp_val, rsp_filename);
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("File write error");
                json_value_free(file_val);
                goto end;
            }
        } 
        /* append vector sets */
        rv = amvp_json_serialize_to_file_pretty_a(file_val, rsp_filename);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("File write error");
            json_value_free(file_val);
            goto end;
        }

        json_value_free(file_val);
        file_val = NULL;
        n++;
        obj = json_array_get_object(reg_array, n);
        vs_entry = vs_entry->next;
    }
    /* append the final ']' to make the JSON work */ 
    rv = amvp_json_serialize_to_file_pretty_a(NULL, rsp_filename);
    AMVP_LOG_STATUS("Completed processing of vector sets. Responses saved in specified file.");
end:
    json_value_free(val);
    return rv;
}

/*
 * Allows application to read JSON vector responses from a file(rsp_filename)
 * and upload them to the server for verification.
 */
AMVP_RESULT amvp_upload_vectors_from_file(AMVP_CTX *ctx, const char *rsp_filename, int fips_validation) {
    JSON_Object *obj = NULL;
    JSON_Object *rsp_obj = NULL;
    JSON_Value *vs_val = NULL;
    JSON_Value *new_val = NULL;
    JSON_Value *val = NULL;
    AMVP_RESULT rv = AMVP_SUCCESS;
    JSON_Array *reg_array;
    int n, i;
    AMVP_STRING_LIST *vs_entry;
    JSON_Array *vect_sets = NULL;
    const char *test_session_url = NULL;
    int vs_cnt = 0, isSample = 0;
    const char *jwt = NULL;
    char *json_result = NULL;
    JSON_Array *vec_array = NULL;
    JSON_Value *vec_array_val = NULL;

    AMVP_LOG_STATUS("Uploading vectors from response file...");

    if (!ctx) {
        return AMVP_NO_CTX;
    }
    if (!rsp_filename) {
        AMVP_LOG_ERR("Must provide value for JSON filename");
        return AMVP_MISSING_ARG;
    }

    if (strnlen_s(rsp_filename, AMVP_JSON_FILENAME_MAX + 1) > AMVP_JSON_FILENAME_MAX) {
        AMVP_LOG_ERR("Provided rsp_filename length > max(%d)", AMVP_JSON_FILENAME_MAX);
        return AMVP_INVALID_ARG;
    }

    val = json_parse_file(rsp_filename);
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

    /*
     * This is the identifiers provided by the server
     * for this specific test session!
     */
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
    
    isSample = json_object_get_boolean(obj, "isSample");
    if (json_object_has_value(obj, "isSample")) {
        ctx->is_sample = isSample;
    } else {
        AMVP_LOG_WARN("Missing indication of whether tests are sample in file, continuing");
    }

    strcpy_s(ctx->jwt_token, AMVP_JWT_TOKEN_MAX + 1, jwt);

    vect_sets = json_object_get_array(obj, "ieSetsId");
    vs_cnt = json_array_get_count(vect_sets);
    for (i = 0; i < vs_cnt; i++) {
        const char *vsid_url = json_array_get_string(vect_sets, i);

        if (!vsid_url) {
            AMVP_LOG_ERR("No vsId URL, results will not be POSTed to server");
            rv = AMVP_MALFORMED_JSON;
            goto end;
        }

        rv = amvp_append_vsid_url(ctx, vsid_url);
        if (rv != AMVP_SUCCESS) goto end;
        AMVP_LOG_INFO("Received vsid_url=%s", vsid_url);
    }

    vs_entry = ctx->vsid_url_list;
    if (!vs_entry) {
        goto end;
    }

    if (fips_validation) {
        rv = amvp_verify_fips_validation_metadata(ctx);
        if (AMVP_SUCCESS != rv) {
            AMVP_LOG_ERR("Validation metadata not ready");
            goto end;
        }

        ctx->fips.do_validation = 1; /* Enable */
    } else {
        ctx->fips.do_validation = 0; /* Disable */
    }

    n = 1;    /* start with second array index */
    reg_array = json_value_get_array(val);
    vs_val = json_array_get_value(reg_array, n);

    while (vs_entry) {

        /* check vsId compared to vs URL */
        rsp_obj = json_array_get_object(reg_array, n);
        ctx->vs_id = json_object_get_number(rsp_obj, "vsId");

        vec_array_val = json_value_init_array();
        vec_array = json_array((const JSON_Value *)vec_array_val);

        json_result = json_serialize_to_string_pretty(vs_val, NULL);
        new_val = json_parse_string(json_result);
        json_free_serialized_string(json_result);

        json_array_append_value(vec_array, new_val);

        ctx->kat_resp = vec_array_val;

        json_result = json_serialize_to_string_pretty(ctx->kat_resp, NULL);
        if (ctx->log_lvl == AMVP_LOG_LVL_VERBOSE) {
            printf("\n\n%s\n\n", json_result);
        } else {
            AMVP_LOG_INFO("\n\n%s\n\n", json_result);
        }
        json_free_serialized_string(json_result);
        AMVP_LOG_STATUS("Sending responses for vector set %d", ctx->vs_id);
        rv = amvp_submit_vector_responses(ctx, vs_entry->string);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Failed to submit test results for vector set - skipping...");
        }

        json_value_free(vec_array_val);
        ctx->kat_resp = NULL;
        n++;
        vs_val = json_array_get_value(reg_array, n);
        vs_entry = vs_entry->next;
    }

    /*
     * Check the test results.
     */
    AMVP_LOG_STATUS("Tests complete, checking results...");
    rv = amvp_check_test_results(ctx);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Unable to retrieve test results");
    }

    rv = amvp_cert_req(ctx);
    if (AMVP_SUCCESS != rv) {
        AMVP_LOG_ERR("cert req failed");
        goto end;
    }
    
    if (fips_validation) {
        /*
         * Tell the server to provision a FIPS certificate for this testSession.
         */
        rv = amvp_validate_test_session(ctx);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Failed to perform Validation of testSession");
            goto end;
        }
    }
end:
    json_value_free(val);
    return rv;
}

/**
 * Allows application (with proper authentication) to connect to server and get results
 * of previous test session.
 */
AMVP_RESULT amvp_get_results_from_server(AMVP_CTX *ctx, const char *request_filename) {
    AMVP_RESULT rv = AMVP_SUCCESS;

    if (!ctx) {
        return AMVP_NO_CTX;
    }
  
    rv = amvp_parse_session_info_file(ctx, request_filename);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Error reading session info file, unable to get results");
        goto end;
    }

    rv = amvp_refresh(ctx);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Failed to refresh login with AMVP server");
        goto end;
    }

    rv = amvp_check_test_results(ctx);
    
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Unable to retrieve test results");
        goto end;
    }
    
end:
    return rv;
}

AMVP_RESULT amvp_get_expected_results(AMVP_CTX *ctx, const char *request_filename, const char *save_filename) {
    JSON_Value *val = NULL, *fw_val = NULL;
    JSON_Object *obj = NULL, *fw_obj = NULL;
    AMVP_RESULT rv = AMVP_SUCCESS;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    rv = amvp_parse_session_info_file(ctx, request_filename);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Failed to parse session info file while trying to get expected results");
        goto end;
    }
    if (save_filename && strnlen_s(save_filename, AMVP_JSON_FILENAME_MAX + 1) > AMVP_JSON_FILENAME_MAX) {
        AMVP_LOG_ERR("Provided filename length > max(%d)", AMVP_JSON_FILENAME_MAX);
        return AMVP_INVALID_ARG;
    }

    if (!ctx->is_sample) {
        AMVP_LOG_ERR("Session not marked as sample");
        rv = AMVP_UNSUPPORTED_OP;
        goto end;
    }

    rv = amvp_refresh(ctx);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Failed to refresh login with AMVP server");
        goto end;
    }

    rv = amvp_retrieve_vector_set_result(ctx, ctx->session_url);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Error retrieving vector set results!");
        goto end;
    }

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

    JSON_Array *results = NULL;
    int count = 0, i = 0;
    JSON_Object *current = NULL;
    const char *vsid_url = NULL;

    results = json_object_get_array(obj, "results");
    if (!results) {
        AMVP_LOG_ERR("Error parsing status from server");
        rv = AMVP_JSON_ERR;
        goto end;
    }

    AMVP_LOG_STATUS("Beginning output of expected results...");

    if (save_filename) {
        //write the session URL and JWT to the file first
        fw_val = json_value_init_object();
        if (!fw_val) {
            AMVP_LOG_ERR("Error initializing JSON object");
            rv = AMVP_MALLOC_FAIL;
            goto end;
        }
        fw_obj = json_value_get_object(fw_val);
        if (!fw_obj) {
            AMVP_LOG_ERR("Error initializing JSON object");
            rv = AMVP_MALFORMED_JSON;
            goto end;
        }
        json_object_set_string(fw_obj, "jwt", ctx->jwt_token);
        json_object_set_string(fw_obj, "url", ctx->session_url);
        rv = amvp_json_serialize_to_file_pretty_w(fw_val, save_filename);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Error writing to provided file.");
            json_value_free(fw_val);
            goto end;
        }
        json_value_free(fw_val);
        fw_val = NULL;
        fw_obj = NULL;
    }

    count = (int)json_array_get_count(results);
    for (i = 0; i < count; i++) {
        current = json_array_get_object(results, i);
        if (!current) {
            AMVP_LOG_ERR("Error parsing status from server");
            rv = AMVP_JSON_ERR;
            goto end;
        }
        
        vsid_url = json_object_get_string(current, "vectorSetUrl");
        if (!vsid_url) {
            AMVP_LOG_ERR("Error parsing vector set URL from server");
            rv = AMVP_JSON_ERR;
            goto end;
        }
        if (strnlen_s(vsid_url, AMVP_ATTR_URL_MAX + 1) > AMVP_ATTR_URL_MAX) {
            AMVP_LOG_ERR("URL is too long. Cannot proceed.");
            rv = AMVP_TRANSPORT_FAIL;
            goto end;
        }

        rv = amvp_retrieve_expected_result(ctx, vsid_url);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Error retrieving expected results from server");
            goto end;
        }

        //If save_filename != null, we are saving to file, otherwise log it all
        if (save_filename) {
            fw_val = json_parse_string(ctx->curl_buf);
            if (!fw_val) {
                AMVP_LOG_ERR("Error parsing JSON from server response");
                rv = AMVP_TRANSPORT_FAIL;
                goto end;
            }
            /* append data */
            rv = amvp_json_serialize_to_file_pretty_a(fw_val, save_filename);
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("Error writing to file");
                goto end;
            }
            json_value_free(fw_val);
            fw_val = NULL;
        } else {
            printf("%s,\n", ctx->curl_buf);
        }
        vsid_url = NULL;
    }
    //append the final ']'
    rv = amvp_json_serialize_to_file_pretty_a(NULL, save_filename);
    AMVP_LOG_STATUS("Completed output of expected results.");
end:
   if (fw_val) json_value_free(fw_val);
   if (val) json_value_free(val);
   return rv;
}

/**
 * Allows application to continue a previous test session by checking which KAT responses the server is missing
 */
AMVP_RESULT amvp_resume_test_session(AMVP_CTX *ctx, const char *request_filename, int fips_validation) {
    JSON_Value *val = NULL;
    JSON_Object *obj = NULL;
    AMVP_RESULT rv = AMVP_SUCCESS;
    
    if (!ctx) {
        return AMVP_NO_CTX;
    }
    
    AMVP_LOG_STATUS("Resuming session...");
    if (ctx->vector_req) {
        AMVP_LOG_STATUS("Restarting download of vector sets to file...");
    }

    rv = amvp_parse_session_info_file(ctx, request_filename);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Unable to parse session info file to resume session");
        goto end;
    }

    rv = amvp_refresh(ctx);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Failed to refresh login with AMVP server");
        goto end;
    }

    rv = amvp_retrieve_vector_set_result(ctx, ctx->session_url);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Error retrieving vector set results!");
        goto end;
    }

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

    if (fips_validation) {
        rv = amvp_verify_fips_validation_metadata(ctx);
        if (AMVP_SUCCESS != rv) {
            AMVP_LOG_ERR("Validation metadata not ready");
            return AMVP_UNSUPPORTED_OP;
        }

        ctx->fips.do_validation = 1; /* Enable */
    } else {
        ctx->fips.do_validation = 0; /* Disable */
    }
    /*
     * Check for vector sets the server received no response to
     */

    JSON_Array *results = NULL;
    int count = 0, i = 0;

    results = json_object_get_array(obj, "results");
    if (!results) {
        AMVP_LOG_ERR("Error parsing status from server");
        rv = AMVP_JSON_ERR;
        goto end;
    }
    
    count = (int)json_array_get_count(results);
    JSON_Object *current = NULL;
    const char *vsid_url = NULL, *status = NULL;
    
    for (i = 0; i < count; i++) {
        int diff = 1;
        current = json_array_get_object(results, i);
        if (!current) {
            AMVP_LOG_ERR("Error parsing status from server");
            rv = AMVP_JSON_ERR;
            goto end;
        }
        
        status = json_object_get_string(current, "status");
        if (!status) {
            AMVP_LOG_ERR("Error parsing status from server");
            rv = AMVP_JSON_ERR;
            goto end;
        }
        vsid_url = json_object_get_string(current, "vectorSetUrl");
        if (!vsid_url) {
            AMVP_LOG_ERR("Error parsing status from server");
            rv = AMVP_JSON_ERR;
            goto end;
        }
        
        if (ctx->vector_req) {
            //If we are just saving to file, we don't need to check status, download all VS
            rv = amvp_append_vsid_url(ctx, vsid_url);
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("Error resuming session");
                goto end;
            }
        } else {
            strcmp_s("expired", 7, status, &diff);
            if (!diff) {
                AMVP_LOG_ERR("One or more vector sets has expired! Start a new session.");
                rv = AMVP_INVALID_ARG;
                goto end;
            }
            
            /*
             * If the result is unreceived, add it to the list of vsID urls
             */
            strcmp_s("unreceived", 10, status, &diff);
            if (!diff) {
                rv = amvp_append_vsid_url(ctx, vsid_url);
                if (rv != AMVP_SUCCESS) {
                    AMVP_LOG_ERR("Error resuming session");
                    goto end;
                }
            }
        }
    }

    if (!ctx->vsid_url_list) {
        AMVP_LOG_STATUS("All vector set results already uploaded. Nothing to resume.");
        goto end;
    } else {
        rv = amvp_process_tests(ctx);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Failed to process vectors");
            goto end;
        }
        if (ctx->vector_req) {
            AMVP_LOG_STATUS("Successfully downloaded vector sets and saved to specified file.");
            return AMVP_SUCCESS;
        }

        /*
         * Check the test results.
         */
        AMVP_LOG_STATUS("Tests complete, checking results...");
        rv = amvp_check_test_results(ctx);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Unable to retrieve test results");
            goto end;
        }

        if (fips_validation) {
            /*
             * Tell the server to provision a FIPS certificate for this testSession.
             */
            rv = amvp_validate_test_session(ctx);
            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("Failed to perform Validation of testSession");
                goto end;
            }
        }

        if (ctx->put) {
           rv = amvp_put_data_from_ctx(ctx);
        }
    }
end:
    if (val) json_value_free(val);
    return rv;
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
 * Allows application to set JSON filename within context
 * to be read in during registration
 */
AMVP_RESULT amvp_set_json_filename(AMVP_CTX *ctx, const char *json_filename) {
    if (!ctx) {
        return AMVP_NO_CTX;
    }
    if (!json_filename) {
        AMVP_LOG_ERR("Must provide value for JSON filename");
        return AMVP_MISSING_ARG;
    }
    if (!ctx->vector_req) {
        AMVP_LOG_ERR("The session must be request only to use a manual registraion");
        return AMVP_UNSUPPORTED_OP;
    }

    if (ctx->json_filename) { free(ctx->json_filename); }

    if (strnlen_s(json_filename, AMVP_JSON_FILENAME_MAX + 1) > AMVP_JSON_FILENAME_MAX) {
        AMVP_LOG_ERR("Provided json_filename length > max(%d)", AMVP_JSON_FILENAME_MAX);
        return AMVP_INVALID_ARG;
    }

    ctx->json_filename = calloc(AMVP_JSON_FILENAME_MAX + 1, sizeof(char));
    if (!ctx->json_filename) {
        return AMVP_MALLOC_FAIL;
    }
    strcpy_s(ctx->json_filename, AMVP_JSON_FILENAME_MAX + 1, json_filename);

    ctx->use_json = 1;

    return AMVP_SUCCESS;
}

/*
 * This will return a string form of the current registration, regardless of whether the session
 * has already been started
 */
char *amvp_get_current_registration(AMVP_CTX *ctx, int *len) {
    char *registration = NULL;
    int length = 0;
    JSON_Value *reg = NULL;
    if (!ctx) {
        return NULL;
    }

    /* If we have a registration saved already, use that. Otherwise, build it and return it */
    if (ctx->registration) {
        reg = ctx->registration;
    } else {
        if (amvp_build_registration_json(ctx, &reg) != AMVP_SUCCESS) {
            return NULL;
        }
    }
    registration = json_serialize_to_string_pretty(reg, &length);
    if (len) *len = length;

    /* free the JSON_Value if built on the fly */
    if (!ctx->registration) {
        json_value_free(reg);
    }
    return registration;
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
 * This function is used by the application to specify the
 * AMVP server URI path segment prefix.
 */
AMVP_RESULT amvp_set_api_context(AMVP_CTX *ctx, const char *api_context) {
    if (!ctx) {
        return AMVP_NO_CTX;
    }
    if (!api_context) {
        return AMVP_INVALID_ARG;
    }
    if (strnlen_s(api_context, AMVP_SESSION_PARAMS_STR_LEN_MAX + 1) > AMVP_SESSION_PARAMS_STR_LEN_MAX) {
        AMVP_LOG_ERR("API context string(s) too long");
        return AMVP_INVALID_ARG;
    }
    if (ctx->api_context) { free(ctx->api_context); }
    ctx->api_context = calloc(AMVP_SESSION_PARAMS_STR_LEN_MAX + 1, sizeof(char));
    if (!ctx->api_context) {
        return AMVP_MALLOC_FAIL;
    }
    strcpy_s(ctx->api_context, AMVP_SESSION_PARAMS_STR_LEN_MAX + 1, api_context);

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

AMVP_RESULT amvp_mark_as_sample(AMVP_CTX *ctx) {
    if (!ctx) {
        return AMVP_NO_CTX;
    }
    ctx->is_sample = 1;
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
    ctx->get = 1;
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
    if (!ctx->get) {
        AMVP_LOG_ERR("Session must be marked as get only to set a get save file");
        return AMVP_UNSUPPORTED_OP;
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

AMVP_RESULT amvp_mark_as_put_after_test(AMVP_CTX *ctx, char *filename) {
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

    if (ctx->put_filename) { free(ctx->put_filename); }
    ctx->put_filename = calloc(AMVP_SESSION_PARAMS_STR_LEN_MAX + 1, sizeof(char));
    if (!ctx->put_filename) {
        return AMVP_MALLOC_FAIL;
    }
    strcpy_s(ctx->put_filename, AMVP_SESSION_PARAMS_STR_LEN_MAX + 1, filename);
    ctx->put = 1;
    return AMVP_SUCCESS;
}

AMVP_RESULT amvp_mark_as_cert_req(AMVP_CTX *ctx, char *filename) {
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

    if (ctx->mod_cert_req_file) { free(ctx->mod_cert_req_file); }
    ctx->mod_cert_req_file = calloc(AMVP_SESSION_PARAMS_STR_LEN_MAX + 1, sizeof(char));
    if (!ctx->mod_cert_req_file) {
        return AMVP_MALLOC_FAIL;
    }
    strcpy_s(ctx->mod_cert_req_file, AMVP_SESSION_PARAMS_STR_LEN_MAX + 1, filename);
    ctx->mod_cert_req = 1;
    return AMVP_SUCCESS;
}

AMVP_RESULT amvp_mark_as_post_only(AMVP_CTX *ctx, char *filename) {

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

    if (ctx->post_filename) { free(ctx->post_filename); }
    ctx->post_filename = calloc(AMVP_SESSION_PARAMS_STR_LEN_MAX + 1, sizeof(char));
    if (!ctx->post_filename) {
        return AMVP_MALLOC_FAIL;
    }

    strcpy_s(ctx->post_filename, AMVP_SESSION_PARAMS_STR_LEN_MAX + 1, filename);
    ctx->post = 1;
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
    ctx->delete = 1;
    return AMVP_SUCCESS;
}

int amvp_get_vector_set_count(AMVP_CTX *ctx) {
    if (!ctx) {
        return -1;
    }
    return ctx->vs_count;
}

/*
 * This function builds the JSON login message that
 * will be sent to the AMVP server. If enabled,
 * it will perform the second of the two-factor
 * authentications using a TOTP.
 */
static AMVP_RESULT amvp_build_login(AMVP_CTX *ctx, char **login, int *login_len, int refresh) {
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
}

/*
 * This function is used to register the DUT with the server.
 * Registration allows the DUT to advertise it's capabilities to
 * the server.  The server will respond with a set of vector set
 * identifiers that the client will need to process.
 */
static AMVP_RESULT amvp_register(AMVP_CTX *ctx) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    char *reg = NULL;
    int reg_len = 0, count = 0;

    JSON_Value *tmp_json = NULL;
    JSON_Array *tmp_arr = NULL;
    if (!ctx) {
        return AMVP_NO_CTX;
    }

    /*
     * Send the capabilities to the AMVP server and get the response,
     * which should be a list of vector set ID urls
     */
    if (ctx->use_json) {
        AMVP_LOG_STATUS("Reading capabilities registration file...");
        tmp_json = json_parse_file(ctx->json_filename);
        if (!tmp_json) {
            AMVP_LOG_ERR("Error reading capabilities file");
            rv = AMVP_JSON_ERR;
            goto end;
        }
        /* Quickly sanity check format */
        tmp_arr = json_value_get_array(tmp_json);
        if (!tmp_arr) {
            AMVP_LOG_ERR("Provided capabilities file in invalid format");
            rv = AMVP_JSON_ERR;
            goto end;
        }
        count = json_array_get_count(tmp_arr);
        if (count < 1 || count > AMVP_CAP_MAX) {
            AMVP_LOG_ERR("Invalid number of capability objects in provided file! Min: 1, Max: %d", AMVP_CAP_MAX);
            rv = AMVP_JSON_ERR;
            goto end;
        }
        ctx->registration = tmp_json;
    } else {
        AMVP_LOG_STATUS("Building registration of capabilities...");
        rv = amvp_build_registration_json(ctx, &tmp_json);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Unable to build registration");
            goto end;
        } else {
            ctx->registration = tmp_json;
        }
    }

    rv = amvp_build_full_registration(ctx, &reg, &reg_len);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Error occurred building registration JSON: %d", rv);
        goto end;
    }

    AMVP_LOG_STATUS("Sending registration of capabilities...");
    AMVP_LOG_INFO("%s", reg);
    rv = amvp_send_test_session_registration(ctx, reg, reg_len);
    if (rv == AMVP_SUCCESS) {
        rv = amvp_parse_test_session_register(ctx);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Failed to parse test session response");
            goto end;
        }
        AMVP_LOG_STATUS("Successfully sent registration and received list of vector set URLs");
        AMVP_LOG_STATUS("Test session URL: %s", ctx->session_url);
    } else {
        AMVP_LOG_ERR("Failed to send registration");
    }

end:
    if (reg) json_free_serialized_string(reg);
    return rv;
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

/*
 * This function will process a single KAT vector set.  Each KAT
 * vector set has an identifier associated with it, called
 * the vs_id.  During registration, libamvp will receive the
 * list of vs_id's that need to be processed during the test
 * session.  This routine will execute the test flow for a single
 * vs_id.  The flow is:
 *    a) Download the KAT vector set from the server using the vs_id
 *    b) Parse the KAT vectors
 *    c) Process each test case in the KAT vector set
 *    d) Generate the response data
 *    e) Send the response data back to the AMVP server
 */
static AMVP_RESULT amvp_process_teid(AMVP_CTX *ctx, char *vsid_url, int count) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    JSON_Value *val = NULL;
    JSON_Value *ts_val = NULL;
    JSON_Object *ts_obj = NULL;
    JSON_Object *obj = NULL;
    JSON_Value *set_val = NULL;
    JSON_Array *set_array = NULL;
    JSON_Array *url_arr = NULL;
    AMVP_STRING_LIST *vs_entry = NULL;
    int retry_period = 0;
    int retry = 1;
    unsigned int time_waited_so_far = 0;
    while (retry) {
        /*
         * Get the KAT vector set
         */
        rv = amvp_retrieve_vector_set(ctx, vsid_url);
        if (rv != AMVP_SUCCESS) goto end;

        val = json_parse_string(ctx->curl_buf);
        if (!val) {
            AMVP_LOG_ERR("JSON parse error");
            rv = AMVP_JSON_ERR;
            goto end;
        }
        obj = amvp_get_obj_from_rsp(ctx, val);

        /*
         * Check if we received a retry response
         */
        retry_period = json_object_get_number(obj, "retry");
        if (retry_period) {
            /*
             * Wait and try again to retrieve the evSet
             */
            if (amvp_retry_handler(ctx, &retry_period, &time_waited_so_far, 1, AMVP_WAITING_FOR_TESTS) != AMVP_KAT_DOWNLOAD_RETRY) {
                AMVP_LOG_STATUS("Maximum wait time with server reached! (Max: %d seconds)", AMVP_MAX_WAIT_TIME);
                rv = AMVP_TRANSPORT_FAIL;
                goto end;
            };
            retry = 1;
        } else {
            /*
             * Save the Evidence Template to file
             */
            if (ctx->vector_req) {
                
                set_array = json_value_get_array(val);
                set_val = json_array_get_value(set_array, 0);
                
                AMVP_LOG_STATUS("Saving vector set %s to file...", vsid_url);
                /* track first vector set with file count */
                if (count == 0) {
                    ts_val = json_value_init_object();
                    ts_obj = json_value_get_object(ts_val);

                    json_object_set_string(ts_obj, "jwt", ctx->jwt_token);
                    json_object_set_string(ts_obj, "url", ctx->session_url);
                    json_object_set_boolean(ts_obj, "isSample", ctx->is_sample);

                    json_object_set_value(ts_obj, "ieSetsId", json_value_init_array());
                    url_arr = json_object_get_array(ts_obj, "ieSetsId");

                    vs_entry = ctx->vsid_url_list;
                    while (vs_entry) {
                        json_array_append_string(url_arr, vs_entry->string);
                        vs_entry = vs_entry->next;
                    }
                    /* Start with identifiers */
                    rv = amvp_json_serialize_to_file_pretty_w(ts_val, ctx->vector_req_file);
                    if (rv != AMVP_SUCCESS) {
                        AMVP_LOG_ERR("File write error");
                        json_value_free(ts_val);
                        goto end;
                    }
                } 
                /* append the TE groups */
                rv = amvp_json_serialize_to_file_pretty_a(set_val, ctx->vector_req_file);
                json_value_free(ts_val);
                goto end;
            }
            /*
             * Process the KAT VectorSet
             */
            rv = amvp_process_ie_set(ctx, obj);
            json_value_free(ts_val);
            retry = 0;
        }

        if (rv != AMVP_SUCCESS) goto end;
        json_value_free(val);
        val = NULL;
    }

    /*
     * Send the responses to the AMVP server
     */
    AMVP_LOG_STATUS("Posting ie set responses for vsId %d to URL: %s...", ctx->vs_id, vsid_url);
    rv = amvp_submit_vector_responses(ctx, vsid_url);

end:
    if (val) json_value_free(val);
    return rv;
}

/*
 * This function is used by the application after registration
 * to commence the testing.  All the testing will be handled
 * by libamvp.  This function will block the caller.  Therefore,
 * it should be run on a separate thread if needed.
 */
static
AMVP_RESULT amvp_process_amvp_tes(AMVP_CTX *ctx) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    AMVP_STRING_LIST *vs_entry = NULL;
    int count = 0;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    /*
     * Iterate through the TE identifiers the server sent to us
     * in the test session register response.  Process each vector set and
     * return the results to the server.
     */
    vs_entry = ctx->vsid_url_list;
    if (!vs_entry) {
        return AMVP_MISSING_ARG;
    }
    while (vs_entry) {
        rv = amvp_process_teid(ctx, vs_entry->string, count);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Unable to process vector set! Error: %d", rv);
            return rv;
        }
        vs_entry = vs_entry->next;
        count++;
    }
    /* Need to add the ending ']' here */
    if (ctx->vector_req) {
        rv = amvp_json_serialize_to_file_pretty_a(NULL, ctx->vector_req_file);
    }
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
    AMVP_PROTOCOL_ERR *err = NULL;
    char *reg = NULL;
    int reg_len = 0, count = 0;

    JSON_Value *tmp_json = NULL;
    JSON_Array *tmp_arr = NULL;
    if (!ctx) {
        return AMVP_NO_CTX;
    }

    /*
     * Send the capabilities to the AMVP server and get the response,
     * which should be a list of vector set ID urls
     */
    AMVP_LOG_STATUS("Reading module cert request file...");
    tmp_json = json_parse_file(ctx->mod_cert_req_file);
    if (!tmp_json) {
        AMVP_LOG_ERR("Error reading capabilities file");
        rv = AMVP_JSON_ERR;
        goto end;
    }
    /* Quickly sanity check format */
    tmp_arr = json_value_get_array(tmp_json);
    if (!tmp_arr) {
        AMVP_LOG_ERR("Provided capabilities file in invalid format");
        rv = AMVP_JSON_ERR;
        goto end;
    }
    count = json_array_get_count(tmp_arr);
    if (count < 1 || count > AMVP_CAP_MAX) {
        AMVP_LOG_ERR("Invalid number of capability objects in provided file! Min: 1, Max: %d", AMVP_CAP_MAX);
        rv = AMVP_JSON_ERR;
        goto end;
    }
    ctx->registration = tmp_json;
    reg = json_serialize_to_string(tmp_json, &reg_len);
    
    AMVP_LOG_STATUS("Sending module cert request...");
    //AMVP_LOG_STATUS("    request: %s", reg);
    //AMVP_LOG_STATUS("    POST...Url: %s","/amv/v1/certRequest");
    rv = amvp_transport_post(ctx, "/amv/v1/certRequest", reg, reg_len);
    
    if (rv == AMVP_SUCCESS) {
        rv = amvp_parse_mod_cert_req(ctx);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Failed to parse test session response");
            goto end;
        }
        AMVP_LOG_STATUS("Successfully sent mod cert req and received list of TE URLs");
    } else {
        AMVP_LOG_ERR("Failed to send registration");
        goto end;
    }

    /*
     * Now we process the test cases given to us during
     * registration earlier.
     */
    rv = amvp_process_amvp_tes(ctx);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Failed to process TEs");
        goto end;
    }

end:
    if (reg) json_free_serialized_string(reg);
    if (err) amvp_free_protocol_err(err);
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
#ifdef AMVP_DEPRECATED
    int large_required = 0;
#endif
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
#ifdef AMVP_DEPRECATED
    large_required = json_object_get_boolean(obj, "largeEndpointRequired");

    if (large_required) {
        /* Grab the large submission sizeConstraint */
        ctx->post_size_constraint = json_object_get_number(obj, "sizeConstraint");
    }
#endif
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

#ifdef AMVP_DEPRECATED
AMVP_RESULT amvp_notify_large(AMVP_CTX *ctx,
                              const char *url,
                              char *large_url,
                              unsigned int data_len) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    JSON_Value *arr_val = NULL, *val = NULL,
               *server_val = NULL;
    JSON_Object *obj = NULL, *server_obj = NULL;
    JSON_Array *arr = NULL;
    char *substr = NULL;
    char snipped_url[AMVP_ATTR_URL_MAX + 1] = {0} ;
    char *large_notify = NULL;
    const char *jwt = NULL;
    int notify_len = 0;
    const char *large_url_str = NULL;

    if (!url) return AMVP_MISSING_ARG;
    if (!large_url) return AMVP_MISSING_ARG;
    if (!(data_len > ctx->post_size_constraint)) return AMVP_INVALID_ARG;

    arr_val = json_value_init_array();
    arr = json_array((const JSON_Value *)arr_val);

    /*
     * Start the large/ array
     */
    val = json_value_init_object();
    obj = json_value_get_object(val);

    /* 
     * Cut off the https://name:port/ prefix and /results suffix
     */
    strstr_s((char *)url, AMVP_ATTR_URL_MAX, "/amv/v1", 8, &substr);
    strcpy_s(snipped_url, AMVP_ATTR_URL_MAX, substr);
    strstr_s(snipped_url, AMVP_ATTR_URL_MAX, "/results", 8, &substr);
    if (!substr) {
        rv = AMVP_INVALID_ARG;
        goto err;
    }
    *substr = '\0';

    json_object_set_string(obj, "vectorSetUrl", snipped_url);
    json_object_set_number(obj, "submissionSize", data_len);
    
    json_array_append_value(arr, val);

    large_notify = json_serialize_to_string(arr_val, &notify_len);

    AMVP_LOG_ERR("Notifying /large endpoint for this submission... %s", large_notify);
    rv = amvp_transport_post(ctx, "large", large_notify, notify_len);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Failed to notify /large endpoint");
        goto err;
    }

    server_val = json_parse_string(ctx->curl_buf);
    if (!server_val) {
        AMVP_LOG_ERR("JSON parse error");
        rv = AMVP_JSON_ERR;
        goto err;
    }
    server_obj = amvp_get_obj_from_rsp(ctx, server_val);

    if (!server_obj) {
        AMVP_LOG_ERR("JSON parse error no server object");
        rv = AMVP_JSON_ERR;
        goto err;
    }

    /* Grab the full large/ endpoint URL */
    large_url_str = json_object_get_string(server_obj, "url");
    if (!large_url_str) {
        AMVP_LOG_ERR("JSON parse error no large URL object");
        rv = AMVP_JSON_ERR;
        goto err;
    }

    strcpy_s(large_url, AMVP_ATTR_URL_MAX, large_url_str);

    jwt = json_object_get_string(server_obj, "accessToken");
    if (jwt) {
        /*
         * A single-use JWT was given.
         */
        if (strnlen_s(jwt, AMVP_JWT_TOKEN_MAX + 1) > AMVP_JWT_TOKEN_MAX) {
            AMVP_LOG_ERR("access_token too large");
            rv = AMVP_JWT_INVALID;
            goto err;
        }

        if (ctx->tmp_jwt) {
            memzero_s(ctx->tmp_jwt, AMVP_JWT_TOKEN_MAX);
        } else {
            ctx->tmp_jwt = calloc(AMVP_JWT_TOKEN_MAX + 1, sizeof(char));
        }
        strcpy_s(ctx->tmp_jwt, AMVP_JWT_TOKEN_MAX + 1, jwt);

        ctx->use_tmp_jwt = 1;
    }

err:
    if (arr_val) json_value_free(arr_val);
    if (server_val) json_value_free(server_val);
    if (large_notify) json_free_serialized_string(large_notify);
    return rv;
}
#endif

/*
 * This routine performs the JSON parsing of the test session registration
 * from the server. It should contain a list of URLs for vector sets that
 * can be queried to get the test parameters.
 */
static AMVP_RESULT amvp_parse_test_session_register(AMVP_CTX *ctx) {
    JSON_Value *val = NULL;
    JSON_Object *obj = NULL;
    JSON_Array *vect_sets = NULL;
    const char *test_session_url = NULL, *access_token = NULL;
    int i = 0, vs_cnt = 0;
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
     * Identify the VS identifiers provided by the server, save them for
     * processing later.
     */
    vect_sets = json_object_get_array(obj, "vectorSetUrls");
    vs_cnt = json_array_get_count(vect_sets);
    for (i = 0; i < vs_cnt; i++) {
        const char *vsid_url = json_array_get_string(vect_sets, i);

        if (!vsid_url) {
            AMVP_LOG_ERR("No vsid_url");
            goto end;
        }

        rv = amvp_append_vsid_url(ctx, vsid_url);
        if (rv != AMVP_SUCCESS) goto end;
        AMVP_LOG_INFO("Received vsid_url=%s", vsid_url);
    }

end:
    if (val) json_value_free(val);
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
 * This function is used by the application after registration
 * to commence the testing.  All the testing will be handled
 * by libamvp.  This function will block the caller.  Therefore,
 * it should be run on a separate thread if needed.
 */
AMVP_RESULT amvp_process_tests(AMVP_CTX *ctx) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    AMVP_STRING_LIST *vs_entry = NULL;
    int count = 0;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    /*
     * Iterate through the VS identifiers the server sent to us
     * in the test session register response.  Process each vector set and
     * return the results to the server.
     */
    vs_entry = ctx->vsid_url_list;
    if (!vs_entry) {
        return AMVP_MISSING_ARG;
    }
    while (vs_entry) {
        rv = amvp_process_vsid(ctx, vs_entry->string, count);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Unable to process vector set! Error: %d", rv);
            return rv;
        }
        vs_entry = vs_entry->next;
        count++;
    }
    /* Need to add the ending ']' here */
    if (ctx->vector_req) {
        rv = amvp_json_serialize_to_file_pretty_a(NULL, ctx->vector_req_file);
    }
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
        AMVP_LOG_STATUS("200 OK KAT values not ready, server requests we wait %u seconds and try again...", *retry_period);
    } else if (situation == AMVP_WAITING_FOR_RESULTS) {
        AMVP_LOG_STATUS("200 OK results not ready, waiting %u seconds and trying again...", *retry_period);
    } else {
        AMVP_LOG_STATUS("200 OK, waiting %u seconds and trying again...", *retry_period);
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

/*
 * This routine will iterate through all the vector sets, requesting
 * the test result from the server for each set.
 */
AMVP_RESULT amvp_check_test_results(AMVP_CTX *ctx) {
    AMVP_RESULT rv = AMVP_SUCCESS;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    rv = amvp_get_result_test_session(ctx, ctx->session_url);
    return rv;
}

/***************************************************************************************************************
* Begin vector processing logic
***************************************************************************************************************/

static AMVP_RESULT amvp_login(AMVP_CTX *ctx, int refresh) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    AMVP_PROTOCOL_ERR *err = NULL;
    char *login = NULL;
    int login_len = 0;

    AMVP_LOG_STATUS("Logging in...");
    rv = amvp_build_login(ctx, &login, &login_len, refresh);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Unable to build login message");
        goto end;
    }
    AMVP_LOG_STATUS("    Login info: %s", login);

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
        //AMVP_LOG_STATUS("    Login Response: %s", ctx->curl_buf);
    }
end:
    if (login) free(login);
    if (err) amvp_free_protocol_err(err);
    return rv;
}

AMVP_RESULT amvp_refresh(AMVP_CTX *ctx) {
    if (!ctx) {
        return AMVP_NO_CTX;
    }

    return amvp_login(ctx, 1);
}


/*
 * This function will process a single KAT vector set.  Each KAT
 * vector set has an identifier associated with it, called
 * the vs_id.  During registration, libamvp will receive the
 * list of vs_id's that need to be processed during the test
 * session.  This routine will execute the test flow for a single
 * vs_id.  The flow is:
 *    a) Download the KAT vector set from the server using the vs_id
 *    b) Parse the KAT vectors
 *    c) Process each test case in the KAT vector set
 *    d) Generate the response data
 *    e) Send the response data back to the AMVP server
 */
static AMVP_RESULT amvp_process_vsid(AMVP_CTX *ctx, char *vsid_url, int count) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    JSON_Value *val = NULL;
    JSON_Value *alg_val = NULL;
    JSON_Array *alg_array = NULL;
    JSON_Array *url_arr = NULL;
    JSON_Value *ts_val = NULL;
    JSON_Object *ts_obj = NULL;
    JSON_Object *obj = NULL;
    AMVP_STRING_LIST *vs_entry = NULL;
    int retry_period = 0;
    int retry = 1;
    unsigned int time_waited_so_far = 0;
    while (retry) {
        /*
         * Get the KAT vector set
         */
        rv = amvp_retrieve_vector_set(ctx, vsid_url);
        if (rv != AMVP_SUCCESS) goto end;

        val = json_parse_string(ctx->curl_buf);
        if (!val) {
            AMVP_LOG_ERR("JSON parse error");
            rv = AMVP_JSON_ERR;
            goto end;
        }
        obj = amvp_get_obj_from_rsp(ctx, val);

        /*
         * Check if we received a retry response
         */
        retry_period = json_object_get_number(obj, "retry");
        if (retry_period) {
            /*
             * Wait and try again to retrieve the VectorSet
             */
            if (amvp_retry_handler(ctx, &retry_period, &time_waited_so_far, 1, AMVP_WAITING_FOR_TESTS) != AMVP_KAT_DOWNLOAD_RETRY) {
                AMVP_LOG_STATUS("Maximum wait time with server reached! (Max: %d seconds)", AMVP_MAX_WAIT_TIME);
                rv = AMVP_TRANSPORT_FAIL;
                goto end;
            };
            retry = 1;
        } else {
            /*
             * Save the KAT VectorSet to file
             */
            if (ctx->vector_req) {
                
                AMVP_LOG_STATUS("Saving vector set %s to file...", vsid_url);
                alg_array = json_value_get_array(val);
                alg_val = json_array_get_value(alg_array, 1);

                /* track first vector set with file count */
                if (count == 0) {
                    ts_val = json_value_init_object();
                    ts_obj = json_value_get_object(ts_val);

                    json_object_set_string(ts_obj, "jwt", ctx->jwt_token);
                    json_object_set_string(ts_obj, "url", ctx->session_url);
                    json_object_set_boolean(ts_obj, "isSample", ctx->is_sample);

                    json_object_set_value(ts_obj, "vectorSetUrls", json_value_init_array());
                    url_arr = json_object_get_array(ts_obj, "vectorSetUrls");

                    vs_entry = ctx->vsid_url_list;
                    while (vs_entry) {
                        json_array_append_string(url_arr, vs_entry->string);
                        vs_entry = vs_entry->next;
                    }
                    /* Start with identifiers */
                    rv = amvp_json_serialize_to_file_pretty_w(ts_val, ctx->vector_req_file);
                    if (rv != AMVP_SUCCESS) {
                        AMVP_LOG_ERR("File write error");
                        json_value_free(ts_val);
                        goto end;
                    }
                } 
                /* append vector set */
                rv = amvp_json_serialize_to_file_pretty_a(alg_val, ctx->vector_req_file);
                json_value_free(ts_val);
                goto end;
            }
            /*
             * Process the KAT VectorSet
             */
            rv = amvp_process_vector_set(ctx, obj);
            json_value_free(ts_val);
            retry = 0;
        }

        if (rv != AMVP_SUCCESS) goto end;
        json_value_free(val);
        val = NULL;
    }

    /*
     * Send the responses to the AMVP server
     */
    AMVP_LOG_STATUS("Posting vector set responses for vsId %d...", ctx->vs_id);
    rv = amvp_submit_vector_responses(ctx, vsid_url);

end:
    if (val) json_value_free(val);
    return rv;
}


/*
 * This function is used to invoke the appropriate handler function
 * for a given ACV operation.  The operation is specified in the
 * KAT vector set that was previously downloaded.  The handler function
 * is looked up in the alg_tbl[] and invoked here.
 */
static AMVP_RESULT amvp_dispatch_vector_set(AMVP_CTX *ctx, JSON_Object *obj) {
    int i;
    const char *alg = json_object_get_string(obj, "algorithm");
    const char *mode = json_object_get_string(obj, "mode");
    int vs_id = json_object_get_number(obj, "vsId");
    int diff = 1;

    ctx->vs_id = vs_id;
    AMVP_RESULT rv;

    if (!alg) {
        AMVP_LOG_ERR("JSON parse error: ACV algorithm not found");
        return AMVP_JSON_ERR;
    }

    AMVP_LOG_STATUS("Processing vector set: %d", vs_id);
    AMVP_LOG_STATUS("Algorithm: %s", alg);
    if (mode) {
        AMVP_LOG_STATUS("Mode: %s", mode);
    }
    for (i = 0; i < AMVP_ALG_MAX; i++) {
        strcmp_s(alg_tbl[i].name,
                 AMVP_ALG_NAME_MAX,
                 alg, &diff);
        if (!diff) {
            if (mode == NULL) {
                rv = (alg_tbl[i].handler)(ctx, obj);
                return rv;
            }

            if (alg_tbl[i].mode != NULL) {
                strcmp_s(alg_tbl[i].mode,
                        AMVP_ALG_MODE_MAX,
                        mode, &diff);
                if (!diff) {
                    rv = (alg_tbl[i].handler)(ctx, obj);
                    return rv;
                }
            }
        }
    }
    return AMVP_UNSUPPORTED_OP;
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


static const char *amvp_locate_auto_entry(AMVP_CTX *ctx, const char *evidence)
{
    int i;
    int diff;
    
    for (i=0; i<9; i++) {
        strcmp_s(evidence, strlen(amvp_evidence_tbl[i].evidence_name), amvp_evidence_tbl[i].evidence_name, &diff);
        if (!diff) {
            return (amvp_evidence_tbl[i].evidence);
        }
    }
    return NULL;
}


/*
 * This function is used to invoke the appropriate handler function
 * for a given ACV operation.  The operation is specified in the
 * KAT vector set that was previously downloaded.  The handler function
 * is looked up in the alg_tbl[] and invoked here.
 */
static AMVP_RESULT amvp_dispatch_ie_set(AMVP_CTX *ctx, JSON_Object *obj) {
    int ie_id = json_object_get_number(obj, "ievSetsId");
    JSON_Value *groupval;
    JSON_Object *groupobj = NULL;
    JSON_Array *groups;
    JSON_Array *tests;

    JSON_Value *reg_arry_val = NULL;
    JSON_Object *reg_obj = NULL;
    JSON_Array *reg_arry = NULL;

    int i, g_cnt, ieset_len;
    int j, t_cnt;

    JSON_Value *r_vs_val = NULL;
    JSON_Object *r_vs = NULL;
    JSON_Array *r_tarr = NULL, *r_garr = NULL;  /* Response testarray, grouparray */
    JSON_Value *r_tval = NULL, *r_gval = NULL;  /* Response testval, groupval */
    JSON_Object *r_tobj = NULL, *r_gobj = NULL; /* Response testobj, groupobj */
    const char *evidence;
    const char *ev_str;
    char *json_result;

    ctx->vs_id = ie_id;
    AMVP_RESULT rv;

    AMVP_LOG_STATUS("Processing ie set: %d", ie_id);
    /*
     * Create AMVP array for response
     */
    rv = amvp_create_array(&reg_obj, &reg_arry_val, &reg_arry);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Failed to create JSON response struct. ");
        return rv;
    }
    
    /*
     * Start to build the JSON response
     */
    rv = amvp_setup_json_ev_group(&ctx, &reg_arry_val, &r_vs_val, &r_vs, &r_garr);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Failed to setup json response");
        return rv;
    }

    groups = json_object_get_array(obj, "teGroups");
    if (!groups) {
        AMVP_LOG_ERR("Failed to include testGroups. ");
        rv = AMVP_MISSING_ARG;
        goto err;
    }

    g_cnt = json_array_get_count(groups);
    for (i = 0; i < g_cnt; i++) {
        int teId = 0;
        groupval = json_array_get_value(groups, i);
        groupobj = json_value_get_object(groupval);

        /*
         * Create a new group in the response with the teid
         * and an array of tests
         */
        r_gval = json_value_init_object();
        r_gobj = json_value_get_object(r_gval);
        
        teId = json_object_get_number(groupobj, "teId");
        if (!teId) {
            AMVP_LOG_ERR("Missing teId from server JSON groub obj");
            rv = AMVP_MALFORMED_JSON;
            goto err;
        }
        json_object_set_number(r_gobj, "teId", teId);
        json_object_set_value(r_gobj, "evidence", json_value_init_array());
        r_tarr = json_object_get_array(r_gobj, "evidence");

        AMVP_LOG_VERBOSE("    Test group: %d", i);

        tests = json_object_get_array(groupobj, "autoTE");
        if (!tests) {
            AMVP_LOG_ERR("Failed to include tests. ");
            rv = AMVP_MISSING_ARG;
            goto err;
        }

        t_cnt = json_array_get_count(tests);
        if (!t_cnt) {
            AMVP_LOG_ERR("Failed to include tests in array. ");
            rv = AMVP_MISSING_ARG;
            goto err;
        }

        for (j = 0; j < t_cnt; j++) {
            AMVP_LOG_VERBOSE("Found new TE ...");
            evidence = json_array_get_string(tests, j);

            if (!evidence) {
                AMVP_LOG_ERR("Failed to include evidence");
                rv = AMVP_MISSING_ARG;
                goto err;
            }

            AMVP_LOG_VERBOSE("        Test case: %d", j);
            AMVP_LOG_VERBOSE("         evidence: %s", evidence);

            /*
             * Create a new test case in the response
             */
            r_tval = json_value_init_object();
            r_tobj = json_value_get_object(r_tval);

            /* Determine if automated, if so gather the evidence information */
            ev_str = amvp_locate_auto_entry(ctx, evidence);
            if (!ev_str) {
                AMVP_LOG_INFO("AMVP skipping TE that is not automated");
                continue;
            }

            json_object_set_string(r_tobj, evidence, ev_str);

            /* Append the test response value to array */
            json_array_append_value(r_tarr, r_tval);
        }
        json_array_append_value(r_garr, r_gval);
    }

    json_array_append_value(reg_arry, r_vs_val);

    json_result = json_serialize_to_string_pretty(ctx->kat_resp, &ieset_len);
    AMVP_LOG_VERBOSE("\n\n%s\n\n", json_result);
    json_free_serialized_string(json_result);
    rv = AMVP_SUCCESS;

err:
    if (rv != AMVP_SUCCESS) {
        amvp_release_json(r_vs_val, r_gval);
    }

    return rv;
}

/*
 * This function is used to process the test cases for
 * a given KAT vector set.  This is invoked after the
 * KAT vector set has been downloaded from the server.  The
 * vectors are stored on the AMVP_CTX in one of the
 * transitory fields.  Therefore, the vs_id isn't needed
 * here to know which vectors need to be processed.
 *
 * The processing logic is:
 *    a) JSON parse the data
 *    b) Identify the AMVP operation to be performed (e.g. AES encrypt)
 *    c) Dispatch the vectors to the handler for the
 *       specified AMVP operation.
 */
static AMVP_RESULT amvp_process_vector_set(AMVP_CTX *ctx, JSON_Object *obj) {
    AMVP_RESULT rv;

    rv = amvp_dispatch_vector_set(ctx, obj);
    if (rv != AMVP_SUCCESS) {
        return rv;
    }

    AMVP_LOG_STATUS("Successfully processed vector set");
    return AMVP_SUCCESS;
}

/*
 * This function is used to process the test cases for
 * a given KAT vector set.  This is invoked after the
 * KAT vector set has been downloaded from the server.  The
 * vectors are stored on the AMVP_CTX in one of the
 * transitory fields.  Therefore, the vs_id isn't needed
 * here to know which vectors need to be processed.
 *
 * The processing logic is:
 *    a) JSON parse the data
 *    b) Identify the AMVP operation to be performed (e.g. AES encrypt)
 *    c) Dispatch the vectors to the handler for the
 *       specified AMVP operation.
 */
static AMVP_RESULT amvp_process_ie_set(AMVP_CTX *ctx, JSON_Object *obj) {
    AMVP_RESULT rv;

    rv = amvp_dispatch_ie_set(ctx, obj);
    if (rv != AMVP_SUCCESS) {
        return rv;
    }

    AMVP_LOG_STATUS("Successfully processed vector set");
    return AMVP_SUCCESS;
}

/*
 * This function will get the test results for a test session by checking the results of each vector set
 */
static AMVP_RESULT amvp_get_result_test_session(AMVP_CTX *ctx, char *session_url) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    JSON_Value *val = NULL;
    JSON_Value *val2 = NULL;
    JSON_Object *obj = NULL;
    JSON_Object *obj2 = NULL;
    int count = 0, i = 0, passed = 0;
    JSON_Array *results = NULL;
    JSON_Object *current = NULL;
    const char *status = NULL, *alg = NULL, *mode = NULL;
    unsigned int time_waited_so_far = 0;
    int retry_interval = AMVP_RETRY_TIME;
    //Maintains a list of names of algorithms that have failed
    AMVP_STRING_LIST *failedAlgList = NULL;
    AMVP_STRING_LIST *failedModeList = NULL;
    /*
     * Maintains a list of the vector set URLs we have already looked up,
     * so we don't redownload failed vector sets every time a retry is done
     */
     AMVP_STRING_LIST *failedVsList = NULL;

    while (1) {
        int testsCompleted = 0;

        /*
         * Get the KAT vector set
         */
        rv = amvp_retrieve_vector_set_result(ctx, session_url);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Error retrieving vector set results!");
            goto end;
        }

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

        /*
         * Check the results for each vector set - flag if some are incomplete,
         * or name failed algorithms (even if others are still incomplete)
         */
        results = json_object_get_array(obj, "results");
        count = (int)json_array_get_count(results);
        for (i = 0; i < count; i++) {
            int diff = 1;
            current = json_array_get_object(results, i);
            status = json_object_get_string(current, "status");
            if (!status) {
                goto end;
            }
            strcmp_s("expired", 7, status, &diff);
            if (!diff) {
                AMVP_LOG_ERR("One or more vector sets expired before results were submitted. Please start a new test session.");
                goto end;
            }
            
            strcmp_s("unreceived", 10, status, &diff);
            if (!diff) {
                AMVP_LOG_ERR("Missing submissions for one or more vector sets. Please submit responses for all vector sets.");
                goto end;
            }
            /*
             * If the result is incomplete, set the flag so it keeps retrying
             */
            strcmp_s("incomplete", 10, status, &diff);
            if (!diff) {
                continue;
            }
            /*
             * If the result is fail, retrieve vector set, get algorithm name, add to list
             */
            strcmp_s("fail", 4, status, &diff);
            if (!diff) {
                const char *vsurl = json_object_get_string(current, "vectorSetUrl");
                if (!vsurl) {
                    AMVP_LOG_ERR("No vector set URL when generating failed algorithm list");
                    break;
                }
                if (!amvp_lookup_str_list(&failedVsList, vsurl)) {
                    //append the vsurl to the list so we dont download/check same one twice
                    rv = amvp_append_str_list(&failedVsList, vsurl);
                    if (rv != AMVP_SUCCESS) {
                        AMVP_LOG_ERR("Error appending failed algorithm name to list, skipping...");
                        continue;
                    }
                    //retrieve_vector_set expects a non-const string
                    char *vs_url = calloc(AMVP_REQUEST_STR_LEN_MAX + 1, sizeof(char));
                    if (!vs_url) {
                        AMVP_LOG_ERR("Unable to calloc when reporting failed algorithms, skipping...");
                        continue;                    
                    }
                    strncpy_s(vs_url, AMVP_REQUEST_STR_LEN_MAX + 1, vsurl, AMVP_REQUEST_STR_LEN_MAX);
                    rv = amvp_retrieve_vector_set(ctx, vs_url);
                    free(vs_url);
                    if (rv != AMVP_SUCCESS) {
                        AMVP_LOG_ERR("Unable to retrieve vector set while reporting failed algorithms, skipping...");
                        continue;
                    }

                    val2 = json_parse_string(ctx->curl_buf);
                    if (!val2) {
                        AMVP_LOG_ERR("JSON parse error while reporting failed algorithms, skipping...");
                        continue;
                    }
                    obj2 = amvp_get_obj_from_rsp(ctx, val2);
                    if (!obj2) {
                        json_value_free(val2);
                        AMVP_LOG_ERR("JSON parse error while reporting failed algorithms, skipping...");
                        continue;
                    }
                    alg = json_object_get_string(obj2, "algorithm");
                    if (!alg) {
                        AMVP_LOG_ERR("JSON parse error while reporting failed algorithms, skipping...");
                        continue;
                    }
                    //Some algorithms have the same names, but different modes. Need to differentiate.
                    if (json_object_get_string(obj2, "mode")) {
                        mode = json_object_get_string(obj2, "mode");
                    }
                    if (!amvp_lookup_str_list(&failedAlgList, alg) || !amvp_lookup_str_list(&failedModeList, mode)) {
                        rv = amvp_append_str_list(&failedAlgList, alg);
                        if (rv != AMVP_SUCCESS) {
                            AMVP_LOG_ERR("Error appending failed algorithm name to list, skipping...");
                            continue;
                        }
                        if (mode) {
                            rv = amvp_append_str_list(&failedModeList, mode);
                        } else {
                            //use empty node to keep mode and algorithm indexes aligned in lists
                            rv = amvp_append_str_list(&failedModeList, "");
                        }
                        if (rv != AMVP_SUCCESS) {
                            AMVP_LOG_ERR("Error appending failed mode name to list, skipping...");
                            continue;
                        }
                        if (val2) json_value_free(val2);
                        val2 = NULL;
                    } else {
                        if (val2) json_value_free(val2);
                        val2 = NULL;
                    }
                }
            }
            testsCompleted++;
        }
        if (testsCompleted >= count) {
            passed = json_object_get_boolean(obj, "passed");
            if (passed == 1) {
                /*
                 * Pass, exit loop
                 */
                AMVP_LOG_STATUS("Passed all vectors in test session!");
                ctx->session_passed = 1;
                rv = AMVP_SUCCESS;
                goto end;
            } else {
                 /*
                  * Fail, continue with reporting results
                  */
                 AMVP_LOG_STATUS("Test session complete: some vectors failed, reporting results...");
                 AMVP_LOG_STATUS("Note: Use verbose-level logging to see results of each test case");
                 amvp_list_failing_algorithms(ctx, &failedAlgList, &failedModeList);
             }
        } else {
              /*
             * If any tests are incomplete, retry, even if some have failed
             */
            amvp_list_failing_algorithms(ctx, &failedAlgList, &failedModeList);
            AMVP_LOG_STATUS("TestSession results incomplete...");
            if (amvp_retry_handler(ctx, &retry_interval, &time_waited_so_far, 1, AMVP_WAITING_FOR_RESULTS) != AMVP_KAT_DOWNLOAD_RETRY) {
                AMVP_LOG_STATUS("Maximum wait time with server reached! (Max: %d seconds)", AMVP_MAX_WAIT_TIME);
                rv = AMVP_TRANSPORT_FAIL;
                goto end;
            }

            if (val) json_value_free(val);
            val = NULL;
            continue;
        }

        for (i = 0; i < count; i++) {
            int diff = 1;
            current = json_array_get_object(results, i);

            status = json_object_get_string(current, "status");
            if (!status) {
                goto end;
            }
            strcmp_s("fail", 4, status, &diff);
            if (diff)
                strcmp_s("error", 5, status, &diff);
            if (!diff) {
                const char *vs_url = json_object_get_string(current, "vectorSetUrl");
                if (ctx->log_lvl == AMVP_LOG_LVL_VERBOSE) {
                    AMVP_LOG_STATUS("Getting details for failed Vector Set...");
                    rv = amvp_retrieve_vector_set_result(ctx, vs_url);
                    printf("\n%s\n", ctx->curl_buf);
                    if (rv != AMVP_SUCCESS) goto end;
                }
            }
        }
        
        /* If we got here, the testSession failed, exit loop*/
        break;
    }

end:
    if (val) json_value_free(val);
    if (failedAlgList) {
        amvp_free_str_list(&failedAlgList);
    }
    if (failedModeList) {
        amvp_free_str_list(&failedModeList);
    }
    if (failedVsList) {
        amvp_free_str_list(&failedVsList);
    }
    return rv;
}

static AMVP_RESULT amvp_validate_test_session(AMVP_CTX *ctx) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    char *validation = NULL;
    int validation_len = 0;

    if (ctx == NULL) return AMVP_NO_CTX;

    if (ctx->session_passed != 1) {
        AMVP_LOG_ERR("This testSession cannot be certified. Required disposition == 'pass'.");
        return AMVP_SUCCESS; // Technically no error occurred
    }

    rv = amvp_build_validation(ctx, &validation, &validation_len);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Unable to build Validation message");
        goto end;
    }

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

end:
    if (validation) free(validation);

    return rv;
}


static
AMVP_RESULT amvp_post_data(AMVP_CTX *ctx, char *filename) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    JSON_Value *reg_arry_val = NULL;
    JSON_Object *reg_obj = NULL;
    JSON_Array *reg_arry = NULL;
    JSON_Array *data_array = NULL;
    JSON_Object *obj = NULL;
    JSON_Value *val = NULL;
    JSON_Value *post_val = NULL;
    JSON_Value *raw_val = NULL;
    const char *path = NULL;
    char *json_result = NULL;
    int len;

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

    data_array = json_value_get_array(val);
    obj = json_array_get_object(data_array, 0);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        goto end;
    }
    path = json_object_get_string(obj, "url");
    if (!path) {
        AMVP_LOG_WARN("Missing path, POST aborted");
        goto end;
    }

    raw_val = json_array_get_value(data_array, 1);
    json_result = json_serialize_to_string_pretty(raw_val, NULL);
    post_val = json_parse_string(json_result);
    json_free_serialized_string(json_result);

    rv = amvp_create_array(&reg_obj, &reg_arry_val, &reg_arry);
    json_array_append_value(reg_arry, post_val);

    json_result = json_serialize_to_string_pretty(reg_arry_val, &len);
    AMVP_LOG_STATUS("\nPOST Data: %s, %s\n\n", path, json_result);
    json_value_free(reg_arry_val);

    rv = amvp_transport_post(ctx, path, json_result, len);
    AMVP_LOG_STATUS("POST response:\n\n%s\n", ctx->curl_buf);
    json_free_serialized_string(json_result);

end:
    json_value_free(val);
    return rv;

}

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
    json_object_set_boolean(ts_obj, "isSample", ctx->is_sample);
    json_object_set_value(ts_obj, "registration", ctx->registration);

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


    if (ctx->mod_cert_req) {
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

    if (ctx->get) { 
        rv = amvp_transport_get(ctx, ctx->get_string, NULL);
        if (ctx->save_filename) {
            AMVP_LOG_STATUS("Saving GET result to specified file...");
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
            AMVP_LOG_STATUS("GET Response:\n\n%s\n", ctx->curl_buf);
        }
        goto end;
    }

    if (ctx->post) { 
        rv = amvp_post_data(ctx, ctx->post_filename);
        goto end;
    }

    if (ctx->post_resources) { 
        rv = amvp_post_resources(ctx, ctx->post_resources_filename);
        goto end;
    }

    if (ctx->mod_cert_req) { 
        rv = amvp_mod_cert_req(ctx);
        goto check;
    }

    if (ctx->delete) {
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

    if (fips_validation) {
        rv = amvp_verify_fips_validation_metadata(ctx);
        if (AMVP_SUCCESS != rv) {
            AMVP_LOG_ERR("Issue(s) with validation metadata, not continuing with session.");
            return AMVP_UNSUPPORTED_OP;
        }

        ctx->fips.do_validation = 1; /* Enable */
    } else {
        ctx->fips.do_validation = 0; /* Disable */
    }

    /*
     * Register with the server to advertise our capabilities and receive
     * the vector sets identifiers.
     */
    rv = amvp_register(ctx);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Failed to register with AMVP server");
        goto end;
    }
    
    //write session info so if we time out or lose connection waiting for results, we can recheck later on
    if (!ctx->put) {
        if (amvp_write_session_info(ctx) != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Error writing the session info file. Continuing, but session will not be able to be resumed or checked later on");
        }
    }

    AMVP_LOG_STATUS("Beginning to download and process vector sets...");

    /*
     * Now we process the test cases given to us during
     * registration earlier.
     */
    rv = amvp_process_tests(ctx);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Failed to process vectors");
        goto end;
    }
check:
    if (ctx->vector_req) {
        AMVP_LOG_STATUS("Successfully downloaded evidence and saved to specified file.");
        return AMVP_SUCCESS;
    }

    /*
     * Check the test results.
     */
    AMVP_LOG_STATUS("Tests complete, checking results...");
    rv = amvp_check_test_results(ctx);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Unable to retrieve test results");
        goto end;
    }
    if (ctx->mod_cert_req) {
        rv = amvp_cert_req(ctx);
        goto end;
    }
    
    if (fips_validation) {
        /*
         * Tell the server to provision a FIPS certificate for this testSession.
         */
        rv = amvp_validate_test_session(ctx);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Failed to perform Validation of testSession");
            goto end;
        }
    }

   if (ctx->put) {
       rv = amvp_put_data_from_ctx(ctx);
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

AMVP_RESULT amvp_put_data_from_file(AMVP_CTX *ctx, const char *put_filename) {
    JSON_Object *obj = NULL;
    JSON_Value *val = NULL;
    JSON_Value *meta_val = NULL;
    AMVP_RESULT rv = AMVP_SUCCESS;
    JSON_Array *reg_array;
    const char *test_session_url = NULL;
    const char *jwt = NULL;
    JSON_Value *put_val = NULL;
    JSON_Value *reg_arry_val = NULL;
    JSON_Object *reg_obj = NULL;
    JSON_Array *reg_arry = NULL;
    int len = 0;
    int validation = 0;
    char *json_result = NULL;

    if (!ctx) {
        return AMVP_NO_CTX;
    }
    if (!put_filename) {
        AMVP_LOG_ERR("Must provide value for JSON filename");
        return AMVP_MISSING_ARG;
    }

    if (strnlen_s(put_filename, AMVP_JSON_FILENAME_MAX + 1) > AMVP_JSON_FILENAME_MAX) {
        AMVP_LOG_ERR("Provided put_filename length > max(%d)", AMVP_JSON_FILENAME_MAX);
        return AMVP_INVALID_ARG;
    }

    val = json_parse_file(put_filename);
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

    /*
     * This is the identifiers provided by the server
     * for this specific test session!
     */
    test_session_url = json_object_get_string(obj, "url");
    if (!test_session_url) {
        AMVP_LOG_ERR("Missing session URL");
        rv = AMVP_MALFORMED_JSON;
        goto end;
    }

    jwt = json_object_get_string(obj, "jwt");
    if (jwt) {
        ctx->jwt_token = calloc(AMVP_JWT_TOKEN_MAX + 1, sizeof(char));
        if (!ctx->jwt_token) {
            rv = AMVP_MALLOC_FAIL;
            goto end;
        }
        strcpy_s(ctx->jwt_token, AMVP_JWT_TOKEN_MAX + 1, jwt);
    } else {
        rv = amvp_login(ctx, 0);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Failed to login with AMVP server");
            goto end;
        }
    }

    meta_val = json_array_get_value(reg_array, 1);
    obj = json_value_get_object(meta_val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        rv = AMVP_MALFORMED_JSON;
        goto end;
    }
    json_result = json_serialize_to_string(meta_val, &len);
    if (jwt && (json_object_has_value(obj, "oe") || json_object_has_value(obj, "oeUrl")) &&
        (json_object_has_value(obj, "module") || json_object_has_value(obj, "moduleUrl"))) {
        validation = 1;
    }

    put_val = json_parse_string(json_result);
    json_free_serialized_string(json_result);
    json_result = NULL;

    rv = amvp_create_array(&reg_obj, &reg_arry_val, &reg_arry);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_STATUS("Failed to create array");
        goto end;
    }
    json_array_append_value(reg_arry, put_val);
    json_result = json_serialize_to_string_pretty(reg_arry_val, &len);

    rv = amvp_transport_put(ctx, test_session_url, json_result, len);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_STATUS("Failed to perform PUT");
        goto end;
    }

    /*
     * Check the test results.
     */
    if (validation) {
        AMVP_LOG_STATUS("Checking validation response...");
        rv = amvp_parse_validation(ctx);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_STATUS("Failed to parse Validation response");
        }
    } else {
        AMVP_LOG_STATUS("PUT response: \n%s", ctx->curl_buf);
    }
end:
    if (json_result) {json_free_serialized_string(json_result);}
    if (val) {json_value_free(val);}
    if (put_val) {json_value_free(put_val);}
    return rv;
}

static AMVP_RESULT amvp_put_data_from_ctx(AMVP_CTX *ctx) {

    AMVP_RESULT rv = AMVP_SUCCESS;
    JSON_Array *reg_array;
    char *json_result = NULL;
    JSON_Value *val = NULL;
    JSON_Value *meta_val = NULL;
    JSON_Value *put_val = NULL;
    JSON_Value *reg_arry_val = NULL;
    JSON_Object *reg_obj = NULL;
    JSON_Array *reg_arry = NULL;
    int len = 0;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (strnlen_s(ctx->put_filename, AMVP_JSON_FILENAME_MAX + 1) > AMVP_JSON_FILENAME_MAX) {
        AMVP_LOG_ERR("Provided put_filename length > max(%d)", AMVP_JSON_FILENAME_MAX);
        return AMVP_INVALID_ARG;
    }

    val = json_parse_file(ctx->put_filename);
    if (!val) {
        AMVP_LOG_ERR("JSON val parse error");
        return AMVP_MALFORMED_JSON;
    }
    reg_array = json_value_get_array(val);

    meta_val = json_array_get_value(reg_array, 0);
    if (!val) {
        AMVP_LOG_ERR("JSON obj parse error");
        rv = AMVP_MALFORMED_JSON;
        goto end;
    }

    json_result = json_serialize_to_string(meta_val, &len);

    put_val = json_parse_string(json_result);
    json_free_serialized_string(json_result);
    json_result = NULL;

    rv = amvp_create_array(&reg_obj, &reg_arry_val, &reg_arry);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_STATUS("Failed to create array");
        goto end;
    }
    json_array_append_value(reg_arry, put_val);
    json_result = json_serialize_to_string_pretty(reg_arry_val, &len);

    rv = amvp_transport_put(ctx, ctx->session_url, json_result, len);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_STATUS("Failed to perform PUT");
        goto end;
    }

    /*
     * Check the test results.
     */
    AMVP_LOG_STATUS("Tests complete, checking results...");
    rv = amvp_parse_validation(ctx);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_STATUS("Failed to parse Validation response");
    }

end:
    if (json_result) {json_free_serialized_string(json_result);}
    if (put_val) {json_value_free(put_val);}
    if (val) {json_value_free(val);}
    return rv;
}

AMVP_SUB_CMAC amvp_get_cmac_alg(AMVP_CIPHER cipher)
{
    if ((cipher == AMVP_CIPHER_START) || (cipher >= AMVP_CIPHER_END)) {
        return 0;
    }
    return (alg_tbl[cipher-1].alg.cmac);
}

AMVP_SUB_HASH amvp_get_hash_alg(AMVP_CIPHER cipher)
{
    if ((cipher == AMVP_CIPHER_START) || (cipher >= AMVP_CIPHER_END)) {
        return 0;
    }
    return (alg_tbl[cipher-1].alg.hash);
}

AMVP_SUB_AES amvp_get_aes_alg(AMVP_CIPHER cipher)
{
    if ((cipher == AMVP_CIPHER_START) || (cipher >= AMVP_CIPHER_END)) {
        return 0;
    }
    return (alg_tbl[cipher-1].alg.aes);
}

AMVP_SUB_TDES amvp_get_tdes_alg(AMVP_CIPHER cipher)
{
    if ((cipher == AMVP_CIPHER_START) || (cipher >= AMVP_CIPHER_END)) {
        return 0;
    }
    return (alg_tbl[cipher-1].alg.tdes);
}

AMVP_SUB_HMAC amvp_get_hmac_alg(AMVP_CIPHER cipher)
{
    if ((cipher == AMVP_CIPHER_START) || (cipher >= AMVP_CIPHER_END)) {
        return 0;
    }
    return (alg_tbl[cipher-1].alg.hmac);
}

AMVP_SUB_KMAC amvp_get_kmac_alg(AMVP_CIPHER cipher)
{
    if ((cipher == AMVP_CIPHER_START) || (cipher >= AMVP_CIPHER_END)) {
        return 0;
    }
    return (alg_tbl[cipher-1].alg.kmac);
}


AMVP_SUB_RSA amvp_get_rsa_alg(AMVP_CIPHER cipher)
{
    if ((cipher == AMVP_CIPHER_START) || (cipher >= AMVP_CIPHER_END)) {
        return 0;
    }
    return (alg_tbl[cipher-1].alg.rsa);
}

AMVP_SUB_DSA amvp_get_dsa_alg(AMVP_CIPHER cipher)
{
    if ((cipher == AMVP_CIPHER_START) || (cipher >= AMVP_CIPHER_END)) {
        return 0;
    }
    return (alg_tbl[cipher-1].alg.dsa);
}

AMVP_SUB_ECDSA amvp_get_ecdsa_alg(AMVP_CIPHER cipher)
{
    if ((cipher == AMVP_CIPHER_START) || (cipher >= AMVP_CIPHER_END)) {
        return 0;
    }
    return (alg_tbl[cipher-1].alg.ecdsa);
}

AMVP_SUB_KDF amvp_get_kdf_alg(AMVP_CIPHER cipher)
{
    if ((cipher == AMVP_CIPHER_START) || (cipher >= AMVP_CIPHER_END)) {
        return 0;
    }
    return (alg_tbl[cipher-1].alg.kdf);
}

AMVP_SUB_DRBG amvp_get_drbg_alg(AMVP_CIPHER cipher)
{
    if ((cipher == AMVP_CIPHER_START) || (cipher >= AMVP_CIPHER_END)) {
        return 0;
    }
    return (alg_tbl[cipher-1].alg.drbg);
}

AMVP_SUB_KAS amvp_get_kas_alg(AMVP_CIPHER cipher)
{
    if ((cipher == AMVP_CIPHER_START) || (cipher >= AMVP_CIPHER_END)) {
        return 0;
    }
    return (alg_tbl[cipher-1].alg.kas);
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
            AMVP_LOG_ERR("Code: %d", list->code);
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
                if (amvp_refresh(ctx) == AMVP_SUCCESS) {
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

    return rv;
}
