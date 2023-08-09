/*
 * Copyright (c) 2021, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libamvp/LICENSE
 */

#ifndef amvp_lcl_h
#define amvp_lcl_h

#include "parson.h"

#define AMVP_VERSION    "1.0"
#define AMVP_LIBRARY_VERSION_NUMBER "0.1.0"
#define AMVP_LIBRARY_VERSION    "libamvp_oss-0.1.0"

#define AMVP_DEFAULT_PATH_SEGMENT "/amvp/v1"

#ifndef AMVP_LOG_ERR
#define AMVP_LOG_ERR(msg, ...) do { \
        amvp_log_msg(ctx, AMVP_LOG_LVL_ERR, __func__, __LINE__, msg, ##__VA_ARGS__); \
} while (0)
#endif

#ifndef AMVP_LOG_WARN
#define AMVP_LOG_WARN(msg, ...) do { \
        amvp_log_msg(ctx, AMVP_LOG_LVL_WARN, __func__, __LINE__, msg, ##__VA_ARGS__); \
} while (0)
#endif

#ifndef AMVP_LOG_STATUS
#define AMVP_LOG_STATUS(msg, ...)  do { \
        amvp_log_msg(ctx, AMVP_LOG_LVL_STATUS, __func__, __LINE__, msg, ##__VA_ARGS__); \
} while (0)
#endif

#ifndef AMVP_LOG_INFO
#define AMVP_LOG_INFO(msg, ...) do { \
        amvp_log_msg(ctx, AMVP_LOG_LVL_INFO, __func__, __LINE__, msg, ##__VA_ARGS__); \
} while (0)
#endif

#ifndef AMVP_LOG_VERBOSE
#define AMVP_LOG_VERBOSE(msg, ...) do { \
        amvp_log_msg(ctx, AMVP_LOG_LVL_VERBOSE, __func__, __LINE__, msg, ##__VA_ARGS__); \
} while (0)
#endif

#ifndef AMVP_LOG_NEWLINE
#define AMVP_LOG_NEWLINE do { \
        amvp_log_newline(ctx); \
} while (0)
#endif

#define AMVP_LOG_TRUNCATED_STR "...[truncated]"
//This MUST be the length of the above string (want to avoid calculating at runtime frequently)
#define AMVP_LOG_TRUNCATED_STR_LEN 14
#define AMVP_LOG_MAX_MSG_LEN 2048

#define AMVP_BIT2BYTE(x) ((x + 7) >> 3) /**< Convert bit length (x, of type integer) into byte length */

#define AMVP_ALG_MAX AMVP_CIPHER_END - 1  /* Used by alg_tbl[] */

#define AMVP_CAP_MAX AMVP_ALG_MAX * 2 /* Arbitrary limit to the number of capability objects that
                                         can be registered via file */
/********************************************************
 * ******************************************************
 * REVISIONS
 * ******************************************************
 ********************************************************
 */
#define AMVP_REV_STR_DEFAULT "1.0"
#define AMVP_REV_STR_2_0 "2.0"
#define AMVP_REV_STR_FIPS186_4 "FIPS186-4"
#define AMVP_REV_STR_SP800_56AR3 "Sp800-56Ar3"
#define AMVP_REV_STR_SP800_56BR2 "Sp800-56Br2"
#define AMVP_REV_STR_SP800_56CR1 "Sp800-56Cr1"
#define AMVP_REV_STR_SP800_56CR2 "Sp800-56Cr2"
#define AMVP_REV_STR_RFC8446 "RFC8446"
#define AMVP_REV_STR_RFC7627 "RFC7627"

/* AES */
#define AMVP_REV_AES_ECB             AMVP_REV_STR_DEFAULT
#define AMVP_REV_AES_CBC             AMVP_REV_STR_DEFAULT
#define AMVP_REV_AES_CBC_CS1         AMVP_REV_STR_DEFAULT
#define AMVP_REV_AES_CBC_CS2         AMVP_REV_STR_DEFAULT
#define AMVP_REV_AES_CBC_CS3         AMVP_REV_STR_DEFAULT
#define AMVP_REV_AES_CFB1            AMVP_REV_STR_DEFAULT
#define AMVP_REV_AES_CFB8            AMVP_REV_STR_DEFAULT
#define AMVP_REV_AES_CFB128          AMVP_REV_STR_DEFAULT
#define AMVP_REV_AES_OFB             AMVP_REV_STR_DEFAULT
#define AMVP_REV_AES_CTR             AMVP_REV_STR_DEFAULT
#define AMVP_REV_AES_GCM             AMVP_REV_STR_DEFAULT
#define AMVP_REV_AES_GCM_SIV         AMVP_REV_STR_DEFAULT
#define AMVP_REV_AES_CCM             AMVP_REV_STR_DEFAULT
#define AMVP_REV_AES_XTS             AMVP_REV_STR_2_0
#define AMVP_REV_AES_KW              AMVP_REV_STR_DEFAULT
#define AMVP_REV_AES_KWP             AMVP_REV_STR_DEFAULT
#define AMVP_REV_AES_GMAC            AMVP_REV_STR_DEFAULT
#define AMVP_REV_AES_XPN             AMVP_REV_STR_DEFAULT

/* TDES */
#define AMVP_REV_TDES_OFB            AMVP_REV_STR_DEFAULT
#define AMVP_REV_TDES_OFBI           AMVP_REV_STR_DEFAULT
#define AMVP_REV_TDES_CFB1           AMVP_REV_STR_DEFAULT
#define AMVP_REV_TDES_CFB8           AMVP_REV_STR_DEFAULT
#define AMVP_REV_TDES_CFB64          AMVP_REV_STR_DEFAULT
#define AMVP_REV_TDES_CFBP1          AMVP_REV_STR_DEFAULT
#define AMVP_REV_TDES_CFBP8          AMVP_REV_STR_DEFAULT
#define AMVP_REV_TDES_CFBP64         AMVP_REV_STR_DEFAULT
#define AMVP_REV_TDES_ECB            AMVP_REV_STR_DEFAULT
#define AMVP_REV_TDES_CBC            AMVP_REV_STR_DEFAULT
#define AMVP_REV_TDES_CBCI           AMVP_REV_STR_DEFAULT
#define AMVP_REV_TDES_CTR            AMVP_REV_STR_DEFAULT
#define AMVP_REV_TDES_KW             AMVP_REV_STR_DEFAULT

/* SHA */
#define AMVP_REV_HASH_SHA1           AMVP_REV_STR_DEFAULT
#define AMVP_REV_HASH_SHA224         AMVP_REV_STR_DEFAULT
#define AMVP_REV_HASH_SHA256         AMVP_REV_STR_DEFAULT
#define AMVP_REV_HASH_SHA384         AMVP_REV_STR_DEFAULT
#define AMVP_REV_HASH_SHA512         AMVP_REV_STR_DEFAULT
#define AMVP_REV_HASH_SHA512_224     AMVP_REV_STR_DEFAULT
#define AMVP_REV_HASH_SHA512_256     AMVP_REV_STR_DEFAULT
#define AMVP_REV_HASH_SHA3_224       AMVP_REV_STR_2_0
#define AMVP_REV_HASH_SHA3_256       AMVP_REV_STR_2_0
#define AMVP_REV_HASH_SHA3_384       AMVP_REV_STR_2_0
#define AMVP_REV_HASH_SHA3_512       AMVP_REV_STR_2_0
#define AMVP_REV_HASH_SHAKE_128      AMVP_REV_STR_DEFAULT
#define AMVP_REV_HASH_SHAKE_256      AMVP_REV_STR_DEFAULT

/* DRBG */
#define AMVP_REV_HASHDRBG            AMVP_REV_STR_DEFAULT
#define AMVP_REV_HMACDRBG            AMVP_REV_STR_DEFAULT
#define AMVP_REV_CTRDRBG             AMVP_REV_STR_DEFAULT

/* HMAC */
#define AMVP_REV_HMAC_SHA1           AMVP_REV_STR_DEFAULT
#define AMVP_REV_HMAC_SHA2_224       AMVP_REV_STR_DEFAULT
#define AMVP_REV_HMAC_SHA2_256       AMVP_REV_STR_DEFAULT
#define AMVP_REV_HMAC_SHA2_384       AMVP_REV_STR_DEFAULT
#define AMVP_REV_HMAC_SHA2_512       AMVP_REV_STR_DEFAULT
#define AMVP_REV_HMAC_SHA2_512_224   AMVP_REV_STR_DEFAULT
#define AMVP_REV_HMAC_SHA2_512_256   AMVP_REV_STR_DEFAULT
#define AMVP_REV_HMAC_SHA3_224       AMVP_REV_STR_DEFAULT
#define AMVP_REV_HMAC_SHA3_256       AMVP_REV_STR_DEFAULT
#define AMVP_REV_HMAC_SHA3_384       AMVP_REV_STR_DEFAULT
#define AMVP_REV_HMAC_SHA3_512       AMVP_REV_STR_DEFAULT

/* CMAC */
#define AMVP_REV_CMAC_AES            AMVP_REV_STR_DEFAULT
#define AMVP_REV_CMAC_TDES           AMVP_REV_STR_DEFAULT

/* KMAC */
#define AMVP_REV_KMAC_128            AMVP_REV_STR_DEFAULT
#define AMVP_REV_KMAC_256            AMVP_REV_STR_DEFAULT

/* DSA */
#define AMVP_REV_DSA                 AMVP_REV_STR_DEFAULT

/* RSA */
#define AMVP_REV_RSA                 AMVP_REV_STR_FIPS186_4
#define AMVP_REV_RSA_PRIM            AMVP_REV_STR_DEFAULT

/* ECDSA */
#define AMVP_REV_ECDSA               AMVP_REV_STR_DEFAULT

/* KAS_ECC */
#define AMVP_REV_KAS_ECC             AMVP_REV_STR_DEFAULT
#define AMVP_REV_KAS_ECC_SSC         AMVP_REV_STR_SP800_56AR3


/* KAS_FFC */
#define AMVP_REV_KAS_FFC             AMVP_REV_STR_DEFAULT
#define AMVP_REV_KAS_FFC_SSC         AMVP_REV_STR_SP800_56AR3

/* KAS_IFC */
#define AMVP_REV_KAS_IFC_SSC         AMVP_REV_STR_SP800_56BR2

/* KDA */
#define AMVP_REV_KDA_ONESTEP         AMVP_REV_STR_SP800_56CR2
#define AMVP_REV_KDA_TWOSTEP         AMVP_REV_STR_SP800_56CR2
#define AMVP_REV_KDA_HKDF            AMVP_REV_STR_SP800_56CR2

/* KTS_IFC */
#define AMVP_REV_KTS_IFC             AMVP_REV_STR_SP800_56BR2

/* KDF */
#define AMVP_REV_KDF135_SNMP         AMVP_REV_STR_DEFAULT
#define AMVP_REV_KDF135_SSH          AMVP_REV_STR_DEFAULT
#define AMVP_REV_KDF135_SRTP         AMVP_REV_STR_DEFAULT
#define AMVP_REV_KDF135_IKEV2        AMVP_REV_STR_DEFAULT
#define AMVP_REV_KDF135_IKEV1        AMVP_REV_STR_DEFAULT
#define AMVP_REV_KDF135_TPM          AMVP_REV_STR_DEFAULT
#define AMVP_REV_KDF135_X942         AMVP_REV_STR_DEFAULT
#define AMVP_REV_KDF135_X963         AMVP_REV_STR_DEFAULT
#define AMVP_REV_KDF108              AMVP_REV_STR_DEFAULT
#define AMVP_REV_PBKDF               AMVP_REV_STR_DEFAULT
#define AMVP_REV_SAFE_PRIMES         AMVP_REV_STR_DEFAULT
#define AMVP_REV_KDF_TLS12           AMVP_REV_STR_RFC7627
#define AMVP_REV_KDF_TLS13           AMVP_REV_STR_RFC8446


/********************************************************
 * ******************************************************
 * ALGORITHM STRINGS
 * ******************************************************
 ********************************************************
 */
#define AMVP_ALG_NAME_MAX 18 /**< Always make sure this is >= the length of AMVP_ALG* strings */
#define AMVP_ALG_MODE_MAX 26 /**< Always make sure this is >= the length of AMVP_MODE* strings */

#define AMVP_ALG_AES_ECB             "AMVP-AES-ECB"
#define AMVP_ALG_AES_CBC             "AMVP-AES-CBC"
#define AMVP_ALG_AES_CBC_CS1         "AMVP-AES-CBC-CS1"
#define AMVP_ALG_AES_CBC_CS2         "AMVP-AES-CBC-CS2"
#define AMVP_ALG_AES_CBC_CS3         "AMVP-AES-CBC-CS3"
#define AMVP_ALG_AES_CFB1            "AMVP-AES-CFB1"
#define AMVP_ALG_AES_CFB8            "AMVP-AES-CFB8"
#define AMVP_ALG_AES_CFB128          "AMVP-AES-CFB128"
#define AMVP_ALG_AES_OFB             "AMVP-AES-OFB"
#define AMVP_ALG_AES_CTR             "AMVP-AES-CTR"
#define AMVP_ALG_AES_GCM             "AMVP-AES-GCM"
#define AMVP_ALG_AES_GCM_SIV         "AMVP-AES-GCM-SIV"
#define AMVP_ALG_AES_CCM             "AMVP-AES-CCM"
#define AMVP_ALG_AES_XTS             "AMVP-AES-XTS"
#define AMVP_ALG_AES_KW              "AMVP-AES-KW"
#define AMVP_ALG_AES_KWP             "AMVP-AES-KWP"
#define AMVP_ALG_AES_GMAC            "AMVP-AES-GMAC"
#define AMVP_ALG_AES_XPN             "AMVP-AES-XPN"
#define AMVP_ALG_TDES_OFB            "AMVP-TDES-OFB"
#define AMVP_ALG_TDES_OFBI           "AMVP-TDES-OFBI"
#define AMVP_ALG_TDES_CFB1           "AMVP-TDES-CFB1"
#define AMVP_ALG_TDES_CFB8           "AMVP-TDES-CFB8"
#define AMVP_ALG_TDES_CFB64          "AMVP-TDES-CFB64"
#define AMVP_ALG_TDES_CFBP1          "AMVP-TDES-CFBP1"
#define AMVP_ALG_TDES_CFBP8          "AMVP-TDES-CFBP8"
#define AMVP_ALG_TDES_CFBP64         "AMVP-TDES-CFBP64"
#define AMVP_ALG_TDES_ECB            "AMVP-TDES-ECB"
#define AMVP_ALG_TDES_CBC            "AMVP-TDES-CBC"
#define AMVP_ALG_TDES_CBCI           "AMVP-TDES-CBCI"
#define AMVP_ALG_TDES_CTR            "AMVP-TDES-CTR"
#define AMVP_ALG_TDES_KW             "AMVP-TDES-KW"
#define AMVP_ALG_SHA1                "SHA-1"
#define AMVP_ALG_SHA224              "SHA2-224"
#define AMVP_ALG_SHA256              "SHA2-256"
#define AMVP_ALG_SHA384              "SHA2-384"
#define AMVP_ALG_SHA512              "SHA2-512"
#define AMVP_ALG_SHA512_224          "SHA2-512/224"
#define AMVP_ALG_SHA512_256          "SHA2-512/256"
#define AMVP_ALG_SHA3_224            "SHA3-224"
#define AMVP_ALG_SHA3_256            "SHA3-256"
#define AMVP_ALG_SHA3_384            "SHA3-384"
#define AMVP_ALG_SHA3_512            "SHA3-512"
#define AMVP_ALG_SHAKE_128           "SHAKE-128"
#define AMVP_ALG_SHAKE_256           "SHAKE-256"
#define AMVP_ALG_HASHDRBG            "hashDRBG"
#define AMVP_ALG_HMACDRBG            "hmacDRBG"
#define AMVP_ALG_CTRDRBG             "ctrDRBG"
#define AMVP_ALG_HMAC_SHA1           "HMAC-SHA-1"
#define AMVP_ALG_HMAC_SHA2_224       "HMAC-SHA2-224"
#define AMVP_ALG_HMAC_SHA2_256       "HMAC-SHA2-256"
#define AMVP_ALG_HMAC_SHA2_384       "HMAC-SHA2-384"
#define AMVP_ALG_HMAC_SHA2_512       "HMAC-SHA2-512"
#define AMVP_ALG_HMAC_SHA2_512_224   "HMAC-SHA2-512/224"
#define AMVP_ALG_HMAC_SHA2_512_256   "HMAC-SHA2-512/256"
#define AMVP_ALG_HMAC_SHA3_224       "HMAC-SHA3-224"
#define AMVP_ALG_HMAC_SHA3_256       "HMAC-SHA3-256"
#define AMVP_ALG_HMAC_SHA3_384       "HMAC-SHA3-384"
#define AMVP_ALG_HMAC_SHA3_512       "HMAC-SHA3-512"

#define AMVP_MODE_AES_128            "AES-128"
#define AMVP_MODE_TDES "TDES"
#define AMVP_MODE_AES_192 "AES-192"
#define AMVP_MODE_AES_256 "AES-256"

#define AMVP_ALG_CMAC_AES            "CMAC-AES"
#define AMVP_ALG_CMAC_AES_128        "CMAC-AES128"
#define AMVP_ALG_CMAC_AES_192        "CMAC-AES192"
#define AMVP_ALG_CMAC_AES_256        "CMAC-AES256"
#define AMVP_ALG_CMAC_TDES           "CMAC-TDES"

#define AMVP_ALG_KMAC_128            "KMAC-128"
#define AMVP_ALG_KMAC_256            "KMAC-256"

#define AMVP_ALG_DSA                 "DSA"
#define AMVP_ALG_DSA_PQGGEN          "pqgGen"
#define AMVP_ALG_DSA_PQGVER          "pqgVer"
#define AMVP_ALG_DSA_KEYGEN          "keyGen"
#define AMVP_ALG_DSA_SIGGEN          "sigGen"
#define AMVP_ALG_DSA_SIGVER          "sigVer"
#define AMVP_MODE_DECPRIM            "decryptionPrimitive"
#define AMVP_MODE_SIGPRIM            "signaturePrimitive"

#define AMVP_ALG_KAS_ECC_CDH         "CDH-Component"
#define AMVP_ALG_KAS_ECC_COMP        "Component"
#define AMVP_ALG_KAS_ECC_NOCOMP      ""


#define AMVP_ALG_KAS_ECC_SSC         "KAS-ECC-SSC"
#define AMVP_ALG_KAS_ECC             "KAS-ECC"
#define AMVP_ALG_KAS_ECC_DPGEN       "dpGen"
#define AMVP_ALG_KAS_ECC_DPVAL       "dpVal"
#define AMVP_ALG_KAS_ECC_KEYPAIRGEN  "keyPairGen"
#define AMVP_ALG_KAS_ECC_FULLVAL     "fullVal"
#define AMVP_ALG_KAS_ECC_PARTIALVAL  "partialVal"
#define AMVP_ALG_KAS_ECC_KEYREGEN    "keyRegen"

#define AMVP_ALG_KAS_FFC_COMP        "Component"
#define AMVP_ALG_KAS_FFC_NOCOMP      ""

#define AMVP_ALG_KAS_FFC_SSC         "KAS-FFC-SSC"
#define AMVP_ALG_KAS_FFC             "KAS-FFC"
#define AMVP_ALG_KAS_FFC_DPGEN       "dpGen"
#define AMVP_ALG_KAS_FFC_MQV2        "MQV2"
#define AMVP_ALG_KAS_FFC_KEYPAIRGEN  "keyPairGen"
#define AMVP_ALG_KAS_FFC_FULLVAL     "fullVal"
#define AMVP_ALG_KAS_FFC_KEYREGEN    "keyRegen"

#define AMVP_ALG_KAS_IFC_SSC         "KAS-IFC-SSC"
#define AMVP_ALG_KAS_IFC_COMP        ""

#define AMVP_ALG_KDA_ALG_STR     "KDA"
#define AMVP_ALG_KDA_ONESTEP     "OneStep"
#define AMVP_ALG_KDA_TWOSTEP     "TwoStep"
#define AMVP_ALG_KDA_HKDF            "HKDF"

#define AMVP_ALG_KTS_IFC             "KTS-IFC"
#define AMVP_ALG_KTS_IFC_COMP        ""

#define AMVP_ALG_SAFE_PRIMES_STR    "safePrimes"
#define AMVP_ALG_SAFE_PRIMES_KEYGEN "keyGen"
#define AMVP_ALG_SAFE_PRIMES_KEYVER "keyVer"

#define AMVP_ECDSA_EXTRA_BITS_STR "extra bits"
#define AMVP_ECDSA_EXTRA_BITS_STR_LEN 10
#define AMVP_ECDSA_TESTING_CANDIDATES_STR "testing candidates"
#define AMVP_ECDSA_TESTING_CANDIDATES_STR_LEN 18

#define AMVP_RSA_PRIME_TEST_TBLC2_STR "tblC2"
#define AMVP_RSA_PRIME_TEST_TBLC2_STR_LEN 5
#define AMVP_RSA_PRIME_TEST_TBLC3_STR "tblC3"
#define AMVP_RSA_PRIME_TEST_TBLC3_STR_LEN 5

#define AMVP_RSA_SIG_TYPE_X931_STR      "ansx9.31"
#define AMVP_RSA_SIG_TYPE_PKCS1V15_STR  "pkcs1v1.5"
#define AMVP_RSA_SIG_TYPE_PKCS1PSS_STR  "pss"

#define AMVP_ALG_RSA                "RSA"
#define AMVP_ALG_ECDSA              "ECDSA"

#define AMVP_MODE_KEYGEN            "keyGen"
#define AMVP_MODE_KEYVER            "keyVer"
#define AMVP_MODE_SIGGEN            "sigGen"
#define AMVP_MODE_SIGVER            "sigVer"
#define AMVP_MODE_COUNTER           "counter"
#define AMVP_MODE_FEEDBACK          "feedback"
#define AMVP_MODE_DPI               "double pipeline iteration"
#define AMVP_KDF135_ALG_STR         "kdf-components"

#define AMVP_AUTH_METHOD_DSA_STR "dsa"
#define AMVP_AUTH_METHOD_PSK_STR "psk"
#define AMVP_AUTH_METHOD_PKE_STR "pke"
#define AMVP_AUTH_METHOD_STR_MAX 3
#define AMVP_AUTH_METHOD_STR_MAX_PLUS 4

#define AMVP_FIXED_DATA_ORDER_AFTER_STR "after fixed data"
#define AMVP_FIXED_DATA_ORDER_BEFORE_STR "before fixed data"
#define AMVP_FIXED_DATA_ORDER_MIDDLE_STR "middle fixed data"
#define AMVP_FIXED_DATA_ORDER_NONE_STR "none"
#define AMVP_FIXED_DATA_ORDER_BEFORE_ITERATOR_STR "before iterator"

#define AMVP_PREREQ_VAL_STR "valValue"
#define AMVP_PREREQ_OBJ_STR "prereqVals"

#define AMVP_TESTTYPE_STR_KAT "KAT"
#define AMVP_TESTTYPE_STR_AFT "AFT"
#define AMVP_TESTTYPE_STR_VOL "VOL"
#define AMVP_TESTTYPE_STR_GDT "GDT"

#define AMVP_DRBG_MODE_TDES          "TDES"
#define AMVP_DRBG_MODE_AES_128       "AES-128"
#define AMVP_DRBG_MODE_AES_192       "AES-192"
#define AMVP_DRBG_MODE_AES_256       "AES-256"

#define AMVP_ALG_KDF135_SNMP     "snmp"
#define AMVP_ALG_KDF135_SSH      "ssh"
#define AMVP_ALG_KDF135_SRTP     "srtp"
#define AMVP_ALG_KDF135_IKEV2    "ikev2"
#define AMVP_ALG_KDF135_IKEV1    "ikev1"
#define AMVP_ALG_KDF135_TPM      "KDF-TPM"
#define AMVP_ALG_KDF108          "KDF"
#define AMVP_ALG_KDF135_X942     "ansix9.42"
#define AMVP_ALG_KDF135_X963     "ansix9.63"
#define AMVP_ALG_PBKDF           "PBKDF"

#define AMVP_ALG_TLS13           "TLS-v1.3"
#define AMVP_ALG_KDF_TLS13         "KDF"
#define AMVP_STR_KDF_TLS13_PSK     "PSK"
#define AMVP_STR_KDF_TLS13_DHE     "DHE"
#define AMVP_STR_KDF_TLS13_PSK_DHE "PSK-DHE"

#define AMVP_ALG_TLS12           "TLS-v1.2"
#define AMVP_ALG_KDF_TLS12       "KDF"

#define AMVP_CAPABILITY_STR_MAX 512 /**< Arbitrary string length limit */

#define AMVP_HEXSTR_MAX (AMVP_DRBG_ENTPY_IN_BIT_MAX >> 2) /**< Represents the largest hexstr that the client will accept.
                                                               Should always be set the the highest hexstr (i.e. bit length)
                                                               the the client will accept from server JSON string field */

/*
 *  Defines the key lengths and block lengths (in bytes)
 *  of symmetric block ciphers.
 */
#define AMVP_KEY_LEN_TDES 24
#define AMVP_KEY_LEN_AES128 16
#define AMVP_KEY_LEN_AES192 24
#define AMVP_KEY_LEN_AES256 32
#define AMVP_BLOCK_LEN_TDES 8
#define AMVP_BLOCK_LEN_AES128 16 /**< 16 byte block size regardless of mode */
#define AMVP_BLOCK_LEN_AES192 16 /**< 16 byte block size regardless of mode */
#define AMVP_BLOCK_LEN_AES256 16 /**< 16 byte block size regardless of mode */

/*
 * Hash algorithm output lengths (in bytes).
 */
#define AMVP_SHA1_BYTE_LEN 20
#define AMVP_SHA224_BYTE_LEN 28
#define AMVP_SHA256_BYTE_LEN 32
#define AMVP_SHA384_BYTE_LEN 48
#define AMVP_SHA512_BYTE_LEN 64

/*
 * The values that are supplied
 * when a client application registers are in bits, as
 * the specs specify.
 *
 * All of these values are used to allocate memory for
 * and check lengths of the character arrays that the
 * library uses in sending/receiving JSON structs in
 * an AMVP interaction.
 */
#define AMVP_SYM_KEY_MAX_STR 128
#define AMVP_SYM_KEY_MAX_BYTES 64       /**< 256 bits, 64 characters */
#define AMVP_SYM_KEY_MAX_BITS 256

#define AMVP_SYM_PT_BIT_MAX 131072                      /**< 131072 bits */
#define AMVP_SYM_PT_MAX (AMVP_SYM_PT_BIT_MAX >> 2)      /**< 32768 characters */
#define AMVP_SYM_PT_BYTE_MAX (AMVP_SYM_PT_BIT_MAX >> 3) /**< 16384 bytes */

#define AMVP_SYM_CT_BIT_MAX 131072                      /**< 131072 bits */
#define AMVP_SYM_CT_MAX (AMVP_SYM_CT_BIT_MAX >> 2)      /**< 32768 characters */
#define AMVP_SYM_CT_BYTE_MAX (AMVP_SYM_CT_BIT_MAX >> 3) /**< 16384 bytes */

#define AMVP_SYM_IV_BIT_MAX 1024                        /**< 1024 bits */
#define AMVP_SYM_IV_MAX (AMVP_SYM_IV_BIT_MAX >> 2)      /**< 256 characters */
#define AMVP_SYM_IV_BYTE_MAX (AMVP_SYM_IV_BIT_MAX >> 3) /**< 128 bytes */
#define AMVP_AES_GCM_SIV_IVLEN 96
#define AMVP_AES_XPN_IVLEN 96

#define AMVP_SYM_TAG_BIT_MIN 4                            /**< 128 bits */
#define AMVP_SYM_TAG_BIT_MAX 128                          /**< 128 bits */
#define AMVP_SYM_TAG_MAX (AMVP_SYM_TAG_BIT_MAX >> 2)      /**< 32 characters */
#define AMVP_SYM_TAG_BYTE_MAX (AMVP_SYM_TAG_BIT_MAX >> 3) /**< 16 bytes */
#define AMVP_AES_GCM_SIV_TAGLEN 128

#define AMVP_SYM_AAD_BIT_MAX 65536                        /**< 65536 bits */
#define AMVP_SYM_AAD_MAX (AMVP_SYM_AAD_BIT_MAX >> 2)      /**< 16384 characters */
#define AMVP_SYM_AAD_BYTE_MAX (AMVP_SYM_AAD_BIT_MAX >> 3) /**< 8192 bytes */

#define AMVP_AES_XPN_SALTLEN 96

#define AMVP_AES_CCM_IV_BIT_MIN 56   /**< 56 bits */
#define AMVP_AES_CCM_IV_BIT_MAX 104  /**< 104 bits */
#define AMVP_AES_GCM_IV_BIT_MIN 8    /**< 8 bits */
#define AMVP_AES_GCM_IV_BIT_MAX 1024 /**< 1024 bits */

#define AMVP_AES_IVGEN_STR "ivGen"
#define AMVP_AES_RFC3686_IVGEN_STR "ivGenMode"
#define AMVP_RFC3686_STR "RFC3686"


/**
 * Accepted length ranges for DRBG.
 * https://github.com/usnistgov/AMVP/blob/master/artifacts/amvp_sub_drbg.txt
 */
#define AMVP_DRB_BIT_MAX 4096
#define AMVP_DRB_BYTE_MAX (AMVP_DRB_BIT_MAX >> 3)
#define AMVP_DRB_STR_MAX (AMVP_DRB_BIT_MAX >> 2)

#define AMVP_DRBG_ENTPY_IN_BIT_MIN 80
#define AMVP_DRBG_ENTPY_IN_BIT_MAX 1048576 /**< 2^20 library limit. Spec allows 2^35 */
#define AMVP_DRBG_ENTPY_IN_BYTE_MAX (AMVP_DRBG_ENTPY_IN_BIT_MAX >> 3)
#define AMVP_DRBG_ENTPY_IN_STR_MAX (AMVP_DRBG_ENTPY_IN_BIT_MAX >> 2)

#define AMVP_DRBG_NONCE_BIT_MIN 40
#define AMVP_DRBG_NONCE_BIT_MAX 512
#define AMVP_DRBG_NONCE_BYTE_MAX (AMVP_DRBG_NONCE_BIT_MAX >> 3)
#define AMVP_DRBG_NONCE_STR_MAX (AMVP_DRBG_NONCE_BIT_MAX >> 2)

#define AMVP_DRBG_PER_SO_BIT_MAX 1048576 /**< 2^20 library limit. Spec allows 2^35 */
#define AMVP_DRBG_PER_SO_BYTE_MAX (AMVP_DRBG_PER_SO_BIT_MAX >> 3)
#define AMVP_DRBG_PER_SO_STR_MAX (AMVP_DRBG_PER_SO_BIT_MAX >> 2)

#define AMVP_DRBG_ADDI_IN_BIT_MAX 1048576 /**< 2^20 library limit. Spec allows 2^35 */
#define AMVP_DRBG_ADDI_IN_BYTE_MAX (AMVP_DRBG_ADDI_IN_BIT_MAX >> 3)
#define AMVP_DRBG_ADDI_IN_STR_MAX (AMVP_DRBG_ADDI_IN_BIT_MAX >> 2)
/*
 * END DRBG
 */

#define AMVP_HASH_MSG_BIT_MIN 0                             /**< 0 bits */
#define AMVP_HASH_MSG_BIT_MAX 65536                         /**< 65536 bits */
#define AMVP_HASH_MSG_STR_MAX (AMVP_HASH_MSG_BIT_MAX >> 2)  /**< 16384 characters */
#define AMVP_HASH_MSG_BYTE_MAX (AMVP_HASH_MSG_BIT_MAX >> 3) /**< 8192 bytes */
#define AMVP_HASH_MD_BIT_MAX 512                            /**< 512 bits */
#define AMVP_HASH_MD_STR_MAX (AMVP_HASH_MD_BIT_MAX >> 2)    /**< 128 characters */
#define AMVP_HASH_MD_BYTE_MAX (AMVP_HASH_MD_BIT_MAX >> 3)   /**< 64 bytes */

//SHAKE does not define a maximum message length, but we want it to be sane still
#define AMVP_SHAKE_MSG_BIT_MAX 131072                         /**< 131072 bits */
#define AMVP_SHAKE_MSG_STR_MAX (AMVP_SHAKE_MSG_BIT_MAX >> 2)  /**< 32768 characters */
#define AMVP_SHAKE_MSG_BYTE_MAX (AMVP_SHAKE_MSG_BIT_MAX >> 3) /**< 16384 bytes */

#define AMVP_HASH_XOF_MD_BIT_MIN 16 /**< XOF (extendable output format) outLength minimum (in bits) */
#define AMVP_HASH_XOF_MD_BIT_MAX 65536 /**< XOF (extendable output format) outLength maximum (in bits) */
#define AMVP_HASH_XOF_MD_STR_MAX (AMVP_HASH_XOF_MD_BIT_MAX >> 2) /**< 16,384 characters */
#define AMVP_HASH_XOF_MD_BYTE_MAX (AMVP_HASH_XOF_MD_BIT_MAX >> 3) /**< 8,192 bytes */

#define AMVP_TDES_KEY_BIT_LEN 192                           /**< 192 bits */
#define AMVP_TDES_KEY_STR_LEN (AMVP_TDES_KEY_BIT_LEN >> 2)  /**< 48 characters */
#define AMVP_TDES_KEY_BYTE_LEN (AMVP_TDES_KEY_BIT_LEN >> 3) /**< 24 bytes */

#define AMVP_KDF135_SSH_EKEY_MAX (AMVP_SHA512_BYTE_LEN)            /**< Encryption Key max.
                                                                        Be able to hold largest sha size, although
                                                                        actual key is a subset (up to 32 bytes).
                                                                        512 bits, 64 bytes */
#define AMVP_KDF135_SSH_IKEY_MAX (AMVP_SHA512_BYTE_LEN)            /**< Integrity Key max
                                                                        512 bits, 64 bytes */
#define AMVP_KDF135_SSH_IV_MAX (AMVP_SHA512_BYTE_LEN)              /**< Initial IV key max
                                                                        Be able to hold largest sha size, although
                                                                        actual IV is a subset (up to 16 bytes).
                                                                        512 bits, 64 bytes */
#define AMVP_KDF135_SSH_STR_OUT_MAX (AMVP_KDF135_SSH_IKEY_MAX * 2) /**< 128 characters */
#define AMVP_KDF135_SSH_STR_IN_MAX 4096                            /**< 4096 characters, needs to accomodate large shared_secret (K) */

/**
 * Accepted length ranges for KDF135_SRTP.
 * https://github.com/usnistgov/AMVP/blob/master/artifacts/amvp_sub_kdf135_srtp.txt
 */
#define AMVP_KDF135_SRTP_KDR_MAX 24
#define AMVP_KDF135_SRTP_KDR_STR_MAX 13
#define AMVP_KDF135_SRTP_MASTER_MAX 65
#define AMVP_KDF135_SRTP_INDEX_MAX 32
#define AMVP_KDF135_SRTP_OUTPUT_MAX 64

/**
 * Accepted length ranges for KDF135_X942.
 * https://github.com/usnistgov/AMVP/blob/master/artifacts/amvp_sub_kdf135_x942.txt
 */
#define AMVP_KDF135_X942_BIT_MAX 4096
#define AMVP_KDF135_X942_STR_MAX (AMVP_KDF135_X942_BIT_MAX >> 2)
#define AMVP_KDF135_X942_BYTE_MAX (AMVP_KDF135_X942_BIT_MAX >> 3)

/**
 * Accepted length ranges for KDF135_X963.
 * https://github.com/usnistgov/AMVP/blob/master/artifacts/amvp_sub_kdf135_x963.txt
 */
#define AMVP_KDF135_X963_KEYDATA_MIN_BITS 128
#define AMVP_KDF135_X963_KEYDATA_MAX_BITS 4096
#define AMVP_KDF135_X963_KEYDATA_MAX_CHARS (AMVP_KDF135_X963_KEYDATA_MAX_BITS >> 2)
#define AMVP_KDF135_X963_KEYDATA_MAX_BYTES (AMVP_KDF135_X963_KEYDATA_MAX_BITS >> 3)
#define AMVP_KDF135_X963_INPUT_MAX 1024 / 8
#define AMVP_KDF135_X963_FIELD_SIZE_224 224
#define AMVP_KDF135_X963_FIELD_SIZE_233 233
#define AMVP_KDF135_X963_FIELD_SIZE_256 256
#define AMVP_KDF135_X963_FIELD_SIZE_283 283
#define AMVP_KDF135_X963_FIELD_SIZE_384 384
#define AMVP_KDF135_X963_FIELD_SIZE_409 409
#define AMVP_KDF135_X963_FIELD_SIZE_521 521
#define AMVP_KDF135_X963_FIELD_SIZE_571 571
#define AMVP_KDF135_X963_SHARED_INFO_LEN_MAX 1024
#define AMVP_KDF135_X963_SHARED_INFO_LEN_MIN 0

/**
 * Accepted length ranges for KDF135_SNMP.
 * https://github.com/usnistgov/AMVP/blob/master/artifacts/amvp_sub_kdf135_snmp.txt
 */
#define AMVP_KDF135_SNMP_PASS_LEN_MIN 64
#define AMVP_KDF135_SNMP_PASS_LEN_MAX 8192
#define AMVP_KDF135_SNMP_ENGID_MAX_BYTES 32
#define AMVP_KDF135_SNMP_ENGID_MAX_STR 64
#define AMVP_KDF135_SNMP_SKEY_MAX 64

/**
 * Accepted length ranges for KDF135_IKEV1.
 * https://github.com/usnistgov/AMVP/blob/master/artifacts/amvp_sub_kdf135_ikev1.txt
 */
#define AMVP_KDF135_IKEV1_COOKIE_STR_MAX 32
#define AMVP_KDF135_IKEV1_COOKIE_BYTE_MAX (AMVP_KDF135_IKEV1_COOKIE_STR_MAX / 2)

#define AMVP_KDF135_IKEV1_SKEY_BYTE_MAX 64 /**< SHA512 byte length */
#define AMVP_KDF135_IKEV1_SKEY_STR_MAX 128 /**< SHA512 hex length */

#define AMVP_KDF135_IKEV1_INIT_NONCE_BIT_MIN 64
#define AMVP_KDF135_IKEV1_INIT_NONCE_BIT_MAX 2048
#define AMVP_KDF135_IKEV1_INIT_NONCE_BYTE_MAX (AMVP_KDF135_IKEV1_INIT_NONCE_BIT_MAX >> 3)
#define AMVP_KDF135_IKEV1_INIT_NONCE_STR_MAX (AMVP_KDF135_IKEV1_INIT_NONCE_BIT_MAX >> 2)

#define AMVP_KDF135_IKEV1_RESP_NONCE_BIT_MIN 64
#define AMVP_KDF135_IKEV1_RESP_NONCE_BIT_MAX 2048
#define AMVP_KDF135_IKEV1_RESP_NONCE_BYTE_MAX (AMVP_KDF135_IKEV1_RESP_NONCE_BIT_MAX >> 3)
#define AMVP_KDF135_IKEV1_RESP_NONCE_STR_MAX (AMVP_KDF135_IKEV1_RESP_NONCE_BIT_MAX >> 2)

#define AMVP_KDF135_IKEV1_DH_SHARED_SECRET_BIT_MIN 224
#define AMVP_KDF135_IKEV1_DH_SHARED_SECRET_BIT_MAX 8192
#define AMVP_KDF135_IKEV1_DH_SHARED_SECRET_BYTE_MAX (AMVP_KDF135_IKEV1_DH_SHARED_SECRET_BIT_MAX >> 3)
#define AMVP_KDF135_IKEV1_DH_SHARED_SECRET_STR_MAX (AMVP_KDF135_IKEV1_DH_SHARED_SECRET_BIT_MAX >> 2)

#define AMVP_KDF135_IKEV1_PSK_BIT_MIN 8
#define AMVP_KDF135_IKEV1_PSK_BIT_MAX 8192
#define AMVP_KDF135_IKEV1_PSK_BYTE_MAX (AMVP_KDF135_IKEV1_PSK_BIT_MAX >> 3)
#define AMVP_KDF135_IKEV1_PSK_STR_MAX (AMVP_KDF135_IKEV1_PSK_BIT_MAX >> 2)
/*
 * END KDF135_IKEV1
 */

/**
 * Accepted length ranges for KDF135_IKEV2.
 * https://github.com/usnistgov/AMVP/blob/master/artifacts/amvp_sub_kdf135_ikev2.txt
 */
#define AMVP_KDF135_IKEV2_SPI_STR_MAX 32
#define AMVP_KDF135_IKEV2_SPI_BYTE_MAX (AMVP_KDF135_IKEV2_SPI_STR_MAX / 2)

#define AMVP_KDF135_IKEV2_SKEY_SEED_BYTE_MAX 64 /**< SHA512 byte length */
#define AMVP_KDF135_IKEV2_SKEY_SEED_STR_MAX 128 /**< SHA512 hex length */

#define AMVP_KDF135_IKEV2_INIT_NONCE_BIT_MIN 64
#define AMVP_KDF135_IKEV2_INIT_NONCE_BIT_MAX 2048
#define AMVP_KDF135_IKEV2_INIT_NONCE_BYTE_MAX (AMVP_KDF135_IKEV2_INIT_NONCE_BIT_MAX >> 3)
#define AMVP_KDF135_IKEV2_INIT_NONCE_STR_MAX (AMVP_KDF135_IKEV2_INIT_NONCE_BIT_MAX >> 2)

#define AMVP_KDF135_IKEV2_RESP_NONCE_BIT_MIN 64
#define AMVP_KDF135_IKEV2_RESP_NONCE_BIT_MAX 2048
#define AMVP_KDF135_IKEV2_RESP_NONCE_BYTE_MAX (AMVP_KDF135_IKEV2_RESP_NONCE_BIT_MAX >> 3)
#define AMVP_KDF135_IKEV2_RESP_NONCE_STR_MAX (AMVP_KDF135_IKEV2_RESP_NONCE_BIT_MAX >> 2)

#define AMVP_KDF135_IKEV2_DH_SHARED_SECRET_BIT_MIN 224
#define AMVP_KDF135_IKEV2_DH_SHARED_SECRET_BIT_MAX 8192
#define AMVP_KDF135_IKEV2_DH_SHARED_SECRET_BYTE_MAX (AMVP_KDF135_IKEV2_DH_SHARED_SECRET_BIT_MAX >> 3)
#define AMVP_KDF135_IKEV2_DH_SHARED_SECRET_STR_MAX (AMVP_KDF135_IKEV2_DH_SHARED_SECRET_BIT_MAX >> 2)

#define AMVP_KDF135_IKEV2_DKEY_MATERIAL_BIT_MIN 160
#define AMVP_KDF135_IKEV2_DKEY_MATERIAL_BIT_MAX 16384
#define AMVP_KDF135_IKEV2_DKEY_MATERIAL_BYTE_MAX (AMVP_KDF135_IKEV2_DKEY_MATERIAL_BIT_MAX >> 3)
#define AMVP_KDF135_IKEV2_DKEY_MATERIAL_STR_MAX (AMVP_KDF135_IKEV2_DKEY_MATERIAL_BIT_MAX >> 2)
/*
 * END KDF135_IKEV2
 */

/**
 * Accepted length ranges for KDF108.
 * https://github.com/usnistgov/AMVP/blob/master/artifacts/amvp_sub_kdf108.txt
 */
#define AMVP_KDF108_KEYOUT_BIT_MIN 160 /**< SHA-1 */
#define AMVP_KDF108_KEYOUT_BIT_MAX 4096 /**< SHA2-512 */
#define AMVP_KDF108_KEYOUT_BYTE_MAX (AMVP_KDF108_KEYOUT_BIT_MAX >> 3)
#define AMVP_KDF108_KEYOUT_STR_MAX (AMVP_KDF108_KEYOUT_BIT_MAX >> 2)

#define AMVP_KDF108_KEYIN_BIT_MAX 4096 /**< Based on supportedLengths */
#define AMVP_KDF108_KEYIN_BYTE_MAX (AMVP_KDF108_KEYIN_BIT_MAX >> 3)
#define AMVP_KDF108_KEYIN_STR_MAX (AMVP_KDF108_KEYIN_BIT_MAX >> 2)

#define AMVP_KDF108_IV_BIT_MAX 512 /**< SHA2-512 */
#define AMVP_KDF108_IV_BYTE_MAX (AMVP_KDF108_IV_BIT_MAX >> 3)
#define AMVP_KDF108_IV_STR_MAX (AMVP_KDF108_IV_BIT_MAX >> 2)

#define AMVP_KDF108_FIXED_DATA_BIT_MAX 512 /**< Arbitrary */
#define AMVP_KDF108_FIXED_DATA_BYTE_MAX (AMVP_KDF108_FIXED_DATA_BIT_MAX >> 3)
#define AMVP_KDF108_FIXED_DATA_STR_MAX (AMVP_KDF108_FIXED_DATA_BIT_MAX >> 2)
/*
 * END KDF108
 */

/**
 * Accepted length ranges for PBKDF.
 */
#define AMVP_PBKDF_ITERATION_MIN 1
#define AMVP_PBKDF_ITERATION_MAX 10000000

#define AMVP_PBKDF_KEY_BIT_MIN 112
#define AMVP_PBKDF_KEY_BIT_MAX 4096
#define AMVP_PBKDF_KEY_BYTE_MIN (AMVP_PBKDF_KEY_BIT_MIN >> 3)
#define AMVP_PBKDF_KEY_STR_MIN (AMVP_PBKDF_KEY_BIT_MIN >> 2)
#define AMVP_PBKDF_KEY_BYTE_MAX (AMVP_PBKDF_KEY_BIT_MAX >> 3)
#define AMVP_PBKDF_KEY_STR_MAX (AMVP_PBKDF_KEY_BIT_MAX >> 2)

#define AMVP_PBKDF_PASS_LEN_MIN 8 //in chars
#define AMVP_PBKDF_PASS_LEN_MAX 128 //in chars

#define AMVP_PBKDF_SALT_LEN_BIT_MIN 128
#define AMVP_PBKDF_SALT_LEN_BIT_MAX 4096
#define AMVP_PBKDF_SALT_LEN_BYTE_MIN (AMVP_PBKDF_SALT_LEN_BIT_MIN >> 3)
#define AMVP_PBKDF_SALT_LEN_STR_MIN (AMVP_PBKDF_SALT_LEN_BIT_MIN >> 2)
#define AMVP_PBKDF_SALT_LEN_BYTE_MAX (AMVP_PBKDF_SALT_LEN_BIT_MAX >> 3)
#define AMVP_PBKDF_SALT_LEN_STR_MAX (AMVP_PBKDF_SALT_LEN_BIT_MAX >> 2)
/*
 * END PBKDF
 */
 
 /**
 * Accepted length ranges for TLS 1.2 KDF
 */
#define AMVP_KDF_TLS12_MSG_MAX 1024 * 4

#define AMVP_KDF_TLS12_PMSECRET_BIT_MAX 384
#define AMVP_KDF_TLS12_PMSECRET_BYTE_MAX (AMVP_KDF_TLS12_PMSECRET_BIT_MAX >> 3)
#define AMVP_KDF_TLS12_PMSECRET_STR_MAX (AMVP_KDF_TLS12_PMSECRET_BIT_MAX >> 2)

/**
 * Accepted length ranges for TLS 1.3 KDF
 */
#define AMVP_KDF_TLS13_DATA_LEN_BIT_MAX 4096 //Arbitrarily selected for sanity checking
#define AMVP_KDF_TLS13_DATA_LEN_STR_MAX (AMVP_KDF_TLS13_DATA_LEN_BIT_MAX >> 2)
#define AMVP_KDF_TLS13_DATA_LEN_BYTE_MAX (AMVP_KDF_TLS13_DATA_LEN_BIT_MAX >> 3)
/*
 * END TLS 1.3 KDF
 */

#define AMVP_HMAC_MSG_MAX       1024

#define AMVP_HMAC_MAC_BIT_MIN 32  /**< 32 bits */
#define AMVP_HMAC_MAC_BIT_MAX 512 /**< 512 bits */
#define AMVP_HMAC_MAC_BYTE_MAX (AMVP_HMAC_MAC_BIT_MAX >> 3)
#define AMVP_HMAC_MAC_STR_MAX (AMVP_HMAC_MAC_BIT_MAX >> 2)

#define AMVP_HMAC_KEY_BIT_MIN 8      /**< 8 bits */
#define AMVP_HMAC_KEY_BIT_MAX 524288 /**< 524288 bits */
#define AMVP_HMAC_KEY_BYTE_MAX (AMVP_HMAC_KEY_BIT_MAX >> 3)
#define AMVP_HMAC_KEY_STR_MAX (AMVP_HMAC_KEY_BIT_MAX >> 2)

#define AMVP_CMAC_MSGLEN_MAX_STR       131072    /**< 524288 bits, 131072 characters */
#define AMVP_CMAC_MSGLEN_MAX       524288
#define AMVP_CMAC_MSGLEN_MIN       0
#define AMVP_CMAC_MACLEN_MAX       128       /**< 512 bits, 128 characters */
#define AMVP_CMAC_MACLEN_MIN       32
#define AMVP_CMAC_KEY_MAX       64        /**< 256 bits, 64 characters */

#define AMVP_KMAC_MSG_BIT_MAX 65536
#define AMVP_KMAC_MSG_BYTE_MAX (AMVP_KMAC_MSG_BIT_MAX >> 3)
#define AMVP_KMAC_MSG_STR_MAX (AMVP_KMAC_MSG_BIT_MAX >> 2)

#define AMVP_KMAC_MAC_BIT_MAX 65536
#define AMVP_KMAC_MAC_BYTE_MAX (AMVP_KMAC_MAC_BIT_MAX >> 3)
#define AMVP_KMAC_MAC_STR_MAX (AMVP_KMAC_MAC_BIT_MAX >> 2)

#define AMVP_KMAC_KEY_BIT_MAX 524288
#define AMVP_KMAC_KEY_BYTE_MAX (AMVP_KMAC_KEY_BIT_MAX >> 3)
#define AMVP_KMAC_KEY_STR_MAX (AMVP_KMAC_KEY_BIT_MAX >> 2)

#define AMVP_KMAC_CUSTOM_STR_MAX 161
#define AMVP_KMAC_CUSTOM_HEX_BIT_MAX 1288
#define AMVP_KMAC_CUSTOM_HEX_BYTE_MAX (AMVP_KMAC_CUSTOM_HEX_BIT_MAX >> 3)
#define AMVP_KMAC_CUSTOM_HEX_STR_MAX (AMVP_KMAC_CUSTOM_HEX_BIT_MAX >> 2)

#define AMVP_DSA_PQG_MAX        3072     /**< 3072 bits, 768 characters */
#define AMVP_DSA_PQG_MAX_BYTES  (AMVP_DSA_PQG_MAX / 2)
#define AMVP_DSA_SEED_MAX       1024
#define AMVP_DSA_SEED_MAX_BYTES (AMVP_DSA_SEED_MAX / 2)
#define AMVP_DSA_MAX_STRING     3072     /**< 3072 bytes */

#define AMVP_ECDSA_EXP_LEN_MAX       512
#define AMVP_ECDSA_MSGLEN_MAX 8192

#define AMVP_KAS_IFC_BIT_MAX 4096*4
#define AMVP_KAS_IFC_BYTE_MAX (AMVP_KAS_IFC_BIT_MAX >> 3)
#define AMVP_KAS_IFC_STR_MAX (AMVP_KAS_IFC_BIT_MAX >> 2)

#define AMVP_KTS_IFC_BIT_MAX 6144
#define AMVP_KTS_IFC_BYTE_MAX (AMVP_KTS_IFC_BIT_MAX >> 3)
#define AMVP_KTS_IFC_STR_MAX (AMVP_KTS_IFC_BIT_MAX >> 2)

#define AMVP_KAS_FFC_BIT_MAX 4096*4
#define AMVP_KAS_FFC_BYTE_MAX (AMVP_KAS_FFC_BIT_MAX >> 3)
#define AMVP_KAS_FFC_STR_MAX (AMVP_KAS_FFC_BIT_MAX >> 2)


#define AMVP_SAFE_PRIMES_BIT_MAX 4096*4
#define AMVP_SAFE_PRIMES_BYTE_MAX (AMVP_SAFE_PRIMES_BIT_MAX >> 3)
#define AMVP_SAFE_PRIMES_STR_MAX (AMVP_SAFE_PRIMES_BIT_MAX >> 2)

#define AMVP_KAS_ECC_BIT_MAX 4096
#define AMVP_KAS_ECC_BYTE_MAX (AMVP_KAS_ECC_BIT_MAX >> 3)
#define AMVP_KAS_ECC_STR_MAX (AMVP_KAS_ECC_BIT_MAX >> 2)

/*
 * START RSA
 */
#define AMVP_RSA_SEEDLEN_MAX    64
#define AMVP_RSA_MSGLEN_MAX     1024
#define AMVP_RSA_SIGNATURE_MAX  2048
#define AMVP_RSA_PUB_EXP_MODE_FIXED_STR "fixed"
#define AMVP_RSA_PUB_EXP_MODE_FIXED_STR_LEN 5
#define AMVP_RSA_PUB_EXP_MODE_RANDOM_STR "random"
#define AMVP_RSA_PUB_EXP_MODE_RANDOM_STR_LEN 6
#define AMVP_RSA_KEY_FORMAT_STD_STR "standard"
#define AMVP_RSA_KEY_FORMAT_STD_STR_LEN 9
#define AMVP_RSA_KEY_FORMAT_CRT_STR "crt"
#define AMVP_RSA_KEY_FORMAT_CRT_STR_LEN 3
#define AMVP_RSA_RANDPQ32_STR   "B.3.2"
#define AMVP_RSA_RANDPQ33_STR   "B.3.3"
#define AMVP_RSA_RANDPQ34_STR   "B.3.4"
#define AMVP_RSA_RANDPQ35_STR   "B.3.5"
#define AMVP_RSA_RANDPQ36_STR   "B.3.6"
#define AMVP_RSA_SIG_TYPE_LEN_MAX    9

#define AMVP_RSA_EXP_BIT_MAX 4096 /**< 2048 bits max for n, 512 characters */
#define AMVP_RSA_EXP_LEN_MAX (AMVP_RSA_EXP_BIT_MAX >> 2)
#define AMVP_RSA_EXP_BYTE_MAX (AMVP_RSA_EXP_BIT_MAX >> 3)

/*
 * END RSA
 */

#define AMVP_KDA_ENCODING_CONCATENATION_STR "concatenation"
#define AMVP_KDA_MAC_SALT_METHOD_DEFAULT_STR "default"
#define AMVP_KDA_MAC_SALT_METHOD_RANDOM_STR "random"
#define AMVP_KDA_PATTERN_LITERAL_STR "literal"
#define AMVP_KDA_PATTERN_UPARTYINFO_STR "uPartyInfo"
#define AMVP_KDA_PATTERN_VPARTYINFO_STR "vPartyInfo"
#define AMVP_KDA_PATTERN_CONTEXT_STR "context"
#define AMVP_KDA_PATTERN_ALGID_STR "algorithmId"
#define AMVP_KDA_PATTERN_LABEL_STR "label"
#define AMVP_KDA_PATTERN_LENGTH_STR "l"
#define AMVP_KDA_PATTERN_T_STR "t"
#define AMVP_KDA_PATTERN_LITERAL_STR_LEN_MAX 64 //arbitrary
#define AMVP_KDA_PATTERN_LITERAL_BYTE_MAX (AMVP_KDA_PATTERN_LITERAL_STR_LEN_MAX >> 3)
//arbitrary - leaving extra space in case spec adds more values later
#define AMVP_KDA_PATTERN_REG_STR_MAX 256

#define AMVP_KDA_DKM_BIT_MAX 8192 //arbitrary
#define AMVP_KDA_DKM_STR_MAX (AMVP_KDA_DKM_BIT_MAX >> 2)
#define AMVP_KDA_DKM_BYTE_MAX (AMVP_KDA_DKM_BIT_MAX >> 3)

#define AMVP_KDA_FIXED_BIT_MAX 8192 //arbitrary
#define AMVP_KDA_FIXED_STR_MAX (AMVP_KDA_FIXED_BIT_MAX >> 2)
#define AMVP_KDA_FIXED_BYTE_MAX (AMVP_KDA_FIXED_BIT_MAX >> 3)

#define AMVP_KDA_SALT_BIT_MAX 1344 //aux function maximum block size
#define AMVP_KDA_SALT_STR_MAX (AMVP_KDA_SALT_BIT_MAX >> 2)
#define AMVP_KDA_SALT_BYTE_MAX (AMVP_KDA_SALT_BIT_MAX >> 3)

#define AMVP_KDA_Z_BIT_MAX 65336 //arbitrary, used spec example
#define AMVP_KDA_Z_STR_MAX (AMVP_KDA_Z_BIT_MAX >> 2)
#define AMVP_KDA_Z_BYTE_MAX (AMVP_KDA_Z_BIT_MAX >> 3)


#define AMVP_CURL_BUF_MAX       (1024 * 1024 * 64) /**< 64 MB */
#define AMVP_RETRY_TIME_MIN     5 /* seconds */
#define AMVP_RETRY_TIME_MAX     300 
#define AMVP_MAX_WAIT_TIME      7200
#define AMVP_RETRY_TIME         30
#define AMVP_RETRY_MODIFIER_MAX 10
#define AMVP_JWT_TOKEN_MAX      2048
#define AMVP_ATTR_URL_MAX       2083 /* MS IE's limit - arbitrary */

#define AMVP_SESSION_PARAMS_STR_LEN_MAX 256
#define AMVP_REQUEST_STR_LEN_MAX 128
#define AMVP_OE_STR_MAX 256
#define AMVP_PATH_SEGMENT_DEFAULT ""
#define AMVP_JSON_FILENAME_MAX 128

#define AMVP_PROTOCOL_VERSION_STR "amvVersion"

/* 
 * This should NOT be made longer than AMVP_JSON_FILENAME_MAX - 15
 * (accounting for _ character, ".json", and 9 digits for testSession ID)
 */
#define AMVP_SAVE_DEFAULT_PREFIX "testSession"

#define AMVP_CFB1_BIT_MASK      0x80


#define AMVP_USER_AGENT_STR_MAX 255
//char cannot exist in any string for http user agent for parsing reasons
#define AMVP_USER_AGENT_DELIMITER ';'
#define AMVP_USER_AGENT_CHAR_REPLACEMENT '_';

/*
 * Max lengths for different values in the HTTP user-agent string, arbitrarily selected
 */
#define AMVP_USER_AGENT_AMVP_STR_MAX 16
#define AMVP_USER_AGENT_OSNAME_STR_MAX 32
#define AMVP_USER_AGENT_OSVER_STR_MAX 64
#define AMVP_USER_AGENT_ARCH_STR_MAX 16
#define AMVP_USER_AGENT_PROC_STR_MAX 64
#define AMVP_USER_AGENT_COMP_STR_MAX 32

#define AMVP_STRING_LIST_MAX_LEN 256 //arbitrary max character count for a string in AMVP_STRING_LIST

/*
 * If library cannot detect hardware or software info for HTTP user-agent string, we can check for them
 * in environmental variables, which are defined here
 */
#define AMVP_USER_AGENT_OSNAME_ENV "ACV_OE_OSNAME"
#define AMVP_USER_AGENT_OSVER_ENV "ACV_OE_OSVERSION"
#define AMVP_USER_AGENT_ARCH_ENV "ACV_OE_ARCHITECTURE"
#define AMVP_USER_AGENT_PROC_ENV "ACV_OE_PROCESSOR"
#define AMVP_USER_AGENT_COMP_ENV "ACV_OE_COMPILER"

typedef struct amvp_alg_handler_t AMVP_ALG_HANDLER;

struct amvp_alg_handler_t {
    AMVP_CIPHER cipher;

    AMVP_RESULT (*handler) (AMVP_CTX *ctx, JSON_Object *obj);

    const char *name;
    const char *mode; /** < Should be NULL unless using an asymmetric alg */
    const char *revision;
    union {
        AMVP_SUB_AES      aes;
        AMVP_SUB_TDES     tdes;
        AMVP_SUB_CMAC     cmac;
        AMVP_SUB_KMAC     kmac;
        AMVP_SUB_KDF      kdf;
        AMVP_SUB_DSA      dsa;
        AMVP_SUB_RSA      rsa;
        AMVP_SUB_ECDSA    ecdsa;
        AMVP_SUB_DRBG     drbg;
        AMVP_SUB_HMAC     hmac;
        AMVP_SUB_HASH     hash;
        AMVP_SUB_KAS      kas;
    } alg;
};

typedef struct amvp_vs_list_t {
    int vs_id;
    struct amvp_vs_list_t *next;
} AMVP_VS_LIST;

struct amvp_result_desc_t {
    AMVP_RESULT rv;
    const char *desc;
};

struct amvp_hash_alg_info {
    AMVP_HASH_ALG id;
    const char *name;
};

struct amvp_ec_curve_info {
    AMVP_EC_CURVE id;
    const char *name;
};

/* This is used when we need a table of acceptable ciphers for specific situations */
struct amvp_function_info {
    AMVP_CIPHER cipher;
    const char *name;
};

struct amvp_alt_revision_info {
    AMVP_REVISION revision;
    const char *name;
};

/*
 * Used to help manage capability structures
 */
typedef enum amvp_capability_type {
    AMVP_SYM_TYPE = 1,
    AMVP_HASH_TYPE,
    AMVP_DRBG_TYPE,
    AMVP_HMAC_TYPE,
    AMVP_CMAC_TYPE,
    AMVP_KMAC_TYPE,
    AMVP_RSA_KEYGEN_TYPE,
    AMVP_RSA_SIGGEN_TYPE,
    AMVP_RSA_SIGVER_TYPE,
    AMVP_RSA_PRIM_TYPE,
    AMVP_ECDSA_KEYGEN_TYPE,
    AMVP_ECDSA_KEYVER_TYPE,
    AMVP_ECDSA_SIGGEN_TYPE,
    AMVP_ECDSA_SIGVER_TYPE,
    AMVP_DSA_TYPE,
    AMVP_KDF135_SNMP_TYPE,
    AMVP_KDF135_SSH_TYPE,
    AMVP_KDF135_SRTP_TYPE,
    AMVP_KDF135_IKEV2_TYPE,
    AMVP_KDF135_IKEV1_TYPE,
    AMVP_KDF135_X942_TYPE,
    AMVP_KDF135_X963_TYPE,
    AMVP_KDF135_TPM_TYPE,
    AMVP_KDF108_TYPE,
    AMVP_PBKDF_TYPE,
    AMVP_KDF_TLS12_TYPE,
    AMVP_KDF_TLS13_TYPE,
    AMVP_KAS_ECC_CDH_TYPE,
    AMVP_KAS_ECC_COMP_TYPE,
    AMVP_KAS_ECC_NOCOMP_TYPE,
    AMVP_KAS_ECC_SSC_TYPE,
    AMVP_KAS_FFC_COMP_TYPE,
    AMVP_KAS_FFC_SSC_TYPE,
    AMVP_KAS_FFC_NOCOMP_TYPE,
    AMVP_KAS_IFC_TYPE,
    AMVP_KDA_ONESTEP_TYPE,
    AMVP_KDA_TWOSTEP_TYPE,
    AMVP_KDA_HKDF_TYPE,
    AMVP_KTS_IFC_TYPE,
    AMVP_SAFE_PRIMES_KEYGEN_TYPE,
    AMVP_SAFE_PRIMES_KEYVER_TYPE
} AMVP_CAP_TYPE;

/*
 * Supported length list
 */
typedef struct amvp_sl_list_t {
    int length;
    struct amvp_sl_list_t *next;
} AMVP_SL_LIST;

/*
 * Supported param list
 */
typedef struct amvp_param_list_t {
    int param;
    struct amvp_param_list_t *next;
} AMVP_PARAM_LIST;

/*
 * list of STATIC strings to be used for supported algs,
 * prime_tests, etc.
 */
typedef struct amvp_name_list_t {
    const char *name;
    struct amvp_name_list_t *next;
} AMVP_NAME_LIST;

/*
 * list of CALLOC'd strings to be used for supported algs,
 * vsid_url etc.
 */
typedef struct amvp_string_list_t {
    char *string;
    struct amvp_string_list_t *next;
} AMVP_STRING_LIST;

/**
 * @struct AMVP_KV_LIST
 * @brief This struct is a list of key/value pairs.
 *
 */
typedef struct amvp_kv_list_t {
    char *key;
    char *value;
    struct amvp_kv_list_t *next;
} AMVP_KV_LIST;

typedef struct amvp_json_domain_obj_t {
    int min;
    int max;
    int increment;
    struct amvp_sl_list_t *values;
} AMVP_JSON_DOMAIN_OBJ;

typedef struct amvp_prereq_alg_val {
    AMVP_PREREQ_ALG alg;
    char *val;
} AMVP_PREREQ_ALG_VAL;

typedef struct amvp_prereq_list {
    AMVP_PREREQ_ALG_VAL prereq_alg_val;
    struct amvp_prereq_list *next;
} AMVP_PREREQ_LIST;

typedef struct amvp_sym_cipher_capability {
    AMVP_CONFORMANCE conformance;
    AMVP_SYM_CIPH_DIR direction;
    AMVP_SYM_CIPH_KO keying_option;
    AMVP_SYM_CIPH_IVGEN_SRC ivgen_source;
    AMVP_SYM_CIPH_IVGEN_MODE ivgen_mode;
    AMVP_SYM_CIPH_SALT_SRC salt_source;
    int perform_ctr_tests;
    unsigned int ctr_incr;
    unsigned int ctr_ovrflw;
    unsigned int dulen_matches_paylen;
    AMVP_SL_LIST *keylen;
    AMVP_SL_LIST *ptlen;
    AMVP_SL_LIST *tweak;
    AMVP_SL_LIST *ivlen;
    AMVP_SL_LIST *aadlen;
    AMVP_SL_LIST *taglen;

    //Support domains for most lengths - APIs should check
    //and allow either/or SL_LIST or domain for not but not both
    AMVP_JSON_DOMAIN_OBJ payload_len;
    AMVP_JSON_DOMAIN_OBJ iv_len;
    AMVP_JSON_DOMAIN_OBJ aad_len;
    AMVP_JSON_DOMAIN_OBJ tweak_len;
    AMVP_JSON_DOMAIN_OBJ du_len;

    int kw_mode;
} AMVP_SYM_CIPHER_CAP;

typedef struct amvp_hash_capability {
    int in_bit;   /* defaults to false */
    int in_empty; /* defaults to false */
    int out_bit; /**< 1 for true, 0 for false
                      Defaults to false.
                      Only for AMVP_HASH_SHAKE_* */
    AMVP_JSON_DOMAIN_OBJ out_len; /**< Required for AMVP_HASH_SHAKE_* */
    AMVP_JSON_DOMAIN_OBJ msg_length;
} AMVP_HASH_CAP;

typedef struct amvp_kdf135_snmp_capability {
    AMVP_SL_LIST *pass_lens;
    AMVP_NAME_LIST *eng_ids;
} AMVP_KDF135_SNMP_CAP;

typedef struct amvp_kdf108_mode_params {
    const char *kdf_mode;
    AMVP_NAME_LIST *mac_mode;
    AMVP_JSON_DOMAIN_OBJ supported_lens;
    AMVP_NAME_LIST *data_order;
    AMVP_SL_LIST *counter_lens;
    int empty_iv_support;
    int requires_empty_iv;
} AMVP_KDF108_MODE_PARAMS;

typedef struct amvp_kdf108_capability {
    AMVP_KDF108_MODE_PARAMS counter_mode;
    AMVP_KDF108_MODE_PARAMS feedback_mode;
    AMVP_KDF108_MODE_PARAMS dpi_mode;
} AMVP_KDF108_CAP;

typedef struct amvp_kdf135_ssh_capability {
    int method[4];
    int sha;
} AMVP_KDF135_SSH_CAP;

typedef struct amvp_kdf135_srtp_capability {
    int supports_zero_kdr;
    int kdr_exp[AMVP_KDF135_SRTP_KDR_MAX];
    AMVP_SL_LIST *aes_keylens;
} AMVP_KDF135_SRTP_CAP;

typedef struct amvp_kdf135_ikev2_capability {
    AMVP_NAME_LIST *hash_algs;
    AMVP_JSON_DOMAIN_OBJ init_nonce_len_domain;
    AMVP_JSON_DOMAIN_OBJ respond_nonce_len_domain;
    AMVP_JSON_DOMAIN_OBJ dh_secret_len;
    AMVP_JSON_DOMAIN_OBJ key_material_len;
} AMVP_KDF135_IKEV2_CAP;

typedef struct amvp_kdf135_ikev1_capability {
    AMVP_NAME_LIST *hash_algs;
    char auth_method[AMVP_AUTH_METHOD_STR_MAX_PLUS];
    AMVP_JSON_DOMAIN_OBJ init_nonce_len_domain;
    AMVP_JSON_DOMAIN_OBJ respond_nonce_len_domain;
    AMVP_JSON_DOMAIN_OBJ dh_secret_len;
    AMVP_JSON_DOMAIN_OBJ psk_len;
} AMVP_KDF135_IKEV1_CAP;


typedef struct amvp_kdf135_x942_capability {
    AMVP_KDF_X942_TYPE type;
    AMVP_JSON_DOMAIN_OBJ key_len;
    AMVP_JSON_DOMAIN_OBJ other_len;
    AMVP_JSON_DOMAIN_OBJ supp_len;
    AMVP_JSON_DOMAIN_OBJ zz_len;
    AMVP_NAME_LIST *hash_algs;
    AMVP_NAME_LIST *oids;
} AMVP_KDF135_X942_CAP;

typedef struct amvp_kdf135_x963_capability {
    AMVP_NAME_LIST *hash_algs;
    AMVP_SL_LIST *shared_info_lengths;
    AMVP_SL_LIST *field_sizes;
    AMVP_SL_LIST *key_data_lengths;
} AMVP_KDF135_X963_CAP;

typedef struct amvp_pbkdf_capability {
    AMVP_NAME_LIST *hmac_algs;
    AMVP_JSON_DOMAIN_OBJ iteration_count_domain;
    AMVP_JSON_DOMAIN_OBJ key_len_domain;
    AMVP_JSON_DOMAIN_OBJ password_len_domain;
    AMVP_JSON_DOMAIN_OBJ salt_len_domain;
} AMVP_PBKDF_CAP;

typedef struct amvp_kdf_tls12_capability {
    AMVP_NAME_LIST *hash_algs;
} AMVP_KDF_TLS12_CAP;

typedef struct amvp_kdf_tls13_capability {
    AMVP_NAME_LIST *hmac_algs;
    AMVP_PARAM_LIST *running_mode;
} AMVP_KDF_TLS13_CAP;

typedef struct amvp_hmac_capability {
    AMVP_JSON_DOMAIN_OBJ key_len; // 8-524288
    AMVP_JSON_DOMAIN_OBJ mac_len; // 32-512
} AMVP_HMAC_CAP;

typedef struct amvp_cmac_capability {
    AMVP_JSON_DOMAIN_OBJ mac_len;
    AMVP_JSON_DOMAIN_OBJ msg_len;
    int direction_gen;
    int direction_ver;
    AMVP_SL_LIST *key_len;       // 128,192,256
    AMVP_SL_LIST *keying_option;
} AMVP_CMAC_CAP;

typedef struct amvp_kmac_capability {
    AMVP_JSON_DOMAIN_OBJ mac_len;
    AMVP_JSON_DOMAIN_OBJ msg_len;
    AMVP_JSON_DOMAIN_OBJ key_len;
    AMVP_XOF_SUPPORT_OPTION xof;
    int hex_customization; // boolean
} AMVP_KMAC_CAP;

typedef struct amvp_drbg_cap_mode {
    int der_func_enabled;
    int entropy_input_len;      //":"112",
    int entropy_len_max;
    int entropy_len_min;
    int entropy_len_step;
    int nonce_len;              //":"56",
    int nonce_len_max;
    int nonce_len_min;
    int nonce_len_step;
    int perso_string_len;       //":"0",
    int perso_len_max;
    int perso_len_min;
    int perso_len_step;
    int additional_input_len;   //":"0",
    int additional_in_len_max;
    int additional_in_len_min;
    int additional_in_len_step;
    int returned_bits_len;      //":"256"
} AMVP_DRBG_CAP_GROUP;

typedef struct amvp_drbg_group_list_t {
    int id;
    AMVP_DRBG_CAP_GROUP *group;
    struct amvp_drbg_group_list_t *next;
} AMVP_DRBG_GROUP_LIST;

typedef struct amvp_drbg_mode_list_t {
    AMVP_DRBG_MODE mode;
    AMVP_DRBG_GROUP_LIST *groups;
    struct amvp_drbg_mode_list_t *next;
} AMVP_DRBG_MODE_LIST;

typedef struct amvp_drbg_capability {
    AMVP_CIPHER cipher;
    AMVP_PREREQ_LIST *prereq_vals;
    int pred_resist_enabled;    // boolean
    int reseed_implemented;     // boolean
    AMVP_DRBG_MODE_LIST *drbg_cap_mode;
} AMVP_DRBG_CAP;

struct amvp_drbg_mode_name_t {
    AMVP_DRBG_MODE mode;
    const char *name;
};

typedef struct amvp_rsa_hash_pair_list {
    const char *name;
    int salt;
    struct amvp_rsa_hash_pair_list *next;
} AMVP_RSA_HASH_PAIR_LIST;

typedef struct amvp_rsa_mode_caps_list {
    unsigned int modulo; // 2048, 3072, 4096 -- defined as macros
    int salt;   // only valid for siggen mode
    AMVP_NAME_LIST *hash_algs;
    AMVP_RSA_HASH_PAIR_LIST *hash_pair;
    AMVP_NAME_LIST *prime_tests;
    struct amvp_rsa_mode_caps_list *next;
} AMVP_RSA_MODE_CAPS_LIST;

typedef struct amvp_rsa_keygen_capability_t {
    int key_format_crt;                     // if false, key format is assumed to be standard
    AMVP_RSA_PUB_EXP_MODE pub_exp_mode;
    char *fixed_pub_exp;               // hex value of e
    AMVP_RSA_KEYGEN_MODE rand_pq;      // as defined in FIPS186-4
    const char *rand_pq_str;
    int info_gen_by_server;                  // boolean
    AMVP_RSA_MODE_CAPS_LIST *mode_capabilities;
    struct amvp_rsa_keygen_capability_t *next; // to support multiple randPQ values
} AMVP_RSA_KEYGEN_CAP;

typedef struct amvp_rsa_prim_capability_t {
    unsigned int prim_type;
    int key_format_crt;                     // if false, key format is assumed to be standard
    AMVP_RSA_PUB_EXP_MODE pub_exp_mode;
    char *fixed_pub_exp;               // hex value of e
    struct amvp_rsa_prim_capability_t *next; // to support multiple randPQ values
} AMVP_RSA_PRIM_CAP;


typedef struct amvp_curve_hash_compatibility_list_t {
    AMVP_EC_CURVE curve;
    AMVP_HASH_ALG algs[AMVP_HASH_ALG_MAX]; //flags for all supported hash algs for curve, use arr so we can memcmp
    struct amvp_curve_hash_compatibility_list_t *next;
} AMVP_CURVE_ALG_COMPAT_LIST;

typedef struct amvp_ecdsa_capability_t {
    //Contains registered curves and hash algs to be used specifically for each curve
    AMVP_CURVE_ALG_COMPAT_LIST *curves;
    AMVP_NAME_LIST *secret_gen_modes;
    //For backwards compatibility, this contains hash algs that will be used with ALL registered curves (HASH_ALG = array index)
    int hash_algs[AMVP_HASH_ALG_MAX + 1];
    AMVP_ECDSA_COMPONENT_MODE component;
} AMVP_ECDSA_CAP;

typedef struct amvp_rsa_sig_capability_t {
    const char *sig_type_str;
    unsigned int sig_type;
    int pub_exp_mode;                           // for sigVer only
    char *fixed_pub_exp;                        // hex value of e
    AMVP_RSA_MODE_CAPS_LIST *mode_capabilities; //holds modRSASigGen (int) and hashSigGen (list)
    struct amvp_rsa_sig_capability_t *next;
} AMVP_RSA_SIG_CAP;


typedef struct amvp_dsa_attrs {
    unsigned int modulo;
    int sha;
    struct amvp_dsa_attrs *next;
} AMVP_DSA_ATTRS;

#define AMVP_DSA_MAX_MODES 5
typedef struct amvp_dsa_cap_mode_t {
    AMVP_DSA_MODE cap_mode;
    int defined;
    int gen_pq_prob;
    int gen_pq_prov;
    int gen_g_unv;
    int gen_g_can;
    AMVP_DSA_ATTRS *dsa_attrs;
} AMVP_DSA_CAP_MODE;

typedef struct amvp_dsa_capability {
    AMVP_CIPHER cipher;
    AMVP_DSA_CAP_MODE *dsa_cap_mode;
} AMVP_DSA_CAP;

typedef struct amvp_kas_ecc_mac {
    int alg;
    int curve;
    AMVP_PARAM_LIST *key;
    int nonce;
    int maclen;
    struct amvp_kas_ecc_mac *next;
} AMVP_KAS_ECC_MAC;

typedef struct amvp_kas_ecc_pset {
    unsigned int set;
    int curve;
    AMVP_PARAM_LIST *sha;
    AMVP_KAS_ECC_MAC *mac;
    struct amvp_kas_ecc_pset *next;
} AMVP_KAS_ECC_PSET;

typedef struct amvp_kas_ecc_scheme {
    AMVP_KAS_ECC_SCHEMES scheme;
    AMVP_KAS_ECC_SET kdf;
    AMVP_PARAM_LIST *role;
    AMVP_KAS_ECC_PSET *pset;
    struct amvp_kas_ecc_scheme *next;
} AMVP_KAS_ECC_SCHEME;


typedef struct amvp_kas_ecc_cap_mode_t {
    AMVP_KAS_ECC_MODE cap_mode;
    AMVP_PREREQ_LIST *prereq_vals;
    AMVP_PARAM_LIST *curve;    /* CDH mode only */
    AMVP_REVISION revision; /* Empty if default is used */
    AMVP_PARAM_LIST *function;
    AMVP_KAS_ECC_SCHEME *scheme; /* other modes use schemes */
    int hash;     /* only a single sha for KAS-ECC-SSC */
} AMVP_KAS_ECC_CAP_MODE;

typedef struct amvp_kas_ecc_capability_t {
    AMVP_CIPHER cipher;
    AMVP_KAS_ECC_CAP_MODE *kas_ecc_mode;
} AMVP_KAS_ECC_CAP;

typedef struct amvp_kas_ffc_mac {
    int alg;
    int curve;
    AMVP_PARAM_LIST *key;
    int nonce;
    int maclen;
    struct amvp_kas_ffc_mac *next;
} AMVP_KAS_FFC_MAC;

typedef struct amvp_kas_ffc_pset {
    unsigned int set;
    AMVP_PARAM_LIST *sha;
    AMVP_KAS_FFC_MAC *mac;
    struct amvp_kas_ffc_pset *next;
} AMVP_KAS_FFC_PSET;

typedef struct amvp_kas_ffc_scheme {
    AMVP_KAS_FFC_SCHEMES scheme;
    AMVP_KAS_FFC_SET kdf;
    AMVP_PARAM_LIST *role;
    AMVP_KAS_FFC_PSET *pset;
    struct amvp_kas_ffc_scheme *next;
} AMVP_KAS_FFC_SCHEME;


typedef struct amvp_kas_ffc_cap_mode_t {
    AMVP_KAS_FFC_MODE cap_mode;
    AMVP_PREREQ_LIST *prereq_vals;
    AMVP_PARAM_LIST *function;
    AMVP_PARAM_LIST *genmeth;
    int hash;
    AMVP_KAS_FFC_SCHEME *scheme; /* other modes use schemes */
} AMVP_KAS_FFC_CAP_MODE;

typedef struct amvp_kas_ffc_capability_t {
    AMVP_CIPHER cipher;
    AMVP_KAS_FFC_CAP_MODE *kas_ffc_mode;
} AMVP_KAS_FFC_CAP;

typedef struct amvp_kas_ifc_capability_t {
    AMVP_CIPHER cipher;
    int hash;
    char *fixed_pub_exp;
    AMVP_PARAM_LIST *kas1_roles;
    AMVP_PARAM_LIST *kas2_roles;
    AMVP_PARAM_LIST *keygen_method;
    AMVP_SL_LIST *modulo;
} AMVP_KAS_IFC_CAP;



typedef struct amvp_safe_primes_cap_mode_t {
    AMVP_PARAM_LIST *genmeth;
} AMVP_SAFE_PRIMES_CAP_MODE;

typedef struct amvp_safe_primes_capability_t {
    AMVP_CIPHER cipher;
    AMVP_SAFE_PRIMES_CAP_MODE *mode;
} AMVP_SAFE_PRIMES_CAP;

typedef struct amvp_kda_onestep_capability_t {
    AMVP_CIPHER cipher;
    AMVP_REVISION revision;
    AMVP_NAME_LIST *aux_functions;
    AMVP_NAME_LIST *mac_salt_methods;
    AMVP_PARAM_LIST *patterns;
    char *literal_pattern_candidate; //optional - only filled if "literal" pattern is used - hex only
    AMVP_PARAM_LIST *encodings;
    AMVP_JSON_DOMAIN_OBJ z;
    int l;
} AMVP_KDA_ONESTEP_CAP;

typedef struct amvp_kda_twostep_capability_t {
    AMVP_CIPHER cipher;
    AMVP_REVISION revision;
    AMVP_NAME_LIST *mac_salt_methods;
    AMVP_PARAM_LIST *patterns;
    char *literal_pattern_candidate; //optional - only filled if "literal" pattern is used - hex only
    AMVP_PARAM_LIST *encodings;
    AMVP_JSON_DOMAIN_OBJ z;
    int l;
    int perform_multi_expansion_tests; /* 56Cr2 only */
    int use_hybrid_shared_secret; /* 56Cr2 only */
    AMVP_JSON_DOMAIN_OBJ aux_secret_len; /* 56Cr2 only */
    AMVP_KDF108_CAP kdf_params; /* All of the KDF108 params get stored in here to avoid duplicate code */
} AMVP_KDA_TWOSTEP_CAP;

typedef struct amvp_kda_hkdf_t {
    AMVP_CIPHER cipher;
    AMVP_PARAM_LIST *patterns;
    AMVP_REVISION revision;
    char *literal_pattern_candidate; //optional - only filled if "literal" pattern is used - hex only
    AMVP_PARAM_LIST *encodings;
    AMVP_NAME_LIST *hmac_algs;
    AMVP_NAME_LIST *mac_salt_methods;
    AMVP_JSON_DOMAIN_OBJ z;
    int l;
    int perform_multi_expansion_tests; /* 56Cr2 only */
    int use_hybrid_shared_secret; /* 56Cr2 only */
    AMVP_JSON_DOMAIN_OBJ aux_secret_len; /* 56Cr2 only */
} AMVP_KDA_HKDF_CAP;

typedef struct amvp_kts_ifc_macs_t {
    AMVP_CIPHER cipher;
    int key_length;
    int mac_length;
    struct amvp_kts_ifc_macs_t *next;
} AMVP_KTS_IFC_MACS;

typedef struct amvp_kts_ifc_schemes_t {
    AMVP_KTS_IFC_SCHEME_TYPE scheme;
    int l;
    AMVP_PARAM_LIST *roles;
    AMVP_KTS_IFC_MACS *macs;  /* not yet supported */
    AMVP_PARAM_LIST *hash;
    int null_assoc_data;
    char *assoc_data_pattern;
    char *encodings;      /* may need to change to SL_LIST */
    struct amvp_kts_ifc_schemes_t *next;
} AMVP_KTS_IFC_SCHEMES;


typedef struct amvp_kts_ifc_capability_t {
    AMVP_CIPHER cipher;
    char *fixed_pub_exp;
    char *iut_id;
    AMVP_PARAM_LIST *functions;
    AMVP_KTS_IFC_SCHEMES *schemes;
    AMVP_PARAM_LIST *keygen_method;
    AMVP_SL_LIST *modulo;
} AMVP_KTS_IFC_CAP;

typedef struct amvp_caps_list_t {
    AMVP_CIPHER cipher;
    AMVP_CAP_TYPE cap_type;
    int has_prereq;    /* used to indicate algorithm can have prereqs */
    AMVP_PREREQ_LIST *prereq_vals;
    union {
        AMVP_SYM_CIPHER_CAP *sym_cap;
        AMVP_HASH_CAP *hash_cap;
        AMVP_DRBG_CAP *drbg_cap;
        AMVP_DSA_CAP *dsa_cap;
        AMVP_HMAC_CAP *hmac_cap;
        AMVP_CMAC_CAP *cmac_cap;
        AMVP_KMAC_CAP *kmac_cap;
        AMVP_RSA_KEYGEN_CAP *rsa_keygen_cap;
        AMVP_RSA_SIG_CAP *rsa_siggen_cap;
        AMVP_RSA_SIG_CAP *rsa_sigver_cap;
        AMVP_RSA_PRIM_CAP *rsa_prim_cap;
        AMVP_ECDSA_CAP *ecdsa_keygen_cap;
        AMVP_ECDSA_CAP *ecdsa_keyver_cap;
        AMVP_ECDSA_CAP *ecdsa_siggen_cap;
        AMVP_ECDSA_CAP *ecdsa_sigver_cap;
        AMVP_KDF135_SNMP_CAP *kdf135_snmp_cap;
        AMVP_KDF135_SSH_CAP *kdf135_ssh_cap;
        AMVP_KDF135_SRTP_CAP *kdf135_srtp_cap;
        AMVP_KDF135_IKEV2_CAP *kdf135_ikev2_cap;
        AMVP_KDF135_IKEV1_CAP *kdf135_ikev1_cap;
        AMVP_KDF135_X942_CAP *kdf135_x942_cap;
        AMVP_KDF135_X963_CAP *kdf135_x963_cap;
        AMVP_KDF108_CAP *kdf108_cap;
        AMVP_PBKDF_CAP *pbkdf_cap;
        AMVP_KDF_TLS12_CAP *kdf_tls12_cap;
        AMVP_KDF_TLS13_CAP *kdf_tls13_cap;
        AMVP_KAS_ECC_CAP *kas_ecc_cap;
        AMVP_KAS_FFC_CAP *kas_ffc_cap;
        AMVP_KAS_IFC_CAP *kas_ifc_cap;
        AMVP_KDA_ONESTEP_CAP *kda_onestep_cap;
        AMVP_KDA_TWOSTEP_CAP *kda_twostep_cap;
        AMVP_KDA_HKDF_CAP *kda_hkdf_cap;
        AMVP_KTS_IFC_CAP *kts_ifc_cap;
        AMVP_SAFE_PRIMES_CAP *safe_primes_keygen_cap;
        AMVP_SAFE_PRIMES_CAP *safe_primes_keyver_cap;
    } cap;

    struct amvp_caps_list_t *next;
} AMVP_CAPS_LIST;

typedef struct amvp_vendor_address_t {
    char *street_1;
    char *street_2;
    char *street_3;
    char *locality;
    char *region;
    char *country;
    char *postal_code;
    char *url; /**< ID URL returned from the server */
} AMVP_VENDOR_ADDRESS;

typedef struct amvp_oe_phone_list_t {
    char *number;
    char *type;
    struct amvp_oe_phone_list_t *next;
} AMVP_OE_PHONE_LIST;

typedef struct amvp_person_t {
    char *url; /**< ID URL returned from the server */
    char *full_name;
    AMVP_OE_PHONE_LIST *phone_numbers;
    AMVP_STRING_LIST *emails;
} AMVP_PERSON;

#define LIBAMVP_PERSONS_MAX 8
typedef struct amvp_persons_t {
    AMVP_PERSON person[LIBAMVP_PERSONS_MAX];
    int count;
} AMVP_PERSONS;

typedef struct amvp_vendor_t {
    unsigned int id; /**< For library tracking purposes */
    char *url; /**< ID URL returned from the server */
    char *name;
    char *website;
    AMVP_OE_PHONE_LIST *phone_numbers;
    AMVP_STRING_LIST *emails;
    AMVP_VENDOR_ADDRESS address;
    AMVP_PERSONS persons;
} AMVP_VENDOR;

#define LIBAMVP_VENDORS_MAX 8
typedef struct amvp_vendors_t {
    AMVP_VENDOR v[LIBAMVP_VENDORS_MAX];
    int count;
} AMVP_VENDORS;

typedef struct amvp_module_t {
    unsigned int id; /**< For library tracking purposes */
    char *name;
    char *type;
    char *version;
    char *description;
    char *url; /**< ID URL returned from the server */
    AMVP_VENDOR *vendor; /**< Pointer to the Vendor to use */
} AMVP_MODULE;

#define LIBAMVP_MODULES_MAX 32
typedef struct amvp_modules_t {
    AMVP_MODULE module[LIBAMVP_MODULES_MAX];
    int count;
} AMVP_MODULES;

typedef struct amvp_dependency_t {
    unsigned int id; /**< For library tracking purposes */
    char *url; /**< Returned from the server */
    char *name;
    char *type;
    char *description;
    char *series;
    char *family;
    char *version;
    char *manufacturer;
} AMVP_DEPENDENCY;

#define LIBAMVP_DEPENDENCIES_MAX 64
typedef struct amvp_dependencies_t {
    AMVP_DEPENDENCY deps[LIBAMVP_DEPENDENCIES_MAX];
    unsigned int count;
} AMVP_DEPENDENCIES;

typedef enum amvp_resource_status {
    AMVP_RESOURCE_STATUS_COMPLETE = 1,
    AMVP_RESOURCE_STATUS_PARTIAL,
    AMVP_RESOURCE_STATUS_INCOMPLETE,
} AMVP_RESOURCE_STATUS;

typedef enum amvp_waiting_status {
    AMVP_WAITING_FOR_TESTS = 1,
    AMVP_WAITING_FOR_RESULTS,
} AMVP_WAITING_STATUS;

typedef struct amvp_oe_dependencies_t {
    AMVP_DEPENDENCY *deps[LIBAMVP_DEPENDENCIES_MAX]; /* Array to pointers of linked dependencies */
    unsigned int count;
    AMVP_RESOURCE_STATUS status; /**< PARTIAL indicates that at least one of the linked Dependencies does not
                                      exist. INCOMPLETE indicates all of the 'url' are missing */
} AMVP_OE_DEPENDENCIES;

typedef struct amvp_oe_t {
    unsigned int id; /**< For library tracking purposes */
    char *name; /**< Name of the Operating Environment */
    char *url; /**< ID URL returned from the server */
    AMVP_OE_DEPENDENCIES dependencies; /**< Pointers to attached dependencies */
} AMVP_OE;

#define LIBAMVP_OES_MAX 8
typedef struct amvp_oes_t {
    AMVP_OE oe[LIBAMVP_OES_MAX];
    int count;
} AMVP_OES;

typedef struct amvp_operating_env_t {
    AMVP_VENDORS vendors; /**< Vendors */
    AMVP_MODULES modules; /**< Modules */
    AMVP_DEPENDENCIES dependencies; /** Dependencies */
    AMVP_OES oes; /**< Operating Environments */
} AMVP_OPERATING_ENV;

typedef struct amvp_fips_t {
    int do_validation; /* Flag indicating whether a FIPS validation
                          should be performed on this testSession. 1 for yes */
    int metadata_loaded; /* Flag indicating whether the metadata necessary for
                           a FIPS validation was successfully loaded into memory. 1 for yes */
    int metadata_ready; /* Flag indicating whether the metadata necessary for
                           a FIPS validation has passed all stages (loaded and verified). 1 for yes */
    AMVP_MODULE *module; /* Pointer to the Module to use for this validation */
    AMVP_OE *oe; /* Pointer to the Operating Environment to use for this validation */
} AMVP_FIPS;

/*
 * This struct holds all the global data for a test session, such
 * as the server name, port#, etc.  Some of the values in this
 * struct are transitory and used during the JSON parsing and
 * vector processing logic.
 */
struct amvp_ctx_t {
    /* Global config values for the session */
    AMVP_LOG_LVL log_lvl;
    int debug;              /* Indicates if the ctx is set to run in "debug" mode for extra output */
    char *server_name;
    char *path_segment;
    int server_port;
    char *cacerts_file;     /* Location of CA certificates Curl will use to verify peer */
    int verify_peer;        /* enables TLS peer verification via Curl */
    char *tls_cert;         /* Location of PEM encoded X509 cert to use for TLS client auth */
    char *tls_key;          /* Location of PEM encoded priv key to use for TLS client auth */

    char *http_user_agent;   /* String containing info to be sent with HTTP requests, currently OE info */
    char *session_file_path; /* String containing the path of the testSession file after it is created when applicable */
    
    AMVP_OPERATING_ENV op_env; /**< The Operating Environment resources available */
    AMVP_STRING_LIST *vsid_url_list;
    char *session_url;
    int session_passed;

    char *json_filename;    /* filename of registration JSON */
    int use_json;           /* flag to indicate a JSON file is being used for registration */
    int is_sample;          /* flag to idicate that we are requesting sample vector responses */
    char *vector_req_file;  /* filename to use to store vector request JSON */
    int vector_req;         /* flag to indicate we are storing vector request JSON in a file */
    int vector_rsp;         /* flag to indicate we are storing vector responses JSON in a file */
    int get;                /* flag to indicate we are only getting status or metadata */
    char *get_string;       /* string used for get request */
    int post;               /* flag to indicate we are only posting metadata */
    char *post_filename;    /* string used for post */
    int put;                /* flag to indicate we are only putting metadata  for post test validation*/
    char *put_filename;     /* string used for put */
    int delete;             /* flag to indicate we are only requesting deleting a resource */
    char *delete_string;    /* string used for delete request */
    char *save_filename;    /* string used for file to save certain HTTP requests to */
    int mod_cert_req;
    char *mod_cert_req_file;    /* string used for file to save certain HTTP requests to */
    int post_resources;
    char *post_resources_filename;    /* string used for file to save certain HTTP requests to */

    AMVP_FIPS fips; /* Information related to a FIPS validation */

    /* test session data */
    AMVP_VS_LIST *vs_list;
    char *jwt_token; /* access_token provided by server for authenticating REST calls */
    char *tmp_jwt; /* access_token provided by server for authenticating a single REST call */
    int use_tmp_jwt; /* 1 if the tmp_jwt should be used */
    JSON_Value *registration; /* The capability registration string sent when creating a test session */

    /* crypto module capabilities list */
    AMVP_CAPS_LIST *caps_list;
    /* Maintain a count of the number of registered vector sets so we can evaluate cost. This can be >= caps_list size */
    int vs_count;

    /* application callbacks */
    AMVP_RESULT (*test_progress_cb) (char *msg, AMVP_LOG_LVL level);

    /* Two-factor authentication callback */
    AMVP_RESULT (*totp_cb) (char **token, int token_max);

    /* Transitory values */
    int vs_id;      /* vs_id currently being processed */

    JSON_Value *kat_resp; /* holds the current set of vector responses */

    char *curl_buf;       /**< Data buffer for inbound Curl messages */
    int curl_read_ctr;    /**< Total number of bytes written to the curl_buf */
    int post_size_constraint;  /**< The number of bytes that the body of an HTTP POST may contain
                                    without requiring the use of the /large endpoint. If the POST body
                                    is larger than this value, then use of the /large endpoint is necessary */

};

AMVP_RESULT amvp_check_test_results(AMVP_CTX *ctx);

AMVP_RESULT amvp_process_tests(AMVP_CTX *ctx);

AMVP_RESULT amvp_send_test_session_registration(AMVP_CTX *ctx, char *reg, int len);

AMVP_RESULT amvp_send_login(AMVP_CTX *ctx, char *login, int len);

AMVP_RESULT amvp_transport_put_validation(AMVP_CTX *ctx, const char *data, int data_len);

AMVP_RESULT amvp_transport_get(AMVP_CTX *ctx, const char *url, const AMVP_KV_LIST *parameters);

AMVP_RESULT amvp_transport_post(AMVP_CTX *ctx, const char *uri, char *data, int data_len);

AMVP_RESULT amvp_transport_put(AMVP_CTX *ctx, const char *endpoint, const char *data, int data_len);

AMVP_RESULT amvp_transport_delete(AMVP_CTX *ctx, const char *endpoint);

AMVP_RESULT amvp_retrieve_vector_set(AMVP_CTX *ctx, char *vsid_url);

AMVP_RESULT amvp_retrieve_vector_set_result(AMVP_CTX *ctx, const char *vsid_url);

AMVP_RESULT amvp_retrieve_expected_result(AMVP_CTX *ctx, const char *api_url);

AMVP_RESULT amvp_submit_vector_responses(AMVP_CTX *ctx, char *vsid_url);

void amvp_log_msg(AMVP_CTX *ctx, AMVP_LOG_LVL level, const char *func, int line, const char *format, ...);
void amvp_log_newline(AMVP_CTX *ctx);

/* AMVP build registration functions used internally */
AMVP_RESULT amvp_build_registration_json(AMVP_CTX *ctx, JSON_Value **reg);

AMVP_RESULT amvp_build_full_registration(AMVP_CTX *ctx, char **out, int *out_len);

AMVP_RESULT amvp_build_validation(AMVP_CTX *ctx, char **out, int *out_len);

/*
 * Operating Environment functions
 */
void amvp_oe_free_operating_env(AMVP_CTX *ctx);

AMVP_RESULT amvp_verify_fips_validation_metadata(AMVP_CTX *ctx);

AMVP_RESULT amvp_notify_large(AMVP_CTX *ctx,
                              const char *url,
                              char *large_url,
                              unsigned int data_len);

/*
 * AMVP utility functions used internally
 */
AMVP_CAPS_LIST *amvp_locate_cap_entry(AMVP_CTX *ctx, AMVP_CIPHER cipher);

const char *amvp_lookup_cipher_name(AMVP_CIPHER alg);

AMVP_CIPHER amvp_lookup_cipher_index(const char *algorithm);

AMVP_CIPHER amvp_lookup_cipher_w_mode_index(const char *algorithm,
                                            const char *mode);

const char *amvp_lookup_cipher_mode_str(AMVP_CIPHER cipher);

const char *amvp_lookup_cipher_revision(AMVP_CIPHER alg);
const char *amvp_lookup_alt_revision_string(AMVP_REVISION rev);

AMVP_DRBG_MODE amvp_lookup_drbg_mode_index(const char *mode);

AMVP_DRBG_MODE_LIST *amvp_locate_drbg_mode_entry(AMVP_CAPS_LIST *cap, AMVP_DRBG_MODE mode);
AMVP_DRBG_MODE_LIST *amvp_create_drbg_mode_entry(AMVP_CAPS_LIST *cap, AMVP_DRBG_MODE mode);
AMVP_DRBG_CAP_GROUP *amvp_locate_drbg_group_entry(AMVP_DRBG_MODE_LIST *mode, int group);
AMVP_DRBG_CAP_GROUP *amvp_create_drbg_group(AMVP_DRBG_MODE_LIST *mode, int group);

const char *amvp_lookup_rsa_randpq_name(int value);

int amvp_lookup_rsa_randpq_index(const char *value);

AMVP_RESULT amvp_create_array(JSON_Object **obj, JSON_Value **val, JSON_Array **arry);

AMVP_RESULT is_valid_tf_param(int value);

const char *amvp_lookup_rsa_prime_test_name(AMVP_RSA_PRIME_TEST_TYPE type);
AMVP_RESULT is_valid_prime_test(const char *value);

AMVP_RESULT is_valid_rsa_mod(int value);

AMVP_HASH_ALG amvp_lookup_hash_alg(const char *name);
const char *amvp_lookup_hash_alg_name(AMVP_HASH_ALG id);

AMVP_EC_CURVE amvp_lookup_ec_curve(AMVP_CIPHER cipher, const char *name);
const char *amvp_lookup_ec_curve_name(AMVP_CIPHER cipher, AMVP_EC_CURVE id);

AMVP_RESULT amvp_refresh(AMVP_CTX *ctx);

void amvp_http_user_agent_handler(AMVP_CTX *ctx);

AMVP_RESULT amvp_setup_json_ev_group(AMVP_CTX **ctx,
                                      JSON_Value **outer_arr_val,
                                      JSON_Value **r_vs_val,
                                      JSON_Object **r_vs,
                                      JSON_Array **groups_arr);

AMVP_RESULT amvp_setup_json_rsp_group(AMVP_CTX **ctx,
                                      JSON_Value **outer_arr_val,
                                      JSON_Value **r_vs_val,
                                      JSON_Object **r_vs,
                                      const char *alg_str,
                                      JSON_Array **groups_arr);

void amvp_release_json(JSON_Value *r_vs_val,
                       JSON_Value *r_gval);

JSON_Object *amvp_get_obj_from_rsp(AMVP_CTX *ctx, JSON_Value *arry_val);

int string_fits(const char *string, unsigned int max_allowed);

AMVP_RESULT amvp_kv_list_append(AMVP_KV_LIST **kv_list,
                                const char *key,
                                const char *value);

void amvp_kv_list_free(AMVP_KV_LIST *kv_list);

void amvp_free_str_list(AMVP_STRING_LIST **list);
AMVP_RESULT amvp_append_sl_list(AMVP_SL_LIST **list, int length);
AMVP_RESULT amvp_append_param_list(AMVP_PARAM_LIST **list, int param);
AMVP_RESULT amvp_append_name_list(AMVP_NAME_LIST **list, const char *string);
int amvp_is_in_name_list(AMVP_NAME_LIST *list, const char *string);
AMVP_RESULT amvp_append_str_list(AMVP_STRING_LIST **list, const char *string);
int amvp_lookup_str_list(AMVP_STRING_LIST **list, const char *string);
int amvp_lookup_param_list(AMVP_PARAM_LIST *list, int value);
const char* amvp_lookup_aux_function_alg_str(AMVP_CIPHER alg);
AMVP_CIPHER amvp_lookup_aux_function_alg_tbl(const char *str);
int amvp_is_domain_already_set(AMVP_JSON_DOMAIN_OBJ *domain);

/* These functions are used for KDF108, but twostep uses KDF108 so we share them */
AMVP_KDF108_MAC_MODE_VAL read_mac_mode(const char *str);
AMVP_KDF108_FIXED_DATA_ORDER_VAL read_ctr_location(const char *str);
AMVP_KDF108_MODE read_mode(const char *str);

AMVP_RESULT amvp_json_serialize_to_file_pretty_a(const JSON_Value *value, const char *filename);
AMVP_RESULT amvp_json_serialize_to_file_pretty_w(const JSON_Value *value, const char *filename);


#endif
