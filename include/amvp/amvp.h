/**
 * @file
 * @brief This is the public header file to be included by applications
 *        using libamvp.
 */

/*
 * Copyright (c) 2021, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libamvp/LICENSE
 */

#ifndef amvp_h
#define amvp_h

#ifdef __cplusplus
extern "C"
{
#endif

#define AMVP_TOTP_LENGTH 8
#define AMVP_TOTP_TOKEN_MAX 128

#define AMVP_MAX_CONTACTS_PER_CERT_REQ 10
#define AMVP_CONTACT_STR_MAX_LEN 16
#define AMVP_MAX_MODULE_NAME_LEN 128

/**
 * @enum AMVP_LOG_LVL
 * @brief This enum defines the different log levels for
 *        the AMVP client library. Each level also contains
 *        the logging for the level below it.
 *        Error level logging will only create output in case of failures.
 *        Warning level logging will create output for situations where the user may want to intervene,
 *        but are not neccessarily issues and running will continue.
 *        Status level logging is the default and will include high-level information about the progress
 *        of the test session and status of processing.
 *        Info level logging contains more info about network activity, metadata processing, and login.
 *        Verbose level logging is extensive and contains info about test groups and cases being run,
 *        more network activity, and other information. This is excessive for most users.
 */
typedef enum amvp_log_lvl {
    AMVP_LOG_LVL_NONE = 0,
    AMVP_LOG_LVL_ERR,
    AMVP_LOG_LVL_WARN,
    AMVP_LOG_LVL_STATUS,
    AMVP_LOG_LVL_INFO,
    AMVP_LOG_LVL_VERBOSE,
    AMVP_LOG_LVL_DEBUG,
    AMVP_LOG_LVL_MAX
} AMVP_LOG_LVL;

/**
 * @struct AMVP_CTX
 * @brief This opaque structure is used to maintain the state of a session with an AMVP server.
 *        A single instance of this context represents a session with the AMVP server. A session
 *        can consist of a regular test session, or various types of requests (like requesting a
 *        metadata listing.) Largely, This context is used by the application layer to perform the
 *        steps to conduct a test session. These steps are:
 *
 *        1. Create the context
 *        2. Specify the server hostname
 *        3. Specify the crypto algorithms to test
 *        4. Register with the AMVP server
 *        5. Commence the test with the server
 *        6. Check the test results
 *        7. Free the context
 */
typedef struct amvp_ctx_t AMVP_CTX;

/**
 * @enum AMVP_RESULT
 * @brief This enum is used to indicate error conditions to the application
 *        layer. Most libamvp function will return a value from this enum.
 */
typedef enum amvp_result {
    AMVP_SUCCESS = 0,
    AMVP_MALLOC_FAIL,        /**< Error allocating memory */
    AMVP_NO_CTX,             /**< An initalized context was expected but not present */
    AMVP_TRANSPORT_FAIL,     /**< Error exchanging data with server outside the bounds of the protocol */
    AMVP_PROTOCOL_RSP_ERR,   /**< Error exchanging data with server that came with a protocol-formatted response */
    AMVP_NO_DATA,            /**< Required data for operation is missing */
    AMVP_UNSUPPORTED_OP,     /**< An operation has been requested that is not supported. This can
                                  either be because parameters are not valid or because the library
                                  does not support something at the time */
    AMVP_CLEANUP_FAIL,       /**< Failure when cleaning up (e.g. freeing memory) after operations */
    AMVP_KAT_DOWNLOAD_RETRY, /**< Does not neccessarily indicate an error, but that data requested
                                  from server is not yet ready to be accessed */
    AMVP_RETRY_OPERATION,    /**< Indiciate to a caller to attempt to retry an operation */
    AMVP_INVALID_ARG,        /**< A provided argument or parameter is not valid for the given operation */
    AMVP_MISSING_ARG,        /**< A required argument or parameter is not provided/null/0 */
    AMVP_CRYPTO_MODULE_FAIL, /**< A non-zero return code was provided by the application callback 
                                  for test case processin; this should indicate that the application
                                  failed to process the test case*/
    AMVP_NO_CAP,             /**< A registered capability object for the given algorithm does not exist. This
                                  usually means an operation is being requested for an algorithm that is not yet
                                  registered */
    AMVP_MALFORMED_JSON,     /**< The given JSON is not properly formatted/readable JSON */
    AMVP_JSON_ERR,           /**< Error occured attempting to parse JSON into data stuctures */
    AMVP_TC_MISSING_DATA,    /**< Data is missing from test case JSON */
    AMVP_TC_INVALID_DATA,    /**< Test case JSON is formatted properly, but the data is bad, does not
                                  match the registration, or does not match the spec */
    AMVP_DATA_TOO_LARGE,     /**< The given parameter larger than the library allows. This can apply to strings,
                                  server responses, files, etc */
    AMVP_CONVERT_DATA_ERR,   /**< Error converting data between hexidecimal and binary (either direction) */
    AMVP_DUP_CIPHER,         /**< The client is attempting to register an algorithm that has already been registered */
    AMVP_TOTP_FAIL,          /**< A failure occured attempting to generate a TOTP */
    AMVP_CTX_NOT_EMPTY,      /**< Occurs specifically when an attempt is made to initialize a CTX that is already initialized */
    AMVP_JWT_MISSING,        /**< A JSON web token is missing from a file or from memory but was expected */
    AMVP_JWT_EXPIRED,        /**< The provided JWT was not accepted by the server because it is expired */
    AMVP_JWT_INVALID,        /**< A provided JSON web token is invalid due to its size, encoding, or contents */
    AMVP_INTERNAL_ERR,       /**< An unexpected error occuring internally to libamvp */
    AMVP_RESULT_MAX
} AMVP_RESULT;

/**
 * These are the available algorithms that libamvp supports. The application layer will need to
 * register one or more of these based on the capabilities of the crypto module being validated.
 * Libamvp may not support every desired algorithm; the list of all algorithms supported by the
 * protocol itself can be found in the AMVP specification.
 *
 * **************** ALERT *****************
 * This enum must stay aligned with alg_tbl[] in amvp.c
 */
/**
 * @enum AMVP_CIPHER
 * @brief This enum lists the various algorithms supported by the AMVP
 *        library
 */
typedef enum amvp_cipher {
    AMVP_CIPHER_START = 0,
    AMVP_AES_GCM,
    AMVP_AES_GCM_SIV,
    AMVP_AES_CCM,
    AMVP_AES_ECB,
    AMVP_AES_CBC,
    AMVP_AES_CBC_CS1,
    AMVP_AES_CBC_CS2,
    AMVP_AES_CBC_CS3,
    AMVP_AES_CFB1,
    AMVP_AES_CFB8,
    AMVP_AES_CFB128,
    AMVP_AES_OFB,
    AMVP_AES_CTR,
    AMVP_AES_XTS,
    AMVP_AES_KW,
    AMVP_AES_KWP,
    AMVP_AES_GMAC,
    AMVP_AES_XPN,
    AMVP_TDES_ECB,
    AMVP_TDES_CBC,
    AMVP_TDES_CBCI,
    AMVP_TDES_OFB,
    AMVP_TDES_OFBI,
    AMVP_TDES_CFB1,
    AMVP_TDES_CFB8,
    AMVP_TDES_CFB64,
    AMVP_TDES_CFBP1,
    AMVP_TDES_CFBP8,
    AMVP_TDES_CFBP64,
    AMVP_TDES_CTR,
    AMVP_TDES_KW,
    AMVP_HASH_SHA1,
    AMVP_HASH_SHA224,
    AMVP_HASH_SHA256,
    AMVP_HASH_SHA384,
    AMVP_HASH_SHA512,
    AMVP_HASH_SHA512_224,
    AMVP_HASH_SHA512_256,
    AMVP_HASH_SHA3_224,
    AMVP_HASH_SHA3_256,
    AMVP_HASH_SHA3_384,
    AMVP_HASH_SHA3_512,
    AMVP_HASH_SHAKE_128,
    AMVP_HASH_SHAKE_256,
    AMVP_HASHDRBG,
    AMVP_HMACDRBG,
    AMVP_CTRDRBG,
    AMVP_HMAC_SHA1,
    AMVP_HMAC_SHA2_224,
    AMVP_HMAC_SHA2_256,
    AMVP_HMAC_SHA2_384,
    AMVP_HMAC_SHA2_512,
    AMVP_HMAC_SHA2_512_224,
    AMVP_HMAC_SHA2_512_256,
    AMVP_HMAC_SHA3_224,
    AMVP_HMAC_SHA3_256,
    AMVP_HMAC_SHA3_384,
    AMVP_HMAC_SHA3_512,
    AMVP_CMAC_AES,
    AMVP_CMAC_TDES,
    AMVP_KMAC_128,
    AMVP_KMAC_256,
    AMVP_DSA_KEYGEN,
    AMVP_DSA_PQGGEN,
    AMVP_DSA_PQGVER,
    AMVP_DSA_SIGGEN,
    AMVP_DSA_SIGVER,
    AMVP_RSA_KEYGEN,
    AMVP_RSA_SIGGEN,
    AMVP_RSA_SIGVER,
    AMVP_RSA_DECPRIM,
    AMVP_RSA_SIGPRIM,
    AMVP_ECDSA_KEYGEN,
    AMVP_ECDSA_KEYVER,
    AMVP_ECDSA_SIGGEN,
    AMVP_ECDSA_SIGVER,
    AMVP_KDF135_SNMP,
    AMVP_KDF135_SSH,
    AMVP_KDF135_SRTP,
    AMVP_KDF135_IKEV2,
    AMVP_KDF135_IKEV1,
    AMVP_KDF135_X942,
    AMVP_KDF135_X963,
    AMVP_KDF108,
    AMVP_PBKDF,
    AMVP_KDF_TLS12,
    AMVP_KDF_TLS13,
    AMVP_KAS_ECC_CDH,
    AMVP_KAS_ECC_COMP,
    AMVP_KAS_ECC_NOCOMP,
    AMVP_KAS_ECC_SSC,
    AMVP_KAS_FFC_COMP,
    AMVP_KAS_FFC_NOCOMP,
    AMVP_KAS_FFC_SSC,
    AMVP_KAS_IFC_SSC,
    AMVP_KDA_ONESTEP,
    AMVP_KDA_TWOSTEP,
    AMVP_KDA_HKDF,
    AMVP_KTS_IFC,
    AMVP_SAFE_PRIMES_KEYGEN,
    AMVP_SAFE_PRIMES_KEYVER,
    AMVP_CIPHER_END
} AMVP_CIPHER;


/**
 * The following are sub-type algorithms which can be used within
 * algorithm specific code to avoid having to include all the
 * above enums in the case statements.
 *
 * To get the sub-type enum call the algorithm specific functions
 * in amvp.c such as amvp_get_aes_alg(CIPHER).
 *
 * These enums MUST maintain the same values as the CIPHER enum
 * above thus ordering is of the utmost importance.
 */
typedef enum amvp_alg_type_aes {
    AMVP_SUB_AES_GCM = AMVP_AES_GCM,
    AMVP_SUB_AES_GCM_SIV,
    AMVP_SUB_AES_CCM,
    AMVP_SUB_AES_ECB,
    AMVP_SUB_AES_CBC,
    AMVP_SUB_AES_CBC_CS1,
    AMVP_SUB_AES_CBC_CS2,
    AMVP_SUB_AES_CBC_CS3,
    AMVP_SUB_AES_CFB1,
    AMVP_SUB_AES_CFB8,
    AMVP_SUB_AES_CFB128,
    AMVP_SUB_AES_OFB,
    AMVP_SUB_AES_CTR,
    AMVP_SUB_AES_XTS,
    AMVP_SUB_AES_XPN,
    AMVP_SUB_AES_KW,
    AMVP_SUB_AES_KWP,
    AMVP_SUB_AES_GMAC
} AMVP_SUB_AES;

/** @enum AMVP_SUB_TDES */
typedef enum amvp_alg_type_tdes {
    AMVP_SUB_TDES_ECB = AMVP_TDES_ECB,
    AMVP_SUB_TDES_CBC,
    AMVP_SUB_TDES_CBCI,
    AMVP_SUB_TDES_OFB,
    AMVP_SUB_TDES_OFBI,
    AMVP_SUB_TDES_CFB1,
    AMVP_SUB_TDES_CFB8,
    AMVP_SUB_TDES_CFB64,
    AMVP_SUB_TDES_CFBP1,
    AMVP_SUB_TDES_CFBP8,
    AMVP_SUB_TDES_CFBP64,
    AMVP_SUB_TDES_CTR,
    AMVP_SUB_TDES_KW
} AMVP_SUB_TDES;

/** @enum AMVP_SUB_CMAC */
typedef enum amvp_alg_type_cmac {
    AMVP_SUB_CMAC_AES = AMVP_CMAC_AES,
    AMVP_SUB_CMAC_TDES
} AMVP_SUB_CMAC;

/** @enum AMVP_SUB_KMAC */
typedef enum amvp_alg_type_kmac {
    AMVP_SUB_KMAC_128 = AMVP_KMAC_128,
    AMVP_SUB_KMAC_256
} AMVP_SUB_KMAC;

/** @enum AMVP_SUB_HMAC */
typedef enum amvp_alg_type_hmac {
    AMVP_SUB_HMAC_SHA1 = AMVP_HMAC_SHA1,
    AMVP_SUB_HMAC_SHA2_224,
    AMVP_SUB_HMAC_SHA2_256,
    AMVP_SUB_HMAC_SHA2_384,
    AMVP_SUB_HMAC_SHA2_512,
    AMVP_SUB_HMAC_SHA2_512_224,
    AMVP_SUB_HMAC_SHA2_512_256,
    AMVP_SUB_HMAC_SHA3_224,
    AMVP_SUB_HMAC_SHA3_256,
    AMVP_SUB_HMAC_SHA3_384,
    AMVP_SUB_HMAC_SHA3_512
} AMVP_SUB_HMAC;

/** @enum AMVP_SUB_HASH */
typedef enum amvp_alg_type_hash {
    AMVP_SUB_HASH_SHA1 = AMVP_HASH_SHA1,
    AMVP_SUB_HASH_SHA2_224,
    AMVP_SUB_HASH_SHA2_256,
    AMVP_SUB_HASH_SHA2_384,
    AMVP_SUB_HASH_SHA2_512,
    AMVP_SUB_HASH_SHA2_512_224,
    AMVP_SUB_HASH_SHA2_512_256,
    AMVP_SUB_HASH_SHA3_224,
    AMVP_SUB_HASH_SHA3_256,
    AMVP_SUB_HASH_SHA3_384,
    AMVP_SUB_HASH_SHA3_512,
    AMVP_SUB_HASH_SHAKE_128,
    AMVP_SUB_HASH_SHAKE_256
} AMVP_SUB_HASH;

/** @enum AMVP_SUB_DSA */
typedef enum amvp_alg_type_dsa {
    AMVP_SUB_DSA_KEYGEN = AMVP_DSA_KEYGEN,
    AMVP_SUB_DSA_PQGGEN,
    AMVP_SUB_DSA_PQGVER,
    AMVP_SUB_DSA_SIGGEN,
    AMVP_SUB_DSA_SIGVER,
} AMVP_SUB_DSA;

/** @enum AMVP_SUB_RSA */
typedef enum amvp_alg_type_rsa {
    AMVP_SUB_RSA_KEYGEN = AMVP_RSA_KEYGEN,
    AMVP_SUB_RSA_SIGGEN,
    AMVP_SUB_RSA_SIGVER,
    AMVP_SUB_RSA_DECPRIM,
    AMVP_SUB_RSA_SIGPRIM
} AMVP_SUB_RSA;

/** @enum AMVP_SUB_ECDSA */
typedef enum amvp_alg_type_ecdsa {
    AMVP_SUB_ECDSA_KEYGEN = AMVP_ECDSA_KEYGEN,
    AMVP_SUB_ECDSA_KEYVER,
    AMVP_SUB_ECDSA_SIGGEN,
    AMVP_SUB_ECDSA_SIGVER
} AMVP_SUB_ECDSA;

/** @enum AMVP_SUB_DRBG */
typedef enum amvp_alg_type_drbg {
    AMVP_SUB_DRBG_HASH = AMVP_HASHDRBG,
    AMVP_SUB_DRBG_HMAC,
    AMVP_SUB_DRBG_CTR
} AMVP_SUB_DRBG;

/** @enum AMVP_SUB_KAS */
typedef enum amvp_alg_type_kas {
    AMVP_SUB_KAS_ECC_CDH = AMVP_KAS_ECC_CDH,
    AMVP_SUB_KAS_ECC_COMP,
    AMVP_SUB_KAS_ECC_NOCOMP,
    AMVP_SUB_KAS_ECC_SSC,
    AMVP_SUB_KAS_FFC_COMP,
    AMVP_SUB_KAS_FFC_SSC,
    AMVP_SUB_KAS_FFC_NOCOMP,
    AMVP_SUB_KAS_IFC_SSC,
    AMVP_SUB_KTS_IFC,
    AMVP_SUB_KDA_ONESTEP,
    AMVP_SUB_KDA_TWOSTEP,
    AMVP_SUB_KDA_HKDF,
    AMVP_SUB_SAFE_PRIMES_KEYGEN,
    AMVP_SUB_SAFE_PRIMES_KEYVER
} AMVP_SUB_KAS;

/** @enum AMVP_SUB_KDF */
typedef enum amvp_alg_type_kdf {
    AMVP_SUB_KDF_SNMP = AMVP_KDF135_SNMP,
    AMVP_SUB_KDF_SSH,
    AMVP_SUB_KDF_SRTP,
    AMVP_SUB_KDF_IKEV2,
    AMVP_SUB_KDF_IKEV1,
    AMVP_SUB_KDF_X942,
    AMVP_SUB_KDF_X963,
    AMVP_SUB_KDF_108,
    AMVP_SUB_KDF_PBKDF,
    AMVP_SUB_KDF_TLS12,
    AMVP_SUB_KDF_TLS13
} AMVP_SUB_KDF;


#define CIPHER_TO_ALG(alg2) (alg_tbl[cipher].alg.alg2)

/**
 * @enum AMVP_PREREQ_ALG
 * @brief This enum lists the prerequisities that are available
 *        to the library during registration. Whereas an AMVP_CIPHER may
 *        specify a certain mode or key size, the prereqs are more
 *        generic.
 */
typedef enum amvp_prereq_mode_t {
    AMVP_PREREQ_AES = 1,
    AMVP_PREREQ_CCM,
    AMVP_PREREQ_CMAC,
    AMVP_PREREQ_DRBG,
    AMVP_PREREQ_DSA,
    AMVP_PREREQ_ECDSA,
    AMVP_PREREQ_HMAC,
    AMVP_PREREQ_KAS,
    AMVP_PREREQ_RSA,
    AMVP_PREREQ_RSADP,
    AMVP_PREREQ_SAFE_PRIMES,
    AMVP_PREREQ_SHA,
    AMVP_PREREQ_TDES,
    AMVP_PREREQ_KMAC
} AMVP_PREREQ_ALG;

/**
 * @enum AMVP_CONFORMANCE
 * @brief this enum lists different conformances that can be claimed in libamvp. These are largely
 *        algorithm specific.
 */
typedef enum amvp_conformance_t {
    AMVP_CONFORMANCE_DEFAULT = 0,
    AMVP_CONFORMANCE_RFC3686,
    AMVP_CONFORMANCE_MAX
} AMVP_CONFORMANCE;

/**
 * @enum AMVP_REVISION
 * @brief this enum lists revisions that may be claimed for ciphers alternative to the default ones
 *        used by libamvp. This may grow over time. Because one revision may apply to multiple
 *        algorithms, this list is universal and the library determines which ones revisions are
 *        allowed for which algorihms.
 */
typedef enum amvp_revision_t {
    AMVP_REVISION_DEFAULT = 0,
    AMVP_REVISION_SP800_56CR1,
    AMVP_REVISION_SP800_56AR3,
    AMVP_REVISION_MAX
} AMVP_REVISION;

/**
 * @enum AMVP_HASH_ALG
 * @brief Represents the general hash algorithms. Can be used as bit flags.
 */
typedef enum amvp_hash_alg {
    AMVP_NO_SHA = 0,
    AMVP_SHA1 = 1,
    AMVP_SHA224 = 2,
    AMVP_SHA256 = 4,
    AMVP_SHA384 = 8,
    AMVP_SHA512 = 16,
    AMVP_SHA512_224 = 32,
    AMVP_SHA512_256 = 64,
    AMVP_SHA3_224 = 128,
    AMVP_SHA3_256 = 256,
    AMVP_SHA3_384 = 512,
    AMVP_SHA3_512 = 1024,
    AMVP_HASH_ALG_MAX = 2048
} AMVP_HASH_ALG;

/**
 * @enum AMVP_TEST_DISPOSITION
 * @brief These values are used to indicate the pass/fail status of a test session
 */
typedef enum amvp_test_disposition {
    AMVP_TEST_DISPOSITION_FAIL = 0,
    AMVP_TEST_DISPOSITION_PASS = 1
} AMVP_TEST_DISPOSITION;

/**
 * The following enumerators are used to track the capabiltiies that the application
 * registers with the library and are used in data fields for some test cases.
 */

/** @enum AMVP_KDF135_SSH_METHOD */
typedef enum amvp_kdf135_ssh_method {
    AMVP_SSH_METH_TDES_CBC = 1,
    AMVP_SSH_METH_AES_128_CBC,
    AMVP_SSH_METH_AES_192_CBC,
    AMVP_SSH_METH_AES_256_CBC,
    AMVP_SSH_METH_MAX
} AMVP_KDF135_SSH_METHOD;

/** @enum AMVP_KDF135_IKEV1_AUTH_METHOD */
typedef enum amvp_kdf135_ikev1_auth_method {
    AMVP_KDF135_IKEV1_AMETH_DSA = 1,
    AMVP_KDF135_IKEV1_AMETH_PSK,
    AMVP_KDF135_IKEV1_AMETH_PKE,
    AMVP_KDF135_IKEV1_AMETH_MAX
} AMVP_KDF135_IKEV1_AUTH_METHOD;

/** @enum AMVP_KDF135_SRTP_PARAM */
typedef enum amvp_kdf135_srtp_param {
    AMVP_SRTP_AES_KEYLEN = 1,
    AMVP_SRTP_SUPPORT_ZERO_KDR,
    AMVP_SRTP_KDF_EXPONENT
} AMVP_KDF135_SRTP_PARAM;

#define AMVP_KDF108_KEYOUT_MAX 64     /**< SHA2-512 */
#define AMVP_KDF108_FIXED_DATA_MAX 64 /**< SHA2-512 */

/** @enum AMVP_KDF108_MODE */
typedef enum amvp_kdf108_mode {
    AMVP_KDF108_MODE_COUNTER = 1,
    AMVP_KDF108_MODE_FEEDBACK,
    AMVP_KDF108_MODE_DPI
} AMVP_KDF108_MODE;

/** @enum AMVP_KDF108_MAC_MODE_VAL */
typedef enum amvp_kdf108_mac_mode_val {
    AMVP_KDF108_MAC_MODE_MIN,
    AMVP_KDF108_MAC_MODE_CMAC_AES128,
    AMVP_KDF108_MAC_MODE_CMAC_AES192,
    AMVP_KDF108_MAC_MODE_CMAC_AES256,
    AMVP_KDF108_MAC_MODE_CMAC_TDES,
    AMVP_KDF108_MAC_MODE_HMAC_SHA1,
    AMVP_KDF108_MAC_MODE_HMAC_SHA224,
    AMVP_KDF108_MAC_MODE_HMAC_SHA256,
    AMVP_KDF108_MAC_MODE_HMAC_SHA384,
    AMVP_KDF108_MAC_MODE_HMAC_SHA512,
    AMVP_KDF108_MAC_MODE_HMAC_SHA512_224,
    AMVP_KDF108_MAC_MODE_HMAC_SHA512_256,
    AMVP_KDF108_MAC_MODE_HMAC_SHA3_224,
    AMVP_KDF108_MAC_MODE_HMAC_SHA3_256,
    AMVP_KDF108_MAC_MODE_HMAC_SHA3_384,
    AMVP_KDF108_MAC_MODE_HMAC_SHA3_512,
    AMVP_KDF108_MAC_MODE_MAX
} AMVP_KDF108_MAC_MODE_VAL;

/** @enum AMVP_KDF108_FIXED_DATA_ORDER_VAL */
typedef enum amvp_kdf108_fixed_data_order_val {
    AMVP_KDF108_FIXED_DATA_ORDER_MIN,
    AMVP_KDF108_FIXED_DATA_ORDER_NONE,
    AMVP_KDF108_FIXED_DATA_ORDER_AFTER,
    AMVP_KDF108_FIXED_DATA_ORDER_BEFORE,
    AMVP_KDF108_FIXED_DATA_ORDER_MIDDLE,
    AMVP_KDF108_FIXED_DATA_ORDER_BEFORE_ITERATOR,
    AMVP_KDF108_FIXED_DATA_ORDER_MAX
} AMVP_KDF108_FIXED_DATA_ORDER_VAL;

/** @enum AMVP_SYM_CIPH_KO */
typedef enum amvp_sym_cipher_keying_option {
    AMVP_SYM_CIPH_KO_NA = 1,
    AMVP_SYM_CIPH_KO_ONE,
    AMVP_SYM_CIPH_KO_THREE, /**< This is outdated and will eventually be removed */
    AMVP_SYM_CIPH_KO_TWO,
    AMVP_SYM_CIPH_KO_BOTH,
    AMVP_SYM_CIPH_KO_MAX
} AMVP_SYM_CIPH_KO;

/**
 * @enum AMVP_SYM_CIPH_IVGEN_SRC
 * @brief The IV generation source for AEAD ciphers. This can be internal, external, or not applicable.
 */
typedef enum amvp_sym_cipher_ivgen_source {
    AMVP_SYM_CIPH_IVGEN_SRC_INT = 1,
    AMVP_SYM_CIPH_IVGEN_SRC_EXT,
    AMVP_SYM_CIPH_IVGEN_SRC_EITHER,
    AMVP_SYM_CIPH_IVGEN_SRC_NA,
    AMVP_SYM_CIPH_IVGEN_SRC_MAX
} AMVP_SYM_CIPH_IVGEN_SRC;


/**
 * @enum AMVP_SYM_CIPH_SALT_SRC
 * @brief The IV generation source for AES_XPN. This can be internal, external, or not applicable.
 */
typedef enum amvp_sym_cipher_salt_source {
    AMVP_SYM_CIPH_SALT_SRC_INT = 1,
    AMVP_SYM_CIPH_SALT_SRC_EXT,
    AMVP_SYM_CIPH_SALT_SRC_NA,
    AMVP_SYM_CIPH_SALT_SRC_MAX
} AMVP_SYM_CIPH_SALT_SRC;

/**
 * @enum AMVP_SYM_CIPH_IVGEN_MODE
 * @brief The IV generation mode. It can comply with 8.2.1, 8.2.2, or may not be applicable for some ciphers.
 */
typedef enum amvp_sym_cipher_ivgen_mode {
    AMVP_SYM_CIPH_IVGEN_MODE_821 = 1,
    AMVP_SYM_CIPH_IVGEN_MODE_822,
    AMVP_SYM_CIPH_IVGEN_MODE_NA,
    AMVP_SYM_CIPH_IVGEN_MODE_MAX
} AMVP_SYM_CIPH_IVGEN_MODE;


/**
 * @enum AMVP_SYM_CIPH_DIR
 * @brief These are the algorithm direction suppported by libamvp. These are used in conjunction
 *        with AMVP_SYM_CIPH when registering the crypto module capabilities with libamvp.
 */
typedef enum amvp_sym_cipher_direction {
    AMVP_SYM_CIPH_DIR_ENCRYPT = 1,
    AMVP_SYM_CIPH_DIR_DECRYPT,
    AMVP_SYM_CIPH_DIR_BOTH,
    AMVP_SYM_CIPH_DIR_MAX
} AMVP_SYM_CIPH_DIR;

/** @enum AMVP_KDF135_SNMP_PARAM */
typedef enum amvp_kdf135_snmp_param {
    AMVP_KDF135_SNMP_PASS_LEN,
    AMVP_KDF135_SNMP_ENGID
} AMVP_KDF135_SNMP_PARAM;

#define AMVP_STR_SHA_1          "SHA-1"
#define AMVP_STR_SHA2_224       "SHA2-224"
#define AMVP_STR_SHA2_256       "SHA2-256"
#define AMVP_STR_SHA2_384       "SHA2-384"
#define AMVP_STR_SHA2_512       "SHA2-512"
#define AMVP_STR_SHA2_512_224   "SHA2-512/224"
#define AMVP_STR_SHA2_512_256   "SHA2-512/256"
#define AMVP_STR_SHA3_224       "SHA3-224"
#define AMVP_STR_SHA3_256       "SHA3-256"
#define AMVP_STR_SHA3_384       "SHA3-384"
#define AMVP_STR_SHA3_512       "SHA3-512"
#define AMVP_STR_SHA_MAX        12

/** @enum AMVP_HASH_PARM */
typedef enum amvp_hash_param {
    AMVP_HASH_IN_BIT = 1,
    AMVP_HASH_IN_EMPTY,
    AMVP_HASH_OUT_BIT, /**< Used for AMVP_HASH_SHAKE_128, AMVP_HASH_SHAKE_256 */
    AMVP_HASH_OUT_LENGTH, /**< Used for AMVP_HASH_SHAKE_128, AMVP_HASH_SHAKE_256 */
    AMVP_HASH_MESSAGE_LEN
} AMVP_HASH_PARM;

/**
 * ****************** ALERT *****************
 * This enum must stay aligned with drbg_mode_tbl[] in amvp_util.c
 */
/** @enum AMVP_DRBG_MODE */
typedef enum amvp_drbg_mode {
    AMVP_DRBG_SHA_1 = 1,
    AMVP_DRBG_SHA_224,
    AMVP_DRBG_SHA_256,
    AMVP_DRBG_SHA_384,
    AMVP_DRBG_SHA_512,
    AMVP_DRBG_SHA_512_224,
    AMVP_DRBG_SHA_512_256,
    AMVP_DRBG_TDES,
    AMVP_DRBG_AES_128,
    AMVP_DRBG_AES_192,
    AMVP_DRBG_AES_256
} AMVP_DRBG_MODE;

/** @enum AMVP_DRBG_PARM */
typedef enum amvp_drbg_param {
    AMVP_DRBG_DER_FUNC_ENABLED = 0,
    AMVP_DRBG_PRED_RESIST_ENABLED,
    AMVP_DRBG_RESEED_ENABLED,
    AMVP_DRBG_ENTROPY_LEN,
    AMVP_DRBG_NONCE_LEN,
    AMVP_DRBG_PERSO_LEN,
    AMVP_DRBG_ADD_IN_LEN,
    AMVP_DRBG_RET_BITS_LEN,
    AMVP_DRBG_PRE_REQ_VALS
} AMVP_DRBG_PARM;

/** @enum AMVP_RSA_PARM */
typedef enum amvp_rsa_param {
    AMVP_RSA_PARM_PUB_EXP_MODE = 1,
    AMVP_RSA_PARM_FIXED_PUB_EXP_VAL,
    AMVP_RSA_PARM_KEY_FORMAT_CRT,
    AMVP_RSA_PARM_RAND_PQ,
    AMVP_RSA_PARM_INFO_GEN_BY_SERVER,
} AMVP_RSA_PARM;

/** @enum AMVP_RSA_PRIME_PARAM */
typedef enum amvp_rsa_prime_param {
    AMVP_RSA_PRIME_HASH_ALG = 1,
    AMVP_RSA_PRIME_TEST,
} AMVP_RSA_PRIME_PARAM;

/** @enum AMVP_ECDSA_PARM */
typedef enum amvp_ecdsa_param {
    AMVP_ECDSA_CURVE,
    AMVP_ECDSA_SECRET_GEN,
    AMVP_ECDSA_HASH_ALG,
    AMVP_ECDSA_COMPONENT_TEST
} AMVP_ECDSA_PARM;

/** @enum AMVP_ECDSA_SECRET_GEN_MODE */
typedef enum amvp_ecdsa_secret_gen_mode {
    AMVP_ECDSA_SECRET_GEN_EXTRA_BITS = 1,
    AMVP_ECDSA_SECRET_GEN_TEST_CAND
} AMVP_ECDSA_SECRET_GEN_MODE;

/** @enum AMVP_EC_CURVE */
typedef enum amvp_ec_curve {
    AMVP_EC_CURVE_START = 0,
    AMVP_EC_CURVE_P192,
    AMVP_EC_CURVE_P224,
    AMVP_EC_CURVE_P256,
    AMVP_EC_CURVE_P384,
    AMVP_EC_CURVE_P521,
    AMVP_EC_CURVE_B163,
    AMVP_EC_CURVE_B233,
    AMVP_EC_CURVE_B283,
    AMVP_EC_CURVE_B409,
    AMVP_EC_CURVE_B571,
    AMVP_EC_CURVE_K163,
    AMVP_EC_CURVE_K233,
    AMVP_EC_CURVE_K283,
    AMVP_EC_CURVE_K409,
    AMVP_EC_CURVE_K571,
    AMVP_EC_CURVE_END
} AMVP_EC_CURVE;

/** @enum AMVP_ECDSA_COMPONENT_MODE */
typedef enum amvp_ecdsa_component_mode {
    AMVP_ECDSA_COMPONENT_MODE_NO,
    AMVP_ECDSA_COMPONENT_MODE_YES,
    AMVP_ECDSA_COMPONENT_MODE_BOTH
} AMVP_ECDSA_COMPONENT_MODE;

/** @enum AMVP_KDF135_IKEV2_PARM */
typedef enum amvp_kdf135_ikev2_param {
    AMVP_KDF_HASH_ALG,
    AMVP_INIT_NONCE_LEN,
    AMVP_RESPOND_NONCE_LEN,
    AMVP_DH_SECRET_LEN,
    AMVP_KEY_MATERIAL_LEN
} AMVP_KDF135_IKEV2_PARM;

/** @enum AMVP_KDF135_IKEV1_PARM */
typedef enum amvp_kdf135_ikev1_param {
    AMVP_KDF_IKEv1_HASH_ALG,
    AMVP_KDF_IKEv1_AUTH_METHOD,
    AMVP_KDF_IKEv1_INIT_NONCE_LEN,
    AMVP_KDF_IKEv1_RESPOND_NONCE_LEN,
    AMVP_KDF_IKEv1_DH_SECRET_LEN,
    AMVP_KDF_IKEv1_PSK_LEN
} AMVP_KDF135_IKEV1_PARM;

/** @enum AMVP_KDF135_X942_TYPE */
typedef enum amvp_kdf_x942_type {
    AMVP_KDF_X942_KDF_TYPE_DER,
    AMVP_KDF_X942_KDF_TYPE_CONCAT,
    AMVP_KDF_X942_KDF_TYPE_BOTH
} AMVP_KDF_X942_TYPE;

/** @enum AMVP_KDF135_X942_OID */
typedef enum amvp_kdf135_x942_oid {
    AMVP_KDF_X942_OID_TDES,
    AMVP_KDF_X942_OID_AES128KW,
    AMVP_KDF_X942_OID_AES192KW,
    AMVP_KDF_X942_OID_AES256KW
} AMVP_KDF135_X942_OID;

/** @enum AMVP_KDF135_X942_PARM */
typedef enum amvp_kdf135_x942_param {
    AMVP_KDF_X942_KDF_TYPE,
    AMVP_KDF_X942_KEY_LEN,
    AMVP_KDF_X942_OTHER_INFO_LEN,
    AMVP_KDF_X942_SUPP_INFO_LEN,
    AMVP_KDF_X942_ZZ_LEN,
    AMVP_KDF_X942_OID,
    AMVP_KDF_X942_HASH_ALG
} AMVP_KDF135_X942_PARM;


/** @enum AMVP_KDF135_X963_PARM */
typedef enum amvp_kdf135_x963_param {
    AMVP_KDF_X963_HASH_ALG,
    AMVP_KDF_X963_KEY_DATA_LEN,
    AMVP_KDF_X963_FIELD_SIZE,
    AMVP_KDF_X963_SHARED_INFO_LEN
} AMVP_KDF135_X963_PARM;

/** @enum AMVP_KDF108_PARM */
typedef enum amvp_kdf108_param {
    AMVP_KDF108_PARAM_MIN,
    AMVP_KDF108_KDF_MODE,
    AMVP_KDF108_MAC_MODE,
    AMVP_KDF108_SUPPORTED_LEN,
    AMVP_KDF108_FIXED_DATA_ORDER,
    AMVP_KDF108_COUNTER_LEN,
    AMVP_KDF108_SUPPORTS_EMPTY_IV,
    AMVP_KDF108_REQUIRES_EMPTY_IV,
    AMVP_KDF108_PARAM_MAX
} AMVP_KDF108_PARM;

/** @enum AMVP_PBKDF_PARM */
typedef enum amvp_pbkdf_param {
    AMVP_PBKDF_PARAM_MIN,
    AMVP_PBKDF_ITERATION_COUNT,
    AMVP_PBKDF_KEY_LEN,
    AMVP_PBKDF_PASSWORD_LEN,
    AMVP_PBKDF_SALT_LEN,
    AMVP_PBKDF_HMAC_ALG
} AMVP_PBKDF_PARM;

/** @enum AMVP_KDF_TLS12_PARM */
typedef enum amvp_kdf_tls12_param {
    AMVP_KDF_TLS12_PARAM_MIN,
    AMVP_KDF_TLS12_HASH_ALG /**< HMAC algorithms supported by TLS 1.2 imeplementation */
} AMVP_KDF_TLS12_PARM;

/** @enum AMVP_KDF_TLS13_RUN_MODE */
typedef enum amvp_kdf_tls13_running_mode {
    AMVP_KDF_TLS13_RUN_MODE_MIN,
    AMVP_KDF_TLS13_RUN_MODE_PSK,
    AMVP_KDF_TLS13_RUN_MODE_DHE,
    AMVP_KDF_TLS13_RUN_MODE_PSK_DHE,
    AMVP_KDF_TLS13_RUN_MODE_MAX
} AMVP_KDF_TLS13_RUN_MODE;

/** @enum AMVP_KDF_TLS13_PARM */
typedef enum amvp_kdf_tls13_param {
    AMVP_KDF_TLS13_PARAM_MIN,
    AMVP_KDF_TLS13_HMAC_ALG,
    AMVP_KDF_TLS13_RUNNING_MODE
} AMVP_KDF_TLS13_PARM;

/** @enum AMVP_RSA_KEY_FORMAT */
typedef enum amvp_rsa_key_format {
    AMVP_RSA_KEY_FORMAT_STANDARD = 1, /**< Standard */
    AMVP_RSA_KEY_FORMAT_CRT           /**< Chinese Remainder Theorem */
} AMVP_RSA_KEY_FORMAT;

/** @enum AMVP_RSA_PUB_EXP_MODE */
typedef enum amvp_rsa_pub_exp_mode {
    AMVP_RSA_PUB_EXP_MODE_FIXED = 1,
    AMVP_RSA_PUB_EXP_MODE_RANDOM
} AMVP_RSA_PUB_EXP_MODE;

/** @enum AMVP_RSA_PRIME_TEST_TYPE */
typedef enum amvp_rsa_prime_test_type {
    AMVP_RSA_PRIME_TEST_TBLC2 = 1,
    AMVP_RSA_PRIME_TEST_TBLC3
} AMVP_RSA_PRIME_TEST_TYPE;

/** @enum AMVP_RSA_KEYGEN_MODE */
typedef enum amvp_rsa_keygen_mode_t {
    AMVP_RSA_KEYGEN_B32 = 1,
    AMVP_RSA_KEYGEN_B33,
    AMVP_RSA_KEYGEN_B34,
    AMVP_RSA_KEYGEN_B35,
    AMVP_RSA_KEYGEN_B36
} AMVP_RSA_KEYGEN_MODE;

/** @enum AMVP_RSA_SIG_TYPE */
typedef enum amvp_rsa_sig_type {
    AMVP_RSA_SIG_TYPE_X931 = 1,
    AMVP_RSA_SIG_TYPE_PKCS1V15,
    AMVP_RSA_SIG_TYPE_PKCS1PSS
} AMVP_RSA_SIG_TYPE;

/** @enum AMVP_RSA_PRIM_KEYFORMAT */
typedef enum amvp_rsa_prim_keyformat {
    AMVP_RSA_PRIM_KEYFORMAT_STANDARD = 1,
    AMVP_RSA_PRIM_KEYFORMAT_CRT
} AMVP_RSA_PRIM_KEYFORMAT;

/** @enum AMVP_SYM_CIPH_PARM */
typedef enum amvp_sym_cipher_parameter {
    AMVP_SYM_CIPH_KEYLEN = 1,
    AMVP_SYM_CIPH_TAGLEN,
    AMVP_SYM_CIPH_IVLEN,
    AMVP_SYM_CIPH_PTLEN,
    AMVP_SYM_CIPH_TWEAK,
    AMVP_SYM_CIPH_AADLEN,
    AMVP_SYM_CIPH_KW_MODE,
    AMVP_SYM_CIPH_PARM_DIR,
    AMVP_SYM_CIPH_PARM_KO,
    AMVP_SYM_CIPH_PARM_PERFORM_CTR,
    AMVP_SYM_CIPH_PARM_CTR_INCR,
    AMVP_SYM_CIPH_PARM_CTR_OVRFLW,
    AMVP_SYM_CIPH_PARM_IVGEN_MODE,
    AMVP_SYM_CIPH_PARM_IVGEN_SRC,
    AMVP_SYM_CIPH_PARM_SALT_SRC,
    AMVP_SYM_CIPH_PARM_CONFORMANCE,
    AMVP_SYM_CIPH_PARM_DULEN_MATCHES_PAYLOADLEN
} AMVP_SYM_CIPH_PARM;


/** @enum AMVP_SYM_CIPH_DOMAIN_PARM */
typedef enum amvp_sym_cipher_domain_parameter {
    AMVP_SYM_CIPH_DOMAIN_IVLEN = 1,
    AMVP_SYM_CIPH_DOMAIN_PTLEN,
    AMVP_SYM_CIPH_DOMAIN_AADLEN,
    AMVP_SYM_CIPH_DOMAIN_DULEN
} AMVP_SYM_CIPH_DOMAIN_PARM;

/** @enum AMVP_SYM_CIPH_TWEAK_MODE */
typedef enum amvp_sym_xts_tweak_mode {
    AMVP_SYM_CIPH_TWEAK_HEX = 1,
    AMVP_SYM_CIPH_TWEAK_NUM,
    AMVP_SYM_CIPH_TWEAK_NONE
} AMVP_SYM_CIPH_TWEAK_MODE;

/** @enum AMVP_SYM_KW_MODE */
typedef enum amvp_sym_kw_mode {
    AMVP_SYM_KW_NONE = 0,
    AMVP_SYM_KW_CIPHER,
    AMVP_SYM_KW_INVERSE,
    AMVP_SYM_KW_MAX
} AMVP_SYM_KW_MODE;

/** @enum AMVP_HMAC_PARM */
typedef enum amvp_hmac_parameter {
    AMVP_HMAC_KEYLEN = 1,
    AMVP_HMAC_KEYBLOCK,
    AMVP_HMAC_MACLEN
} AMVP_HMAC_PARM;

/** @enum AMVP_CMAC_PARM */
typedef enum amvp_cmac_parameter {
    AMVP_CMAC_MACLEN,
    AMVP_CMAC_MSGLEN,
    AMVP_CMAC_KEYLEN,
    AMVP_CMAC_KEYING_OPTION,
    AMVP_CMAC_DIRECTION_GEN,
    AMVP_CMAC_DIRECTION_VER
} AMVP_CMAC_PARM;

/** @enum AMVP_KMAC_PARM */
typedef enum amvp_kmac_parameter {
    AMVP_KMAC_MACLEN,
    AMVP_KMAC_MSGLEN,
    AMVP_KMAC_KEYLEN,
    AMVP_KMAC_XOF_SUPPORT,
    AMVP_KMAC_HEX_CUSTOM_SUPPORT
} AMVP_KMAC_PARM;

/** @enum AMVP_CMAC_KEY_ATTR */
typedef enum amvp_cmac_keylen {
    AMVP_CMAC_KEYING_OPTION_1 = 1,
    AMVP_CMAC_KEYING_OPTION_2 = 2,
    AMVP_CMAC_KEYLEN_128 = 128,
    AMVP_CMAC_KEYLEN_192 = 192,
    AMVP_CMAC_KEYLEN_256 = 256
} AMVP_CMAC_KEY_ATTR;

/** @enum AMVP_CMAC_TDES_KEYING_OPTION */
typedef enum amvp_cmac_tdes_keying_option {
    AMVP_CMAC_TDES_KEYING_OPTION_MIN = 0,
    AMVP_CMAC_TDES_KEYING_OPTION_1,
    AMVP_CMAC_TDES_KEYING_OPTION_2,
    AMVP_CMAC_TDES_KEYING_OPTION_MAX
} AMVP_CMAC_TDES_KEYING_OPTION;

/** @enum AMVP_CMAC_MSG_LEN_INDEX */
typedef enum amvp_cmac_msg_len_index {
    CMAC_BLK_DIVISIBLE_1 = 0,
    CMAC_BLK_DIVISIBLE_2,
    CMAC_BLK_NOT_DIVISIBLE_1,
    CMAC_BLK_NOT_DIVISIBLE_2,
    CMAC_MSG_LEN_MAX,
    CMAC_MSG_LEN_NUM_ITEMS
} AMVP_CMAC_MSG_LEN_INDEX;

/** @enum AMVP_XOF_SUPPORT_OPTION */
typedef enum amvp_xof_support_option {
    AMVP_XOF_SUPPORT_FALSE = 0,
    AMVP_XOF_SUPPORT_TRUE,
    AMVP_XOF_SUPPORT_BOTH
} AMVP_XOF_SUPPORT_OPTION;

/** @enum AMVP_DSA_MODE */
typedef enum amvp_dsa_mode {
    AMVP_DSA_MODE_KEYGEN = 1,
    AMVP_DSA_MODE_PQGGEN,
    AMVP_DSA_MODE_PQGVER,
    AMVP_DSA_MODE_SIGGEN,
    AMVP_DSA_MODE_SIGVER
} AMVP_DSA_MODE;

/** @enum AMVP_DSA_PARM */
typedef enum amvp_dsa_parm {
    AMVP_DSA_LN1024_160 = 1,
    AMVP_DSA_LN2048_224,
    AMVP_DSA_LN2048_256,
    AMVP_DSA_LN3072_256,
    AMVP_DSA_GENPQ,
    AMVP_DSA_GENG
} AMVP_DSA_PARM;

/** @enum AMVP_DSA_GEN_PARM */
typedef enum amvp_dsa_gen_parm {
    AMVP_DSA_PROVABLE = 1,
    AMVP_DSA_PROBABLE,
    AMVP_DSA_CANONICAL,
    AMVP_DSA_UNVERIFIABLE
} AMVP_DSA_GEN_PARM;

/** @enum AMVP_KAS_ECC_MODE */
typedef enum amvp_kas_ecc_mode {
    AMVP_KAS_ECC_MODE_COMPONENT = 1,
    AMVP_KAS_ECC_MODE_CDH,
    AMVP_KAS_ECC_MODE_NOCOMP,
    AMVP_KAS_ECC_MODE_NONE,
    AMVP_KAS_ECC_MAX_MODES
} AMVP_KAS_ECC_MODE;

/** @enum AMVP_KAS_ECC_FUNC */
typedef enum amvp_kas_ecc_func {
    AMVP_KAS_ECC_FUNC_PARTIAL = 1,
    AMVP_KAS_ECC_FUNC_DPGEN,
    AMVP_KAS_ECC_FUNC_DPVAL,
    AMVP_KAS_ECC_FUNC_KEYPAIR,
    AMVP_KAS_ECC_FUNC_KEYREGEN,
    AMVP_KAS_ECC_FUNC_FULL,
    AMVP_KAS_ECC_MAX_FUNCS
} AMVP_KAS_ECC_FUNC;

/** @enum AMVP_KAS_ECC_PARAM */
typedef enum amvp_kas_ecc_param {
    AMVP_KAS_ECC_FUNCTION = 1,
    AMVP_KAS_ECC_REVISION,
    AMVP_KAS_ECC_CURVE,
    AMVP_KAS_ECC_ROLE,
    AMVP_KAS_ECC_KDF,
    AMVP_KAS_ECC_EB,
    AMVP_KAS_ECC_EC,
    AMVP_KAS_ECC_ED,
    AMVP_KAS_ECC_EE,
    AMVP_KAS_ECC_HASH,
    AMVP_KAS_ECC_NONE
} AMVP_KAS_ECC_PARAM;

/** @enum AMVP_KAS_ECC_ROLES */
typedef enum amvp_kas_ecc_roles {
    AMVP_KAS_ECC_ROLE_INITIATOR = 1,
    AMVP_KAS_ECC_ROLE_RESPONDER
} AMVP_KAS_ECC_ROLES;

/** @enum AMVP_KAS_ECC_SET */
typedef enum amvp_kas_ecc_set {
    AMVP_KAS_ECC_NOKDFNOKC = 1,
    AMVP_KAS_ECC_KDFNOKC,
    AMVP_KAS_ECC_KDFKC,
    AMVP_KAS_ECC_PARMSET
} AMVP_KAS_ECC_SET;

/** @enum AMVP_KAS_ECC_SCHEMES */
typedef enum amvp_kas_ecc_schemes {
    AMVP_KAS_ECC_EPHEMERAL_UNIFIED = 1,
    AMVP_KAS_ECC_FULL_MQV,
    AMVP_KAS_ECC_FULL_UNIFIED,
    AMVP_KAS_ECC_ONEPASS_DH,
    AMVP_KAS_ECC_ONEPASS_MQV,
    AMVP_KAS_ECC_ONEPASS_UNIFIED,
    AMVP_KAS_ECC_STATIC_UNIFIED,
    AMVP_KAS_ECC_SCHEMES_MAX
} AMVP_KAS_ECC_SCHEMES;

/** @enum AMVP_KAS_FFC_MODE */
typedef enum amvp_kas_ffc_mode {
    AMVP_KAS_FFC_MODE_COMPONENT = 1,
    AMVP_KAS_FFC_MODE_NOCOMP,
    AMVP_KAS_FFC_MODE_NONE,
    AMVP_KAS_FFC_MAX_MODES
} AMVP_KAS_FFC_MODE;

/** @enum AMVP_KAS_FFC_SCHEMES */
typedef enum amvp_kas_ffc_schemes {
    AMVP_KAS_FFC_DH_EPHEMERAL = 1,
    AMVP_KAS_FFC_DH_HYBRID1,
    AMVP_KAS_FFC_FULL_MQV1,
    AMVP_KAS_FFC_FULL_MQV2,
    AMVP_KAS_FFC_DH_HYBRID_ONEFLOW,
    AMVP_KAS_FFC_DH_ONEFLOW,
    AMVP_KAS_FFC_DH_STATIC,
    AMVP_KAS_FFC_MAX_SCHEMES
} AMVP_KAS_FFC_SCHEMES;

/** @enum AMVP_KAS_FFC_FUNC */
typedef enum amvp_kas_ffc_func {
    AMVP_KAS_FFC_FUNC_DPGEN = 1,
    AMVP_KAS_FFC_FUNC_DPVAL,
    AMVP_KAS_FFC_FUNC_KEYPAIR,
    AMVP_KAS_FFC_FUNC_KEYREGEN,
    AMVP_KAS_FFC_FUNC_FULL,
    AMVP_KAS_FFC_MAX_FUNCS
} AMVP_KAS_FFC_FUNC;

/** @enum AMVP_KAS_FFC_PARAM */
typedef enum amvp_kas_ffc_param {
    AMVP_KAS_FFC_FUNCTION = 1,
    AMVP_KAS_FFC_CURVE,
    AMVP_KAS_FFC_ROLE,
    AMVP_KAS_FFC_HASH,
    AMVP_KAS_FFC_GEN_METH,
    AMVP_KAS_FFC_KDF,
    AMVP_KAS_FFC_FB,
    AMVP_KAS_FFC_FC,
    AMVP_KAS_FFC_MODP2048,
    AMVP_KAS_FFC_MODP3072,
    AMVP_KAS_FFC_MODP4096,
    AMVP_KAS_FFC_MODP6144,
    AMVP_KAS_FFC_MODP8192,
    AMVP_KAS_FFC_FFDHE2048,
    AMVP_KAS_FFC_FFDHE3072,
    AMVP_KAS_FFC_FFDHE4096,
    AMVP_KAS_FFC_FFDHE6144,
    AMVP_KAS_FFC_FFDHE8192
} AMVP_KAS_FFC_PARAM;

/** @enum AMVP_KAS_FFC_ROLES */
typedef enum amvp_kas_ffc_roles {
    AMVP_KAS_FFC_ROLE_INITIATOR = 1,
    AMVP_KAS_FFC_ROLE_RESPONDER
} AMVP_KAS_FFC_ROLES;

/** @enum AMVP_KAS_FFC_SET */
typedef enum amvp_kas_ffc_set {
    AMVP_KAS_FFC_NOKDFNOKC = 1,
    AMVP_KAS_FFC_KDFNOKC,
    AMVP_KAS_FFC_KDFKC,
    AMVP_KAS_FFC_PARMSET
} AMVP_KAS_FFC_SET;

/** @enum AMVP_KAS_FFC_TEST_TYPE */
typedef enum amvp_kas_ffc_test_type {
    AMVP_KAS_FFC_TT_AFT = 1,
    AMVP_KAS_FFC_TT_VAL
} AMVP_KAS_FFC_TEST_TYPE;

/** @enum AMVP_SAFE_PRIMES_PARAM */
typedef enum amvp_safe_primes_param {
    AMVP_SAFE_PRIMES_GENMETH = 1,
} AMVP_SAFE_PRIMES_PARAM;

/** @enum AMVP_SAFE_PRIMES_MODE */
typedef enum amvp_safe_primes_mode {
    AMVP_SAFE_PRIMES_MODP2048 = 1,
    AMVP_SAFE_PRIMES_MODP3072,
    AMVP_SAFE_PRIMES_MODP4096,
    AMVP_SAFE_PRIMES_MODP6144,
    AMVP_SAFE_PRIMES_MODP8192,
    AMVP_SAFE_PRIMES_FFDHE2048,
    AMVP_SAFE_PRIMES_FFDHE3072,
    AMVP_SAFE_PRIMES_FFDHE4096,
    AMVP_SAFE_PRIMES_FFDHE6144,
    AMVP_SAFE_PRIMES_FFDHE8192
} AMVP_SAFE_PRIMES_MODE;

/** @enum AMVP_SAFE_PRIMES_TEST_TYPE */
typedef enum amvp_safe_primes_test_type {
    AMVP_SAFE_PRIMES_TT_AFT = 1,
    AMVP_SAFE_PRIMES_TT_VAL
} AMVP_SAFE_PRIMES_TEST_TYPE;

/** @enum AMVP_KAS_IFC_PARAM */
typedef enum amvp_kas_ifc_param {
    AMVP_KAS_IFC_KEYGEN_METHOD = 1,
    AMVP_KAS_IFC_MODULO,
    AMVP_KAS_IFC_HASH,
    AMVP_KAS_IFC_KAS1,
    AMVP_KAS_IFC_KAS2,
    AMVP_KAS_IFC_FIXEDPUBEXP
} AMVP_KAS_IFC_PARAM;

/** @enum AMVP_KAS_IFC_KEYGEN */
typedef enum amvp_kas_ifc_keygen {
    AMVP_KAS_IFC_RSAKPG1_BASIC = 1,
    AMVP_KAS_IFC_RSAKPG1_PRIME_FACTOR,
    AMVP_KAS_IFC_RSAKPG1_CRT,
    AMVP_KAS_IFC_RSAKPG2_BASIC,
    AMVP_KAS_IFC_RSAKPG2_PRIME_FACTOR,
    AMVP_KAS_IFC_RSAKPG2_CRT
} AMVP_KAS_IFC_KEYGEN;

/** @enum AMVP_KAS_IFC_ROLES */
typedef enum amvp_kas_ifc_roles {
    AMVP_KAS_IFC_INITIATOR = 1,
    AMVP_KAS_IFC_RESPONDER
} AMVP_KAS_IFC_ROLES;

/** @enum AMVP_KAS_IFC_TEST_TYPE */
typedef enum amvp_kas_ifc_test_type {
    AMVP_KAS_IFC_TT_AFT = 1,
    AMVP_KAS_IFC_TT_VAL
} AMVP_KAS_IFC_TEST_TYPE;

/** @enum AMVP_KDA_ENCODING */
typedef enum amvp_kda_encoding {
    AMVP_KDA_ENCODING_NONE = 0,
    AMVP_KDA_ENCODING_CONCAT,
    AMVP_KDA_ENCODING_MAX
} AMVP_KDA_ENCODING;

/** @enum AMVP_KDA_PATTERN_CANDIDATE */
typedef enum amvp_kda_pattern_candidate {
    AMVP_KDA_PATTERN_NONE = 0,
    AMVP_KDA_PATTERN_LITERAL,
    AMVP_KDA_PATTERN_UPARTYINFO,
    AMVP_KDA_PATTERN_VPARTYINFO,
    AMVP_KDA_PATTERN_CONTEXT,
    AMVP_KDA_PATTERN_ALGID,
    AMVP_KDA_PATTERN_LABEL,
    AMVP_KDA_PATTERN_L,
    AMVP_KDA_PATTERN_T,
    AMVP_KDA_PATTERN_MAX
} AMVP_KDA_PATTERN_CANDIDATE;

/** @enum AMVP_KDA_MAC_SALT_METHOD */
typedef enum amvp_kda_mac_salt_method {
    AMVP_KDA_MAC_SALT_METHOD_NONE = 0,
    AMVP_KDA_MAC_SALT_METHOD_DEFAULT,
    AMVP_KDA_MAC_SALT_METHOD_RANDOM,
    AMVP_KDA_MAC_SALT_METHOD_MAX
} AMVP_KDA_MAC_SALT_METHOD;

/** @enum AMVP_KDA_PARM */
typedef enum amvp_kda_param {
    AMVP_KDA_PATTERN = 1,
    AMVP_KDA_REVISION,
    AMVP_KDA_ENCODING_TYPE,
    AMVP_KDA_Z,
    AMVP_KDA_L,
    AMVP_KDA_MAC_SALT,
    AMVP_KDA_PERFORM_MULTIEXPANSION_TESTS,
    AMVP_KDA_MAC_ALG,
    AMVP_KDA_USE_HYBRID_SECRET,
    AMVP_KDA_ONESTEP_AUX_FUNCTION,
    AMVP_KDA_TWOSTEP_SUPPORTED_LEN,
    AMVP_KDA_TWOSTEP_FIXED_DATA_ORDER,
    AMVP_KDA_TWOSTEP_COUNTER_LEN,
    AMVP_KDA_TWOSTEP_SUPPORTS_EMPTY_IV,
    AMVP_KDA_TWOSTEP_REQUIRES_EMPTY_IV
} AMVP_KDA_PARM;

/** @enum AMVP_KTS_IFC_PARAM */
typedef enum amvp_kts_ifc_param {
    AMVP_KTS_IFC_KEYGEN_METHOD = 1,
    AMVP_KTS_IFC_SCHEME,
    AMVP_KTS_IFC_FUNCTION,
    AMVP_KTS_IFC_MODULO,
    AMVP_KTS_IFC_IUT_ID,
    AMVP_KTS_IFC_KEYPAIR_GEN,
    AMVP_KTS_IFC_PARTIAL_VAL,
    AMVP_KTS_IFC_FIXEDPUBEXP
} AMVP_KTS_IFC_PARAM;

/** @enum AMVP_KTS_IFC_KEYGEN */
typedef enum amvp_kts_ifc_keygen {
    AMVP_KTS_IFC_RSAKPG1_BASIC = 1,
    AMVP_KTS_IFC_RSAKPG1_PRIME_FACTOR,
    AMVP_KTS_IFC_RSAKPG1_CRT,
    AMVP_KTS_IFC_RSAKPG2_BASIC,
    AMVP_KTS_IFC_RSAKPG2_PRIME_FACTOR,
    AMVP_KTS_IFC_RSAKPG2_CRT
} AMVP_KTS_IFC_KEYGEN;

/** @enum AMVP_KTS_IFC_ROLES */
typedef enum amvp_kts_ifc_roles {
    AMVP_KTS_IFC_INITIATOR = 1,
    AMVP_KTS_IFC_RESPONDER
} AMVP_KTS_IFC_ROLES;

/** @enum AMVP_KTS_IFC_SCHEME_PARAM */
typedef enum amvp_kts_ifc_scheme_param {
    AMVP_KTS_IFC_NULL_ASSOC_DATA = 1,
    AMVP_KTS_IFC_AD_PATTERN,
    AMVP_KTS_IFC_ENCODING,
    AMVP_KTS_IFC_HASH,
    AMVP_KTS_IFC_ROLE,
    AMVP_KTS_IFC_L,
    AMVP_KTS_IFC_MAC_METHODS
} AMVP_KTS_IFC_SCHEME_PARAM;

/** @enum AMVP_KTS_IFC_SCHEME_TYPE */
typedef enum amvp_kts_ifc_scheme_type {
    AMVP_KTS_IFC_KAS1_BASIC = 1,
    AMVP_KTS_IFC_KAS1_PARTYV,
    AMVP_KTS_IFC_KAS2_BASIC,
    AMVP_KTS_IFC_KAS2_BILATERAL,
    AMVP_KTS_IFC_KAS2_PARTYU,
    AMVP_KTS_IFC_KAS2_PARTYV
} AMVP_KTS_IFC_SCHEME_TYPE;

#define AMVP_KAS_IFC_CONCAT 2
/** @enum AMVP_KTS_IFC_TEST_TYPE */
typedef enum amvp_kts_ifc_test_type {
    AMVP_KTS_IFC_TT_AFT = 1,
    AMVP_KTS_IFC_TT_VAL
} AMVP_KTS_IFC_TEST_TYPE;

/** @defgroup APIs Public APIs for libamvp
 *  @brief this section describes APIs for libamvp.
 */
/** @internal ALL APIS SHOULD BE ADDED UNDER THE INGORUP BLOCK. */
/** @ingroup APIs
 * @{
 */

/**
 * @brief Allows an application to specify a symmetric cipher capability to be tested by the AMVP
 *        server.
 *        This function should be called to enable crypto capabilities for symmetric ciphers that
 *        will be tested by the AMVP server. This includes AES and 3DES. This function may be
 *        called multiple times to specify more than one crypto capability, such as AES-CBC,
 *        AES-CTR, AES-GCM, etc.
 *        When the application enables a crypto capability, such as AES-GCM, it also needs to
 *        specify a callback function that will be used by libamvp when that crypto capability is
 *        needed during a test session.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_sym_cipher_enable(AMVP_CTX *ctx,
                                       AMVP_CIPHER cipher);

/**
 * @brief amvp_cap_sym_cipher_set_parm() allows an application to specify length-based
 *        operational parameters to be used for a given cipher during a test session with the AMVP
 *        server.
 *
 *        This function should be called to enable crypto capabilities for symmetric ciphers that
 *        will be tested by the AMVP server. This includes AES and 3DES.
 *
 *        This function may be called multiple times to specify more than one crypto parameter
 *        value for the cipher. For instance, if cipher supports key lengths of 128, 192, and 256
 *        bits, then this function would be called three times. Once for 128, once for 192, and
 *        once again for 256. The AMVP_CIPHER value passed to this function should already have
 *        been setup by invoking amvp_enable_sym_cipher_cap() for that cipher earlier.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 * @param parm AMVP_SYM_CIPH_PARM enum value identifying the algorithm parameter that is being
 *        specified. An example would be the supported plaintext length of the algorithm.
 * @param length The length value for the symmetric cipher parameter being set
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_sym_cipher_set_parm(AMVP_CTX *ctx,
                                         AMVP_CIPHER cipher,
                                         AMVP_SYM_CIPH_PARM parm,
                                         int length);

/**
 * @brief amvp_cap_sym_cipher_set_domain allow an application to specify length-based operational
 *        parameters to be used for a given cipher during a test session with the AMVP server.
 *
 *        The user should call this to specify the supported key PT lengths, AAD lengths, and IV
 *        lengths This is called multiple times, for different parms.
 *
 *        The AMVP_CIPHER value passed to this function should already have been setup by invoking
 *        amvp_enable_sym_cipher_cap() for that cipher earlier.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 * @param parm AMVP_SYM_CIPH_PARM enum value identifying the algorithm parameter that is being
 *        specified. An example would be the supported key length of the algorithm.
 * @param min the minimum value of the domain (range of possible values) being set
 * @param max the maximum value of the domain being set
 * @param increment the increment of the domain being set. Should evenly divide into the other
 *        values.
 *
 * @return AMVP_RESULT
*/
AMVP_RESULT amvp_cap_sym_cipher_set_domain(AMVP_CTX *ctx,
                                           AMVP_CIPHER cipher,
                                           AMVP_SYM_CIPH_DOMAIN_PARM parm,
                                           int min,
                                           int max,
                                           int increment);

/**
 * @brief amvp_cap_hash_enable() allows an application to specify a hash capability to be tested
 *        by the AMVP server.
 *
 *        This function should be called to enable crypto capabilities for hash algorithms that
 *        will be tested by the AMVP server. This includes SHA-1, SHA-256, SHA-384, etc. This
 *        function may be called multiple times to specify more than one crypto capability.
 *
 *        When the application enables a crypto capability, such as SHA-1, it also needs to specify
 *        a callback function that will be used by libamvp when that crypto capability is needed
 *        during a test session.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_hash_enable(AMVP_CTX *ctx,
                                 AMVP_CIPHER cipher);

/**
 * @brief amvp_cap_hash_set_parm() allows an application to specify operational parameters to be
 *        used for a given hash alg during a test session with the AMVP server.
 *
 *        This function should be called to enable crypto capabilities for hash capabilities that
 *        will be tested by the AMVP server. This includes SHA-1, SHA-256, SHA-384, etc.
 *
 *        This function may be called multiple times to specify more than one crypto parameter
 *        value for the hash algorithm. The AMVP_CIPHER value passed to this function should
 *        already have been setup by invoking amvp_enable_hash_cap().
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 * @param param AMVP_HASH_PARM enum value identifying the algorithm parameter that is being
 *        specified. An example would be a flag indicating if empty input values are allowed.
 * @param value the value corresponding to the parameter being set
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_hash_set_parm(AMVP_CTX *ctx,
                                   AMVP_CIPHER cipher,
                                   AMVP_HASH_PARM param,
                                   int value);

/**
 * @brief amvp_cap_hash_set_domain() functions similarly to @ref amvp_cap_hash_set_parm() but uses
 *        a range of values for certain parameters instead of a single value.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 * @param parm AMVP_HASH_PARM enum value identifying the algorithm parameter that is being
 *        specified. An example would be message length.
 * @param min the lower value of the supported range of values
 * @param max the maximum supported value for the given parameter
 * @param increment the supported increment for every value in between min and max
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_hash_set_domain(AMVP_CTX *ctx,
                                     AMVP_CIPHER cipher,
                                     AMVP_HASH_PARM parm,
                                     int min,
                                     int max,
                                     int increment);

/**
 * @brief amvp_enable_drbg_cap() allows an application to specify a hash capability to be tested by
 *        the AMVP server.
 *
 *        This function should be called to enable crypto capabilities for drbg algorithms that
 *        will be tested by the AMVP server. This includes HASHDRBG, HMACDRBG, CTRDRBG. This
 *        function may be called multiple times to specify more than one crypto capability.
 *
 *        When the application enables a crypto capability, such as AMVP_HASHDRBG, it also needs to
 *        specify a callback function that will be used by libamvp when that crypto capability is
 *        needed during a test session.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_drbg_enable(AMVP_CTX *ctx,
                                 AMVP_CIPHER cipher);

/**
 * @brief amvp_cap_drbg_set_parm() allows an application to specify operational parameters to be
 *        used for a given DRBG alg during a test session with the AMVP server.
 *
 *        This function should be called to enable crypto capabilities for hash capabilities that
 *        will be tested by the AMVP server. This includes HASHDRBG, HMACDRBG, CTRDRBG. This
 *        function may be called multiple times to specify more than one crypto capability.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 * @param mode AMVP_DRBG_MODE enum value specifying mode. An example would be AMVP_DRBG_SHA_1
 * @param group The group of capabilities for the given AMVP DRBG modes. Different groups can be
 *        defined for different capabilities; e.g. different lengths can be supported with and
 *        without derivation function support. Groups must be used in a linear fashion (group 0
 *        must be defined before you can define group 1, group 1 before group 2, etc)
 * @param param AMVP_DRBG_PARM enum value identifying the algorithm parameter that is being
 *        specified. An example would be prediction resistance.
 * @param value the value corresponding to the parameter being set
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_drbg_set_parm(AMVP_CTX *ctx,
                                   AMVP_CIPHER cipher,
                                   AMVP_DRBG_MODE mode,
                                   int group,
                                   AMVP_DRBG_PARM param,
                                   int value);

/**
 * @brief amvp_enable_drbg_length_cap() allows an application to register a DRBG capability
 *        length-based paramter.
 *
 *        This function should be used to register a length-based parameter for a DRBG capability.
 *        An example would be entropy, nonce, perso where a minimum, step, and maximum can be
 *        specified.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 * @param mode AMVP_DRBG_MODE enum value specifying mode. An example would be AMVP_DRBG_SHA_1
 * @param group The group of capabilities for the given AMVP DRBG modes. Different groups can be
 *        defined for different capabilities; e.g. different lengths can be supported with and
 *        without derivation function support. Groups must be used in a linear fashion (group 0
 *        must be defined before you can define group 1, group 1 before group 2, etc)
 * @param param AMVP_DRBG_PARM enum value specifying paramter. An example would be
 *        AMVP_DRBG_ENTROPY_LEN
 * @param min minimum value
 * @param step increment value
 * @param max maximum value
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_drbg_set_length(AMVP_CTX *ctx,
                                     AMVP_CIPHER cipher,
                                     AMVP_DRBG_MODE mode,
                                     int group,
                                     AMVP_DRBG_PARM param,
                                     int min,
                                     int step,
                                     int max);

/**
 * @brief amvp_enable_dsa_cap()
 *        This function should be used to enable DSA capabilities. Specific modes and parameters
 *        can use amvp_cap_dsa_set_parm.
 *
 *        When the application enables a crypto capability, such as DSA, it also needs to specify a
 *        callback function that will be used by libamvp when that crypto capability is needed
 *        during a test session.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_dsa_enable(AMVP_CTX *ctx,
                                AMVP_CIPHER cipher);

/**
 * @brief amvp_cap_dsa_set_parm() allows an application to specify operational parameters to be
 *        used for a given dsa alg during a test session with the AMVP server. This function
 *        should be called to enable crypto capabilities for DSA modes and functions. It may be
 *        called multiple times to specify more than one crypto capability.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 * @param mode AMVP_DSA_MODE enum value specifying mode. An example would be AMVP_DSA_MODE_PQGGEN
 * @param param AMVP_DSA_PARM enum value identifying the algorithm parameter that is being
 *        specified. An example would be AMVP_DSA_GENPQ.
 * @param value the value corresponding to the parameter being set
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_dsa_set_parm(AMVP_CTX *ctx,
                                  AMVP_CIPHER cipher,
                                  AMVP_DSA_MODE mode,
                                  AMVP_DSA_PARM param,
                                  int value);

/**
 * @brief amvp_enable_kas_ecc_cap()
 *        This function should be used to enable KAS-ECC capabilities. Specific modes and
 *        parameters can use amvp_cap_kas_ecc_set_parm.
 *
 *        When the application enables a crypto capability, such as KAS-ECC, it also needs to
 *        specify a callback function that will be used by libamvp when that crypto capability is
 *        needed during a test session.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kas_ecc_enable(AMVP_CTX *ctx,
                                    AMVP_CIPHER cipher);

/**
 * @brief amvp_enable_kas_ecc_prereq_cap() allows an application to specify a prerequisite
 *        algorithm for a given KAS-ECC mode during a test session with the AMVP server. This
 *        function should be called to enable a prerequisite for an KAS-ECC mode capability that
 *        will be tested by the server.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 * @param mode AMVP_KAS_ECC_MODE enum value specifying mode. An example would be
 *        AMVP_KAS_ECC_MODE_PARTIAL
 * @param pre_req AMVP_PREREQ_ALG enum that the specified cipher/mode depends on
 * @param value "same" or number
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kas_ecc_set_prereq(AMVP_CTX *ctx,
                                        AMVP_CIPHER cipher,
                                        AMVP_KAS_ECC_MODE mode,
                                        AMVP_PREREQ_ALG pre_req,
                                        char *value);

/**
 * @brief amvp_cap_kas_ecc_set_parm() allows an application to specify operational parameters to
 *        be used for a given kas-ecc alg during a test session with the AMVP server. This function
 *        should be called to enable crypto capabilities for KAS-ECC modes and functions. It may be
 *        called multiple times to specify more than one crypto capability.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 * @param mode AMVP_KAS_ECC_MODE enum value specifying mode. An example would be
 *        AMVP_KAS_ECC_MODE_PARTIALVAL
 * @param param AMVP_KAS_ECC_PARAM enum value identifying the algorithm parameter that is being
 *        specified. An example would be AMVP_KAS_ECC_????
 * @param value the value corresponding to the parameter being set
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kas_ecc_set_parm(AMVP_CTX *ctx,
                                      AMVP_CIPHER cipher,
                                      AMVP_KAS_ECC_MODE mode,
                                      AMVP_KAS_ECC_PARAM param,
                                      int value);

/**
 * @brief amvp_cap_kas_ecc_set_scheme() allows an application to specify operational parameters to
 *        be used for a given kas-ecc alg during a test session with the AMVP server  This function
 *        should be called to enable crypto capabilities for KAS-ECC modes and functions. It may be
 *        called multiple times to specify more than one crypto capability.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 * @param mode AMVP_KAS_ECC_MODE enum value specifying mode. An example would be
 *        AMVP_KAS_ECC_MODE_CDH
 * @param scheme The AMVP_KAS_ECC_SCHEMES value specifying the desired scheme
 * @param param AMVP_KAS_ECC_PARAM enum value identifying the algorithm parameter that is being
 *        specified. An example would be AMVP_KAS_ECC_????
 * @param option the value for some schemes which require an additional option to be set
 * @param value the value corresponding to the parameter being set
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kas_ecc_set_scheme(AMVP_CTX *ctx,
                                        AMVP_CIPHER cipher,
                                        AMVP_KAS_ECC_MODE mode,
                                        AMVP_KAS_ECC_SCHEMES scheme,
                                        AMVP_KAS_ECC_PARAM param,
                                        int option,
                                        int value);


/**
 * @brief amvp_cap_kas_ifc_enable()
 *        This function should be used to enable KAS-IFC capabilities. Specific modes and
 *        parameters can use amvp_cap_kas_ifc_set_parm.
 *
 *        When the application enables a crypto capability, such as KAS-IFC, it also needs to
 *        specify a callback function that will be used by libamvp when that crypto capability is
 *        needed during a test session.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kas_ifc_enable(AMVP_CTX *ctx,
                                    AMVP_CIPHER cipher);


/**
 * @brief amvp_cap_kas_ifc_set_parm() allows an application to specify operational parameters to be
 *        used for a given alg during a test session with the AMVP server. This function should be
 *        called to enable crypto capabilities for KAS-IFC modes and functions. It may be called
 *        multiple times to specify more than one crypto capability.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 * @param param AMVP_KAS_IFC_PARAM enum value identifying the algorithm parameter that is being
 *        specified. An example would be AMVP_KAS_IFC_????
 * @param value the value corresponding to the parameter being set
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kas_ifc_set_parm(AMVP_CTX *ctx,
                                      AMVP_CIPHER cipher,
                                      AMVP_KAS_IFC_PARAM param,
                                      int value);

/**
 * @brief amvp_cap_kas_ifc_set_exponent() allows an application to specify public exponent to be
 *        used for a given alg during a test session with the AMVP server.  This function should be
 *        called to enable crypto capabilities for KAS-IFC modes and functions. It may be called
 *        multiple times to specify more than one crypto capability.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 * @param param AMVP_KAS_IFC_PARAM enum value identifying the algorithm parameter that is being
 *        specified. An example would be AMVP_KAS_IFC_????
 * @param value the string value corresponding to the public exponent being set
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kas_ifc_set_exponent(AMVP_CTX *ctx,
                                          AMVP_CIPHER cipher,
                                          AMVP_KAS_IFC_PARAM param,
                                          char *value);


/**
 * @brief amvp_cap_kts_ifc_enable()
 *        This function should be used to enable KTS-IFC capabilities. Specific modes and
 *        parameters can use amvp_enable_kts_ifc_set_parm, amvp_cap_kts_ifc_set_param_string and
 *        amvp_cap_kts_ifc_set_scheme_string.
 *
 *        When the application enables a crypto capability, such as KTS-IFC, it also needs to
 *        specify a callback function that will be used by libamvp when that crypto capability is
 *        needed during a test session.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kts_ifc_enable(AMVP_CTX *ctx,
                                    AMVP_CIPHER cipher);


/**
 * @brief amvp_cap_kts_ifc_set_parm() allows an application to specify operational parameters to be
 *        used for a given alg during a test session with the AMVP server. This function should be
 *        called to enable crypto capabilities for KTS-IFC modes and functions. It may be called
 *        multiple times to specify more than one crypto capability.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 * @param param AMVP_KTS_IFC_PARAM enum value identifying the algorithm parameter that is being
 *        specified. An example would be AMVP_KTS_IFC_????
 * @param value the value corresponding to the parameter being set
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kts_ifc_set_parm(AMVP_CTX *ctx,
                                      AMVP_CIPHER cipher,
                                      AMVP_KTS_IFC_PARAM param,
                                      int value);

/**
 * @brief amvp_cap_kts_ifc_set_scheme_parm() allows an application to specify operational
 *        parameters to be used for KTS-IFC scheme parameters  during a test session with the AMVP
 *        server. This function should be called to enable crypto capabilities for KTS-IFC modes
 *        and functions. It may be called  multiple times to specify more than one crypto
 *        capability.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 * @param scheme AMVP_KTS_IFC_SCHEME enum value identifying the scheme type that is being specified.
 *        An example would be AMVP_KTS_IFC_KAS1_BASIC
 * @param param AMVP_KTS_IFC_SCHEME_PARAM enum value identifying the scheme option that is being
 *        specified. An example would be AMVP_KTS_IFC_ROLE
 * @param value the value corresponding to the parameter being set
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kts_ifc_set_scheme_parm(AMVP_CTX *ctx,
                                             AMVP_CIPHER cipher,
                                             AMVP_KTS_IFC_SCHEME_TYPE scheme,
                                             AMVP_KTS_IFC_SCHEME_PARAM param,
                                             int value);

/**
 * @brief amvp_cap_kts_ifc_set_param_string() allows an application to specify
 *     string based params to be used for a given alg during a
 *      test session with the AMVP server.
 *     This function should be called to enable crypto capabilities for
 *    KTS-IFC modes and functions. It may be called  multiple times to specify
 *   more than one crypto capability.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 * @param param AMVP_KTS_IFC_PARAM enum value identifying the algorithm parameter
 *        that is being specified. An example would be AMVP_KTS_IFC_FIXEDPUBEXP
 * @param value the string value corresponding to the public exponent being set
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kts_ifc_set_param_string(AMVP_CTX *ctx,
                                             AMVP_CIPHER cipher,
                                             AMVP_KTS_IFC_PARAM param,
                                             char *value);

/**
 * @brief amvp_cap_kts_ifc_set_scheme_string() allows an application to specify string based params
 *        to be used for a given alg during a test session with the AMVP server. This function
 *        should be called to enable crypto capabilities for KTS-IFC modes and functions. It may be
 *        called multiple times to specify more than one crypto capability.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 * @param scheme AMVP_KTS_IFC_SCHEME enum value identifying the scheme type that is being specified.
 *        An example would be AMVP_KTS_IFC_KAS1_BASIC
 * @param param AMVP_KTS_IFC_PARAM enum value identifying the algorithm parameter that is being
 *        specified. An example would be AMVP_KTS_IFC_ENCODING
 * @param value the string value corresponding to the public exponent being set
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kts_ifc_set_scheme_string(AMVP_CTX *ctx,
                                               AMVP_CIPHER cipher,
                                               AMVP_KTS_IFC_SCHEME_TYPE scheme,
                                               AMVP_KTS_IFC_PARAM param,
                                               char *value);

/**
 * @brief amvp_enable_kas_ffc_cap()
 *        This function should be used to enable KAS-FFC capabilities. Specific modes and
 *        parameters can use amvp_cap_kas_ffc_set_parm.
 *
 *        When the application enables a crypto capability, such as KAS-FFC, it also needs to
 *        specify a callback function that will be used by libamvp when that crypto capability is
 *        needed during a test session.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 *
 * @return AMVP_RESULT
 */

AMVP_RESULT amvp_cap_kas_ffc_enable(AMVP_CTX *ctx,
                                    AMVP_CIPHER cipher);

/**
 * @brief amvp_enable_kas_ffc_prereq_cap() allows an application to specify a prerequisite
 *        algorithm for a given KAS-FFC mode during a test session with the AMVP server. This
 *        function should be called to enable a prerequisite for an KAS-FFC mode capability that
 *        will be tested by the server.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 * @param mode AMVP_KAS_FFC_MODE enum value specifying mode. An example would be
 *        AMVP_KAS_FFC_MODE_PARTIAL
 * @param pre_req AMVP_PREREQ_ALG enum that the specified cipher/mode depends on
 * @param value "same" or number
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kas_ffc_set_prereq(AMVP_CTX *ctx,
                                        AMVP_CIPHER cipher,
                                        AMVP_KAS_FFC_MODE mode,
                                        AMVP_PREREQ_ALG pre_req,
                                        char *value);

/**
 * @brief amvp_cap_kas_ffc_set_parm() allows an application to specify operational parameters to
 *        be used for a given alg during a test session with the AMVP server. This function should
 *        be called to enable crypto capabilities for KAS-FFC modes and functions. It may be called
 *        multiple times to specify more than one crypto capability.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 * @param mode AMVP_KAS_FFC_MODE enum value specifying mode. An example would be
 *        AMVP_KAS_FFC_MODE_DPGEN
 * @param param AMVP_KAS_FFC_PARAM enum value identifying the algorithm parameter that is being
 *        specified. An example would be AMVP_KAS_FFC_????
 * @param value the value corresponding to the parameter being set
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kas_ffc_set_parm(AMVP_CTX *ctx,
                                      AMVP_CIPHER cipher,
                                      AMVP_KAS_FFC_MODE mode,
                                      AMVP_KAS_FFC_PARAM param,
                                      int value);


/**
 * @brief amvp_enable_kas_ffc_cap_scheme() allows an application to specify scheme parameters to be
 *        used for a given alg during a test session with the AMVP server. This function should be
 *        called to enable crypto capabilities for KAS-FFC modes and functions. It may be called
 *        multiple times to specify more than one crypto capability.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 * @param mode AMVP_KAS_FFC_MODE enum value specifying mode. An example would be
 *        AMVP_KAS_FFC_MODE_COMPONENT
 * @param scheme AMVP_KAS_FFC_SCHEME enum value identifying the algorithm parameter that is being
 *        specified. An example would be AMVP_KAS_FFC_DH_EPHEMERAL
 * @param param AMVP_KAS_FFC_PARAM enum value identifying the algorithm parameter that is being
 *        specified. An example would be AMVP_KAS_FFC_KDF
 * @param value the value corresponding to the parameter being set
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kas_ffc_set_scheme(AMVP_CTX *ctx,
                                        AMVP_CIPHER cipher,
                                        AMVP_KAS_FFC_MODE mode,
                                        AMVP_KAS_FFC_SCHEMES scheme,
                                        AMVP_KAS_FFC_PARAM param,
                                        int value);

/**
 * @brief amvp_enable_kda_set_domain() allows an application to specify operational parameters
 *        to be used for a given alg during a test session with the AMVP server. This function
 *        should be called to enable crypto capabilities for KDA modes and functions. It may be
 *        called multiple times to specify more than one crypto capability.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 * @param param AMVP_KDA_PARM enum value identifying the algorithm parameter that is being
 *        specified. An example would be AMVP_KDA_HKDF_???
 * @param min Minumum supported value for the corresponding parameter
 * @param max Maximum supported value for the corresponding parameter
 * @param increment Increment value supported
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kda_set_domain(AMVP_CTX *ctx,
                                       AMVP_CIPHER cipher,
                                       AMVP_KDA_PARM param,
                                       int min,
                                       int max,
                                       int increment);

/**
 * @brief amvp_enable_kda_twostep_set_domain() allows an application to specify operational parameters
 *        to be used for a given alg during a test session with the AMVP server. This function
 *        should be called to enable crypto capabilities for KDA modes and functions. It may be
 *        called multiple times to specify more than one crypto capability.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param param AMVP_KDA_PARM enum value identifying the algorithm parameter that is being
 *        specified. An example would be AMVP_KDA_HKDF_???
 * @param min Minumum supported value for the corresponding parameter
 * @param max Maximum supported value for the corresponding parameter
 * @param increment Increment value supported
 * @param kdf_mode The kdf mode being set - counter, feedback, or double pipeline iteration
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kda_twostep_set_domain(AMVP_CTX *ctx,
                                       AMVP_KDA_PARM param,
                                       int min,
                                       int max,
                                       int increment,
                                       int kdf_mode);


/**
 * @brief amvp_enable_kda_set_parm() allows an application to specify operational parameters
 *        to be used for a given alg during a test session with the AMVP server. This function
 *        should be called to enable crypto capabilities for KDA modes and functions. It may be
 *        called multiple times to specify more than one crypto capability.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 * @param param AMVP_KDA_PARM enum value identifying the algorithm parameter that is being
 *        specified. An example would be AMVP_KDA_HKDF_???
 * @param value the value corresponding to the parameter being set
 * @param string a constant string value required by some parameters, will return an error if
 *        incorrectly used with wrong parameters
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kda_set_parm(AMVP_CTX *ctx,
                                      AMVP_CIPHER cipher,
                                      AMVP_KDA_PARM param,
                                      int value,
                                      const char* string);

/**
 * @brief amvp_cap_kda_twostep_set_parm() allows an application to specify operational parameters
 *        to be used for a given alg during a test session with the AMVP server. This function
 *        should be called to enable crypto capabilities for KDA modes and functions. It may be
 *        called multiple times to specify more than one crypto capability.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param param AMVP_KDA_PARM enum value identifying the algorithm parameter that is being
 *        specified. An example would be AMVP_KDA_TWOSTEP_??
 * @param value the value corresponding to the parameter being set
 * @param kdf_mode The kdf mode being set - counter, feedback, or double pipeline iteration
 * @param string a constant string value required by some parameters, will return an error if
 *        incorrectly used with wrong parameters
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kda_twostep_set_parm(AMVP_CTX *ctx, 
                                          AMVP_KDA_PARM param,
                                          int value, 
                                          int kdf_mode, 
                                          const char* string);

/**
 * @brief amvp_enable_kda_enable()
 *        This function should be used to enable KDA functions. Parameters are set using
 *        amvp_cap_kda_set_parm().
 *
 *        When the application enables a crypto capability, such as KDA-HKDF, it also needs to
 *        specify a callback function that will be used by libamvp when that crypto capability is
 *        needed during a test session.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kda_enable(AMVP_CTX *ctx,
                                    AMVP_CIPHER cipher);

/**
 * @brief amvp_enable_rsa_*_cap()
 *        This function should be used to enable RSA capabilities. Specific modes and parameters
 *        can use amvp_cap_rsa_parm, amvp_enable_rsa_bignum_set_parm,
 *        amvp_enable_rsa_primes_parm depending on the need.
 *
 *        When the application enables a crypto capability, such as RSA, it also needs to specify a
 *        callback function that will be used by libamvp when that crypto capability is needed
 *        during a test session.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_rsa_keygen_enable(AMVP_CTX *ctx,
                                       AMVP_CIPHER cipher);

AMVP_RESULT amvp_cap_rsa_sig_enable(AMVP_CTX *ctx,
                                    AMVP_CIPHER cipher);

AMVP_RESULT amvp_cap_rsa_prim_enable(AMVP_CTX *ctx,
                                     AMVP_CIPHER cipher);

AMVP_RESULT amvp_cap_ecdsa_enable(AMVP_CTX *ctx,
                                  AMVP_CIPHER cipher);

/**
 * @brief amvp_cap_rsa_*_set_parm() allows an application to specify operational parameters to
 *        be used for a given RSA alg during a test session with the AMVP server. This function
 *        should be called to enable parameters for RSA capabilities that will be tested by the
 *        AMVP server. This function may be called multiple times to specify more than one crypto
 *        capability.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param param AMVP_RSA_PARM enum value identifying the algorithm parameter that is being
 *        specified. An example would be public exponent
 * @param value the value corresponding to the parameter being set
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_rsa_keygen_set_parm(AMVP_CTX *ctx,
                                         AMVP_RSA_PARM param,
                                         int value);

AMVP_RESULT amvp_cap_rsa_sigver_set_parm(AMVP_CTX *ctx,
                                         AMVP_RSA_PARM param,
                                         int value);

AMVP_RESULT amvp_cap_rsa_keygen_set_mode(AMVP_CTX *ctx,
                                         AMVP_RSA_KEYGEN_MODE value);

AMVP_RESULT amvp_cap_rsa_prim_set_parm(AMVP_CTX *ctx,
                                       AMVP_RSA_PARM prim_type,
                                       int value);

AMVP_RESULT amvp_cap_rsa_prim_set_exponent(AMVP_CTX *ctx,
                                           AMVP_RSA_PARM param,
                                           char *value);

AMVP_RESULT amvp_cap_rsa_siggen_set_type(AMVP_CTX *ctx,
                                         AMVP_RSA_SIG_TYPE type);

AMVP_RESULT amvp_cap_rsa_sigver_set_type(AMVP_CTX *ctx,
                                         AMVP_RSA_SIG_TYPE type);

AMVP_RESULT amvp_cap_rsa_siggen_set_mod_parm(AMVP_CTX *ctx,
                                             AMVP_RSA_SIG_TYPE sig_type,
                                             unsigned int mod,
                                             int hash_alg,
                                             int salt_len);

AMVP_RESULT amvp_cap_rsa_sigver_set_mod_parm(AMVP_CTX *ctx,
                                             AMVP_RSA_SIG_TYPE sig_type,
                                             unsigned int mod,
                                             int hash_alg,
                                             int salt_len);

AMVP_RESULT amvp_cap_ecdsa_set_parm(AMVP_CTX *ctx,
                                    AMVP_CIPHER cipher,
                                    AMVP_ECDSA_PARM param,
                                    int value);

AMVP_RESULT amvp_cap_ecdsa_set_curve_hash_alg(AMVP_CTX *ctx,
                                              AMVP_CIPHER cipher,
                                              AMVP_EC_CURVE curve,
                                              AMVP_HASH_ALG alg);


/**
 * @brief amvp_enable_rsa_bignum_parm() allows an application to specify BIGNUM operational
 *        parameters to be used for a given RSA alg during a test session with the AMVP server.
 *        This function behaves the same as amvp_cap_rsa_set_parm() but instead allows the
 *        application to specify a BIGNUM parameter
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param param AMVP_RSA_PARM enum value identifying the algorithm parameter that is being
 *        specified. An example would be public exponent
 * @param value BIGNUM value corresponding to the parameter being set
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_rsa_keygen_set_exponent(AMVP_CTX *ctx,
                                             AMVP_RSA_PARM param,
                                             char *value);
AMVP_RESULT amvp_cap_rsa_sigver_set_exponent(AMVP_CTX *ctx,
                                             AMVP_RSA_PARM param,
                                             char *value);

/**
 * @brief amvp_cap_rsa_keygen_set_primes() allows an application to specify RSA key generation
 *        provable or probable primes parameters for use during a test session with the AMVP
 *        server. The function behaves similarly to amvp_cap_rsa_set_parm() and
 *        amvp_enable_rsa_*_exp_parm() but allows for a modulo and hash algorithm parameter to be
 *        specified alongside the provable or probable parameter.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param mode AMVP_RSA_MODE enum value specifying mode. In this case it will always be
 *        AMVP_RSA_MODE_KEYGEN
 * @param mod Supported RSA modulo value for probable or provable prime generation
 * @param param AMVP_RSA_PRIME_PARAM enum value identifying the parameter that will be given for
 *              the \p value. One of: AMVP_RSA_PRIME_HASH_ALG, AMVP_RSA_PRIME_TEST
 * @param value Integer value corresponding to the specified \p param.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_rsa_keygen_set_primes(AMVP_CTX *ctx,
                                           AMVP_RSA_KEYGEN_MODE mode,
                                           unsigned int mod,
                                           AMVP_RSA_PRIME_PARAM param,
                                           int value);

/**
 * @brief amvp_enable_hmac_cap() allows an application to specify an HMAC capability to be tested
 *        by the AMVP server. This function should be called to enable crypto capabilities for hmac
 *        algorithms that will be tested by the AMVP server. This includes HMAC-SHA-1,
 *        HMAC-SHA2-256, HMAC-SHA2-384, etc. This function may be called multiple times to specify
 *        more than one crypto capability.
 *
 *        When the application enables a crypto capability, such as HMAC-SHA-1, it also needs to
 *        specify a callback function that will be used by libamvp when that crypto capability is
 *        needed during a test session.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_hmac_enable(AMVP_CTX *ctx,
                                 AMVP_CIPHER cipher);

/**
 * @brief amvp_cap_hmac_set_parm() allows an application to specify operational parameters for
 *        use during a test session with the AMVP server. This function allows the application to
 *        specify parameters for use when registering HMAC capability with the server.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 * @param parm AMVP_HMAC_PARM enum value specifying parameter
 * @param value Supported value for the corresponding parameter
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_hmac_set_parm(AMVP_CTX *ctx,
                                   AMVP_CIPHER cipher,
                                   AMVP_HMAC_PARM parm,
                                   int value);

/**
 * @brief Allows an application to specify operational parameters for use during a test session
 *        with the AMVP server.This function allows the application to specify parameters for use
 *        when registering HMAC capability with the server.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 * @param parm AMVP_HMAC_PARM enum value specifying parameter
 * @param min Minumum supported value for the corresponding parameter
 * @param max Maximum supported value for the corresponding parameter
 * @param increment Increment value supported
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_hmac_set_domain(AMVP_CTX *ctx,
                                     AMVP_CIPHER cipher,
                                     AMVP_HMAC_PARM parm,
                                     int min,
                                     int max,
                                     int increment);

/**
 * @brief amvp_enable_cmac_cap() allows an application to specify an CMAC capability to be tested
 *         by the AMVP server. This function should be called to enable crypto capabilities for
 *         cmac algorithms that will be tested by the AMVP server. This includes CMAC-AES-128,
 *         CMAC-AES-192, CMAC-AES-256, etc. This function may be called multiple times to specify
 *         more than one crypto capability.
 *
 *         When the application enables a crypto capability, such as CMAC-AES-128, it also needs to
 *         specify a callback function that will be used by libamvp when that crypto capability is
 *         needed during a test session.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_cmac_enable(AMVP_CTX *ctx,
                                 AMVP_CIPHER cipher);

/**
 * @brief amvp_cap_cmac_set_parm() allows an application to specify operational parameters for
 *        use during a test session with the AMVP server. This function allows the application to
 *        specify parameters for use when registering CMAC capability with the server.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 * @param parm AMVP_CMAC_PARM enum value specifying parameter
 * @param value Supported value for the corresponding parameter
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_cmac_set_parm(AMVP_CTX *ctx,
                                   AMVP_CIPHER cipher,
                                   AMVP_CMAC_PARM parm,
                                   int value);

/**
 * @brief amvp_cap_cmac_set_domain() allows an application to specify operational parameters for
 *        use during a test session with the AMVP server. This function allows the application to
 *        specify parameters for use when registering CMAC capability with the server.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 * @param parm AMVP_CMAC_PARM enum value specifying parameter
 * @param min Minumum supported value for the corresponding parameter
 * @param max Maximum supported value for the corresponding parameter
 * @param increment Increment value supported
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_cmac_set_domain(AMVP_CTX *ctx,
                                     AMVP_CIPHER cipher,
                                     AMVP_CMAC_PARM parm,
                                     int min,
                                     int max,
                                     int increment);

/**
 * @brief amvp_cap_kmac_enable() allows an application to specify an KMAC capability to be tested
 *         by the AMVP server. This function should be called to enable crypto capabilities for
 *         kmac algorithms that will be tested by the AMVP server. This includes KMAC-128 and
 *         KMAC-256. This function may be called multiple times to specify
 *         more than one crypto capability.
 *
 *         When the application enables a crypto capability, such as KMAC-128, it also needs to
 *         specify a callback function that will be used by libamvp when that crypto capability is
 *         needed during a test session.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kmac_enable(AMVP_CTX *ctx,
                                 AMVP_CIPHER cipher);

/**
 * @brief amvp_cap_kmac_set_parm() allows an application to specify operational parameters for
 *        use during a test session with the AMVP server. This function allows the application to
 *        specify parameters for use when registering KMAC capability with the server.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 * @param parm AMVP_KMAC_PARM enum value specifying parameter
 * @param value Supported value for the corresponding parameter
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kmac_set_parm(AMVP_CTX *ctx,
                                   AMVP_CIPHER cipher,
                                   AMVP_KMAC_PARM parm,
                                   int value);

/**
 * @brief amvp_cap_kmac_set_domain() allows an application to specify operational parameters for
 *        use during a test session with the AMVP server. This function allows the application to
 *        specify parameters for use when registering KMAC capability with the server.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 * @param parm AMVP_KMAC_PARM enum value specifying parameter
 * @param min Minumum supported value for the corresponding parameter
 * @param max Maximum supported value for the corresponding parameter
 * @param increment Increment value supported
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kmac_set_domain(AMVP_CTX *ctx,
                                     AMVP_CIPHER cipher,
                                     AMVP_KMAC_PARM parm,
                                     int min,
                                     int max,
                                     int increment);


/**
 * @brief amvp_cap_kdf135_*_enable() allows an application to specify a kdf cipher capability to be
 *        tested by the AMVP server. When the application enables a crypto capability, such as
 *        KDF135_SNMP, it also needs to specify a callback function that will be used by libamvp
 *        when that crypto capability is needed during a test session.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kdf135_snmp_enable(AMVP_CTX *ctx);

/**
 * @brief see @ref amvp_cap_kdf135_snmp_enable()
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kdf135_ssh_enable(AMVP_CTX *ctx);

/**
 * @brief see @ref amvp_cap_kdf135_snmp_enable()
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kdf135_srtp_enable(AMVP_CTX *ctx);

/**
 * @brief see @ref amvp_cap_kdf135_snmp_enable()
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kdf135_ikev2_enable(AMVP_CTX *ctx);

/**
 * @brief see @ref amvp_cap_kdf135_snmp_enable()
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kdf135_ikev1_enable(AMVP_CTX *ctx);

/**
 * @brief see @ref amvp_cap_kdf135_snmp_enable()
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kdf135_x942_enable(AMVP_CTX *ctx);

/**
 * @brief see @ref amvp_cap_kdf135_snmp_enable()
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kdf135_x963_enable(AMVP_CTX *ctx);

/**
 * @brief amvp_cap_kdf108_enable() allows an application to specify a kdf cipher capability to be
 *        tested by the AMVP server. When the application enables a crypto capability, it also
 *        needs to specify a callback function that will be used by libamvp  when that crypto
 *        capability is needed during a test session.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kdf108_enable(AMVP_CTX *ctx);

/**
 * @brief amvp_cap_pbkdf_enable() allows an application to specify a kdf cipher capability to be
 *        tested by the AMVP server. When the application enables a crypto capability, it also
 *        needs to specify a callback function that will be used by libamvp  when that crypto
 *        capability is needed during a test session.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_pbkdf_enable(AMVP_CTX *ctx);

/**
 * @brief amvp_cap_kdf_tls12_enable() allows an application to specify a kdf cipher capability to
 *        be tested by the AMVP server. When the application enables a crypto capability, it also
 *        needs to specify a callback function that will be used by libamvp  when that crypto
 *        capability is needed during a test session.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kdf_tls12_enable(AMVP_CTX *ctx);

/**
 * @brief amvp_cap_kdf_tls13_enable() allows an application to specify a kdf cipher capability to
 *        be tested by the AMVP server. When the application enables a crypto capability, it also
 *        needs to specify a callback function that will be used by libamvp  when that crypto
 *        capability is needed during a test session.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kdf_tls13_enable(AMVP_CTX *ctx);

/**
 * @brief amvp_cap_kdf135_ssh_set_parm() allows an application to specify operational parameters
 *        to be used during a test session with the AMVP server. This function should be called
 *        after amvp_enable_kdf135_ssh_cap() to specify the parameters for the corresponding KDF.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cap AMVP_CIPHER enum value identifying the crypto capability, here it will always be
 *        AMVP_KDF135_SSH
 * @param method AMVP_KDF135_SSH_METHOD enum value specifying method type
 * @param param AMVP_HASH_ALG enum value
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kdf135_ssh_set_parm(AMVP_CTX *ctx,
                                         AMVP_CIPHER cap,
                                         AMVP_KDF135_SSH_METHOD method,
                                         AMVP_HASH_ALG param);


/**
 * @brief amvp_cap_kdf135_srtp_set_parm() allows an application to specify operational
 *        parameters to be used during a test session with the AMVP server. This function should be
 *        called after amvp_enable_kdf135_srtp_cap() to specify the parameters for the
 *        corresponding KDF.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cap AMVP_CIPHER enum value identifying the crypto capability, here it will always be
 *        AMVP_KDF135_SRTP
 * @param param amvp_cap_kdf135_srtp_set_parm enum value specifying parameter
 * @param value integer value for parameter
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kdf135_srtp_set_parm(AMVP_CTX *ctx,
                                          AMVP_CIPHER cap,
                                          AMVP_KDF135_SRTP_PARAM param,
                                          int value);

/**
 * @brief amvp_cap_kdf108_set_parm() allows an application to specify operational parameters to
 *        be used during a test session with the AMVP server. This function should be called after
 *        amvp_enable_kdf108_cap() to specify the parameters for the corresponding KDF.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param mode AMVP_KDF108_MODE enum value identifying the kdf108 mode
 * @param param AMVP_KDF108_PARM enum value specifying parameter
 * @param value integer value for parameter
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kdf108_set_parm(AMVP_CTX *ctx,
                                     AMVP_KDF108_MODE mode,
                                     AMVP_KDF108_PARM param,
                                     int value);

/**
 * @brief amvp_cap_kdf135_x942_set_parm() allows an application to specify operational
 *        parameters to be used during a test session with the AMVP server. This function should be
 *        called after amvp_cap_kdf135_x942_enable() to specify the parameters for the
 *        corresponding KDF.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param param AMVP_KDF135_X942_PARM enum value specifying parameter
 * @param value integer value for parameter
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kdf135_x942_set_parm(AMVP_CTX *ctx,
                                          AMVP_KDF135_X942_PARM param,
                                          int value);

/**
 * @brief amvp_cap_kdf135_x942_set_domain() allows an application to specify operational
 *        parameters to be used during a test session with the AMVP server. This function should be
 *        called after amvp_cap_kdf135_x942_enable() to specify the parameters for the
 *        corresponding KDF.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param param AMVP_KDF135_X942_PARM enum value identifying the X9.42 parameter
 * @param min integer minimum for domain parameter
 * @param max integer maximum for domain parameter
 * @param increment integer increment for domain parameter
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kdf135_x942_set_domain(AMVP_CTX *ctx,
                                             AMVP_KDF135_X942_PARM param,
                                             int min,
                                             int max,
                                             int increment);

/**
 * @brief amvp_enable_kdf135_x963_cap_param() allows an application to specify operational
 *        parameters to be used during a test session with the AMVP server. This function should be
 *        called after amvp_enable_kdf135_srtp_cap() to specify the parameters for the
 *        corresponding KDF.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param param AMVP_KDF135_X963_PARM enum value specifying parameter
 * @param value integer value for parameter. The acceptable hash algs are defined in an enum
 *        AMVP_KDF135_X963_HASH_VALS in the library
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kdf135_x963_set_parm(AMVP_CTX *ctx,
                                          AMVP_KDF135_X963_PARM param,
                                          int value);

/**
 * @brief amvp_cap_kdf135_snmp_set_parm() allows an application to specify operational
 *        parameters to be used during a test session with the AMVP server.  This function should
 *        be called after amvp_enable_kdf135_srtp_cap() to specify the parameters for the
 *        corresponding KDF.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param kcap AMVP_CIPHER enum value specifying parameter
 * @param param AMVP_KDF135_SNMP_PARAM enum value specifying parameter
 * @param value integer value for parameter
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kdf135_snmp_set_parm(AMVP_CTX *ctx,
                                          AMVP_CIPHER kcap,
                                          AMVP_KDF135_SNMP_PARAM param,
                                          int value);

/**
 * @brief amvp_enable_kdf135_snmp_engid_parm() allows an application to specify a custom engid to
 *        be used during a test session with the AMVP server. This function should be called after
 *        amvp_enable_kdf135_snmp_cap() to specify the parameters for the corresponding KDF.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param kcap AMVP_CIPHER enum value specifying parameter
 * @param engid a hexadecimal string representing engine ID
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kdf135_snmp_set_engid(AMVP_CTX *ctx,
                                           AMVP_CIPHER kcap,
                                           const char *engid);

/**
 * @brief amvp_enable_kdf135_ikev2_cap_param() allows an application to specify operational
 *        parameters to be used during a test session with the AMVP server.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param param AMVP_KDF135_IKEV2_PARM enum specifying parameter to enable. Here it is always
 *        AMVP_KDF_HASH_ALG. Other params should be enabled with
 *        amvp_enable_kdf135_ikev2_domain_param
 * @param value String value for parameter
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kdf135_ikev2_set_parm(AMVP_CTX *ctx,
                                           AMVP_KDF135_IKEV2_PARM param,
                                           int value);

/**
 * @brief amvp_enable_kdf135_ikev1_cap_param() allows an application to specify operational
 *        parameters to be used during a test session with the AMVP server.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param param AMVP_KDF135_IKEV1_PARM enum specifying parameter to enable. Here it is
 *        AMVP_KDF_HASH_ALG or AMVP_KDF_IKEv1_AUTH_METHOD. Other params should be enabled with
 *        amvp_enable_kdf135_ikev1_domain_param
 * @param value String value for parameter
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kdf135_ikev1_set_parm(AMVP_CTX *ctx,
                                           AMVP_KDF135_IKEV1_PARM param,
                                           int value);

/**
 * @brief amvp_enable_kdf135_ikev2_cap_len_param() allows an application to specify operational
 *        lengths to be used during a test session with the AMVP server.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param param AMVP_KDF135_IKEV2_PARM enum specifying parameter to enable.
 * @param value length
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kdf135_ikev2_set_length(AMVP_CTX *ctx,
                                             AMVP_KDF135_IKEV2_PARM param,
                                             int value);

/**
 * @brief amvp_enable_kdf135_ikev2_domain_param() allows an application to specify operational
 *        parameters to be used during a test session with the AMVP server. This function should be
 *        called after amvp_enable_kdf135_ikev2_cap() to specify the parameters for the
 *        corresponding KDF.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param param AMVP_KDF135_IKEV2_PARM enum value identifying the IKEv2 parameter
 * @param min integer minimum for domain parameter
 * @param max integer maximum for domain parameter
 * @param increment integer increment for domain parameter
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kdf135_ikev2_set_domain(AMVP_CTX *ctx,
                                             AMVP_KDF135_IKEV2_PARM param,
                                             int min,
                                             int max,
                                             int increment);

/**
 * @brief amvp_enable_kdf135_ikev1_set_domain() allows an application to specify operational
 *        parameters to be used during a test session with the AMVP server. This function should be
 *        called after amvp_cap_kdf135_ikev1_enable() to specify the parameters for the
 *        corresponding KDF.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param param AMVP_KDF135_IKEV1_PARM enum value identifying the IKEv1 parameter
 * @param min integer minimum for domain parameter
 * @param max integer maximum for domain parameter
 * @param increment integer increment for domain parameter
 *
 * @return AMVP_RESULT
 */

AMVP_RESULT amvp_cap_kdf135_ikev1_set_domain(AMVP_CTX *ctx,
                                             AMVP_KDF135_IKEV1_PARM param,
                                             int min,
                                             int max,
                                             int increment);

/**
 * @brief amvp_enable_kdf108_set_domain() allows an application to specify operational parameters
 *        to be used during a test session with the AMVP server. This function should be called
 *        after amvp_cap_kdf108_enable() to specify the parameters for the corresponding KDF.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param mode AMVP_KDF108_MODE enum value identifying the KDF108 mode
 * @param param AMVP_KDF108_PARM enum value identifying the KDF108 parameter
 * @param min integer minimum for domain parameter
 * @param max integer maximum for domain parameter
 * @param increment integer increment for domain parameter
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kdf108_set_domain(AMVP_CTX *ctx,
                                       AMVP_KDF108_MODE mode,
                                       AMVP_KDF108_PARM param,
                                       int min,
                                       int max,
                                       int increment);

/**
 * @brief amvp_enable_pbkdf_set_domain() allows an application to specify operational parameters to
 *        be used during a test session with the AMVP server. This function should be called after
 *        amvp_cap_pbkdf_enable() to specify the parameters for the corresponding KDF.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param param AMVP_PBKDF_PARM enum value identifying the PBKDF parameter
 * @param min integer minimum for domain parameter
 * @param max integer maximum for domain parameter
 * @param increment integer increment for domain parameter
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_pbkdf_set_domain(AMVP_CTX *ctx,
                                      AMVP_PBKDF_PARM param,
                                      int min, int max,
                                      int increment);

/**
 * @brief amvp_cap_pbkdf_set_parm() allows an application to specify operational parameters to be
 *        used during a test session with the AMVP server. This function should be called after
 *        amvp_cap_pbkdf_enable() to specify the parameters for the corresponding KDF.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param param AMVP_PBKDF_PARM enum value specifying parameter
 * @param value integer value for parameter
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_pbkdf_set_parm(AMVP_CTX *ctx,
                                    AMVP_PBKDF_PARM param,
                                    int value);

/**
 * @brief amvp_cap_kdf_tls12_set_parm() allows an application to specify operational parameters to
 *        be used during a test session with the AMVP server. This function should be called after
 *        amvp_cap_kdf_tls12_enable() to specify the parameters for the corresponding KDF.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param param AMVP_KDF_TLS12_PARM enum value specifying parameter
 * @param value integer value for parameter
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kdf_tls12_set_parm(AMVP_CTX *ctx,
                                        AMVP_KDF_TLS12_PARM param,
                                        int value);

/**
 * @brief amvp_cap_kdf_tls13_set_parm() allows an application to specify operational parameters to
 *        be used during a test session with the AMVP server. This function should be called after
 *        amvp_cap_kdf_tls13_enable() to specify the parameters for the corresponding KDF.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param param AMVP_KDF_TLS13_PARM enum value specifying parameter
 * @param value integer value for parameter
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_kdf_tls13_set_parm(AMVP_CTX *ctx,
                                        AMVP_KDF_TLS13_PARM param,
                                        int value);

AMVP_RESULT amvp_cap_safe_primes_enable(AMVP_CTX *ctx,
                                        AMVP_CIPHER cipher);

/**
 * @brief amvp_cap_safe_primes_set_parm() allows an application to specify operational
 *        parameters to be used for a given safe_primes alg during a test session with the AMVP
 *        server. This function should be called to enable crypto capabilities for safe_primes
 *        capabilities that will be tested by the AMVP server. This includes KEYGEN and KEYVER.
 *
 *        This function may be called multiple times to specify more than one crypto parameter
 *        value for the safe_primes algorithm. The AMVP_CIPHER value passed to this function should
 *        already have been setup by invoking amvp_cap_safe_primes_enable().
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability.
 * @param param AMVP_SAFE_PRIMES_PARAM enum value identifying the algorithm parameter that is being
 *        specified.
 * @param mode the value corresponding to the parameter being set, at present only generation mode
 *        is supported.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_safe_primes_set_parm(AMVP_CTX *ctx,
                                          AMVP_CIPHER cipher,
                                          AMVP_SAFE_PRIMES_PARAM param,
                                          AMVP_SAFE_PRIMES_MODE mode);



/**
 * @brief amvp_enable_prereq_cap() allows an application to specify a prerequisite for a cipher
 *        capability that was previously registered.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cipher AMVP_CIPHER enum value identifying the crypto capability that has a prerequisite
 * @param pre_req_cap AMVP_PREREQ_ALG enum identifying the prerequisite
 * @param value value for specified prerequisite
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cap_set_prereq(AMVP_CTX *ctx,
                                AMVP_CIPHER cipher,
                                AMVP_PREREQ_ALG pre_req_cap,
                                char *value);

/**
 * @brief amvp_create_test_session() creates a context that can be used to commence a test session
 *        with an AMVP server. This function should be called first to create a context that is
 *        used to manage all the API calls into libamvp. The context should be released after the
 *        test session has completed by invoking amvp_free_test_session().
 *
 *        When creating a new test session, a function pointer can be provided to receive logging
 *        messages from libamvp. The application can then forward the log messages to any logging
 *        service it desires, such as syslog.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param progress_cb Address of function to receive log messages from libamvp.
 * @param level The level of detail to use in logging, as defined by AMVP_LOG_LVL.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_create_test_session(AMVP_CTX **ctx,
                                     AMVP_RESULT (*progress_cb)(char *msg, AMVP_LOG_LVL level),
                                     AMVP_LOG_LVL level);

/**
 * @brief amvp_free_test_session() releases the memory associated withan AMVP_CTX. This function
 *        will free an AMVP_CTX. Failure to invoke this function will result in a memory leak in
 *        the application layer. This function should be invoked after a test session has completed
 *        and a reference to the context is no longer needed.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_free_test_session(AMVP_CTX *ctx);

/**
 * @brief amvp_set_server() specifies the AMVP server and TCP port number to use when contacting
 *        the server. This function is used to specify the hostname or IP address of the AMVP
 *        server. The TCP port number can also be specified if the server doesn't use port 443.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param server_name Name or IP address of the AMVP server.
 * @param port TCP port number the server listens on.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_set_server(AMVP_CTX *ctx, const char *server_name, int port);

/**
 * @brief amvp_set_path_segment() specifies the URI prefix used by the AMVP server. Some AMVP
 *        servers use a prefix in the URI for the path to the AMVP REST interface. Calling this
 *        function allows the path segment prefix to be specified. The value provided to this
 *        function is prepended to the path segment of the URI used for the AMVP REST calls.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param path_segment Value to embed in the URI path after the server name and before the AMVP
 *        well-known path.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_set_path_segment(AMVP_CTX *ctx, const char *path_segment);

/**
 * @brief amvp_set_cacerts() specifies PEM encoded certificates to use as the root trust anchors
 *        for establishing the TLS session with the AMVP server. AMVP uses TLS as the transport. In
 *        order to verify the identity of the AMVP server, the TLS stack requires one or more root
 *        certificates that can be used to verify the identify of the AMVP TLS certificate during
 *        the TLS handshake. These root certificates are set using this function. They must be PEM
 *        encoded and all contained in the same file.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param ca_file Name of file containing all the PEM encoded X.509 certificates used as trust
 *        anchors for the TLS session.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_set_cacerts(AMVP_CTX *ctx, const char *ca_file);

/**
 * @brief amvp_set_certkey() specifies PEM encoded certificate and private key to use for
 *        establishing the TLS session with the AMVP server. AMVP uses TLS as the transport. In
 *        order for the AMVP server to verify the identity the DUT using libamvp, a certificate
 *        needs to be presented during the TLS handshake. The certificate used by libamvp needs to
 *        be trusted by the AMVP server. Otherwise the TLS handshake will fail.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param cert_file Name of file containing the PEM encoded X.509 certificate to use as the client
 *        identity.
 * @param key_file Name of file containing PEM encoded private key associated with the client
 *        certificate.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_set_certkey(AMVP_CTX *ctx, char *cert_file, char *key_file);

/**
 * @brief amvp_mark_as_sample() marks the registration as a sample. This function sets a flag that
 *        will allow the client to retrieve the correct answers later on, allowing for comparison
 *        and debugging.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_mark_as_sample(AMVP_CTX *ctx);

/**
 * @brief amvp_mark_as_request_only() marks the registration as a request only. This function sets
 *         a flag that will allow the client to retrieve the vectors from the server and store them
 *         in a file for later use.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param filename Name of the file to be used for the request vectors
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_mark_as_request_only(AMVP_CTX *ctx, char *filename);

/**
 * @brief amvp_mark_as_get_only() marks the operation as a GET only. This function will take the
 *        string parameter and perform a GET to check the get of a specific request. The request ID
 *        must be part of the string.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param string used for the get, such as '/amvp/v1/requests/383'
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_mark_as_get_only(AMVP_CTX *ctx, char *string);

/**
 * @brief amvp_set_get_save_file() indicates a file to save get requests to. This function will
 *        only work if amvp_mark_as_get_only() has already been successfully called. It will take a
 *        string parameter for the location to save the results from the GET request indicated in
 *        amvp_mark_as_get_only() to as a file.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param filename location to save the GET results to (assumes data in JSON format)
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_set_get_save_file(AMVP_CTX *ctx, char *filename);

/**
 * @brief amvp_mark_as_post_only() marks the operation as a POST only. This function will take the
 *        filename and perform a POST of the data in the file to the URL
 *        /amvp/v1/(first field in file)
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param filename file containing URL and content to POST
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_mark_as_post_only(AMVP_CTX *ctx, char *filename);

/**
 * @brief amvp_mark_as_delete only() marks the operation as a DELETE only. This function will
 *        perform an HTTP DELETE call on the resource at the givenURL.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param request_url url of resource to delete
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_mark_as_delete_only(AMVP_CTX *ctx, char *request_url);

/**
 * @brief amvp_mark_as_put_after_test() will attempt to PUT the given file (with the URL inside)
 *        at the conclusion of a test session run with the given CTX.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param filename the path to the file to PUT after the test session
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_mark_as_put_after_test(AMVP_CTX *ctx, char *filename);

/**
 * @brief amvp_get_vector_set_count will return the number of vector sets that are expected based on the current
 * registration. This should be seen as a close estimate not an exact number, as different AMVP servers could
 * possibly have different behaviors.
 *
 * @param ctx Pointer to AMVP_CTX with registered algorithms
 *
 * @return Count of expected vector sets
 */
int amvp_get_vector_set_count(AMVP_CTX *ctx);

/**
 * @brief Performs the AMVP testing procedures.
 *        This function will do the following actions:
 *          1. Verify the provided metadata if user has specified \p fips_validation.
 *          2. Register a new testSession with the AMVP server with the capabilities attached to
 *             the \p ctx.
 *          3. Communicate with the AMVP server to acquire the test vectors, calculate the results
 *             and upload the results to the server.
 *          4. Check the results of each vector associated with the testSession. The success or
 *             failure information will be printed to stderr.
 *          5. Request that the AMVP server perform a FIPS validation (if \p fips_validation == 1
 *             and testSession is passed).
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param fips_validation A flag to indicate whether a fips validation is being performed on the
 *        test session
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_run(AMVP_CTX *ctx, int fips_validation);

AMVP_RESULT amvp_oe_ingest_metadata(AMVP_CTX *ctx, const char *metadata_file);

AMVP_RESULT amvp_oe_set_fips_validation_metadata(AMVP_CTX *ctx,
                                                 unsigned int module_id,
                                                 unsigned int oe_id);

AMVP_RESULT amvp_oe_module_new(AMVP_CTX *ctx,
                               unsigned int id,
                               const char *name);

AMVP_RESULT amvp_oe_module_set_type_version_desc(AMVP_CTX *ctx,
                                                 unsigned int id,
                                                 const char *type,
                                                 const char *version,
                                                 const char *description);

AMVP_RESULT amvp_oe_dependency_new(AMVP_CTX *ctx, unsigned int id);

AMVP_RESULT amvp_oe_oe_new(AMVP_CTX *ctx,
                           unsigned int id,
                           const char *oe_name);

AMVP_RESULT amvp_oe_oe_set_dependency(AMVP_CTX *ctx,
                                      unsigned int oe_id,
                                      unsigned int dependency_id);

/**
 * @brief amvp_set_json_filename specifies JSON registration file to be used during registration.
 *        This allows the app to skip the amvp_enable_* API calls
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param json_filename Name of the file that contains the JSON registration
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_set_json_filename(AMVP_CTX *ctx, const char *json_filename);

/**
 * @brief amvp_get_current_registration returns a string form of the currently registered set of capabilities. If a test
 * session has already begun it will use the session's submitted registration. If it has not yet begun, only the capabilities
 * registered thus far will be returrned.
 *
 * @param ctx The ctx to retrieve registration from
 * @param len An optional pointer to an integer for saving the length of the returned string
 * @return The string (char*) form of the current registration. The string must be later freed by the user.
 */
char *amvp_get_current_registration(AMVP_CTX *ctx, int *len);

/**
 * @brief amvp_load_kat_filename loads and processes JSON kat vector file This option will not
 *        communicate with the server at all.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param kat_filename Name of the file that contains the JSON kat vectors
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_load_kat_filename(AMVP_CTX *ctx, const char *kat_filename);

/**
 * @brief Uploads a set of vector set responses that were processed from an offline vector set JSON
 *        file.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param rsp_filename Name of the file that contains the completed vector set results
 * @param fips_validation Should be != 0 in case of fips validation (metadata must be provided)
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_upload_vectors_from_file(AMVP_CTX *ctx, const char *rsp_filename, int fips_validation);

/**
 * @brief Runs a set of tests from vector sets that were saved to a file and saves the results in a
 *        different file.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param req_filename Name of the file that contains the unprocessed vector sets
 * @param rsp_filename Name of the file to save vector set test results to
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_run_vectors_from_file(AMVP_CTX *ctx, const char *req_filename, const char *rsp_filename);

/**
 * @brief performs an HTTP PUT on a given libamvp JSON file to the ACV server
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param put_filename name of the file to PUT to the ACV server
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_put_data_from_file(AMVP_CTX *ctx, const char *put_filename);

/**
 * @brief Retrieves the results of an already-completed test session
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param request_filename File containing the session info created by libamvp
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_get_results_from_server(AMVP_CTX *ctx, const char *request_filename);

/**
 * @brief Gets the expected test results for test sessions marked as samples
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param request_filename File containing the session info created by libamvp
 * @param save_filename path/name for file to save the expected results too. OPTIONAL. If null,
 *        will print expected results to log.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_get_expected_results(AMVP_CTX *ctx, const char *request_filename, const char *save_filename);

/**
 * @brief Queries the server for any vector sets that have not received a response (e.x. in case of
 *        lose of connectivity during testing), downloads those vector sets, and continues to
 *        process them
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param request_filename File containing the session info created by libamvp
 * @param fips_validation Should be != 0 in case of fips validation (metadata must be provided)
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_resume_test_session(AMVP_CTX *ctx, const char *request_filename, int fips_validation);


/**
 * @brief Requests the server to cancel a test session and delete associated data
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param request_filename File containing the session info created by libamvp
 * @param save_filename OPTIONAL arugment indicated a file the server response can be saved to.
 *        Leave NULL if not applicable
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_cancel_test_session(AMVP_CTX *ctx, const char *request_filename, const char *save_filename);

/**
 * @brief amvp_set_2fa_callback() sets a callback function which will create or obtain a TOTP
 *        password for the second part of the two-factor authentication.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 * @param totp_cb Function that will get the TOTP password
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_set_2fa_callback(AMVP_CTX *ctx, AMVP_RESULT (*totp_cb)(char **token, int token_max));

/**
 * @brief amvp_bin_to_hexstr() Converts a binary string to hex
 *
 * @param src Pointer to the binary source string
 * @param src_len Length of source sting in bytes
 * @param dest Length of destination hex string
 * @param dest_max Maximum length allowed for destination
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_bin_to_hexstr(const unsigned char *src, int src_len, char *dest, int dest_max);

/**
 * @brief amvp_hexstr_to_bin() Converts a hex string to binary
 *
 * @param src Pointer to the hex source string
 * @param dest Length of destination binary string
 * @param dest_max Maximum length allowed for destination
 * @param converted_len the number of bytes converted (output length)
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_hexstr_to_bin(const char *src, unsigned char *dest, int dest_max, int *converted_len);

/**
 * @brief amvp_lookup_error_string() is a utility that returns a more descriptive string for an AMVP_RESULT
 *        error code
 *
 * @param rv AMVP_RESULT error code
 *
 * @return (char *) error string
 */
const char *amvp_lookup_error_string(AMVP_RESULT rv);

/**
 * @brief amvp_cleanup() extends the curl_global_cleanup function to applications using libamvp to
 *        perform cleanup of curl resources
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_create_test_session.
 *
 * @return AMVP_RESULT
 *
 */
AMVP_RESULT amvp_cleanup(AMVP_CTX *ctx);

/**
 * @brief amvp_version() fetch the library version string
 *
 * @return (char *) library string, formatted like: libamvp_oss-1.0.0
 */
const char *amvp_version(void);

/**
 * @brief amvp_protocol_version() fetch the protocol version string
 *
 * @return (char *) protocol version, formated like: 0.5
 */
const char *amvp_protocol_version(void);

AMVP_SUB_CMAC amvp_get_cmac_alg(AMVP_CIPHER cipher);
AMVP_SUB_KMAC amvp_get_kmac_alg(AMVP_CIPHER cipher);
AMVP_SUB_HASH amvp_get_hash_alg(AMVP_CIPHER cipher);
AMVP_SUB_AES amvp_get_aes_alg(AMVP_CIPHER cipher);
AMVP_SUB_TDES amvp_get_tdes_alg(AMVP_CIPHER cipher);
AMVP_SUB_HMAC amvp_get_hmac_alg(AMVP_CIPHER cipher);
AMVP_SUB_ECDSA amvp_get_ecdsa_alg(AMVP_CIPHER cipher);
AMVP_SUB_RSA amvp_get_rsa_alg(AMVP_CIPHER cipher);
AMVP_SUB_DSA amvp_get_dsa_alg(AMVP_CIPHER cipher);
AMVP_SUB_KDF amvp_get_kdf_alg(AMVP_CIPHER cipher);
AMVP_SUB_DRBG amvp_get_drbg_alg(AMVP_CIPHER cipher);
AMVP_SUB_KAS amvp_get_kas_alg(AMVP_CIPHER cipher);
AMVP_RESULT amvp_mod_cert_req(AMVP_CTX *ctx);
AMVP_RESULT amvp_mark_as_cert_req(AMVP_CTX *ctx, int module_id, int vendor_id);
AMVP_RESULT amvp_cert_req_add_contact(AMVP_CTX *ctx, const char *contact_id);
AMVP_RESULT amvp_create_module(AMVP_CTX *ctx, char *filename);
AMVP_RESULT amvp_get_module_request(AMVP_CTX *ctx, char *filename);
AMVP_RESULT amvp_submit_evidence(AMVP_CTX *ctx, const char *filename);
AMVP_RESULT amvp_submit_security_policy(AMVP_CTX *ctx, const char *filename);
AMVP_RESULT amvp_read_cert_req_info_file(AMVP_CTX *ctx, const char *filename);

AMVP_RESULT amvp_retrieve_docs(AMVP_CTX *ctx, char *vsid_url);
AMVP_RESULT amvp_mark_as_post_resources(AMVP_CTX *ctx, char *filename);
AMVP_RESULT amvp_post_resources(AMVP_CTX *ctx, const char *resource_file);

/** @} */
/** @internal ALL APIS SHOULD BE ADDED ABOVE THESE BLOCKS */

#ifdef __cplusplus
}
#endif
#endif
