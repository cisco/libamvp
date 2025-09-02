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

#define AMVP_MAX_ACV_CERTS_PER_CERT_REQ 5
#define AMVP_MAX_ESV_CERTS_PER_CERT_REQ 5
#define AMVP_CERT_STR_MAX_LEN 16

typedef enum amvp_cert_type {
    AMVP_CERT_TYPE_NONE = 0,
    AMVP_CERT_TYPE_ACV,
    AMVP_CERT_TYPE_ESV,
    AMVP_CERT_TYPE_AMV,
    AMVP_CERT_TYPE_MAX
} AMVP_CERT_TYPE;

typedef enum amvp_contact_type {
    AMVP_CONTACT_TYPE_TESTER = 0,
    AMVP_CONTACT_TYPE_REVIEWER,
    AMVP_CONTACT_TYPE_MAX
} AMVP_CONTACT_TYPE;

typedef enum amvp_evidence_type {
    AMVP_EVIDENCE_TYPE_NA = 0,
    AMVP_EVIDENCE_TYPE_FUNCTIONAL_TEST,
    AMVP_EVIDENCE_TYPE_SOURCE_CODE,
    AMVP_EVIDENCE_TYPE_OTHER_DOC,
    AMVP_EVIDENCE_TYPE_FSM,
    AMVP_EVIDENCE_TYPE_MAX
} AMVP_EVIDENCE_TYPE;

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
    AMVP_KAT_DOWNLOAD_RETRY, /**< Does not neccessarily indicate an error, but that data requested
                                  from server is not yet ready to be accessed */
    AMVP_RETRY_OPERATION,    /**< Indiciate to a caller to attempt to retry an operation */
    AMVP_INVALID_ARG,        /**< A provided argument or parameter is not valid for the given operation */
    AMVP_MISSING_ARG,        /**< A required argument or parameter is not provided/null/0 */
    AMVP_JSON_ERR,           /**< Error occurred attempting to parse JSON into data stuctures */
    AMVP_TOTP_FAIL,          /**< A failure occurred attempting to generate a TOTP */
    AMVP_CTX_NOT_EMPTY,      /**< Occurs specifically when an attempt is made to initialize a CTX that is already initialized */
    AMVP_JWT_MISSING,        /**< A JSON web token is missing from a file or from memory but was expected */
    AMVP_JWT_EXPIRED,        /**< The provided JWT was not accepted by the server because it is expired */
    AMVP_JWT_INVALID,        /**< A provided JSON web token is invalid due to its size, encoding, or contents */
    AMVP_INTERNAL_ERR,       /**< An unexpected error occuring internally to libamvp */
    AMVP_RESULT_MAX
} AMVP_RESULT;


/** @defgroup APIs Public APIs for libamvp
 *  @brief this section describes APIs for libamvp.
 */
/** @internal ALL APIS SHOULD BE ADDED UNDER THE INGORUP BLOCK. */
/** @ingroup APIs
 * @{
 */

/**
 * @brief amvp_init_cert_request() creates a context that can be used to commence a test session
 *        with an AMVP server. This function should be called first to create a context that is
 *        used to manage all the API calls into libamvp. The context should be released after the
 *        test session has completed by invoking amvp_free_test_session().
 *
 *        When creating a new test session, a function pointer can be provided to receive logging
 *        messages from libamvp. The application can then forward the log messages to any logging
 *        service it desires, such as syslog.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_init_cert_request.
 * @param progress_cb Address of function to receive log messages from libamvp.
 * @param level The level of detail to use in logging, as defined by AMVP_LOG_LVL.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_init_cert_request(AMVP_CTX **ctx,
                                     AMVP_RESULT (*progress_cb)(char *msg, AMVP_LOG_LVL level),
                                     AMVP_LOG_LVL level);

/**
 * @brief amvp_free_test_session() releases the memory associated withan AMVP_CTX. This function
 *        will free an AMVP_CTX. Failure to invoke this function will result in a memory leak in
 *        the application layer. This function should be invoked after a test session has completed
 *        and a reference to the context is no longer needed.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_init_cert_request.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_free_test_session(AMVP_CTX *ctx);

/**
 * @brief amvp_set_server() specifies the AMVP server and TCP port number to use when contacting
 *        the server. This function is used to specify the hostname or IP address of the AMVP
 *        server. The TCP port number can also be specified if the server doesn't use port 443.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_init_cert_request.
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
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_init_cert_request.
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
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_init_cert_request.
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
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_init_cert_request.
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
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_init_cert_request.
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_mark_as_sample(AMVP_CTX *ctx);

/**
 * @brief amvp_mark_as_get_only() marks the operation as a GET only. This function will take the
 *        string parameter and perform a GET to check the get of a specific request. The request ID
 *        must be part of the string.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_init_cert_request.
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
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_init_cert_request.
 * @param filename location to save the GET results to (assumes data in JSON format)
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_set_get_save_file(AMVP_CTX *ctx, char *filename);

/**
 * @brief amvp_mark_as_delete only() marks the operation as a DELETE only. This function will
 *        perform an HTTP DELETE call on the resource at the givenURL.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_init_cert_request.
 * @param request_url url of resource to delete
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_mark_as_delete_only(AMVP_CTX *ctx, char *request_url);

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
 * @brief amvp_set_2fa_callback() sets a callback function which will create or obtain a TOTP
 *        password for the second part of the two-factor authentication.
 *
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_init_cert_request.
 * @param totp_cb Function that will get the TOTP password
 *
 * @return AMVP_RESULT
 */
AMVP_RESULT amvp_set_2fa_callback(AMVP_CTX *ctx, AMVP_RESULT (*totp_cb)(char **token, int token_max));

/**
 * @brief amvp_decode_base64 converts a base64 encoded string into a byte buffer
 *
 * @param val the base64 string to decode
 * @param dest location to store output of decoded buffer
 *
 * @return the pointer to the buffer of the decoded string
 */
unsigned char* amvp_decode_base64(const char *val, unsigned int *output_len);

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
 * @param ctx Pointer to AMVP_CTX that was previously created by calling amvp_init_cert_request.
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

AMVP_RESULT amvp_check_cert_req_status(AMVP_CTX *ctx);
AMVP_RESULT amvp_mod_cert_req(AMVP_CTX *ctx);
AMVP_RESULT amvp_mark_as_cert_req(AMVP_CTX *ctx, const char *module_name, int vendor_id);
AMVP_RESULT amvp_cert_req_add_contact(AMVP_CTX *ctx, const char *contact_id, AMVP_CONTACT_TYPE contact_type);
AMVP_RESULT amvp_cert_req_add_sub_cert(AMVP_CTX *ctx, const char *cert_id, AMVP_CERT_TYPE type);
AMVP_RESULT amvp_get_module_request(AMVP_CTX *ctx, char *filename);
AMVP_RESULT amvp_submit_evidence(AMVP_CTX *ctx, const char *filename, AMVP_EVIDENCE_TYPE type);
AMVP_RESULT amvp_submit_security_policy(AMVP_CTX *ctx, const char *filename);
AMVP_RESULT amvp_submit_security_policy_template(AMVP_CTX *ctx, const char *filename);
AMVP_RESULT amvp_get_security_policy(AMVP_CTX *ctx);
AMVP_RESULT amvp_read_cert_req_info_file(AMVP_CTX *ctx, const char *filename);
AMVP_RESULT amvp_finalize_cert_request(AMVP_CTX *ctx);

AMVP_RESULT amvp_retrieve_docs(AMVP_CTX *ctx, char *vsid_url);

/** @} */
/** @internal ALL APIS SHOULD BE ADDED ABOVE THESE BLOCKS */

#ifdef __cplusplus
}
#endif
#endif
