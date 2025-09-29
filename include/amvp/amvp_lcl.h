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
#include "amvp_error.h"

#define AMVP_VERSION    "0.1"
#define AMVP_LIBRARY_VERSION_NUMBER "0.1.0"
#define AMVP_LIBRARY_VERSION    "libamvp_oss-0.1.0"

#define AMVP_DEFAULT_PATH_SEGMENT "/amvp/v1"

#ifndef AMVP_LOG_ERR
#define AMVP_LOG_ERR(msg, ...) do { \
        amvp_log_msg(ctx, AMVP_LOG_LVL_ERR, __func__, __LINE__, 0, msg, ##__VA_ARGS__); \
} while (0)
#endif

#ifndef AMVP_LOG_WARN
#define AMVP_LOG_WARN(msg, ...) do { \
        amvp_log_msg(ctx, AMVP_LOG_LVL_WARN, __func__, __LINE__, 0, msg, ##__VA_ARGS__); \
} while (0)
#endif

#ifndef AMVP_LOG_STATUS
#define AMVP_LOG_STATUS(msg, ...)  do { \
        amvp_log_msg(ctx, AMVP_LOG_LVL_STATUS, __func__, __LINE__, 0, msg, ##__VA_ARGS__); \
} while (0)
#endif

#ifndef AMVP_LOG_TABLE
#define AMVP_LOG_TABLE(msg, ...)  do { \
        amvp_log_msg(ctx, AMVP_LOG_LVL_STATUS, __func__, __LINE__, 1, msg, ##__VA_ARGS__); \
} while (0)
#endif

#ifndef AMVP_LOG_INFO
#define AMVP_LOG_INFO(msg, ...) do { \
        amvp_log_msg(ctx, AMVP_LOG_LVL_INFO, __func__, __LINE__, 0, msg, ##__VA_ARGS__); \
} while (0)
#endif

#ifndef AMVP_LOG_VERBOSE
#define AMVP_LOG_VERBOSE(msg, ...) do { \
        amvp_log_msg(ctx, AMVP_LOG_LVL_VERBOSE, __func__, __LINE__, 0, msg, ##__VA_ARGS__); \
} while (0)
#endif

#ifndef AMVP_LOG_DEBUG
#define AMVP_LOG_DEBUG(msg, ...) do { \
        amvp_log_msg(ctx, AMVP_LOG_LVL_DEBUG, __func__, __LINE__, 0, msg, ##__VA_ARGS__); \
} while (0)
#endif

#define AMVP_LOG_TRUNCATED_STR "...[truncated]"
//This MUST be the length of the above string (want to avoid calculating at runtime frequently)
#define AMVP_LOG_TRUNCATED_STR_LEN 14
#define AMVP_LOG_MAX_MSG_LEN 2048 /* 2 KiB */
#define AMVP_LOG_MAX_MSG_LEN_VERBOSE 4 * 1024 * 1024 /* 4 MiB */

#define AMVP_MODULE_FILENAME_MAX_LEN 32 /* Arbitrary */
#define AMVP_MODULE_FILENAME_DEFAULT "module"
#define AMVP_MODULE_ENDPOINT "modules"

#define AMVP_REQ_FILENAME_MAX_LEN 32 /* Arbitrary */
#define AMVP_REQ_FILENAME_DEFAULT "request"

#define AMVP_CERT_REQUEST_FILENAME_MAX_LEN 64 /* Arbitrary */
#define AMVP_CERT_REQUEST_FILENAME_DEFAULT "cert_request"

#define AMVP_REQ_STATUS_STR_INITIAL "initial"
#define AMVP_REQ_STATUS_STR_APPROVED "approved"

/* JSON field names for parsing */
#define AMVP_JSON_FIELD_NAME "name"
#define AMVP_JSON_FIELD_TE "te"
#define AMVP_JSON_FIELD_COMPLETE "complete"
#define AMVP_JSON_FIELD_REQUIRED "required"
#define AMVP_JSON_FIELD_ONEOF "oneOf"
#define AMVP_JSON_FIELD_TYPES "types"
#define AMVP_JSON_FIELD_SUBMITTED "submitted"
#define AMVP_JSON_FIELD_URL "url"
#define AMVP_JSON_FIELD_CERT_REQUEST_ID "certRequestId"
#define AMVP_JSON_FIELD_MODULE_ID "moduleId"
#define AMVP_JSON_FIELD_VENDOR_ID "vendorId"
#define AMVP_JSON_FIELD_VALIDATION_CERTIFICATE "validationCertificate"
#define AMVP_JSON_FIELD_RULE_FEEDBACK "ruleFeedback"
#define AMVP_JSON_FIELD_EVIDENCE_LIST "evidenceList"
#define AMVP_JSON_FIELD_MISSING_SP_TEMPLATE "missingSPTemplate"
#define AMVP_JSON_FIELD_MISSING_SP_SUBMISSION "missingSecurityPolicySubmission"
#define AMVP_JSON_FIELD_SP_STATUS "securityPolicyStatus"

/* Security policy status values */
#define AMVP_SP_STATUS_PENDING "acceptingSubmissions"
#define AMVP_SP_STATUS_APPROVED "approved"
#define AMVP_SP_STATUS_REJECTED "rejected"
#define AMVP_SP_STATUS_INCOMPLETE "incomplete"

#define AMVP_BIT2BYTE(x) ((x + 7) >> 3) /**< Convert bit length (x, of type integer) into byte length */

#define AMVP_CAPABILITY_STR_MAX 512 /**< Arbitrary string length limit */

#define AMVP_HEXSTR_MAX (AMVP_DRBG_ENTPY_IN_BIT_MAX >> 2) /**< Represents the largest hexstr that the client will accept.
                                                               Should always be set the the highest hexstr (i.e. bit length)
                                                               the the client will accept from server JSON string field */

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
#define AMVP_JSON_FILENAME_MAX 128

#define AMVP_PROTOCOL_VERSION_STR "amvVersion"

/* 
 * This should NOT be made longer than AMVP_JSON_FILENAME_MAX - 15
 * (accounting for _ character, ".json", and 9 digits for testSession ID)
 */
#define AMVP_SAVE_DEFAULT_PREFIX "testSession"

#define AMVP_CERT_REQ_STATUS_MAX_LEN 32
#define AMVP_CERT_REQ_STATUS_STR_INITIAL "initial"
#define AMVP_CERT_REQ_STATUS_STR_READY "ready"
#define AMVP_CERT_REQ_STATUS_STR_SUBMITTED "requirementsSubmitted"
#define AMVP_CERT_REQ_STATUS_STR_IN_REVIEW "inReview"
#define AMVP_CERT_REQ_STATUS_STR_APPROVED "approved"
#define AMVP_CERT_REQ_STATUS_STR_REJECTED "rejected"
#define AMVP_CERT_REQ_STATUS_STR_ERROR "error"

#define AMVP_SP_STATUS_STR_UNSUBMITTED "acceptingSubmissions"
#define AMVP_SP_STATUS_STR_PROCESSING "processingSubmission"
#define AMVP_SP_STATUS_STR_WAITING_GENERATION "pendingGeneration"
#define AMVP_SP_STATUS_STR_GENERATING "processingGeneration"
#define AMVP_SP_STATUS_STR_SUCCESS "success"
#define AMVP_SP_STATUS_STR_SUBMITTED "submitted"
#define AMVP_SP_STATUS_STR_ERROR "error"

#define AMVP_CERTIFY_ENDPOINT "certify"

#define AMVP_ANSI_COLOR_GREEN "\x1b[0;32m"
#define AMVP_ANSI_COLOR_YELLOW "\x1b[33m"
#define AMVP_ANSI_COLOR_RESET "\x1b[0m"
#define AMVP_ANSI_COLOR_RED "\x1b[31m"


#define AMVP_USER_AGENT_STR_MAX 255
//char cannot exist in any string for http user agent for parsing reasons
#define AMVP_USER_AGENT_DELIMITER ';'
#define AMVP_USER_AGENT_CHAR_REPLACEMENT '_';
#define AMVP_MAX_FILE_PAYLOAD_SIZE 1024 * 1024 * 64 /**< 64 MB */
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

/* Buffer size constants for test evidence table output */
#define AMVP_EVIDENCE_TYPES_BUFFER_SIZE 512
#define AMVP_EVIDENCE_ALL_TYPES_BUFFER_SIZE 1024
#define AMVP_EVIDENCE_STATUS_BUFFER_SIZE 64

#define AMVP_MAX_CONTACTS_PER_CERT_REQ 10
#define AMVP_CONTACT_STR_MAX_LEN 16

/*
 * If library cannot detect hardware or software info for HTTP user-agent string, we can check for them
 * in environmental variables, which are defined here
 */
#define AMVP_USER_AGENT_OSNAME_ENV "AMV_OE_OSNAME"
#define AMVP_USER_AGENT_OSVER_ENV "AMV_OE_OSVERSION"
#define AMVP_USER_AGENT_ARCH_ENV "AMV_OE_ARCHITECTURE"
#define AMVP_USER_AGENT_PROC_ENV "AMV_OE_PROCESSOR"
#define AMVP_USER_AGENT_COMP_ENV "AMV_OE_COMPILER"

#define AMVP_SP_SECTION_COUNT 12

struct amvp_result_desc_t {
    AMVP_RESULT rv;
    const char *desc;
};

struct amvp_sp_section_name_t {
    int id; /**< ID of the section */
    const char *name; /**< Name of the section */
};


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

typedef enum amvp_request_status {
    AMVP_REQUEST_STATUS_INITIAL = 1,
    AMVP_REQUEST_STATUS_APPROVED,
    AMVP_REQUEST_STATUS_REJECTED
} AMVP_REQUEST_STATUS;

typedef enum amvp_waiting_status {
    AMVP_WAITING_FOR_TESTS = 1,
    AMVP_WAITING_FOR_RESULTS,
} AMVP_WAITING_STATUS;

typedef enum amvp_cert_req_status {
    AMVP_CERT_REQ_STATUS_UNKNOWN = 1,
    AMVP_CERT_REQ_STATUS_INITIAL,
    AMVP_CERT_REQ_STATUS_READY,
    AMVP_CERT_REQ_STATUS_SUBMITTED,
    AMVP_CERT_REQ_STATUS_IN_REVIEW,
    AMVP_CERT_REQ_STATUS_APPROVED,
    AMVP_CERT_REQ_STATUS_REJECTED,
    AMVP_CERT_REQ_STATUS_ERROR
} AMVP_CERT_REQ_STATUS;

typedef enum amvp_sp_status {
    AMVP_SP_STATUS_UNKNOWN = 0,
    AMVP_SP_STATUS_UNSUBMITTED,
    AMVP_SP_STATUS_PROCESSING,
    AMVP_SP_STATUS_WAITING_GENERATION,
    AMVP_SP_STATUS_GENERATING,
    AMVP_SP_STATUS_SUCCESS,
    AMVP_SP_STATUS_ERROR
} AMVP_SP_STATUS;

typedef struct amvp_cert_req_t {
    char module_file[AMVP_JSON_FILENAME_MAX + 1];
    int vendor_id;
    int tester_count;
    int reviewer_count;
    int acv_cert_count;
    int esv_cert_count; 
    char *tester_id[AMVP_MAX_CONTACTS_PER_CERT_REQ];
    char *reviewer_id[AMVP_MAX_CONTACTS_PER_CERT_REQ];
    char *acv_cert[AMVP_MAX_ACV_CERTS_PER_CERT_REQ];
    char *esv_cert[AMVP_MAX_ESV_CERTS_PER_CERT_REQ];
} AMVP_CERT_REQ;

typedef enum amvp_action {
    AMVP_ACTION_UNSET = 0,
    AMVP_ACTION_GET,
    AMVP_ACTION_POST,
    AMVP_ACTION_PUT,
    AMVP_ACTION_DELETE,
    AMVP_ACTION_CERT_REQ,
    AMVP_ACTION_SUBMIT_CRSESSION_RESPONSES,
    AMVP_ACTION_NA
} AMVP_ACTION;

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
    int server_port;
    char *cacerts_file;     /* Location of CA certificates Curl will use to verify peer */
    int verify_peer;        /* enables TLS peer verification via Curl */
    char *tls_cert;         /* Location of PEM encoded X509 cert to use for TLS client auth */
    char *tls_key;          /* Location of PEM encoded priv key to use for TLS client auth */

    char *http_user_agent;   /* String containing info to be sent with HTTP requests, currently OE info */
    char *session_file_path; /* String containing the path of the testSession file after it is created when applicable */

    AMVP_STRING_LIST *vsid_url_list;
    char *session_url;
    int session_file_has_te_list;

    AMVP_ACTION action;

    char *get_string;       /* string used for get  request */
    char *delete_string;    /* string used for delete request */
    char *save_filename;    /* string used for file to save certain HTTP requests to */
    char *mod_cert_req_file;    /* string used for file to save certain HTTP requests to */

    AMVP_CERT_REQ cert_req_info; /* Stores info related to a cert request */

    /* test session data */
    char *jwt_token; /* access_token provided by server for authenticating REST calls */
    char *tmp_jwt; /* access_token provided by server for authenticating a single REST call */
    int use_tmp_jwt; /* 1 if the tmp_jwt should be used */
    JSON_Value *registration; /* The capability registration string sent when creating a test session */

    /* application callbacks */
    AMVP_RESULT (*test_progress_cb) (char *msg, AMVP_LOG_LVL level);

    /* Two-factor authentication callback */
    AMVP_RESULT (*totp_cb) (char **token, int token_max);

    JSON_Value *kat_resp; /* holds the current set of vector responses */

    char *curl_buf;       /**< Data buffer for inbound Curl messages */
    int curl_read_ctr;    /**< Total number of bytes written to the curl_buf */
    int post_size_constraint;  /**< The number of bytes that the body of an HTTP POST may contain
                                    without requiring the use of the /large endpoint. If the POST body
                                    is larger than this value, then use of the /large endpoint is necessary */
    AMVP_PROTOCOL_ERR *error; /**< Object to store info related to protocol error. Should be freed and set null when handled */
};

/* Network action types for transport layer */
typedef enum amvp_net_action {
    AMVP_NET_GET = 1, /**< Generic (get) */
    AMVP_NET_POST,    /**< Generic (post) */
    AMVP_NET_PUT,     /**< Generic (put) */
    AMVP_NET_POST_MULTIPART, /**< Multipart form-data (post) */
    AMVP_NET_DELETE   /**< delete vector set results, data */
} AMVP_NET_ACTION;

AMVP_RESULT amvp_send_login(AMVP_CTX *ctx, char *login, int len);
AMVP_RESULT amvp_refresh(AMVP_CTX *ctx);

AMVP_RESULT amvp_send_evidence(AMVP_CTX *ctx, AMVP_EVIDENCE_TYPE type, const char *url, char *ev, int ev_len);
AMVP_RESULT amvp_request_security_policy_generation(AMVP_CTX *ctx, const char *url, char *data);
AMVP_RESULT amvp_send_security_policy(AMVP_CTX *ctx, const char *url, char *sp, int sp_len);
AMVP_RESULT amvp_get_security_policy_json(AMVP_CTX *ctx, const char *url, JSON_Value **result);

AMVP_RESULT amvp_network_action(AMVP_CTX *ctx, AMVP_NET_ACTION action, const char *endpoint_path, const char *data, int data_len);
AMVP_RESULT amvp_transport_get(AMVP_CTX *ctx, const char *endpoint_path);
AMVP_RESULT amvp_transport_post(AMVP_CTX *ctx, const char *endpoint_path, const char *data, int data_len);
AMVP_RESULT amvp_transport_put(AMVP_CTX *ctx, const char *endpoint_path, const char *data, int data_len);
AMVP_RESULT amvp_transport_delete(AMVP_CTX *ctx, const char *endpoint_path);
AMVP_RESULT amvp_transport_post_multipart_form(AMVP_CTX *ctx, const char *endpoint_path, const char *file_path);
AMVP_RESULT amvp_send_sp_template(AMVP_CTX *ctx, const char *url, const char *file_path);

AMVP_RESULT amvp_build_registration_json(AMVP_CTX *ctx, JSON_Value **reg);
AMVP_RESULT amvp_create_response_obj(JSON_Object **obj, JSON_Value **val);
AMVP_RESULT amvp_add_version_to_obj(JSON_Object *obj);
JSON_Object *amvp_get_obj_from_rsp(AMVP_CTX *ctx, JSON_Value *arry_val);
void amvp_release_json(JSON_Value *r_vs_val, JSON_Value *r_gval);

AMVP_RESULT amvp_verify_fips_validation_metadata(AMVP_CTX *ctx);

void amvp_log_msg(AMVP_CTX *ctx, AMVP_LOG_LVL level, const char *func, int line, int use_large_buffer, const char *format, ...);

AMVP_RESULT amvp_kv_list_append(AMVP_KV_LIST **kv_list, const char *key, const char *value);
void amvp_kv_list_free(AMVP_KV_LIST *kv_list);
void amvp_free_str_list(AMVP_STRING_LIST **list);
AMVP_RESULT amvp_append_sl_list(AMVP_SL_LIST **list, int length);
AMVP_RESULT amvp_append_param_list(AMVP_PARAM_LIST **list, int param);
AMVP_RESULT amvp_append_name_list(AMVP_NAME_LIST **list, const char *string);
AMVP_RESULT amvp_append_str_list(AMVP_STRING_LIST **list, const char *string);
int amvp_is_in_name_list(AMVP_NAME_LIST *list, const char *string);
int amvp_lookup_str_list(AMVP_STRING_LIST **list, const char *string);
int amvp_lookup_param_list(AMVP_PARAM_LIST *list, int value);
int amvp_is_domain_already_set(AMVP_JSON_DOMAIN_OBJ *domain);
void amvp_free_sl(AMVP_SL_LIST *list);
void amvp_free_nl(AMVP_NAME_LIST *list);

unsigned char* amvp_decode_base64(const char *val, unsigned int *output_len);

int string_fits(const char *string, unsigned int max_allowed);
void amvp_http_user_agent_handler(AMVP_CTX *ctx);
const char *amvp_lookup_sp_section_name(int id);

AMVP_RESULT amvp_retry_handler(AMVP_CTX *ctx, int *retry_period, unsigned int *waited_so_far, int modifier, AMVP_WAITING_STATUS situation);
AMVP_RESULT amvp_handle_protocol_error(AMVP_CTX *ctx, AMVP_PROTOCOL_ERR *err);
int amvp_get_request_status(AMVP_CTX *ctx, char **output);

AMVP_RESULT amvp_save_cert_req_info_file(AMVP_CTX *ctx, JSON_Object *contents);
AMVP_RESULT amvp_json_serialize_to_file_pretty_a(const JSON_Value *value, const char *filename);
AMVP_RESULT amvp_json_serialize_to_file_pretty_w(const JSON_Value *value, const char *filename);

/* Display/output functions */
AMVP_RESULT amvp_output_cert_request_status(AMVP_CTX *ctx, JSON_Object *status_json);

/* Utility functions */
AMVP_CERT_REQ_STATUS amvp_parse_cert_req_status_str(JSON_Object *json);

/* Transport utility functions */
AMVP_RESULT sanity_check_ctx(AMVP_CTX *ctx);
AMVP_RESULT inspect_http_code(AMVP_CTX *ctx, int code);
void log_network_status(AMVP_CTX *ctx, AMVP_NET_ACTION action, int http_code, const char *url);
char* url_encode_parameter(const char *param);
void amvp_http_user_agent_handler(AMVP_CTX *ctx);
AMVP_RESULT execute_network_action(AMVP_CTX *ctx, AMVP_NET_ACTION action, const char *url, const char *data,
                                   int data_len, int *curl_code);

/* Centralized endpoint functions - single entry points for protocol operations */
AMVP_RESULT amvp_get_session_status(AMVP_CTX *ctx, JSON_Value **result);
AMVP_RESULT amvp_submit_cert_request(AMVP_CTX *ctx, const char *request_data, int data_len);
AMVP_RESULT amvp_send_cert_finalization(AMVP_CTX *ctx);
AMVP_RESULT amvp_get_module_info(AMVP_CTX *ctx, int module_id, JSON_Value **result);
AMVP_RESULT amvp_send_get_request(AMVP_CTX *ctx, const char *endpoint_path);

/* Utility functions */
const char *amvp_lookup_evidence_type_string(AMVP_EVIDENCE_TYPE type);

/* Internal validation functions */
AMVP_RESULT amvp_validate_contact_id(const char *id);
AMVP_RESULT amvp_validate_acv_cert_id(const char *id);
AMVP_RESULT amvp_validate_esv_cert_id(const char *id);

#endif
