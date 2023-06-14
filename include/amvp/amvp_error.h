/**
 * @file
 * @brief This is the public header file to be included by applications
 *        using libamvp.
 */

/*
 * Copyright (c) 2023, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libamvp/LICENSE
 */

#ifndef amvp_error_h
#define amvp_error_h

#define AMVP_ERR_MSG_ARR_SIZE 2
#define AMVP_ERR_CATEGORY_STR "category"
#define AMVP_ERR_DESC_STR "description"
#define AMVP_ERR_ERR_STR "errors"
#define AMVP_ERR_CODE_STR "code"
#define AMVP_ERR_MSG_STR "messages"

#define AMVP_ERR_DESC_STR_MAX 256 /* Arbitrary */
#define AMVP_ERR_BUF_MAX 8192 /* Arbitrary */
#define AMVP_ERR_MAX_OBJECT_COUNT 100 /* Arbitrary */
#define AMVP_ERR_MAX_DESC_STRINGS 20 /* Arbitrary */

/* Begin protocol-defined codes for categories and errors */
typedef enum amvp_prot_error_cat {
    AMVP_PROTOCOL_ERR_GENERAL = 0,
    AMVP_PROTOCOL_ERR_AUTH = 1,
    AMVP_PROTOCOL_ERR_MALFORMED_PAYLOAD = 2,
    AMVP_PROTOCOL_ERR_INVALID_REQUEST = 3,
    AMVP_PROTOCOL_ERR_ON_SERVER = 4,
    AMVP_PROTOCOL_ERR_CAT_MAX
} AMVP_PROTOCOL_ERR_CATEGORY;

typedef enum amvp_prot_err_auth {
    AMVP_ERR_CODE_AUTH_MISSING_PW = 1,
    AMVP_ERR_CODE_AUTH_INVALID_JWT = 2,
    AMVP_ERR_CODE_AUTH_EXPIRED_JWT = 3,
    AMVP_ERR_CODE_AUTH_INVALID_PW = 4
} AMVP_ERR_CODE_AUTH;

/* End protocol-defined codes */

typedef struct amvp_prot_error_list {
    int code;
    char *desc[AMVP_ERR_MAX_DESC_STRINGS];
    int desc_count;
    struct amvp_prot_error_list *next;
} AMVP_PROTOCOL_ERR_LIST;

typedef struct amvp_protocol_error {
    AMVP_PROTOCOL_ERR_CATEGORY category;
    const char *category_desc;
    AMVP_PROTOCOL_ERR_LIST *errors;
} AMVP_PROTOCOL_ERR;

int amvp_is_protocol_error_message(const char *buf);
AMVP_PROTOCOL_ERR *amvp_parse_protocol_error(const char *buf);
int amvp_check_for_protocol_error(AMVP_PROTOCOL_ERR *err, AMVP_PROTOCOL_ERR_CATEGORY cat, int code);
void amvp_free_protocol_err(AMVP_PROTOCOL_ERR *err);

#endif
