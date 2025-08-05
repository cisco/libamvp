/** @file */
/*
 * Copyright (c) 2021, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libamvp/LICENSE
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <unistd.h>
#include "amvp.h"
#include "amvp_lcl.h"
#include "amvp_error.h"
#include "safe_lib.h"

#include <curl/curl.h>

/*
 * Basic logging for libamvp
 */
void amvp_log_msg(AMVP_CTX *ctx, AMVP_LOG_LVL level, const char *func, int line, const char *fmt, ...) {
    va_list arguments;
    int iter = 0, ret = 0;
    //One extra char for null terminator
    char tmp[AMVP_LOG_MAX_MSG_LEN + 1];
    tmp[AMVP_LOG_MAX_MSG_LEN] = '\0';

    if (!ctx) {
        return;
    }

    if (ctx->debug) {
        iter = snprintf(tmp, AMVP_LOG_MAX_MSG_LEN, "[%s:%d]: ", func, line);
    }

    if (ctx->test_progress_cb && (ctx->log_lvl >= level)) {
        /*  Pull the arguments from the stack and invoke the logger function */
        va_start(arguments, fmt);
        ret = vsnprintf(tmp + iter, AMVP_LOG_MAX_MSG_LEN + 1 - iter, fmt, arguments);
        if (ret < 0 || ret >= AMVP_LOG_MAX_MSG_LEN + 1 - iter) {
            memcpy_s(tmp + AMVP_LOG_MAX_MSG_LEN - AMVP_LOG_TRUNCATED_STR_LEN,
                     AMVP_LOG_TRUNCATED_STR_LEN,
                     AMVP_LOG_TRUNCATED_STR, AMVP_LOG_TRUNCATED_STR_LEN);
            tmp[AMVP_LOG_MAX_MSG_LEN] = '\0';
        } else {
            iter += ret;
            tmp[iter] = '\0';
        }
        ctx->test_progress_cb(tmp, level);
        va_end(arguments);
        fflush(stdout);
    }
}

/*
 * Sometimes there is a need for line separation in the logs, but we still prefer for
 * the app handler to deal with it instead of making assumptions about output
 */
void amvp_log_newline(AMVP_CTX *ctx) {
     char tmp[] = "\n";
     ctx->test_progress_cb(tmp, AMVP_LOG_LVL_STATUS);
 }

/*!
 *
 * @brief Free all memory in the libamvp library.
 *        Please use this before you application exits.
 *
 * The libamvp library allocates memory internally that needs
 * to be freed before the calling application exits. The user
 * of libamvp should ensure that this function is called upon
 * encountering an error, or successful program termination.
 *
 * Curl requires a cleanup function to be invoked when done.
 * We must extend this to our user, which is done here.
 * Our users shouldn't have to include curl.h.
 *
 * @param ctx Pointer to AMVP_CTX to be freed. May be NULL.
 *
 */
AMVP_RESULT amvp_cleanup(AMVP_CTX *ctx) {
    AMVP_RESULT rv = AMVP_SUCCESS;

    if (ctx) {
        /* Only call if ctx is not null */
        rv = amvp_free_test_session(ctx);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Failed to free parameter 'ctx'");
        }
    }
    curl_global_cleanup();
    return rv;
}

AMVP_RESULT amvp_create_response_obj(JSON_Object **obj, JSON_Value **val) {
    JSON_Value *tval = NULL;
    JSON_Object *tobj = NULL;

    tval = json_value_init_object();
    tobj = json_value_get_object(tval);
    if (!tobj) {
        return AMVP_JSON_ERR;
    }

    json_object_set_string(tobj, "amvVersion", AMVP_VERSION);
    *obj = tobj;
    *val = tval;
    return AMVP_SUCCESS;
}

AMVP_RESULT amvp_add_version_to_obj(JSON_Object *obj) {
    json_object_set_string(obj, "amvVersion", AMVP_VERSION);
    return AMVP_SUCCESS;
}

/*
 * This function returns a string that describes the error
 * code passed in.
 */
const char *amvp_lookup_error_string(AMVP_RESULT rv) {
    int i;
    struct amvp_result_desc_t error_desc_tbl[AMVP_RESULT_MAX - 1] = {
        { AMVP_MALLOC_FAIL,        "Error allocating memory"                          },
        { AMVP_NO_CTX,             "No valid context found"                           },
        { AMVP_TRANSPORT_FAIL,     "Error using transport library"                    },
        { AMVP_NO_DATA,            "Trying to use data but none was found"            },
        { AMVP_UNSUPPORTED_OP,     "Unsupported operation"                            },
        { AMVP_KAT_DOWNLOAD_RETRY, "Error, need to retry"                             },
        { AMVP_INVALID_ARG,        "Invalid argument"                                 },
        { AMVP_MISSING_ARG,        "Missing a required argument"                      },
        { AMVP_JSON_ERR,           "Error using JSON library"                         },
        { AMVP_TOTP_FAIL,          "Failed to base64 decode TOTP seed"                },
        { AMVP_CTX_NOT_EMPTY,      "ctx already initialized"                          },
        { AMVP_JWT_MISSING,        "Error using JWT"                                  },
        { AMVP_JWT_EXPIRED,        "Provided JWT has expired"                         },
        { AMVP_JWT_INVALID,        "Proivded JWT is not valid"                        },
        { AMVP_INTERNAL_ERR,       "Unexpected error occurred internally"              }
    };

    for (i = 0; i < AMVP_RESULT_MAX - 1; i++) {
        if (rv == error_desc_tbl[i].rv) {
            return error_desc_tbl[i].desc;
        }
    }
    return "Unknown error";
}

const char *amvp_lookup_sp_section_name(int id) {
    int i;
    struct amvp_sp_section_name_t section_name_tbl[AMVP_SP_SECTION_COUNT] = {
        {1, "General"},
        {2, "Cryptographic Module Specification"},
        {3, "Cryptographic Module Interfaces"},
        {4, "Roles, Services, and Authentication"},
        {5, "Software/Firmware Security"},
        {6, "Operational Environment"},
        {7, "Physical Security"},
        {8, "Non-invasive Security"},
        {9, "Sensitive Security Parameter Management"},
        {10, "Self Tests"},
        {11, "Life Cycle Assurance"},
        {12, "Mitigation of Other Attacks"}
    };
    for (i = 0; i < AMVP_SP_SECTION_COUNT; i++) {
        if (id == section_name_tbl[i].id) {
            return section_name_tbl[i].name;
        }
    }
    return "Unknown Section";
}


#define AMVP_UTIL_KV_STR_MAX 256

AMVP_RESULT amvp_kv_list_append(AMVP_KV_LIST **kv_list,
                                const char *key,
                                const char *value) {
    AMVP_KV_LIST *kv = NULL;

    if (kv_list == NULL || key == NULL || value == NULL) {
        return AMVP_INVALID_ARG;
    }
    if (!string_fits(key, AMVP_UTIL_KV_STR_MAX)) {
        return AMVP_INVALID_ARG;
    }
    if (!string_fits(value, AMVP_UTIL_KV_STR_MAX)) {
        return AMVP_INVALID_ARG;
    }

    if (*kv_list == NULL) {
        *kv_list = calloc(1, sizeof(AMVP_KV_LIST));
        if (*kv_list == NULL) return AMVP_MALLOC_FAIL;
        kv = *kv_list;
    } else {
        AMVP_KV_LIST *current = *kv_list;
        while (current->next) {
            current = current->next;
        }

        // Append the next entry
        current->next = calloc(1, sizeof(AMVP_KV_LIST));
        if (current->next == NULL) return AMVP_MALLOC_FAIL;
        kv = current->next;
    }

    kv->key = calloc(AMVP_UTIL_KV_STR_MAX + 1, sizeof(char));
    if (kv->key == NULL) return AMVP_MALLOC_FAIL;
    kv->value = calloc(AMVP_UTIL_KV_STR_MAX + 1, sizeof(char));
    if (kv->value == NULL) return AMVP_MALLOC_FAIL;

    strcpy_s(kv->key, AMVP_UTIL_KV_STR_MAX + 1, key);
    strcpy_s(kv->value, AMVP_UTIL_KV_STR_MAX + 1, value);

    return AMVP_SUCCESS;
}

void amvp_kv_list_free(AMVP_KV_LIST *kv_list) {
    AMVP_KV_LIST *tmp;

    while (kv_list) {
        tmp = kv_list;
        kv_list = kv_list->next;
        if (tmp->key) free(tmp->key);
        if (tmp->value) free(tmp->value);
        free(tmp);
    }
}

JSON_Object *amvp_get_obj_from_rsp(AMVP_CTX *ctx, JSON_Value *arry_val) {
    JSON_Object *obj = NULL;

    if (!ctx || !arry_val) {
        AMVP_LOG_ERR("Missing arguments");
        return NULL;
    }

    obj = json_value_get_object(arry_val);
    return obj;
}

void amvp_release_json(JSON_Value *r_vs_val,
                       JSON_Value *r_gval) {

    if (r_gval) json_value_free(r_gval);
    if (r_vs_val) json_value_free(r_vs_val);
}

/**
 * @brief Determine if the given \p string fits within the \p max_allowed length.
 *
 * Measure the length of the \p string to see whether it's length
 * (not including terminator) is <= \p max_allowed.
 *
 * @return 1 Length of \string <= \p max_allowed
 * @return 0 Length of \string > \p max_allowed
 * 
 */
int string_fits(const char *string, unsigned int max_allowed) {
    if (strnlen_s(string, max_allowed + 1) > max_allowed) {
        return 0;
    }

    return 1;
}

/*
 * Simple utility function to free a string
 * list.
 */
void amvp_free_str_list(AMVP_STRING_LIST **list) {
    AMVP_STRING_LIST *top = NULL;
    AMVP_STRING_LIST *tmp = NULL;

    if (list == NULL) return;
    top = *list;
    if (top == NULL) return;

    while (top) {
        if (top->string) free(top->string);
        tmp = top;
        top = top->next;
        free(tmp);
    }

    *list = NULL;
}

/**
 * Simple utility function to add an entry to a SL list. if the list is NULL, it is created
 * with the given entry being the first one.
 */
AMVP_RESULT amvp_append_sl_list(AMVP_SL_LIST **list, int length) {
    AMVP_SL_LIST *current = NULL;
    if (!list) {
        return AMVP_NO_DATA;
    }

    if (*list == NULL) {
        *list = calloc(1, sizeof(AMVP_SL_LIST));
        if (!*list) {
            return AMVP_MALLOC_FAIL;
        }
        (*list)->length = length;
        return AMVP_SUCCESS;
    }
    current = *list;
    while (current) {
        if (!current->next) {
            current->next = calloc(1, sizeof(AMVP_SL_LIST));
            if (!current->next) {
                return AMVP_MALLOC_FAIL;
            }
            current->next->length = length;
            return AMVP_SUCCESS;
        }
        current = current->next;
    }

    /* Code should never reach here */
    return AMVP_UNSUPPORTED_OP;
}

/**
 * Simple utility function to add an entry to a param list. if the list is NULL, it is created
 * with the given entry being the first one.
 */
AMVP_RESULT amvp_append_param_list(AMVP_PARAM_LIST **list, int param) {
    AMVP_PARAM_LIST *current = NULL;
    if (!list) {
        return AMVP_NO_DATA;
    }

    if (*list == NULL) {
        *list = calloc(1, sizeof(AMVP_PARAM_LIST));
        if (!*list) {
            return AMVP_MALLOC_FAIL;
        }
        (*list)->param = param;
        return AMVP_SUCCESS;
    }
    current = *list;
    while (current) {
        if (!current->next) {
            current->next = calloc(1, sizeof(AMVP_PARAM_LIST));
            if (!current->next) {
                return AMVP_MALLOC_FAIL;
            }
            current->next->param = param;
            return AMVP_SUCCESS;
        }
        current = current->next;
    }

    /* Code should never reach here */
    return AMVP_UNSUPPORTED_OP;
}

/**
 * Simple utility function to add a entry to a name list. If the list is NULL, it is created
 * with the given entry being the first one. Note the string is REFERENCED, not copied.
 * This function should be able to accomdate the removal of names from the list if needed in the
 * future; if a name is removed from the list but its node remains (with a NULL value) then
 * the given string will be added to the "dummy" node
 */
AMVP_RESULT amvp_append_name_list(AMVP_NAME_LIST **list, const char *string) {
    AMVP_NAME_LIST *current = NULL;
    if (!list) {
        return AMVP_NO_DATA;
    }

    if (!*list) {
        *list = calloc(1, sizeof(AMVP_NAME_LIST));
        if (!*list) {
            return AMVP_MALLOC_FAIL;
        }
    }
    current = *list;
    while (current) {
        if (!current->name) {
            current->name = string;
            return AMVP_SUCCESS;
        }
        if (!current->next) {
            current->next = calloc(1, sizeof(AMVP_NAME_LIST));
            if (!current->next) {
                return AMVP_MALLOC_FAIL;
            }
        }
        current = current->next;
    }
    /* Code should never reach here */
    return AMVP_UNSUPPORTED_OP;
}

/**
 * Check if a REFERENCE to a certain string already exists in a name list
 */
int amvp_is_in_name_list(AMVP_NAME_LIST *list, const char *string) {
    AMVP_NAME_LIST *current = NULL;
    if (!list) {
        return 0;
    }
    current = list;
    while (current) {
        if (current->name && current->name == string) {
            return 1;
        }
        current = current->next;
    }
    return 0;
}

/**
 * Simple utility function to add a string to a string list.
 * Note that the string is COPIED and not referenced.
 */
AMVP_RESULT amvp_append_str_list(AMVP_STRING_LIST **list, const char *string) {
    AMVP_STRING_LIST *current = NULL;
    AMVP_STRING_LIST *prev = NULL;
    char *word = NULL;

    if (!list) {
        return AMVP_NO_DATA;
    }

    int len = strnlen_s(string, AMVP_STRING_LIST_MAX_LEN);
    word = calloc(len + 1, sizeof(char));
    if (!word) {
        return AMVP_MALLOC_FAIL;
    }
    strncpy_s(word, len + 1, string, len);

    if (*list == NULL) {
        *list = calloc(1, sizeof(AMVP_STRING_LIST));
        if (*list == NULL) {
            free(word);
            return AMVP_MALLOC_FAIL;
        }
        (*list)->string = word;
        return AMVP_SUCCESS;
    } else {
        current = *list;
        while (current) {
            prev = current;
            current = current->next;
        }
        prev->next = calloc(1, sizeof(AMVP_STRING_LIST));
        if (!prev->next) {
            free(word);
            return AMVP_MALLOC_FAIL;
        }
        prev->next->string = word;
        return AMVP_SUCCESS;
    }

}

/**
 * Simple utility for looking to see if a string already exists
 * inside of a string list.
 */
int amvp_lookup_str_list(AMVP_STRING_LIST **list, const char *string) {
    AMVP_STRING_LIST *tmp = NULL;
    if (!list || *list == NULL || !string) {
        return 0;
    }
    tmp = *list;
    int diff = 1;
    int len1 = 0;
    int len2 = 0;
    int minlen = 0;
    while(tmp && tmp->string) {
        len1 = strnlen_s(tmp->string, AMVP_STRING_LIST_MAX_LEN);
        len2 = strnlen_s(string, AMVP_STRING_LIST_MAX_LEN);
        minlen = len1 < len2 ? len1 : len2;
        strncmp_s(tmp->string, len1, string, minlen, &diff);
        if (!diff) {
            return 1;
        }
        tmp = tmp->next;
    }
    return 0;
}

/**
 * Simple utility for searching if a value already exists in a
 * param list.
 */
int amvp_lookup_param_list(AMVP_PARAM_LIST *list, int value) {
    if (!list) {
        return 0;
    }
    while(list) {
        if (value == list->param) {
            return 1;
        } else {
            list = list->next;
        }
    }
    return 0;
}

/**
 * Checks if a domain value in a capability object has already been set
 * if all values are 0, then domain is considered empty
 * helps keep code cleaner in places where we woud need to reference
 * through several unions/pointers
 */
int amvp_is_domain_already_set(AMVP_JSON_DOMAIN_OBJ *domain) {
    return domain->min + domain->max + domain->increment;
}

AMVP_RESULT amvp_json_serialize_to_file_pretty_a(const JSON_Value *value, const char *filename) {
    AMVP_RESULT return_code = AMVP_SUCCESS;
    FILE *fp = NULL;
    char *serialized_string = NULL; 

    if (!filename) {
        return AMVP_INVALID_ARG;
    }

    fp = fopen(filename, "a");
    if (fp == NULL) {
        return AMVP_JSON_ERR;
    }
    if (!value) {
        if (fputs(" ]", fp) == EOF) {
            return_code = AMVP_JSON_ERR;
        }
    } else {

        serialized_string = json_serialize_to_string_pretty(value, NULL);
        if (serialized_string == NULL) {
            fclose(fp);
            return AMVP_JSON_ERR;
        }
        if (fputs(", ", fp) == EOF) {
            return_code = AMVP_JSON_ERR;
            goto end;
        }
        if (fputs(serialized_string, fp) == EOF) {
            return_code = AMVP_JSON_ERR;
        }
    }
end:
    if (fclose(fp) == EOF) {
        return_code = AMVP_JSON_ERR;
    }
    json_free_serialized_string(serialized_string);
    return return_code;
}

AMVP_RESULT amvp_json_serialize_to_file_pretty_w(const JSON_Value *value, const char *filename) {
    AMVP_RESULT return_code = AMVP_SUCCESS;
    FILE *fp = NULL;
    char *serialized_string = NULL;

    if (!value) {
        return AMVP_JSON_ERR;
    }
    if (!filename) {
        return AMVP_INVALID_ARG;
    }

    serialized_string = json_serialize_to_string_pretty(value, NULL);
    if (serialized_string == NULL) {
        return AMVP_JSON_ERR;
    }
    fp = fopen(filename, "w");
    if (fp == NULL) {
        json_free_serialized_string(serialized_string);
        return AMVP_JSON_ERR;
    }
    if (fputs("[ ", fp) == EOF) {
        return_code = AMVP_JSON_ERR;
        goto end;
    }
    if (fputs(serialized_string, fp) == EOF) {
        json_free_serialized_string(serialized_string);
        return_code = AMVP_JSON_ERR;
    }
end:
    if (fclose(fp) == EOF) {
        return_code = AMVP_JSON_ERR;
    }
    json_free_serialized_string(serialized_string);
    return return_code;
}

/*
 * Gets the status of a request from the curl buffer. If status is approved, store approved Url in the buffer 
 */
int amvp_get_request_status(AMVP_CTX *ctx, char **output) {
    JSON_Value *val = NULL;
    JSON_Object *obj = NULL;
    const char *stat = NULL, *other = NULL;
    char *out = NULL;
    int diff = 0, len = 0, rv = 0;

    val = json_parse_string(ctx->curl_buf);
    if (!val) return 0;
    obj = amvp_get_obj_from_rsp(ctx, val);
    if (!obj) goto end;
    stat = json_object_get_string(obj, "status");
    if (!stat) goto end;

    len = strnlen_s(stat, AMVP_REQUEST_STR_LEN_MAX + 1);
    if (len > AMVP_REQUEST_STR_LEN_MAX) return 0;

    strncmp_s(stat, len, "initial", 7, &diff);
    if (!diff) {
        rv = AMVP_REQUEST_STATUS_INITIAL;
        goto end;
    }

    strncmp_s(stat, len, "approved", 7, &diff);
    if (!diff) {
        other = json_object_get_string(obj, "approvedUrl");
        if (!other) {
            AMVP_LOG_ERR("Request has approved status, but is missing approved URL from server");
            goto end;
        }
        len = strnlen_s(other, AMVP_REQUEST_STR_LEN_MAX + 1);
        if (len > AMVP_REQUEST_STR_LEN_MAX) {
            AMVP_LOG_ERR("Approved URL string length too long");
            goto end;
        }
        out = calloc(len + 1, sizeof(char));
        if (!out) {
            AMVP_LOG_ERR("Unable to allocate memory for approved URL");
            goto end;
        }
        if (strncpy_s(out, len + 1, other, len)) {
            AMVP_LOG_ERR("Failure to copy approved URL");
            free(out);
            goto end;
        }

        *output = out;
        rv = AMVP_REQUEST_STATUS_APPROVED;
        goto end;
    }

    strncmp_s(stat, len, "rejected", 8, &diff);
    if (!diff) {
        rv = AMVP_REQUEST_STATUS_REJECTED;
        goto end;
    }

end:
    if (val) json_value_free(val);
    return rv;
}


/*
 * Simple utility function to free a supported length
 * list from the capabilities structure.
 */
void amvp_free_sl(AMVP_SL_LIST *list) {
    AMVP_SL_LIST *top = list;
    AMVP_SL_LIST *tmp;

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
void amvp_free_nl(AMVP_NAME_LIST *list) {
    AMVP_NAME_LIST *top = list;
    AMVP_NAME_LIST *tmp;

    while (top) {
        tmp = top;
        top = top->next;
        free(tmp);
    }
}


/*
 * This is a retry handler, which pauses for a specific time.
 * This allows the server time to generate the vectors on behalf of
 * the client and to process the vector responses. The caller of this function
 * can choose to implement a retry backoff using 'modifier'. Additionally, this
 * function will ensure that retry periods will sum to no longer than AMVP_MAX_WAIT_TIME.
 */
AMVP_RESULT amvp_retry_handler(AMVP_CTX *ctx, int *retry_period, unsigned int *waited_so_far, int modifier, AMVP_WAITING_STATUS situation) {
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
        AMVP_LOG_STATUS("Certification request session not yet ready, server requests we wait %u seconds and try again...", *retry_period);
    } else if (situation == AMVP_WAITING_FOR_RESULTS) {
        AMVP_LOG_STATUS("Results not ready, waiting %u seconds and trying again...", *retry_period);
    } else {
        AMVP_LOG_STATUS("Waiting %u seconds and trying again...", *retry_period);
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


static void amvp_generic_error_log(AMVP_CTX *ctx, AMVP_PROTOCOL_ERR *err) {
    AMVP_PROTOCOL_ERR_LIST *list = NULL;
    int i = 0;

    AMVP_LOG_ERR("Error(s) reported by server while attempting task.");
    AMVP_LOG_ERR("Category: %s", err->category_desc);
    AMVP_LOG_ERR("Error(s):");

    list = err->errors;
    while (list) {
        AMVP_LOG_ERR("    Code: %d", list->code);
        AMVP_LOG_ERR("    Messages:");
        for (i = 0; i < list->desc_count; i++) {
            AMVP_LOG_ERR("        %s", list->desc[i]);
        }
        list = list->next;
    }
}

/* Return AMVP_RETRY_OPERATION if we want the caller to try whatever task again */
AMVP_RESULT amvp_handle_protocol_error(AMVP_CTX *ctx, AMVP_PROTOCOL_ERR *err) {
    AMVP_PROTOCOL_ERR_LIST *list = NULL;
    AMVP_RESULT rv = AMVP_INTERNAL_ERR;

    if (!err) {
        return AMVP_MISSING_ARG;
    }
    list = err->errors;
    if (!list) {
        return AMVP_MISSING_ARG;
    }
    switch (err->category) {
    case AMVP_PROTOCOL_ERR_AUTH:
        while (list) {
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
                AMVP_LOG_STATUS("Attempting to refresh JWT and continue...");
                if (amvp_refresh(ctx) == AMVP_SUCCESS) {
                    AMVP_LOG_STATUS("JWT successfully refreshed. Trying again...");
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

    amvp_free_protocol_err(ctx->error);
    ctx->error = NULL;
    return rv;
}

int amvp_get_id_from_url(AMVP_CTX *ctx, const char *url) {
    int id = 0;

    sscanf(url, "/amvp/v1/certRequests/%d", &id);
    if (id <= 0) {
        AMVP_LOG_ERR("Unable to parse ID from URL: %s", url);
        return -1;
    }
    return id;
}

/** 
 * This function assumes the curl buffer has cert request status information.
 * It will overwrite the file if it already exists.
 */
AMVP_RESULT amvp_save_cert_req_info_file(AMVP_CTX *ctx, JSON_Object *contents) {
    char *file = NULL;
    AMVP_RESULT rv = AMVP_INTERNAL_ERR;
    int id = 0;
    const char *url = NULL;

    AMVP_LOG_STATUS("Saving session info to file...");

    url = json_object_get_string(contents, "url");
    if (!url) {
        AMVP_LOG_ERR("Error getting URL from cert request JSON");
        rv = AMVP_JSON_ERR;
        goto end;
    }
    id = amvp_get_id_from_url(ctx, url);
    if (id < 0) {
        AMVP_LOG_ERR("Error getting ID from URL");
        rv = AMVP_JSON_ERR;
        goto end;
    }
    json_object_set_string(contents, "accessToken", ctx->jwt_token);
    /* Create the name of the file we are saving info to */
    file = calloc(AMVP_CERT_REQUEST_FILENAME_MAX_LEN + 1, sizeof(char));
    if (!file) {
        AMVP_LOG_ERR("Error allocating memory for certify request filename");
        rv = AMVP_MALLOC_FAIL;
        goto end;
    }
    snprintf(file, AMVP_CERT_REQUEST_FILENAME_MAX_LEN + 1, "%s_%d.json", AMVP_CERT_REQUEST_FILENAME_DEFAULT, id);

    /* Save the payload to the file */
    rv = (json_serialize_to_file_pretty(json_object_get_wrapping_value(contents), file) == JSONSuccess ? AMVP_SUCCESS : AMVP_INTERNAL_ERR);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Failed to write module creation response to file!");
    } else {
        AMVP_LOG_STATUS("Successfully created cert request file %s", file);
    }

    rv = AMVP_SUCCESS;
end:
    return rv;
}
