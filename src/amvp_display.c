/*
 * Copyright (c) 2021, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libamvp/LICENSE
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "amvp.h"
#include "amvp_lcl.h"
#include "amvp_error.h"
#include "parson.h"
#include "safe_lib.h"

/* Helper function to get module name from ID */
static char* amvp_get_module_name_from_id(AMVP_CTX *ctx, int id) {
    char *url = NULL, *module_name = NULL;
    AMVP_RESULT rv = AMVP_SUCCESS;
    JSON_Value *val = NULL;
    JSON_Object *obj = NULL;

    url = calloc(AMVP_ATTR_URL_MAX + 1, sizeof(char));
    if (!url) {
        AMVP_LOG_ERR("Memory allocation error while fetching module name");
        goto end;
    }
    snprintf(url, AMVP_ATTR_URL_MAX + 1, "/amvp/v1/modules/%d", id);
    rv = amvp_transport_get(ctx, url, NULL);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Error fetching module name");
        goto end;
    }

    val = json_parse_string(ctx->curl_buf);
    if (!val) {
        AMVP_LOG_ERR("Error reading response when getting module name");
        goto end;
    }
    obj = amvp_get_obj_from_rsp(ctx, val);
    if (json_object_has_value(obj, AMVP_JSON_FIELD_NAME)) {
        module_name = calloc(AMVP_MAX_MODULE_NAME_LEN + 1, sizeof(char));
        if (!module_name) {
            AMVP_LOG_ERR("Error allocating memory for module name");
            goto end;
        }
        strncpy_s(module_name, AMVP_MAX_MODULE_NAME_LEN + 1, json_object_get_string(obj, AMVP_JSON_FIELD_NAME), json_object_get_string_len(obj, AMVP_JSON_FIELD_NAME));
    }

end:
    if (val) json_value_free(val);
    if (url) free(url);
    return module_name;
}

/* Data structure for test evidence table row */
typedef struct {
    char evidence_id[64];
    char status[32];
    char types_list[1024];
    int is_complete;
    int total_required;
    int submitted_required;
} amvp_evidence_row_t;

/* Helper function to format a single type with status symbol */
static void amvp_format_type_with_status(const char *type, int is_submitted, 
                                        char *output, size_t output_size, size_t *output_position) {
    const char *status_symbol = is_submitted ? "✓" : "✗";

    size_t remaining = output_size - *output_position;
    int written = snprintf(output + *output_position, remaining, "%s %s", type, status_symbol);
    if (written > 0 && (size_t)written < remaining) {
        *output_position += written;
    }
}

/* Helper function to process types array and build formatted string */
static AMVP_RESULT amvp_build_types_string(JSON_Array *types_arr, JSON_Array *submitted_arr, 
                                          int is_oneof, char *output, size_t output_size, 
                                          size_t *output_position, int *total_count, int *submitted_count) {
    if (!types_arr) return AMVP_SUCCESS;

    size_t num_types = json_array_get_count(types_arr);
    size_t num_submitted_files = submitted_arr ? json_array_get_count(submitted_arr) : 0;
    int group_is_submitted = (num_submitted_files > 0);

    /* Add separator if we already have content */
    if (*output_position > 0 && *output_position < output_size - 3) {
        strcpy_s(output + *output_position, output_size - *output_position, ", ");
        *output_position += 2;
    }

    if (is_oneof) {
        /* For oneOf groups, increment totals only once per group */
        (*total_count)++;
        if (group_is_submitted) (*submitted_count)++;

        /* For oneOf groups, format as "(type1 or type2) ✓" */
        if (num_types > 1) {
            if (*output_position < output_size - 1) {
                output[(*output_position)++] = '(';
            }

            for (size_t i = 0; i < num_types; i++) {
                const char *type = json_array_get_string(types_arr, i);
                if (!type) continue;

                if (i > 0) {
                    if (*output_position < output_size - 5) {
                        strcpy_s(output + *output_position, output_size - *output_position, " or ");
                        *output_position += 4;
                    }
                }

                size_t remaining = output_size - *output_position;
                int written = snprintf(output + *output_position, remaining, "%s", type);
                if (written > 0 && (size_t)written < remaining) {
                    *output_position += written;
                }
            }

            if (*output_position < output_size - 1) {
                output[(*output_position)++] = ')';
            }

            /* Add status symbol after the parentheses */
            const char *status_symbol = group_is_submitted ? " ✓" : " ✗";
            size_t remaining = output_size - *output_position;
            int written = snprintf(output + *output_position, remaining, "%s", status_symbol);
            if (written > 0 && (size_t)written < remaining) {
                *output_position += written;
            }
        } else if (num_types == 1) {
            /* Single oneOf type, just format as "type ✓" */
            const char *type = json_array_get_string(types_arr, 0);
            if (type) {
                amvp_format_type_with_status(type, group_is_submitted, output, output_size, output_position);
            }
        }
    } else {
        /* For required types, each type gets its own status */
        for (size_t i = 0; i < num_types; i++) {
            const char *type = json_array_get_string(types_arr, i);
            if (!type) continue;

            (*total_count)++;
            if (group_is_submitted) (*submitted_count)++;

            if (i > 0) {
                if (*output_position < output_size - 3) {
                    strcpy_s(output + *output_position, output_size - *output_position, ", ");
                    *output_position += 2;
                }
            }

            amvp_format_type_with_status(type, group_is_submitted, output, output_size, output_position);
        }
    }

    return AMVP_SUCCESS;
}

/* Helper function to populate a single evidence row */
static AMVP_RESULT amvp_populate_evidence_row(JSON_Object *evidence_obj, amvp_evidence_row_t *row) {
    AMVP_RESULT result = AMVP_SUCCESS;
    size_t output_position = 0;

    /* Clear the row */
    memset(row, 0, sizeof(amvp_evidence_row_t));

    /* Get basic info */
    const char *evidence_id = json_object_get_string(evidence_obj, AMVP_JSON_FIELD_TE);
    if (!evidence_id) return AMVP_INVALID_ARG;

    strcpy_s(row->evidence_id, sizeof(row->evidence_id), evidence_id);
    row->is_complete = json_object_get_boolean(evidence_obj, AMVP_JSON_FIELD_COMPLETE);

    /* Process required types */
    JSON_Array *required_arr = json_object_get_array(evidence_obj, AMVP_JSON_FIELD_REQUIRED);
    if (required_arr) {
        size_t num_required_groups = json_array_get_count(required_arr);
        for (size_t i = 0; i < num_required_groups; i++) {
            JSON_Object *required_group = json_array_get_object(required_arr, i);
            if (!required_group) continue;

            JSON_Array *types_arr = json_object_get_array(required_group, AMVP_JSON_FIELD_TYPES);
            JSON_Array *submitted_arr = json_object_get_array(required_group, AMVP_JSON_FIELD_SUBMITTED);

            result = amvp_build_types_string(types_arr, submitted_arr, 0, 
                                       row->types_list, sizeof(row->types_list), 
                                       &output_position, &row->total_required, &row->submitted_required);
            if (result != AMVP_SUCCESS) return result;
        }
    }

    /* Process oneOf types */
    JSON_Array *oneof_arr = json_object_get_array(evidence_obj, AMVP_JSON_FIELD_ONEOF);
    if (oneof_arr) {
        size_t num_oneof_groups = json_array_get_count(oneof_arr);
        for (size_t i = 0; i < num_oneof_groups; i++) {
            JSON_Object *oneof_group = json_array_get_object(oneof_arr, i);
            if (!oneof_group) continue;

            JSON_Array *types_arr = json_object_get_array(oneof_group, AMVP_JSON_FIELD_TYPES);
            JSON_Array *submitted_arr = json_object_get_array(oneof_group, AMVP_JSON_FIELD_SUBMITTED);

            result = amvp_build_types_string(types_arr, submitted_arr, 1, 
                                       row->types_list, sizeof(row->types_list), 
                                       &output_position, &row->total_required, &row->submitted_required);
            if (result != AMVP_SUCCESS) return result;
        }
    }

    /* Format status */
    if (row->is_complete) {
        strcpy_s(row->status, sizeof(row->status), "Complete");
    } else if (row->submitted_required > 0) {
        snprintf(row->status, sizeof(row->status), "Partial (%d/%d)", 
                row->submitted_required, row->total_required);
    } else {
        strcpy_s(row->status, sizeof(row->status), "Pending");
    }

    return AMVP_SUCCESS;
}

/* Function to output test evidence table */
static AMVP_RESULT amvp_output_test_evidence_table(AMVP_CTX *ctx, JSON_Array *te_array) {
    if (!ctx) return AMVP_INVALID_ARG;

    AMVP_LOG_NEWLINE;
    AMVP_LOG_STATUS("    Test Evidence Status:");

    /* Handle empty case */
    if (!te_array || json_array_get_count(te_array) == 0) {
        AMVP_LOG_STATUS(AMVP_ANSI_COLOR_GREEN "        All expected test evidence has been submitted!" AMVP_ANSI_COLOR_RESET);
        return AMVP_SUCCESS;
    }

    /* Output table header */
    AMVP_LOG_STATUS("        %-15s %-15s %s", "Test Evidence", "Status", "Required Types");
    AMVP_LOG_STATUS("        %-15s %-15s %s", "-------------", "------", "--------------");

    size_t arr_size = json_array_get_count(te_array);
    int has_incomplete = 0;

    /* Process each test evidence item */
    for (size_t i = 0; i < arr_size; i++) {
        JSON_Object *evidence_obj = json_array_get_object(te_array, i);
        if (!evidence_obj) continue;

        amvp_evidence_row_t row;
        AMVP_RESULT result = amvp_populate_evidence_row(evidence_obj, &row);
        if (result != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Failed to process test evidence row");
            continue;
        }

        if (!row.is_complete) has_incomplete = 1;

        /* Choose color based on status */
        const char *color = row.is_complete ? AMVP_ANSI_COLOR_GREEN : 
                           (row.submitted_required > 0 ? AMVP_ANSI_COLOR_YELLOW : AMVP_ANSI_COLOR_RED);

        /* Output the row */
        AMVP_LOG_STATUS("        %-15s %s%-15s" AMVP_ANSI_COLOR_RESET " %s", 
                       row.evidence_id, color, row.status,
                       strlen(row.types_list) > 0 ? row.types_list : "-");
    }

    /* Add summary message */
    AMVP_LOG_STATUS("        ");
    if (has_incomplete) {
        AMVP_LOG_STATUS("        " AMVP_ANSI_COLOR_YELLOW "Note: Some test evidence submissions are still pending." AMVP_ANSI_COLOR_RESET);
    } else {
        AMVP_LOG_STATUS("        " AMVP_ANSI_COLOR_GREEN "All test evidence requirements are complete!" AMVP_ANSI_COLOR_RESET);
    }

    return AMVP_SUCCESS;
}

/* Function to output prettified cert request status to log */
AMVP_RESULT amvp_output_cert_request_status(AMVP_CTX *ctx, JSON_Object *status_json) {
    JSON_Array *arr = NULL, *feedback = NULL;
    char *module_name = NULL;
    int request_id = 0, module_id = 0, vendor_id = 0, i = 0;
    size_t arr_size = 0;
    AMVP_RESULT result = AMVP_SUCCESS;
    AMVP_NAME_LIST *feedback_list = NULL, *feedback_iter = NULL;
    AMVP_CERT_REQ_STATUS cert_req_status = AMVP_CERT_REQ_STATUS_UNKNOWN;
    const char *cert_id = NULL;

    if (!ctx || !status_json) {
        return AMVP_INTERNAL_ERR;
    }

    cert_req_status = amvp_parse_cert_req_status_str(status_json);

    /* We want to collect all the information from JSON first, then output all at once so we have better control over output */
    if (json_object_has_value_of_type(status_json, AMVP_JSON_FIELD_URL, JSONString)) {
        sscanf(json_object_get_string(status_json, AMVP_JSON_FIELD_URL), "/amvp/v1/certRequests/%d", &request_id);
    } else if (json_object_has_value_of_type(status_json, AMVP_JSON_FIELD_CERT_REQUEST_ID, JSONNumber)) {
        request_id = (int) json_object_get_number(status_json, AMVP_JSON_FIELD_CERT_REQUEST_ID);
    }

    module_id = (int)json_object_get_number(status_json, AMVP_JSON_FIELD_MODULE_ID);
    module_name = amvp_get_module_name_from_id(ctx, module_id);
    if (!module_name) {
        AMVP_LOG_ERR("Error getting module name from cert request info");
        goto end;
    }

    if (json_object_has_value_of_type(status_json, AMVP_JSON_FIELD_VENDOR_ID, JSONNumber)) {
        vendor_id = (int)json_object_get_number(status_json, AMVP_JSON_FIELD_VENDOR_ID);
    }

    /* Begin prettified logging of data */
    AMVP_LOG_STATUS("");
    AMVP_LOG_STATUS("Current status of module certification request:");
    AMVP_LOG_STATUS(AMVP_ANSI_COLOR_GREEN "    Certification Request %d" AMVP_ANSI_COLOR_RESET, request_id);
    AMVP_LOG_STATUS(AMVP_ANSI_COLOR_GREEN "    Module ID: %d (%s)" AMVP_ANSI_COLOR_RESET, module_id, module_name);
    if (vendor_id) {
        AMVP_LOG_STATUS(AMVP_ANSI_COLOR_GREEN "    Vendor ID: %d" AMVP_ANSI_COLOR_RESET, vendor_id);
    }
    AMVP_LOG_STATUS("    Status:");
    switch (cert_req_status) {
    case AMVP_CERT_REQ_STATUS_INITIAL:
        AMVP_LOG_STATUS("        " AMVP_ANSI_COLOR_YELLOW "The cert request has not yet finished initializing." AMVP_ANSI_COLOR_RESET);
        goto end;
    case AMVP_CERT_REQ_STATUS_READY:
        AMVP_LOG_STATUS("        " AMVP_ANSI_COLOR_GREEN "The cert request is ready for data submissions!" AMVP_ANSI_COLOR_RESET);
        break;
    case AMVP_CERT_REQ_STATUS_SUBMITTED:
        AMVP_LOG_STATUS("        " AMVP_ANSI_COLOR_GREEN "All required data has been submitted!" AMVP_ANSI_COLOR_RESET);
        break;
    case AMVP_CERT_REQ_STATUS_IN_REVIEW:
        AMVP_LOG_STATUS("        " AMVP_ANSI_COLOR_YELLOW "The cert request is currently being reviewed." AMVP_ANSI_COLOR_RESET);
        goto end;
    case AMVP_CERT_REQ_STATUS_APPROVED:
        cert_id = json_object_get_string(status_json, AMVP_JSON_FIELD_VALIDATION_CERTIFICATE);
        if (!cert_id) {
            AMVP_LOG_ERR("Server marked request as approved, but failed to provide a certificate number");
            goto end;
        }
        AMVP_LOG_STATUS("        " AMVP_ANSI_COLOR_GREEN "The cert request has been approved!" AMVP_ANSI_COLOR_RESET);
        AMVP_LOG_STATUS("        " AMVP_ANSI_COLOR_GREEN "Certificate ID: %s" AMVP_ANSI_COLOR_RESET, cert_id);
        goto end;
    case AMVP_CERT_REQ_STATUS_REJECTED:
        AMVP_LOG_STATUS("        " AMVP_ANSI_COLOR_RED "The cert request has been rejected." AMVP_ANSI_COLOR_RESET);
        feedback = json_object_get_array(status_json, AMVP_JSON_FIELD_RULE_FEEDBACK);
        if (!feedback) {
            AMVP_LOG_ERR("Server marked request as rejected, but failed to provide reasoning");
            goto end;
        }
        arr_size = json_array_get_count(feedback);
        if (arr_size <= 0 || arr_size > 16) {
            AMVP_LOG_ERR("Server provided invalid feedback list (empty or too long)");
            goto end;
        }
        for (i = 0; i < (int)arr_size; i++) {
            amvp_append_name_list(&feedback_list, json_array_get_string(feedback, i));
        }
        AMVP_LOG_STATUS("        " AMVP_ANSI_COLOR_RED "Reasoning:" AMVP_ANSI_COLOR_RESET);
        feedback_iter = feedback_list;
        while (feedback_iter) {
            AMVP_LOG_STATUS(AMVP_ANSI_COLOR_RED "          %s" AMVP_ANSI_COLOR_RESET, feedback_iter->name);
            feedback_iter = feedback_iter->next;
        }
        break;
    case AMVP_CERT_REQ_STATUS_ERROR:
        AMVP_LOG_ERR("        " AMVP_ANSI_COLOR_RED "The cert request has encountered an error." AMVP_ANSI_COLOR_RESET);
        goto end;
    case AMVP_CERT_REQ_STATUS_UNKNOWN:
    default:
        AMVP_LOG_ERR("        " AMVP_ANSI_COLOR_RED "The cert request status is unknown." AMVP_ANSI_COLOR_RESET);
        goto end;
    }

    /* Get the test evidence status list */
    arr = json_object_get_array(status_json, AMVP_JSON_FIELD_EVIDENCE_LIST);
    if (!arr) {
        AMVP_LOG_ERR("Error getting evidence list from cert request info");
        goto end;
    }
    result = amvp_output_test_evidence_table(ctx, arr);
    if (result != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Error outputting test evidence table");
        goto end;
    }

    /* Get the security policy status information */
    AMVP_LOG_STATUS("");
    AMVP_LOG_STATUS("    Security Policy Status:");

    /* Check for missing SP template */
    if (json_object_has_value_of_type(status_json, AMVP_JSON_FIELD_MISSING_SP_TEMPLATE, JSONBoolean)) {
        int missing_sp_template = json_object_get_boolean(status_json, AMVP_JSON_FIELD_MISSING_SP_TEMPLATE);
        if (missing_sp_template) {
            AMVP_LOG_STATUS("        Security Policy Template: " AMVP_ANSI_COLOR_RED "Pending" AMVP_ANSI_COLOR_RESET);
        } else {
            AMVP_LOG_STATUS("        Security Policy Template: " AMVP_ANSI_COLOR_GREEN "Submitted" AMVP_ANSI_COLOR_RESET);
        }
    }

    /* Check for missing security policy submission */
    if (json_object_has_value_of_type(status_json, AMVP_JSON_FIELD_MISSING_SP_SUBMISSION, JSONBoolean)) {
        int missing_sp_submission = json_object_get_boolean(status_json, AMVP_JSON_FIELD_MISSING_SP_SUBMISSION);
        if (missing_sp_submission) {
            AMVP_LOG_STATUS("        Security Policy Data: " AMVP_ANSI_COLOR_RED "Pending" AMVP_ANSI_COLOR_RESET);
        } else {
            AMVP_LOG_STATUS("        Security Policy Data: " AMVP_ANSI_COLOR_GREEN "Submitted" AMVP_ANSI_COLOR_RESET);
        }
    }

    /* Parse and display security policy status */
    if (json_object_has_value_of_type(status_json, AMVP_JSON_FIELD_SP_STATUS, JSONString)) {
        const char *sp_status = json_object_get_string(status_json, AMVP_JSON_FIELD_SP_STATUS);
        if (sp_status) {
            /* TODO: Parse specific securityPolicyStatus values and provide appropriate messaging */
            /* Placeholder for different status values - add specific handling as needed */
            if (strcmp(sp_status, AMVP_SP_STATUS_PENDING) == 0) {
                AMVP_LOG_STATUS("        " AMVP_ANSI_COLOR_YELLOW "Waiting for security policy submissions." AMVP_ANSI_COLOR_RESET);
            } else if (strcmp(sp_status, AMVP_SP_STATUS_APPROVED) == 0) {
                AMVP_LOG_STATUS("        " AMVP_ANSI_COLOR_GREEN "Security policy has been approved." AMVP_ANSI_COLOR_RESET);
            } else if (strcmp(sp_status, AMVP_SP_STATUS_REJECTED) == 0) {
                AMVP_LOG_STATUS("        " AMVP_ANSI_COLOR_RED "Security policy has been rejected." AMVP_ANSI_COLOR_RESET);
            } else if (strcmp(sp_status, AMVP_SP_STATUS_INCOMPLETE) == 0) {
                AMVP_LOG_STATUS("        " AMVP_ANSI_COLOR_YELLOW "Security policy submission is incomplete." AMVP_ANSI_COLOR_RESET);
            } else {
                /* Unknown status - display as-is */
                AMVP_LOG_STATUS("        " AMVP_ANSI_COLOR_YELLOW "Security policy status: %s" AMVP_ANSI_COLOR_RESET, sp_status);
            }
        }
    }

    AMVP_LOG_STATUS("");

end:
    if (feedback_list) amvp_free_nl(feedback_list);
    if (module_name) free(module_name);
    return result;
}
