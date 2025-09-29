/*
 * Copyright (c) 2025, Cisco Systems, Inc.
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

/* Buffer size defines for display messages */
#define AMVP_DISPLAY_TABLE_MSG_MAX    (5 * 1024 * 1024)  /* 5 MiB for table output */
#define AMVP_DISPLAY_STATUS_MSG_MAX   (512 * 1024)       /* 0.5 MiB for status messages */
#define AMVP_DISPLAY_SP_MSG_MAX       (512 * 1024)       /* 0.5 MiB for security policy messages */

/* Helper function to get module name from ID */
static char* amvp_get_module_name_from_id(AMVP_CTX *ctx, int id) {
    char *module_name = NULL;
    AMVP_RESULT rv = AMVP_SUCCESS;
    JSON_Value *val = NULL;
    JSON_Object *obj = NULL;

    rv = amvp_get_module_info(ctx, id, &val);
    if (rv != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Error fetching module name");
        goto end;
    }

    if (!val) {
        AMVP_LOG_ERR("No JSON data received when getting module name");
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
    return module_name;
}

/* Helper function to parse basic cert request info */
static AMVP_RESULT amvp_parse_cert_request_basic_info(JSON_Object *status_json,
                                                     int *request_id, int *module_id, int *vendor_id) {
    double temp = 0.0;

    *request_id = 0;
    *module_id = 0;
    *vendor_id = 0;

    if (json_object_has_value_of_type(status_json, AMVP_JSON_FIELD_URL, JSONString)) {
        sscanf(json_object_get_string(status_json, AMVP_JSON_FIELD_URL), "/amvp/v1/certRequests/%d", request_id);
    } else if (json_object_has_value_of_type(status_json, AMVP_JSON_FIELD_CERT_REQUEST_ID, JSONNumber)) {
        temp = json_object_get_number(status_json, AMVP_JSON_FIELD_CERT_REQUEST_ID);
        *request_id = (int)temp;
    }

    temp = json_object_get_number(status_json, AMVP_JSON_FIELD_MODULE_ID);
    *module_id = (int)temp;

    if (json_object_has_value_of_type(status_json, AMVP_JSON_FIELD_VENDOR_ID, JSONNumber)) {
        temp = json_object_get_number(status_json, AMVP_JSON_FIELD_VENDOR_ID);
        *vendor_id = (int)temp;
    }

    return AMVP_SUCCESS;
}

/* Helper function to parse security policy status info */
static void amvp_parse_sp_status_info(JSON_Object *status_json,
                                     int *missing_sp_template, int *missing_sp_submission,
                                     const char **sp_status) {
    *missing_sp_template = 0;
    *missing_sp_submission = 0;
    *sp_status = NULL;

    if (json_object_has_value_of_type(status_json, AMVP_JSON_FIELD_MISSING_SP_TEMPLATE, JSONBoolean)) {
        *missing_sp_template = json_object_get_boolean(status_json, AMVP_JSON_FIELD_MISSING_SP_TEMPLATE);
    }
    if (json_object_has_value_of_type(status_json, AMVP_JSON_FIELD_MISSING_SP_SUBMISSION, JSONBoolean)) {
        *missing_sp_submission = json_object_get_boolean(status_json, AMVP_JSON_FIELD_MISSING_SP_SUBMISSION);
    }
    if (json_object_has_value_of_type(status_json, AMVP_JSON_FIELD_SP_STATUS, JSONString)) {
        *sp_status = json_object_get_string(status_json, AMVP_JSON_FIELD_SP_STATUS);
    }
}

/* Function to output overall cert request status */
static AMVP_RESULT amvp_output_overall_status(AMVP_CTX *ctx, JSON_Object *status_json,
                                             int request_id, int module_id, int vendor_id,
                                             const char *module_name) {
    AMVP_CERT_REQ_STATUS cert_req_status;
    const char *cert_id = NULL;
    const char *status_color = NULL;
    const char *status_text = NULL;
    AMVP_NAME_LIST *feedback_list = NULL, *feedback_iter = NULL;
    JSON_Array *feedback = NULL;
    size_t arr_size = 0;
    int i = 0;

    cert_req_status = amvp_parse_cert_req_status_str(status_json);

    /* Determine status color and text for all cases */
    switch (cert_req_status) {
    case AMVP_CERT_REQ_STATUS_APPROVED:
        cert_id = json_object_get_string(status_json, AMVP_JSON_FIELD_VALIDATION_CERTIFICATE);
        if (!cert_id) {
            AMVP_LOG_ERR("Server marked request as approved, but failed to provide a certificate number");
            return AMVP_INVALID_ARG;
        }
        status_color = AMVP_ANSI_COLOR_GREEN;
        status_text = "The cert request has been approved!";
        break;
    case AMVP_CERT_REQ_STATUS_INITIAL:
        status_color = AMVP_ANSI_COLOR_YELLOW;
        status_text = "The cert request has not yet finished initializing.";
        break;
    case AMVP_CERT_REQ_STATUS_READY:
        status_color = AMVP_ANSI_COLOR_GREEN;
        status_text = "The cert request is ready for data submissions!";
        break;
    case AMVP_CERT_REQ_STATUS_SUBMITTED:
        status_color = AMVP_ANSI_COLOR_GREEN;
        status_text = "All required data has been submitted! Awaiting finalization of cert request by user.";
        break;
    case AMVP_CERT_REQ_STATUS_IN_REVIEW:
        status_color = AMVP_ANSI_COLOR_YELLOW;
        status_text = "The cert request is currently being reviewed. Check back later.";
        break;
    case AMVP_CERT_REQ_STATUS_REJECTED:
        status_color = AMVP_ANSI_COLOR_RED;
        status_text = "The cert request has been rejected.";
        break;
    case AMVP_CERT_REQ_STATUS_ERROR:
        status_color = AMVP_ANSI_COLOR_RED;
        status_text = "The cert request has encountered an error.";
        break;
    case AMVP_CERT_REQ_STATUS_UNKNOWN:
    default:
        status_color = AMVP_ANSI_COLOR_RED;
        status_text = "The cert request status is unknown.";
        break;
    }

    /* Handle rejected status feedback */
    if (cert_req_status == AMVP_CERT_REQ_STATUS_REJECTED) {
        feedback = json_object_get_array(status_json, AMVP_JSON_FIELD_RULE_FEEDBACK);
        if (!feedback) {
            AMVP_LOG_ERR("Server marked request as rejected, but failed to provide reasoning");
            return AMVP_INVALID_ARG;
        }
        arr_size = json_array_get_count(feedback);
        if (arr_size <= 0 || arr_size > 16) {
            AMVP_LOG_ERR("Server provided invalid feedback list (empty or too long)");
            return AMVP_INVALID_ARG;
        }
        for (i = 0; i < (int)arr_size; i++) {
            amvp_append_name_list(&feedback_list, json_array_get_string(feedback, i));
        }
    }

    /* Build complete status message including reasoning if rejected */
    char *status_msg = calloc(AMVP_DISPLAY_STATUS_MSG_MAX, sizeof(char));
    if (!status_msg) {
        AMVP_LOG_ERR("Error allocating memory for status message");
        if (feedback_list) amvp_free_nl(feedback_list);
        return AMVP_MALLOC_FAIL;
    }

    size_t msg_pos = 0;

    /* Build main status part */
    if (vendor_id) {
        if (cert_req_status == AMVP_CERT_REQ_STATUS_APPROVED) {
            msg_pos += snprintf(status_msg + msg_pos, AMVP_DISPLAY_STATUS_MSG_MAX - msg_pos,
                               "Current status of module certification request:\n"
                               "%s            Certification Request %d%s\n"
                               "%s            Module ID: %d (%s)%s\n"
                               "%s            Vendor ID: %d%s\n"
                               "            Status:\n"
                               "                %s%s%s\n"
                               "                %sCertificate ID: %s%s\n",
                               AMVP_ANSI_COLOR_GREEN, request_id, AMVP_ANSI_COLOR_RESET,
                               AMVP_ANSI_COLOR_GREEN, module_id, module_name, AMVP_ANSI_COLOR_RESET,
                               AMVP_ANSI_COLOR_GREEN, vendor_id, AMVP_ANSI_COLOR_RESET,
                               status_color, status_text, AMVP_ANSI_COLOR_RESET,
                               AMVP_ANSI_COLOR_GREEN, cert_id, AMVP_ANSI_COLOR_RESET);
        } else {
            msg_pos += snprintf(status_msg + msg_pos, AMVP_DISPLAY_STATUS_MSG_MAX - msg_pos,
                               "Current status of module certification request:\n"
                               "%s            Certification Request %d%s\n"
                               "%s            Module ID: %d (%s)%s\n"
                               "%s            Vendor ID: %d%s\n"
                               "            Status:\n"
                               "                %s%s%s",
                               AMVP_ANSI_COLOR_GREEN, request_id, AMVP_ANSI_COLOR_RESET,
                               AMVP_ANSI_COLOR_GREEN, module_id, module_name, AMVP_ANSI_COLOR_RESET,
                               AMVP_ANSI_COLOR_GREEN, vendor_id, AMVP_ANSI_COLOR_RESET,
                               status_color, status_text, AMVP_ANSI_COLOR_RESET);
        }
    } else {
        if (cert_req_status == AMVP_CERT_REQ_STATUS_APPROVED) {
            msg_pos += snprintf(status_msg + msg_pos, AMVP_DISPLAY_STATUS_MSG_MAX - msg_pos,
                               "Current status of module certification request:\n"
                               "%s            Certification Request %d%s\n"
                               "%s            Module ID: %d (%s)%s\n"
                               "            Status:\n"
                               "                %s%s%s\n"
                               "                %sCertificate ID: %s%s\n",
                               AMVP_ANSI_COLOR_GREEN, request_id, AMVP_ANSI_COLOR_RESET,
                               AMVP_ANSI_COLOR_GREEN, module_id, module_name, AMVP_ANSI_COLOR_RESET,
                               status_color, status_text, AMVP_ANSI_COLOR_RESET,
                               AMVP_ANSI_COLOR_GREEN, cert_id, AMVP_ANSI_COLOR_RESET);
        } else {
            msg_pos += snprintf(status_msg + msg_pos, AMVP_DISPLAY_STATUS_MSG_MAX - msg_pos,
                               "Current status of module certification request:\n"
                               "%s            Certification Request %d%s\n"
                               "%s            Module ID: %d (%s)%s\n"
                               "            Status:\n"
                               "                %s%s%s",
                               AMVP_ANSI_COLOR_GREEN, request_id, AMVP_ANSI_COLOR_RESET,
                               AMVP_ANSI_COLOR_GREEN, module_id, module_name, AMVP_ANSI_COLOR_RESET,
                               status_color, status_text, AMVP_ANSI_COLOR_RESET);
        }
    }

    /* Add reasoning if rejected */
    if (cert_req_status == AMVP_CERT_REQ_STATUS_REJECTED && feedback_list) {
        msg_pos += snprintf(status_msg + msg_pos, AMVP_DISPLAY_STATUS_MSG_MAX - msg_pos,
                           "\n                %sReasoning:%s", AMVP_ANSI_COLOR_RED, AMVP_ANSI_COLOR_RESET);

        feedback_iter = feedback_list;
        while (feedback_iter && msg_pos < AMVP_DISPLAY_STATUS_MSG_MAX - 1) {
            msg_pos += snprintf(status_msg + msg_pos, AMVP_DISPLAY_STATUS_MSG_MAX - msg_pos,
                               "\n%s                    %s%s", AMVP_ANSI_COLOR_RED, feedback_iter->name, AMVP_ANSI_COLOR_RESET);
            feedback_iter = feedback_iter->next;
        }
        amvp_free_nl(feedback_list);
    }

    /* Add final newline for proper spacing */
    if (msg_pos < AMVP_DISPLAY_STATUS_MSG_MAX - 2) {
        msg_pos += snprintf(status_msg + msg_pos, AMVP_DISPLAY_STATUS_MSG_MAX - msg_pos, "\n");
    }

    /* Output the complete status message */
    AMVP_LOG_STATUS("%s", status_msg);
    free(status_msg);

    return AMVP_SUCCESS;
}

/* Function to output security policy status */
static AMVP_RESULT amvp_output_sp_status(AMVP_CTX *ctx, int missing_sp_template, int missing_sp_submission,
                                        const char *sp_status) {
    const char *overall_status_color = NULL;
    const char *overall_status_text = NULL;
    const char *template_status = NULL;
    const char *template_color = NULL;
    const char *data_status = NULL;
    const char *data_color = NULL;

    /* Determine overall SP status */
    if (sp_status) {
        if (strcmp(sp_status, AMVP_SP_STATUS_APPROVED) == 0) {
            overall_status_color = AMVP_ANSI_COLOR_GREEN;
            overall_status_text = "Security policy has been approved.";
        } else if (strcmp(sp_status, AMVP_SP_STATUS_REJECTED) == 0) {
            overall_status_color = AMVP_ANSI_COLOR_RED;
            overall_status_text = "Security policy has been rejected.";
        } else if (strcmp(sp_status, AMVP_SP_STATUS_PENDING) == 0) {
            overall_status_color = AMVP_ANSI_COLOR_YELLOW;
            overall_status_text = "Waiting for security policy submissions.";
        } else if (strcmp(sp_status, AMVP_SP_STATUS_INCOMPLETE) == 0) {
            overall_status_color = AMVP_ANSI_COLOR_YELLOW;
            overall_status_text = "Security policy submission is incomplete.";
        } else if (strcmp(sp_status, AMVP_SP_STATUS_STR_WAITING_GENERATION) == 0) {
            overall_status_color = AMVP_ANSI_COLOR_YELLOW;
            overall_status_text = "All data submitted. Awaiting document generation request.";
        } else if (strcmp(sp_status, AMVP_SP_STATUS_STR_GENERATING) == 0) {
            overall_status_color = AMVP_ANSI_COLOR_YELLOW;
            overall_status_text = "All data received. Document generation in progress.";
        } else if (strcmp(sp_status, AMVP_SP_STATUS_STR_PROCESSING) == 0) {
            overall_status_color = AMVP_ANSI_COLOR_YELLOW;
            overall_status_text = "Security policy status update in progress; processing previous submission.";
        } else if (strcmp(sp_status, AMVP_SP_STATUS_STR_SUBMITTED) == 0) {
            overall_status_color = AMVP_ANSI_COLOR_GREEN;
            overall_status_text = "All security policy requirements submitted; document is available!";
        } else {
            overall_status_color = AMVP_ANSI_COLOR_YELLOW;
            overall_status_text = sp_status; /* Show unknown status as-is */
        }
    } else if (missing_sp_template || missing_sp_submission) {
        overall_status_color = AMVP_ANSI_COLOR_YELLOW;
        overall_status_text = "Security policy submissions are pending.";
    } else {
        overall_status_color = AMVP_ANSI_COLOR_YELLOW;
        overall_status_text = "Security policy status is unknown.";
    }

    /* Determine template status */
    if (missing_sp_template == 1) {
        template_status = "Pending";
        template_color = AMVP_ANSI_COLOR_RED;
    } else if (missing_sp_template == 0) {
        template_status = "Submitted";
        template_color = AMVP_ANSI_COLOR_GREEN;
    } else {
        template_status = "Unknown";
        template_color = AMVP_ANSI_COLOR_YELLOW;
    }

    /* Determine data status */
    if (missing_sp_submission == 1) {
        data_status = "Pending";
        data_color = AMVP_ANSI_COLOR_RED;
    } else if (missing_sp_submission == 0) {
        data_status = "Submitted";
        data_color = AMVP_ANSI_COLOR_GREEN;
    } else {
        data_status = "Unknown";
        data_color = AMVP_ANSI_COLOR_YELLOW;
    }

    AMVP_LOG_STATUS("Security Policy Status: %s%s%s\n\n"
                   "            Security Policy Template: %s%s%s\n"
                   "            Security Policy Data: %s%s%s",
                   overall_status_color, overall_status_text, AMVP_ANSI_COLOR_RESET,
                   template_color, template_status, AMVP_ANSI_COLOR_RESET,
                   data_color, data_status, AMVP_ANSI_COLOR_RESET);

    return AMVP_SUCCESS;
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

/* Data structure for parsed certificate request status */
typedef struct {
    int request_id;
    int module_id;
    int vendor_id;
    char *module_name;
    char *cert_id;
    AMVP_CERT_REQ_STATUS status;
    AMVP_NAME_LIST *feedback_list;
    JSON_Array *evidence_array;
    int missing_sp_template;
    int missing_sp_submission;
    const char *sp_status;
} amvp_cert_request_data_t;

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

    memset(row, 0, sizeof(amvp_evidence_row_t));

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
    char *table_msg = NULL;
    size_t table_pos = 0;
    size_t arr_size = 0;
    int has_incomplete = 0;
    size_t i = 0;
    JSON_Object *evidence_obj = NULL;
    amvp_evidence_row_t row;
    AMVP_RESULT result = AMVP_SUCCESS;
    const char *color = NULL;

    if (!ctx) return AMVP_INVALID_ARG;

    table_msg = calloc(AMVP_DISPLAY_TABLE_MSG_MAX, sizeof(char));
    if (!table_msg) {
        AMVP_LOG_ERR("Error allocating memory for table message");
        return AMVP_MALLOC_FAIL;
    }

    table_pos += snprintf(table_msg + table_pos, AMVP_DISPLAY_TABLE_MSG_MAX - table_pos, "Test Evidence Status: ");

    /* Handle empty case */
    if (!te_array || json_array_get_count(te_array) == 0) {
        table_pos += snprintf(table_msg + table_pos, AMVP_DISPLAY_TABLE_MSG_MAX - table_pos,
                             AMVP_ANSI_COLOR_GREEN "            All expected test evidence has been submitted!" AMVP_ANSI_COLOR_RESET);
        AMVP_LOG_STATUS("%s", table_msg);
        free(table_msg);
        return AMVP_SUCCESS;
    }

    arr_size = json_array_get_count(te_array);

    for (i = 0; i < arr_size; i++) {
        evidence_obj = json_array_get_object(te_array, i);
        if (!evidence_obj) continue;

        result = amvp_populate_evidence_row(evidence_obj, &row);
        if (result != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Failed to process test evidence row");
            continue;
        }

        if (!row.is_complete) has_incomplete = 1;
    }
    if (has_incomplete) {
        table_pos += snprintf(table_msg + table_pos, AMVP_DISPLAY_TABLE_MSG_MAX - table_pos,
                              AMVP_ANSI_COLOR_YELLOW "Evidence submissions are still pending." AMVP_ANSI_COLOR_RESET "\n");
    } else {
        table_pos += snprintf(table_msg + table_pos, AMVP_DISPLAY_TABLE_MSG_MAX - table_pos,
                              AMVP_ANSI_COLOR_GREEN "All test evidence requirements are submitted!" AMVP_ANSI_COLOR_RESET "\n");
    }

    table_pos += snprintf(table_msg + table_pos, AMVP_DISPLAY_TABLE_MSG_MAX - table_pos,
                         "            %-15s %-15s %s\n", "Test Evidence", "Status", "Required Types");
    table_pos += snprintf(table_msg + table_pos, AMVP_DISPLAY_TABLE_MSG_MAX - table_pos,
                         "            %-15s %-15s %s\n", "-------------", "------", "--------------");
    for (i = 0; i < arr_size; i++) {
        evidence_obj = json_array_get_object(te_array, i);
        if (!evidence_obj) continue;

        result = amvp_populate_evidence_row(evidence_obj, &row);
        if (result != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Failed to process test evidence row");
            continue;
        }

        color = row.is_complete ? AMVP_ANSI_COLOR_GREEN :
               (row.submitted_required > 0 ? AMVP_ANSI_COLOR_YELLOW : AMVP_ANSI_COLOR_RED);

        table_pos += snprintf(table_msg + table_pos, AMVP_DISPLAY_TABLE_MSG_MAX - table_pos,
                             "            %-15s %s%-15s" AMVP_ANSI_COLOR_RESET " %s\n",
                             row.evidence_id, color, row.status,
                             strlen(row.types_list) > 0 ? row.types_list : "-");
    }

    AMVP_LOG_TABLE("%s", table_msg);

    free(table_msg);
    return AMVP_SUCCESS;
}

/* Function to output prettified cert request status to log */
AMVP_RESULT amvp_output_cert_request_status(AMVP_CTX *ctx, JSON_Object *status_json) {
    JSON_Array *evidence_array = NULL;
    char *module_name = NULL;
    int request_id = 0, module_id = 0, vendor_id = 0;
    AMVP_RESULT result = AMVP_SUCCESS;
    AMVP_CERT_REQ_STATUS cert_req_status = AMVP_CERT_REQ_STATUS_UNKNOWN;
    const char *sp_status = NULL;
    int missing_sp_template = 0;
    int missing_sp_submission = 0;

    if (!ctx || !status_json) {
        return AMVP_INTERNAL_ERR;
    }

    /* Parse all the data we need */
    cert_req_status = amvp_parse_cert_req_status_str(status_json);
    result = amvp_parse_cert_request_basic_info(status_json, &request_id, &module_id, &vendor_id);
    if (result != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Error parsing cert request basic info");
        return result;
    }

    module_name = amvp_get_module_name_from_id(ctx, module_id);
    if (!module_name) {
        AMVP_LOG_ERR("Error getting module name from cert request info");
        return AMVP_INTERNAL_ERR;
    }

    amvp_parse_sp_status_info(status_json, &missing_sp_template, &missing_sp_submission, &sp_status);

    /* Output overall status */
    result = amvp_output_overall_status(ctx, status_json, request_id, module_id, vendor_id, module_name);
    if (result != AMVP_SUCCESS) {
        goto end;
    }

    /* For approved status, we're done */
    if (cert_req_status == AMVP_CERT_REQ_STATUS_APPROVED) {
        goto end;
    }

    /* For other statuses that don't show details, we're done */
    if (cert_req_status != AMVP_CERT_REQ_STATUS_READY && cert_req_status != AMVP_CERT_REQ_STATUS_SUBMITTED) {
        goto end;
    }

    /* Output test evidence table for ready/submitted statuses */
    evidence_array = json_object_get_array(status_json, AMVP_JSON_FIELD_EVIDENCE_LIST);
    if (!evidence_array) {
        AMVP_LOG_ERR("Error getting evidence list from cert request info");
        result = AMVP_INTERNAL_ERR;
        goto end;
    }

    result = amvp_output_test_evidence_table(ctx, evidence_array);
    if (result != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Error outputting test evidence table");
        goto end;
    }

    /* Output security policy status */
    result = amvp_output_sp_status(ctx, missing_sp_template, missing_sp_submission, sp_status);
    if (result != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Error outputting security policy status");
        goto end;
    }

end:
    if (module_name) free(module_name);
    return result;
}