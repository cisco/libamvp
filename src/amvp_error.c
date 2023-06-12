/** @file */
/*
 * Copyright (c) 2021, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libamvp/LICENSE
 */


#include "amvp.h"
#include "amvp_lcl.h"
#include "amvp_error.h"
#include "safe_lib.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void amvp_free_protocol_err(AMVP_PROTOCOL_ERR *err) {
    AMVP_PROTOCOL_ERR_LIST *current = NULL, *tmp = NULL;
    int i = 0;
    current = err->errors;
    while(current) {
        tmp = current->next;
        for (i = 0; i < current->desc_count; i++) {
            free(current->desc[i]);
        }
        free(current);
        current = tmp;
    }
    free(err);
}

int amvp_check_for_protocol_error(AMVP_PROTOCOL_ERR *err, AMVP_PROTOCOL_ERR_CATEGORY cat, int code) {
    AMVP_PROTOCOL_ERR_LIST *list = NULL;

    if (!err || cat < 0 || cat >= AMVP_PROTOCOL_ERR_CAT_MAX) {
        return -1;
    }
    if (err->category != cat) {
        return 0;
    }

    list = err->errors;
    while (list) {
        if (list->code == code) {
            return 1;
        }
        list = list->next;
    }

    return 0;
}

AMVP_PROTOCOL_ERR *amvp_parse_protocol_error(const char *buf) {
    JSON_Value *val = NULL;
    JSON_Array *arr = NULL, *arr2 = NULL;
    JSON_Object *obj = NULL;
    AMVP_PROTOCOL_ERR *err_obj = NULL;
    AMVP_PROTOCOL_ERR_LIST *list = NULL, *iter = NULL;
    int value = 0, success = 0, count = 0, count2 = 0, i = 0, j = 0;
    const char *tmp = NULL;

    if (!buf) {
        return NULL;
    }

    val = json_parse_string(buf);
    if (!val) { goto err; }
    arr = json_value_get_array(val);
    if (!arr) { goto err; }
    obj = json_array_get_object(arr, 1);
    if (!obj) { goto err; }
    err_obj = calloc(1, sizeof(AMVP_PROTOCOL_ERR));
    if (!err_obj) { goto err; }

    /* Get the category number. Since 0 is a valid option, check that the value exists before parsing it */
    if (!json_object_has_value_of_type(obj, AMVP_ERR_CATEGORY_STR, JSONNumber)) {
        goto err;
    }
    value = json_object_get_number(obj, AMVP_ERR_CATEGORY_STR);
    if (value < 0 || value >= AMVP_PROTOCOL_ERR_CAT_MAX) {
        goto err;
    }
    err_obj->category = value;

    /* Get the category description */
    tmp = json_object_get_string(obj, AMVP_ERR_DESC_STR);
    if (!tmp) { goto err; }
    if (strnlen_s(tmp, AMVP_ERR_DESC_STR_MAX + 1) > AMVP_ERR_DESC_STR_MAX) {
        goto err;
    }
    err_obj->category_desc = strdup(tmp);

    arr = json_object_get_array(obj, AMVP_ERR_ERR_STR);
    if (!arr) { goto err; }
    count = json_array_get_count(arr);
    if (count <= 0 || count >= AMVP_ERR_MAX_OBJECT_COUNT) {
        goto err;
    }

    iter = err_obj->errors;
    while (iter && iter->next) {
        iter = iter->next;
    }

    for (i = 0; i < count; i++) {
        obj = json_array_get_object(arr, i);
        if (!obj) { goto err; }
        if (!json_object_has_value_of_type(obj, AMVP_ERR_CODE_STR, JSONNumber)) {
            goto err;
        }

        /* Get the code number */
        list = calloc(1, sizeof(AMVP_PROTOCOL_ERR_LIST));
        if (!list)  {goto err; }
        list->code = json_object_get_number(obj, AMVP_ERR_CODE_STR);

        /* Get the list of strings up to a certain maximum */
        arr2 = json_object_get_array(obj, AMVP_ERR_MSG_STR);
        if (!arr2) { goto err; }
        count2 = json_array_get_count(arr2) < AMVP_ERR_MAX_DESC_STRINGS ? count2 : AMVP_ERR_MAX_DESC_STRINGS;
        for (j = 0; j < count2; j++) {
            if (list->desc_count >= AMVP_ERR_MAX_DESC_STRINGS) {
                break;
            }
            tmp = json_array_get_string(arr2, count2);
            if (strnlen_s(tmp, AMVP_ERR_DESC_STR_MAX + 1 > AMVP_ERR_DESC_STR_MAX)) {
                goto err;
            }
            list->desc[list->desc_count] = strdup(tmp);
            if (list->desc[list->desc_count]) {
                goto err;
            }
            list->desc_count++;
        }
        if (!err_obj->errors) {
            err_obj->errors = list;
        } else {
            iter->next = list;
        }
    }
    success = 1;
err:
    if (val) json_value_free(val);
    if (!success && err_obj) {
        amvp_free_protocol_err(err_obj);
        return NULL;
    } else {
        return err_obj;
    }
}

int amvp_is_protocol_error_message(const char *buf) {
    JSON_Value *val = NULL;
    JSON_Array *arr = NULL;
    JSON_Object *obj = NULL;

    /* Check that root is array with two objects */
    val = json_parse_string(buf);
    if (!val) {
        goto err;
    }

    arr = json_value_get_array(val);
    if (!arr) {
        goto err;
    }

    if (json_array_get_count(arr) != AMVP_ERR_MSG_ARR_SIZE) {
        goto err;
    }

    /* Check that obj 1 is the amvVersion */
    obj = json_array_get_object(arr, 0);
    if (!obj) {
        goto err;
    }

    if (!json_object_has_value(obj, AMVP_PROTOCOL_VERSION_STR)) {
        goto err;
    }

    /* Check that the second object has a "category", description", and "errors" */
    obj = json_array_get_object(arr, 1);
    if (!obj) {
        goto err;
    }

    if (!json_object_has_value(obj, AMVP_ERR_CATEGORY_STR)) { goto err; }
    if (!json_object_has_value(obj, AMVP_ERR_DESC_STR)) { goto err; }
    if (!json_object_has_value(obj, AMVP_ERR_ERR_STR)) { goto err; }

    arr = json_object_get_array(obj, AMVP_ERR_ERR_STR);
    if (!arr) {
        goto err;
    }

    json_value_free(val);
    return 1;

err:
    if (val) json_value_free(val);
    return 0;
}
