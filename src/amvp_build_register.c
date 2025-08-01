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
#include <string.h>
#include <stdlib.h>
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif
#include "amvp.h"
#include "amvp_lcl.h"
#include "parson.h"
#include "safe_str_lib.h"
#include "safe_mem_lib.h"

/*
 * This builds a cert req
 */
AMVP_RESULT amvp_build_registration_json(AMVP_CTX *ctx, JSON_Value **reg) {
    JSON_Value *val = NULL, *module_val = NULL;
    JSON_Array *req_arr = NULL;
    JSON_Object *cap_obj = NULL;

    int i = 0;
    if (!ctx) {
        AMVP_LOG_ERR("No ctx for build_test_session");
        return AMVP_NO_CTX;
    }
    if (ctx->cert_req_info.contact_count <= 0) {
        AMVP_LOG_ERR("Cannot build cert req without any contact IDs");
        return AMVP_MISSING_ARG;
    }

    val = json_value_init_object();
    cap_obj = json_value_get_object(val);

    json_object_set_number(cap_obj, "vendorId", ctx->cert_req_info.vendor_id);
    json_object_set_value(cap_obj, "contacts", json_value_init_array());
    req_arr = json_object_get_array(cap_obj, "contacts");

    for (i = 0; i < ctx->cert_req_info.contact_count; i++) {
        json_array_append_string(req_arr, ctx->cert_req_info.contact_id[i]);
    }

    if (ctx->cert_req_info.acv_cert_count > 0) {
        json_object_set_value(cap_obj, "algorithmCertificates", json_value_init_array());
        req_arr = json_object_get_array(cap_obj, "algorithmCertificates");
        for (i = 0; i < ctx->cert_req_info.acv_cert_count; i++) {
            json_array_append_string(req_arr, ctx->cert_req_info.acv_cert[i]);
        }
    }

    if (ctx->cert_req_info.esv_cert_count > 0) {
        json_object_set_value(cap_obj, "entropyCertificates", json_value_init_array());
        req_arr = json_object_get_array(cap_obj, "entropyCertificates");
        for (i = 0; i < ctx->cert_req_info.esv_cert_count; i++) {
            json_array_append_string(req_arr, ctx->cert_req_info.esv_cert[i]);
        }
    }

    module_val = json_parse_file(ctx->cert_req_info.module_file);
    if (!module_val) {
        AMVP_LOG_ERR("Provided module file is invalid or does not exist");
        json_value_free(val);
        return AMVP_INVALID_ARG;
    }

    json_object_set_value(cap_obj, "module", module_val);

    *reg = val;

    return AMVP_SUCCESS;
}

/*
 * This function builds the JSON message to register an OE with the
 * validating crypto server
 */
AMVP_RESULT amvp_build_validation(AMVP_CTX *ctx,
                                  char **out,
                                  int *out_len) {
    JSON_Value *top_array_val = NULL, *val = NULL;
    JSON_Array *top_array = NULL;
    JSON_Object *obj = NULL;
    AMVP_OE *oe = NULL;
    AMVP_MODULE *module = NULL;

    if (!ctx) return AMVP_NO_CTX;
    oe = ctx->fips.oe;
    module = ctx->fips.module;

    /*
     * Start top-level array
     */
    top_array_val = json_value_init_array();
    top_array = json_array((const JSON_Value *)top_array_val);

    /*
     * Start the next object, which will be appended to the top-level array
     */
    val = json_value_init_object();
    obj = json_value_get_object(val);

    /*
     * Add the OE
     */
    if (oe->url) {
        json_object_set_string(obj, "oeUrl", oe->url);
    } else {
        /* Need to create a new OE */
        JSON_Value *oe_val = NULL;
        JSON_Object *oe_obj = NULL;

        oe_val = json_value_init_object();
        oe_obj = json_value_get_object(oe_val);

        json_object_set_string(oe_obj, "name", oe->name);

        if (oe->dependencies.status == AMVP_RESOURCE_STATUS_COMPLETE ||
            oe->dependencies.status == AMVP_RESOURCE_STATUS_PARTIAL) {
            /*
             * There are some "complete" urls to record.
             */
            JSON_Array *dep_url_array = NULL;
            unsigned int i = 0;

            json_object_set_value(oe_obj, "dependencyUrls", json_value_init_array());
            dep_url_array = json_object_get_array(oe_obj, "dependencyUrls");

            for (i = 0; i < oe->dependencies.count; i++) {
                AMVP_DEPENDENCY *dependency = oe->dependencies.deps[i];
                if (dependency->url) {
                    json_array_append_string(dep_url_array, dependency->url);
                }
            }
        }

        if (oe->dependencies.status == AMVP_RESOURCE_STATUS_INCOMPLETE ||
            oe->dependencies.status == AMVP_RESOURCE_STATUS_PARTIAL) {
            /*
             * There are some dependencies that we need to create.
             */
            JSON_Array *dep_array = NULL;
            unsigned int i = 0;

            json_object_set_value(oe_obj, "dependencies", json_value_init_array());
            dep_array = json_object_get_array(oe_obj, "dependencies");

            for (i = 0; i < oe->dependencies.count; i++) {
                AMVP_DEPENDENCY *dependency = oe->dependencies.deps[i];

                if (dependency->url == NULL) {
                    JSON_Value *dep_val = json_value_init_object();;
                    JSON_Object *dep_obj = json_value_get_object(dep_val);

                    if (dependency->type) {
                        json_object_set_string(dep_obj, "type", dependency->type);
                    }
                    if (dependency->name) {
                        json_object_set_string(dep_obj, "name", dependency->name);
                    }
                    if (dependency->description) {
                        json_object_set_string(dep_obj, "description", dependency->description);
                    }
                    if (dependency->version) {
                        json_object_set_string(dep_obj, "version", dependency->version);
                    }
                    if (dependency->family) {
                        json_object_set_string(dep_obj, "family", dependency->family);
                    }
                    if (dependency->series) {
                        json_object_set_string(dep_obj, "series", dependency->series);
                    }
                    if (dependency->manufacturer) {
                        json_object_set_string(dep_obj, "manufacturer", dependency->manufacturer);
                    }

                    json_array_append_value(dep_array, dep_val);
                }
            }
        }

        /*
         * Attach the OE object
         */
        json_object_set_value(obj, "oe", oe_val);
    }

    /*
     * Add the Module
     */
    if (module->url) {
        json_object_set_string(obj, "moduleUrl", module->url);
    } else {
        /* Need to create a new Module */
        JSON_Value *module_val = NULL;
        JSON_Object *module_obj = NULL;
        JSON_Array *contact_url_array = NULL;
        int i = 0;

        module_val = json_value_init_object();
        module_obj = json_value_get_object(module_val);

        json_object_set_string(module_obj, "name", module->name);
        if (module->version) {
            json_object_set_string(module_obj, "version", module->version);
        }
        if (module->type) {
            json_object_set_string(module_obj, "type", module->type);
        }
        if (module->description) {
            json_object_set_string(module_obj, "description", module->description);
        }

        json_object_set_string(module_obj, "vendorUrl", module->vendor->url);
        json_object_set_string(module_obj, "addressUrl", module->vendor->address.url);

        json_object_set_value(module_obj, "contactUrls", json_value_init_array());
        contact_url_array = json_object_get_array(module_obj, "contactUrls");

        for (i = 0; i < module->vendor->persons.count; i++) {
            AMVP_PERSON *person = &module->vendor->persons.person[i];
            json_array_append_string(contact_url_array, person->url);
        }

        /*
         * Attach the Module object
         */
        json_object_set_value(obj, "module", module_val);
    }

    json_array_append_value(top_array, val);
    *out = json_serialize_to_string(top_array_val, out_len);

    if (top_array_val) json_value_free(top_array_val);

    return AMVP_SUCCESS;
}

