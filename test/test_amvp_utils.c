/** @file */
/*
 * Copyright (c) 2020, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libamvp/LICENSE
 */


#include "ut_common.h"
#include "amvp/amvp_lcl.h"

AMVP_CTX *ctx;

/*
 * Try to pass variety of parms to amvp_log_msg
 */
Test(LogMsg, null_ctx) {
    AMVP_RESULT rv = AMVP_SUCCESS;

    amvp_log_msg(NULL, AMVP_LOG_LVL_MAX, __func__, __LINE__, "test");
    cr_assert(rv == AMVP_SUCCESS);

    setup_empty_ctx(&ctx);
    amvp_log_msg(ctx, AMVP_LOG_LVL_MAX+1, __func__, __LINE__, "test");
    cr_assert(rv == AMVP_SUCCESS);

    amvp_log_msg(ctx, AMVP_LOG_LVL_MAX, __func__, __LINE__, NULL);
    cr_assert(rv == AMVP_SUCCESS);
    
    amvp_cleanup(ctx);
}

/*
 * Try to pass NULL to amvp_cleanup
 */
Test(Cleanup, null_ctx) {
    AMVP_RESULT rv = AMVP_SUCCESS;

    amvp_cleanup(NULL);
    cr_assert(rv == AMVP_SUCCESS);

}

/*
 * Try to pass valid and invalid alg to amvp_lookup_cipher_revision
 */
Test(LookupCipherRevision, null_ctx) {
    const char *ptr = NULL;

    ptr = amvp_lookup_cipher_revision(AMVP_KAS_FFC_NOCOMP);
    cr_assert(ptr != NULL);

    ptr = amvp_lookup_cipher_revision(AMVP_CIPHER_END);
    cr_assert_null(ptr);

    ptr = amvp_lookup_cipher_revision(AMVP_CIPHER_START);
    cr_assert_null(ptr);

}


/*
 * Try to pass amvp_locate_cap_entry NULL ctx
 */
Test(LocateCapEntry, null_ctx) {
    AMVP_CAPS_LIST *list;

    list = amvp_locate_cap_entry(NULL, AMVP_AES_GCM);
    cr_assert_null(list);
}


Test(LookupCipherIndex, null_param) {
    AMVP_CIPHER cipher;
    cipher = amvp_lookup_cipher_index(NULL);
    cr_assert(cipher == AMVP_CIPHER_START);

    cipher = amvp_lookup_cipher_index("Bad Name");
    cr_assert(cipher == AMVP_CIPHER_START);

    cipher = amvp_lookup_cipher_index(AMVP_ALG_AES_CBC);
    cr_assert(cipher == AMVP_AES_CBC);

}

Test(LookupRSARandPQIndex, null_param) {
    int rv = amvp_lookup_rsa_randpq_index(NULL);
    cr_assert(!rv);
}

Test(JsonSerializeToFilePrettyW, null_param) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    JSON_Value *value;

    rv = amvp_json_serialize_to_file_pretty_w(NULL, "test");
    cr_assert(rv == AMVP_JSON_ERR);

    value = json_value_init_object();
    rv = amvp_json_serialize_to_file_pretty_w(value, NULL);
    cr_assert(rv == AMVP_INVALID_ARG);

    rv = amvp_json_serialize_to_file_pretty_w(value, "no_file");
    cr_assert(rv == AMVP_SUCCESS);
    
    json_value_free(value);
}

Test(JsonSerializeToFilePrettyA, null_param) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    JSON_Value *value;

    rv = amvp_json_serialize_to_file_pretty_a(NULL, "test");
    cr_assert(rv == AMVP_SUCCESS);

    value = json_value_init_object();
    rv = amvp_json_serialize_to_file_pretty_a(value, NULL);
    cr_assert(rv == AMVP_INVALID_ARG);

    rv = amvp_json_serialize_to_file_pretty_a(value, "no_file");
    cr_assert(rv == AMVP_SUCCESS);
    
    json_value_free(value);
}

/*
 * Exercise string_fits logic
 */
Test(StringFits, null_ctx) {
     int rc = 0;

    rc = string_fits("tests", 3);
    cr_assert(rc == 0);

    rc = string_fits("test", 6);
    cr_assert(rc == 1);
}

/*
 * Exercise is_valid_rsa_mod logic
 */
Test(ValidRsaMod, null_ctx) {
     AMVP_RESULT rv = AMVP_SUCCESS;

    rv = is_valid_rsa_mod(4096);
    cr_assert(rv == AMVP_SUCCESS);

    rv = is_valid_rsa_mod(4097);
    cr_assert(rv == AMVP_INVALID_ARG);
}

/*
 * Exercise amvp_lookup_error_string logic
 */
Test(LookupErrorString, null_ctx) {
    const char *str = NULL;
    char *dup = "ctx already initialized";
    char *ukn = "Unknown error";

    str = amvp_lookup_error_string(AMVP_CTX_NOT_EMPTY);
    cr_assert(!strncmp(str, dup, strlen(dup)));

    str = amvp_lookup_error_string(AMVP_RESULT_MAX);
    cr_assert(!strncmp(str, ukn, strlen(ukn)));
}


/*
 * Exercise amvp_kv_list_append, amvp_kvlist_free and amvp_free_str_list logic
 */
Test(KvList, null_ctx) {
    AMVP_KV_LIST *kv = NULL;
    AMVP_RESULT rv = AMVP_SUCCESS;
    char *key = NULL, *value = NULL;
    AMVP_STRING_LIST *list = NULL;

    rv = amvp_kv_list_append(NULL, NULL, NULL);
    cr_assert(rv == AMVP_INVALID_ARG);

    rv = amvp_kv_list_append(&kv, NULL, NULL);
    cr_assert(rv == AMVP_INVALID_ARG);

    rv = amvp_kv_list_append(&kv, "this is the key", NULL);
    cr_assert(rv == AMVP_INVALID_ARG);

    key = calloc(strlen("this is the key") + 1, sizeof(char));
    value = calloc(strlen("value") + 1, sizeof(char));
    memcpy(value, "value", 5);
    memcpy(key, "This is the key", 15);
    rv = amvp_kv_list_append(&kv, key, value);
    cr_assert(rv == AMVP_SUCCESS);

    amvp_kv_list_free(NULL);
    amvp_kv_list_free(kv);
    amvp_free_str_list(NULL);
    amvp_free_str_list(&list);
    list = calloc(sizeof(AMVP_STRING_LIST), sizeof(char));
    list->string = key;
    amvp_free_str_list(&list);
    cr_assert(list == NULL);
    free(value);
}

/*
 * Exercise amvp_get_obj_from_rsp logic
 */
Test(GetObjFromRsp, null_ctx) {
    JSON_Object *obj = NULL;
    JSON_Value *val = NULL;

    obj = amvp_get_obj_from_rsp(NULL, NULL);
    cr_assert(obj == NULL);

    setup_empty_ctx(&ctx);
    obj = amvp_get_obj_from_rsp(ctx, NULL);
    cr_assert(obj == NULL);

    val = json_parse_file("json/aes/aes.json");
    obj = amvp_get_obj_from_rsp(ctx, val);
    cr_assert(obj != NULL);
    
    json_value_free(val);
    amvp_free_test_session(ctx);
}

