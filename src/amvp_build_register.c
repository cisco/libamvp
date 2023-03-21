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

typedef struct amvp_prereqs_mode_name_t {
    AMVP_PREREQ_ALG alg;
    const char *name;
} AMVP_PREREQ_MODE_NAME;

#define AMVP_NUM_PREREQS 14
struct amvp_prereqs_mode_name_t amvp_prereqs_tbl[AMVP_NUM_PREREQS] = {
    { AMVP_PREREQ_AES,   "AES"   },
    { AMVP_PREREQ_CCM,   "CCM"   },
    { AMVP_PREREQ_CMAC,  "CMAC"  },
    { AMVP_PREREQ_DRBG,  "DRBG"  },
    { AMVP_PREREQ_DSA,   "DSA"   },
    { AMVP_PREREQ_ECDSA, "ECDSA" },
    { AMVP_PREREQ_HMAC,  "HMAC"  },
    { AMVP_PREREQ_KAS,   "KAS"   },
    { AMVP_PREREQ_RSA,   "RSA"   },
    { AMVP_PREREQ_RSADP, "RSADP" },
    { AMVP_PREREQ_SAFE_PRIMES,   "safePrimes"   },
    { AMVP_PREREQ_SHA,   "SHA"   },
    { AMVP_PREREQ_TDES,  "TDES"  },
    { AMVP_PREREQ_KMAC,  "KMAC"  }
};

static AMVP_RESULT amvp_lookup_prereqVals(JSON_Object *cap_obj, AMVP_CAPS_LIST *cap_entry) {
    JSON_Array *prereq_array = NULL;
    AMVP_PREREQ_LIST *prereq_vals, *next_pre_req;
    AMVP_PREREQ_ALG_VAL *pre_req;
    const char *alg_str;
    int i = 0;

    if (!cap_entry) { return AMVP_INVALID_ARG; }

    if (!cap_entry->has_prereq) { return AMVP_SUCCESS; }
    /*
     * Init json array
     */
    json_object_set_value(cap_obj, AMVP_PREREQ_OBJ_STR, json_value_init_array());
    prereq_array = json_object_get_array(cap_obj, AMVP_PREREQ_OBJ_STR);

    /*
     * return OK if nothing present
     */
    prereq_vals = cap_entry->prereq_vals;

    while (prereq_vals) {
        JSON_Value *val = NULL;
        JSON_Object *obj = NULL;
        val = json_value_init_object();
        obj = json_value_get_object(val);
        pre_req = &prereq_vals->prereq_alg_val;

        for (i = 0; i < AMVP_NUM_PREREQS; i++) {
            if (amvp_prereqs_tbl[i].alg == pre_req->alg) {
                alg_str = amvp_prereqs_tbl[i].name;
                json_object_set_string(obj, "algorithm", alg_str);
                json_object_set_string(obj, AMVP_PREREQ_VAL_STR, pre_req->val);
                break;
            }
        }

        json_array_append_value(prereq_array, val);
        next_pre_req = prereq_vals->next;
        prereq_vals = next_pre_req;
    }

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_build_hash_register_cap(JSON_Object *cap_obj, AMVP_CAPS_LIST *cap_entry) {
    JSON_Array *msg_array = NULL;
    JSON_Value *msg_val = NULL;
    JSON_Object *msg_obj = NULL;
    AMVP_HASH_CAP *hash_cap = cap_entry->cap.hash_cap;
    const char *revision = NULL;

    if (!hash_cap) {
        return AMVP_MISSING_ARG;
    }

    json_object_set_string(cap_obj, "algorithm", amvp_lookup_cipher_name(cap_entry->cipher));

    revision = amvp_lookup_cipher_revision(cap_entry->cipher);
    if (revision == NULL) return AMVP_INVALID_ARG;
    json_object_set_string(cap_obj, "revision", revision);

    if (cap_entry->cipher == AMVP_HASH_SHA3_224 ||
            cap_entry->cipher == AMVP_HASH_SHA3_256 ||
            cap_entry->cipher == AMVP_HASH_SHA3_384 ||
            cap_entry->cipher == AMVP_HASH_SHA3_512 ||
            cap_entry->cipher == AMVP_HASH_SHAKE_128 ||
            cap_entry->cipher == AMVP_HASH_SHAKE_256) {
        json_object_set_boolean(cap_obj, "inBit", cap_entry->cap.hash_cap->in_bit);
        json_object_set_boolean(cap_obj, "inEmpty", cap_entry->cap.hash_cap->in_empty);
    }

    if (cap_entry->cipher == AMVP_HASH_SHAKE_128 ||
        cap_entry->cipher == AMVP_HASH_SHAKE_256) {
        /* SHAKE specific capabilities */
        JSON_Array *tmp_arr = NULL;
        JSON_Value *tmp_val = NULL;
        JSON_Object *tmp_obj = NULL;

        json_object_set_boolean(cap_obj, "outBit", cap_entry->cap.hash_cap->out_bit);

        json_object_set_value(cap_obj, "outputLen", json_value_init_array());
        tmp_arr = json_object_get_array(cap_obj, "outputLen");
        tmp_val = json_value_init_object();
        tmp_obj = json_value_get_object(tmp_val);

        json_object_set_number(tmp_obj, "min", cap_entry->cap.hash_cap->out_len.min);
        json_object_set_number(tmp_obj, "max", cap_entry->cap.hash_cap->out_len.max);
        json_object_set_number(tmp_obj, "increment", cap_entry->cap.hash_cap->out_len.increment);

        json_array_append_value(tmp_arr, tmp_val);
    } else {
        json_object_set_value(cap_obj, "messageLength", json_value_init_array());
        msg_array = json_object_get_array(cap_obj, "messageLength");

        msg_val = json_value_init_object();
        msg_obj = json_value_get_object(msg_val);

        json_object_set_number(msg_obj, "min", hash_cap->msg_length.min);
        json_object_set_number(msg_obj, "max", hash_cap->msg_length.max);
        json_object_set_number(msg_obj, "increment", hash_cap->msg_length.increment);
        json_array_append_value(msg_array, msg_val);
    }

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_build_hmac_register_cap(JSON_Object *cap_obj, AMVP_CAPS_LIST *cap_entry) {
    JSON_Array *temp_arr = NULL;
    AMVP_RESULT result;
    AMVP_HMAC_CAP *hmac_cap = cap_entry->cap.hmac_cap;
    AMVP_SL_LIST *list = NULL;
    const char *revision = NULL;

    if (!cap_entry->cap.hmac_cap) {
        return AMVP_NO_CAP;
    }
    json_object_set_string(cap_obj, "algorithm", amvp_lookup_cipher_name(cap_entry->cipher));

    revision = amvp_lookup_cipher_revision(cap_entry->cipher);
    if (revision == NULL) return AMVP_INVALID_ARG;
    json_object_set_string(cap_obj, "revision", revision);

    result = amvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != AMVP_SUCCESS) { return result; }

    /*
     * Set the supported key lengths
     */
    json_object_set_value(cap_obj, "keyLen", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "keyLen");

    if (hmac_cap->key_len.increment != 0) {
        JSON_Value *key_len_val = NULL;
        JSON_Object *key_len_obj = NULL;
        key_len_val = json_value_init_object();
        key_len_obj = json_value_get_object(key_len_val);
        json_object_set_number(key_len_obj, "min", hmac_cap->key_len.min);
        json_object_set_number(key_len_obj, "max", hmac_cap->key_len.max);
        json_object_set_number(key_len_obj, "increment", hmac_cap->key_len.increment);
        json_array_append_value(temp_arr, key_len_val);
    }

    list = hmac_cap->key_len.values;
    while (list) {
        json_array_append_number(temp_arr, list->length);
        list = list->next;
    }

    /*
     * Set the supported mac lengths
     */
    json_object_set_value(cap_obj, "macLen", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "macLen");

    if (hmac_cap->mac_len.increment != 0) {
        JSON_Value *mac_len_val = NULL;
        JSON_Object *mac_len_obj = NULL;
        mac_len_val = json_value_init_object();
        mac_len_obj = json_value_get_object(mac_len_val);
        json_object_set_number(mac_len_obj, "min", hmac_cap->mac_len.min);
        json_object_set_number(mac_len_obj, "max", hmac_cap->mac_len.max);
        json_object_set_number(mac_len_obj, "increment", hmac_cap->mac_len.increment);
        json_array_append_value(temp_arr, mac_len_val);
    }

    list = hmac_cap->mac_len.values;
    while (list) {
        json_array_append_number(temp_arr, list->length);
        list = list->next;
    }

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_build_cmac_register_cap(JSON_Object *cap_obj, AMVP_CAPS_LIST *cap_entry) {
    JSON_Array *temp_arr = NULL, *capabilities_arr = NULL;
    JSON_Value *capabilities_val = NULL, *msg_len_val = NULL, *mac_len_val = NULL;
    JSON_Object *capabilities_obj = NULL, *msg_len_obj = NULL, *mac_len_obj = NULL;
    AMVP_SL_LIST *sl_list;
    AMVP_RESULT result;
    AMVP_CMAC_CAP *cmac_cap = cap_entry->cap.cmac_cap;
    const char *revision = NULL;

    json_object_set_string(cap_obj, "algorithm", amvp_lookup_cipher_name(cap_entry->cipher));

    revision = amvp_lookup_cipher_revision(cap_entry->cipher);
    if (revision == NULL) return AMVP_INVALID_ARG;
    json_object_set_string(cap_obj, "revision", revision);

    result = amvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != AMVP_SUCCESS) { return result; }

    capabilities_val = json_value_init_object();
    capabilities_obj = json_value_get_object(capabilities_val);

    json_object_set_value(cap_obj, "capabilities", json_value_init_array());
    capabilities_arr = json_object_get_array(cap_obj, "capabilities");

    json_object_set_value(capabilities_obj, "direction", json_value_init_array());
    temp_arr = json_object_get_array(capabilities_obj, "direction");
    if (!cap_entry->cap.cmac_cap->direction_gen && !cap_entry->cap.cmac_cap->direction_ver) {
        json_value_free(capabilities_val);
        return AMVP_MISSING_ARG;
    }
    if (cap_entry->cap.cmac_cap->direction_gen) { json_array_append_string(temp_arr, "gen"); }
    if (cap_entry->cap.cmac_cap->direction_ver) { json_array_append_string(temp_arr, "ver"); }

    json_object_set_value(capabilities_obj, "msgLen", json_value_init_array());
    temp_arr = json_object_get_array(capabilities_obj, "msgLen");

    if (cap_entry->cap.cmac_cap->msg_len.increment != 0) {
        msg_len_val = json_value_init_object();
        msg_len_obj = json_value_get_object(msg_len_val);
        json_object_set_number(msg_len_obj, "min", cmac_cap->msg_len.min);
        json_object_set_number(msg_len_obj, "max", cmac_cap->msg_len.max);
        json_object_set_number(msg_len_obj, "increment", cmac_cap->msg_len.increment);
        json_array_append_value(temp_arr, msg_len_val);
    }

    sl_list = cap_entry->cap.cmac_cap->msg_len.values;
    while (sl_list) {
        json_array_append_number(temp_arr, sl_list->length);
        sl_list = sl_list->next;
    }

    /*
     * Set the supported mac lengths
     */
    json_object_set_value(capabilities_obj, "macLen", json_value_init_array());
    temp_arr = json_object_get_array(capabilities_obj, "macLen");

    if (cap_entry->cap.cmac_cap->mac_len.increment != 0) {
        mac_len_val = json_value_init_object();
        mac_len_obj = json_value_get_object(mac_len_val);
        json_object_set_number(mac_len_obj, "min", cmac_cap->mac_len.min);
        json_object_set_number(mac_len_obj, "max", cmac_cap->mac_len.max);
        json_object_set_number(mac_len_obj, "increment", cmac_cap->mac_len.increment);
        json_array_append_value(temp_arr, mac_len_val);
    }

    sl_list = cap_entry->cap.cmac_cap->mac_len.values;
    while (sl_list) {
        json_array_append_number(temp_arr, sl_list->length);
        sl_list = sl_list->next;
    }

    if (cap_entry->cipher == AMVP_CMAC_AES) {
        /*
         * Set the supported key lengths. if CMAC-AES
         */
        json_object_set_value(capabilities_obj, "keyLen", json_value_init_array());
        temp_arr = json_object_get_array(capabilities_obj, "keyLen");
        sl_list = cap_entry->cap.cmac_cap->key_len;
        while (sl_list) {
            json_array_append_number(temp_arr, sl_list->length);
            sl_list = sl_list->next;
        }
    } else if (cap_entry->cipher == AMVP_CMAC_TDES) {
        /*
         * Set the supported key lengths. if CMAC-TDES
         */
        json_object_set_value(capabilities_obj, "keyingOption", json_value_init_array());
        temp_arr = json_object_get_array(capabilities_obj, "keyingOption");
        sl_list = cap_entry->cap.cmac_cap->keying_option;
        if (!sl_list) {
            json_value_free(capabilities_val);
            return AMVP_MISSING_ARG;
        }
        while (sl_list) {
            json_array_append_number(temp_arr, sl_list->length);
            sl_list = sl_list->next;
        }
    }

    json_array_append_value(capabilities_arr, capabilities_val);

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_build_kmac_register_cap(JSON_Object *cap_obj, AMVP_CAPS_LIST *cap_entry) {
    JSON_Array *temp_arr = NULL;
    JSON_Value *msg_len_val = NULL, *mac_len_val = NULL, *key_len_val = NULL;
    JSON_Object *msg_len_obj = NULL, *mac_len_obj = NULL, *key_len_obj = NULL;
    AMVP_RESULT result;
    AMVP_KMAC_CAP *kmac_cap = cap_entry->cap.kmac_cap;
    AMVP_SL_LIST *list = NULL;
    const char *revision = NULL;

    json_object_set_string(cap_obj, "algorithm", amvp_lookup_cipher_name(cap_entry->cipher));

    revision = amvp_lookup_cipher_revision(cap_entry->cipher);
    if (revision == NULL) return AMVP_INVALID_ARG;
    json_object_set_string(cap_obj, "revision", revision);

    result = amvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != AMVP_SUCCESS) { return result; }

    json_object_set_value(cap_obj, "xof", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "xof");
    switch (cap_entry->cap.kmac_cap->xof) {
    case AMVP_XOF_SUPPORT_FALSE:
        json_array_append_boolean(temp_arr, 0);
        break;
    case AMVP_XOF_SUPPORT_TRUE:
        json_array_append_boolean(temp_arr, 1);
        break;
    case AMVP_XOF_SUPPORT_BOTH:
        json_array_append_boolean(temp_arr, 1);
        json_array_append_boolean(temp_arr, 0);
        break;
    default:
        return AMVP_INVALID_ARG;
    }

    json_object_set_boolean(cap_obj, "hexCustomization", cap_entry->cap.kmac_cap->hex_customization);

    json_object_set_value(cap_obj, "msgLen", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "msgLen");

    if (kmac_cap->msg_len.increment != 0) {
        msg_len_val = json_value_init_object();
        msg_len_obj = json_value_get_object(msg_len_val);
        json_object_set_number(msg_len_obj, "min", kmac_cap->msg_len.min);
        json_object_set_number(msg_len_obj, "max", kmac_cap->msg_len.max);
        json_object_set_number(msg_len_obj, "increment", kmac_cap->msg_len.increment);
        json_array_append_value(temp_arr, msg_len_val);
    }

    list = kmac_cap->msg_len.values;
    while (list) {
        json_array_append_number(temp_arr, list->length);
        list = list->next;
    }

    /* Set the supported mac lengths */
    json_object_set_value(cap_obj, "macLen", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "macLen");

    if (kmac_cap->mac_len.increment != 0) {
        mac_len_val = json_value_init_object();
        mac_len_obj = json_value_get_object(mac_len_val);
        json_object_set_number(mac_len_obj, "min", kmac_cap->mac_len.min);
        json_object_set_number(mac_len_obj, "max", kmac_cap->mac_len.max);
        json_object_set_number(mac_len_obj, "increment", kmac_cap->mac_len.increment);
        json_array_append_value(temp_arr, mac_len_val);
    }

    list = kmac_cap->mac_len.values;
    while (list) {
        json_array_append_number(temp_arr, list->length);
        list = list->next;
    }

    /* Set the supported key lengths */
    json_object_set_value(cap_obj, "keyLen", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "keyLen");

    if (kmac_cap->key_len.increment != 0) {
        key_len_val = json_value_init_object();
        key_len_obj = json_value_get_object(key_len_val);
        json_object_set_number(key_len_obj, "min", kmac_cap->key_len.min);
        json_object_set_number(key_len_obj, "max", kmac_cap->key_len.max);
        json_object_set_number(key_len_obj, "increment", kmac_cap->key_len.increment);
        json_array_append_value(temp_arr, key_len_val);
    }

    list = kmac_cap->key_len.values;
    while (list) {
        json_array_append_number(temp_arr, list->length);
        list = list->next;
    }

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_build_sym_cipher_register_cap(JSON_Object *cap_obj, AMVP_CAPS_LIST *cap_entry) {
    JSON_Array *kwc_arr = NULL;
    JSON_Array *mode_arr = NULL;
    JSON_Array *opts_arr = NULL;
    AMVP_SL_LIST *sl_list;
    AMVP_RESULT result;
    AMVP_SYM_CIPHER_CAP *sym_cap;
    JSON_Object *tmp_obj = NULL;
    JSON_Value *tmp_val = NULL;
    const char *revision = NULL;

    json_object_set_string(cap_obj, "algorithm", amvp_lookup_cipher_name(cap_entry->cipher));

    revision = amvp_lookup_cipher_revision(cap_entry->cipher);
    if (revision == NULL) return AMVP_INVALID_ARG;
    json_object_set_string(cap_obj, "revision", revision);

    sym_cap = cap_entry->cap.sym_cap;
    if (!sym_cap) {
        return AMVP_MISSING_ARG;
    }
    result = amvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != AMVP_SUCCESS) { return result; }

    /*
     * If we have a non-default conformance, set the array
     */
    switch (sym_cap->conformance) {
    case AMVP_CONFORMANCE_RFC3686:
        json_object_set_value(cap_obj, "conformances", json_value_init_array());
        mode_arr = json_object_get_array(cap_obj, "conformances");
        json_array_append_string(mode_arr, AMVP_RFC3686_STR);
    case AMVP_CONFORMANCE_DEFAULT:
    case AMVP_CONFORMANCE_MAX:
    default:
        break;
    }

    /*
     * Set the direction capability
     */
    if (!sym_cap->direction) {
        return AMVP_MISSING_ARG;
    }
    json_object_set_value(cap_obj, "direction", json_value_init_array());
    mode_arr = json_object_get_array(cap_obj, "direction");
    if (sym_cap->direction == AMVP_SYM_CIPH_DIR_ENCRYPT ||
        sym_cap->direction == AMVP_SYM_CIPH_DIR_BOTH) {
        json_array_append_string(mode_arr, "encrypt");
    }
    if (sym_cap->direction == AMVP_SYM_CIPH_DIR_DECRYPT ||
        sym_cap->direction == AMVP_SYM_CIPH_DIR_BOTH) {
        json_array_append_string(mode_arr, "decrypt");
    }

    /*
     * Set the keywrap modes capability
     */
    if ((cap_entry->cipher == AMVP_AES_KW) || (cap_entry->cipher == AMVP_AES_KWP) ||
        (cap_entry->cipher == AMVP_TDES_KW)) {
        json_object_set_value(cap_obj, "kwCipher", json_value_init_array());
        kwc_arr = json_object_get_array(cap_obj, "kwCipher");
        if (sym_cap->kw_mode & AMVP_SYM_KW_CIPHER) {
            json_array_append_string(kwc_arr, "cipher");
        }
        if (sym_cap->kw_mode & AMVP_SYM_KW_INVERSE) {
            json_array_append_string(kwc_arr, "inverse");
        }
    }

    if ((cap_entry->cipher == AMVP_AES_CTR) || (cap_entry->cipher == AMVP_TDES_CTR)) {
        json_object_set_boolean(cap_obj, "incrementalCounter", sym_cap->ctr_incr);
        json_object_set_boolean(cap_obj, "overflowCounter", sym_cap->ctr_ovrflw);
        json_object_set_boolean(cap_obj, "performCounterTests", sym_cap->perform_ctr_tests);
    }

    /*
     * Set the IV generation source if applicable
     */

    //For some reason, RFC3686 uses "ivGenMode" instead of "ivGen" here- may be corrected
    //spec-side later on
    const char *ivGenLabel;
    if (cap_entry->cipher == AMVP_AES_CTR&& sym_cap->conformance == AMVP_CONFORMANCE_RFC3686) {
        ivGenLabel = AMVP_AES_RFC3686_IVGEN_STR;
    } else {
        ivGenLabel = AMVP_AES_IVGEN_STR;
    }
    switch (sym_cap->ivgen_source) {
    case AMVP_SYM_CIPH_IVGEN_SRC_INT:
        json_object_set_string(cap_obj, ivGenLabel, "internal");
        break;
    case AMVP_SYM_CIPH_IVGEN_SRC_EXT:
        json_object_set_string(cap_obj, ivGenLabel, "external");
        break;
    case AMVP_SYM_CIPH_IVGEN_SRC_NA:
    case AMVP_SYM_CIPH_IVGEN_SRC_MAX:
    case AMVP_SYM_CIPH_IVGEN_SRC_EITHER:
    default:
        if (cap_entry->cipher == AMVP_AES_GCM || cap_entry->cipher == AMVP_AES_GMAC ||
                cap_entry->cipher == AMVP_AES_XPN ||
                (cap_entry->cipher == AMVP_AES_CTR && sym_cap->conformance == AMVP_CONFORMANCE_RFC3686)) {
            return AMVP_MISSING_ARG;
        }
        break;
    }

        /*
     * Set the salt generation source if applicable (XPN)
     */
    switch (sym_cap->salt_source) {
    case AMVP_SYM_CIPH_SALT_SRC_INT:
        json_object_set_string(cap_obj, "saltGen", "internal");
        break;
    case AMVP_SYM_CIPH_SALT_SRC_EXT:
        json_object_set_string(cap_obj, "saltGen", "external");
        break;
    case AMVP_SYM_CIPH_SALT_SRC_NA:
    case AMVP_SYM_CIPH_SALT_SRC_MAX:
    default:
        /* do nothing, this is an optional capability */
        break;
    }

    /* Set the IV generation mode if applicable */
    if (sym_cap->ivgen_source == AMVP_SYM_CIPH_IVGEN_SRC_INT) {
        switch (sym_cap->ivgen_mode) {
        case AMVP_SYM_CIPH_IVGEN_MODE_821:
            json_object_set_string(cap_obj, "ivGenMode", "8.2.1");
            break;
        case AMVP_SYM_CIPH_IVGEN_MODE_822:
            json_object_set_string(cap_obj, "ivGenMode", "8.2.2");
            break;
        case AMVP_SYM_CIPH_IVGEN_MODE_NA:
        case AMVP_SYM_CIPH_IVGEN_MODE_MAX:
        default:
            return AMVP_MISSING_ARG;
            break;
        }
    }

    /*
     * Set the TDES keyingOptions  if applicable
     */
    if (sym_cap->keying_option != AMVP_SYM_CIPH_KO_NA) {
        json_object_set_value(cap_obj, "keyingOption", json_value_init_array());
        opts_arr = json_object_get_array(cap_obj, "keyingOption");
        if (sym_cap->keying_option == AMVP_SYM_CIPH_KO_THREE ||
            sym_cap->keying_option == AMVP_SYM_CIPH_KO_ONE ||
            sym_cap->keying_option == AMVP_SYM_CIPH_KO_BOTH) {
            json_array_append_number(opts_arr, 1);
        }
        if (sym_cap->keying_option == AMVP_SYM_CIPH_KO_TWO ||
            sym_cap->keying_option == AMVP_SYM_CIPH_KO_BOTH) {
            json_array_append_number(opts_arr, 2);
        }
    }

    /*
     * Set the supported key lengths
     */
    sl_list = sym_cap->keylen;
    if (sl_list) {
        json_object_set_value(cap_obj, "keyLen", json_value_init_array());
        opts_arr = json_object_get_array(cap_obj, "keyLen");
        while (sl_list) {
            json_array_append_number(opts_arr, sl_list->length);
            sl_list = sl_list->next;
        }
    } else {
        //If cipher is AES, we need keylengths. If TDES, we do not. 
        AMVP_SUB_AES checkAes = amvp_get_aes_alg(cap_entry->cipher);
        switch (checkAes) {
        case AMVP_SUB_AES_ECB:
        case AMVP_SUB_AES_CBC:
        case AMVP_SUB_AES_OFB:
        case AMVP_SUB_AES_CFB128:
        case AMVP_SUB_AES_CFB8:
        case AMVP_SUB_AES_CFB1:
        case AMVP_SUB_AES_CBC_CS1:
        case AMVP_SUB_AES_CBC_CS2:
        case AMVP_SUB_AES_CBC_CS3:
        case AMVP_SUB_AES_CCM:
        case AMVP_SUB_AES_GCM:
        case AMVP_SUB_AES_GCM_SIV:
        case AMVP_SUB_AES_CTR:
        case AMVP_SUB_AES_XTS:
        case AMVP_SUB_AES_XPN:
        case AMVP_SUB_AES_KW:
        case AMVP_SUB_AES_KWP:
        case AMVP_SUB_AES_GMAC:
            return AMVP_MISSING_ARG;
        default:
            break;
        }
    }

    /*
     * Set the supported tag lengths (for AEAD ciphers)
     */
    if ((cap_entry->cipher == AMVP_AES_GCM) || (cap_entry->cipher == AMVP_AES_CCM)
          || (cap_entry->cipher == AMVP_AES_GMAC) || (cap_entry->cipher == AMVP_AES_XPN)) {
        json_object_set_value(cap_obj, "tagLen", json_value_init_array());
        opts_arr = json_object_get_array(cap_obj, "tagLen");
        sl_list = sym_cap->taglen;
        while (sl_list) {
            json_array_append_number(opts_arr, sl_list->length);
            sl_list = sl_list->next;
        }
    }

    /*
     * Set the supported IV lengths
     */
    switch (cap_entry->cipher) {
    case AMVP_CIPHER_START:
    case AMVP_TDES_ECB:
    case AMVP_TDES_CBC:
    case AMVP_TDES_CBCI:
    case AMVP_TDES_OFB:
    case AMVP_TDES_OFBI:
    case AMVP_TDES_CFB1:
    case AMVP_TDES_CFB8:
    case AMVP_TDES_CFB64:
    case AMVP_TDES_CFBP1:
    case AMVP_TDES_CFBP8:
    case AMVP_TDES_CFBP64:
    case AMVP_TDES_CTR:
    case AMVP_TDES_KW:
    case AMVP_AES_ECB:
    case AMVP_AES_CFB1:
    case AMVP_AES_CFB8:
    case AMVP_AES_CFB128:
    case AMVP_AES_CTR:
    case AMVP_AES_OFB:
    case AMVP_AES_CBC:
    case AMVP_AES_CBC_CS1:
    case AMVP_AES_CBC_CS2:
    case AMVP_AES_CBC_CS3:
    case AMVP_AES_KW:
    case AMVP_AES_KWP:
    case AMVP_AES_XTS:
    case AMVP_AES_XPN:
    case AMVP_HASH_SHA1:
    case AMVP_HASH_SHA224:
    case AMVP_HASH_SHA256:
    case AMVP_HASH_SHA384:
    case AMVP_HASH_SHA512:
    case AMVP_HASH_SHA512_224:
    case AMVP_HASH_SHA512_256:
    case AMVP_HASH_SHA3_224:
    case AMVP_HASH_SHA3_256:
    case AMVP_HASH_SHA3_384:
    case AMVP_HASH_SHA3_512:
    case AMVP_HASH_SHAKE_128:
    case AMVP_HASH_SHAKE_256:
    case AMVP_HASHDRBG:
    case AMVP_HMACDRBG:
    case AMVP_CTRDRBG:
    case AMVP_HMAC_SHA1:
    case AMVP_HMAC_SHA2_224:
    case AMVP_HMAC_SHA2_256:
    case AMVP_HMAC_SHA2_384:
    case AMVP_HMAC_SHA2_512:
    case AMVP_HMAC_SHA2_512_224:
    case AMVP_HMAC_SHA2_512_256:
    case AMVP_HMAC_SHA3_224:
    case AMVP_HMAC_SHA3_256:
    case AMVP_HMAC_SHA3_384:
    case AMVP_HMAC_SHA3_512:
    case AMVP_CMAC_AES:
    case AMVP_CMAC_TDES:
    case AMVP_KMAC_128:
    case AMVP_KMAC_256:
    case AMVP_DSA_KEYGEN:
    case AMVP_DSA_PQGGEN:
    case AMVP_DSA_PQGVER:
    case AMVP_DSA_SIGGEN:
    case AMVP_DSA_SIGVER:
    case AMVP_RSA_KEYGEN:
    case AMVP_RSA_SIGGEN:
    case AMVP_RSA_SIGVER:
    case AMVP_ECDSA_KEYGEN:
    case AMVP_ECDSA_KEYVER:
    case AMVP_ECDSA_SIGGEN:
    case AMVP_ECDSA_SIGVER:
    case AMVP_KDF135_SNMP:
    case AMVP_KDF135_SSH:
    case AMVP_KDF135_SRTP:
    case AMVP_KDF135_IKEV2:
    case AMVP_KDF135_IKEV1:
    case AMVP_KDF135_X942:
    case AMVP_KDF135_X963:
    case AMVP_KDF108:
    case AMVP_PBKDF:
    case AMVP_KDF_TLS12:
    case AMVP_KDF_TLS13:
    case AMVP_KAS_ECC_CDH:
    case AMVP_KAS_ECC_COMP:
    case AMVP_KAS_ECC_NOCOMP:
    case AMVP_KAS_ECC_SSC:
    case AMVP_KAS_FFC_COMP:
    case AMVP_KAS_FFC_NOCOMP:
    case AMVP_KDA_ONESTEP:
    case AMVP_KDA_TWOSTEP:
    case AMVP_KDA_HKDF:
    case AMVP_RSA_DECPRIM:
    case AMVP_RSA_SIGPRIM:
    case AMVP_KAS_FFC_SSC:
    case AMVP_KAS_IFC_SSC:
    case AMVP_KTS_IFC:
    case AMVP_SAFE_PRIMES_KEYGEN:
    case AMVP_SAFE_PRIMES_KEYVER:
    case AMVP_CIPHER_END:
        break;
    case AMVP_AES_GCM:
    case AMVP_AES_GCM_SIV:
    case AMVP_AES_CCM:
    case AMVP_AES_GMAC:
    default:
        json_object_set_value(cap_obj, "ivLen", json_value_init_array());
        opts_arr = json_object_get_array(cap_obj, "ivLen");
        if (sym_cap->ivlen) {
            sl_list = sym_cap->ivlen;
            while (sl_list) {
                json_array_append_number(opts_arr, sl_list->length);
                sl_list = sl_list->next;
            }
        } else {
            tmp_val = json_value_init_object();
            tmp_obj = json_value_get_object(tmp_val);
            json_object_set_number(tmp_obj, "max", sym_cap->iv_len.max);
            json_object_set_number(tmp_obj, "min", sym_cap->iv_len.min);
            json_object_set_number(tmp_obj, "increment", sym_cap->iv_len.increment);
            json_array_append_value(opts_arr, tmp_val);
        }
    }

    /*
     * Set the supported lengths (could be pt, ct, data, etc.
     * see alg spec for more details)
     */
    if (sym_cap->ptlen) {
        json_object_set_value(cap_obj, "payloadLen", json_value_init_array());
        opts_arr = json_object_get_array(cap_obj, "payloadLen");
        sl_list = sym_cap->ptlen;
        while (sl_list) {
            json_array_append_number(opts_arr, sl_list->length);
            sl_list = sl_list->next;
        }
    } else if (sym_cap->payload_len.min || sym_cap->payload_len.max ||
                sym_cap->payload_len.increment) {
        json_object_set_value(cap_obj, "payloadLen", json_value_init_array());
        opts_arr = json_object_get_array(cap_obj, "payloadLen");
        tmp_val = json_value_init_object();
        tmp_obj = json_value_get_object(tmp_val);
        json_object_set_number(tmp_obj, "max", sym_cap->payload_len.max);
        json_object_set_number(tmp_obj, "min", sym_cap->payload_len.min);
        json_object_set_number(tmp_obj, "increment", sym_cap->payload_len.increment);
        json_array_append_value(opts_arr, tmp_val);
    } else {
        //For most AES ciphers, we need payload lengths. If TDES, we do not. 
        AMVP_SUB_AES checkAes = amvp_get_aes_alg(cap_entry->cipher);
        switch (checkAes) {
        case AMVP_SUB_AES_CBC_CS1:
        case AMVP_SUB_AES_CBC_CS2:
        case AMVP_SUB_AES_CBC_CS3:
        case AMVP_SUB_AES_CCM:
        case AMVP_SUB_AES_GCM:
        case AMVP_SUB_AES_GCM_SIV:
        case AMVP_SUB_AES_CTR:
        case AMVP_SUB_AES_XTS:
        case AMVP_SUB_AES_XPN:
        case AMVP_SUB_AES_KW:
        case AMVP_SUB_AES_KWP:
            return AMVP_MISSING_ARG;
        case AMVP_SUB_AES_CBC:
        case AMVP_SUB_AES_ECB:
        case AMVP_SUB_AES_OFB:
        case AMVP_SUB_AES_CFB128:
        case AMVP_SUB_AES_CFB8:
        case AMVP_SUB_AES_CFB1:
        case AMVP_SUB_AES_GMAC:
        default:
            break;
        }
    }

    if (cap_entry->cipher == AMVP_AES_XTS) {
        json_object_set_value(cap_obj, "tweakMode", json_value_init_array());
        opts_arr = json_object_get_array(cap_obj, "tweakMode");
        sl_list = sym_cap->tweak;
        while (sl_list) {
            switch (sl_list->length) {
            case AMVP_SYM_CIPH_TWEAK_HEX:
                json_array_append_string(opts_arr, "hex");
                break;
            case AMVP_SYM_CIPH_TWEAK_NUM:
                json_array_append_string(opts_arr, "number");
                break;
            default:
                break;
            }
            sl_list = sl_list->next;
        }

        json_object_set_boolean(cap_obj, "dataUnitLenMatchesPayload", sym_cap->dulen_matches_paylen);
        if (!sym_cap->dulen_matches_paylen) {
            json_object_set_value(cap_obj, "dataUnitLen", json_value_init_array());
            opts_arr = json_object_get_array(cap_obj, "dataUnitLen");
            tmp_val = json_value_init_object();
            tmp_obj = json_value_get_object(tmp_val);
            json_object_set_number(tmp_obj, "max", sym_cap->du_len.max);
            json_object_set_number(tmp_obj, "min", sym_cap->du_len.min);
            json_object_set_number(tmp_obj, "increment", sym_cap->du_len.increment);
            json_array_append_value(opts_arr, tmp_val);
        }
    }

    /*
     * Set the supported AAD lengths (for AEAD ciphers)
     */
    if ((cap_entry->cipher == AMVP_AES_GCM) || (cap_entry->cipher == AMVP_AES_CCM)
            || (cap_entry->cipher == AMVP_AES_GMAC) || (cap_entry->cipher == AMVP_AES_GCM_SIV)
            || (cap_entry->cipher == AMVP_AES_XPN)) {
        json_object_set_value(cap_obj, "aadLen", json_value_init_array());
        opts_arr = json_object_get_array(cap_obj, "aadLen");
        if (sym_cap->aadlen) {
            sl_list = sym_cap->aadlen;
            while (sl_list) {
                json_array_append_number(opts_arr, sl_list->length);
                sl_list = sl_list->next;
            }
        } else {
            tmp_val = json_value_init_object();
            tmp_obj = json_value_get_object(tmp_val);
            json_object_set_number(tmp_obj, "max", sym_cap->aad_len.max);
            json_object_set_number(tmp_obj, "min", sym_cap->aad_len.min);
            json_object_set_number(tmp_obj, "increment", sym_cap->aad_len.increment);
            json_array_append_value(opts_arr, tmp_val);
        }
    }
    return AMVP_SUCCESS;
}

static const char *amvp_lookup_drbg_mode_string(AMVP_DRBG_MODE_LIST *drbg_cap_mode) {
    const char *mode_str = NULL;

    switch (drbg_cap_mode->mode) {
    case AMVP_DRBG_SHA_1:
        mode_str = AMVP_STR_SHA_1;
        break;
    case AMVP_DRBG_SHA_224:
        mode_str = AMVP_STR_SHA2_224;
        break;
    case AMVP_DRBG_SHA_256:
        mode_str = AMVP_STR_SHA2_256;
        break;
    case AMVP_DRBG_SHA_384:
        mode_str = AMVP_STR_SHA2_384;
        break;
    case AMVP_DRBG_SHA_512:
        mode_str = AMVP_STR_SHA2_512;
        break;
    case AMVP_DRBG_SHA_512_224:
        mode_str = AMVP_STR_SHA2_512_224;
        break;
    case AMVP_DRBG_SHA_512_256:
        mode_str = AMVP_STR_SHA2_512_256;
        break;
    case AMVP_DRBG_TDES:
        mode_str = AMVP_DRBG_MODE_TDES;
        break;
    case AMVP_DRBG_AES_128:
        mode_str = AMVP_DRBG_MODE_AES_128;
        break;
    case AMVP_DRBG_AES_192:
        mode_str = AMVP_DRBG_MODE_AES_192;
        break;
    case AMVP_DRBG_AES_256:
        mode_str = AMVP_DRBG_MODE_AES_256;
        break;
    default:
        return NULL;
    }
    return mode_str;
}

static AMVP_RESULT amvp_build_drbg_register_cap(JSON_Object *cap_obj, AMVP_CAPS_LIST *cap_entry) {
    AMVP_RESULT result;
    AMVP_DRBG_CAP *cap = NULL;
    AMVP_DRBG_CAP_GROUP *cap_group = NULL;
    JSON_Object *len_obj = NULL;
    JSON_Value *len_val = NULL;
    JSON_Array *array = NULL;
    const char *revision = NULL;
    AMVP_DRBG_MODE_LIST *cap_mode_list = NULL;
    AMVP_DRBG_GROUP_LIST *cap_group_list = NULL;
    JSON_Value *val = NULL;
    JSON_Object *capabilities_obj = NULL;
    JSON_Array *capabilities_array = NULL;
    const char *mode_str = NULL;

    if (!&cap_entry->cap.drbg_cap) {
        return AMVP_NO_CAP;
    } else {
        cap = cap_entry->cap.drbg_cap;
    }

    if (!cap->drbg_cap_mode || !cap->drbg_cap_mode->groups) {
        return AMVP_MISSING_ARG;
    }

    json_object_set_string(cap_obj, "algorithm", amvp_lookup_cipher_name(cap_entry->cipher));

    revision = amvp_lookup_cipher_revision(cap_entry->cipher);
    if (revision == NULL) return AMVP_INVALID_ARG;
    json_object_set_string(cap_obj, "revision", revision);

    result = amvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != AMVP_SUCCESS) { return result; }

    json_object_set_value(cap_obj, "predResistanceEnabled", json_value_init_array());
    array = json_object_get_array(cap_obj, "predResistanceEnabled");
    json_array_append_boolean(array, cap->pred_resist_enabled);
    json_object_set_boolean(cap_obj, "reseedImplemented", cap->reseed_implemented);

    json_object_set_value(cap_obj, "capabilities", json_value_init_array());
    capabilities_array = json_object_get_array(cap_obj, "capabilities");

    cap_mode_list = cap->drbg_cap_mode;

     while(cap_mode_list) {
        cap_group_list = cap_mode_list->groups;
        mode_str = amvp_lookup_drbg_mode_string(cap_mode_list);
        if (!mode_str) { return AMVP_INVALID_ARG; }
        while (cap_group_list) {
            cap_group = cap_group_list->group;
            if (!cap_group) {
                return AMVP_INVALID_ARG;
            }

            val = json_value_init_object();
            capabilities_obj = json_value_get_object(val);
            json_object_set_string(capabilities_obj, "mode", mode_str);
            if (cap_entry->cipher == AMVP_CTRDRBG) {
                json_object_set_boolean(capabilities_obj, "derFuncEnabled", cap_group->der_func_enabled);
            }
            //Set entropy range
            json_object_set_value(capabilities_obj, "entropyInputLen", json_value_init_array());
            array = json_object_get_array(capabilities_obj, "entropyInputLen");
            if (!cap_group->entropy_len_step) {
                if (cap_group->entropy_len_min) {
                    json_array_append_number(array, cap_group->entropy_len_min);
                } else if (cap_group->entropy_len_max) {
                    json_array_append_number(array, cap_group->entropy_len_max);
                }
            } else {
                len_val = json_value_init_object();
                len_obj = json_value_get_object(len_val);
                json_object_set_number(len_obj, "max", cap_group->entropy_len_max);
                json_object_set_number(len_obj, "min", cap_group->entropy_len_min);
                json_object_set_number(len_obj, "increment", cap_group->entropy_len_step);
                json_array_append_value(array, len_val);
            }

            json_object_set_value(capabilities_obj, "nonceLen", json_value_init_array());
            array = json_object_get_array(capabilities_obj, "nonceLen");
            if (!cap_group->nonce_len_step) {
                if (cap_group->nonce_len_min) {
                    json_array_append_number(array, cap_group->nonce_len_min);
                } else if (cap_group->nonce_len_max) {
                    json_array_append_number(array, cap_group->nonce_len_max);
                }
                if (!cap_group->nonce_len_min && !cap_group->nonce_len_max) {
                    json_array_append_number(array, 0);
                }
            } else {
                len_val = json_value_init_object();
                len_obj = json_value_get_object(len_val);
                json_object_set_number(len_obj, "max", cap_group->nonce_len_max);
                json_object_set_number(len_obj, "min", cap_group->nonce_len_min);
                json_object_set_number(len_obj, "increment", cap_group->nonce_len_step);
                json_array_append_value(array, len_val);
            }

            json_object_set_value(capabilities_obj, "persoStringLen", json_value_init_array());
            array = json_object_get_array(capabilities_obj, "persoStringLen");
            if (!cap_group->perso_len_step) {
                if (cap_group->perso_len_min) {
                    json_array_append_number(array, cap_group->perso_len_min);
                } else if (cap_group->perso_len_max) {
                    json_array_append_number(array, cap_group->perso_len_max);
                }
                if (!cap_group->perso_len_min && !cap_group->perso_len_max) {
                    json_array_append_number(array, 0);
                }
            } else {
                len_val = json_value_init_object();
                len_obj = json_value_get_object(len_val);
                json_object_set_number(len_obj, "max", cap_group->perso_len_max);
                json_object_set_number(len_obj, "min", cap_group->perso_len_min);
                json_object_set_number(len_obj, "increment", cap_group->perso_len_step);
                json_array_append_value(array, len_val);
            }

            json_object_set_value(capabilities_obj, "additionalInputLen", json_value_init_array());
            array = json_object_get_array(capabilities_obj, "additionalInputLen");
            if (!cap_group->additional_in_len_step) {
                if (cap_group->additional_in_len_min) {
                    json_array_append_number(array, cap_group->additional_in_len_min);
                } else if (cap_group->additional_in_len_max) {
                    json_array_append_number(array, cap_group->additional_in_len_max);
                }
                if (!cap_group->additional_in_len_min && !cap_group->additional_in_len_max) {
                    json_array_append_number(array, 0);
                }
            } else {
                len_val = json_value_init_object();
                len_obj = json_value_get_object(len_val);
                json_object_set_number(len_obj, "max", cap_group->additional_in_len_max);
                json_object_set_number(len_obj, "min", cap_group->additional_in_len_min);
                json_object_set_number(len_obj, "increment", cap_group->additional_in_len_step);
                json_array_append_value(array, len_val);
            }

            //Set DRBG Length
            json_object_set_number(capabilities_obj, "returnedBitsLen", cap_group->returned_bits_len);
            json_array_append_value(capabilities_array, val);
            cap_group_list = cap_group_list->next;
        }
        cap_mode_list = cap_mode_list->next;
    }
    return AMVP_SUCCESS;
}

/*
 * Builds the JSON object for RSA keygen primes
 */
static AMVP_RESULT amvp_lookup_rsa_primes(JSON_Object *cap_obj, AMVP_RSA_KEYGEN_CAP *rsa_cap) {
    JSON_Array *primes_array = NULL, *hash_array = NULL, *prime_test_array = NULL;

    AMVP_RSA_MODE_CAPS_LIST *current_mode_cap;
    AMVP_NAME_LIST *comp_name, *next_name;

    if (!rsa_cap) { return AMVP_INVALID_ARG; }

    /*
     * return OK if nothing present
     */
    current_mode_cap = rsa_cap->mode_capabilities;
    if (!current_mode_cap) {
        return AMVP_SUCCESS;
    }

    json_object_set_value(cap_obj, "properties", json_value_init_array());
    primes_array = json_object_get_array(cap_obj, "properties");

    while (current_mode_cap) {
        JSON_Value *val = NULL;
        JSON_Object *obj = NULL;
        val = json_value_init_object();
        obj = json_value_get_object(val);

        json_object_set_number(obj, "modulo", current_mode_cap->modulo);

        json_object_set_value(obj, "hashAlg", json_value_init_array());
        hash_array = json_object_get_array(obj, "hashAlg");
        comp_name = current_mode_cap->hash_algs;

        while (comp_name) {
            if (amvp_lookup_hash_alg(comp_name->name)) {
                json_array_append_string(hash_array, comp_name->name);
            }
            next_name = comp_name->next;
            comp_name = next_name;
        }

        comp_name = current_mode_cap->prime_tests;

        if (comp_name) {
            json_object_set_value(obj, "primeTest", json_value_init_array());
            prime_test_array = json_object_get_array(obj, "primeTest");

            while (comp_name) {
                if (is_valid_prime_test(comp_name->name) == AMVP_SUCCESS) {
                    json_array_append_string(prime_test_array, comp_name->name);
                }
                next_name = comp_name->next;
                comp_name = next_name;
            }
        }

        json_array_append_value(primes_array, val);
        current_mode_cap = current_mode_cap->next;
    }
    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_build_rsa_keygen_register_cap(JSON_Object *cap_obj, AMVP_CAPS_LIST *cap_entry) {
    AMVP_RESULT result;
    const char *revision = NULL;

    json_object_set_string(cap_obj, "algorithm", "RSA");

    revision = amvp_lookup_cipher_revision(cap_entry->cipher);
    if (revision == NULL) return AMVP_INVALID_ARG;
    json_object_set_string(cap_obj, "revision", revision);

    json_object_set_string(cap_obj, "mode", "keyGen");

    result = amvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != AMVP_SUCCESS) { return result; }

    /*
     * Iterate through list of RSA modes and create registration object
     * for each one, appending to the array as we go
     */
    AMVP_RSA_KEYGEN_CAP *keygen_cap = cap_entry->cap.rsa_keygen_cap;
    if (!keygen_cap) {
        return AMVP_NO_CAP;
    }

    JSON_Array *alg_specs_array = NULL;
    JSON_Value *alg_specs_val = NULL;
    JSON_Object *alg_specs_obj = NULL;

    json_object_set_boolean(cap_obj, "infoGeneratedByServer", keygen_cap->info_gen_by_server);
    if (!keygen_cap->pub_exp_mode) {
        return AMVP_MISSING_ARG;
    }
    json_object_set_string(cap_obj, "pubExpMode",
                           keygen_cap->pub_exp_mode == AMVP_RSA_PUB_EXP_MODE_FIXED ?
                           AMVP_RSA_PUB_EXP_MODE_FIXED_STR : AMVP_RSA_PUB_EXP_MODE_RANDOM_STR);
    if (keygen_cap->pub_exp_mode == AMVP_RSA_PUB_EXP_MODE_FIXED) {
        json_object_set_string(cap_obj, "fixedPubExp", (const char *)keygen_cap->fixed_pub_exp);
    }
    json_object_set_string(cap_obj, "keyFormat", keygen_cap->key_format_crt ? "crt" : "standard");

    json_object_set_value(cap_obj, "capabilities", json_value_init_array());
    alg_specs_array = json_object_get_array(cap_obj, "capabilities");

    while (keygen_cap) {
        alg_specs_val = json_value_init_object();
        alg_specs_obj = json_value_get_object(alg_specs_val);

        json_object_set_string(alg_specs_obj, "randPQ", amvp_lookup_rsa_randpq_name(keygen_cap->rand_pq));
        result = amvp_lookup_rsa_primes(alg_specs_obj, keygen_cap);
        if (result != AMVP_SUCCESS) {
            return result;
        }

        json_array_append_value(alg_specs_array, alg_specs_val);
        keygen_cap = keygen_cap->next;
    }

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_build_rsa_sig_register_cap(JSON_Object *cap_obj, AMVP_CAPS_LIST *cap_entry) {
    AMVP_RESULT result = AMVP_SUCCESS;
    AMVP_RSA_SIG_CAP *rsa_cap_mode = NULL;
    JSON_Array *alg_specs_array = NULL, *sig_type_caps_array = NULL, *hash_pair_array = NULL;
    JSON_Value *alg_specs_val = NULL, *sig_type_val = NULL, *hash_pair_val = NULL;
    JSON_Object *alg_specs_obj = NULL, *sig_type_obj = NULL, *hash_pair_obj = NULL;
    const char *revision = NULL;
    int diff = 1;

    json_object_set_string(cap_obj, "algorithm", "RSA");

    revision = amvp_lookup_cipher_revision(cap_entry->cipher);
    if (revision == NULL) return AMVP_INVALID_ARG;
    json_object_set_string(cap_obj, "revision", revision);

    if (cap_entry->cipher == AMVP_RSA_SIGGEN) {
        json_object_set_string(cap_obj, "mode", "sigGen");
        rsa_cap_mode = cap_entry->cap.rsa_siggen_cap;
        if (!rsa_cap_mode) {
            return AMVP_MISSING_ARG;
        }
        result = amvp_lookup_prereqVals(cap_obj, cap_entry);
        if (result != AMVP_SUCCESS) { return result; }
    } else if (cap_entry->cipher == AMVP_RSA_SIGVER) {
        json_object_set_string(cap_obj, "mode", "sigVer");
        rsa_cap_mode = cap_entry->cap.rsa_sigver_cap;
        if (!rsa_cap_mode) {
            return AMVP_MISSING_ARG;
        }
        result = amvp_lookup_prereqVals(cap_obj, cap_entry);
        if (result != AMVP_SUCCESS) { return result; }

        json_object_set_string(cap_obj, "pubExpMode",
                               rsa_cap_mode->pub_exp_mode == AMVP_RSA_PUB_EXP_MODE_FIXED ?
                               AMVP_RSA_PUB_EXP_MODE_FIXED_STR : AMVP_RSA_PUB_EXP_MODE_RANDOM_STR);
        if (rsa_cap_mode->pub_exp_mode == AMVP_RSA_PUB_EXP_MODE_FIXED) {
            json_object_set_string(cap_obj, "fixedPubExp", (const char *)rsa_cap_mode->fixed_pub_exp);
        }
    }

    json_object_set_value(cap_obj, "capabilities", json_value_init_array());
    alg_specs_array = json_object_get_array(cap_obj, "capabilities");

    while (rsa_cap_mode) {
        alg_specs_val = json_value_init_object();
        alg_specs_obj = json_value_get_object(alg_specs_val);
        json_object_set_string(alg_specs_obj, "sigType", rsa_cap_mode->sig_type_str);

        json_object_set_value(alg_specs_obj, "properties", json_value_init_array());
        sig_type_caps_array = json_object_get_array(alg_specs_obj, "properties");

        AMVP_RSA_MODE_CAPS_LIST *current_sig_type_cap = rsa_cap_mode->mode_capabilities;

        while (current_sig_type_cap) {
            sig_type_val = json_value_init_object();
            sig_type_obj = json_value_get_object(sig_type_val);

            json_object_set_number(sig_type_obj, "modulo", current_sig_type_cap->modulo);
            json_object_set_value(sig_type_obj, "hashPair", json_value_init_array());
            hash_pair_array = json_object_get_array(sig_type_obj, "hashPair");

            AMVP_RSA_HASH_PAIR_LIST *current_hash_pair = current_sig_type_cap->hash_pair;
            while (current_hash_pair) {
                hash_pair_val = json_value_init_object();
                hash_pair_obj = json_value_get_object(hash_pair_val);
                if (!current_hash_pair->name) {
                    return AMVP_MISSING_ARG;
                }
                json_object_set_string(hash_pair_obj, "hashAlg", current_hash_pair->name);
                strncmp_s(rsa_cap_mode->sig_type_str, AMVP_RSA_SIG_TYPE_LEN_MAX, "pss", 3, &diff);
                if (!diff) {
                    json_object_set_number(hash_pair_obj, "saltLen", current_hash_pair->salt);
                }

                json_array_append_value(hash_pair_array, hash_pair_val);
                current_hash_pair = current_hash_pair->next;
            }

            current_sig_type_cap = current_sig_type_cap->next;
            json_array_append_value(sig_type_caps_array, sig_type_val);
        }
        json_array_append_value(alg_specs_array, alg_specs_val);
        rsa_cap_mode = rsa_cap_mode->next;
    }

    return result;
}

static AMVP_RESULT amvp_build_rsa_prim_register_cap(JSON_Object *cap_obj, AMVP_CAPS_LIST *cap_entry) {
    AMVP_RESULT result;
    const char *revision = NULL;

    json_object_set_string(cap_obj, "algorithm", "RSA");

    revision = amvp_lookup_cipher_revision(cap_entry->cipher);
    if (revision == NULL) return AMVP_INVALID_ARG;
    json_object_set_string(cap_obj, "revision", revision);

    if (cap_entry->cipher == AMVP_RSA_DECPRIM) {
        json_object_set_string(cap_obj, "mode", "decryptionPrimitive");
    } else if (cap_entry->cipher == AMVP_RSA_SIGPRIM) {
        json_object_set_string(cap_obj, "mode", "signaturePrimitive");
    } else {
        return AMVP_INVALID_ARG;
    }
    result = amvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != AMVP_SUCCESS) { return result; }

    /*
     * Iterate through list of RSA modes and create registration object
     * for each one, appending to the array as we go
     */
    AMVP_RSA_PRIM_CAP *prim_cap = cap_entry->cap.rsa_prim_cap;
    if (!prim_cap) {
        return AMVP_NO_CAP;
    }

    if (cap_entry->cipher == AMVP_RSA_SIGPRIM) {
        json_object_set_string(cap_obj, "pubExpMode",
                               prim_cap->pub_exp_mode == AMVP_RSA_PUB_EXP_MODE_FIXED ?
                               AMVP_RSA_PUB_EXP_MODE_FIXED_STR : AMVP_RSA_PUB_EXP_MODE_RANDOM_STR);
        if (prim_cap->pub_exp_mode == AMVP_RSA_PUB_EXP_MODE_FIXED) {
            json_object_set_string(cap_obj, "fixedPubExp", (const char *)prim_cap->fixed_pub_exp);
        }
        json_object_set_string(cap_obj, "keyFormat", prim_cap->key_format_crt ? "crt" : "standard");
    }

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_build_ecdsa_register_cap(AMVP_CTX *ctx, AMVP_CIPHER cipher, JSON_Object *cap_obj, AMVP_CAPS_LIST *cap_entry) {
    AMVP_RESULT result;
    JSON_Array *caps_arr = NULL, *curves_arr = NULL, *secret_modes_arr = NULL, *hash_arr = NULL;
    AMVP_CURVE_ALG_COMPAT_LIST *current_curve = NULL, *iter = NULL;
    AMVP_NAME_LIST *current_secret_mode = NULL;
    JSON_Value *alg_caps_val = NULL;
    JSON_Object *alg_caps_obj = NULL;
    const char *revision = NULL, *tmp = NULL;
    int i = 0, diff = 0;
    AMVP_EC_CURVE track[AMVP_EC_CURVE_END + 1] = { 0 };
    AMVP_SUB_ECDSA alg;

    json_object_set_string(cap_obj, "algorithm", "ECDSA");

    revision = amvp_lookup_cipher_revision(cap_entry->cipher);
    if (revision == NULL) return AMVP_INVALID_ARG;
    json_object_set_string(cap_obj, "revision", revision);

    alg = amvp_get_ecdsa_alg(cap_entry->cipher);
    if (alg == 0) {
        AMVP_LOG_ERR("Invalid cipher value");
        return 1;
    }

    switch (alg) {
    case AMVP_SUB_ECDSA_KEYGEN:
        json_object_set_string(cap_obj, "mode", "keyGen");
        if (!cap_entry->cap.ecdsa_keygen_cap) {
            return AMVP_NO_CAP;
        }
        current_curve = cap_entry->cap.ecdsa_keygen_cap->curves;
        current_secret_mode = cap_entry->cap.ecdsa_keygen_cap->secret_gen_modes;
        break;
    case AMVP_SUB_ECDSA_KEYVER:
        json_object_set_string(cap_obj, "mode", "keyVer");
        if (!cap_entry->cap.ecdsa_keyver_cap) {
            return AMVP_NO_CAP;
        }
        current_curve = cap_entry->cap.ecdsa_keyver_cap->curves;
        break;
    case AMVP_SUB_ECDSA_SIGGEN:
        json_object_set_string(cap_obj, "mode", "sigGen");
        if (!cap_entry->cap.ecdsa_siggen_cap) {
            return AMVP_NO_CAP;
        }
        if (cap_entry->cap.ecdsa_siggen_cap->component == AMVP_ECDSA_COMPONENT_MODE_YES) {
            json_object_set_boolean(cap_obj, "componentTest", 1);
        } else {
            json_object_set_boolean(cap_obj, "componentTest", 0);
        }
        current_curve = cap_entry->cap.ecdsa_siggen_cap->curves;
        //add "universally" set hash algs here instead of later to be resliant to different combos of API calls
        while (current_curve) {
            for (i = 0; i < AMVP_HASH_ALG_MAX; i++) {
                if (cap_entry->cap.ecdsa_siggen_cap->hash_algs[i]) {
                    current_curve->algs[i] = 1;
                }
            }
            current_curve = current_curve->next;
        }
        current_curve = cap_entry->cap.ecdsa_siggen_cap->curves;
        break;
    case AMVP_SUB_ECDSA_SIGVER:
        json_object_set_string(cap_obj, "mode", "sigVer");
        if (!cap_entry->cap.ecdsa_sigver_cap) {
            return AMVP_NO_CAP;
        }
        if (cap_entry->cap.ecdsa_sigver_cap->component == AMVP_ECDSA_COMPONENT_MODE_YES) {
            json_object_set_boolean(cap_obj, "componentTest", 1);
        } else {
            json_object_set_boolean(cap_obj, "componentTest", 0);
        }
        current_curve = cap_entry->cap.ecdsa_sigver_cap->curves;
        //add "universally" set hash algs here instead of later to be resliant to different combos of API calls
        while (current_curve) {
            for (i = 0; i < AMVP_HASH_ALG_MAX; i++) {
                if (cap_entry->cap.ecdsa_sigver_cap->hash_algs[i]) {
                    current_curve->algs[i] = 1;
                }
            }
            current_curve = current_curve->next;
        }
        current_curve = cap_entry->cap.ecdsa_sigver_cap->curves;
        break;
    default:
        return AMVP_INVALID_ARG;
        break;
    }

    result = amvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != AMVP_SUCCESS) { return result; }

    if (!current_curve) {
        if (alg_caps_val) json_value_free(alg_caps_val);
        return AMVP_MISSING_ARG;
    }

    /*
     * Iterate through list of ECDSA modes and create registration object
     * for each one, appending to the array as we go
     */
    if (cipher == AMVP_ECDSA_KEYVER || cipher == AMVP_ECDSA_KEYGEN) {
        json_object_set_value(cap_obj, "curve", json_value_init_array());
        curves_arr = json_object_get_array(cap_obj, "curve");
        while (current_curve) {
            tmp = amvp_lookup_ec_curve_name(cipher, current_curve->curve);
            if (!tmp) {
                if (alg_caps_val) json_value_free(alg_caps_val);
                return AMVP_MISSING_ARG;
            }
            json_array_append_string(curves_arr, tmp);
            current_curve = current_curve->next;
        }
    }

    if (cipher == AMVP_ECDSA_KEYGEN) {
        json_object_set_value(cap_obj, "secretGenerationMode", json_value_init_array());
        secret_modes_arr = json_object_get_array(cap_obj, "secretGenerationMode");
        while (current_secret_mode) {
            if (!current_secret_mode->name) {
                return AMVP_MISSING_ARG;
            }
            json_array_append_string(secret_modes_arr, current_secret_mode->name);
            current_secret_mode = current_secret_mode->next;
        }
    }

    /**
     * hashAlgs is relatively complicated. We want to compare every curve that is registered and the hash
     * algs registered to them. If they have the same hash algs, we put them in the same object within
     * the capabilities array. If they have different hash algs, a new object is created.
     */
    if (cipher == AMVP_ECDSA_SIGGEN || cipher == AMVP_ECDSA_SIGVER) {
        json_object_set_value(cap_obj, "capabilities", json_value_init_array());
        caps_arr = json_object_get_array(cap_obj, "capabilities");

        while (current_curve) {
            if (!current_curve->curve) {
                if (alg_caps_val) json_value_free(alg_caps_val);
                return AMVP_MISSING_ARG;
            }

            if (track[current_curve->curve]) {
                current_curve = current_curve->next;
                continue;
            }

            //One of these vals for every object in the array - every object being list of curves
            //that share the same hashAlgs
            alg_caps_val = json_value_init_object();
            alg_caps_obj = json_value_get_object(alg_caps_val);

            json_object_set_value(alg_caps_obj, "curve", json_value_init_array());
            curves_arr = json_object_get_array(alg_caps_obj, "curve");
            json_object_set_value(alg_caps_obj, "hashAlg", json_value_init_array());
            hash_arr = json_object_get_array(alg_caps_obj, "hashAlg");

            tmp = amvp_lookup_ec_curve_name(cipher, current_curve->curve);
            if (!tmp) {
                if (alg_caps_val) json_value_free(alg_caps_val);
                return AMVP_INVALID_ARG;
            }

            //Add current curve and its hash algs to current obj
            json_array_append_string(curves_arr, tmp);
            for (i = 0; i < AMVP_HASH_ALG_MAX; i++) {
                if (current_curve->algs[i]) {
                    tmp = amvp_lookup_hash_alg_name(i);
                    if (!tmp) {
                        if (alg_caps_val) json_value_free(alg_caps_val);
                        return AMVP_INVALID_ARG;
                    }
                    json_array_append_string(hash_arr, tmp);
                }
            }
            //Track that we have already dealt with this curve
            track[current_curve->curve] = 1;

            //Now, check every curve on the list aftetwards, and memcmp to see if it has the same hashAlgs,
            //appending it to the same obj when applicable
            iter = current_curve->next;
            while (iter) {
                //If the curve is already accounted for by a previous current_curve, skip
                if (current_curve->curve == iter->curve || track[iter->curve]) {
                    iter = iter->next;
                    continue;
                }
                memcmp_s(current_curve->algs, sizeof(current_curve->algs), iter->algs, sizeof(iter->algs), &diff);
                if (!diff) {
                    //if they have the same algs arrays, they go in the same obj in the capabilities array
                    tmp = amvp_lookup_ec_curve_name(cipher, iter->curve);
                    if (!tmp) {
                        if (alg_caps_val) json_value_free(alg_caps_val);
                        return AMVP_INVALID_ARG;
                    }
                    json_array_append_string(curves_arr, tmp);
                    track[iter->curve] = 1;
                }
                iter = iter->next;
            }

            //Now, append the obj to the array before moving on
            json_array_append_value(caps_arr, alg_caps_val);
            current_curve = current_curve->next;
        }
    }

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_build_kdf135_snmp_register_cap(JSON_Object *cap_obj, AMVP_CAPS_LIST *cap_entry) {
    AMVP_RESULT result;
    JSON_Array *temp_arr = NULL;
    AMVP_NAME_LIST *current_engid;
    AMVP_SL_LIST *current_val;
    const char *revision = NULL;

    json_object_set_string(cap_obj, "algorithm", AMVP_KDF135_ALG_STR);

    revision = amvp_lookup_cipher_revision(cap_entry->cipher);
    if (revision == NULL) return AMVP_INVALID_ARG;
    json_object_set_string(cap_obj, "revision", revision);

    json_object_set_string(cap_obj, "mode", AMVP_ALG_KDF135_SNMP);

    result = amvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != AMVP_SUCCESS) { return result; }

    json_object_set_value(cap_obj, "engineId", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "engineId");

    current_engid = cap_entry->cap.kdf135_snmp_cap->eng_ids;
    while (current_engid) {
        json_array_append_string(temp_arr, current_engid->name);
        current_engid = current_engid->next;
    }

    json_object_set_value(cap_obj, "passwordLength", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "passwordLength");

    current_val = cap_entry->cap.kdf135_snmp_cap->pass_lens;
    while (current_val) {
        json_array_append_number(temp_arr, current_val->length);
        current_val = current_val->next;
    }

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_build_kdf108_mode_register(JSON_Object **mode_obj, AMVP_KDF108_MODE_PARAMS *mode_params) {
    JSON_Array *tmp_arr = NULL;
    JSON_Value *tmp_val = NULL;
    JSON_Object *tmp_obj = NULL;
    AMVP_NAME_LIST *nl_obj;
    AMVP_SL_LIST *sl_obj;

    /* mac mode list */
    json_object_set_value(*mode_obj, "macMode", json_value_init_array());
    tmp_arr = json_object_get_array(*mode_obj, "macMode");
    nl_obj = mode_params->mac_mode;
    while (nl_obj) {
        json_array_append_string(tmp_arr, nl_obj->name);
        nl_obj = nl_obj->next;
    }

    /* supported lens domain obj */
    json_object_set_value(*mode_obj, "supportedLengths", json_value_init_array());
    tmp_arr = json_object_get_array(*mode_obj, "supportedLengths");
    if (mode_params->supported_lens.increment != 0) {
        tmp_val = json_value_init_object();
        tmp_obj = json_value_get_object(tmp_val);
        json_object_set_number(tmp_obj, "min", mode_params->supported_lens.min);
        json_object_set_number(tmp_obj, "max", mode_params->supported_lens.max);
        json_object_set_number(tmp_obj, "increment", mode_params->supported_lens.increment);
        json_array_append_value(tmp_arr, tmp_val);
    }

    sl_obj = mode_params->supported_lens.values;
    while (sl_obj) {
        json_array_append_number(tmp_arr, sl_obj->length);
        sl_obj = sl_obj->next;
    }

    /* fixed data order list */
    json_object_set_value(*mode_obj, "fixedDataOrder", json_value_init_array());
    tmp_arr = json_object_get_array(*mode_obj, "fixedDataOrder");
    nl_obj = mode_params->data_order;
    while (nl_obj) {
        json_array_append_string(tmp_arr, nl_obj->name);
        nl_obj = nl_obj->next;
    }

    /* counter length list */
    json_object_set_value(*mode_obj, "counterLength", json_value_init_array());
    tmp_arr = json_object_get_array(*mode_obj, "counterLength");
    sl_obj = mode_params->counter_lens;
    while (sl_obj) {
        json_array_append_number(tmp_arr, sl_obj->length);
        sl_obj = sl_obj->next;
    }

    json_object_set_boolean(*mode_obj, "supportsEmptyIv", mode_params->empty_iv_support);
    if (mode_params->empty_iv_support) {
        json_object_set_boolean(*mode_obj, "requiresEmptyIv", mode_params->requires_empty_iv);
    }

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_build_kdf108_register_cap(JSON_Object *cap_obj, AMVP_CAPS_LIST *cap_entry) {
    AMVP_RESULT result;
    JSON_Array *alg_specs_array = NULL;
    JSON_Value *alg_specs_counter_val = NULL, *alg_specs_feedback_val = NULL, *alg_specs_dpi_val = NULL;
    JSON_Object *alg_specs_counter_obj = NULL, *alg_specs_feedback_obj = NULL, *alg_specs_dpi_obj = NULL;
    const char *revision = NULL;

    json_object_set_string(cap_obj, "algorithm", "KDF");

    revision = amvp_lookup_cipher_revision(cap_entry->cipher);
    if (revision == NULL) return AMVP_INVALID_ARG;
    json_object_set_string(cap_obj, "revision", revision);

    result = amvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != AMVP_SUCCESS) { return result; }

    json_object_set_value(cap_obj, "capabilities", json_value_init_array());
    alg_specs_array = json_object_get_array(cap_obj, "capabilities");

    if (cap_entry->cap.kdf108_cap->counter_mode.kdf_mode) {
        alg_specs_counter_val = json_value_init_object();
        alg_specs_counter_obj = json_value_get_object(alg_specs_counter_val);
        json_object_set_string(alg_specs_counter_obj, "kdfMode", "counter");
        amvp_build_kdf108_mode_register(&alg_specs_counter_obj, &cap_entry->cap.kdf108_cap->counter_mode);
        json_array_append_value(alg_specs_array, alg_specs_counter_val);
    }
    if (cap_entry->cap.kdf108_cap->feedback_mode.kdf_mode) {
        alg_specs_feedback_val = json_value_init_object();
        alg_specs_feedback_obj = json_value_get_object(alg_specs_feedback_val);
        json_object_set_string(alg_specs_feedback_obj, "kdfMode", "feedback");
        amvp_build_kdf108_mode_register(&alg_specs_feedback_obj, &cap_entry->cap.kdf108_cap->feedback_mode);
        json_array_append_value(alg_specs_array, alg_specs_feedback_val);
    }
    if (cap_entry->cap.kdf108_cap->dpi_mode.kdf_mode) {
        alg_specs_dpi_val = json_value_init_object();
        alg_specs_dpi_obj = json_value_get_object(alg_specs_dpi_val);
        json_object_set_string(alg_specs_dpi_obj, "kdfMode", "dpi");
        amvp_build_kdf108_mode_register(&alg_specs_dpi_obj, &cap_entry->cap.kdf108_cap->dpi_mode);
        json_array_append_value(alg_specs_array, alg_specs_dpi_val);
    }

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_build_kdf135_x942_register_cap(JSON_Object *cap_obj, AMVP_CAPS_LIST *cap_entry) {
    AMVP_RESULT result;
    JSON_Array *tmp_arr = NULL;
    JSON_Value *tmp_val = NULL;
    JSON_Object *tmp_obj = NULL;
    AMVP_NAME_LIST *nl_obj = NULL;
    AMVP_KDF135_X942_CAP *cap = NULL;
    const char *revision = NULL;

    json_object_set_string(cap_obj, "algorithm", AMVP_KDF135_ALG_STR);

    revision = amvp_lookup_cipher_revision(cap_entry->cipher);
    if (revision == NULL) return AMVP_INVALID_ARG;
    json_object_set_string(cap_obj, "revision", revision);

    json_object_set_string(cap_obj, "mode", AMVP_ALG_KDF135_X942);

    result = amvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != AMVP_SUCCESS) { return result; }

    cap = cap_entry->cap.kdf135_x942_cap;

    /* KDF type */
    json_object_set_value(cap_obj, "kdfType", json_value_init_array());
    tmp_arr = json_object_get_array(cap_obj, "kdfType");
    tmp_val = json_value_init_object();
    tmp_obj = json_value_get_object(tmp_val);
    switch (cap->type) {
    case AMVP_KDF_X942_KDF_TYPE_DER:
        json_array_append_string(tmp_arr, "DER");
        break;
    case AMVP_KDF_X942_KDF_TYPE_CONCAT:
        json_array_append_string(tmp_arr, "concatenation");
        break;
    case AMVP_KDF_X942_KDF_TYPE_BOTH:
        json_array_append_string(tmp_arr, "DER");
        json_array_append_string(tmp_arr, "concatenation");
        break;
    default:
        return AMVP_INVALID_ARG;
    }

    /* key length list */
    json_object_set_value(cap_obj, "keyLen", json_value_init_array());
    tmp_arr = json_object_get_array(cap_obj, "keyLen");
    tmp_val = json_value_init_object();
    tmp_obj = json_value_get_object(tmp_val);
    json_object_set_number(tmp_obj, "min", cap->key_len.min);
    json_object_set_number(tmp_obj, "max", cap->key_len.max);
    json_object_set_number(tmp_obj, "increment", cap->key_len.increment);
    json_array_append_value(tmp_arr, tmp_val);

    /* other info length list */
    json_object_set_value(cap_obj, "otherInfoLen", json_value_init_array());
    tmp_arr = json_object_get_array(cap_obj, "otherInfoLen");
    tmp_val = json_value_init_object();
    tmp_obj = json_value_get_object(tmp_val);
    json_object_set_number(tmp_obj, "min", cap->other_len.min);
    json_object_set_number(tmp_obj, "max", cap->other_len.max);
    json_object_set_number(tmp_obj, "increment", cap->other_len.increment);
    json_array_append_value(tmp_arr, tmp_val);

    /* supp info length list */
    json_object_set_value(cap_obj, "suppInfoLen", json_value_init_array());
    tmp_arr = json_object_get_array(cap_obj, "suppInfoLen");
    tmp_val = json_value_init_object();
    tmp_obj = json_value_get_object(tmp_val);
    json_object_set_number(tmp_obj, "min", cap->supp_len.min);
    json_object_set_number(tmp_obj, "max", cap->supp_len.max);
    json_object_set_number(tmp_obj, "increment", cap->supp_len.increment);
    json_array_append_value(tmp_arr, tmp_val);

    /* zz length list */
    json_object_set_value(cap_obj, "zzLen", json_value_init_array());
    tmp_arr = json_object_get_array(cap_obj, "zzLen");
    tmp_val = json_value_init_object();
    tmp_obj = json_value_get_object(tmp_val);
    json_object_set_number(tmp_obj, "min", cap->zz_len.min);
    json_object_set_number(tmp_obj, "max", cap->zz_len.max);
    json_object_set_number(tmp_obj, "increment", cap->zz_len.increment);
    json_array_append_value(tmp_arr, tmp_val);

    /* Array of hash algs */
    json_object_set_value(cap_obj, "hashAlg", json_value_init_array());
    tmp_arr = json_object_get_array(cap_obj, "hashAlg");
    nl_obj = cap->hash_algs;
    while (nl_obj) {
        json_array_append_string(tmp_arr, nl_obj->name);
        nl_obj = nl_obj->next;
    }

    /* Array of OIDs */
    if (cap->type == AMVP_KDF_X942_KDF_TYPE_DER || cap->type == AMVP_KDF_X942_KDF_TYPE_BOTH) {
        json_object_set_value(cap_obj, "oid", json_value_init_array());
        tmp_arr = json_object_get_array(cap_obj, "oid");
        nl_obj = cap->oids;
        while (nl_obj) {
            json_array_append_string(tmp_arr, nl_obj->name);
            nl_obj = nl_obj->next;
        }
    }
    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_build_kdf135_x963_register_cap(JSON_Object *cap_obj, AMVP_CAPS_LIST *cap_entry) {
    AMVP_RESULT result;
    JSON_Array *tmp_arr = NULL;
    AMVP_NAME_LIST *nl_obj;
    AMVP_SL_LIST *sl_obj;
    const char *revision = NULL;

    json_object_set_string(cap_obj, "algorithm", AMVP_KDF135_ALG_STR);

    revision = amvp_lookup_cipher_revision(cap_entry->cipher);
    if (revision == NULL) return AMVP_INVALID_ARG;
    json_object_set_string(cap_obj, "revision", revision);

    json_object_set_string(cap_obj, "mode", "ansix9.63");

    result = amvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != AMVP_SUCCESS) { return result; }

    /* Array of hash algs */
    json_object_set_value(cap_obj, "hashAlg", json_value_init_array());
    tmp_arr = json_object_get_array(cap_obj, "hashAlg");
    nl_obj = cap_entry->cap.kdf135_x963_cap->hash_algs;
    while (nl_obj) {
        json_array_append_string(tmp_arr, nl_obj->name);
        nl_obj = nl_obj->next;
    }

    /* key data length list */
    json_object_set_value(cap_obj, "keyDataLength", json_value_init_array());
    tmp_arr = json_object_get_array(cap_obj, "keyDataLength");
    sl_obj = cap_entry->cap.kdf135_x963_cap->key_data_lengths;
    while (sl_obj) {
        json_array_append_number(tmp_arr, sl_obj->length);
        sl_obj = sl_obj->next;
    }

    /* field size list */
    json_object_set_value(cap_obj, "fieldSize", json_value_init_array());
    tmp_arr = json_object_get_array(cap_obj, "fieldSize");
    sl_obj = cap_entry->cap.kdf135_x963_cap->field_sizes;
    while (sl_obj) {
        json_array_append_number(tmp_arr, sl_obj->length);
        sl_obj = sl_obj->next;
    }

    /* shared info length list */
    json_object_set_value(cap_obj, "sharedInfoLength", json_value_init_array());
    tmp_arr = json_object_get_array(cap_obj, "sharedInfoLength");
    sl_obj = cap_entry->cap.kdf135_x963_cap->shared_info_lengths;
    while (sl_obj) {
        json_array_append_number(tmp_arr, sl_obj->length);
        sl_obj = sl_obj->next;
    }

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_build_kdf135_ikev2_register_cap(JSON_Object *cap_obj, AMVP_CAPS_LIST *cap_entry) {
    AMVP_RESULT result;
    JSON_Array *tmp_arr = NULL, *alg_specs_array = NULL;
    JSON_Value *tmp_val = NULL, *alg_specs_val = NULL;
    JSON_Object *tmp_obj = NULL, *alg_specs_obj = NULL;
    AMVP_NAME_LIST *current_hash;
    AMVP_SL_LIST *list;
    AMVP_KDF135_IKEV2_CAP *cap = cap_entry->cap.kdf135_ikev2_cap;
    const char *revision = NULL;

    json_object_set_string(cap_obj, "algorithm", AMVP_KDF135_ALG_STR);

    revision = amvp_lookup_cipher_revision(cap_entry->cipher);
    if (revision == NULL) return AMVP_INVALID_ARG;
    json_object_set_string(cap_obj, "revision", revision);

    json_object_set_string(cap_obj, "mode", AMVP_ALG_KDF135_IKEV2);
    result = amvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != AMVP_SUCCESS) { return result; }

    json_object_set_value(cap_obj, "capabilities", json_value_init_array());
    alg_specs_array = json_object_get_array(cap_obj, "capabilities");

    alg_specs_val = json_value_init_object();
    alg_specs_obj = json_value_get_object(alg_specs_val);

    /* initiator nonce len */
    json_object_set_value(alg_specs_obj, "initiatorNonceLength", json_value_init_array());
    tmp_arr = json_object_get_array(alg_specs_obj, "initiatorNonceLength");

    if (cap->init_nonce_len_domain.increment != 0) {
        tmp_val = json_value_init_object();
        tmp_obj = json_value_get_object(tmp_val);
        json_object_set_number(tmp_obj, "min", cap->init_nonce_len_domain.min);
        json_object_set_number(tmp_obj, "max", cap->init_nonce_len_domain.max);
        json_object_set_number(tmp_obj, "increment", cap->init_nonce_len_domain.increment);
        json_array_append_value(tmp_arr, tmp_val);
    }

    list = cap->init_nonce_len_domain.values;
    while (list) {
        json_array_append_number(tmp_arr, list->length);
        list = list->next;
    }

    /* responder nonce len */
    json_object_set_value(alg_specs_obj, "responderNonceLength", json_value_init_array());
    tmp_arr = json_object_get_array(alg_specs_obj, "responderNonceLength");

    if (cap->respond_nonce_len_domain.increment != 0) {
        tmp_val = json_value_init_object();
        tmp_obj = json_value_get_object(tmp_val);
        json_object_set_number(tmp_obj, "min", cap->respond_nonce_len_domain.min);
        json_object_set_number(tmp_obj, "max", cap->respond_nonce_len_domain.max);
        json_object_set_number(tmp_obj, "increment", cap->respond_nonce_len_domain.increment);
        json_array_append_value(tmp_arr, tmp_val);
    }

    list = cap->respond_nonce_len_domain.values;
    while (list) {
        json_array_append_number(tmp_arr, list->length);
        list = list->next;
    }

    /* Diffie Hellman shared secret len */
    json_object_set_value(alg_specs_obj, "diffieHellmanSharedSecretLength", json_value_init_array());
    tmp_arr = json_object_get_array(alg_specs_obj, "diffieHellmanSharedSecretLength");

    if (cap->dh_secret_len.increment != 0) {
        tmp_val = json_value_init_object();
        tmp_obj = json_value_get_object(tmp_val);
        json_object_set_number(tmp_obj, "min", cap->dh_secret_len.min);
        json_object_set_number(tmp_obj, "max", cap->dh_secret_len.max);
        json_object_set_number(tmp_obj, "increment", cap->dh_secret_len.increment);
        json_array_append_value(tmp_arr, tmp_val);
    }

    list = cap->dh_secret_len.values;
    while (list) {
        json_array_append_number(tmp_arr, list->length);
        list = list->next;
    }

    /* Derived keying material len */
    json_object_set_value(alg_specs_obj, "derivedKeyingMaterialLength", json_value_init_array());
    tmp_arr = json_object_get_array(alg_specs_obj, "derivedKeyingMaterialLength");

    if (cap->key_material_len.increment != 0) {
        tmp_val = json_value_init_object();
        tmp_obj = json_value_get_object(tmp_val);
        json_object_set_number(tmp_obj, "min", cap->key_material_len.min);
        json_object_set_number(tmp_obj, "max", cap->key_material_len.max);
        json_object_set_number(tmp_obj, "increment", cap->key_material_len.increment);
        json_array_append_value(tmp_arr, tmp_val);
    }
    list = cap->key_material_len.values;
    while (list) {
        json_array_append_number(tmp_arr, list->length);
        list = list->next;
    }

    /* Array of hash algs */
    json_object_set_value(alg_specs_obj, "hashAlg", json_value_init_array());
    tmp_arr = json_object_get_array(alg_specs_obj, "hashAlg");
    current_hash = cap->hash_algs;
    while (current_hash) {
        json_array_append_string(tmp_arr, current_hash->name);
        current_hash = current_hash->next;
    }

    json_array_append_value(alg_specs_array, alg_specs_val);

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_build_kdf135_ikev1_register_cap(JSON_Object *cap_obj, AMVP_CAPS_LIST *cap_entry) {
    AMVP_RESULT result;
    JSON_Array *alg_specs_array = NULL, *tmp_arr = NULL;
    JSON_Value *alg_specs_val = NULL, *tmp_val = NULL;
    JSON_Object *alg_specs_obj = NULL, *tmp_obj = NULL;
    AMVP_NAME_LIST *current_hash;
    const char *revision = NULL;

    json_object_set_string(cap_obj, "algorithm", AMVP_KDF135_ALG_STR);

    revision = amvp_lookup_cipher_revision(cap_entry->cipher);
    if (revision == NULL) return AMVP_INVALID_ARG;
    json_object_set_string(cap_obj, "revision", revision);

    json_object_set_string(cap_obj, "mode", AMVP_ALG_KDF135_IKEV1);
    result = amvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != AMVP_SUCCESS) { return result; }

    json_object_set_value(cap_obj, "capabilities", json_value_init_array());
    alg_specs_array = json_object_get_array(cap_obj, "capabilities");

    alg_specs_val = json_value_init_object();
    alg_specs_obj = json_value_get_object(alg_specs_val);

    /* initiator nonce len */
    json_object_set_value(alg_specs_obj, "initiatorNonceLength", json_value_init_array());
    tmp_arr = json_object_get_array(alg_specs_obj, "initiatorNonceLength");
    tmp_val = json_value_init_object();
    tmp_obj = json_value_get_object(tmp_val);
    json_object_set_number(tmp_obj, "min", cap_entry->cap.kdf135_ikev1_cap->init_nonce_len_domain.min);
    json_object_set_number(tmp_obj, "max", cap_entry->cap.kdf135_ikev1_cap->init_nonce_len_domain.max);
    json_object_set_number(tmp_obj, "increment", cap_entry->cap.kdf135_ikev1_cap->init_nonce_len_domain.increment);
    json_array_append_value(tmp_arr, tmp_val);

    /* responder nonce len */
    json_object_set_value(alg_specs_obj, "responderNonceLength", json_value_init_array());
    tmp_arr = json_object_get_array(alg_specs_obj, "responderNonceLength");
    tmp_val = json_value_init_object();
    tmp_obj = json_value_get_object(tmp_val);
    json_object_set_number(tmp_obj, "min", cap_entry->cap.kdf135_ikev1_cap->respond_nonce_len_domain.min);
    json_object_set_number(tmp_obj, "max", cap_entry->cap.kdf135_ikev1_cap->respond_nonce_len_domain.max);
    json_object_set_number(tmp_obj, "increment", cap_entry->cap.kdf135_ikev1_cap->respond_nonce_len_domain.increment);
    json_array_append_value(tmp_arr, tmp_val);

    /* Diffie Hellman shared secret len */
    json_object_set_value(alg_specs_obj, "diffieHellmanSharedSecretLength", json_value_init_array());
    tmp_arr = json_object_get_array(alg_specs_obj, "diffieHellmanSharedSecretLength");
    tmp_val = json_value_init_object();
    tmp_obj = json_value_get_object(tmp_val);
    json_object_set_number(tmp_obj, "min", cap_entry->cap.kdf135_ikev1_cap->dh_secret_len.min);
    json_object_set_number(tmp_obj, "max", cap_entry->cap.kdf135_ikev1_cap->dh_secret_len.max);
    json_object_set_number(tmp_obj, "increment", cap_entry->cap.kdf135_ikev1_cap->dh_secret_len.increment);
    json_array_append_value(tmp_arr, tmp_val);

    /* Pre shared key len */
    json_object_set_value(alg_specs_obj, "preSharedKeyLength", json_value_init_array());
    tmp_arr = json_object_get_array(alg_specs_obj, "preSharedKeyLength");
    tmp_val = json_value_init_object();
    tmp_obj = json_value_get_object(tmp_val);
    json_object_set_number(tmp_obj, "min", cap_entry->cap.kdf135_ikev1_cap->psk_len.min);
    json_object_set_number(tmp_obj, "max", cap_entry->cap.kdf135_ikev1_cap->psk_len.max);
    json_object_set_number(tmp_obj, "increment", cap_entry->cap.kdf135_ikev1_cap->psk_len.increment);
    json_array_append_value(tmp_arr, tmp_val);

    /* Array of hash algs */
    json_object_set_value(alg_specs_obj, "hashAlg", json_value_init_array());
    tmp_arr = json_object_get_array(alg_specs_obj, "hashAlg");
    current_hash = cap_entry->cap.kdf135_ikev1_cap->hash_algs;
    while (current_hash) {
        json_array_append_string(tmp_arr, current_hash->name);
        current_hash = current_hash->next;
    }

    json_object_set_string(alg_specs_obj, "authenticationMethod", cap_entry->cap.kdf135_ikev1_cap->auth_method);

    json_array_append_value(alg_specs_array, alg_specs_val);

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_build_kdf135_srtp_register_cap(JSON_Object *cap_obj, AMVP_CAPS_LIST *cap_entry) {
    AMVP_RESULT result;
    JSON_Array *tmp_arr = NULL;
    int i;
    AMVP_SL_LIST *current_aes_keylen;
    const char *revision = NULL;

    json_object_set_string(cap_obj, "algorithm", AMVP_KDF135_ALG_STR);

    revision = amvp_lookup_cipher_revision(cap_entry->cipher);
    if (revision == NULL) return AMVP_INVALID_ARG;
    json_object_set_string(cap_obj, "revision", revision);

    json_object_set_string(cap_obj, "mode", AMVP_ALG_KDF135_SRTP);

    result = amvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != AMVP_SUCCESS) { return result; }

    json_object_set_value(cap_obj, "aesKeyLength", json_value_init_array());
    tmp_arr = json_object_get_array(cap_obj, "aesKeyLength");
    current_aes_keylen = cap_entry->cap.kdf135_srtp_cap->aes_keylens;
    while (current_aes_keylen) {
        json_array_append_number(tmp_arr, current_aes_keylen->length);
        current_aes_keylen = current_aes_keylen->next;
    }

    json_object_set_boolean(cap_obj, "supportsZeroKdr", cap_entry->cap.kdf135_srtp_cap->supports_zero_kdr);

    json_object_set_value(cap_obj, "kdrExponent", json_value_init_array());
    tmp_arr = json_object_get_array(cap_obj, "kdrExponent");
    for (i = 0; i < 24; i++) {
        if (cap_entry->cap.kdf135_srtp_cap->kdr_exp[i] == 1) {
            json_array_append_number(tmp_arr, i + 1);
        }
    }

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_build_kdf135_ssh_register_cap(JSON_Object *cap_obj, AMVP_CAPS_LIST *cap_entry) {
    JSON_Array *temp_arr = NULL;
    AMVP_RESULT result;
    const char *revision = NULL;

    json_object_set_string(cap_obj, "algorithm", amvp_lookup_cipher_name(cap_entry->cipher));

    revision = amvp_lookup_cipher_revision(cap_entry->cipher);
    if (revision == NULL) return AMVP_INVALID_ARG;
    json_object_set_string(cap_obj, "revision", revision);

    json_object_set_string(cap_obj, "mode", AMVP_ALG_KDF135_SSH);
    json_object_set_value(cap_obj, "cipher", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "cipher");
    if (cap_entry->cap.kdf135_ssh_cap->method[0] == AMVP_SSH_METH_TDES_CBC) {
        json_array_append_string(temp_arr, "TDES");
    }

    if (cap_entry->cap.kdf135_ssh_cap->method[1] == AMVP_SSH_METH_AES_128_CBC) {
        json_array_append_string(temp_arr, "AES-128");
    }

    if (cap_entry->cap.kdf135_ssh_cap->method[2] == AMVP_SSH_METH_AES_192_CBC) {
        json_array_append_string(temp_arr, "AES-192");
    }

    if (cap_entry->cap.kdf135_ssh_cap->method[3] == AMVP_SSH_METH_AES_256_CBC) {
        json_array_append_string(temp_arr, "AES-256");
    }

    json_object_set_value(cap_obj, "hashAlg", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "hashAlg");
    if (cap_entry->cap.kdf135_ssh_cap->sha & AMVP_SHA1) {
        json_array_append_string(temp_arr, "SHA-1");
    }
    if (cap_entry->cap.kdf135_ssh_cap->sha & AMVP_SHA224) {
        json_array_append_string(temp_arr, "SHA2-224");
    }
    if (cap_entry->cap.kdf135_ssh_cap->sha & AMVP_SHA256) {
        json_array_append_string(temp_arr, "SHA2-256");
    }
    if (cap_entry->cap.kdf135_ssh_cap->sha & AMVP_SHA384) {
        json_array_append_string(temp_arr, "SHA2-384");
    }
    if (cap_entry->cap.kdf135_ssh_cap->sha & AMVP_SHA512) {
        json_array_append_string(temp_arr, "SHA2-512");
    }

    result = amvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != AMVP_SUCCESS) { return result; }

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_build_pbkdf_register_cap(JSON_Object *cap_obj, AMVP_CAPS_LIST *cap_entry) {
    JSON_Array *temp_cap_arr = NULL;
    JSON_Array *temp_arr = NULL;
    JSON_Value *tmp_val = NULL, *cap_val = NULL;
    JSON_Object *tmp_obj = NULL, *cap_sub_obj = NULL;
    AMVP_NAME_LIST *hmac_alg_list = NULL;
    AMVP_RESULT result;
    const char *revision = NULL;

    json_object_set_string(cap_obj, "algorithm", amvp_lookup_cipher_name(cap_entry->cipher));

    revision = amvp_lookup_cipher_revision(cap_entry->cipher);
    if (revision == NULL) return AMVP_INVALID_ARG;
    json_object_set_string(cap_obj, "revision", revision);

    result = amvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != AMVP_SUCCESS) { return result; }

    json_object_set_value(cap_obj, "capabilities", json_value_init_array());
    temp_cap_arr = json_object_get_array(cap_obj, "capabilities");
    cap_val = json_value_init_object();
    cap_sub_obj = json_value_get_object(cap_val);

    //create the "iterationCount" array within the "capabilities" array and populate it
    json_object_set_value(cap_sub_obj, "iterationCount", json_value_init_array());
    temp_arr = json_object_get_array(cap_sub_obj, "iterationCount");
    tmp_val = json_value_init_object();
    tmp_obj = json_value_get_object(tmp_val);
    json_object_set_number(tmp_obj, "min", cap_entry->cap.pbkdf_cap->iteration_count_domain.min);
    json_object_set_number(tmp_obj, "max", cap_entry->cap.pbkdf_cap->iteration_count_domain.max);
    json_object_set_number(tmp_obj, "increment", cap_entry->cap.pbkdf_cap->iteration_count_domain.increment);
    json_array_append_value(temp_arr, tmp_val);

    //create the "keyLen" array within the "capabilities" array and populate it
    json_object_set_value(cap_sub_obj, "keyLen", json_value_init_array());
    temp_arr = json_object_get_array(cap_sub_obj, "keyLen");
    tmp_val = json_value_init_object();
    tmp_obj = json_value_get_object(tmp_val);
    json_object_set_number(tmp_obj, "min", cap_entry->cap.pbkdf_cap->key_len_domain.min);
    json_object_set_number(tmp_obj, "max", cap_entry->cap.pbkdf_cap->key_len_domain.max);
    json_object_set_number(tmp_obj, "increment", cap_entry->cap.pbkdf_cap->key_len_domain.increment);
    json_array_append_value(temp_arr, tmp_val);

    //create the "passwordLen" array within the "capabilities" array and populate it
    json_object_set_value(cap_sub_obj, "passwordLen", json_value_init_array());
    temp_arr = json_object_get_array(cap_sub_obj, "passwordLen");
    tmp_val = json_value_init_object();
    tmp_obj = json_value_get_object(tmp_val);
    json_object_set_number(tmp_obj, "min", cap_entry->cap.pbkdf_cap->password_len_domain.min);
    json_object_set_number(tmp_obj, "max", cap_entry->cap.pbkdf_cap->password_len_domain.max);
    json_object_set_number(tmp_obj, "increment", cap_entry->cap.pbkdf_cap->password_len_domain.increment);
    json_array_append_value(temp_arr, tmp_val);

    //create the "saltLen" array within the "capabilities" array and populate it
    json_object_set_value(cap_sub_obj, "saltLen", json_value_init_array());
    temp_arr = json_object_get_array(cap_sub_obj, "saltLen");
    tmp_val = json_value_init_object();
    tmp_obj = json_value_get_object(tmp_val);
    json_object_set_number(tmp_obj, "min", cap_entry->cap.pbkdf_cap->salt_len_domain.min);
    json_object_set_number(tmp_obj, "max", cap_entry->cap.pbkdf_cap->salt_len_domain.max);
    json_object_set_number(tmp_obj, "increment", cap_entry->cap.pbkdf_cap->salt_len_domain.increment);
    json_array_append_value(temp_arr, tmp_val);

    //create the "hmacAlg" array within the "capabilities" array and populate it
    json_object_set_value(cap_sub_obj, "hmacAlg", json_value_init_array());
    temp_arr = json_object_get_array(cap_sub_obj, "hmacAlg");
    hmac_alg_list = cap_entry->cap.pbkdf_cap->hmac_algs;
    while (hmac_alg_list) {
        json_array_append_string(temp_arr, hmac_alg_list->name);
        hmac_alg_list = hmac_alg_list->next;
    }

    json_array_append_value(temp_cap_arr, cap_val);
    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_build_kdf_tls12_register_cap(JSON_Object *cap_obj, AMVP_CAPS_LIST *cap_entry) {
    JSON_Array *temp_arr = NULL;
    AMVP_RESULT result;
    const char *revision = NULL, *mode = NULL;
    AMVP_NAME_LIST *hash_alg_list = NULL;

    json_object_set_string(cap_obj, "algorithm", AMVP_ALG_TLS12);

    revision = amvp_lookup_cipher_revision(cap_entry->cipher);
    if (!revision) return AMVP_INVALID_ARG;
    json_object_set_string(cap_obj, "revision", revision);

    mode = amvp_lookup_cipher_mode_str(AMVP_KDF_TLS12);
    if (mode == NULL) return AMVP_INVALID_ARG;
    json_object_set_string(cap_obj, "mode", mode);

    //create the "hashAlg" array and populate it
    json_object_set_value(cap_obj, "hashAlg", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "hashAlg");
    hash_alg_list = cap_entry->cap.kdf_tls12_cap->hash_algs;
    while (hash_alg_list) {
        json_array_append_string(temp_arr, hash_alg_list->name);
        hash_alg_list = hash_alg_list->next;
    }

    result = amvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != AMVP_SUCCESS) { return result; }

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_build_kdf_tls13_register_cap(JSON_Object *cap_obj, AMVP_CAPS_LIST *cap_entry) {
    JSON_Array *temp_arr = NULL;
    AMVP_NAME_LIST *hmac_alg_list = NULL;
    AMVP_PARAM_LIST *run_mode_list = NULL;
    AMVP_RESULT result;
    const char *revision = NULL, *mode = NULL;

    json_object_set_string(cap_obj, "algorithm", amvp_lookup_cipher_name(cap_entry->cipher));

    revision = amvp_lookup_cipher_revision(cap_entry->cipher);
    if (revision == NULL) return AMVP_INVALID_ARG;
    json_object_set_string(cap_obj, "revision", revision);

    mode = amvp_lookup_cipher_mode_str(AMVP_KDF_TLS13);
    if (mode == NULL) return AMVP_INVALID_ARG;
    json_object_set_string(cap_obj, "mode", mode);

    result = amvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != AMVP_SUCCESS) { return result; }

    //create the "hmacAlg" array and populate it
    json_object_set_value(cap_obj, "hmacAlg", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "hmacAlg");
    hmac_alg_list = cap_entry->cap.kdf_tls13_cap->hmac_algs;
    while (hmac_alg_list) {
        json_array_append_string(temp_arr, hmac_alg_list->name);
        hmac_alg_list = hmac_alg_list->next;
    }

    //create the "runningMode" array and populate it
    json_object_set_value(cap_obj, "runningMode", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "runningMode");
    run_mode_list = cap_entry->cap.kdf_tls13_cap->running_mode;
    while (run_mode_list) {
        if (run_mode_list->param == AMVP_KDF_TLS13_RUN_MODE_PSK) {
            json_array_append_string(temp_arr, AMVP_STR_KDF_TLS13_PSK);
        } else if (run_mode_list->param == AMVP_KDF_TLS13_RUN_MODE_DHE) {
            json_array_append_string(temp_arr, AMVP_STR_KDF_TLS13_DHE);
        } else if (run_mode_list->param == AMVP_KDF_TLS13_RUN_MODE_PSK_DHE) {
            json_array_append_string(temp_arr, AMVP_STR_KDF_TLS13_PSK_DHE);
        } else {
            return AMVP_INVALID_ARG;
        }
        run_mode_list = run_mode_list->next;
    }

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_build_dsa_hashalgs(JSON_Object *cap_obj,
                                           AMVP_DSA_ATTRS *attrs) {
    JSON_Array *sha_arr = NULL;

    json_object_set_value(cap_obj, "hashAlg", json_value_init_array());
    sha_arr = json_object_get_array(cap_obj, "hashAlg");
    if (!sha_arr) {
        return AMVP_JSON_ERR;
    }

    if (attrs->sha & AMVP_SHA1) {
        json_array_append_string(sha_arr, "SHA-1");
    }
    if (attrs->sha & AMVP_SHA224) {
        json_array_append_string(sha_arr, "SHA2-224");
    }
    if (attrs->sha & AMVP_SHA256) {
        json_array_append_string(sha_arr, "SHA2-256");
    }
    if (attrs->sha & AMVP_SHA384) {
        json_array_append_string(sha_arr, "SHA2-384");
    }
    if (attrs->sha & AMVP_SHA512) {
        json_array_append_string(sha_arr, "SHA2-512");
    }
    if (attrs->sha & AMVP_SHA512_224) {
        json_array_append_string(sha_arr, "SHA2-512/224");
    }
    if (attrs->sha & AMVP_SHA512_256) {
        json_array_append_string(sha_arr, "SHA2-512/256");
    }

    if (json_array_get_count(sha_arr) == 0) {
        return AMVP_MISSING_ARG;
    }

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_build_dsa_pqggen_register(JSON_Array *meth_array,
                                                  AMVP_CAPS_LIST *cap_entry) {
    AMVP_DSA_ATTRS *attrs = NULL;
    AMVP_RESULT rv;
    AMVP_DSA_CAP_MODE *dsa_cap_mode = NULL;
    JSON_Array *temp_arr = NULL;
    JSON_Value *new_cap_val = NULL;
    JSON_Object *new_cap_obj = NULL;

    dsa_cap_mode = &cap_entry->cap.dsa_cap->dsa_cap_mode[AMVP_DSA_MODE_PQGGEN - 1];
    attrs = dsa_cap_mode->dsa_attrs;
    if (!attrs) {
        return AMVP_MISSING_ARG;
    }

    while (attrs) {
        new_cap_val = json_value_init_object();
        new_cap_obj = json_value_get_object(new_cap_val);

        json_object_set_value(new_cap_obj, "pqGen", json_value_init_array());
        temp_arr = json_object_get_array(new_cap_obj, "pqGen");
        if (dsa_cap_mode->gen_pq_prob) {
            json_array_append_string(temp_arr, "probable");
        }
        if (dsa_cap_mode->gen_pq_prov) {
            json_array_append_string(temp_arr, "provable");
        }
        if (!dsa_cap_mode->gen_pq_prob && !dsa_cap_mode->gen_pq_prov) {
            return AMVP_MISSING_ARG;
        }

        json_object_set_value(new_cap_obj, "gGen", json_value_init_array());
        temp_arr = json_object_get_array(new_cap_obj, "gGen");
        if (dsa_cap_mode->gen_g_unv) {
            json_array_append_string(temp_arr, "unverifiable");
        }
        if (dsa_cap_mode->gen_g_can) {
            json_array_append_string(temp_arr, "canonical");
        }
        if (!dsa_cap_mode->gen_g_unv && !dsa_cap_mode->gen_g_can) {
            return AMVP_MISSING_ARG;
        }

        switch (attrs->modulo) {
        case AMVP_DSA_LN2048_224:
            json_object_set_number(new_cap_obj, "l", 2048);
            json_object_set_number(new_cap_obj, "n", 224);
            break;
        case AMVP_DSA_LN2048_256:
            json_object_set_number(new_cap_obj, "l", 2048);
            json_object_set_number(new_cap_obj, "n", 256);
            break;
        case AMVP_DSA_LN3072_256:
            json_object_set_number(new_cap_obj, "l", 3072);
            json_object_set_number(new_cap_obj, "n", 256);
            break;
        case AMVP_DSA_LN1024_160:
        default:
            return AMVP_INVALID_ARG;

            break;
        }
        rv = amvp_build_dsa_hashalgs(new_cap_obj, attrs);
        if (rv != AMVP_SUCCESS) {
            return rv;
        }

        attrs = attrs->next;
        json_array_append_value(meth_array, new_cap_val);
    }
    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_build_dsa_pqgver_register(JSON_Array *meth_array,
                                                  AMVP_CAPS_LIST *cap_entry) {
    AMVP_RESULT result = AMVP_SUCCESS;
    AMVP_DSA_ATTRS *attrs = NULL;
    AMVP_DSA_CAP_MODE *dsa_cap_mode = NULL;
    JSON_Array *temp_arr = NULL;
    JSON_Value *new_cap_val = NULL;
    JSON_Object *new_cap_obj = NULL;

    dsa_cap_mode = &cap_entry->cap.dsa_cap->dsa_cap_mode[AMVP_DSA_MODE_PQGVER - 1];
    attrs = dsa_cap_mode->dsa_attrs;

    while (attrs) {
        new_cap_val = json_value_init_object();
        new_cap_obj = json_value_get_object(new_cap_val);

        json_object_set_value(new_cap_obj, "pqGen", json_value_init_array());
        temp_arr = json_object_get_array(new_cap_obj, "pqGen");
        if (dsa_cap_mode->gen_pq_prob) {
            json_array_append_string(temp_arr, "probable");
        }
        if (dsa_cap_mode->gen_pq_prov) {
            json_array_append_string(temp_arr, "provable");
        }
        if (!dsa_cap_mode->gen_pq_prob && !dsa_cap_mode->gen_pq_prov) {
            return AMVP_MISSING_ARG;
        }

        json_object_set_value(new_cap_obj, "gGen", json_value_init_array());
        temp_arr = json_object_get_array(new_cap_obj, "gGen");
        if (dsa_cap_mode->gen_g_unv) {
            json_array_append_string(temp_arr, "unverifiable");
        }
        if (dsa_cap_mode->gen_g_can) {
            json_array_append_string(temp_arr, "canonical");
        }
        if (!dsa_cap_mode->gen_g_unv && !dsa_cap_mode->gen_g_can) {
            return AMVP_MISSING_ARG;
        }

        switch (attrs->modulo) {
        case AMVP_DSA_LN1024_160:
            json_object_set_number(new_cap_obj, "l", 1024);
            json_object_set_number(new_cap_obj, "n", 160);
            break;
        case AMVP_DSA_LN2048_224:
            json_object_set_number(new_cap_obj, "l", 2048);
            json_object_set_number(new_cap_obj, "n", 224);
            break;
        case AMVP_DSA_LN2048_256:
            json_object_set_number(new_cap_obj, "l", 2048);
            json_object_set_number(new_cap_obj, "n", 256);
            break;
        case AMVP_DSA_LN3072_256:
            json_object_set_number(new_cap_obj, "l", 3072);
            json_object_set_number(new_cap_obj, "n", 256);
            break;
        default:
            break;
        }
        result = amvp_build_dsa_hashalgs(new_cap_obj, attrs);
        if (result != AMVP_SUCCESS) {
            return result;
        }

        attrs = attrs->next;
        json_array_append_value(meth_array, new_cap_val);
    }

    return result;
}

static AMVP_RESULT amvp_build_dsa_keygen_register(JSON_Array *meth_array,
                                                  AMVP_CAPS_LIST *cap_entry) {
    AMVP_DSA_CAP_MODE *dsa_cap_mode = NULL;
    AMVP_DSA_ATTRS *attrs = NULL;
    JSON_Value *ln_val = NULL;
    JSON_Object *ln_obj = NULL;

    dsa_cap_mode = &cap_entry->cap.dsa_cap->dsa_cap_mode[AMVP_DSA_MODE_KEYGEN - 1];
    attrs = dsa_cap_mode->dsa_attrs;

    while (attrs) {
        switch (attrs->modulo) {
        case AMVP_DSA_LN2048_224:
            ln_val = json_value_init_object();
            ln_obj = json_value_get_object(ln_val);
            json_object_set_number(ln_obj, "l", 2048);
            json_object_set_number(ln_obj, "n", 224);
            json_array_append_value(meth_array, ln_val);
            break;
        case AMVP_DSA_LN2048_256:
            ln_val = json_value_init_object();
            ln_obj = json_value_get_object(ln_val);
            json_object_set_number(ln_obj, "l", 2048);
            json_object_set_number(ln_obj, "n", 256);
            json_array_append_value(meth_array, ln_val);
            break;
        case AMVP_DSA_LN3072_256:
            ln_val = json_value_init_object();
            ln_obj = json_value_get_object(ln_val);
            json_object_set_number(ln_obj, "l", 3072);
            json_object_set_number(ln_obj, "n", 256);
            json_array_append_value(meth_array, ln_val);
            break;
        case AMVP_DSA_LN1024_160:
        default:
            break;
        }
        attrs = attrs->next;
    }

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_build_dsa_siggen_register(JSON_Array *meth_array,
                                                  AMVP_CAPS_LIST *cap_entry) {
    AMVP_DSA_CAP_MODE *dsa_cap_mode = NULL;
    AMVP_RESULT rv;
    AMVP_DSA_ATTRS *attrs = NULL;
    JSON_Value *new_cap_val = NULL;
    JSON_Object *new_cap_obj = NULL;

    dsa_cap_mode = &cap_entry->cap.dsa_cap->dsa_cap_mode[AMVP_DSA_MODE_SIGGEN - 1];
    attrs = dsa_cap_mode->dsa_attrs;

    while (attrs) {
        new_cap_val = json_value_init_object();
        new_cap_obj = json_value_get_object(new_cap_val);

        switch (attrs->modulo) {
        case AMVP_DSA_LN2048_224:
            json_object_set_number(new_cap_obj, "l", 2048);
            json_object_set_number(new_cap_obj, "n", 224);
            break;
        case AMVP_DSA_LN2048_256:
            json_object_set_number(new_cap_obj, "l", 2048);
            json_object_set_number(new_cap_obj, "n", 256);
            break;
        case AMVP_DSA_LN3072_256:
            json_object_set_number(new_cap_obj, "l", 3072);
            json_object_set_number(new_cap_obj, "n", 256);
            break;
        case AMVP_DSA_LN1024_160:
        default:
            break;
        }
        rv = amvp_build_dsa_hashalgs(new_cap_obj, attrs);
        if (rv != AMVP_SUCCESS) {
            return rv;
        }
        attrs = attrs->next;
        json_array_append_value(meth_array, new_cap_val);
    }

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_build_dsa_sigver_register(JSON_Array *meth_array,
                                                  AMVP_CAPS_LIST *cap_entry) {
    AMVP_DSA_CAP_MODE *dsa_cap_mode = NULL;
    AMVP_RESULT rv;
    AMVP_DSA_ATTRS *attrs = NULL;
    JSON_Value *new_cap_val = NULL;
    JSON_Object *new_cap_obj = NULL;

    dsa_cap_mode = &cap_entry->cap.dsa_cap->dsa_cap_mode[AMVP_DSA_MODE_SIGVER - 1];
    attrs = dsa_cap_mode->dsa_attrs;

    while (attrs) {
        new_cap_val = json_value_init_object();
        new_cap_obj = json_value_get_object(new_cap_val);

        switch (attrs->modulo) {
        case AMVP_DSA_LN1024_160:
            json_object_set_number(new_cap_obj, "l", 1024);
            json_object_set_number(new_cap_obj, "n", 160);
            break;
        case AMVP_DSA_LN2048_224:
            json_object_set_number(new_cap_obj, "l", 2048);
            json_object_set_number(new_cap_obj, "n", 224);
            break;
        case AMVP_DSA_LN2048_256:
            json_object_set_number(new_cap_obj, "l", 2048);
            json_object_set_number(new_cap_obj, "n", 256);
            break;
        case AMVP_DSA_LN3072_256:
            json_object_set_number(new_cap_obj, "l", 3072);
            json_object_set_number(new_cap_obj, "n", 256);
            break;
        default:
            break;
        }
        rv = amvp_build_dsa_hashalgs(new_cap_obj, attrs);
        if (rv != AMVP_SUCCESS) {
            return rv;
        }

        attrs = attrs->next;
        json_array_append_value(meth_array, new_cap_val);
    }

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_build_dsa_register_cap(JSON_Object *cap_obj,
                                               AMVP_CAPS_LIST *cap_entry,
                                               AMVP_DSA_MODE mode) {
    AMVP_RESULT result;
    JSON_Array *meth_array = NULL;
    const char *revision = NULL;

    if (!cap_entry->cap.dsa_cap) {
        return AMVP_NO_CAP;
    }
    json_object_set_string(cap_obj, "algorithm", "DSA");

    revision = amvp_lookup_cipher_revision(cap_entry->cipher);
    if (revision == NULL) return AMVP_INVALID_ARG;
    json_object_set_string(cap_obj, "revision", revision);

    switch (mode) {
    case AMVP_DSA_MODE_PQGGEN:
        json_object_set_string(cap_obj, "mode", "pqgGen");
        break;
    case AMVP_DSA_MODE_PQGVER:
        json_object_set_string(cap_obj, "mode", "pqgVer");
        break;
    case AMVP_DSA_MODE_KEYGEN:
        json_object_set_string(cap_obj, "mode", "keyGen");
        break;
    case AMVP_DSA_MODE_SIGGEN:
        json_object_set_string(cap_obj, "mode", "sigGen");
        break;
    case AMVP_DSA_MODE_SIGVER:
        json_object_set_string(cap_obj, "mode", "sigVer");
        break;
    default:
        return AMVP_INVALID_ARG;
    }
    result = amvp_lookup_prereqVals(cap_obj, cap_entry);
    if (result != AMVP_SUCCESS) { return result; }

    json_object_set_value(cap_obj, "capabilities", json_value_init_array());
    meth_array = json_object_get_array(cap_obj, "capabilities");

    switch (mode) {
    case AMVP_DSA_MODE_PQGGEN:
        if (cap_entry->cap.dsa_cap->dsa_cap_mode[mode - 1].defined) {
            result = amvp_build_dsa_pqggen_register(meth_array, cap_entry);
            if (result != AMVP_SUCCESS) { return result; }
        }
        break;
    case AMVP_DSA_MODE_PQGVER:
        if (cap_entry->cap.dsa_cap->dsa_cap_mode[mode - 1].defined) {
            result = amvp_build_dsa_pqgver_register(meth_array, cap_entry);
            if (result != AMVP_SUCCESS) { return result; }
        }
        break;
    case AMVP_DSA_MODE_KEYGEN:
        if (cap_entry->cap.dsa_cap->dsa_cap_mode[mode - 1].defined) {
            result = amvp_build_dsa_keygen_register(meth_array, cap_entry);
            if (result != AMVP_SUCCESS) { return result; }
        }
        break;
    case AMVP_DSA_MODE_SIGGEN:
        if (cap_entry->cap.dsa_cap->dsa_cap_mode[mode - 1].defined) {
            result = amvp_build_dsa_siggen_register(meth_array, cap_entry);
            if (result != AMVP_SUCCESS) { return result; }
        }
        break;
    case AMVP_DSA_MODE_SIGVER:
        if (cap_entry->cap.dsa_cap->dsa_cap_mode[mode - 1].defined) {
            result = amvp_build_dsa_sigver_register(meth_array, cap_entry);
            if (result != AMVP_SUCCESS) { return result; }
        }
        break;
    default:
        return AMVP_NO_CAP;
    }
    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_lookup_kas_ecc_prereqVals(JSON_Object *cap_obj,
                                                  AMVP_KAS_ECC_CAP_MODE *kas_ecc_mode) {
    JSON_Array *prereq_array = NULL;
    AMVP_PREREQ_LIST *prereq_vals, *next_pre_req;
    AMVP_PREREQ_ALG_VAL *pre_req;
    const char *alg_str;
    int i;

    if (!kas_ecc_mode) { return AMVP_INVALID_ARG; }

    /*
     * Init json array
     */
    json_object_set_value(cap_obj, AMVP_PREREQ_OBJ_STR, json_value_init_array());
    prereq_array = json_object_get_array(cap_obj, AMVP_PREREQ_OBJ_STR);

    /*
     * return OK if nothing present
     */
    prereq_vals = kas_ecc_mode->prereq_vals;
    if (!prereq_vals) {
        return AMVP_SUCCESS;
    }


    while (prereq_vals) {
        JSON_Value *val = NULL;
        JSON_Object *obj = NULL;
        val = json_value_init_object();
        obj = json_value_get_object(val);
        pre_req = &prereq_vals->prereq_alg_val;

        for (i = 0; i < AMVP_NUM_PREREQS; i++) {
            if (amvp_prereqs_tbl[i].alg == pre_req->alg) {
                alg_str = amvp_prereqs_tbl[i].name;
                json_object_set_string(obj, "algorithm", alg_str);
                json_object_set_string(obj, AMVP_PREREQ_VAL_STR, pre_req->val);
                break;
            }
        }

        json_array_append_value(prereq_array, val);
        next_pre_req = prereq_vals->next;
        prereq_vals = next_pre_req;
    }
    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_build_kas_ecc_register_cap(AMVP_CTX *ctx,
                                                   JSON_Object *cap_obj,
                                                   AMVP_CAPS_LIST *cap_entry,
                                                   int i) {
    JSON_Array *temp_arr = NULL;
    AMVP_RESULT result;
    AMVP_KAS_ECC_CAP_MODE *kas_ecc_mode;
    AMVP_KAS_ECC_CAP *kas_ecc_cap;
    AMVP_PARAM_LIST *current_func;
    AMVP_PARAM_LIST *current_curve;
    JSON_Value *func_val = NULL;
    JSON_Object *func_obj = NULL;
    JSON_Value *sch_val = NULL;
    JSON_Object *sch_obj = NULL;
    JSON_Value *kdf_val = NULL;
    JSON_Object *kdf_obj = NULL;
    JSON_Value *pset_val = NULL;
    JSON_Object *pset_obj = NULL;
    JSON_Value *set_val = NULL;
    JSON_Object *set_obj = NULL;
    AMVP_KAS_ECC_SCHEME *current_scheme;
    AMVP_KAS_ECC_PSET *current_pset;
    AMVP_PARAM_LIST *sha, *role;
    AMVP_KAS_ECC_SET kdf;
    AMVP_KAS_ECC_SCHEMES scheme;
    int set;
    const char *revision = NULL;

    kas_ecc_cap = cap_entry->cap.kas_ecc_cap;
    if (!kas_ecc_cap) {
        return AMVP_NO_CAP;
    }
    kas_ecc_mode = &kas_ecc_cap->kas_ecc_mode[i - 1];
    if (kas_ecc_mode->prereq_vals) {
        json_object_set_string(cap_obj, "algorithm", amvp_lookup_cipher_name(cap_entry->cipher));

        if (kas_ecc_mode->revision) {
            revision = amvp_lookup_alt_revision_string(kas_ecc_mode->revision);
        } else {
            revision = amvp_lookup_cipher_revision(cap_entry->cipher);
        }
        if (revision == NULL) return AMVP_INVALID_ARG;
        json_object_set_string(cap_obj, "revision", revision);

        switch (kas_ecc_mode->cap_mode) {
        case AMVP_KAS_ECC_MODE_CDH:
            json_object_set_string(cap_obj, "mode", "CDH-Component");
            break;
        case AMVP_KAS_ECC_MODE_COMPONENT:
            json_object_set_string(cap_obj, "mode", "Component");
            break;
        case AMVP_KAS_ECC_MODE_NONE:
            break;
        case AMVP_KAS_ECC_MODE_NOCOMP:
        case AMVP_KAS_ECC_MAX_MODES:
        default:
            AMVP_LOG_ERR("Unsupported KAS-ECC mode %d", kas_ecc_mode->cap_mode);
            return AMVP_INVALID_ARG;

            break;
        }
        result = amvp_lookup_kas_ecc_prereqVals(cap_obj, kas_ecc_mode);
        if (result != AMVP_SUCCESS) { return result; }
        switch (i) {
        case AMVP_KAS_ECC_MODE_CDH:

            json_object_set_value(cap_obj, "function", json_value_init_array());
            temp_arr = json_object_get_array(cap_obj, "function");
            current_func = kas_ecc_mode->function;
            while (current_func) {
                switch (current_func->param) {
                case AMVP_KAS_ECC_FUNC_PARTIAL:
                    json_array_append_string(temp_arr, "partialVal");
                    break;
                case AMVP_KAS_ECC_FUNC_DPGEN:
                    json_array_append_string(temp_arr, "dpGen");
                    break;
                case AMVP_KAS_ECC_FUNC_DPVAL:
                    json_array_append_string(temp_arr, "dpVal");
                    break;
                case AMVP_KAS_ECC_FUNC_KEYPAIR:
                    json_array_append_string(temp_arr, "keyPairGen");
                    break;
                case AMVP_KAS_ECC_FUNC_KEYREGEN:
                    json_array_append_string(temp_arr, "keyRegen");
                    break;
                case AMVP_KAS_ECC_FUNC_FULL:
                    json_array_append_string(temp_arr, "fullVal");
                    break;
                default:
                    AMVP_LOG_ERR("Unsupported KAS-ECC function %d", current_func->param);
                    return AMVP_INVALID_ARG;

                    break;
                }
                current_func = current_func->next;
            }
            json_object_set_value(cap_obj, "curve", json_value_init_array());
            temp_arr = json_object_get_array(cap_obj, "curve");
            current_curve = kas_ecc_mode->curve;
            while (current_curve) {
                const char *curve_str = NULL;

                curve_str = amvp_lookup_ec_curve_name(kas_ecc_cap->cipher,
                                                      current_curve->param);
                if (!curve_str) {
                    AMVP_LOG_ERR("Unsupported curve %d",
                                 current_curve->param);
                    return AMVP_INVALID_ARG;
                }

                json_array_append_string(temp_arr, curve_str);

                current_curve = current_curve->next;
            }
            break;
       /* SP800-56Ar3 does not use a mode, so it is identified with NONE */
        case AMVP_KAS_ECC_MODE_NONE:
            sch_val = json_value_init_object();
            sch_obj = json_value_get_object(sch_val);

            func_val = json_value_init_object();
            func_obj = json_value_get_object(func_val);

            current_scheme = kas_ecc_mode->scheme;
            while (current_scheme) {
                scheme = current_scheme->scheme;

                json_object_set_value(func_obj, "kasRole", json_value_init_array());
                temp_arr = json_object_get_array(func_obj, "kasRole");
                role = current_scheme->role;
                while (role) {
                    switch (role->param) {
                    case AMVP_KAS_ECC_ROLE_INITIATOR:
                        json_array_append_string(temp_arr, "initiator");
                        break;
                    case AMVP_KAS_ECC_ROLE_RESPONDER:
                        json_array_append_string(temp_arr, "responder");
                        break;
                    default:
                        AMVP_LOG_ERR("Unsupported KAS-ECC role %d", role->param);
                        return AMVP_INVALID_ARG;

                        break;
                    }
                    role = role->next;
                }
                switch (scheme) {
                case AMVP_KAS_ECC_EPHEMERAL_UNIFIED:
                    json_object_set_value(sch_obj, "ephemeralUnified", func_val);
                    break;
                case AMVP_KAS_ECC_FULL_MQV:
                case AMVP_KAS_ECC_FULL_UNIFIED:
                case AMVP_KAS_ECC_ONEPASS_DH:
                case AMVP_KAS_ECC_ONEPASS_MQV:
                case AMVP_KAS_ECC_ONEPASS_UNIFIED:
                case AMVP_KAS_ECC_STATIC_UNIFIED:
                case AMVP_KAS_ECC_SCHEMES_MAX:
                default:
                    AMVP_LOG_ERR("Unsupported KAS-ECC scheme %d", scheme);
                    return AMVP_INVALID_ARG;

                    break;
                }
                json_object_set_value(cap_obj, "scheme", sch_val);
                current_scheme = current_scheme->next;
            }

            json_object_set_value(cap_obj, "domainParameterGenerationMethods", json_value_init_array());
            temp_arr = json_object_get_array(cap_obj, "domainParameterGenerationMethods");
            current_curve = kas_ecc_mode->curve;
            while (current_curve) {
                const char *curve_str = NULL;

                curve_str = amvp_lookup_ec_curve_name(kas_ecc_cap->cipher,
                                                      current_curve->param);
                if (!curve_str) {
                    AMVP_LOG_ERR("Unsupported curve %d",
                                 current_curve->param);
                    return AMVP_INVALID_ARG;
                }

                json_array_append_string(temp_arr, curve_str);

                current_curve = current_curve->next;
            }
            switch (kas_ecc_mode->hash) {
                case AMVP_SHA224:
                    json_object_set_string(cap_obj, "hashFunctionZ", "SHA2-224");
                    break;
                case AMVP_SHA256:
                    json_object_set_string(cap_obj, "hashFunctionZ", "SHA2-256");
                    break;
                case AMVP_SHA384:
                    json_object_set_string(cap_obj, "hashFunctionZ", "SHA2-384");
                    break;
                case AMVP_SHA512:
                    json_object_set_string(cap_obj, "hashFunctionZ", "SHA2-512");
                    break;
                case AMVP_SHA512_224:
                    json_object_set_string(cap_obj, "hashFunctionZ", "SHA2-512/224");
                    break;
                case AMVP_SHA512_256:
                    json_object_set_string(cap_obj, "hashFunctionZ", "SHA2-512/256");
                    break;
                case AMVP_SHA3_224:
                    json_object_set_string(cap_obj, "hashFunctionZ", "SHA3-224");
                    break;
                case AMVP_SHA3_256:
                    json_object_set_string(cap_obj, "hashFunctionZ", "SHA3-256");
                    break;
                case AMVP_SHA3_384:
                    json_object_set_string(cap_obj, "hashFunctionZ", "SHA3-384");
                    break;
                case AMVP_SHA3_512:
                    json_object_set_string(cap_obj, "hashFunctionZ", "SHA3-512");
                    break;
                case AMVP_NO_SHA:
                    break;
                default:
                    AMVP_LOG_ERR("Unsupported KAS-ECC sha param %d", kas_ecc_mode->hash);
                    return AMVP_INVALID_ARG;
                    break;
            }
            break;
        case AMVP_KAS_ECC_MODE_COMPONENT:
            json_object_set_value(cap_obj, "function", json_value_init_array());
            temp_arr = json_object_get_array(cap_obj, "function");
            current_func = kas_ecc_mode->function;
            while (current_func) {
                switch (current_func->param) {
                case AMVP_KAS_ECC_FUNC_PARTIAL:
                    json_array_append_string(temp_arr, "partialVal");
                    break;
                case AMVP_KAS_ECC_FUNC_DPGEN:
                case AMVP_KAS_ECC_FUNC_DPVAL:
                case AMVP_KAS_ECC_FUNC_KEYPAIR:
                case AMVP_KAS_ECC_FUNC_KEYREGEN:
                case AMVP_KAS_ECC_FUNC_FULL:
                default:
                    AMVP_LOG_ERR("Unsupported KAS-ECC function %d", current_func->param);
                    return AMVP_INVALID_ARG;

                    break;
                }
                current_func = current_func->next;
            }

            sch_val = json_value_init_object();
            sch_obj = json_value_get_object(sch_val);

            func_val = json_value_init_object();
            func_obj = json_value_get_object(func_val);

            kdf_val = json_value_init_object();
            kdf_obj = json_value_get_object(kdf_val);

            pset_val = json_value_init_object();
            pset_obj = json_value_get_object(pset_val);

            current_scheme = kas_ecc_mode->scheme;
            while (current_scheme) {
                kdf = current_scheme->kdf;
                scheme = current_scheme->scheme;
                current_pset = current_scheme->pset;
                while (current_pset) {
                    const char *curve_str = NULL;

                    set_val = json_value_init_object();
                    set_obj = json_value_get_object(set_val);

                    set = current_pset->set;
                    curve_str = amvp_lookup_ec_curve_name(kas_ecc_cap->cipher,
                                                          current_pset->curve);
                    if (!curve_str) {
                        AMVP_LOG_ERR("Unsupported curve %d",
                                     current_pset->curve);
                        return AMVP_INVALID_ARG;
                    }
                    json_object_set_string(set_obj, "curve", curve_str);

                    json_object_set_value(set_obj, "hashAlg", json_value_init_array());
                    temp_arr = json_object_get_array(set_obj, "hashAlg");
                    sha = current_pset->sha;
                    while (sha) {
                        switch (sha->param) {
                        case AMVP_SHA224:
                            json_array_append_string(temp_arr, "SHA2-224");
                            break;
                        case AMVP_SHA256:
                            json_array_append_string(temp_arr, "SHA2-256");
                            break;
                        case AMVP_SHA384:
                            json_array_append_string(temp_arr, "SHA2-384");
                            break;
                        case AMVP_SHA512:
                            json_array_append_string(temp_arr, "SHA2-512");
                            break;
                        default:
                            AMVP_LOG_ERR("Unsupported KAS-ECC sha param %d", sha->param);
                            return AMVP_INVALID_ARG;

                            break;
                        }
                        sha = sha->next;
                    }
                    switch (set) {
                    case AMVP_KAS_ECC_EB:
                        json_object_set_value(pset_obj, "eb", set_val);
                        break;
                    case AMVP_KAS_ECC_EC:
                        json_object_set_value(pset_obj, "ec", set_val);
                        break;
                    case AMVP_KAS_ECC_ED:
                        json_object_set_value(pset_obj, "ed", set_val);
                        break;
                    case AMVP_KAS_ECC_EE:
                        json_object_set_value(pset_obj, "ee", set_val);
                        break;
                    default:
                        AMVP_LOG_ERR("Unsupported KAS-ECC set %d", set);
                        return AMVP_INVALID_ARG;

                        break;
                    }
                    current_pset = current_pset->next;
                }
                json_object_set_value(kdf_obj, "parameterSet", pset_val);

                json_object_set_value(func_obj, "kasRole", json_value_init_array());
                temp_arr = json_object_get_array(func_obj, "kasRole");
                role = current_scheme->role;
                while (role) {
                    switch (role->param) {
                    case AMVP_KAS_ECC_ROLE_INITIATOR:
                        json_array_append_string(temp_arr, "initiator");
                        break;
                    case AMVP_KAS_ECC_ROLE_RESPONDER:
                        json_array_append_string(temp_arr, "responder");
                        break;
                    default:
                        AMVP_LOG_ERR("Unsupported KAS-ECC role %d", role->param);
                        return AMVP_INVALID_ARG;

                        break;
                    }
                    role = role->next;
                }
                switch (kdf) {
                case AMVP_KAS_ECC_NOKDFNOKC:
                    json_object_set_value(func_obj, "noKdfNoKc", kdf_val);
                    break;
                case AMVP_KAS_ECC_KDFNOKC:
                    json_object_set_value(func_obj, "kdfNoKc", kdf_val);
                    break;
                case AMVP_KAS_ECC_KDFKC:
                    json_object_set_value(func_obj, "kdfKc", kdf_val);
                    break;
                case AMVP_KAS_ECC_PARMSET:
                default:
                    break;
                }
                switch (scheme) {
                case AMVP_KAS_ECC_EPHEMERAL_UNIFIED:
                    json_object_set_value(sch_obj, "ephemeralUnified", func_val);
                    break;
                case AMVP_KAS_ECC_FULL_MQV:
                case AMVP_KAS_ECC_FULL_UNIFIED:
                case AMVP_KAS_ECC_ONEPASS_DH:
                case AMVP_KAS_ECC_ONEPASS_MQV:
                case AMVP_KAS_ECC_ONEPASS_UNIFIED:
                case AMVP_KAS_ECC_STATIC_UNIFIED:
                case AMVP_KAS_ECC_SCHEMES_MAX:
                default:
                    AMVP_LOG_ERR("Unsupported KAS-ECC scheme %d", scheme);
                    return AMVP_INVALID_ARG;

                    break;
                }
                json_object_set_value(cap_obj, "scheme", sch_val);
                current_scheme = current_scheme->next;
            }
            break;
        default:
            AMVP_LOG_ERR("Unsupported KAS-ECC mode %d", i);
            return AMVP_INVALID_ARG;

            break;
        }
    } else {
        return AMVP_MISSING_ARG;
    }
    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_lookup_kas_ffc_prereqVals(JSON_Object *cap_obj,
                                                  AMVP_KAS_FFC_CAP_MODE *kas_ffc_mode) {
    JSON_Array *prereq_array = NULL;
    AMVP_PREREQ_LIST *prereq_vals, *next_pre_req;
    AMVP_PREREQ_ALG_VAL *pre_req;
    const char *alg_str;
    int i;

    if (!kas_ffc_mode) { return AMVP_INVALID_ARG; }

    /*
     * Init json array
     */
    json_object_set_value(cap_obj, AMVP_PREREQ_OBJ_STR, json_value_init_array());
    prereq_array = json_object_get_array(cap_obj, AMVP_PREREQ_OBJ_STR);

    /*
     * return OK if nothing present
     */
    prereq_vals = kas_ffc_mode->prereq_vals;
    if (!prereq_vals) {
        return AMVP_SUCCESS;
    }


    while (prereq_vals) {
        JSON_Value *val = NULL;
        JSON_Object *obj = NULL;
        val = json_value_init_object();
        obj = json_value_get_object(val);
        pre_req = &prereq_vals->prereq_alg_val;

        for (i = 0; i < AMVP_NUM_PREREQS; i++) {
            if (amvp_prereqs_tbl[i].alg == pre_req->alg) {
                alg_str = amvp_prereqs_tbl[i].name;
                json_object_set_string(obj, "algorithm", alg_str);
                json_object_set_string(obj, AMVP_PREREQ_VAL_STR, pre_req->val);
                break;
            }
        }

        json_array_append_value(prereq_array, val);
        next_pre_req = prereq_vals->next;
        prereq_vals = next_pre_req;
    }
    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_build_kas_ffc_register_cap(AMVP_CTX *ctx,
                                                   JSON_Object *cap_obj,
                                                   AMVP_CAPS_LIST *cap_entry,
                                                   int i) {
    JSON_Array *temp_arr = NULL;
    AMVP_RESULT result;
    AMVP_KAS_FFC_CAP_MODE *kas_ffc_mode;
    AMVP_KAS_FFC_CAP *kas_ffc_cap;
    AMVP_PARAM_LIST *current_func;
    JSON_Value *func_val = NULL;
    JSON_Object *func_obj = NULL;
    JSON_Value *sch_val = NULL;
    JSON_Object *sch_obj = NULL;
    JSON_Value *kdf_val = NULL;
    JSON_Object *kdf_obj = NULL;
    JSON_Value *pset_val = NULL;
    JSON_Object *pset_obj = NULL;
    JSON_Value *set_val = NULL;
    JSON_Object *set_obj = NULL;
    AMVP_KAS_FFC_SCHEME *current_scheme;
    AMVP_KAS_FFC_PSET *current_pset;
    AMVP_PARAM_LIST *sha, *role, *genmeth;
    AMVP_KAS_FFC_SET kdf;
    AMVP_KAS_FFC_SCHEMES scheme;
    int set;
    const char *revision = NULL;

    kas_ffc_cap = cap_entry->cap.kas_ffc_cap;
    if (!kas_ffc_cap) {
        return AMVP_NO_CAP;
    }
    kas_ffc_mode = &kas_ffc_cap->kas_ffc_mode[i - 1];
    if (kas_ffc_mode->prereq_vals) {
        json_object_set_string(cap_obj, "algorithm", amvp_lookup_cipher_name(cap_entry->cipher));

        revision = amvp_lookup_cipher_revision(cap_entry->cipher);
        if (revision == NULL) return AMVP_INVALID_ARG;
        json_object_set_string(cap_obj, "revision", revision);

        switch (kas_ffc_mode->cap_mode) {
        case AMVP_KAS_FFC_MODE_COMPONENT:
            json_object_set_string(cap_obj, "mode", "Component");
            break;
        case AMVP_KAS_FFC_MODE_NONE:
            break;
        case AMVP_KAS_FFC_MODE_NOCOMP:
        case AMVP_KAS_FFC_MAX_MODES:
        default:
            AMVP_LOG_ERR("Unsupported KAS-FFC mode %d", kas_ffc_mode->cap_mode);
            return AMVP_INVALID_ARG;

            break;
        }
        result = amvp_lookup_kas_ffc_prereqVals(cap_obj, kas_ffc_mode);
        if (result != AMVP_SUCCESS) { return result; }
        switch (i) {
        case AMVP_KAS_FFC_MODE_COMPONENT:
            json_object_set_value(cap_obj, "function", json_value_init_array());
            temp_arr = json_object_get_array(cap_obj, "function");
            current_func = kas_ffc_mode->function;
            while (current_func) {
                switch (current_func->param) {
                case AMVP_KAS_FFC_FUNC_DPGEN:
                    json_array_append_string(temp_arr, "dpGen");
                    break;
                case AMVP_KAS_FFC_FUNC_DPVAL:
                    json_array_append_string(temp_arr, "dpVal");
                    break;
                case AMVP_KAS_FFC_FUNC_KEYPAIR:
                    json_array_append_string(temp_arr, "keyPairGen");
                    break;
                case AMVP_KAS_FFC_FUNC_KEYREGEN:
                    json_array_append_string(temp_arr, "keyRegen");
                    break;
                case AMVP_KAS_FFC_FUNC_FULL:
                    json_array_append_string(temp_arr, "fullVal");
                    break;
                default:
                    AMVP_LOG_ERR("Unsupported KAS-FFC function %d", current_func->param);
                    return AMVP_INVALID_ARG;

                    break;
                }
                current_func = current_func->next;
            }

            sch_val = json_value_init_object();
            sch_obj = json_value_get_object(sch_val);

            func_val = json_value_init_object();
            func_obj = json_value_get_object(func_val);

            kdf_val = json_value_init_object();
            kdf_obj = json_value_get_object(kdf_val);

            pset_val = json_value_init_object();
            pset_obj = json_value_get_object(pset_val);

            current_scheme = kas_ffc_mode->scheme;
            while (current_scheme) {
                kdf = current_scheme->kdf;
                scheme = current_scheme->scheme;
                current_pset = current_scheme->pset;
                while (current_pset) {
                    set_val = json_value_init_object();
                    set_obj = json_value_get_object(set_val);

                    set = current_pset->set;

                    json_object_set_value(set_obj, "hashAlg", json_value_init_array());
                    temp_arr = json_object_get_array(set_obj, "hashAlg");
                    sha = current_pset->sha;
                    while (sha) {
                        switch (sha->param) {
                        case AMVP_SHA224:
                            json_array_append_string(temp_arr, "SHA2-224");
                            break;
                        case AMVP_SHA256:
                            json_array_append_string(temp_arr, "SHA2-256");
                            break;
                        case AMVP_SHA384:
                            json_array_append_string(temp_arr, "SHA2-384");
                            break;
                        case AMVP_SHA512:
                            json_array_append_string(temp_arr, "SHA2-512");
                            break;
                        default:
                            AMVP_LOG_ERR("Unsupported KAS-FFC sha param %d", sha->param);
                            return AMVP_INVALID_ARG;

                            break;
                        }
                        sha = sha->next;
                    }
                    switch (set) {
                    case AMVP_KAS_FFC_FB:
                        json_object_set_value(pset_obj, "fb", set_val);
                        break;
                    case AMVP_KAS_FFC_FC:
                        json_object_set_value(pset_obj, "fc", set_val);
                        break;
                    default:
                        AMVP_LOG_ERR("Unsupported KAS-FFC set %d", set);
                        return AMVP_INVALID_ARG;

                        break;
                    }
                    current_pset = current_pset->next;
                }
                json_object_set_value(kdf_obj, "parameterSet", pset_val);

                json_object_set_value(func_obj, "kasRole", json_value_init_array());
                temp_arr = json_object_get_array(func_obj, "kasRole");
                role = current_scheme->role;
                while (role) {
                    switch (role->param) {
                    case AMVP_KAS_FFC_ROLE_INITIATOR:
                        json_array_append_string(temp_arr, "initiator");
                        break;
                    case AMVP_KAS_FFC_ROLE_RESPONDER:
                        json_array_append_string(temp_arr, "responder");
                        break;
                    default:
                        AMVP_LOG_ERR("Unsupported KAS-FFC role %d", role->param);
                        return AMVP_INVALID_ARG;

                        break;
                    }
                    role = role->next;
                }
                switch (kdf) {
                case AMVP_KAS_FFC_NOKDFNOKC:
                    json_object_set_value(func_obj, "noKdfNoKc", kdf_val);
                    break;
                case AMVP_KAS_FFC_KDFNOKC:
                    json_object_set_value(func_obj, "kdfNoKc", kdf_val);
                    break;
                case AMVP_KAS_FFC_KDFKC:
                    json_object_set_value(func_obj, "kdfKc", kdf_val);
                    break;
                case AMVP_KAS_FFC_PARMSET:
                default:
                    AMVP_LOG_ERR("Unsupported KAS-FFC kdf %d", kdf);
                    return AMVP_INVALID_ARG;

                    break;
                }
                switch (scheme) {
                case AMVP_KAS_FFC_DH_EPHEMERAL:
                    json_object_set_value(sch_obj, "dhEphem", func_val);
                    break;
                case AMVP_KAS_FFC_FULL_MQV1:
                case AMVP_KAS_FFC_FULL_MQV2:
                case AMVP_KAS_FFC_DH_HYBRID1:
                case AMVP_KAS_FFC_DH_HYBRID_ONEFLOW:
                case AMVP_KAS_FFC_DH_ONEFLOW:
                case AMVP_KAS_FFC_DH_STATIC:
                case AMVP_KAS_FFC_MAX_SCHEMES:
                default:
                    AMVP_LOG_ERR("Unsupported KAS-FFC scheme %d", scheme);
                    return AMVP_INVALID_ARG;

                    break;
                }
                json_object_set_value(cap_obj, "scheme", sch_val);
                current_scheme = current_scheme->next;
            }
            break;
        case AMVP_KAS_FFC_MODE_NONE:
            sch_val = json_value_init_object();
            sch_obj = json_value_get_object(sch_val);

            func_val = json_value_init_object();
            func_obj = json_value_get_object(func_val);

            current_scheme = kas_ffc_mode->scheme;
            while (current_scheme) {
                scheme = current_scheme->scheme;
                json_object_set_value(func_obj, "kasRole", json_value_init_array());
                temp_arr = json_object_get_array(func_obj, "kasRole");
                role = current_scheme->role;
                while (role) {
                    switch (role->param) {
                    case AMVP_KAS_FFC_ROLE_INITIATOR:
                        json_array_append_string(temp_arr, "initiator");
                        break;
                    case AMVP_KAS_FFC_ROLE_RESPONDER:
                        json_array_append_string(temp_arr, "responder");
                        break;
                    default:
                        AMVP_LOG_ERR("Unsupported KAS-FFC role %d", role->param);
                        return AMVP_INVALID_ARG;

                        break;
                    }
                    role = role->next;
                }
                switch (scheme) {
                case AMVP_KAS_FFC_DH_EPHEMERAL:
                    json_object_set_value(sch_obj, "dhEphem", func_val);
                    break;
                case AMVP_KAS_FFC_FULL_MQV1:
                case AMVP_KAS_FFC_FULL_MQV2:
                case AMVP_KAS_FFC_DH_HYBRID1:
                case AMVP_KAS_FFC_DH_HYBRID_ONEFLOW:
                case AMVP_KAS_FFC_DH_ONEFLOW:
                case AMVP_KAS_FFC_DH_STATIC:
                case AMVP_KAS_FFC_MAX_SCHEMES:
                default:
                    AMVP_LOG_ERR("Unsupported KAS-FFC scheme %d", scheme);
                    return AMVP_INVALID_ARG;

                    break;
                }
                json_object_set_value(cap_obj, "scheme", sch_val);
                current_scheme = current_scheme->next;
            }
            json_object_set_value(cap_obj, "scheme", sch_val);

            switch (kas_ffc_mode->hash) {
                case AMVP_SHA224:
                    json_object_set_string(cap_obj, "hashFunctionZ", "SHA2-224");
                    break;
                case AMVP_SHA256:
                    json_object_set_string(cap_obj, "hashFunctionZ", "SHA2-256");
                    break;
                case AMVP_SHA384:
                    json_object_set_string(cap_obj, "hashFunctionZ", "SHA2-384");
                    break;
                case AMVP_SHA512:
                    json_object_set_string(cap_obj, "hashFunctionZ", "SHA2-512");
                    break;
                case AMVP_SHA512_224:
                    json_object_set_string(cap_obj, "hashFunctionZ", "SHA2-512/224");
                    break;
                case AMVP_SHA512_256:
                    json_object_set_string(cap_obj, "hashFunctionZ", "SHA2-512/256");
                    break;
                case AMVP_SHA3_224:
                    json_object_set_string(cap_obj, "hashFunctionZ", "SHA3-224");
                    break;
                case AMVP_SHA3_256:
                    json_object_set_string(cap_obj, "hashFunctionZ", "SHA3-256");
                    break;
                case AMVP_SHA3_384:
                    json_object_set_string(cap_obj, "hashFunctionZ", "SHA3-384");
                    break;
                case AMVP_SHA3_512:
                    json_object_set_string(cap_obj, "hashFunctionZ", "SHA3-512");
                    break;
                case AMVP_NO_SHA:
                    break;
                default:
                    AMVP_LOG_ERR("Unsupported KAS-FFC sha param %d", kas_ffc_mode->hash);
                    return AMVP_INVALID_ARG;
                    break;
            }
            genmeth = kas_ffc_mode->genmeth;
            json_object_set_value(cap_obj, "domainParameterGenerationMethods", json_value_init_array());
            temp_arr = json_object_get_array(cap_obj, "domainParameterGenerationMethods");
            while (genmeth) {
                switch (genmeth->param) {
                    case AMVP_KAS_FFC_FB:
                        json_array_append_string(temp_arr, "FB");
                        break;
                    case AMVP_KAS_FFC_FC:
                        json_array_append_string(temp_arr, "FC");
                        break;
                    case AMVP_KAS_FFC_MODP2048:
                        json_array_append_string(temp_arr, "modp-2048");
                        break;
                    case AMVP_KAS_FFC_MODP3072:
                        json_array_append_string(temp_arr, "modp-3072");
                        break;
                    case AMVP_KAS_FFC_MODP4096:
                        json_array_append_string(temp_arr, "modp-4096");
                        break;
                    case AMVP_KAS_FFC_MODP6144:
                        json_array_append_string(temp_arr, "modp-6144");
                        break;
                    case AMVP_KAS_FFC_MODP8192:
                        json_array_append_string(temp_arr, "modp-8192");
                        break;
                    case AMVP_KAS_FFC_FFDHE2048:
                        json_array_append_string(temp_arr, "ffdhe2048");
                        break;
                    case AMVP_KAS_FFC_FFDHE3072:
                        json_array_append_string(temp_arr, "ffdhe3072");
                        break;
                    case AMVP_KAS_FFC_FFDHE4096:
                        json_array_append_string(temp_arr, "ffdhe4096");
                        break;
                    case AMVP_KAS_FFC_FFDHE6144:
                        json_array_append_string(temp_arr, "ffdhe6144");
                        break;
                    case AMVP_KAS_FFC_FFDHE8192:
                        json_array_append_string(temp_arr, "ffdhe8192");
                        break;

                    default:
                        AMVP_LOG_ERR("Unsupported KAS-FFC sha param %d", genmeth->param);
                        return AMVP_INVALID_ARG;

                        break;
                }
                genmeth = genmeth->next;
            }
            break;

        default:
            AMVP_LOG_ERR("Unsupported KAS-FFC mode %d", i);
            return AMVP_INVALID_ARG;

            break;
        }
    } else {
        return AMVP_MISSING_ARG;
    }
    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_build_kas_ifc_register_cap(AMVP_CTX *ctx,
                                                   JSON_Object *cap_obj,
                                                   AMVP_CAPS_LIST *cap_entry) {
    JSON_Array *temp_arr = NULL;
    AMVP_RESULT result;
    const char *revision = NULL;
    AMVP_KAS_IFC_CAP *kas_ifc_cap = NULL;
    AMVP_PARAM_LIST *current_param;
    AMVP_SL_LIST *current_len;
    JSON_Value *sch_val = NULL;
    JSON_Object *sch_obj = NULL;
    JSON_Value *role_val = NULL;
    JSON_Object *role_obj = NULL;

    kas_ifc_cap = cap_entry->cap.kas_ifc_cap;
    if (!kas_ifc_cap) {
        return AMVP_NO_CAP;
    }

    if (cap_entry->prereq_vals) {
        json_object_set_string(cap_obj, "algorithm", amvp_lookup_cipher_name(cap_entry->cipher));

        revision = amvp_lookup_cipher_revision(cap_entry->cipher);
        if (revision == NULL) return AMVP_INVALID_ARG;
        json_object_set_string(cap_obj, "revision", revision);
        result = amvp_lookup_prereqVals(cap_obj, cap_entry);
        if (result != AMVP_SUCCESS) { return result; }
    }
    switch (kas_ifc_cap->hash) {
        case AMVP_SHA224:
            json_object_set_string(cap_obj, "hashFunctionZ", "SHA2-224");
            break;
        case AMVP_SHA256:
            json_object_set_string(cap_obj, "hashFunctionZ", "SHA2-256");
            break;
        case AMVP_SHA384:
            json_object_set_string(cap_obj, "hashFunctionZ", "SHA2-384");
            break;
        case AMVP_SHA512:
            json_object_set_string(cap_obj, "hashFunctionZ", "SHA2-512");
            break;
        case AMVP_SHA512_224:
            json_object_set_string(cap_obj, "hashFunctionZ", "SHA2-512/224");
            break;
        case AMVP_SHA512_256:
            json_object_set_string(cap_obj, "hashFunctionZ", "SHA2-512/256");
            break;
        case AMVP_SHA3_224:
            json_object_set_string(cap_obj, "hashFunctionZ", "SHA3-224");
            break;
        case AMVP_SHA3_256:
            json_object_set_string(cap_obj, "hashFunctionZ", "SHA3-256");
            break;
        case AMVP_SHA3_384:
            json_object_set_string(cap_obj, "hashFunctionZ", "SHA3-384");
            break;
        case AMVP_SHA3_512:
            json_object_set_string(cap_obj, "hashFunctionZ", "SHA3-512");
            break;
        case AMVP_NO_SHA:
            break;
        default:
            AMVP_LOG_ERR("Unsupported KAS-IFC sha param %d", kas_ifc_cap->hash);
            return AMVP_INVALID_ARG;
            break;
    }
    json_object_set_string(cap_obj, "fixedPubExp", (const char *)kas_ifc_cap->fixed_pub_exp);

    json_object_set_value(cap_obj, "modulo", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "modulo");
    current_len = kas_ifc_cap->modulo;
    while (current_len) {
        json_array_append_number(temp_arr, current_len->length);
        current_len = current_len->next;
    }

    json_object_set_value(cap_obj, "keyGenerationMethods", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "keyGenerationMethods");
    current_param = kas_ifc_cap->keygen_method;
    while (current_param) {
        switch (current_param->param)
        {
            case AMVP_KAS_IFC_RSAKPG1_BASIC:
                json_array_append_string(temp_arr, "rsakpg1-basic");
                break;
            case AMVP_KAS_IFC_RSAKPG1_PRIME_FACTOR:
                json_array_append_string(temp_arr, "rsakpg1-prime-factor");
                break;
            case AMVP_KAS_IFC_RSAKPG1_CRT:
                json_array_append_string(temp_arr, "rsakpg1-crt");
                break;
            case AMVP_KAS_IFC_RSAKPG2_BASIC:
                json_array_append_string(temp_arr, "rsakpg2-basic");
                break;
            case AMVP_KAS_IFC_RSAKPG2_PRIME_FACTOR:
                json_array_append_string(temp_arr, "rsakpg2-prime-factor");
                break;
            case AMVP_KAS_IFC_RSAKPG2_CRT:
                json_array_append_string(temp_arr, "rsakpg2-crt");
                break;
            default:
                AMVP_LOG_ERR("Unsupported KAS-IFC keygen param %d", current_param->param);
                return AMVP_INVALID_ARG;
                break;
        }
        current_param = current_param->next;
    }

    sch_val = json_value_init_object();
    sch_obj = json_value_get_object(sch_val);

    current_param = kas_ifc_cap->kas1_roles;
    if (current_param) {
        role_val = json_value_init_object();
        role_obj = json_value_get_object(role_val);
        json_object_set_value(role_obj, "kasRole", json_value_init_array());
        temp_arr = json_object_get_array(role_obj, "kasRole");
        while (current_param) {
            switch (current_param->param)
            {
                case AMVP_KAS_IFC_INITIATOR:
                    json_array_append_string(temp_arr, "initiator");
                    break;
                case AMVP_KAS_IFC_RESPONDER:
                    json_array_append_string(temp_arr, "responder");
                    break;
                default:
                    AMVP_LOG_ERR("Unsupported KAS-IFC KAS1 role param %d", current_param->param);
                    return AMVP_INVALID_ARG;
                    break;
            }
            current_param = current_param->next;
        }
    }
    if (kas_ifc_cap->kas1_roles) {
        json_object_set_value(sch_obj, "KAS1", role_val);
    }
    current_param = kas_ifc_cap->kas2_roles;
    if (current_param) {
        role_val = json_value_init_object();
        role_obj = json_value_get_object(role_val);
        json_object_set_value(role_obj, "kasRole", json_value_init_array());
        temp_arr = json_object_get_array(role_obj, "kasRole");
        while (current_param) {
            switch (current_param->param)
            {
                case AMVP_KAS_IFC_INITIATOR:
                    json_array_append_string(temp_arr, "initiator");
                    break;
                case AMVP_KAS_IFC_RESPONDER:
                    json_array_append_string(temp_arr, "responder");
                    break;
                default:
                    AMVP_LOG_ERR("Unsupported KAS-IFC KAS2 role param %d", current_param->param);
                    return AMVP_INVALID_ARG;
                    break;
            }
            current_param = current_param->next;
        }
    }    
    if (kas_ifc_cap->kas2_roles) {
        json_object_set_value(sch_obj, "KAS2", role_val);
    }
    json_object_set_value(cap_obj, "scheme", sch_val);

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_build_kda_onestep_register_cap(AMVP_CTX *ctx,
                                                           JSON_Object *cap_obj,
                                                           AMVP_CAPS_LIST *cap_entry) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    JSON_Array *temp_arr = NULL, *temp_arr2 = NULL;
    JSON_Value *tmp_val = NULL;
    JSON_Object *tmp_obj = NULL;
    AMVP_NAME_LIST *tmp_name_list = NULL, *tmp_name_list2 = NULL;
    AMVP_PARAM_LIST *tmp_param_list;
    const char *revision = NULL;
    const char *mode = NULL;
    char *pattern_str = NULL;

    pattern_str = calloc(AMVP_KDA_PATTERN_REG_STR_MAX + 1, sizeof(char));
    if (!pattern_str) {
        AMVP_LOG_ERR("Error allocating memory for KDA-ONESTEP pattern string");
        return AMVP_MALLOC_FAIL;
    }

    json_object_set_string(cap_obj, "algorithm", amvp_lookup_cipher_name(cap_entry->cipher));
    mode = amvp_lookup_cipher_mode_str(cap_entry->cipher);
    if (!mode) {
        AMVP_LOG_ERR("Unable to find mode string for KDA-ONESTEP when building registration");
        rv = AMVP_INTERNAL_ERR;
        goto err;
    }
    json_object_set_string(cap_obj, "mode", mode);
    if (cap_entry->cap.kda_onestep_cap->revision) {
        revision = amvp_lookup_alt_revision_string(cap_entry->cap.kda_onestep_cap->revision);
    } else {
        revision = amvp_lookup_cipher_revision(cap_entry->cipher);
    }
    if (!revision) {
        AMVP_LOG_ERR("Unable to find revision string for KDA-ONESTEP when building registration");
        rv = AMVP_INVALID_ARG;
        goto err;
    }
    json_object_set_string(cap_obj, "revision", revision);

    rv = amvp_lookup_prereqVals(cap_obj, cap_entry);
    if (rv != AMVP_SUCCESS) { goto err; }

    //pattern string is list of pattern values separated by '||'
    tmp_param_list = cap_entry->cap.kda_onestep_cap->patterns;
    if (!tmp_param_list) {
        AMVP_LOG_ERR("Missing patterns list when building registration");
        rv = AMVP_UNSUPPORTED_OP;
        goto err;
    }
    while (tmp_param_list) {
        switch (tmp_param_list->param) {
        case AMVP_KDA_PATTERN_LITERAL:
            if (!cap_entry->cap.kda_onestep_cap->literal_pattern_candidate) {
                AMVP_LOG_ERR("Missing literal pattern candidate for registration");
                rv = AMVP_MISSING_ARG;
                goto err;
            }
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1,
                      AMVP_KDA_PATTERN_LITERAL_STR,
                      sizeof(AMVP_KDA_PATTERN_LITERAL_STR) - 1);
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1, "[", 1);
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1,
                      cap_entry->cap.kda_onestep_cap->literal_pattern_candidate,
                      AMVP_KDA_PATTERN_LITERAL_STR_LEN_MAX);
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1, "]", 1);
            break;
        case AMVP_KDA_PATTERN_UPARTYINFO:
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1,
                      AMVP_KDA_PATTERN_UPARTYINFO_STR,
                      sizeof(AMVP_KDA_PATTERN_UPARTYINFO_STR) - 1);
            break;
        case AMVP_KDA_PATTERN_VPARTYINFO:
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1,
                      AMVP_KDA_PATTERN_VPARTYINFO_STR,
                      sizeof(AMVP_KDA_PATTERN_VPARTYINFO_STR) - 1);
            break;
        case AMVP_KDA_PATTERN_CONTEXT:
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1,
                      AMVP_KDA_PATTERN_CONTEXT_STR,
                      sizeof(AMVP_KDA_PATTERN_CONTEXT_STR) - 1);
            break;
        case AMVP_KDA_PATTERN_ALGID:
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1,
                      AMVP_KDA_PATTERN_ALGID_STR,
                      sizeof(AMVP_KDA_PATTERN_ALGID_STR) - 1);
            break;
        case AMVP_KDA_PATTERN_LABEL:
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1,
                      AMVP_KDA_PATTERN_LABEL_STR,
                      sizeof(AMVP_KDA_PATTERN_LABEL_STR) - 1);
            break;
        case AMVP_KDA_PATTERN_L:
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1,
                      AMVP_KDA_PATTERN_LENGTH_STR,
                      sizeof(AMVP_KDA_PATTERN_LENGTH_STR) - 1);
            break;
        case AMVP_KDA_PATTERN_T:
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1,
                      AMVP_KDA_PATTERN_T_STR,
                      sizeof(AMVP_KDA_PATTERN_T_STR) - 1);
            break;
        default:
            AMVP_LOG_ERR("Invalid pattern value in pattern list");
            rv = AMVP_INVALID_ARG;
            goto err;
        }

        if (tmp_param_list->next) {
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1, "||", 2); 
        }
        tmp_param_list = tmp_param_list->next;
    }
    json_object_set_string(cap_obj, "fixedInfoPattern", pattern_str);

    //create the "encodings" array and populate it
    json_object_set_value(cap_obj, "encoding", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "encoding");
    tmp_param_list = cap_entry->cap.kda_onestep_cap->encodings;
    while (tmp_param_list) {
        switch (tmp_param_list->param) {
        case AMVP_KDA_ENCODING_CONCAT:
            json_array_append_string(temp_arr, AMVP_KDA_ENCODING_CONCATENATION_STR);
            break;
        default:
            AMVP_LOG_ERR("Invalid encoding value in encoding list");
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        tmp_param_list = tmp_param_list->next;
    }

    //create the "auxFunctions" array and populate it
    json_object_set_value(cap_obj, "auxFunctions", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "auxFunctions");
    tmp_name_list = cap_entry->cap.kda_onestep_cap->aux_functions;
    while (tmp_name_list) {
        tmp_val = json_value_init_object();
        tmp_obj = json_value_get_object(tmp_val);
        json_object_set_string(tmp_obj, "auxFunctionName", tmp_name_list->name);
        json_object_set_value(tmp_obj, "macSaltMethods", json_value_init_array());
        temp_arr2 = json_object_get_array(tmp_obj, "macSaltMethods");
        tmp_name_list2 = cap_entry->cap.kda_onestep_cap->mac_salt_methods;
        while (tmp_name_list2) {
            json_array_append_string(temp_arr2, tmp_name_list2->name);
            tmp_name_list2 = tmp_name_list2->next;
        }
        json_array_append_value(temp_arr, tmp_val);
        tmp_name_list = tmp_name_list->next;
    }

    //append the "l" value
    json_object_set_number(cap_obj, "l", cap_entry->cap.kda_onestep_cap->l);

    //append the "z" domain
    json_object_set_value(cap_obj, "z", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "z");
    tmp_val = json_value_init_object();
    tmp_obj = json_value_get_object(tmp_val);
    json_object_set_number(tmp_obj, "min", cap_entry->cap.kda_onestep_cap->z.min);
    json_object_set_number(tmp_obj, "max", cap_entry->cap.kda_onestep_cap->z.max);
    json_object_set_number(tmp_obj, "increment", cap_entry->cap.kda_onestep_cap->z.increment);
    json_array_append_value(temp_arr, tmp_val);
err:
    if (pattern_str) free(pattern_str);
    return rv;
}

static AMVP_RESULT amvp_build_kda_twostep_register_cap(AMVP_CTX *ctx,
                                                   JSON_Object *cap_obj,
                                                   AMVP_CAPS_LIST *cap_entry) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    JSON_Value *common_val = NULL;
    JSON_Object *common_obj = NULL;
    JSON_Array *alg_specs_array = NULL, *tmp_arr = NULL;
    JSON_Value *tmp_val = NULL;
    JSON_Object *tmp_obj = NULL;
    JSON_Value *alg_specs_counter_val = NULL, *alg_specs_feedback_val = NULL, *alg_specs_dpi_val = NULL;
    JSON_Object *alg_specs_counter_obj = NULL, *alg_specs_feedback_obj = NULL, *alg_specs_dpi_obj = NULL;
    AMVP_NAME_LIST *tmp_name_list = NULL;
    AMVP_PARAM_LIST *tmp_param_list;
    AMVP_SL_LIST *list = NULL;
    const char *revision = NULL;
    const char *mode = NULL;
    char *pattern_str = NULL;
    AMVP_KDA_TWOSTEP_CAP *cap = cap_entry->cap.kda_twostep_cap;

    pattern_str = calloc(AMVP_KDA_PATTERN_REG_STR_MAX + 1, sizeof(char));
    if (!pattern_str) {
        AMVP_LOG_ERR("Error allocating memory for kda_twostep pattern string");
        return AMVP_MALLOC_FAIL;
    }

    if (!cap_entry->cap.kdf108_cap->counter_mode.kdf_mode && !cap_entry->cap.kdf108_cap->dpi_mode.kdf_mode
            && !cap_entry->cap.kdf108_cap->feedback_mode.kdf_mode) {
        AMVP_LOG_ERR("Must enable at least one KDF108 mode in KDA-Twostep");
        goto err;
    }

    json_object_set_string(cap_obj, "algorithm", amvp_lookup_cipher_name(cap_entry->cipher));
    mode = amvp_lookup_cipher_mode_str(cap_entry->cipher);
    if (!mode) {
        AMVP_LOG_ERR("Unable to find mode string for KDA-TWOSTEP when building registration");
        rv = AMVP_INVALID_ARG;
        goto err;
    }
    json_object_set_string(cap_obj, "mode", mode);
    if (cap->revision) {
        revision = amvp_lookup_alt_revision_string(cap->revision);
    } else {
        revision = amvp_lookup_cipher_revision(cap_entry->cipher);
    }
    if (!revision) {
        AMVP_LOG_ERR("Unable to find revision string for KDA-TWOSTEP when building registration");
        rv = AMVP_INVALID_ARG;
        goto err;
    }
    json_object_set_string(cap_obj, "revision", revision);

    rv= amvp_lookup_prereqVals(cap_obj, cap_entry);
    if (rv != AMVP_SUCCESS) { goto err; }

    //append the "l" value
    json_object_set_number(cap_obj, "l", cap->l);

    //append the "z" domain
    json_object_set_value(cap_obj, "z", json_value_init_array());
    tmp_arr = json_object_get_array(cap_obj, "z");
    tmp_val = json_value_init_object();
    tmp_obj = json_value_get_object(tmp_val);
    json_object_set_number(tmp_obj, "min", cap->z.min);
    json_object_set_number(tmp_obj, "max", cap->z.max);
    json_object_set_number(tmp_obj, "increment", cap->z.increment);
    json_array_append_value(tmp_arr, tmp_val);

    //append performMultiExpansionTests boolean, only for Cr2
    if (cap->revision != AMVP_REVISION_SP800_56CR1) {
        json_object_set_boolean(cap_obj, "performMultiExpansionTests", cap->perform_multi_expansion_tests);
    }

    /* Append the "usesHybridShareSecret" value and "auxSharedSecretLen" value if enabled */
    if (cap_entry->cap.kda_twostep_cap->use_hybrid_shared_secret) {
        json_object_set_boolean(cap_obj, "usesHybridSharedSecret", 1);
        json_object_set_value(cap_obj, "auxSharedSecretLen", json_value_init_array());
        tmp_arr = json_object_get_array(cap_obj, "auxSharedSecretLen");

        if (cap_entry->cap.kda_twostep_cap->aux_secret_len.min != 0 ||
                cap_entry->cap.kda_twostep_cap->aux_secret_len.max != 0 ||
                cap_entry->cap.kda_twostep_cap->aux_secret_len.increment != 0) {
            tmp_val = json_value_init_object();
            tmp_obj = json_value_get_object(tmp_val);
            json_object_set_number(tmp_obj, "min", cap_entry->cap.kda_twostep_cap->aux_secret_len.min);
            json_object_set_number(tmp_obj, "max", cap_entry->cap.kda_twostep_cap->aux_secret_len.max);
            json_object_set_number(tmp_obj, "increment", cap_entry->cap.kda_twostep_cap->aux_secret_len.increment);
            json_array_append_value(tmp_arr, tmp_val);
        }

        list = cap_entry->cap.kda_twostep_cap->aux_secret_len.values;
        while (list) {
            json_array_append_number(tmp_arr, list->length);
            list = list->next;
        }
    } else if (!cap_entry->cap.kda_twostep_cap->revision) {
        /* Only applies if using default revision */
        json_object_set_boolean(cap_obj, "usesHybridSharedSecret", 0);
    }

    /* Make an object with all of the common parameters in it. Then, copy it for each mode and add
    mode-specific stuff */
    common_val = json_value_init_object();
    common_obj = json_value_get_object(common_val);

    //pattern string is list of pattern values separated by '||'
    tmp_param_list = cap->patterns;
    if (!tmp_param_list) {
        AMVP_LOG_ERR("Missing patterns list when building registration");
        rv = AMVP_UNSUPPORTED_OP;
        goto err;
    }
    while (tmp_param_list) {
        switch (tmp_param_list->param) {
        case AMVP_KDA_PATTERN_LITERAL:
            if (!cap->literal_pattern_candidate) {
                AMVP_LOG_ERR("Missing literal pattern candidate for registration");
                rv = AMVP_MISSING_ARG;
                goto err;
            }
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1,
                      AMVP_KDA_PATTERN_LITERAL_STR,
                      sizeof(AMVP_KDA_PATTERN_LITERAL_STR) - 1);
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1, "[", 1);
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1,
                      cap->literal_pattern_candidate,
                      AMVP_KDA_PATTERN_LITERAL_STR_LEN_MAX);
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1, "]", 1);
            break;
        case AMVP_KDA_PATTERN_UPARTYINFO:
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1,
                      AMVP_KDA_PATTERN_UPARTYINFO_STR,
                      sizeof(AMVP_KDA_PATTERN_UPARTYINFO_STR) - 1);
            break;
        case AMVP_KDA_PATTERN_VPARTYINFO:
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1,
                      AMVP_KDA_PATTERN_VPARTYINFO_STR,
                      sizeof(AMVP_KDA_PATTERN_VPARTYINFO_STR) - 1);
            break;
        case AMVP_KDA_PATTERN_CONTEXT:
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1,
                      AMVP_KDA_PATTERN_CONTEXT_STR,
                      sizeof(AMVP_KDA_PATTERN_CONTEXT_STR) - 1);
            break;
        case AMVP_KDA_PATTERN_ALGID:
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1,
                      AMVP_KDA_PATTERN_ALGID_STR,
                      sizeof(AMVP_KDA_PATTERN_ALGID_STR) - 1);
            break;
        case AMVP_KDA_PATTERN_LABEL:
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1,
                      AMVP_KDA_PATTERN_LABEL_STR,
                      sizeof(AMVP_KDA_PATTERN_LABEL_STR) - 1);
            break;
        case AMVP_KDA_PATTERN_L:
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1,
                      AMVP_KDA_PATTERN_LENGTH_STR,
                      sizeof(AMVP_KDA_PATTERN_LENGTH_STR) - 1);
            break;
        case AMVP_KDA_PATTERN_T:
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1,
                      AMVP_KDA_PATTERN_T_STR,
                      sizeof(AMVP_KDA_PATTERN_T_STR) - 1);
            break;
        default:
            AMVP_LOG_ERR("Invalid pattern value in pattern list");
            rv = AMVP_INVALID_ARG;
            goto err;
        }

        if (tmp_param_list->next) {
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1, "||", 2); 
        }
        tmp_param_list = tmp_param_list->next;
    }
    json_object_set_string(common_obj, "fixedInfoPattern", pattern_str);

    //create the "encodings" array and populate it
    json_object_set_value(common_obj, "encoding", json_value_init_array());
    tmp_arr = json_object_get_array(common_obj, "encoding");
    tmp_param_list = cap->encodings;
    while (tmp_param_list) {
        switch (tmp_param_list->param) {
        case AMVP_KDA_ENCODING_CONCAT:
            json_array_append_string(tmp_arr, AMVP_KDA_ENCODING_CONCATENATION_STR);
            break;
        default:
            AMVP_LOG_ERR("Invalid encoding value in encoding list");
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        tmp_param_list = tmp_param_list->next;
    }

    //create the "macSaltMethods" array and populate it
    json_object_set_value(common_obj, "macSaltMethods", json_value_init_array());
    tmp_arr = json_object_get_array(common_obj, "macSaltMethods");
    tmp_name_list = cap->mac_salt_methods;
    while (tmp_name_list) {
        json_array_append_string(tmp_arr, tmp_name_list->name);
        tmp_name_list = tmp_name_list->next;
    }

    json_object_set_value(cap_obj, "capabilities", json_value_init_array());
    alg_specs_array = json_object_get_array(cap_obj, "capabilities");

    if (cap->kdf_params.counter_mode.kdf_mode) {
        alg_specs_counter_val = json_value_deep_copy(common_val);
        alg_specs_counter_obj = json_value_get_object(alg_specs_counter_val);
        json_object_set_string(alg_specs_counter_obj, "kdfMode", "counter");
        amvp_build_kdf108_mode_register(&alg_specs_counter_obj, &cap->kdf_params.counter_mode);
        json_array_append_value(alg_specs_array, alg_specs_counter_val);
    }
    if (cap->kdf_params.feedback_mode.kdf_mode) {
        alg_specs_feedback_val = json_value_deep_copy(common_val);
        alg_specs_feedback_obj = json_value_get_object(alg_specs_feedback_val);
        json_object_set_string(alg_specs_feedback_obj, "kdfMode", "feedback");
        amvp_build_kdf108_mode_register(&alg_specs_feedback_obj, &cap->kdf_params.feedback_mode);
        json_array_append_value(alg_specs_array, alg_specs_feedback_val);
    }
    if (cap->kdf_params.dpi_mode.kdf_mode) {
        alg_specs_dpi_val = json_value_deep_copy(common_val);
        alg_specs_dpi_obj = json_value_get_object(alg_specs_dpi_val);
        json_object_set_string(alg_specs_dpi_obj, "kdfMode", "dpi");
        amvp_build_kdf108_mode_register(&alg_specs_dpi_obj, &cap->kdf_params.dpi_mode);
        json_array_append_value(alg_specs_array, alg_specs_dpi_val);
    }

err:
    if (pattern_str) free(pattern_str);
    if (common_val) json_value_free(common_val);
    return rv;
}

static AMVP_RESULT amvp_build_kda_hkdf_register_cap(AMVP_CTX *ctx,
                                                   JSON_Object *cap_obj,
                                                   AMVP_CAPS_LIST *cap_entry) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    JSON_Array *temp_arr = NULL;
    JSON_Value *tmp_val = NULL;
    JSON_Object *tmp_obj = NULL;
    AMVP_NAME_LIST *tmp_name_list = NULL;
    AMVP_PARAM_LIST *tmp_param_list;
    AMVP_SL_LIST *list = NULL;
    const char *revision = NULL;
    const char *mode = NULL;
    char *pattern_str = NULL;
    AMVP_KDA_HKDF_CAP *cap = cap_entry->cap.kda_hkdf_cap;

    pattern_str = calloc(AMVP_KDA_PATTERN_REG_STR_MAX + 1, sizeof(char));
    if (!pattern_str) {
        AMVP_LOG_ERR("Error allocating memory for kda_hkdf pattern string");
        return AMVP_MALLOC_FAIL;
    }

    json_object_set_string(cap_obj, "algorithm", amvp_lookup_cipher_name(cap_entry->cipher));
    mode = amvp_lookup_cipher_mode_str(cap_entry->cipher);
    if (!mode) {
        AMVP_LOG_ERR("Unable to find mode string for KDA-HKDF when building registration");
        rv = AMVP_INVALID_ARG;
        goto err;
    }
    json_object_set_string(cap_obj, "mode", mode);
    if (cap->revision) {
        revision = amvp_lookup_alt_revision_string(cap->revision);
    } else {
        revision = amvp_lookup_cipher_revision(cap_entry->cipher);
    }
    if (!revision) {
        AMVP_LOG_ERR("Unable to find revision string for KDA-HKDF when building registration");
        rv = AMVP_INVALID_ARG;
        goto err;
    }
    json_object_set_string(cap_obj, "revision", revision);

    rv = amvp_lookup_prereqVals(cap_obj, cap_entry);
    if (rv != AMVP_SUCCESS) { goto err; }

    //pattern string is list of pattern values separated by '||'
    tmp_param_list = cap->patterns;
    if (!tmp_param_list) {
        AMVP_LOG_ERR("Missing patterns list when building registration");
        rv = AMVP_UNSUPPORTED_OP;
        goto err;
    }
    while (tmp_param_list) {
        switch (tmp_param_list->param) {
        case AMVP_KDA_PATTERN_LITERAL:
            if (!cap->literal_pattern_candidate) {
                AMVP_LOG_ERR("Missing literal pattern candidate for registration");
                rv = AMVP_MISSING_ARG;
                goto err;
            }
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1,
                      AMVP_KDA_PATTERN_LITERAL_STR,
                      sizeof(AMVP_KDA_PATTERN_LITERAL_STR) - 1);
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1, "[", 1);
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1,
                      cap->literal_pattern_candidate,
                      AMVP_KDA_PATTERN_LITERAL_STR_LEN_MAX);
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1, "]", 1);
            break;
        case AMVP_KDA_PATTERN_UPARTYINFO:
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1,
                      AMVP_KDA_PATTERN_UPARTYINFO_STR,
                      sizeof(AMVP_KDA_PATTERN_UPARTYINFO_STR) - 1);
            break;
        case AMVP_KDA_PATTERN_VPARTYINFO:
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1,
                      AMVP_KDA_PATTERN_VPARTYINFO_STR,
                      sizeof(AMVP_KDA_PATTERN_VPARTYINFO_STR) - 1);
            break;
        case AMVP_KDA_PATTERN_CONTEXT:
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1,
                      AMVP_KDA_PATTERN_CONTEXT_STR,
                      sizeof(AMVP_KDA_PATTERN_CONTEXT_STR) - 1);
            break;
        case AMVP_KDA_PATTERN_ALGID:
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1,
                      AMVP_KDA_PATTERN_ALGID_STR,
                      sizeof(AMVP_KDA_PATTERN_ALGID_STR) - 1);
            break;
        case AMVP_KDA_PATTERN_LABEL:
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1,
                      AMVP_KDA_PATTERN_LABEL_STR,
                      sizeof(AMVP_KDA_PATTERN_LABEL_STR) - 1);
            break;
        case AMVP_KDA_PATTERN_L:
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1,
                      AMVP_KDA_PATTERN_LENGTH_STR,
                      sizeof(AMVP_KDA_PATTERN_LENGTH_STR) - 1);
            break;
        case AMVP_KDA_PATTERN_T:
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1,
                      AMVP_KDA_PATTERN_T_STR,
                      sizeof(AMVP_KDA_PATTERN_T_STR) - 1);
            break;
        default:
            AMVP_LOG_ERR("Invalid pattern value in pattern list");
            rv = AMVP_INVALID_ARG;
            goto err;
        }

        if (tmp_param_list->next) {
            strncat_s(pattern_str, AMVP_KDA_PATTERN_REG_STR_MAX + 1, "||", 2); 
        }
        tmp_param_list = tmp_param_list->next;
    }
    json_object_set_string(cap_obj, "fixedInfoPattern", pattern_str);

    //create the "encodings" array and populate it
    json_object_set_value(cap_obj, "encoding", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "encoding");
    tmp_param_list = cap->encodings;
    while (tmp_param_list) {
        switch (tmp_param_list->param) {
        case AMVP_KDA_ENCODING_CONCAT:
            json_array_append_string(temp_arr, AMVP_KDA_ENCODING_CONCATENATION_STR);
            break;
        default:
            AMVP_LOG_ERR("Invalid encoding value in encoding list");
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        tmp_param_list = tmp_param_list->next;
    }

    //create the "hmacAlg" array and populate it
    json_object_set_value(cap_obj, "hmacAlg", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "hmacAlg");
    tmp_name_list = cap->hmac_algs;
    while (tmp_name_list) {
        json_array_append_string(temp_arr, tmp_name_list->name);
        tmp_name_list = tmp_name_list->next;
    }

    //create the "macSaltMethods" array and populate it
    json_object_set_value(cap_obj, "macSaltMethods", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "macSaltMethods");
    tmp_name_list = cap->mac_salt_methods;
    while (tmp_name_list) {
        json_array_append_string(temp_arr, tmp_name_list->name);
        tmp_name_list = tmp_name_list->next;
    }

    //append the "l" value
    json_object_set_number(cap_obj, "l", cap->l);

    //append the "z" domain
    json_object_set_value(cap_obj, "z", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "z");
    tmp_val = json_value_init_object();
    tmp_obj = json_value_get_object(tmp_val);
    json_object_set_number(tmp_obj, "min", cap->z.min);
    json_object_set_number(tmp_obj, "max", cap->z.max);
    json_object_set_number(tmp_obj, "increment", cap->z.increment);
    json_array_append_value(temp_arr, tmp_val);

    //append performMultiExpansionTests boolean, only for Cr2
    if (cap->revision != AMVP_REVISION_SP800_56CR1) {
        json_object_set_boolean(cap_obj, "performMultiExpansionTests", cap->perform_multi_expansion_tests);
    }

    /* Append the "usesHybridShareSecret" value and "auxSharedSecretLen" value if enabled */
    if (cap_entry->cap.kda_hkdf_cap->use_hybrid_shared_secret) {
        json_object_set_boolean(cap_obj, "usesHybridSharedSecret", 1);
        json_object_set_value(cap_obj, "auxSharedSecretLen", json_value_init_array());
        temp_arr = json_object_get_array(cap_obj, "auxSharedSecretLen");

        if (cap_entry->cap.kda_hkdf_cap->aux_secret_len.min != 0 ||
                cap_entry->cap.kda_hkdf_cap->aux_secret_len.max != 0 ||
                cap_entry->cap.kda_hkdf_cap->aux_secret_len.increment != 0) {
            tmp_val = json_value_init_object();
            tmp_obj = json_value_get_object(tmp_val);
            json_object_set_number(tmp_obj, "min", cap_entry->cap.kda_hkdf_cap->aux_secret_len.min);
            json_object_set_number(tmp_obj, "max", cap_entry->cap.kda_hkdf_cap->aux_secret_len.max);
            json_object_set_number(tmp_obj, "increment", cap_entry->cap.kda_hkdf_cap->aux_secret_len.increment);
            json_array_append_value(temp_arr, tmp_val);
        }

        list = cap_entry->cap.kda_hkdf_cap->aux_secret_len.values;
        while (list) {
            json_array_append_number(temp_arr, list->length);
            list = list->next;
        }
    } else if (!cap_entry->cap.kda_hkdf_cap->revision) {
        /* Only applies if using default revision */
        json_object_set_boolean(cap_obj, "usesHybridSharedSecret", 0);
    }
err:
    if (pattern_str) free(pattern_str);
    return rv;
}

static AMVP_RESULT amvp_build_kts_ifc_register_cap(AMVP_CTX *ctx,
                                                   JSON_Object *cap_obj,
                                                   AMVP_CAPS_LIST *cap_entry) {
    JSON_Array *temp_arr = NULL;
    AMVP_RESULT result;
    const char *revision = NULL, *hash = NULL;
    AMVP_KTS_IFC_CAP *kts_ifc_cap = NULL;
    AMVP_PARAM_LIST *current_param;
    AMVP_KTS_IFC_SCHEMES *current_scheme;
    AMVP_SL_LIST *current_len;
    JSON_Value *sch_val = NULL;
    JSON_Object *sch_obj = NULL;
    JSON_Value *meth_val = NULL;
    JSON_Object *meth_obj = NULL;
    JSON_Value *guts_val = NULL;
    JSON_Object *guts_obj = NULL;

    kts_ifc_cap = cap_entry->cap.kts_ifc_cap;
    if (!kts_ifc_cap) {
        return AMVP_NO_CAP;
    }

    if (cap_entry->prereq_vals) {
        json_object_set_string(cap_obj, "algorithm", amvp_lookup_cipher_name(cap_entry->cipher));

        revision = amvp_lookup_cipher_revision(cap_entry->cipher);
        if (revision == NULL) return AMVP_INVALID_ARG;
        json_object_set_string(cap_obj, "revision", revision);
        result = amvp_lookup_prereqVals(cap_obj, cap_entry);
        if (result != AMVP_SUCCESS) { return result; }
    }
    json_object_set_string(cap_obj, "fixedPubExp", (const char *)kts_ifc_cap->fixed_pub_exp);
    json_object_set_string(cap_obj, "iutId", (const char *)kts_ifc_cap->iut_id);

    json_object_set_value(cap_obj, "modulo", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "modulo");
    current_len = kts_ifc_cap->modulo;
    while (current_len) {
        json_array_append_number(temp_arr, current_len->length);
        current_len = current_len->next;
    }

    json_object_set_value(cap_obj, "keyGenerationMethods", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "keyGenerationMethods");
    current_param = kts_ifc_cap->keygen_method;
    while (current_param) {
        switch (current_param->param)
        {
            case AMVP_KTS_IFC_RSAKPG1_BASIC:
                json_array_append_string(temp_arr, "rsakpg1-basic");
                break;
            case AMVP_KTS_IFC_RSAKPG1_PRIME_FACTOR:
                json_array_append_string(temp_arr, "rsakpg1-prime-factor");
                break;
            case AMVP_KTS_IFC_RSAKPG1_CRT:
                json_array_append_string(temp_arr, "rsakpg1-crt");
                break;
            case AMVP_KTS_IFC_RSAKPG2_BASIC:
                json_array_append_string(temp_arr, "rsakpg2-basic");
                break;
            case AMVP_KTS_IFC_RSAKPG2_PRIME_FACTOR:
                json_array_append_string(temp_arr, "rsakpg2-prime-factor");
                break;
            case AMVP_KTS_IFC_RSAKPG2_CRT:
                json_array_append_string(temp_arr, "rsakpg2-crt");
                break;
            default:
                AMVP_LOG_ERR("Unsupported KTS-IFC keygen param %d", current_param->param);
                return AMVP_INVALID_ARG;
                break;
        }
        current_param = current_param->next;
    }

    json_object_set_value(cap_obj, "function", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "function");
    current_param = kts_ifc_cap->functions;
    while (current_param) {
        switch (current_param->param)
        {
            case AMVP_KTS_IFC_KEYPAIR_GEN:
                json_array_append_string(temp_arr, "keyPairGen");
                break;
            case AMVP_KTS_IFC_PARTIAL_VAL:
                json_array_append_string(temp_arr, "partialVal");
                break;
            default:
                AMVP_LOG_ERR("Unsupported KTS-IFC function param %d", current_param->param);
                return AMVP_INVALID_ARG;
                break;
        }
        current_param = current_param->next;
    }

    current_scheme = kts_ifc_cap->schemes;
    if (!current_scheme) {
        return AMVP_NO_CAP;
    }
    sch_val = json_value_init_object();
    sch_obj = json_value_get_object(sch_val);

    while (current_scheme) {

        guts_val = json_value_init_object();
        guts_obj = json_value_get_object(guts_val);

        json_object_set_number(guts_obj, "l", current_scheme->l);

        current_param = current_scheme->roles;
        if (current_param) {
            json_object_set_value(guts_obj, "kasRole", json_value_init_array());
            temp_arr = json_object_get_array(guts_obj, "kasRole");
            while (current_param) {
                switch (current_param->param)
                {
                    case AMVP_KTS_IFC_INITIATOR:
                        json_array_append_string(temp_arr, "initiator");
                        break;
                    case AMVP_KTS_IFC_RESPONDER:
                        json_array_append_string(temp_arr, "responder");
                        break;
                    default:
                        AMVP_LOG_ERR("Unsupported KTS-IFC role param %d", current_param->param);
                        return AMVP_INVALID_ARG;
                        break;
                }
                current_param = current_param->next;
            }
        }

        meth_val = json_value_init_object();
        meth_obj = json_value_get_object(meth_val);

        current_param = current_scheme->hash;
        if (current_param) {
            json_object_set_value(meth_obj, "hashAlgs", json_value_init_array());
            temp_arr = json_object_get_array(meth_obj, "hashAlgs");
            while (current_param) {
                hash = amvp_lookup_hash_alg_name(current_param->param);
                if (!hash) {
                    AMVP_LOG_ERR("Unsupported KTS-IFC sha param %d", current_param->param);
                    return AMVP_INVALID_ARG;
                    break;
                }
                json_array_append_string(temp_arr, hash);
                current_param = current_param->next;
            }
        }
        json_object_set_boolean(meth_obj, "supportsNullAssociatedData", current_scheme->null_assoc_data);
        if (current_scheme->assoc_data_pattern) {
            json_object_set_string(meth_obj, "associatedDataPattern", current_scheme->assoc_data_pattern);
        }
        json_object_set_value(meth_obj, "encoding", json_value_init_array());
        temp_arr = json_object_get_array(meth_obj, "encoding");
        json_array_append_string(temp_arr, current_scheme->encodings);
        json_object_set_value(guts_obj, "ktsMethod", meth_val);
        json_object_set_value(sch_obj, "KTS-OAEP-basic", guts_val);
        
        current_scheme = current_scheme->next;
    }

    json_object_set_value(cap_obj, "scheme", sch_val);

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_build_safe_primes_register_cap(AMVP_CTX *ctx,
                                                       JSON_Object *cap_obj,
                                                       AMVP_CAPS_LIST *cap_entry) {
    JSON_Array *temp_arr = NULL;
    AMVP_RESULT result;
    const char *revision = NULL;
    AMVP_SAFE_PRIMES_CAP *safe_primes_cap = NULL;
    AMVP_SAFE_PRIMES_CAP_MODE *safe_primes_cap_mode = NULL;
    AMVP_PARAM_LIST *current_genmeth;


    if (cap_entry->prereq_vals) {
        json_object_set_string(cap_obj, "algorithm", amvp_lookup_cipher_name(cap_entry->cipher));

        revision = amvp_lookup_cipher_revision(cap_entry->cipher);
        if (revision == NULL) return AMVP_INVALID_ARG;
        json_object_set_string(cap_obj, "revision", revision);
        result = amvp_lookup_prereqVals(cap_obj, cap_entry);
        if (result != AMVP_SUCCESS) { return result; }
    }

    if (cap_entry->cipher == AMVP_SAFE_PRIMES_KEYGEN) {
        json_object_set_string(cap_obj, "mode", "keyGen");
        safe_primes_cap = cap_entry->cap.safe_primes_keygen_cap;
    }
    if (cap_entry->cipher == AMVP_SAFE_PRIMES_KEYVER) {
        json_object_set_string(cap_obj, "mode", "keyVer");
        safe_primes_cap = cap_entry->cap.safe_primes_keyver_cap;
    }

    if (!safe_primes_cap) {
        return AMVP_NO_CAP;
    }

    safe_primes_cap_mode = safe_primes_cap->mode;
    if (!safe_primes_cap_mode) {
        return AMVP_NO_CAP;
    }
    json_object_set_value(cap_obj, "safePrimeGroups", json_value_init_array());
    temp_arr = json_object_get_array(cap_obj, "safePrimeGroups");

    current_genmeth = safe_primes_cap_mode->genmeth;
    if (current_genmeth) {
        while (current_genmeth) {
            switch (current_genmeth->param) {
                case AMVP_SAFE_PRIMES_MODP2048:
                    json_array_append_string(temp_arr, "modp-2048");
                    break;
                case AMVP_SAFE_PRIMES_MODP3072:
                    json_array_append_string(temp_arr, "modp-3072");
                    break;
                case AMVP_SAFE_PRIMES_MODP4096:
                    json_array_append_string(temp_arr, "modp-4096");
                    break;
                case AMVP_SAFE_PRIMES_MODP6144:
                    json_array_append_string(temp_arr, "modp-6144");
                    break;
                case AMVP_SAFE_PRIMES_MODP8192:
                    json_array_append_string(temp_arr, "modp-8192");
                    break;
                case AMVP_SAFE_PRIMES_FFDHE2048:
                    json_array_append_string(temp_arr, "ffdhe2048");
                    break;
                case AMVP_SAFE_PRIMES_FFDHE3072:
                    json_array_append_string(temp_arr, "ffdhe3072");
                    break;
                case AMVP_SAFE_PRIMES_FFDHE4096:
                    json_array_append_string(temp_arr, "ffdhe4096");
                    break;
                case AMVP_SAFE_PRIMES_FFDHE6144:
                    json_array_append_string(temp_arr, "ffdhe6144");
                    break;
                case AMVP_SAFE_PRIMES_FFDHE8192:
                    json_array_append_string(temp_arr, "ffdhe8192");
                    break;
                default:
                    AMVP_LOG_ERR("Unsupported SAFE-PRIMES param %d", current_genmeth->param);
                    return AMVP_INVALID_ARG;
            }
            current_genmeth = current_genmeth->next;
        }
    }
    return AMVP_SUCCESS;
}

/*
 * This function builds the JSON register message that
 * will be sent to the AMVP server to advertised the crypto
 * capabilities of the module under test.
 */
AMVP_RESULT amvp_build_registration_json(AMVP_CTX *ctx, JSON_Value **reg) {
    AMVP_RESULT rv = AMVP_SUCCESS;
    AMVP_CAPS_LIST *cap_entry;
    JSON_Value *val = NULL, *cap_val = NULL;
    JSON_Array *caps_arr = NULL;
    JSON_Object *cap_obj = NULL;

    if (!ctx) {
        AMVP_LOG_ERR("No ctx for build_test_session");
        return AMVP_NO_CTX;
    }

  /*  val = json_value_init_object();
    obj = json_value_get_object(val);


    json_object_set_value(obj, "algorithms", json_value_init_array());
    caps_arr = json_object_get_array(obj, "algorithms"); */
    val = json_value_init_array();
    caps_arr = json_value_get_array(val);
    /*
     * Iterate through all the capabilities the user has enabled
     */
    if (ctx->caps_list) {
        cap_entry = ctx->caps_list;
        while (cap_entry) {
            /*
             * Create a new capability to be advertised in the JSON
             * registration message
             */
            cap_val = json_value_init_object();
            cap_obj = json_value_get_object(cap_val);

            /*
             * Build up the capability JSON based on the cipher type
             */
            switch (cap_entry->cipher) {
            case AMVP_AES_GCM:
            case AMVP_AES_XPN:
            case AMVP_AES_GMAC:
            case AMVP_AES_CTR:
                /**
                 * If we need to test both internal and external IV gen, we need two different
                 * algorithm registrations/vector sets currently.
                 */
                if (cap_entry->cap.sym_cap->ivgen_source == AMVP_SYM_CIPH_IVGEN_SRC_EITHER) {
                    cap_entry->cap.sym_cap->ivgen_source = AMVP_SYM_CIPH_IVGEN_SRC_INT;
                    rv = amvp_build_sym_cipher_register_cap(cap_obj, cap_entry);
                    if (rv != AMVP_SUCCESS) {
                        cap_entry->cap.sym_cap->ivgen_source = AMVP_SYM_CIPH_IVGEN_SRC_EITHER;
                        break;
                    }
                    json_array_append_value(caps_arr, cap_val);
                    cap_val = json_value_init_object();
                    cap_obj = json_value_get_object(cap_val);
                    cap_entry->cap.sym_cap->ivgen_source = AMVP_SYM_CIPH_IVGEN_SRC_EXT;
                    rv = amvp_build_sym_cipher_register_cap(cap_obj, cap_entry);
                    cap_entry->cap.sym_cap->ivgen_source = AMVP_SYM_CIPH_IVGEN_SRC_EITHER;
                } else {
                    rv = amvp_build_sym_cipher_register_cap(cap_obj, cap_entry);
                }
                break;
            case AMVP_AES_GCM_SIV:
            case AMVP_AES_CCM:
            case AMVP_AES_ECB:
            case AMVP_AES_CFB1:
            case AMVP_AES_CFB8:
            case AMVP_AES_CFB128:
            case AMVP_AES_OFB:
            case AMVP_AES_CBC:
            case AMVP_AES_CBC_CS1:
            case AMVP_AES_CBC_CS2:
            case AMVP_AES_CBC_CS3:
            case AMVP_AES_KW:
            case AMVP_AES_KWP:
            case AMVP_AES_XTS:
            case AMVP_TDES_ECB:
            case AMVP_TDES_CBC:
            case AMVP_TDES_CTR:
            case AMVP_TDES_OFB:
            case AMVP_TDES_CFB64:
            case AMVP_TDES_CFB8:
            case AMVP_TDES_CFB1:
            case AMVP_TDES_CBCI:
            case AMVP_TDES_OFBI:
            case AMVP_TDES_CFBP1:
            case AMVP_TDES_CFBP8:
            case AMVP_TDES_CFBP64:
            case AMVP_TDES_KW:
                rv = amvp_build_sym_cipher_register_cap(cap_obj, cap_entry);
                break;
            case AMVP_HASH_SHA1:
            case AMVP_HASH_SHA224:
            case AMVP_HASH_SHA256:
            case AMVP_HASH_SHA384:
            case AMVP_HASH_SHA512:
            case AMVP_HASH_SHA512_224:
            case AMVP_HASH_SHA512_256:
            case AMVP_HASH_SHA3_224:
            case AMVP_HASH_SHA3_256:
            case AMVP_HASH_SHA3_384:
            case AMVP_HASH_SHA3_512:
            case AMVP_HASH_SHAKE_128:
            case AMVP_HASH_SHAKE_256:
                rv = amvp_build_hash_register_cap(cap_obj, cap_entry);
                break;
            case AMVP_HASHDRBG:
            case AMVP_HMACDRBG:
            case AMVP_CTRDRBG:
                rv = amvp_build_drbg_register_cap(cap_obj, cap_entry);
                break;
            case AMVP_HMAC_SHA1:
            case AMVP_HMAC_SHA2_224:
            case AMVP_HMAC_SHA2_256:
            case AMVP_HMAC_SHA2_384:
            case AMVP_HMAC_SHA2_512:
            case AMVP_HMAC_SHA2_512_224:
            case AMVP_HMAC_SHA2_512_256:
            case AMVP_HMAC_SHA3_224:
            case AMVP_HMAC_SHA3_256:
            case AMVP_HMAC_SHA3_384:
            case AMVP_HMAC_SHA3_512:
                rv = amvp_build_hmac_register_cap(cap_obj, cap_entry);
                break;
            case AMVP_CMAC_AES:
            case AMVP_CMAC_TDES:
                rv = amvp_build_cmac_register_cap(cap_obj, cap_entry);
                break;
            case AMVP_KMAC_128:
            case AMVP_KMAC_256:
                rv = amvp_build_kmac_register_cap(cap_obj, cap_entry);
                break;
            case AMVP_DSA_KEYGEN:
                rv = amvp_build_dsa_register_cap(cap_obj, cap_entry, AMVP_DSA_MODE_KEYGEN);
                break;
            case AMVP_DSA_PQGVER:
                rv = amvp_build_dsa_register_cap(cap_obj, cap_entry, AMVP_DSA_MODE_PQGVER);
                break;
            case AMVP_DSA_PQGGEN:
                rv = amvp_build_dsa_register_cap(cap_obj, cap_entry, AMVP_DSA_MODE_PQGGEN);
                break;
            case AMVP_DSA_SIGGEN:
                rv = amvp_build_dsa_register_cap(cap_obj, cap_entry, AMVP_DSA_MODE_SIGGEN);
                break;
            case AMVP_DSA_SIGVER:
                rv = amvp_build_dsa_register_cap(cap_obj, cap_entry, AMVP_DSA_MODE_SIGVER);
                break;
            case AMVP_RSA_KEYGEN:
                rv = amvp_build_rsa_keygen_register_cap(cap_obj, cap_entry);
                break;
            case AMVP_RSA_SIGGEN:
            case AMVP_RSA_SIGVER:
                rv = amvp_build_rsa_sig_register_cap(cap_obj, cap_entry);
                break;
            case AMVP_RSA_SIGPRIM:
            case AMVP_RSA_DECPRIM:
                rv = amvp_build_rsa_prim_register_cap(cap_obj, cap_entry);
                break;
            case AMVP_ECDSA_KEYGEN:
            case AMVP_ECDSA_KEYVER:
                rv = amvp_build_ecdsa_register_cap(ctx, cap_entry->cipher, cap_obj, cap_entry);
                break;
            case AMVP_ECDSA_SIGGEN:
                /* If component_test = BOTH, we need two registrations */
                if (cap_entry->cap.ecdsa_siggen_cap->component == AMVP_ECDSA_COMPONENT_MODE_BOTH) {
                    cap_entry->cap.ecdsa_siggen_cap->component = AMVP_ECDSA_COMPONENT_MODE_NO;
                    rv = amvp_build_ecdsa_register_cap(ctx, cap_entry->cipher, cap_obj, cap_entry);
                    if (rv != AMVP_SUCCESS) {
                        cap_entry->cap.ecdsa_siggen_cap->component = AMVP_ECDSA_COMPONENT_MODE_BOTH;
                        break;
                    }
                    json_array_append_value(caps_arr, cap_val);
                    cap_val = json_value_init_object();
                    cap_obj = json_value_get_object(cap_val);
                    cap_entry->cap.ecdsa_siggen_cap->component = AMVP_ECDSA_COMPONENT_MODE_YES;
                    rv = amvp_build_ecdsa_register_cap(ctx, cap_entry->cipher, cap_obj, cap_entry);
                    cap_entry->cap.ecdsa_siggen_cap->component = AMVP_ECDSA_COMPONENT_MODE_BOTH;
                } else {
                    rv = amvp_build_ecdsa_register_cap(ctx, cap_entry->cipher, cap_obj, cap_entry);
                }
                break;
            case AMVP_ECDSA_SIGVER:
                /* If component_test = BOTH, we need two registrations */
                if (cap_entry->cap.ecdsa_sigver_cap->component == AMVP_ECDSA_COMPONENT_MODE_BOTH) {
                    cap_entry->cap.ecdsa_sigver_cap->component = AMVP_ECDSA_COMPONENT_MODE_NO;
                    rv = amvp_build_ecdsa_register_cap(ctx, cap_entry->cipher, cap_obj, cap_entry);
                    if (rv != AMVP_SUCCESS) {
                        cap_entry->cap.ecdsa_sigver_cap->component = AMVP_ECDSA_COMPONENT_MODE_BOTH;
                        break;
                    }
                    json_array_append_value(caps_arr, cap_val);
                    cap_val = json_value_init_object();
                    cap_obj = json_value_get_object(cap_val);
                    cap_entry->cap.ecdsa_sigver_cap->component = AMVP_ECDSA_COMPONENT_MODE_YES;
                    rv = amvp_build_ecdsa_register_cap(ctx, cap_entry->cipher, cap_obj, cap_entry);
                    cap_entry->cap.ecdsa_sigver_cap->component = AMVP_ECDSA_COMPONENT_MODE_BOTH;
                } else {
                    rv = amvp_build_ecdsa_register_cap(ctx, cap_entry->cipher, cap_obj, cap_entry);
                }
                break;
            case AMVP_KDF135_SNMP:
                rv = amvp_build_kdf135_snmp_register_cap(cap_obj, cap_entry);
                break;
            case AMVP_KDF135_SSH:
                rv = amvp_build_kdf135_ssh_register_cap(cap_obj, cap_entry);
                break;
            case AMVP_KDF135_SRTP:
                rv = amvp_build_kdf135_srtp_register_cap(cap_obj, cap_entry);
                break;
            case AMVP_KDF135_IKEV2:
                rv = amvp_build_kdf135_ikev2_register_cap(cap_obj, cap_entry);
                break;
            case AMVP_KDF135_IKEV1:
                rv = amvp_build_kdf135_ikev1_register_cap(cap_obj, cap_entry);
                break;
            case AMVP_KDF135_X942:
                rv = amvp_build_kdf135_x942_register_cap(cap_obj, cap_entry);
                break;
            case AMVP_KDF135_X963:
                rv = amvp_build_kdf135_x963_register_cap(cap_obj, cap_entry);
                break;
            case AMVP_KDF108:
                rv = amvp_build_kdf108_register_cap(cap_obj, cap_entry);
                break;
            case AMVP_PBKDF:
                rv = amvp_build_pbkdf_register_cap(cap_obj, cap_entry);
                break;
            case AMVP_KDF_TLS12:
                rv = amvp_build_kdf_tls12_register_cap(cap_obj, cap_entry);
                break;
            case AMVP_KDF_TLS13:
                rv = amvp_build_kdf_tls13_register_cap(cap_obj, cap_entry);
                break;
            case AMVP_KAS_ECC_CDH:
                rv = amvp_build_kas_ecc_register_cap(ctx, cap_obj, cap_entry, AMVP_KAS_ECC_MODE_CDH);
                break;
            case AMVP_KAS_ECC_COMP:
                rv = amvp_build_kas_ecc_register_cap(ctx, cap_obj, cap_entry, AMVP_KAS_ECC_MODE_COMPONENT);
                break;
            case AMVP_KAS_ECC_SSC:
                rv = amvp_build_kas_ecc_register_cap(ctx, cap_obj, cap_entry, AMVP_KAS_ECC_MODE_NONE);
                break;
            case AMVP_KAS_ECC_NOCOMP:
                rv = amvp_build_kas_ecc_register_cap(ctx, cap_obj, cap_entry, AMVP_KAS_ECC_MODE_NOCOMP);
                break;
            case AMVP_KAS_FFC_COMP:
                rv = amvp_build_kas_ffc_register_cap(ctx, cap_obj, cap_entry, AMVP_KAS_FFC_MODE_COMPONENT);
                break;
            case AMVP_KAS_FFC_NOCOMP:
                rv = amvp_build_kas_ffc_register_cap(ctx, cap_obj, cap_entry, AMVP_KAS_FFC_MODE_NOCOMP);
                break;
            case AMVP_KAS_FFC_SSC:
                rv = amvp_build_kas_ffc_register_cap(ctx, cap_obj, cap_entry, AMVP_KAS_FFC_MODE_NONE);
                break;
            case AMVP_KAS_IFC_SSC:
                rv = amvp_build_kas_ifc_register_cap(ctx, cap_obj, cap_entry);
                break;
            case AMVP_KDA_ONESTEP:
                rv = amvp_build_kda_onestep_register_cap(ctx, cap_obj, cap_entry);
                break;
            case AMVP_KDA_TWOSTEP:
                rv = amvp_build_kda_twostep_register_cap(ctx, cap_obj, cap_entry);
                break;
            case AMVP_KDA_HKDF:
                rv = amvp_build_kda_hkdf_register_cap(ctx, cap_obj, cap_entry);
                break;
            case AMVP_KTS_IFC:
                rv = amvp_build_kts_ifc_register_cap(ctx, cap_obj, cap_entry);
                break;
            case AMVP_SAFE_PRIMES_KEYGEN:
            case AMVP_SAFE_PRIMES_KEYVER:
                rv = amvp_build_safe_primes_register_cap(ctx, cap_obj, cap_entry);
                break;
            case AMVP_CIPHER_START:
            case AMVP_CIPHER_END:
            default:
                AMVP_LOG_ERR("Cap entry not found, %d.", cap_entry->cipher);
                json_value_free(cap_val);
                json_value_free(val);
                return AMVP_NO_CAP;
            }

            if (rv != AMVP_SUCCESS) {
                AMVP_LOG_ERR("failed to build registration for cipher %s (%d)", amvp_lookup_cipher_name(cap_entry->cipher), rv);
                json_value_free(cap_val);
                json_value_free(val);
                return rv;
            }

            /*
             * Now that we've built up the JSON for this capability,
             * add it to the array of capabilities on the register message.
             */
            json_array_append_value(caps_arr, cap_val);

            /* Advance to next cap entry */
            cap_entry = cap_entry->next;
        }
    } else {
        AMVP_LOG_ERR("No capabilities added to ctx");
        json_value_free(val);
        return AMVP_NO_CAP;
    }

    *reg = val;

    return AMVP_SUCCESS;
}

static JSON_Value *amvp_version_json_value(void) {
    JSON_Value *version_val = NULL;
    JSON_Object *version_obj = NULL;

    version_val = json_value_init_object();
    version_obj = json_value_get_object(version_val);

    json_object_set_string(version_obj, "amvVersion", AMVP_VERSION);

    return version_val;
}

AMVP_RESULT amvp_build_full_registration(AMVP_CTX *ctx, char **out, int *out_len) {
    JSON_Value *top_array_val = NULL, *val = NULL;
    JSON_Array *top_array = NULL;
    JSON_Object *obj = NULL;

    /*
     * Start top-level array
     */
    top_array_val = json_value_init_array();
    if (!top_array_val) {
        return AMVP_MALLOC_FAIL;
    }
    top_array = json_array((const JSON_Value *)top_array_val);
    json_array_append_value(top_array, amvp_version_json_value());

    val = json_value_init_object();
    obj = json_value_get_object(val);

    json_object_set_boolean(obj, "isSample", ctx->is_sample);
    json_object_set_value(obj, "algorithms", ctx->registration);

    json_array_append_value(top_array, val);
    *out = json_serialize_to_string(top_array_val, out_len);

    json_object_soft_remove(obj, "algorithms");
    if (top_array_val) json_value_free(top_array_val);
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
    json_array_append_value(top_array, amvp_version_json_value());

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

