/** @file */
/*
 * Copyright (c) 2021, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libamvp/LICENSE
 */


/*
 * This file tests the build_registration API
 * including when some of the capability APIs aren't called
 * (some required values weren't added, for example)
 * test_amvp_capabilities.c tests the enable_* APIs
 */

#include "ut_common.h"
#include "amvp/amvp_lcl.h"

static AMVP_CTX *ctx = NULL;
static AMVP_RESULT rv = 0;
static char *cvalue = "same";
static char *reg;
static JSON_Value *reg_value;
static JSON_Value *generated_value;
static JSON_Value *known_good_value;
static JSON_Object *generated_obj;
static JSON_Object *known_good_obj;


static void add_des_details_good(void) {
    /*
     * Enable 3DES-ECB
     */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_TDES_ECB, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_TDES_ECB, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_TDES_ECB, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_ONE);
    cr_assert(rv == AMVP_SUCCESS);

    /*
     * Enable 3DES-CBC
     */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_TDES_CBC, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_TDES_CBC, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_TDES_CBC, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_ONE);
    cr_assert(rv == AMVP_SUCCESS);

    /*
     * Enable 3DES-OFB
     */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_TDES_OFB, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_TDES_OFB, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_TDES_OFB, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_ONE);
    cr_assert(rv == AMVP_SUCCESS);

    /*
     * Enable 3DES-CFB64
     */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_TDES_CFB64, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_TDES_CFB64, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_TDES_CFB64, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_ONE);
    cr_assert(rv == AMVP_SUCCESS);

    /*
     * Enable 3DES-CFB8
     */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_TDES_CFB8, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_TDES_CFB8, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_TDES_CFB8, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_ONE);
    cr_assert(rv == AMVP_SUCCESS);

    /*
     * Enable 3DES-CFB1
     */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_TDES_CFB1, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_TDES_CFB1, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_TDES_CFB1, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_ONE);
    cr_assert(rv == AMVP_SUCCESS);
}

static void add_aes_details_good(void) {
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_GCM, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_AES_GCM, AMVP_PREREQ_AES, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_AES_GCM, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_NA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_PARM_IVGEN_SRC, AMVP_SYM_CIPH_IVGEN_SRC_INT);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_PARM_IVGEN_MODE, AMVP_SYM_CIPH_IVGEN_MODE_821);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_KEYLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_KEYLEN, 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_TAGLEN, 96);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_TAGLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_IVLEN, 96);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_PTLEN, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_PTLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_PTLEN, 136);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_PTLEN, 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_PTLEN, 264);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_AADLEN, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_AADLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_AADLEN, 136);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_AADLEN, 256);
    cr_assert(rv == AMVP_SUCCESS);

    /*
     * Enable AES-ECB 128,192,256 bit key
     */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_ECB, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_ECB, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_ECB, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_NA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_ECB, AMVP_SYM_CIPH_PARM_IVGEN_SRC, AMVP_SYM_CIPH_IVGEN_SRC_NA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_ECB, AMVP_SYM_CIPH_PARM_IVGEN_MODE, AMVP_SYM_CIPH_IVGEN_MODE_NA);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_ECB, AMVP_SYM_CIPH_KEYLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_ECB, AMVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_ECB, AMVP_SYM_CIPH_KEYLEN, 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_ECB, AMVP_SYM_CIPH_PTLEN, 1536);
    cr_assert(rv == AMVP_SUCCESS);

    /*
     * Enable AES-CBC 128 bit key
     */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_CBC, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_NA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC, AMVP_SYM_CIPH_PARM_IVGEN_SRC, AMVP_SYM_CIPH_IVGEN_SRC_NA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC, AMVP_SYM_CIPH_PARM_IVGEN_MODE, AMVP_SYM_CIPH_IVGEN_MODE_NA);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC, AMVP_SYM_CIPH_KEYLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC, AMVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC, AMVP_SYM_CIPH_KEYLEN, 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC, AMVP_SYM_CIPH_PTLEN, 1536);
    cr_assert(rv == AMVP_SUCCESS);

    /*
     * Enable AES-CFB1 128,192,256 bit key
     */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_CFB1, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB1, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB1, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_NA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB1, AMVP_SYM_CIPH_PARM_IVGEN_SRC, AMVP_SYM_CIPH_IVGEN_SRC_NA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB1, AMVP_SYM_CIPH_PARM_IVGEN_MODE, AMVP_SYM_CIPH_IVGEN_MODE_NA);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB1, AMVP_SYM_CIPH_KEYLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB1, AMVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB1, AMVP_SYM_CIPH_KEYLEN, 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB1, AMVP_SYM_CIPH_PTLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);

    /*
     * Enable AES-CFB8 128,192,256 bit key
     */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_CFB8, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB8, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB8, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_NA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB8, AMVP_SYM_CIPH_PARM_IVGEN_SRC, AMVP_SYM_CIPH_IVGEN_SRC_NA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB8, AMVP_SYM_CIPH_PARM_IVGEN_MODE, AMVP_SYM_CIPH_IVGEN_MODE_NA);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB8, AMVP_SYM_CIPH_KEYLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB8, AMVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB8, AMVP_SYM_CIPH_KEYLEN, 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB8, AMVP_SYM_CIPH_PTLEN, 256);
    cr_assert(rv == AMVP_SUCCESS);

    /*
     * Enable AES-CFB128 128,192,256 bit key
     */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_CFB128, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB128, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB128, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_NA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB128, AMVP_SYM_CIPH_PARM_IVGEN_SRC, AMVP_SYM_CIPH_IVGEN_SRC_NA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB128, AMVP_SYM_CIPH_PARM_IVGEN_MODE, AMVP_SYM_CIPH_IVGEN_MODE_NA);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB128, AMVP_SYM_CIPH_KEYLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB128, AMVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB128, AMVP_SYM_CIPH_KEYLEN, 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CFB128, AMVP_SYM_CIPH_PTLEN, 1536);
    cr_assert(rv == AMVP_SUCCESS);

    /*
     * Enable AES-OFB 128, 192, 256 bit key
     */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_OFB, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_OFB, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_OFB, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_NA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_OFB, AMVP_SYM_CIPH_PARM_IVGEN_SRC, AMVP_SYM_CIPH_IVGEN_SRC_NA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_OFB, AMVP_SYM_CIPH_PARM_IVGEN_MODE, AMVP_SYM_CIPH_IVGEN_MODE_NA);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_OFB, AMVP_SYM_CIPH_KEYLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_OFB, AMVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_OFB, AMVP_SYM_CIPH_KEYLEN, 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_OFB, AMVP_SYM_CIPH_PTLEN, 1536);
    cr_assert(rv == AMVP_SUCCESS);

    /*
     * Register AES CCM capabilities
     */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_CCM, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_AES_CCM, AMVP_PREREQ_AES, cvalue);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CCM, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CCM, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_NA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CCM, AMVP_SYM_CIPH_PARM_IVGEN_SRC, AMVP_SYM_CIPH_IVGEN_SRC_NA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CCM, AMVP_SYM_CIPH_PARM_IVGEN_MODE, AMVP_SYM_CIPH_IVGEN_MODE_NA);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CCM, AMVP_SYM_CIPH_KEYLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CCM, AMVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CCM, AMVP_SYM_CIPH_KEYLEN, 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CCM, AMVP_SYM_CIPH_PTLEN, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CCM, AMVP_SYM_CIPH_PTLEN, 192);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CCM, AMVP_SYM_CIPH_TAGLEN, 32);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CCM, AMVP_SYM_CIPH_TAGLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CCM, AMVP_SYM_CIPH_IVLEN, 56);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CCM, AMVP_SYM_CIPH_IVLEN, 104);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CCM, AMVP_SYM_CIPH_AADLEN, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CCM, AMVP_SYM_CIPH_AADLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);

    /*
     * Enable AES keywrap for various key sizes and PT lengths
     * Note: this is with padding disabled, minimum PT length is 128 bits and must be
     *       a multiple of 64 bits. openssl does not support INVERSE mode.
     */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_KW, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KW, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KW, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_NA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KW, AMVP_SYM_CIPH_PARM_IVGEN_SRC, AMVP_SYM_CIPH_IVGEN_SRC_NA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KW, AMVP_SYM_CIPH_PARM_IVGEN_MODE, AMVP_SYM_CIPH_IVGEN_MODE_NA);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KW, AMVP_SYM_CIPH_KW_MODE, AMVP_SYM_KW_CIPHER);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KW, AMVP_SYM_CIPH_KEYLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KW, AMVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KW, AMVP_SYM_CIPH_KEYLEN, 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KW, AMVP_SYM_CIPH_PTLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KW, AMVP_SYM_CIPH_PTLEN, 192);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KW, AMVP_SYM_CIPH_PTLEN, 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KW, AMVP_SYM_CIPH_PTLEN, 320);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KW, AMVP_SYM_CIPH_PTLEN, 1280);
    cr_assert(rv == AMVP_SUCCESS);

    /*
     * Enable AES-XTS 128 and 256 bit key
     */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_XTS, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XTS, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XTS, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_NA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XTS, AMVP_SYM_CIPH_PARM_IVGEN_SRC, AMVP_SYM_CIPH_IVGEN_SRC_NA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XTS, AMVP_SYM_CIPH_PARM_IVGEN_MODE, AMVP_SYM_CIPH_IVGEN_MODE_NA);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XTS, AMVP_SYM_CIPH_KEYLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XTS, AMVP_SYM_CIPH_KEYLEN, 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XTS, AMVP_SYM_CIPH_PTLEN, 65536);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XTS, AMVP_SYM_CIPH_TWEAK, AMVP_SYM_CIPH_TWEAK_HEX);
    cr_assert(rv == AMVP_SUCCESS);
}

static void add_hash_details_good(void) {
    rv = amvp_cap_hash_enable(ctx, AMVP_HASH_SHA1, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_hash_set_domain(ctx, AMVP_HASH_SHA1, AMVP_HASH_MESSAGE_LEN, 0, 65528, 8);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_hash_enable(ctx, AMVP_HASH_SHA224, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_hash_set_domain(ctx, AMVP_HASH_SHA224, AMVP_HASH_MESSAGE_LEN, 0, 65528, 8);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_hash_enable(ctx, AMVP_HASH_SHA256, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_hash_set_domain(ctx, AMVP_HASH_SHA256, AMVP_HASH_MESSAGE_LEN, 0, 65528, 8);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_hash_enable(ctx, AMVP_HASH_SHA384, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_hash_set_domain(ctx, AMVP_HASH_SHA384, AMVP_HASH_MESSAGE_LEN, 0, 65528, 8);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_hash_enable(ctx, AMVP_HASH_SHA512, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_hash_set_domain(ctx, AMVP_HASH_SHA512, AMVP_HASH_MESSAGE_LEN, 0, 65528, 8);
    cr_assert(rv == AMVP_SUCCESS);
}

static void add_drbg_details_good(void) {
    rv = amvp_cap_drbg_enable(ctx, AMVP_HASHDRBG, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0,
                                   AMVP_DRBG_DER_FUNC_ENABLED, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_HASHDRBG, 
                                     AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0,
                                   AMVP_DRBG_PRED_RESIST_ENABLED, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0,
                                   AMVP_DRBG_RESEED_ENABLED, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0,
                                     AMVP_DRBG_ENTROPY_LEN, (int)128, (int)64,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0,
                                     AMVP_DRBG_NONCE_LEN, (int)96, (int)32,(int) 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0,
                                     AMVP_DRBG_PERSO_LEN, (int)0, (int)128,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0,
                                     AMVP_DRBG_ADD_IN_LEN, (int)0, (int)128,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HASHDRBG, AMVP_DRBG_SHA_1, 0,
                                   AMVP_DRBG_RET_BITS_LEN, 160);
    cr_assert(rv == AMVP_SUCCESS);

    //AMVP_HMACDRBG
    rv = amvp_cap_drbg_enable(ctx, AMVP_HMACDRBG, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_HMACDRBG, 
                                     AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_HMACDRBG, 
                                     AMVP_PREREQ_HMAC, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0,
                                   AMVP_DRBG_DER_FUNC_ENABLED, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0,
                                   AMVP_DRBG_PRED_RESIST_ENABLED, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0,
                                   AMVP_DRBG_RESEED_ENABLED, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_drbg_set_parm(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0,
                                   AMVP_DRBG_RET_BITS_LEN, 224);
    cr_assert(rv == AMVP_SUCCESS);
    //Add length range
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0,
                                     AMVP_DRBG_ENTROPY_LEN, (int)192, (int)64,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0,
                                     AMVP_DRBG_NONCE_LEN, (int)192, (int)64,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0,
                                     AMVP_DRBG_PERSO_LEN, (int)0, (int)128,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_HMACDRBG, AMVP_DRBG_SHA_224, 0,
                                     AMVP_DRBG_ADD_IN_LEN, (int)0, (int)128,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);

    // AMVP_CTRDRBG
    rv = amvp_cap_drbg_enable(ctx, AMVP_CTRDRBG, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_CTRDRBG, 
                                     AMVP_PREREQ_AES, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0,
                                     AMVP_DRBG_ENTROPY_LEN, (int)128, (int)128, (int) 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0,
                                     AMVP_DRBG_NONCE_LEN, (int)64, (int)64,(int) 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0,
                                     AMVP_DRBG_PERSO_LEN, (int)0, (int)256,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_drbg_set_length(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0,
                                     AMVP_DRBG_ADD_IN_LEN, (int)0, (int)256,(int) 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_drbg_set_parm(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0,
                                   AMVP_DRBG_DER_FUNC_ENABLED, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_drbg_set_parm(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0,
                                   AMVP_DRBG_PRED_RESIST_ENABLED, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_drbg_set_parm(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0,
                                   AMVP_DRBG_RESEED_ENABLED, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_drbg_set_parm(ctx, AMVP_CTRDRBG, AMVP_DRBG_AES_128, 0,
                                   AMVP_DRBG_RET_BITS_LEN, 256);
    cr_assert(rv == AMVP_SUCCESS);
}

static void add_cmac_details_good(void) {
    rv = amvp_cap_cmac_enable(ctx, AMVP_CMAC_AES, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_cmac_set_domain(ctx, AMVP_CMAC_AES, AMVP_CMAC_MSGLEN, 0, 65536, 8);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_cmac_set_parm(ctx, AMVP_CMAC_AES, AMVP_CMAC_MACLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_cmac_set_parm(ctx, AMVP_CMAC_AES, AMVP_CMAC_KEYLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_cmac_set_parm(ctx, AMVP_CMAC_AES, AMVP_CMAC_KEYLEN, 192);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_cmac_set_parm(ctx, AMVP_CMAC_AES, AMVP_CMAC_KEYLEN, 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_cmac_set_parm(ctx, AMVP_CMAC_AES, AMVP_CMAC_DIRECTION_GEN, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_cmac_set_parm(ctx, AMVP_CMAC_AES, AMVP_CMAC_DIRECTION_VER, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_CMAC_AES, AMVP_PREREQ_AES, cvalue);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_cmac_enable(ctx, AMVP_CMAC_TDES, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_cmac_set_domain(ctx, AMVP_CMAC_TDES, AMVP_CMAC_MSGLEN, 0, 65536, 8);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_cmac_set_parm(ctx, AMVP_CMAC_TDES, AMVP_CMAC_MACLEN, 64);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_cmac_set_parm(ctx, AMVP_CMAC_TDES, AMVP_CMAC_KEYING_OPTION, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_cmac_set_parm(ctx, AMVP_CMAC_TDES, AMVP_CMAC_DIRECTION_GEN, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_cmac_set_parm(ctx, AMVP_CMAC_TDES, AMVP_CMAC_DIRECTION_VER, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_CMAC_TDES, AMVP_PREREQ_TDES, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
}

static void add_hmac_details_good(void) {
    rv = amvp_cap_hmac_enable(ctx, AMVP_HMAC_SHA1, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_hmac_set_domain(ctx, AMVP_HMAC_SHA1, AMVP_HMAC_KEYLEN, 256, 448, 8);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_hmac_set_domain(ctx, AMVP_HMAC_SHA1, AMVP_HMAC_MACLEN, 32, 160, 8);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_HMAC_SHA1, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_hmac_enable(ctx, AMVP_HMAC_SHA2_224, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_hmac_set_domain(ctx, AMVP_HMAC_SHA2_224, AMVP_HMAC_KEYLEN, 256, 448, 8);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_hmac_set_domain(ctx, AMVP_HMAC_SHA2_224, AMVP_HMAC_MACLEN, 32, 224, 8);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_HMAC_SHA2_224, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_hmac_enable(ctx, AMVP_HMAC_SHA2_256, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_hmac_set_domain(ctx, AMVP_HMAC_SHA2_256, AMVP_HMAC_KEYLEN, 256, 448, 8);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_hmac_set_domain(ctx, AMVP_HMAC_SHA2_256, AMVP_HMAC_MACLEN, 32, 256, 8);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_HMAC_SHA2_256, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_hmac_enable(ctx, AMVP_HMAC_SHA2_384, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_hmac_set_domain(ctx, AMVP_HMAC_SHA2_384, AMVP_HMAC_KEYLEN, 256, 448, 8);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_hmac_set_domain(ctx, AMVP_HMAC_SHA2_384, AMVP_HMAC_MACLEN, 32, 384, 8);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_HMAC_SHA2_384, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_hmac_enable(ctx, AMVP_HMAC_SHA2_512, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_hmac_set_domain(ctx, AMVP_HMAC_SHA2_512, AMVP_HMAC_KEYLEN, 256, 448, 8);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_hmac_set_domain(ctx, AMVP_HMAC_SHA2_512, AMVP_HMAC_MACLEN, 32, 512, 8);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_HMAC_SHA2_512, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
}

static void add_dsa_details_good(void) {
    rv = amvp_cap_dsa_enable(ctx, AMVP_DSA_PQGGEN, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_DSA_PQGGEN, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_DSA_PQGGEN, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_GENPQ, AMVP_DSA_PROBABLE);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_GENG, AMVP_DSA_CANONICAL);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_LN2048_224, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_LN2048_224, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_LN2048_224, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_LN2048_224, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_LN2048_256, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_LN2048_256, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_LN2048_256, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_LN3072_256, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_LN3072_256, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_LN3072_256, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_dsa_enable(ctx, AMVP_DSA_PQGVER, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_DSA_PQGVER, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_DSA_PQGVER, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_GENPQ, AMVP_DSA_PROBABLE);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_GENG, AMVP_DSA_CANONICAL);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN2048_224, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN2048_224, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN2048_224, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN2048_224, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN2048_256, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN2048_256, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN2048_256, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN3072_256, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN3072_256, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_LN3072_256, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);

    
    rv = amvp_cap_dsa_enable(ctx, AMVP_DSA_KEYGEN, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_DSA_KEYGEN, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_DSA_KEYGEN, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_KEYGEN, AMVP_DSA_MODE_KEYGEN, AMVP_DSA_LN2048_224, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_KEYGEN, AMVP_DSA_MODE_KEYGEN, AMVP_DSA_LN2048_224, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_KEYGEN, AMVP_DSA_MODE_KEYGEN, AMVP_DSA_LN2048_224, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_KEYGEN, AMVP_DSA_MODE_KEYGEN, AMVP_DSA_LN2048_224, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_KEYGEN, AMVP_DSA_MODE_KEYGEN, AMVP_DSA_LN2048_256, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_KEYGEN, AMVP_DSA_MODE_KEYGEN, AMVP_DSA_LN2048_256, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_KEYGEN, AMVP_DSA_MODE_KEYGEN, AMVP_DSA_LN2048_256, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_KEYGEN, AMVP_DSA_MODE_KEYGEN, AMVP_DSA_LN2048_256, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_KEYGEN, AMVP_DSA_MODE_KEYGEN, AMVP_DSA_LN3072_256, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_KEYGEN, AMVP_DSA_MODE_KEYGEN, AMVP_DSA_LN3072_256, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_KEYGEN, AMVP_DSA_MODE_KEYGEN, AMVP_DSA_LN3072_256, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_KEYGEN, AMVP_DSA_MODE_KEYGEN, AMVP_DSA_LN3072_256, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);

    
    rv = amvp_cap_dsa_enable(ctx, AMVP_DSA_SIGGEN, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_DSA_SIGGEN, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_DSA_SIGGEN, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN2048_224, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN2048_224, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN2048_224, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN2048_224, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN2048_256, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN2048_256, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN2048_256, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN2048_256, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN3072_256, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN3072_256, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN3072_256, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGGEN, AMVP_DSA_MODE_SIGGEN, AMVP_DSA_LN3072_256, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);

    
    rv = amvp_cap_dsa_enable(ctx, AMVP_DSA_SIGVER, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_DSA_SIGVER, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_DSA_SIGVER, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_224, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_224, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_224, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_224, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_256, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_256, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_256, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN2048_256, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN3072_256, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN3072_256, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN3072_256, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_SIGVER, AMVP_DSA_MODE_SIGVER, AMVP_DSA_LN3072_256, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);
}

static void add_rsa_details_good(void) {
    char *expo_str = calloc(7, sizeof(char));
    strncpy(expo_str, "010001", 7);

    rv = amvp_cap_rsa_keygen_enable(ctx, AMVP_RSA_KEYGEN, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_RSA_KEYGEN, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_RSA_KEYGEN, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_keygen_set_parm(ctx, AMVP_RSA_PARM_PUB_EXP_MODE, AMVP_RSA_PUB_EXP_MODE_FIXED);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_keygen_set_parm(ctx, AMVP_RSA_PARM_INFO_GEN_BY_SERVER, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_keygen_set_parm(ctx, AMVP_RSA_PARM_KEY_FORMAT_CRT, 0);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_rsa_keygen_set_exponent(ctx, AMVP_RSA_PARM_FIXED_PUB_EXP_VAL, expo_str);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_rsa_keygen_set_mode(ctx, AMVP_RSA_KEYGEN_B34);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_keygen_set_primes(ctx, AMVP_RSA_KEYGEN_B34, 2048, AMVP_RSA_PRIME_HASH_ALG, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    // TODO: leaving this in here as a workaround until the server allows it as optional
    rv = amvp_cap_rsa_keygen_set_primes(ctx, AMVP_RSA_KEYGEN_B34, 2048, AMVP_RSA_PRIME_TEST, AMVP_RSA_PRIME_TEST_TBLC2);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_keygen_set_primes(ctx, AMVP_RSA_KEYGEN_B34, 3072, AMVP_RSA_PRIME_HASH_ALG, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    // TODO: leaving this in here as a workaround until the server allows it as optional
    rv = amvp_cap_rsa_keygen_set_primes(ctx, AMVP_RSA_KEYGEN_B34, 3072, AMVP_RSA_PRIME_TEST, AMVP_RSA_PRIME_TEST_TBLC2);
    cr_assert(rv == AMVP_SUCCESS);

    /*
     * Enable siggen
     */
    rv = amvp_cap_rsa_sig_enable(ctx, AMVP_RSA_SIGGEN, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);

    // RSA w/ sigType: X9.31
    rv = amvp_cap_rsa_siggen_set_type(ctx, AMVP_RSA_SIG_TYPE_X931);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 2048, AMVP_SHA256, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 2048, AMVP_SHA384, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 2048, AMVP_SHA512, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 3072, AMVP_SHA256, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 3072, AMVP_SHA384, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 3072, AMVP_SHA512, 0);
    cr_assert(rv == AMVP_SUCCESS);

    // RSA w/ sigType: PKCS1v1.5
    rv = amvp_cap_rsa_siggen_set_type(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 2048, AMVP_SHA1, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 2048, AMVP_SHA224, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 2048, AMVP_SHA256, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 2048, AMVP_SHA384, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 2048, AMVP_SHA512, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 3072, AMVP_SHA1, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 3072, AMVP_SHA224, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 3072, AMVP_SHA256, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 3072, AMVP_SHA384, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 3072, AMVP_SHA512, 0);
    cr_assert(rv == AMVP_SUCCESS);

    // RSA w/ sigType: PKCS1PSS -- has salt
    rv = amvp_cap_rsa_siggen_set_type(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 2048, AMVP_SHA1, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 2048, AMVP_SHA224, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 2048, AMVP_SHA256, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 2048, AMVP_SHA384, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 2048, AMVP_SHA512, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 3072, AMVP_SHA1, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 3072, AMVP_SHA224, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 3072, AMVP_SHA256, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 3072, AMVP_SHA384, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_siggen_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 3072, AMVP_SHA512, 0);
    cr_assert(rv == AMVP_SUCCESS);

    /*
     * Enable sigver
     */
    rv = amvp_cap_rsa_sig_enable(ctx, AMVP_RSA_SIGVER, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_rsa_sigver_set_parm(ctx, AMVP_RSA_PARM_PUB_EXP_MODE, AMVP_RSA_PUB_EXP_MODE_FIXED);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_sigver_set_exponent(ctx, AMVP_RSA_PARM_FIXED_PUB_EXP_VAL, expo_str);
    cr_assert(rv == AMVP_SUCCESS);

    // RSA w/ sigType: X9.31
    rv = amvp_cap_rsa_sigver_set_type(ctx, AMVP_RSA_SIG_TYPE_X931);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 2048, AMVP_SHA1, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 2048, AMVP_SHA256, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 2048, AMVP_SHA384, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 2048, AMVP_SHA512, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 3072, AMVP_SHA1, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 3072, AMVP_SHA256, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 3072, AMVP_SHA384, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_X931, 3072, AMVP_SHA512, 0);
    cr_assert(rv == AMVP_SUCCESS);

    // RSA w/ sigType: PKCS1v1.5
    rv = amvp_cap_rsa_sigver_set_type(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 2048, AMVP_SHA1, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 2048, AMVP_SHA224, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 2048, AMVP_SHA256, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 2048, AMVP_SHA384, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 2048, AMVP_SHA512, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 3072, AMVP_SHA1, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 3072, AMVP_SHA224, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 3072, AMVP_SHA256, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 3072, AMVP_SHA384, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1V15, 3072, AMVP_SHA512, 0);
    cr_assert(rv == AMVP_SUCCESS);

    // RSA w/ sigType: PKCS1PSS -- has salt
    rv = amvp_cap_rsa_sigver_set_type(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 2048, AMVP_SHA1, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 2048, AMVP_SHA224, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 2048, AMVP_SHA256, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 2048, AMVP_SHA384, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 2048, AMVP_SHA512, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 3072, AMVP_SHA1, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 3072, AMVP_SHA224, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 3072, AMVP_SHA256, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 3072, AMVP_SHA384, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_rsa_sigver_set_mod_parm(ctx, AMVP_RSA_SIG_TYPE_PKCS1PSS, 3072, AMVP_SHA512, 0);
    cr_assert(rv == AMVP_SUCCESS);
    free(expo_str);
}

static void add_ecdsa_details_good(void) {
    rv = amvp_cap_ecdsa_enable(ctx, AMVP_ECDSA_KEYGEN, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_ECDSA_KEYGEN, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_ECDSA_KEYGEN, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P521);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K233);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K283);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K409);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K571);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B233);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B283);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B409);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B571);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYGEN, AMVP_ECDSA_SECRET_GEN, AMVP_ECDSA_SECRET_GEN_TEST_CAND);
    cr_assert(rv == AMVP_SUCCESS);

    /*
     * Enable ECDSA keyVer...
     */
    rv = amvp_cap_ecdsa_enable(ctx, AMVP_ECDSA_KEYVER, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_ECDSA_KEYVER, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_ECDSA_KEYVER, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P521);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K233);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K283);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K409);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K571);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B233);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B283);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B409);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_KEYVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B571);
    cr_assert(rv == AMVP_SUCCESS);

    
    /*
     * Enable ECDSA sigGen...
     */
    rv = amvp_cap_ecdsa_enable(ctx, AMVP_ECDSA_SIGGEN, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_ECDSA_SIGGEN, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_ECDSA_SIGGEN, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P521);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K233);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K283);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K409);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K571);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B233);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B283);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B409);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B571);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_curve_hash_alg(ctx, AMVP_ECDSA_SIGGEN, AMVP_EC_CURVE_P224, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_curve_hash_alg(ctx, AMVP_ECDSA_SIGGEN, AMVP_EC_CURVE_P256, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_curve_hash_alg(ctx, AMVP_ECDSA_SIGGEN, AMVP_EC_CURVE_P384, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_curve_hash_alg(ctx, AMVP_ECDSA_SIGGEN, AMVP_EC_CURVE_P521, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_curve_hash_alg(ctx, AMVP_ECDSA_SIGGEN, AMVP_EC_CURVE_K233, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_curve_hash_alg(ctx, AMVP_ECDSA_SIGGEN, AMVP_EC_CURVE_K283, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_curve_hash_alg(ctx, AMVP_ECDSA_SIGGEN, AMVP_EC_CURVE_K409, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_curve_hash_alg(ctx, AMVP_ECDSA_SIGGEN, AMVP_EC_CURVE_K571, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_curve_hash_alg(ctx, AMVP_ECDSA_SIGGEN, AMVP_EC_CURVE_B233, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_curve_hash_alg(ctx, AMVP_ECDSA_SIGGEN, AMVP_EC_CURVE_B283, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_curve_hash_alg(ctx, AMVP_ECDSA_SIGGEN, AMVP_EC_CURVE_B409, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_curve_hash_alg(ctx, AMVP_ECDSA_SIGGEN, AMVP_EC_CURVE_B571, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    //rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_HASH_ALG, AMVP_SHA224);
    //cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_HASH_ALG, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_HASH_ALG, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGGEN, AMVP_ECDSA_HASH_ALG, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);

    /*
     * Enable ECDSA sigVer...
     */
    rv = amvp_cap_ecdsa_enable(ctx, AMVP_ECDSA_SIGVER, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_ECDSA_SIGVER, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_ECDSA_SIGVER, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_P521);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K233);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K283);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K409);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_K571);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B233);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B283);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B409);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_CURVE, AMVP_EC_CURVE_B571);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_curve_hash_alg(ctx, AMVP_ECDSA_SIGVER, AMVP_EC_CURVE_P224, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_curve_hash_alg(ctx, AMVP_ECDSA_SIGVER, AMVP_EC_CURVE_P256, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_curve_hash_alg(ctx, AMVP_ECDSA_SIGVER, AMVP_EC_CURVE_P384, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_curve_hash_alg(ctx, AMVP_ECDSA_SIGVER, AMVP_EC_CURVE_P521, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_curve_hash_alg(ctx, AMVP_ECDSA_SIGVER, AMVP_EC_CURVE_K233, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_curve_hash_alg(ctx, AMVP_ECDSA_SIGVER, AMVP_EC_CURVE_K283, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_curve_hash_alg(ctx, AMVP_ECDSA_SIGVER, AMVP_EC_CURVE_K409, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_curve_hash_alg(ctx, AMVP_ECDSA_SIGVER, AMVP_EC_CURVE_K571, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_curve_hash_alg(ctx, AMVP_ECDSA_SIGVER, AMVP_EC_CURVE_B233, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_curve_hash_alg(ctx, AMVP_ECDSA_SIGVER, AMVP_EC_CURVE_B283, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_curve_hash_alg(ctx, AMVP_ECDSA_SIGVER, AMVP_EC_CURVE_B409, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_curve_hash_alg(ctx, AMVP_ECDSA_SIGVER, AMVP_EC_CURVE_B571, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    //rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_HASH_ALG, AMVP_SHA224);
    //cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_HASH_ALG, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_HASH_ALG, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_ecdsa_set_parm(ctx, AMVP_ECDSA_SIGVER, AMVP_ECDSA_HASH_ALG, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);
}

static void add_kdf_details_good(void) {
    int i, flags = 0;

    /*
     * Enable KDF-135
     */
    rv = amvp_cap_kdf135_snmp_enable(ctx, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_SNMP, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_snmp_set_parm(ctx, AMVP_KDF135_SNMP, AMVP_KDF135_SNMP_PASS_LEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_snmp_set_parm(ctx, AMVP_KDF135_SNMP, AMVP_KDF135_SNMP_PASS_LEN, 64);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_snmp_set_engid(ctx, AMVP_KDF135_SNMP, "testengidtestengid");
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_kdf135_ssh_enable(ctx, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_SSH, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_SSH, AMVP_PREREQ_TDES, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_SSH, AMVP_PREREQ_AES, cvalue);
    cr_assert(rv == AMVP_SUCCESS);

    //Bit flags for kdf135_ssh sha capabilities
    flags = AMVP_SHA1 | AMVP_SHA224 |AMVP_SHA256
            | AMVP_SHA384 | AMVP_SHA512;

    rv = amvp_cap_kdf135_ssh_set_parm(ctx, AMVP_KDF135_SSH, AMVP_SSH_METH_TDES_CBC, flags);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ssh_set_parm(ctx, AMVP_KDF135_SSH, AMVP_SSH_METH_AES_128_CBC, flags);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ssh_set_parm(ctx, AMVP_KDF135_SSH, AMVP_SSH_METH_AES_192_CBC, flags);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ssh_set_parm(ctx, AMVP_KDF135_SSH, AMVP_SSH_METH_AES_256_CBC, flags);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_kdf135_srtp_enable(ctx, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_SRTP, AMVP_PREREQ_AES, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_srtp_set_parm(ctx, AMVP_KDF135_SRTP, AMVP_SRTP_SUPPORT_ZERO_KDR, 0);
    cr_assert(rv == AMVP_SUCCESS);
    for (i = 0; i < 24; i++) {
        rv = amvp_cap_kdf135_srtp_set_parm(ctx, AMVP_KDF135_SRTP, AMVP_SRTP_KDF_EXPONENT, i + 1);
        cr_assert(rv == AMVP_SUCCESS);
    }
    rv = amvp_cap_kdf135_srtp_set_parm(ctx, AMVP_KDF135_SRTP, AMVP_SRTP_AES_KEYLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_srtp_set_parm(ctx, AMVP_KDF135_SRTP, AMVP_SRTP_AES_KEYLEN, 192);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_srtp_set_parm(ctx, AMVP_KDF135_SRTP, AMVP_SRTP_AES_KEYLEN, 256);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_kdf135_ikev2_enable(ctx, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_IKEV2, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_IKEV2, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    // can use len_param or domain_param for these attributes
    rv = amvp_cap_kdf135_ikev2_set_length(ctx, AMVP_INIT_NONCE_LEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev2_set_length(ctx, AMVP_INIT_NONCE_LEN, 2048);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev2_set_length(ctx, AMVP_RESPOND_NONCE_LEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev2_set_length(ctx, AMVP_RESPOND_NONCE_LEN, 2048);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev2_set_length(ctx, AMVP_DH_SECRET_LEN, 2048);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev2_set_length(ctx, AMVP_KEY_MATERIAL_LEN, 1056);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev2_set_length(ctx, AMVP_KEY_MATERIAL_LEN, 3072);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev2_set_parm(ctx, AMVP_KDF_HASH_ALG, AMVP_SHA1);
    cr_assert(rv == AMVP_SUCCESS);

    /*
     * KDF108 Counter Mode
     */
    rv = amvp_cap_kdf108_enable(ctx, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF108, AMVP_PREREQ_HMAC, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf108_set_domain(ctx, AMVP_KDF108_MODE_COUNTER, AMVP_KDF108_SUPPORTED_LEN, 8, 384, 8);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_COUNTER, AMVP_KDF108_MAC_MODE, AMVP_KDF108_MAC_MODE_HMAC_SHA1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_COUNTER, AMVP_KDF108_MAC_MODE, AMVP_KDF108_MAC_MODE_HMAC_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_COUNTER, AMVP_KDF108_MAC_MODE, AMVP_KDF108_MAC_MODE_HMAC_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_COUNTER, AMVP_KDF108_MAC_MODE, AMVP_KDF108_MAC_MODE_HMAC_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_COUNTER, AMVP_KDF108_MAC_MODE, AMVP_KDF108_MAC_MODE_HMAC_SHA512);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_COUNTER, AMVP_KDF108_COUNTER_LEN, 8);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_COUNTER, AMVP_KDF108_FIXED_DATA_ORDER, AMVP_KDF108_FIXED_DATA_ORDER_AFTER);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_COUNTER, AMVP_KDF108_SUPPORTS_EMPTY_IV, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_COUNTER, AMVP_KDF108_REQUIRES_EMPTY_IV, 0);
    cr_assert(rv == AMVP_INVALID_ARG);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_COUNTER, AMVP_KDF108_SUPPORTS_EMPTY_IV, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_COUNTER, AMVP_KDF108_REQUIRES_EMPTY_IV, 1);
    cr_assert(rv == AMVP_SUCCESS);

}

static void add_kas_ecc_details_good(void) {
    rv = amvp_cap_kas_ecc_enable(ctx, AMVP_KAS_ECC_CDH, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ecc_set_prereq(ctx, AMVP_KAS_ECC_CDH, AMVP_KAS_ECC_MODE_CDH, AMVP_PREREQ_ECDSA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_CDH, AMVP_KAS_ECC_MODE_CDH, AMVP_KAS_ECC_FUNCTION, AMVP_KAS_ECC_FUNC_PARTIAL);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_CDH, AMVP_KAS_ECC_MODE_CDH, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_P224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_CDH, AMVP_KAS_ECC_MODE_CDH, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_P256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_CDH, AMVP_KAS_ECC_MODE_CDH, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_P384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_CDH, AMVP_KAS_ECC_MODE_CDH, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_P521);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_CDH, AMVP_KAS_ECC_MODE_CDH, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_K233);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_CDH, AMVP_KAS_ECC_MODE_CDH, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_K283);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_CDH, AMVP_KAS_ECC_MODE_CDH, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_K409);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_CDH, AMVP_KAS_ECC_MODE_CDH, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_K571);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_CDH, AMVP_KAS_ECC_MODE_CDH, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_B233);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_CDH, AMVP_KAS_ECC_MODE_CDH, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_B283);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_CDH, AMVP_KAS_ECC_MODE_CDH, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_B409);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_CDH, AMVP_KAS_ECC_MODE_CDH, AMVP_KAS_ECC_CURVE, AMVP_EC_CURVE_B571);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_kas_ecc_enable(ctx, AMVP_KAS_ECC_COMP, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ecc_set_prereq(ctx, AMVP_KAS_ECC_COMP, AMVP_KAS_ECC_MODE_COMPONENT, AMVP_PREREQ_ECDSA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ecc_set_prereq(ctx, AMVP_KAS_ECC_COMP, AMVP_KAS_ECC_MODE_COMPONENT, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ecc_set_prereq(ctx, AMVP_KAS_ECC_COMP, AMVP_KAS_ECC_MODE_COMPONENT, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ecc_set_prereq(ctx, AMVP_KAS_ECC_COMP, AMVP_KAS_ECC_MODE_COMPONENT, AMVP_PREREQ_CCM, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ecc_set_prereq(ctx, AMVP_KAS_ECC_COMP, AMVP_KAS_ECC_MODE_COMPONENT, AMVP_PREREQ_CMAC, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ecc_set_prereq(ctx, AMVP_KAS_ECC_COMP, AMVP_KAS_ECC_MODE_COMPONENT, AMVP_PREREQ_HMAC, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ecc_set_parm(ctx, AMVP_KAS_ECC_COMP, AMVP_KAS_ECC_MODE_COMPONENT, AMVP_KAS_ECC_FUNCTION, AMVP_KAS_ECC_FUNC_PARTIAL);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ecc_set_scheme(ctx, AMVP_KAS_ECC_COMP, AMVP_KAS_ECC_MODE_COMPONENT, AMVP_KAS_ECC_EPHEMERAL_UNIFIED,  AMVP_KAS_ECC_ROLE, 0, AMVP_KAS_ECC_ROLE_INITIATOR);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ecc_set_scheme(ctx, AMVP_KAS_ECC_COMP, AMVP_KAS_ECC_MODE_COMPONENT, AMVP_KAS_ECC_EPHEMERAL_UNIFIED,  AMVP_KAS_ECC_ROLE, 0, AMVP_KAS_ECC_ROLE_RESPONDER);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ecc_set_scheme(ctx, AMVP_KAS_ECC_COMP, AMVP_KAS_ECC_MODE_COMPONENT, AMVP_KAS_ECC_EPHEMERAL_UNIFIED,  AMVP_KAS_ECC_KDF, 0, AMVP_KAS_ECC_NOKDFNOKC);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ecc_set_scheme(ctx, AMVP_KAS_ECC_COMP, AMVP_KAS_ECC_MODE_COMPONENT, AMVP_KAS_ECC_EPHEMERAL_UNIFIED, AMVP_KAS_ECC_EB, AMVP_EC_CURVE_P224, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ecc_set_scheme(ctx, AMVP_KAS_ECC_COMP, AMVP_KAS_ECC_MODE_COMPONENT, AMVP_KAS_ECC_EPHEMERAL_UNIFIED, AMVP_KAS_ECC_EC, AMVP_EC_CURVE_P256, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ecc_set_scheme(ctx, AMVP_KAS_ECC_COMP, AMVP_KAS_ECC_MODE_COMPONENT, AMVP_KAS_ECC_EPHEMERAL_UNIFIED, AMVP_KAS_ECC_ED, AMVP_EC_CURVE_P384, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ecc_set_scheme(ctx, AMVP_KAS_ECC_COMP, AMVP_KAS_ECC_MODE_COMPONENT, AMVP_KAS_ECC_EPHEMERAL_UNIFIED, AMVP_KAS_ECC_EE, AMVP_EC_CURVE_P521, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);
}

static void add_kas_ffc_details_good(void) {
    rv = amvp_cap_kas_ffc_enable(ctx, AMVP_KAS_FFC_COMP, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ffc_set_prereq(ctx, AMVP_KAS_FFC_COMP, AMVP_KAS_FFC_MODE_COMPONENT, AMVP_PREREQ_DSA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ffc_set_prereq(ctx, AMVP_KAS_FFC_COMP, AMVP_KAS_FFC_MODE_COMPONENT, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ffc_set_prereq(ctx, AMVP_KAS_FFC_COMP, AMVP_KAS_FFC_MODE_COMPONENT, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ffc_set_prereq(ctx, AMVP_KAS_FFC_COMP, AMVP_KAS_FFC_MODE_COMPONENT, AMVP_PREREQ_CCM, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ffc_set_prereq(ctx, AMVP_KAS_FFC_COMP, AMVP_KAS_FFC_MODE_COMPONENT, AMVP_PREREQ_CMAC, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ffc_set_prereq(ctx, AMVP_KAS_FFC_COMP, AMVP_KAS_FFC_MODE_COMPONENT, AMVP_PREREQ_HMAC, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ffc_set_parm(ctx, AMVP_KAS_FFC_COMP, AMVP_KAS_FFC_MODE_COMPONENT, AMVP_KAS_FFC_FUNCTION, AMVP_KAS_FFC_FUNC_DPGEN);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ffc_set_parm(ctx, AMVP_KAS_FFC_COMP, AMVP_KAS_FFC_MODE_COMPONENT, AMVP_KAS_FFC_FUNCTION, AMVP_KAS_FFC_FUNC_DPVAL);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ffc_set_scheme(ctx, AMVP_KAS_FFC_COMP, AMVP_KAS_FFC_MODE_COMPONENT, AMVP_KAS_FFC_DH_EPHEMERAL,  AMVP_KAS_FFC_ROLE, AMVP_KAS_FFC_ROLE_INITIATOR);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ffc_set_scheme(ctx, AMVP_KAS_FFC_COMP, AMVP_KAS_FFC_MODE_COMPONENT, AMVP_KAS_FFC_DH_EPHEMERAL,  AMVP_KAS_FFC_ROLE, AMVP_KAS_FFC_ROLE_RESPONDER);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ffc_set_scheme(ctx, AMVP_KAS_FFC_COMP, AMVP_KAS_FFC_MODE_COMPONENT, AMVP_KAS_FFC_DH_EPHEMERAL,  AMVP_KAS_FFC_KDF, AMVP_KAS_FFC_NOKDFNOKC);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ffc_set_scheme(ctx, AMVP_KAS_FFC_COMP, AMVP_KAS_FFC_MODE_COMPONENT, AMVP_KAS_FFC_DH_EPHEMERAL, AMVP_KAS_FFC_FB, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ffc_set_scheme(ctx, AMVP_KAS_FFC_COMP, AMVP_KAS_FFC_MODE_COMPONENT, AMVP_KAS_FFC_DH_EPHEMERAL, AMVP_KAS_FFC_FC, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kas_ffc_set_scheme(ctx, AMVP_KAS_FFC_COMP, AMVP_KAS_FFC_MODE_COMPONENT, AMVP_KAS_FFC_DH_EPHEMERAL, AMVP_KAS_FFC_FB, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
}

static void teardown(void) {
    if (ctx) {
        ctx->registration = NULL; /* This will always point to one of the below values, free it below */
        teardown_ctx(&ctx);
        ctx = NULL;
    }

    if (reg) {
        free(reg);
        reg = NULL;
    }

    if (known_good_value) {
        json_value_free(known_good_value);
        known_good_value = NULL;
    }
    if (generated_value) {
        json_value_free(generated_value);
        generated_value = NULL;
    }
    if (reg_value) {
        json_value_free(reg_value);
        reg_value = NULL;
    }

    generated_obj = NULL;
    known_good_obj = NULL;

}


#if 0
/*
 * The ctx is null, expecting failure.
 */
Test(BUILD_VENDORS, null_ctx) {
    rv = amvp_build_vendors(NULL, &reg);
    cr_assert(rv == AMVP_NO_CTX);
}

/*
 * The ctx is null, expecting failure.
 */
Test(BUILD_MODULES, null_ctx) {
    rv = amvp_build_modules(NULL, &reg);
    cr_assert(rv == AMVP_NO_CTX);
}

/*
 * The ctx is null, expecting failure.
 */
Test(BUILD_DEPS, null_dep) {
    rv = amvp_build_dependency(NULL, &reg);
    cr_assert(rv == AMVP_MISSING_ARG);
}

/*
 * The ctx is null, expecting failure.
 */
Test(BUILD_OES, null_ctx) {
    rv = amvp_build_oes(NULL, &reg);
    cr_assert(rv == AMVP_NO_CTX);
}

/*
 * This makes sure that the output of a good registration matches
 * the correct json structure
 */
Test(BUILD_VENDORS, good_vendors_output, .init = setup_empty_with_vendor_and_module_info, .fini = teardown) {
    rv = amvp_build_vendors(ctx, &reg);
    cr_assert(rv == AMVP_SUCCESS);

    generated_value = json_parse_string(reg);
    generated_obj = ut_get_obj_from_rsp(generated_value);
    if (!generated_obj) {
        AMVP_LOG_ERR("JSON obj parse error (gen)");
        return;
    }
    known_good_value = json_parse_file("json/registration_setup/vendors.json");
    known_good_obj = ut_get_obj_from_rsp(known_good_value);
    if (!known_good_obj) {
        AMVP_LOG_ERR("JSON obj parse error (known)");
        return;
    }

    cr_assert(json_value_equals((JSON_Value *)known_good_obj, (JSON_Value *)generated_obj) == JSONSuccess);
}

/*
 * This makes sure that the output of a good registration matches
 * the correct json structure
 */
Test(BUILD_MODULES, good_modules_output, .init = setup_empty_with_vendor_and_module_info, .fini = teardown) {
    rv = amvp_build_modules(ctx, &reg);
    cr_assert(rv == AMVP_SUCCESS);

    generated_value = json_parse_string(reg);
    generated_obj = ut_get_obj_from_rsp(generated_value);
    if (!generated_obj) {
        AMVP_LOG_ERR("JSON obj parse error (gen)");
        return;
    }
    known_good_value = json_parse_file("json/registration_setup/modules.json");
    known_good_obj = ut_get_obj_from_rsp(known_good_value);
    if (!known_good_obj) {
        AMVP_LOG_ERR("JSON obj parse error (known)");
        return;
    }

    cr_assert(json_value_equals((JSON_Value *)known_good_obj, (JSON_Value *)generated_obj) == JSONSuccess);
}

/*
 * This makes sure that the output of a good registration matches
 * the correct json structure
 */
Test(BUILD_OES, good_oes_output, .init = setup_empty_with_vendor_and_module_info, .fini = teardown) {
    rv = amvp_build_oes(ctx, &reg);
    cr_assert(rv == AMVP_SUCCESS);

    generated_value = json_parse_string(reg);
    generated_obj = ut_get_obj_from_rsp(generated_value);
    if (!generated_obj) {
        AMVP_LOG_ERR("JSON obj parse error (gen)");
        return;
    }
    known_good_value = json_parse_file("json/registration_setup/oes.json");
    known_good_obj = ut_get_obj_from_rsp(known_good_value);
    if (!known_good_obj) {
        AMVP_LOG_ERR("JSON obj parse error (known)");
        return;
    }

    cr_assert(json_value_equals((JSON_Value *)known_good_obj, (JSON_Value *)generated_obj) == JSONSuccess);
}

/*
 * This makes sure that the output of a good registration matches
 * the correct json structure
 */
Test(BUILD_DEPS, good_deps_output, .init = setup_empty_with_vendor_and_module_info, .fini = teardown) {
    rv = amvp_build_dependency(ctx->dependency_list, &reg);
    cr_assert(rv == AMVP_SUCCESS);

    generated_value = json_parse_string(reg);
    generated_obj = ut_get_obj_from_rsp(generated_value);
    if (!generated_obj) {
        AMVP_LOG_ERR("JSON obj parse error (gen)");
        return;
    }
    known_good_value = json_parse_file("json/registration_setup/deps.json");
    known_good_obj = ut_get_obj_from_rsp(known_good_value);
    if (!known_good_obj) {
        AMVP_LOG_ERR("JSON obj parse error (known)");
        return;
    }

    cr_assert(json_value_equals((JSON_Value *) known_good_obj, (JSON_Value *) generated_obj) == JSONSuccess);
}
#endif

/*
 * The ctx is null, expecting failure.
 */
Test(BUILD_TEST_SESSION, null_ctx) {
    rv = amvp_build_registration_json(NULL, &generated_value);
    cr_assert(rv == AMVP_NO_CTX);
}

/*
 * The ctx is has no capabilities, expecting failure.
 */
Test(BUILD_TEST_SESSION, np_caps_ctx, .fini = teardown) {
    setup_empty_ctx(&ctx);
    rv = amvp_build_registration_json(ctx, &generated_value);
    cr_assert(rv == AMVP_NO_CAP);
}

/*
 * This makes sure that the output of a good registration matches
 * the correct json structure
 */
Test(BUILD_TEST_SESSION, good_aes_output, .fini = teardown) {
    setup_empty_ctx(&ctx);
    add_aes_details_good();

    rv = amvp_build_registration_json(ctx, &reg_value);
    cr_assert(rv == AMVP_SUCCESS);
    ctx->registration = reg_value;

    rv = amvp_build_full_registration(ctx, &reg, NULL);
    cr_assert(rv == AMVP_SUCCESS);

    generated_value = json_parse_string(reg);
    generated_obj = ut_get_obj_from_rsp(generated_value);
    if (!generated_obj) {
        AMVP_LOG_ERR("JSON obj parse error (gen)");
        return;
    }
    known_good_value = json_parse_file("json/aes/aes_reg_good.json");
    known_good_obj = ut_get_obj_from_rsp(known_good_value);
    if (!known_good_obj) {
        AMVP_LOG_ERR("JSON obj parse error (known)");
        return;
    }

    cr_assert(json_value_equals((JSON_Value *)generated_obj, (JSON_Value *)known_good_obj) == JSONSuccess);
}

/*
 * The ctx has an aes registration that is missing keylen
 * (a required val)
 */
Test(BUILD_TEST_SESSION, missing_required_keylen_aes, .fini = teardown) {
    setup_empty_ctx(&ctx);
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_GCM, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);;
    rv = amvp_cap_set_prereq(ctx, AMVP_AES_GCM, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_NA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_PARM_IVGEN_SRC, AMVP_SYM_CIPH_IVGEN_SRC_INT);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_PARM_IVGEN_MODE, AMVP_SYM_CIPH_IVGEN_MODE_821);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_TAGLEN, 96);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_IVLEN, 96);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_PTLEN, 0);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_AADLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_build_registration_json(ctx, &generated_value);
    cr_assert(rv == AMVP_MISSING_ARG);
}

/*
 * The ctx has an aes registration where enable_sym_cipher_cap_parm was
 * never called
 */
Test(BUILD_TEST_SESSION, missing_required_direction_aes, .fini = teardown) {
    setup_empty_ctx(&ctx);
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_GCM, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_AES_GCM, AMVP_PREREQ_AES, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_AES_GCM, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_NA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_PARM_IVGEN_SRC, AMVP_SYM_CIPH_IVGEN_SRC_INT);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_GCM, AMVP_SYM_CIPH_PARM_IVGEN_MODE, AMVP_SYM_CIPH_IVGEN_MODE_821);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_build_registration_json(ctx, &generated_value);
    cr_assert(rv == AMVP_MISSING_ARG);
}

/*
 * The ctx has a good hash registration
 */
Test(BUILD_TEST_SESSION, good_hash, .fini = teardown) {
    setup_empty_ctx(&ctx);
    add_hash_details_good();

    rv = amvp_build_registration_json(ctx, &reg_value);
    cr_assert(rv == AMVP_SUCCESS);
    ctx->registration = reg_value;

    rv = amvp_build_full_registration(ctx, &reg, NULL);
    cr_assert(rv == AMVP_SUCCESS);

    generated_value = json_parse_string(reg);
    generated_obj = ut_get_obj_from_rsp(generated_value);
    if (!generated_obj) {
        AMVP_LOG_ERR("JSON obj parse error (gen)");
        return;
    }
    known_good_value = json_parse_file("json/hash/hash_reg_good.json");
    known_good_obj = ut_get_obj_from_rsp(known_good_value);
    if (!known_good_obj) {
        AMVP_LOG_ERR("JSON obj parse error (known)");
        return;
    }

    cr_assert(json_value_equals((JSON_Value *)generated_obj, (JSON_Value *)known_good_obj) == JSONSuccess);
}

/*
 * The ctx has a good drbg registration
 */
Test(BUILD_TEST_SESSION, good_drbg, .fini = teardown) {
    setup_empty_ctx(&ctx);
    add_drbg_details_good();

    rv = amvp_build_registration_json(ctx, &reg_value);
    cr_assert(rv == AMVP_SUCCESS);
    ctx->registration = reg_value;

    rv = amvp_build_full_registration(ctx, &reg, NULL);
    cr_assert(rv == AMVP_SUCCESS);

    generated_value = json_parse_string(reg);
    generated_obj = ut_get_obj_from_rsp(generated_value);
    if (!generated_obj) {
        AMVP_LOG_ERR("JSON obj parse error (gen)");
        return;
    }
    known_good_value = json_parse_file("json/drbg/drbg_reg_good.json");
    known_good_obj = ut_get_obj_from_rsp(known_good_value);
    if (!known_good_obj) {
        AMVP_LOG_ERR("JSON obj parse error (known)");
        return;
    }

    cr_assert(json_value_equals((JSON_Value *)generated_obj, (JSON_Value *)known_good_obj) == JSONSuccess);
}

/*
 * The detail capability APIs for drbg are never called
 */
Test(BUILD_TEST_SESSION, drbg_missing_cap_parms, .fini = teardown) {
    setup_empty_ctx(&ctx);
    rv = amvp_cap_drbg_enable(ctx, AMVP_HASHDRBG, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_build_registration_json(ctx, &generated_value);
    cr_assert(rv == AMVP_MISSING_ARG);
}

/*
 * This makes sure that the output of a good registration matches
 * the correct json structure
 */
Test(BUILD_TEST_SESSION, good_cmac_output, .fini = teardown) {
    setup_empty_ctx(&ctx);
    add_cmac_details_good();

    rv = amvp_build_registration_json(ctx, &reg_value);
    cr_assert(rv == AMVP_SUCCESS);
    ctx->registration = reg_value;

    rv = amvp_build_full_registration(ctx, &reg, NULL);
    cr_assert(rv == AMVP_SUCCESS);

    generated_value = json_parse_string(reg);
    generated_obj = ut_get_obj_from_rsp(generated_value);
    if (!generated_obj) {
        AMVP_LOG_ERR("JSON obj parse error (gen)");
        return;
    }
    known_good_value = json_parse_file("json/cmac/cmac_reg_good.json");
    known_good_obj = ut_get_obj_from_rsp(known_good_value);
    if (!known_good_obj) {
        AMVP_LOG_ERR("JSON obj parse error (known)");
        return;
    }

    cr_assert(json_value_equals((JSON_Value *)generated_obj, (JSON_Value *)known_good_obj) == JSONSuccess);
}

/*
 * cmac direction attribute never enabled
 */
Test(BUILD_TEST_SESSION, cmac_missing_direction, .fini = teardown) {
    setup_empty_ctx(&ctx);
    rv = amvp_cap_cmac_enable(ctx, AMVP_CMAC_AES, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_cmac_set_domain(ctx, AMVP_CMAC_AES, AMVP_CMAC_MSGLEN, 0, 65536, 8);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_cmac_set_parm(ctx, AMVP_CMAC_AES, AMVP_CMAC_MACLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_cmac_set_parm(ctx, AMVP_CMAC_AES, AMVP_CMAC_KEYLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_CMAC_AES, AMVP_PREREQ_AES, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_build_registration_json(ctx, &generated_value);
    cr_assert(rv == AMVP_MISSING_ARG);
}

/*
 * cmac direction attribute never enabled
 */
Test(BUILD_TEST_SESSION, cmac_missing_tdes_ko, .fini = teardown) {
    setup_empty_ctx(&ctx);
    rv = amvp_cap_cmac_enable(ctx, AMVP_CMAC_TDES, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_cmac_set_domain(ctx, AMVP_CMAC_TDES, AMVP_CMAC_MSGLEN, 0, 65536, 8);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_cmac_set_parm(ctx, AMVP_CMAC_TDES, AMVP_CMAC_MACLEN, 64);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_cmac_set_parm(ctx, AMVP_CMAC_TDES, AMVP_CMAC_DIRECTION_GEN, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_cmac_set_parm(ctx, AMVP_CMAC_TDES, AMVP_CMAC_DIRECTION_VER, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_CMAC_TDES, AMVP_PREREQ_TDES, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_build_registration_json(ctx, &generated_value);
    cr_assert(rv == AMVP_MISSING_ARG);
}

/*
 * The ctx has a good hmac registration
 */
Test(BUILD_TEST_SESSION, good_hmac, .fini = teardown) {
    setup_empty_ctx(&ctx);
    add_hmac_details_good();

    rv = amvp_build_registration_json(ctx, &reg_value);
    cr_assert(rv == AMVP_SUCCESS);
    ctx->registration = reg_value;

    rv = amvp_build_full_registration(ctx, &reg, NULL);
    cr_assert(rv == AMVP_SUCCESS);

    generated_value = json_parse_string(reg);
    generated_obj = ut_get_obj_from_rsp(generated_value);
    if (!generated_obj) {
        AMVP_LOG_ERR("JSON obj parse error (gen)");
        return;
    }
    known_good_value = json_parse_file("json/hmac/hmac_reg_good.json");
    known_good_obj = ut_get_obj_from_rsp(known_good_value);
    if (!known_good_obj) {
        AMVP_LOG_ERR("JSON obj parse error (known)");
        return;
    }

    cr_assert(json_value_equals((JSON_Value *)generated_obj, (JSON_Value *)known_good_obj) == JSONSuccess);
}

/*
 * The ctx has a good dsa registration
 */
Test(BUILD_TEST_SESSION, good_dsa, .fini = teardown) {
    setup_empty_ctx(&ctx);
    add_dsa_details_good();

    rv = amvp_build_registration_json(ctx, &reg_value);
    cr_assert(rv == AMVP_SUCCESS);
    ctx->registration = reg_value;

    rv = amvp_build_full_registration(ctx, &reg, NULL);
    cr_assert(rv == AMVP_SUCCESS);

    generated_value = json_parse_string(reg);
    generated_obj = ut_get_obj_from_rsp(generated_value);
    if (!generated_obj) {
        AMVP_LOG_ERR("JSON obj parse error (gen)");
        return;
    }
    known_good_value = json_parse_file("json/dsa/dsa_reg_good.json");
    known_good_obj = ut_get_obj_from_rsp(known_good_value);
    if (!known_good_obj) {
        AMVP_LOG_ERR("JSON obj parse error (known)");
        return;
    }

    cr_assert(json_value_equals((JSON_Value *)generated_obj, (JSON_Value *)known_good_obj) == JSONSuccess);
}

/*
 * dsa registration with missing args
 */
Test(BUILD_TEST_SESSION, dsa_missing_pqgen, .fini = teardown) {
    setup_empty_ctx(&ctx);
    rv = amvp_cap_dsa_enable(ctx, AMVP_DSA_PQGGEN, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_GENG, AMVP_DSA_CANONICAL);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_build_registration_json(ctx, &generated_value);
    cr_assert(rv == AMVP_MISSING_ARG);

    rv = amvp_cap_dsa_enable(ctx, AMVP_DSA_PQGVER, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_GENG, AMVP_DSA_CANONICAL);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_build_registration_json(ctx, &generated_value);
    cr_assert(rv == AMVP_MISSING_ARG);
}

/*
 * dsa registration with missing args
 */
Test(BUILD_TEST_SESSION, dsa_missing_ggen, .fini = teardown) {
    setup_empty_ctx(&ctx);
    rv = amvp_cap_dsa_enable(ctx, AMVP_DSA_PQGGEN, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_GENPQ, AMVP_DSA_PROBABLE);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_build_registration_json(ctx, &generated_value);
    cr_assert(rv == AMVP_MISSING_ARG);

    rv = amvp_cap_dsa_enable(ctx, AMVP_DSA_PQGVER, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_GENPQ, AMVP_DSA_PROBABLE);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_build_registration_json(ctx, &generated_value);
    cr_assert(rv == AMVP_MISSING_ARG);
}

/*
 * dsa registration with missing args
 */
Test(BUILD_TEST_SESSION, dsa_missing_hashalgs, .fini = teardown) {
    setup_empty_ctx(&ctx);
    rv = amvp_cap_dsa_enable(ctx, AMVP_DSA_PQGGEN, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_GENPQ, AMVP_DSA_PROBABLE);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGGEN, AMVP_DSA_MODE_PQGGEN, AMVP_DSA_GENG, AMVP_DSA_CANONICAL);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_build_registration_json(ctx, &generated_value);
    cr_assert(rv == AMVP_MISSING_ARG);

    rv = amvp_cap_dsa_enable(ctx, AMVP_DSA_PQGVER, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_GENPQ, AMVP_DSA_PROBABLE);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_dsa_set_parm(ctx, AMVP_DSA_PQGVER, AMVP_DSA_MODE_PQGVER, AMVP_DSA_GENG, AMVP_DSA_CANONICAL);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_build_registration_json(ctx, &generated_value);
    cr_assert(rv == AMVP_MISSING_ARG);

    rv = amvp_cap_dsa_enable(ctx, AMVP_DSA_KEYGEN, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_build_registration_json(ctx, &generated_value);
    cr_assert(rv == AMVP_MISSING_ARG);

    rv = amvp_cap_dsa_enable(ctx, AMVP_DSA_SIGGEN, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_build_registration_json(ctx, &generated_value);
    cr_assert(rv == AMVP_MISSING_ARG);

    rv = amvp_cap_dsa_enable(ctx, AMVP_DSA_SIGVER, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_build_registration_json(ctx, &generated_value);
    cr_assert(rv == AMVP_MISSING_ARG);
}

/*
 * This makes sure that the output of a good registration matches
 * the correct json structure
 */
Test(BUILD_TEST_SESSION, good_des_output, .fini = teardown) {
    setup_empty_ctx(&ctx);
    add_des_details_good();

    rv = amvp_build_registration_json(ctx, &reg_value);
    cr_assert(rv == AMVP_SUCCESS);
    ctx->registration = reg_value;

    rv = amvp_build_full_registration(ctx, &reg, NULL);
    cr_assert(rv == AMVP_SUCCESS);

    generated_value = json_parse_string(reg);
    generated_obj = ut_get_obj_from_rsp(generated_value);
    if (!generated_obj) {
        AMVP_LOG_ERR("JSON obj parse error (gen)");
        return;
    }

    known_good_value = json_parse_file("json/des/des_reg_good.json");
    known_good_obj = ut_get_obj_from_rsp(known_good_value);
    if (!known_good_obj) {
        AMVP_LOG_ERR("JSON obj parse error (known)");
        return;
    }

    cr_assert(json_value_equals((JSON_Value *)generated_obj, (JSON_Value *)known_good_obj) == JSONSuccess);
}

/*
 * The ctx has a good rsa registration
 */
Test(BUILD_TEST_SESSION, good_rsa, .fini = teardown) {
    setup_empty_ctx(&ctx);
    add_rsa_details_good();

    rv = amvp_build_registration_json(ctx, &reg_value);
    cr_assert(rv == AMVP_SUCCESS);
    ctx->registration = reg_value;

    rv = amvp_build_full_registration(ctx, &reg, NULL);
    cr_assert(rv == AMVP_SUCCESS);

    generated_value = json_parse_string(reg);
    generated_obj = ut_get_obj_from_rsp(generated_value);
    if (!generated_obj) {
        AMVP_LOG_ERR("JSON obj parse error (gen)");
        return;
    }
    known_good_value = json_parse_file("json/rsa/rsa_reg_good.json");
    known_good_obj = ut_get_obj_from_rsp(known_good_value);
    if (!known_good_obj) {
        AMVP_LOG_ERR("JSON obj parse error (known)");
        return;
    }

    cr_assert(json_value_equals((JSON_Value *)generated_obj, (JSON_Value *)known_good_obj) == JSONSuccess);
}

/*
 * The rsa registration never calls params API
 */
Test(BUILD_TEST_SESSION, rsa_no_params, .fini = teardown) {
    setup_empty_ctx(&ctx);

    rv = amvp_cap_rsa_keygen_enable(ctx, AMVP_RSA_KEYGEN, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_build_registration_json(ctx, &generated_value);
    cr_assert(rv == AMVP_MISSING_ARG);
}

/*
 * The ctx has a good ecdsa registration
 */
Test(BUILD_TEST_SESSION, good_ecdsa, .fini = teardown) {
    setup_empty_ctx(&ctx);
    add_ecdsa_details_good();

    rv = amvp_build_registration_json(ctx, &reg_value);
    cr_assert(rv == AMVP_SUCCESS);
    ctx->registration = reg_value;

    rv = amvp_build_full_registration(ctx, &reg, NULL);
    cr_assert(rv == AMVP_SUCCESS);

    generated_value = json_parse_string(reg);
    generated_obj = ut_get_obj_from_rsp(generated_value);
    if (!generated_obj) {
        AMVP_LOG_ERR("JSON obj parse error (gen)");
        return;
    }
    known_good_value = json_parse_file("json/ecdsa/ecdsa_reg_good.json");
    known_good_obj = ut_get_obj_from_rsp(known_good_value);
    if (!known_good_obj) {
        AMVP_LOG_ERR("JSON obj parse error (known)");
        return;
    }

    cr_assert(json_value_equals((JSON_Value *)generated_obj, (JSON_Value *)known_good_obj) == JSONSuccess);
}

/*
 * The ecdsa registration never calls params API
 */
Test(BUILD_TEST_SESSION, ecdsa_no_params, .fini = teardown) {
    setup_empty_ctx(&ctx);

    rv = amvp_cap_ecdsa_enable(ctx, AMVP_ECDSA_KEYVER, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_build_registration_json(ctx, &generated_value);
    cr_assert(rv == AMVP_MISSING_ARG);
}

/*
 * The ctx has a good kdf registration
 */
Test(BUILD_TEST_SESSION, good_kdf, .fini = teardown) {
    setup_empty_ctx(&ctx);
    add_kdf_details_good();

    rv = amvp_build_registration_json(ctx, &reg_value);
    cr_assert(rv == AMVP_SUCCESS);
    ctx->registration = reg_value;

    rv = amvp_build_full_registration(ctx, &reg, NULL);
    cr_assert(rv == AMVP_SUCCESS);

    generated_value = json_parse_string(reg);
    generated_obj = ut_get_obj_from_rsp(generated_value);
    if (!generated_obj) {
        AMVP_LOG_ERR("JSON obj parse error (gen)");
        return;
    }
    known_good_value = json_parse_file("json/kdf/kdf_reg_good.json");
    known_good_obj = ut_get_obj_from_rsp(known_good_value);
    if (!known_good_obj) {
        AMVP_LOG_ERR("JSON obj parse error (known)");
        return;
    }

    cr_assert(json_value_equals((JSON_Value *)generated_obj, (JSON_Value *)known_good_obj) == JSONSuccess);
}

/*
 * kdf enable modes not in ciscossl
 */
Test(BUILD_TEST_SESSION, kdf_more_modes, .fini = teardown) {
    setup_empty_ctx(&ctx);
    rv = amvp_cap_kdf108_enable(ctx, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_kdf108_set_domain(ctx, AMVP_KDF108_MODE_FEEDBACK, AMVP_KDF108_SUPPORTED_LEN, 8, 384, 8);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_FEEDBACK, AMVP_KDF108_MAC_MODE, AMVP_KDF108_MAC_MODE_HMAC_SHA1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_FEEDBACK, AMVP_KDF108_MAC_MODE, AMVP_KDF108_MAC_MODE_HMAC_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_FEEDBACK, AMVP_KDF108_COUNTER_LEN, 8);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_FEEDBACK, AMVP_KDF108_FIXED_DATA_ORDER, AMVP_KDF108_FIXED_DATA_ORDER_AFTER);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_FEEDBACK, AMVP_KDF108_SUPPORTS_EMPTY_IV, 0);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_kdf108_set_domain(ctx, AMVP_KDF108_MODE_DPI, AMVP_KDF108_SUPPORTED_LEN, 8, 384, 8);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_DPI, AMVP_KDF108_MAC_MODE, AMVP_KDF108_MAC_MODE_HMAC_SHA1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_DPI, AMVP_KDF108_MAC_MODE, AMVP_KDF108_MAC_MODE_HMAC_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_DPI, AMVP_KDF108_COUNTER_LEN, 8);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_DPI, AMVP_KDF108_FIXED_DATA_ORDER, AMVP_KDF108_FIXED_DATA_ORDER_AFTER);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf108_set_parm(ctx, AMVP_KDF108_MODE_DPI, AMVP_KDF108_SUPPORTS_EMPTY_IV, 0);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_kdf135_x963_enable(ctx, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_HASH_ALG, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_HASH_ALG, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_HASH_ALG, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_HASH_ALG, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_KEY_DATA_LEN, 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_FIELD_SIZE, 224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_x963_set_parm(ctx, AMVP_KDF_X963_SHARED_INFO_LEN, 256);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_kdf135_ikev1_enable(ctx, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_IKEV1, AMVP_PREREQ_SHA, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_KDF135_IKEV1, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev1_set_domain(ctx, AMVP_KDF_IKEv1_INIT_NONCE_LEN, 64, 2048, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev1_set_domain(ctx, AMVP_KDF_IKEv1_RESPOND_NONCE_LEN, 64, 2048, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev1_set_domain(ctx, AMVP_KDF_IKEv1_DH_SECRET_LEN, 224, 8192, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev1_set_domain(ctx, AMVP_KDF_IKEv1_PSK_LEN, 8, 8192, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev1_set_parm(ctx, AMVP_KDF_IKEv1_HASH_ALG, AMVP_SHA1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev1_set_parm(ctx, AMVP_KDF_IKEv1_HASH_ALG, AMVP_SHA384);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev1_set_parm(ctx, AMVP_KDF_IKEv1_HASH_ALG, AMVP_SHA224);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev1_set_parm(ctx, AMVP_KDF_IKEv1_HASH_ALG, AMVP_SHA256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev1_set_parm(ctx, AMVP_KDF_IKEv1_HASH_ALG, AMVP_SHA512);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev1_set_parm(ctx, AMVP_KDF_IKEv1_AUTH_METHOD, AMVP_KDF135_IKEV1_AMETH_PSK);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev1_set_parm(ctx, AMVP_KDF_IKEv1_AUTH_METHOD, AMVP_KDF135_IKEV1_AMETH_DSA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_kdf135_ikev1_set_parm(ctx, AMVP_KDF_IKEv1_AUTH_METHOD, AMVP_KDF135_IKEV1_AMETH_PKE);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_build_registration_json(ctx, &generated_value);
    cr_assert(rv == AMVP_SUCCESS);
}

/*
 * The ctx has a good kas ecc registration
 */
Test(BUILD_TEST_SESSION, good_kas_ecc, .fini = teardown) {
    setup_empty_ctx(&ctx);
    add_kas_ecc_details_good();

    rv = amvp_build_registration_json(ctx, &reg_value);
    cr_assert(rv == AMVP_SUCCESS);
    ctx->registration = reg_value;

    rv = amvp_build_full_registration(ctx, &reg, NULL);
    cr_assert(rv == AMVP_SUCCESS);

    generated_value = json_parse_string(reg);
    generated_obj = ut_get_obj_from_rsp(generated_value);
    if (!generated_obj) {
        AMVP_LOG_ERR("JSON obj parse error (gen)");
        return;
    }
    known_good_value = json_parse_file("json/kas_ecc/kas_ecc_reg_good.json");
    known_good_obj = ut_get_obj_from_rsp(known_good_value);
    if (!known_good_obj) {
        AMVP_LOG_ERR("JSON obj parse error (known)");
        return;
    }

    cr_assert(json_value_equals((JSON_Value *)generated_obj, (JSON_Value *)known_good_obj) == JSONSuccess);
}

/*
 * The kas registration never calls params API
 */
Test(BUILD_TEST_SESSION, kas_ecc_no_params, .fini = teardown) {
    setup_empty_ctx(&ctx);

    rv = amvp_cap_kas_ecc_enable(ctx, AMVP_KAS_ECC_CDH, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_build_registration_json(ctx, &generated_value);
    cr_assert(rv == AMVP_MISSING_ARG);
}

/*
 * The ctx has a good kas ffc registration
 */
Test(BUILD_TEST_SESSION, good_kas_ffc, .fini = teardown) {
    setup_empty_ctx(&ctx);
    add_kas_ffc_details_good();

    rv = amvp_build_registration_json(ctx, &reg_value);
    cr_assert(rv == AMVP_SUCCESS);
    ctx->registration = reg_value;

    rv = amvp_build_full_registration(ctx, &reg, NULL);
    cr_assert(rv == AMVP_SUCCESS);

    generated_value = json_parse_string(reg);
    generated_obj = ut_get_obj_from_rsp(generated_value);
    if (!generated_obj) {
        AMVP_LOG_ERR("JSON obj parse error (gen)");
        return;
    }
    known_good_value = json_parse_file("json/kas_ffc/kas_ffc_reg_good.json");
    known_good_obj = ut_get_obj_from_rsp(known_good_value);
    if (!known_good_obj) {
        AMVP_LOG_ERR("JSON obj parse error (known)");
        return;
    }

    cr_assert(json_value_equals((JSON_Value *)generated_obj, (JSON_Value *)known_good_obj) == JSONSuccess);
}

/*
 * The kas registration never calls params API
 */
Test(BUILD_TEST_SESSION, kas_ffc_no_params, .fini = teardown) {
    setup_empty_ctx(&ctx);

    rv = amvp_cap_kas_ffc_enable(ctx, AMVP_KAS_FFC_COMP, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_build_registration_json(ctx, &generated_value);
    cr_assert(rv == AMVP_MISSING_ARG);
}
