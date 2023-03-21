/** @file */
/*
 * Copyright (c) 2021, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libamvp/LICENSE
 */


#include "ut_common.h"
#include "amvp/amvp_lcl.h"

static AMVP_CTX *ctx = NULL;
static AMVP_RESULT rv = 0;
static JSON_Object *obj = NULL;
static JSON_Value *val = NULL;
static char cvalue[] = "same";

static void setup(void) {
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
     * Enable AES-CBC-CS1, CS2, and CS3
     */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_CBC_CS1, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS1, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS1, AMVP_SYM_CIPH_KEYLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS1, AMVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS1, AMVP_SYM_CIPH_KEYLEN, 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_domain(ctx, AMVP_AES_CBC_CS1, AMVP_SYM_CIPH_DOMAIN_PTLEN, 128, 65536, 8);
    cr_assert(rv == AMVP_SUCCESS);
    
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_CBC_CS2, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS2, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS2, AMVP_SYM_CIPH_KEYLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS2, AMVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS2, AMVP_SYM_CIPH_KEYLEN, 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_domain(ctx, AMVP_AES_CBC_CS2, AMVP_SYM_CIPH_DOMAIN_PTLEN, 128, 65536, 8);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_CBC_CS3, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS3, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS3, AMVP_SYM_CIPH_KEYLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS3, AMVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS3, AMVP_SYM_CIPH_KEYLEN, 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_domain(ctx, AMVP_AES_CBC_CS3, AMVP_SYM_CIPH_DOMAIN_PTLEN, 128, 65536, 8);
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

#ifdef OPENSSL_KWP
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_KWP, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_NA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_PARM_IVGEN_SRC, AMVP_SYM_CIPH_IVGEN_SRC_NA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_PARM_IVGEN_MODE, AMVP_SYM_CIPH_IVGEN_MODE_NA);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_enable_value(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_KW_MODE, AMVP_SYM_KW_CIPHER);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_KEYLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_KEYLEN, 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_PTLEN, 8);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_PTLEN, 32);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_PTLEN, 72);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_PTLEN, 96);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_PTLEN, 808);
    cr_assert(rv == AMVP_SUCCESS);
#endif

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

    /*
     * Enable AES-CTR 128, 192, 256 bit key
     */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_CTR, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_NA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_PARM_IVGEN_SRC, AMVP_SYM_CIPH_IVGEN_SRC_NA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_PARM_IVGEN_MODE, AMVP_SYM_CIPH_IVGEN_MODE_NA);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_PARM_CTR_INCR, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_PARM_CTR_OVRFLW, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_KEYLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_KEYLEN, 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_PTLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);

}

static void setup_fail(void) {
    setup_empty_ctx(&ctx);

    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_GCM, &dummy_handler_failure);
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
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_ECB, &dummy_handler_failure);
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
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_CBC, &dummy_handler_failure);
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
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_CFB1, &dummy_handler_failure);
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
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_CFB8, &dummy_handler_failure);
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
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_CFB128, &dummy_handler_failure);
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
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_OFB, &dummy_handler_failure);
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
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_CCM, &dummy_handler_failure);
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
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_KW, &dummy_handler_failure);
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

#ifdef OPENSSL_KWP
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_KWP, &dummy_handler_failure);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_NA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_PARM_IVGEN_SRC, AMVP_SYM_CIPH_IVGEN_SRC_NA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_PARM_IVGEN_MODE, AMVP_SYM_CIPH_IVGEN_MODE_NA);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_enable_value(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_KW_MODE, AMVP_SYM_KW_CIPHER);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_KEYLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_KEYLEN, 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_PTLEN, 8);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_PTLEN, 32);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_PTLEN, 72);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_PTLEN, 96);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_PTLEN, 808);
    cr_assert(rv == AMVP_SUCCESS);
#endif

    /*
     * Enable AES-XTS 128 and 256 bit key
     */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_XTS, &dummy_handler_failure);
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

    /*
     * Enable AES-CTR 128, 192, 256 bit key
     */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_CTR, &dummy_handler_failure);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_NA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_PARM_IVGEN_SRC, AMVP_SYM_CIPH_IVGEN_SRC_NA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_PARM_IVGEN_MODE, AMVP_SYM_CIPH_IVGEN_MODE_NA);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_PARM_CTR_INCR, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_PARM_CTR_OVRFLW, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_KEYLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_KEYLEN, 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_PTLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_XPN, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_AES_XPN, AMVP_PREREQ_AES, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_AES_XPN, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XPN, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XPN, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_NA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XPN, AMVP_SYM_CIPH_PARM_IVGEN_SRC, AMVP_SYM_CIPH_IVGEN_SRC_INT);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XPN, AMVP_SYM_CIPH_PARM_IVGEN_MODE, AMVP_SYM_CIPH_IVGEN_MODE_821);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XPN, AMVP_SYM_CIPH_PARM_SALT_SRC, AMVP_SYM_CIPH_SALT_SRC_EXT);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XPN, AMVP_SYM_CIPH_KEYLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XPN, AMVP_SYM_CIPH_KEYLEN, 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XPN, AMVP_SYM_CIPH_TAGLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_domain(ctx, AMVP_AES_XPN, AMVP_SYM_CIPH_DOMAIN_PTLEN, 0, 65536, 8);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_domain(ctx, AMVP_AES_XPN, AMVP_SYM_CIPH_DOMAIN_AADLEN, 0, 65536, 8);
    cr_assert(rv == AMVP_SUCCESS);

}

static void teardown(void) {
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test capabilites API.
 */
Test(AES_CAPABILITY, good) {
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
     * Enable AES-CBC-CS1, CS2, and CS3
     */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_CBC_CS1, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS1, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS1, AMVP_SYM_CIPH_KEYLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS1, AMVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS1, AMVP_SYM_CIPH_KEYLEN, 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_domain(ctx, AMVP_AES_CBC_CS1, AMVP_SYM_CIPH_DOMAIN_PTLEN, 128, 65536, 8);
    cr_assert(rv == AMVP_SUCCESS);
    
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_CBC_CS2, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS2, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS2, AMVP_SYM_CIPH_KEYLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS2, AMVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS2, AMVP_SYM_CIPH_KEYLEN, 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_domain(ctx, AMVP_AES_CBC_CS2, AMVP_SYM_CIPH_DOMAIN_PTLEN, 128, 65536, 8);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_CBC_CS3, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS3, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS3, AMVP_SYM_CIPH_KEYLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS3, AMVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CBC_CS3, AMVP_SYM_CIPH_KEYLEN, 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_domain(ctx, AMVP_AES_CBC_CS3, AMVP_SYM_CIPH_DOMAIN_PTLEN, 128, 65536, 8);
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

#ifdef OPENSSL_KWP
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_KWP, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_NA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_PARM_IVGEN_SRC, AMVP_SYM_CIPH_IVGEN_SRC_NA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_PARM_IVGEN_MODE, AMVP_SYM_CIPH_IVGEN_MODE_NA);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_enable_value(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_KW_MODE, AMVP_SYM_KW_CIPHER);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_KEYLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_KEYLEN, 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_PTLEN, 8);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_PTLEN, 32);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_PTLEN, 72);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_PTLEN, 96);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_KWP, AMVP_SYM_CIPH_PTLEN, 808);
    cr_assert(rv == AMVP_SUCCESS);
#endif

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

    /*
     * Enable AES-CTR 128, 192, 256 bit key
     */
    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_CTR, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_NA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_PARM_IVGEN_SRC, AMVP_SYM_CIPH_IVGEN_SRC_NA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_PARM_IVGEN_MODE, AMVP_SYM_CIPH_IVGEN_MODE_NA);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_PARM_CTR_INCR, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_PARM_CTR_OVRFLW, 1);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_KEYLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_KEYLEN, 192);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_KEYLEN, 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_CTR, AMVP_SYM_CIPH_PTLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_enable(ctx, AMVP_AES_XPN, &dummy_handler_success);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_AES_XPN, AMVP_PREREQ_AES, cvalue);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_set_prereq(ctx, AMVP_AES_XPN, AMVP_PREREQ_DRBG, cvalue);
    cr_assert(rv == AMVP_SUCCESS);

    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XPN, AMVP_SYM_CIPH_PARM_DIR, AMVP_SYM_CIPH_DIR_BOTH);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XPN, AMVP_SYM_CIPH_PARM_KO, AMVP_SYM_CIPH_KO_NA);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XPN, AMVP_SYM_CIPH_PARM_IVGEN_SRC, AMVP_SYM_CIPH_IVGEN_SRC_INT);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XPN, AMVP_SYM_CIPH_PARM_IVGEN_MODE, AMVP_SYM_CIPH_IVGEN_MODE_821);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XPN, AMVP_SYM_CIPH_PARM_SALT_SRC, AMVP_SYM_CIPH_SALT_SRC_EXT);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XPN, AMVP_SYM_CIPH_KEYLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XPN, AMVP_SYM_CIPH_KEYLEN, 256);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_parm(ctx, AMVP_AES_XPN, AMVP_SYM_CIPH_TAGLEN, 128);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_domain(ctx, AMVP_AES_XPN, AMVP_SYM_CIPH_DOMAIN_PTLEN, 0, 65536, 8);
    cr_assert(rv == AMVP_SUCCESS);
    rv = amvp_cap_sym_cipher_set_domain(ctx, AMVP_AES_XPN, AMVP_SYM_CIPH_DOMAIN_AADLEN, 0, 65536, 8);
    cr_assert(rv == AMVP_SUCCESS);

    teardown_ctx(&ctx);
}

/*
 * Test the KAT handler API.
 * The ctx is empty (no capabilities), expecting failure.
 */
Test(AES_API, empty_ctx) {
    setup_empty_ctx(&ctx);

    val = json_parse_file("json/aes/aes.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        goto end;
    }

    rv  = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_TC_INVALID_DATA);
    json_value_free(val);

end:
    if (ctx) teardown_ctx(&ctx);
}

/*
 * Test KAT handler API.
 * The ctx is NULL, expecting failure.
 */
Test(AES_API, null_ctx) {
    val = json_parse_file("json/aes/aes.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }

    /* Test with NULL JSON object */
    rv  = amvp_aes_kat_handler(NULL, obj);
    cr_assert(rv == AMVP_NO_CTX);
    json_value_free(val);
}


/*
 * Test the KAT handler API.
 * The obj is null, expecting failure.
 */
Test(AES_API, null_json_obj, .init = setup, .fini = teardown) {
    rv  = amvp_aes_kat_handler(ctx, NULL);
    cr_assert(rv == AMVP_JSON_ERR);
}

/*
 * This is a good JSON.
 * Expecting success.
 */
Test(AES_HANDLER, good, .init = setup, .fini = teardown) {
    val = json_parse_file("json/aes/aes.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_SUCCESS);
    json_value_free(val);
}


/*
 * The value for key:"algorithm" is wrong.
 */
Test(AES_HANDLER, wrong_algorithm, .init = setup, .fini = teardown) {
    val = json_parse_file("json/aes/aes_1.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_TC_INVALID_DATA);
    json_value_free(val);
}


/*
 * The key:"direction" is missing.
 */
Test(AES_HANDLER, missing_direction, .init = setup, .fini = teardown) {
    val = json_parse_file("json/aes/aes_2.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_TC_MISSING_DATA);
    json_value_free(val);
}


/*
 * The value for key:"direction" is wrong.
 */
Test(AES_HANDLER, wrong_direction, .init = setup, .fini = teardown) {
    val = json_parse_file("json/aes/aes_3.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_TC_INVALID_DATA);
    json_value_free(val);
}


/*
 * The key:"testType" is missing.
 */
Test(AES_HANDLER, missing_testType, .init = setup, .fini = teardown) {
    val = json_parse_file("json/aes/aes_4.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_TC_MISSING_DATA);
    json_value_free(val);
}


/*
 * The value for key:"testType" is wrong.
 */
Test(AES_HANDLER, wrong_testType, .init = setup, .fini = teardown) {
    val = json_parse_file("json/aes/aes_5.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_TC_INVALID_DATA);
    json_value_free(val);
}


/*
 * The key:"keyLen" is missing.
 */
Test(AES_HANDLER, missing_keyLen, .init = setup, .fini = teardown) {
    val = json_parse_file("json/aes/aes_6.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_TC_INVALID_DATA);
    json_value_free(val);
}


/*
 * The value for key:"keyLen" is wrong.
 */
Test(AES_HANDLER, wrong_keyLen, .init = setup, .fini = teardown) {
    val = json_parse_file("json/aes/aes_7.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_TC_INVALID_DATA);
    json_value_free(val);
}


/*
 * The value for key:"ptLen" is too big.
 */
Test(AES_HANDLER, big_ptLen, .init = setup, .fini = teardown) {
    val = json_parse_file("json/aes/aes_8.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_TC_INVALID_DATA);
    json_value_free(val);
}


/*
 * The key:"ivLen" is missing.
 */
Test(AES_HANDLER, missing_ivLen, .init = setup, .fini = teardown) {
    val = json_parse_file("json/aes/aes_9.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_TC_MISSING_DATA);
    json_value_free(val);
}


/*
 * The value for key:"ivLen" is too small (GCM).
 */
Test(AES_HANDLER, small_ivLen_gcm, .init = setup, .fini = teardown) {
    val = json_parse_file("json/aes/aes_10.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_TC_INVALID_DATA);
    json_value_free(val);
}


/*
 * The value for key:"ivLen" is too big (GCM).
 */
Test(AES_HANDLER, big_ivLen_gcm, .init = setup, .fini = teardown) {
    val = json_parse_file("json/aes/aes_11.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_TC_INVALID_DATA);
    json_value_free(val);
}


/*
 * The value for key:"ivLen" is too small (CCM).
 */
Test(AES_HANDLER, small_ivLen_ccm, .init = setup, .fini = teardown) {
    val = json_parse_file("json/aes/aes_12.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_TC_INVALID_DATA);
    json_value_free(val);
}


/*
 * The value for key:"ivLen" is too big (CCM).
 */
Test(AES_HANDLER, big_ivLen_ccm, .init = setup, .fini = teardown) {
    val = json_parse_file("json/aes/aes_13.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_TC_INVALID_DATA);
    json_value_free(val);
}


/*
 * The value for key:"ivLen" is not an increment of 8 (CCM)
 */
Test(AES_HANDLER, wrong_ivLen_ccm, .init = setup, .fini = teardown) {
    val = json_parse_file("json/aes/aes_14.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_TC_INVALID_DATA);
    json_value_free(val);
}


/*
 * The value for key:"tagLen" is too small.
 */
Test(AES_HANDLER, small_tagLen, .init = setup, .fini = teardown) {
    val = json_parse_file("json/aes/aes_15.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_TC_INVALID_DATA);
    json_value_free(val);
}


/*
 * The value for key:"tagLen" is too big.
 */
Test(AES_HANDLER, big_tagLen, .init = setup, .fini = teardown) {
    val = json_parse_file("json/aes/aes_16.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_TC_INVALID_DATA);
    json_value_free(val);
}


/*
 * The value for key:"aadLen" is too big.
 */
Test(AES_HANDLER, big_aadLen, .init = setup, .fini = teardown) {
    val = json_parse_file("json/aes/aes_17.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_TC_INVALID_DATA);
    json_value_free(val);
}


/*
 * The key:"key" is missing.
 */
Test(AES_HANDLER, missing_key, .init = setup, .fini = teardown) {
    val = json_parse_file("json/aes/aes_18.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_TC_MISSING_DATA);
    json_value_free(val);
}


/*
 * The value for key:"key" string is too long.
 */
Test(AES_HANDLER, long_key, .init = setup, .fini = teardown) {
    val = json_parse_file("json/aes/aes_19.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_TC_INVALID_DATA);
    json_value_free(val);
}


/*
 * The key:"pt" is missing.
 */
Test(AES_HANDLER, missing_pt, .init = setup, .fini = teardown) {
    val = json_parse_file("json/aes/aes_20.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_TC_MISSING_DATA);
    json_value_free(val);
}


/*
 * The value for key:"pt" string is too long.
 */
Test(AES_HANDLER, long_pt, .init = setup, .fini = teardown) {
    val = json_parse_file("json/aes/aes_21.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_TC_INVALID_DATA);
    json_value_free(val);
}


/*
 * The key:"ct" is missing.
 */
Test(AES_HANDLER, missing_ct, .init = setup, .fini = teardown) {
    val = json_parse_file("json/aes/aes_22.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_TC_MISSING_DATA);
    json_value_free(val);
}


/*
 * The value for key:"ct" string is too long.
 */
Test(AES_HANDLER, long_ct, .init = setup, .fini = teardown) {
    val = json_parse_file("json/aes/aes_23.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_TC_INVALID_DATA);
    json_value_free(val);
}


/*
 * The key:"tag" is missing.
 */
Test(AES_HANDLER, missing_tag, .init = setup, .fini = teardown) {
    val = json_parse_file("json/aes/aes_24.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_TC_MISSING_DATA);
    json_value_free(val);
}


/*
 * The value for key:"tag" string is too long.
 */
Test(AES_HANDLER, long_tag, .init = setup, .fini = teardown) {
    val = json_parse_file("json/aes/aes_25.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_TC_INVALID_DATA);
    json_value_free(val);
}


/*
 * The key:"iv" is missing.
 */
Test(AES_HANDLER, missing_iv, .init = setup, .fini = teardown) {
    val = json_parse_file("json/aes/aes_26.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_TC_MISSING_DATA);
    json_value_free(val);
}


/*
 * The value for key:"iv" string is too long.
 */
Test(AES_HANDLER, long_iv, .init = setup, .fini = teardown) {
    val = json_parse_file("json/aes/aes_27.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_TC_INVALID_DATA);
    json_value_free(val);
}


/*
 * The key:"aad" is missing.
 */
Test(AES_HANDLER, missing_aad, .init = setup, .fini = teardown) {
    val = json_parse_file("json/aes/aes_28.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_TC_MISSING_DATA);
    json_value_free(val);
}


/*
 * The value for key:"aad" string is too long.
 */
Test(AES_HANDLER, long_aad, .init = setup, .fini = teardown) {
    val = json_parse_file("json/aes/aes_29.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_TC_INVALID_DATA);
    json_value_free(val);
}


/*
 * The value for key:"tgId" is missing
 */
Test(AES_HANDLER, missing_gid, .init = setup, .fini = teardown) {
    val = json_parse_file("json/aes/aes_30.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_TC_MISSING_DATA);
    json_value_free(val);
}


/*
 * The boolean for "incrementalCounter" is missing/not a boolean
 */
Test(AES_HANDLER, bad_inc_ctr, .init = setup, .fini = teardown) {
    val = json_parse_file("json/aes/aes_31.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_TC_INVALID_DATA);
    json_value_free(val);
}


/*
 * The boolean for "overflowCounter" is missing/not a boolean
 */
Test(AES_HANDLER, bad_ovrflw_ctr, .init = setup, .fini = teardown) {
    val = json_parse_file("json/aes/aes_32.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_TC_INVALID_DATA);
    json_value_free(val);
}


/*
 * Missing tg info in last tg
 */
Test(AES_HANDLER, tgLast, .init = setup, .fini = teardown) {
    val = json_parse_file("json/aes/aes_33.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_TC_MISSING_DATA);
    json_value_free(val);
}


/*
 * Missing field in last tc
 */
Test(AES_HANDLER, tcLast, .init = setup, .fini = teardown) {
    val = json_parse_file("json/aes/aes_34.json");
    
    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    rv  = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_TC_MISSING_DATA);
    json_value_free(val);
}


/*
 * This is a good JSON.
 * Will fail as defined by the counter values.
 */
Test(AES_HANDLER, cryptoFail1, .init = setup_fail, .fini = teardown) {
    val = json_parse_file("json/aes/aes.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 0; /* fail on first iteration of AFT */

    rv = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * This is a good JSON.
 * Will fail as defined by the counter values.
 */
Test(AES_HANDLER, cryptoFail2, .init = setup_fail, .fini = teardown) {
    val = json_parse_file("json/aes/aes.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 5;  /* fail on 6th iteration of AFT */

    rv = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * This is a good JSON.
 * Will fail as defined by the counter values.
 */
Test(AES_HANDLER, cryptoFail3, .init = setup_fail, .fini = teardown) {
    val = json_parse_file("json/aes/aes.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 2138; /* fail on first iteration of MCT */

    rv = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

/*
 * This is a good JSON.
 * Will fail as defined by the counter values.
 */
Test(AES_HANDLER, cryptoFail4, .init = setup_fail, .fini = teardown) {
    val = json_parse_file("json/aes/aes.json");

    obj = ut_get_obj_from_rsp(val);
    if (!obj) {
        AMVP_LOG_ERR("JSON obj parse error");
        return;
    }
    counter_set = 0;
    counter_fail = 2144; /* fail on sixth iteration of MCT */

    rv = amvp_aes_kat_handler(ctx, obj);
    cr_assert(rv == AMVP_CRYPTO_MODULE_FAIL);
    json_value_free(val);
}

