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

static AMVP_RESULT validate_domain_range(int min, int max, int inc) {
    if (min > max || min < 0 || max < 0 || inc < 0 || (max - min) % inc != 0) {
        return AMVP_INVALID_ARG;
    }
    return AMVP_SUCCESS;
}

static AMVP_DSA_CAP *allocate_dsa_cap(void) {
    AMVP_DSA_CAP *cap = NULL;
    AMVP_DSA_CAP_MODE *modes = NULL;
    int i = 0;

    // Allocate the capability object
    cap = calloc(1, sizeof(AMVP_DSA_CAP));
    if (!cap) return NULL;

    // Allocate the array of dsa_mode
    modes = calloc(AMVP_DSA_MAX_MODES, sizeof(AMVP_DSA_CAP_MODE));
    if (!modes) {
        free(cap);
        return NULL;
    }
    cap->dsa_cap_mode = modes;

    /*
     * Set the cap_mode types
     */
    for (i = 0; i < AMVP_DSA_MAX_MODES; i++) {
        // The AMVP_DSA_MODE enum starts at 1
        cap->dsa_cap_mode[i].cap_mode = (AMVP_DSA_MODE)(i + 1);
    }

    return cap;
}

static AMVP_KAS_ECC_CAP *allocate_kas_ecc_cap(void) {
    AMVP_KAS_ECC_CAP *cap = NULL;
    AMVP_KAS_ECC_CAP_MODE *modes = NULL;
    int i = 0;

    cap = calloc(1, sizeof(AMVP_KAS_ECC_CAP));
    if (!cap) {
        return NULL;
    }

    modes = calloc(AMVP_KAS_ECC_MAX_MODES, sizeof(AMVP_KAS_ECC_CAP_MODE));
    if (!modes) {
        free(cap);
        return NULL;
    }
    cap->kas_ecc_mode = (AMVP_KAS_ECC_CAP_MODE *)modes;

    for (i = 0; i < AMVP_KAS_ECC_MAX_MODES; i++) {
        cap->kas_ecc_mode[i].cap_mode = (AMVP_KAS_ECC_MODE)(i + 1);
    }

    return cap;
}

static AMVP_KAS_FFC_CAP *allocate_kas_ffc_cap(void) {
    AMVP_KAS_FFC_CAP *cap = NULL;
    AMVP_KAS_FFC_MODE *modes = NULL;
    int i = 0;

    cap = calloc(1, sizeof(AMVP_KAS_FFC_CAP));
    if (!cap) {
        return NULL;
    }

    modes = calloc(AMVP_KAS_FFC_MAX_MODES, sizeof(AMVP_KAS_FFC_CAP_MODE));
    if (!modes) {
        free(cap);
        return NULL;
    }

    cap->kas_ffc_mode = (AMVP_KAS_FFC_CAP_MODE *)modes;
    for (i = 0; i < AMVP_KAS_FFC_MAX_MODES; i++) {
        cap->kas_ffc_mode[i].cap_mode = (AMVP_KAS_FFC_MODE)(i + 1);
    }

    return cap;
}

static AMVP_KAS_IFC_CAP *allocate_kas_ifc_cap(void) {
    AMVP_KAS_IFC_CAP *cap = NULL;

    cap = calloc(1, sizeof(AMVP_KAS_IFC_CAP));
    if (!cap) {
        return NULL;
    }

    return cap;
}

static AMVP_KTS_IFC_CAP *allocate_kts_ifc_cap(void) {
    AMVP_KTS_IFC_CAP *cap = NULL;

    cap = calloc(1, sizeof(AMVP_KTS_IFC_CAP));
    if (!cap) {
        return NULL;
    }

    return cap;
}

static AMVP_SAFE_PRIMES_CAP *allocate_safe_primes_cap(void) {
    AMVP_SAFE_PRIMES_CAP *cap = NULL;

    cap = calloc(1, sizeof(AMVP_SAFE_PRIMES_CAP));
    if (!cap) {
        return NULL;
    }

    return cap;
}

/*!
 * @brief Create and append an AMVP_CAPS_LIST object
 *        to the current list.
 *
 * This function is designed to handle all of the
 * AMVP_CIPHER and AMVP_CAP_TYPE permutations.
 *
 * @param[in] ctx Pointer to AMVP_CTX whose cap_list will be appended to.
 * @param[in] type AMVP_CAP_TYPE enum value.
 * @param[in] cipher AMVP_CIPHER enum value.
 * @param[in] crypto_handler The function pointer for crypto module callback.
 *
 * @return AMVP_RESULT
 */
static AMVP_RESULT amvp_cap_list_append(AMVP_CTX *ctx,
                                        AMVP_CAP_TYPE type,
                                        AMVP_CIPHER cipher,
                                        int (*crypto_handler)(AMVP_TEST_CASE *test_case)) {
    AMVP_CAPS_LIST *cap_entry, *cap_e2;
    AMVP_RESULT rv = AMVP_SUCCESS;

    /*
     * Check for duplicate entry
     */
    if (amvp_locate_cap_entry(ctx, cipher)) {
        return AMVP_DUP_CIPHER;
    }

    cap_entry = calloc(1, sizeof(AMVP_CAPS_LIST));
    if (!cap_entry) {
        return AMVP_MALLOC_FAIL;
    }

    switch (type) {
    case AMVP_CMAC_TYPE:
        cap_entry->cap.cmac_cap = calloc(1, sizeof(AMVP_CMAC_CAP));
        if (!cap_entry->cap.cmac_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case AMVP_KMAC_TYPE:
        cap_entry->cap.kmac_cap = calloc(1, sizeof(AMVP_KMAC_CAP));
        if (!cap_entry->cap.kmac_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case AMVP_DRBG_TYPE:
        cap_entry->cap.drbg_cap = calloc(1, sizeof(AMVP_DRBG_CAP));
        if (!cap_entry->cap.drbg_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case AMVP_DSA_TYPE:
        cap_entry->cap.dsa_cap = allocate_dsa_cap();
        if (!cap_entry->cap.dsa_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case AMVP_ECDSA_KEYGEN_TYPE:
        if (cipher != AMVP_ECDSA_KEYGEN) {
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.ecdsa_keygen_cap = calloc(1, sizeof(AMVP_ECDSA_CAP));
        if (!cap_entry->cap.ecdsa_keygen_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case AMVP_ECDSA_KEYVER_TYPE:
        if (cipher != AMVP_ECDSA_KEYVER) {
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.ecdsa_keyver_cap = calloc(1, sizeof(AMVP_ECDSA_CAP));
        if (!cap_entry->cap.ecdsa_keyver_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case AMVP_ECDSA_SIGGEN_TYPE:
        if (cipher != AMVP_ECDSA_SIGGEN) {
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.ecdsa_siggen_cap = calloc(1, sizeof(AMVP_ECDSA_CAP));
        if (!cap_entry->cap.ecdsa_siggen_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case AMVP_ECDSA_SIGVER_TYPE:
        if (cipher != AMVP_ECDSA_SIGVER) {
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.ecdsa_sigver_cap = calloc(1, sizeof(AMVP_ECDSA_CAP));
        if (!cap_entry->cap.ecdsa_sigver_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case AMVP_HASH_TYPE:
        cap_entry->cap.hash_cap = calloc(1, sizeof(AMVP_HASH_CAP));
        if (!cap_entry->cap.hash_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case AMVP_HMAC_TYPE:
        cap_entry->cap.hmac_cap = calloc(1, sizeof(AMVP_HMAC_CAP));
        if (!cap_entry->cap.hmac_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case AMVP_KAS_ECC_CDH_TYPE:
        if (cipher != AMVP_KAS_ECC_CDH) {
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kas_ecc_cap = allocate_kas_ecc_cap();
        if (!cap_entry->cap.kas_ecc_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case AMVP_KAS_ECC_COMP_TYPE:
        if (cipher != AMVP_KAS_ECC_COMP) {
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kas_ecc_cap = allocate_kas_ecc_cap();
        if (!cap_entry->cap.kas_ecc_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case AMVP_KAS_ECC_NOCOMP_TYPE:
        if (cipher != AMVP_KAS_ECC_NOCOMP) {
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kas_ecc_cap = allocate_kas_ecc_cap();
        if (!cap_entry->cap.kas_ecc_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case AMVP_KAS_ECC_SSC_TYPE:
        if (cipher != AMVP_KAS_ECC_SSC) {
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kas_ecc_cap = allocate_kas_ecc_cap();
        if (!cap_entry->cap.kas_ecc_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case AMVP_KAS_FFC_SSC_TYPE:
        if (cipher != AMVP_KAS_FFC_SSC) {
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kas_ffc_cap = allocate_kas_ffc_cap();
        if (!cap_entry->cap.kas_ffc_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;
    case AMVP_KAS_FFC_COMP_TYPE:
        if (cipher != AMVP_KAS_FFC_COMP) {
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kas_ffc_cap = allocate_kas_ffc_cap();
        if (!cap_entry->cap.kas_ffc_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case AMVP_KAS_FFC_NOCOMP_TYPE:
        if (cipher != AMVP_KAS_FFC_NOCOMP) {
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kas_ffc_cap = allocate_kas_ffc_cap();
        if (!cap_entry->cap.kas_ffc_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case AMVP_KDA_HKDF_TYPE:
        if (cipher != AMVP_KDA_HKDF) {
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kda_hkdf_cap = calloc(1, sizeof(AMVP_KDA_HKDF_CAP));
        if (!cap_entry->cap.kda_hkdf_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case AMVP_KDA_ONESTEP_TYPE:
        if (cipher != AMVP_KDA_ONESTEP) {
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kda_onestep_cap = calloc(1, sizeof(AMVP_KDA_ONESTEP_CAP));
        if (!cap_entry->cap.kda_onestep_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case AMVP_KDA_TWOSTEP_TYPE:
        if (cipher != AMVP_KDA_TWOSTEP) {
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kda_twostep_cap = calloc(1, sizeof(AMVP_KDA_TWOSTEP_CAP));
        if (!cap_entry->cap.kda_twostep_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case AMVP_KAS_IFC_TYPE:
        if (cipher != AMVP_KAS_IFC_SSC) {
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kas_ifc_cap = allocate_kas_ifc_cap();
        if (!cap_entry->cap.kas_ifc_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case AMVP_KTS_IFC_TYPE:
        if (cipher != AMVP_KTS_IFC) {
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kts_ifc_cap = allocate_kts_ifc_cap();
        if (!cap_entry->cap.kts_ifc_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case AMVP_KDF108_TYPE:
        if (cipher != AMVP_KDF108) {
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kdf108_cap = calloc(1, sizeof(AMVP_KDF108_CAP));
        if (!cap_entry->cap.kdf108_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case AMVP_KDF135_IKEV1_TYPE:
        if (cipher != AMVP_KDF135_IKEV1) {
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kdf135_ikev1_cap = calloc(1, sizeof(AMVP_KDF135_IKEV1_CAP));
        if (!cap_entry->cap.kdf135_ikev1_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case AMVP_KDF135_IKEV2_TYPE:
        if (cipher != AMVP_KDF135_IKEV2) {
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kdf135_ikev2_cap = calloc(1, sizeof(AMVP_KDF135_IKEV2_CAP));
        if (!cap_entry->cap.kdf135_ikev2_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case AMVP_KDF135_SNMP_TYPE:
        if (cipher != AMVP_KDF135_SNMP) {
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kdf135_snmp_cap = calloc(1, sizeof(AMVP_KDF135_SNMP_CAP));
        if (!cap_entry->cap.kdf135_snmp_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case AMVP_KDF135_SRTP_TYPE:
        if (cipher != AMVP_KDF135_SRTP) {
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kdf135_srtp_cap = calloc(1, sizeof(AMVP_KDF135_SRTP_CAP));
        if (!cap_entry->cap.kdf135_srtp_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case AMVP_KDF135_SSH_TYPE:
        if (cipher != AMVP_KDF135_SSH) {
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kdf135_ssh_cap = calloc(1, sizeof(AMVP_KDF135_SSH_CAP));
        if (!cap_entry->cap.kdf135_ssh_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case AMVP_KDF135_X942_TYPE:
        if (cipher != AMVP_KDF135_X942) {
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kdf135_x942_cap = calloc(1, sizeof(AMVP_KDF135_X942_CAP));
        if (!cap_entry->cap.kdf135_x942_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case AMVP_KDF135_X963_TYPE:
        if (cipher != AMVP_KDF135_X963) {
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kdf135_x963_cap = calloc(1, sizeof(AMVP_KDF135_X963_CAP));
        if (!cap_entry->cap.kdf135_x963_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case AMVP_PBKDF_TYPE:
        if (cipher != AMVP_PBKDF) {
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.pbkdf_cap = calloc(1, sizeof(AMVP_PBKDF_CAP));
        if (!cap_entry->cap.pbkdf_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;

        case AMVP_KDF_TLS12_TYPE:
        if (cipher != AMVP_KDF_TLS12) {
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kdf_tls12_cap = calloc(1, sizeof(AMVP_KDF_TLS12_CAP));
        if (!cap_entry->cap.kdf_tls12_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case AMVP_KDF_TLS13_TYPE:
        if (cipher != AMVP_KDF_TLS13) {
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.kdf_tls13_cap = calloc(1, sizeof(AMVP_KDF_TLS13_CAP));
        if (!cap_entry->cap.kdf_tls13_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case AMVP_RSA_KEYGEN_TYPE:
        if (cipher != AMVP_RSA_KEYGEN) {
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.rsa_keygen_cap = calloc(1, sizeof(AMVP_RSA_KEYGEN_CAP));
        if (!cap_entry->cap.rsa_keygen_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case AMVP_RSA_SIGGEN_TYPE:
        if (cipher != AMVP_RSA_SIGGEN) {
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.rsa_siggen_cap = calloc(1, sizeof(AMVP_RSA_SIG_CAP));
        if (!cap_entry->cap.rsa_siggen_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;
    case AMVP_RSA_SIGVER_TYPE:
        if (cipher != AMVP_RSA_SIGVER) {
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.rsa_sigver_cap = calloc(1, sizeof(AMVP_RSA_SIG_CAP));
        if (!cap_entry->cap.rsa_sigver_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;
    case AMVP_RSA_PRIM_TYPE:
        if ((cipher != AMVP_RSA_SIGPRIM) && (cipher != AMVP_RSA_DECPRIM)) {
            rv = AMVP_INVALID_ARG;
            goto err;
        }
        cap_entry->cap.rsa_prim_cap = calloc(1, sizeof(AMVP_RSA_PRIM_CAP));
        if (!cap_entry->cap.rsa_prim_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;
    case AMVP_SYM_TYPE:
        cap_entry->cap.sym_cap = calloc(1, sizeof(AMVP_SYM_CIPHER_CAP));
        if (!cap_entry->cap.sym_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        cap_entry->cap.sym_cap->perform_ctr_tests = 1; //true by default
        cap_entry->cap.sym_cap->dulen_matches_paylen = 1; //true by default
        break;

    case AMVP_SAFE_PRIMES_KEYGEN_TYPE:
        cap_entry->cap.safe_primes_keygen_cap = allocate_safe_primes_cap();
        if (!cap_entry->cap.safe_primes_keygen_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case AMVP_SAFE_PRIMES_KEYVER_TYPE:
        cap_entry->cap.safe_primes_keyver_cap = allocate_safe_primes_cap();
        if (!cap_entry->cap.safe_primes_keyver_cap) {
            rv = AMVP_MALLOC_FAIL;
            goto err;
        }
        break;

    case AMVP_KDF135_TPM_TYPE:
    default:
        AMVP_LOG_ERR("Invalid parameter 'type'");
        rv = AMVP_INVALID_ARG;
        goto err;
    }

    // Set the other necessary fields
    cap_entry->cipher = cipher;
    cap_entry->crypto_handler = crypto_handler;
    cap_entry->cap_type = type;

    // Append to list
    if (!ctx->caps_list) {
        ctx->caps_list = cap_entry;
    } else {
        cap_e2 = ctx->caps_list;
        while (cap_e2->next) {
            cap_e2 = cap_e2->next;
        }
        cap_e2->next = cap_entry;
    }

    /* Assume here one cap = one vector set; for special cases we will handle those as the parameter is set */
    ctx->vs_count++;
    return AMVP_SUCCESS;

err:
    if (cap_entry) free(cap_entry);

    return rv;
}

static AMVP_RESULT amvp_validate_kdf135_ssh_param_value(AMVP_KDF135_SSH_METHOD method, AMVP_HASH_ALG param) {
    AMVP_RESULT retval = AMVP_INVALID_ARG;

    if ((method < AMVP_SSH_METH_MAX) && (method > 0)) {
        if ((param & AMVP_SHA3_224) ||
            (param & AMVP_SHA3_256) ||
            (param & AMVP_SHA3_384) ||
            (param & AMVP_SHA3_512)) {
            retval = AMVP_INVALID_ARG;
            
        } else if ((param & AMVP_SHA1) ||
                   (param & AMVP_SHA224) ||
                   (param & AMVP_SHA256) ||
                   (param & AMVP_SHA384) ||
                   (param & AMVP_SHA512)) {
            retval = AMVP_SUCCESS;
        }
    }
    return retval;
}

static AMVP_RESULT amvp_validate_kdf135_srtp_param_value(AMVP_KDF135_SRTP_PARAM param, int value) {
    AMVP_RESULT retval = AMVP_INVALID_ARG;

    switch (param) {
    case AMVP_SRTP_AES_KEYLEN:
        if (value == 128 ||
            value == 192 ||
            value == 256) {
            retval = AMVP_SUCCESS;
        }
        break;
    case AMVP_SRTP_SUPPORT_ZERO_KDR:
        retval = is_valid_tf_param(value);
        break;
    case AMVP_SRTP_KDF_EXPONENT:
        if (value >= 1 && value <= 24) {
            retval = AMVP_SUCCESS;
        }
        break;
    default:
        // Invalid
        break;
    }
    return retval;
}

static AMVP_RESULT amvp_validate_kdf135_x942_domain_value(AMVP_KDF135_X942_PARM param, int min, int max, int inc) {
    switch (param) {
    case AMVP_KDF_X942_KEY_LEN:
    case AMVP_KDF_X942_ZZ_LEN:
        if (min >= 1 && max <= 4096 && inc % 8 == 0) {
            return AMVP_SUCCESS;
        }
        break;
    case AMVP_KDF_X942_OTHER_INFO_LEN:
    case AMVP_KDF_X942_SUPP_INFO_LEN:
        if (min >= 0 && max <= 4096 && inc % 8 == 0) {
            return AMVP_SUCCESS;
        }
        break;
    case AMVP_KDF_X942_KDF_TYPE:
    case AMVP_KDF_X942_OID:
    case AMVP_KDF_X942_HASH_ALG:
    default:
        break;
    }

    return AMVP_INVALID_ARG;
}

static AMVP_RESULT amvp_validate_kdf108_param_value(AMVP_CTX *ctx, AMVP_KDF108_PARM param, int value) {
    AMVP_RESULT retval = AMVP_INVALID_ARG;

    switch (param) {
    case AMVP_KDF108_KDF_MODE:
        AMVP_LOG_ERR("No need to explicity enable mode string. It is set implicity as params are added to a mode.");
        break;
    case AMVP_KDF108_MAC_MODE:
        if (value > AMVP_KDF108_MAC_MODE_MIN && value < AMVP_KDF108_MAC_MODE_MAX) {
            retval = AMVP_SUCCESS;
        }
        break;
    case AMVP_KDF108_FIXED_DATA_ORDER:
        if (value > AMVP_KDF108_FIXED_DATA_ORDER_MIN && value < AMVP_KDF108_FIXED_DATA_ORDER_MAX) {
            retval = AMVP_SUCCESS;
        }
        break;
    case AMVP_KDF108_COUNTER_LEN:
        if (value <= 32 && value % 8 == 0) {
            retval = AMVP_SUCCESS;
        }
        break;
    case AMVP_KDF108_SUPPORTS_EMPTY_IV:
    case AMVP_KDF108_REQUIRES_EMPTY_IV:
        retval = is_valid_tf_param(value);
        break;
    case AMVP_KDF108_PARAM_MIN:
    case AMVP_KDF108_PARAM_MAX:
    case AMVP_KDF108_SUPPORTED_LEN:
        if (value >= 1 && value <= AMVP_KDF108_KEYIN_BIT_MAX) {
            retval = AMVP_SUCCESS;
        }
        break;
    default:
        break;
    }
    return retval;
}

static AMVP_RESULT amvp_dsa_set_modulo(AMVP_DSA_CAP_MODE *dsa_cap_mode,
                                       AMVP_DSA_PARM param,
                                       AMVP_HASH_ALG value) {
    AMVP_DSA_ATTRS *attrs;

    if (!dsa_cap_mode) {
        return AMVP_NO_CTX;
    }

    attrs = dsa_cap_mode->dsa_attrs;
    if (!attrs) {
        attrs = calloc(1, sizeof(AMVP_DSA_ATTRS));
        if (!attrs) {
            return AMVP_MALLOC_FAIL;
        }
        dsa_cap_mode->dsa_attrs = attrs;
        attrs->modulo = param;
        attrs->next = NULL;
    }
    while (1) {
        if (attrs->modulo == param) {
            attrs->sha |= value;
            return AMVP_SUCCESS;
        }
        if (attrs->next == NULL) {
            break;
        }
        attrs = attrs->next;
    }
    attrs->next = calloc(1, sizeof(AMVP_DSA_ATTRS));
    if (!attrs->next) {
        return AMVP_MALLOC_FAIL;
    }
    attrs = attrs->next;
    attrs->modulo = param;
    attrs->sha |= value;
    attrs->next = NULL;
    return AMVP_SUCCESS;
}

/*
 * Add DSA per modulo parameters
 */
static AMVP_RESULT amvp_add_dsa_mode_parm(AMVP_CTX *ctx,
                                          AMVP_DSA_CAP_MODE *dsa_cap_mode,
                                          AMVP_DSA_PARM param,
                                          AMVP_HASH_ALG value) {
    AMVP_RESULT rv;

    /*
     * Validate input
     */
    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (!dsa_cap_mode) {
        return AMVP_NO_CTX;
    }

    rv = amvp_dsa_set_modulo(dsa_cap_mode, param, value);
    if (rv != AMVP_SUCCESS) {
        return rv;
    }

    return AMVP_SUCCESS;
}

/*
 * Add top level DSA pqggen parameters
 */
static AMVP_RESULT amvp_add_dsa_pqggen_parm(AMVP_CTX *ctx,
                                            AMVP_DSA_CAP_MODE *dsa_cap_mode,
                                            AMVP_DSA_PARM param,
                                            int value) {
    switch (param) {
    case AMVP_DSA_GENPQ:
        switch (value) {
        case AMVP_DSA_PROVABLE:
            dsa_cap_mode->gen_pq_prov = 1;
            break;
        case AMVP_DSA_PROBABLE:
            dsa_cap_mode->gen_pq_prob = 1;
            break;
        default:
            return AMVP_INVALID_ARG;

            break;
        }
        break;
    case AMVP_DSA_GENG:
        switch (value) {
        case AMVP_DSA_CANONICAL:
            dsa_cap_mode->gen_g_can = 1;
            break;
        case AMVP_DSA_UNVERIFIABLE:
            dsa_cap_mode->gen_g_unv = 1;
            break;
        default:
            return AMVP_INVALID_ARG;

            break;
        }
        break;
    case AMVP_DSA_LN1024_160:
        /* allow for verify only */
        if (dsa_cap_mode->cap_mode == AMVP_DSA_MODE_SIGVER || dsa_cap_mode->cap_mode == AMVP_DSA_MODE_PQGVER) {
            return amvp_add_dsa_mode_parm(ctx, dsa_cap_mode, param, value);
        } else {
            return AMVP_INVALID_ARG;
        }
    case AMVP_DSA_LN2048_224:
    case AMVP_DSA_LN2048_256:
    case AMVP_DSA_LN3072_256:
        return amvp_add_dsa_mode_parm(ctx, dsa_cap_mode, param, value);
        break;
    default:
        return AMVP_INVALID_ARG;
        break;
    }

    return AMVP_SUCCESS;
}

/*
 * Add top level DSA pqggen parameters
 */
static AMVP_RESULT amvp_add_dsa_keygen_parm(AMVP_CTX *ctx,
                                            AMVP_DSA_CAP_MODE *dsa_cap_mode,
                                            AMVP_DSA_PARM param,
                                            int value) {
    switch (param) {
    case AMVP_DSA_LN2048_224:
    case AMVP_DSA_LN2048_256:
    case AMVP_DSA_LN3072_256:
        return amvp_add_dsa_mode_parm(ctx, dsa_cap_mode, param, value);
        break;
    case AMVP_DSA_LN1024_160:
    case AMVP_DSA_GENPQ:
    case AMVP_DSA_GENG:
    default:
        return AMVP_INVALID_ARG;

        break;
    }

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_validate_sym_cipher_parm_value(AMVP_CIPHER cipher, AMVP_SYM_CIPH_PARM parm, int value) {
    AMVP_RESULT retval = AMVP_INVALID_ARG;

    switch (parm) {
    case AMVP_SYM_CIPH_KEYLEN:
        switch (cipher) {
        case AMVP_AES_GCM:
        case AMVP_AES_GCM_SIV:
        case AMVP_AES_CCM:
        case AMVP_AES_ECB:
        case AMVP_AES_CBC:
        case AMVP_AES_CBC_CS1:
        case AMVP_AES_CBC_CS2:
        case AMVP_AES_CBC_CS3:
        case AMVP_AES_CFB1:
        case AMVP_AES_CFB8:
        case AMVP_AES_CFB128:
        case AMVP_AES_OFB:
        case AMVP_AES_CTR:
        case AMVP_AES_XTS:
        case AMVP_AES_KW:
        case AMVP_AES_KWP:
        case AMVP_AES_GMAC:
        case AMVP_AES_XPN:
            if (value == 128 || value == 192 || value == 256) {
                retval = AMVP_SUCCESS;
            }
            break;
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
            if (value == 192) {
                retval = AMVP_SUCCESS;
            }
            break;
        case AMVP_CIPHER_START:
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
        case AMVP_RSA_SIGPRIM:
        case AMVP_RSA_DECPRIM:
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
        case AMVP_KAS_FFC_SSC:
        case AMVP_KAS_IFC_SSC:
        case AMVP_KTS_IFC:
        case AMVP_SAFE_PRIMES_KEYGEN:
        case AMVP_SAFE_PRIMES_KEYVER:
        case AMVP_CIPHER_END:
        default:
            break;
        }
        break;
    case AMVP_SYM_CIPH_TAGLEN:
        switch (cipher) {
        case AMVP_AES_GCM:
        case AMVP_AES_GMAC:
        case AMVP_AES_CCM:
        case AMVP_AES_XPN:
            if (value > 0 && value % 8 == 0 && value <= 128) {
                retval = AMVP_SUCCESS;
            }
            break;
        case AMVP_CIPHER_START:
        case AMVP_AES_GCM_SIV:
        case AMVP_AES_ECB:
        case AMVP_AES_CBC:
        case AMVP_AES_CBC_CS1:
        case AMVP_AES_CBC_CS2:
        case AMVP_AES_CBC_CS3:
        case AMVP_AES_CFB1:
        case AMVP_AES_CFB8:
        case AMVP_AES_CFB128:
        case AMVP_AES_OFB:
        case AMVP_AES_CTR:
        case AMVP_AES_XTS:
        case AMVP_AES_KW:
        case AMVP_AES_KWP:
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
        case AMVP_RSA_SIGPRIM:
        case AMVP_RSA_DECPRIM:
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
        case AMVP_KAS_FFC_SSC:
        case AMVP_KAS_IFC_SSC:
        case AMVP_KTS_IFC:
        case AMVP_SAFE_PRIMES_KEYGEN:
        case AMVP_SAFE_PRIMES_KEYVER:
        case AMVP_CIPHER_END:
        default:
            break;
        }
        break;
    case AMVP_SYM_CIPH_IVLEN:
        switch (cipher) {
        case AMVP_AES_GCM:
        case AMVP_AES_GCM_SIV:
        case AMVP_AES_CCM:
        case AMVP_AES_GMAC:
        case AMVP_TDES_CBC:
        case AMVP_AES_OFB:
        case AMVP_TDES_CFB1:
        case AMVP_TDES_OFB:
        case AMVP_TDES_CFB8:
        case AMVP_TDES_CFB64:
            if (value >= 8 && value <= 1024) {
                retval = AMVP_SUCCESS;
            }
            break;
        case AMVP_CIPHER_START:
        case AMVP_AES_ECB:
        case AMVP_AES_CBC:
        case AMVP_AES_CBC_CS1:
        case AMVP_AES_CBC_CS2:
        case AMVP_AES_CBC_CS3:
        case AMVP_AES_CFB1:
        case AMVP_AES_CFB8:
        case AMVP_AES_CFB128:
        case AMVP_AES_CTR:
        case AMVP_AES_XTS:
        case AMVP_AES_KW:
        case AMVP_AES_KWP:
        case AMVP_AES_XPN:
        case AMVP_TDES_ECB:
        case AMVP_TDES_CBCI:
        case AMVP_TDES_OFBI:
        case AMVP_TDES_CFBP1:
        case AMVP_TDES_CFBP8:
        case AMVP_TDES_CFBP64:
        case AMVP_TDES_CTR:
        case AMVP_TDES_KW:
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
        case AMVP_RSA_SIGPRIM:
        case AMVP_RSA_DECPRIM:
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
        case AMVP_KAS_FFC_SSC:
        case AMVP_KAS_IFC_SSC:
        case AMVP_KTS_IFC:
        case AMVP_SAFE_PRIMES_KEYGEN:
        case AMVP_SAFE_PRIMES_KEYVER:
        case AMVP_CIPHER_END:
        default:
            break;
        }
        break;
    case AMVP_SYM_CIPH_TWEAK:
        if (cipher == AMVP_AES_XTS && value >= AMVP_SYM_CIPH_TWEAK_HEX &&
            value < AMVP_SYM_CIPH_TWEAK_NONE) {
            retval = AMVP_SUCCESS;
        }
        break;
    case AMVP_SYM_CIPH_AADLEN:
        switch (cipher) {
        case AMVP_AES_GCM:
        case AMVP_AES_GCM_SIV:
        case AMVP_AES_CCM:
        case AMVP_AES_ECB:
        case AMVP_AES_CBC:
        case AMVP_AES_CFB1:
        case AMVP_AES_CFB8:
        case AMVP_AES_CFB128:
        case AMVP_AES_OFB:
        case AMVP_AES_CTR:
        case AMVP_AES_GMAC:
        case AMVP_AES_XPN:
            if (value >= 0 && value <= 65536) {
                retval = AMVP_SUCCESS;
            }
            break;
        case AMVP_CIPHER_START:
        case AMVP_AES_CBC_CS1:
        case AMVP_AES_CBC_CS2:
        case AMVP_AES_CBC_CS3:
        case AMVP_AES_XTS:
        case AMVP_AES_KW:
        case AMVP_AES_KWP:
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
        case AMVP_RSA_SIGPRIM:
        case AMVP_RSA_DECPRIM:
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
        case AMVP_KAS_FFC_SSC:
        case AMVP_KAS_IFC_SSC:
        case AMVP_KTS_IFC:
        case AMVP_SAFE_PRIMES_KEYGEN:
        case AMVP_SAFE_PRIMES_KEYVER:
        case AMVP_CIPHER_END:
        default:
            break;
        }
        break;
    case AMVP_SYM_CIPH_PTLEN:
        switch(cipher) {
        case AMVP_AES_GMAC:
            break;
        case AMVP_CIPHER_START:
        case AMVP_AES_GCM:
        case AMVP_AES_GCM_SIV:
        case AMVP_AES_CCM:
        case AMVP_AES_ECB:
        case AMVP_AES_CBC:
        case AMVP_AES_CBC_CS1:
        case AMVP_AES_CBC_CS2:
        case AMVP_AES_CBC_CS3:
        case AMVP_AES_CFB1:
        case AMVP_AES_CFB8:
        case AMVP_AES_CFB128:
        case AMVP_AES_OFB:
        case AMVP_AES_CTR:
        case AMVP_AES_XTS:
        case AMVP_AES_KW:
        case AMVP_AES_KWP:
        case AMVP_AES_XPN:
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
        case AMVP_RSA_SIGPRIM:
        case AMVP_RSA_DECPRIM:
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
        case AMVP_KAS_FFC_SSC:
        case AMVP_KAS_IFC_SSC:
        case AMVP_KTS_IFC:
        case AMVP_SAFE_PRIMES_KEYGEN:
        case AMVP_SAFE_PRIMES_KEYVER:
        case AMVP_CIPHER_END:
        default:
            if (value >= 0 && value <= 65536) {
                retval = AMVP_SUCCESS;
            }
            break;
         }
        break;
    case AMVP_SYM_CIPH_KW_MODE:
    case AMVP_SYM_CIPH_PARM_DIR:
    case AMVP_SYM_CIPH_PARM_KO:
    case AMVP_SYM_CIPH_PARM_PERFORM_CTR:
    case AMVP_SYM_CIPH_PARM_CTR_INCR:
    case AMVP_SYM_CIPH_PARM_CTR_OVRFLW:
    case AMVP_SYM_CIPH_PARM_IVGEN_MODE:
    case AMVP_SYM_CIPH_PARM_IVGEN_SRC:
    case AMVP_SYM_CIPH_PARM_SALT_SRC:
    case AMVP_SYM_CIPH_PARM_CONFORMANCE:
    case AMVP_SYM_CIPH_PARM_DULEN_MATCHES_PAYLOADLEN:
    default:
        break;
    }

    return retval;
}

static AMVP_RESULT amvp_validate_sym_cipher_domain_value(AMVP_CIPHER cipher, AMVP_SYM_CIPH_DOMAIN_PARM parm,
                                                       int min, int max, int increment) {

    AMVP_RESULT retval = AMVP_INVALID_ARG;
    int diff = 0;

    if (min > max || min < 0 || increment <= 0) {
        return retval;
    }

    diff = max - min;
    if (diff % increment != 0) {
        return retval;
    }

    switch (cipher) {
    case AMVP_AES_GCM:
        switch (parm) {
        case AMVP_SYM_CIPH_DOMAIN_IVLEN:
            if (min >= 8 && max <= 1024) {
                retval = AMVP_SUCCESS;
            }
            break;
        case AMVP_SYM_CIPH_DOMAIN_PTLEN:
            if (min >= 0 && max <= 65536) {
                retval = AMVP_SUCCESS;
            }
            break;
        case AMVP_SYM_CIPH_DOMAIN_AADLEN:
            if (min >= 0 && max <= 65536) {
                retval = AMVP_SUCCESS;
            }
            break;
        case AMVP_SYM_CIPH_DOMAIN_DULEN:
        default:
            break;
        }
        break;
    case AMVP_AES_GCM_SIV:
        switch (parm) {
        case AMVP_SYM_CIPH_DOMAIN_PTLEN:
            if (min >= 0 && max <= 65536 && increment == 8) {
                retval = AMVP_SUCCESS;
            }
            break;
        case AMVP_SYM_CIPH_DOMAIN_AADLEN:
            if (min >= 0 && max <= 65536 && increment == 8) {
                retval = AMVP_SUCCESS;
            }
            break;
        case AMVP_SYM_CIPH_DOMAIN_IVLEN:
        case AMVP_SYM_CIPH_DOMAIN_DULEN:
        default:
            break;
        }
        break;
    case AMVP_AES_CCM:
        switch (parm) {
        case AMVP_SYM_CIPH_DOMAIN_IVLEN:
            if (min >= 56 && max <= 104 && increment == 8) {
                retval = AMVP_SUCCESS;
            }
            break;
        case AMVP_SYM_CIPH_DOMAIN_PTLEN:
            if (min >= 0 && max <= 256 && increment == 8) {
                retval = AMVP_SUCCESS;
            }
            break;
        case AMVP_SYM_CIPH_DOMAIN_AADLEN:
            if (min >= 0 && max <= 524288) {
                retval = AMVP_SUCCESS;
            }
            break;
        case AMVP_SYM_CIPH_DOMAIN_DULEN:
        default:
            break;
        }
        break;
    case AMVP_AES_CBC_CS1:
    case AMVP_AES_CBC_CS2:
    case AMVP_AES_CBC_CS3:
        switch (parm) {
        case AMVP_SYM_CIPH_DOMAIN_PTLEN:
            if (min >= 128 && max <= 65536) {
                retval = AMVP_SUCCESS;
            }
            break;
        case AMVP_SYM_CIPH_DOMAIN_IVLEN:
        case AMVP_SYM_CIPH_DOMAIN_AADLEN:
        case AMVP_SYM_CIPH_DOMAIN_DULEN:
        default:
            break;
        }
        break;
    case AMVP_AES_CTR:
        switch (parm) {
        case AMVP_SYM_CIPH_DOMAIN_PTLEN:
            if (min >= 1 && max <= 128) {
                retval = AMVP_SUCCESS;
            }
            break;
        case AMVP_SYM_CIPH_DOMAIN_IVLEN:
        case AMVP_SYM_CIPH_DOMAIN_AADLEN:
        case AMVP_SYM_CIPH_DOMAIN_DULEN:
        default:
            break;
        }
        break;
    case AMVP_AES_XTS:
        switch (parm) {
        case AMVP_SYM_CIPH_DOMAIN_PTLEN:
            if (min >= 128 && max <= 65536) {
                retval = AMVP_SUCCESS;
            }
            break;
        case AMVP_SYM_CIPH_DOMAIN_DULEN:
            if (min >= 128 && max <= 65536 && increment % 8 == 0) {
                retval = AMVP_SUCCESS;
            }
            break;
        case AMVP_SYM_CIPH_DOMAIN_IVLEN:
        case AMVP_SYM_CIPH_DOMAIN_AADLEN:
        default:
            break;
        }
        break;
    case AMVP_AES_KW:
        switch (parm) {
        case AMVP_SYM_CIPH_DOMAIN_PTLEN:
            if (min >= 128 && max <= 524288 && increment % 8 == 0) {
                retval = AMVP_SUCCESS;
            }
            break;
        case AMVP_SYM_CIPH_DOMAIN_IVLEN:
        case AMVP_SYM_CIPH_DOMAIN_AADLEN:
        case AMVP_SYM_CIPH_DOMAIN_DULEN:
        default:
            break;
        }
        break;
    case AMVP_AES_KWP:
        switch (parm) {
        case AMVP_SYM_CIPH_DOMAIN_PTLEN:
            if (min >= 0 && max <= 524288) {
                retval = AMVP_SUCCESS;
            }
            break;
        case AMVP_SYM_CIPH_DOMAIN_IVLEN:
        case AMVP_SYM_CIPH_DOMAIN_AADLEN:
        case AMVP_SYM_CIPH_DOMAIN_DULEN:
        default:
            break;
        }
        break;
    case AMVP_AES_GMAC:
        switch (parm) {
        case AMVP_SYM_CIPH_DOMAIN_IVLEN:
            if (min >= 8 && max <= 1024 && increment % 8 == 0) {
                retval = AMVP_SUCCESS;
            }
            break;
        case AMVP_SYM_CIPH_DOMAIN_AADLEN:
            if (min >= 0 && max <= 65536 && increment % 8 == 0) {
                retval = AMVP_SUCCESS;
            }
            break;
        case AMVP_SYM_CIPH_DOMAIN_PTLEN:
        case AMVP_SYM_CIPH_DOMAIN_DULEN:
        default:
            break;
        }
        break;
    case AMVP_AES_XPN:
        switch (parm) {
        case AMVP_SYM_CIPH_DOMAIN_IVLEN:
            if (min >= 8 && max <= 1024) {
                retval = AMVP_SUCCESS;
            }
            break;
        case AMVP_SYM_CIPH_DOMAIN_PTLEN:
            if (min >= 0 && max <= 65536) {
                retval = AMVP_SUCCESS;
            }
            break;
        case AMVP_SYM_CIPH_DOMAIN_AADLEN:
            if (min >= 0 && max <= 65536) {
                retval = AMVP_SUCCESS;
            }
            break;
        case AMVP_SYM_CIPH_DOMAIN_DULEN:
        default:
            break;
        }
        break;
    case AMVP_TDES_CTR:
    case AMVP_TDES_KW:
        switch (parm) {
        case AMVP_SYM_CIPH_DOMAIN_PTLEN:
            if (min >= 0 && max <= 65536) {
                retval = AMVP_SUCCESS;
            }
            break;
        case AMVP_SYM_CIPH_DOMAIN_IVLEN:
        case AMVP_SYM_CIPH_DOMAIN_AADLEN:
        case AMVP_SYM_CIPH_DOMAIN_DULEN:
        default:
            break;
        }
        break;
    case AMVP_CIPHER_START:
    case AMVP_AES_ECB:
    case AMVP_AES_CBC:
    case AMVP_AES_CFB1:
    case AMVP_AES_CFB8:
    case AMVP_AES_CFB128:
    case AMVP_AES_OFB:
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
    case AMVP_RSA_SIGPRIM:
    case AMVP_RSA_DECPRIM:
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
    case AMVP_KAS_FFC_SSC:
    case AMVP_KAS_IFC_SSC:
    case AMVP_KTS_IFC:
    case AMVP_SAFE_PRIMES_KEYGEN:
    case AMVP_SAFE_PRIMES_KEYVER:
    case AMVP_CIPHER_END:
    default:
        break;
    }

    return retval;
}

static AMVP_RESULT amvp_validate_prereq_val(AMVP_CIPHER cipher, AMVP_PREREQ_ALG pre_req) {
    switch (cipher) {
    case AMVP_AES_GCM:
    case AMVP_AES_GCM_SIV:
    case AMVP_AES_CCM:
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
    case AMVP_AES_GMAC:
    case AMVP_AES_XPN:
        if (pre_req == AMVP_PREREQ_AES ||
            pre_req == AMVP_PREREQ_DRBG) {
            return AMVP_SUCCESS;
        }
        break;
    case AMVP_TDES_ECB:
    case AMVP_TDES_CBC:
    case AMVP_TDES_OFB:
    case AMVP_TDES_CFB64:
    case AMVP_TDES_CFB8:
    case AMVP_TDES_CFB1:
    case AMVP_TDES_KW:
        if (pre_req == AMVP_PREREQ_TDES) {
            return AMVP_SUCCESS;
        }
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
        return AMVP_INVALID_ARG;

        break;
    case AMVP_HASHDRBG:
        if (pre_req == AMVP_PREREQ_SHA) {
            return AMVP_SUCCESS;
        }
        break;
     case AMVP_HMACDRBG:
        if (pre_req == AMVP_PREREQ_SHA ||
            pre_req == AMVP_PREREQ_HMAC) {
                return AMVP_SUCCESS;
        }
        break;
     case AMVP_CTRDRBG:
         if (pre_req == AMVP_PREREQ_AES ||
             pre_req == AMVP_PREREQ_TDES) {
             return AMVP_SUCCESS;
         }
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
        if (pre_req == AMVP_PREREQ_SHA) {
            return AMVP_SUCCESS;
        }
        break;
    case AMVP_CMAC_AES:
    case AMVP_CMAC_TDES:
        if (pre_req == AMVP_PREREQ_AES ||
            pre_req == AMVP_PREREQ_SHA ||
            pre_req == AMVP_PREREQ_TDES) {
            return AMVP_SUCCESS;
        }
        break;
    case AMVP_KMAC_128:
    case AMVP_KMAC_256:
        break;
    case AMVP_DSA_KEYGEN:
    case AMVP_DSA_PQGGEN:
    case AMVP_DSA_PQGVER:
    case AMVP_DSA_SIGGEN:
    case AMVP_DSA_SIGVER:
        if (pre_req == AMVP_PREREQ_SHA ||
            pre_req == AMVP_PREREQ_DRBG) {
            return AMVP_SUCCESS;
        }
        break;
    case AMVP_RSA_KEYGEN:
    case AMVP_RSA_SIGGEN:
    case AMVP_RSA_SIGVER:
    case AMVP_RSA_SIGPRIM:
    case AMVP_RSA_DECPRIM:
    case AMVP_ECDSA_KEYGEN:
    case AMVP_ECDSA_KEYVER:
    case AMVP_ECDSA_SIGGEN:
    case AMVP_ECDSA_SIGVER:
        if (pre_req == AMVP_PREREQ_SHA ||
            pre_req == AMVP_PREREQ_DRBG) {
            return AMVP_SUCCESS;
        }
        break;
    case AMVP_KDF135_SNMP:
    case AMVP_KDF135_SSH:
        if (pre_req == AMVP_PREREQ_SHA ||
            pre_req == AMVP_PREREQ_HMAC ||
            pre_req == AMVP_PREREQ_TDES ||
            pre_req == AMVP_PREREQ_AES) {
            return AMVP_SUCCESS;
        }
        break;
    case AMVP_KDF135_SRTP:
        if (pre_req == AMVP_PREREQ_AES) {
            return AMVP_SUCCESS;
        }
        break;
    case AMVP_KDF135_IKEV2:
    case AMVP_KDF135_IKEV1:
        if (pre_req == AMVP_PREREQ_DRBG ||
            pre_req == AMVP_PREREQ_SHA) {
            return AMVP_SUCCESS;
        }
        break;
    case AMVP_KDF108:
        if (pre_req == AMVP_PREREQ_DRBG ||
            pre_req == AMVP_PREREQ_HMAC ||
            pre_req == AMVP_PREREQ_CMAC ||
            pre_req == AMVP_PREREQ_KAS) {
            return AMVP_SUCCESS;
        }
        break;
    case AMVP_PBKDF:
        if (pre_req == AMVP_PREREQ_HMAC) {
            return AMVP_SUCCESS;
        }
        break;
    case AMVP_KDF_TLS12:
        if (pre_req == AMVP_PREREQ_HMAC ||
            pre_req == AMVP_PREREQ_SHA) {
                return AMVP_SUCCESS;
            }
        break;
    case AMVP_KDF_TLS13:
        if (pre_req == AMVP_PREREQ_HMAC) {
            return AMVP_SUCCESS;
        }
        break;
    case AMVP_KAS_ECC_COMP:
    case AMVP_KAS_ECC_SSC:
    case AMVP_KAS_ECC_NOCOMP:
        if (pre_req == AMVP_PREREQ_DRBG ||
            pre_req == AMVP_PREREQ_HMAC ||
            pre_req == AMVP_PREREQ_CMAC ||
            pre_req == AMVP_PREREQ_SHA ||
            pre_req == AMVP_PREREQ_CCM ||
            pre_req == AMVP_PREREQ_ECDSA) {
            return AMVP_SUCCESS;
        }
        break;
    case AMVP_KAS_ECC_CDH:
        if (pre_req == AMVP_PREREQ_ECDSA) {
            return AMVP_SUCCESS;
        }
        break;
    case AMVP_KAS_FFC_COMP:
    case AMVP_KAS_FFC_NOCOMP:
    case AMVP_KAS_FFC_SSC:
        if (pre_req == AMVP_PREREQ_DRBG ||
            pre_req == AMVP_PREREQ_HMAC ||
            pre_req == AMVP_PREREQ_CMAC ||
            pre_req == AMVP_PREREQ_SHA ||
            pre_req == AMVP_PREREQ_SAFE_PRIMES ||
            pre_req == AMVP_PREREQ_CCM ||
            pre_req == AMVP_PREREQ_DSA) {
            return AMVP_SUCCESS;
        }
        break;
    case AMVP_KTS_IFC:
        if (pre_req == AMVP_PREREQ_DRBG || /* will need to add macs if/when supported */
            pre_req == AMVP_PREREQ_HMAC ||
            pre_req == AMVP_PREREQ_SHA ||
            pre_req == AMVP_PREREQ_RSA ||
            pre_req == AMVP_PREREQ_RSADP) {
            return AMVP_SUCCESS;
        }
        break;
    case AMVP_KAS_IFC_SSC:
        if (pre_req == AMVP_PREREQ_DRBG ||
            pre_req == AMVP_PREREQ_HMAC ||
            pre_req == AMVP_PREREQ_SHA ||
            pre_req == AMVP_PREREQ_RSA ||
            pre_req == AMVP_PREREQ_RSADP) {
            return AMVP_SUCCESS;
        }
        break;
    case AMVP_KDA_ONESTEP:
        if (pre_req == AMVP_PREREQ_DRBG ||
            pre_req == AMVP_PREREQ_HMAC ||
            pre_req == AMVP_PREREQ_KMAC ||
            pre_req == AMVP_PREREQ_SHA) {
            return AMVP_SUCCESS;
        }
        break;
    case AMVP_KDA_TWOSTEP:
        if (pre_req == AMVP_PREREQ_DRBG ||
            pre_req == AMVP_PREREQ_HMAC ||
            pre_req == AMVP_PREREQ_SHA) {
            return AMVP_SUCCESS;
        }
        break;
    case AMVP_KDA_HKDF:
        if (pre_req == AMVP_PREREQ_DRBG ||
            pre_req == AMVP_PREREQ_HMAC ||
            pre_req == AMVP_PREREQ_SHA) {
            return AMVP_SUCCESS;
        }
        break;
    case AMVP_KDF135_X942:
        if (pre_req == AMVP_PREREQ_SHA) {
            return AMVP_SUCCESS;
        }
        break;
    case AMVP_KDF135_X963:
        if (pre_req == AMVP_PREREQ_SHA) {
            return AMVP_SUCCESS;
        }
        break;
    case AMVP_SAFE_PRIMES_KEYGEN:
    case AMVP_SAFE_PRIMES_KEYVER:
        if (pre_req == AMVP_PREREQ_DRBG ||
            pre_req == AMVP_PREREQ_SHA) {
            return AMVP_SUCCESS;
        }
        break;
    case AMVP_CIPHER_START:
    case AMVP_TDES_CBCI:
    case AMVP_TDES_OFBI:
    case AMVP_TDES_CFBP1:
    case AMVP_TDES_CFBP8:
    case AMVP_TDES_CFBP64:
    case AMVP_TDES_CTR:
    case AMVP_CIPHER_END:
    default:
        break;
    }

    return AMVP_INVALID_ARG;
}

/*
 * Append a pre req val to the list of prereqs
 */
static AMVP_RESULT amvp_add_prereq_val(AMVP_CIPHER cipher,
                                       AMVP_CAPS_LIST *cap_list,
                                       AMVP_PREREQ_ALG pre_req,
                                       char *value) {
    AMVP_PREREQ_LIST *prereq_entry, *prereq_entry_2;
    AMVP_RESULT result;

    prereq_entry = calloc(1, sizeof(AMVP_PREREQ_LIST));
    if (!prereq_entry) {
        return AMVP_MALLOC_FAIL;
    }
    prereq_entry->prereq_alg_val.alg = pre_req;
    prereq_entry->prereq_alg_val.val = value;

    result = amvp_validate_prereq_val(cipher, pre_req);
    if (result != AMVP_SUCCESS) {
        free(prereq_entry);
        return result;
    }
    /*
     * 1st entry
     */
    if (!cap_list->prereq_vals) {
        cap_list->prereq_vals = prereq_entry;
    } else {
        /*
         * append to the last in the list
         */
        prereq_entry_2 = cap_list->prereq_vals;
        while (prereq_entry_2->next) {
            prereq_entry_2 = prereq_entry_2->next;
        }
        prereq_entry_2->next = prereq_entry;
    }
    return AMVP_SUCCESS;
}

AMVP_RESULT amvp_cap_set_prereq(AMVP_CTX *ctx,
                                AMVP_CIPHER cipher,
                                AMVP_PREREQ_ALG pre_req_cap,
                                char *value) {
    AMVP_CAPS_LIST *cap_list;

    if (!ctx) {
        return AMVP_NO_CTX;
    }
    if (!value || strnlen_s(value, 12) == 0) {
        return AMVP_INVALID_ARG;
    }

    /*
     * Locate this cipher in the caps array
     */
    cap_list = amvp_locate_cap_entry(ctx, cipher);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    }

    cap_list->has_prereq = 1;     /* make sure this is set */
    /*
     * Add the value to the cap
     */
    return amvp_add_prereq_val(cipher, cap_list, pre_req_cap, value);
}

/*
 * The user should call this after invoking amvp_enable_sym_cipher_cap()
 * to specify the supported key lengths, PT lengths, AAD lengths, IV
 * lengths, and tag lengths. This is called multiple times, for different parms
 * 
 * NOTE: Sym ciphers originally used range values instead of domain. Range values
 * will be phsed out slowly where applicable. For now, allow either set domain OR 
 * set parm to be called for a param, but not both.
 */
AMVP_RESULT amvp_cap_sym_cipher_set_domain(AMVP_CTX *ctx,
                                           AMVP_CIPHER cipher,
                                           AMVP_SYM_CIPH_DOMAIN_PARM parm,
                                           int min,
                                           int max,
                                           int increment) {
    AMVP_CAPS_LIST *cap = NULL;
    AMVP_SYM_CIPHER_CAP *symcap = NULL;
    AMVP_RESULT rv = AMVP_SUCCESS;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    switch (cipher) {
    case AMVP_AES_GCM:
    case AMVP_AES_GCM_SIV:
    case AMVP_AES_CCM:
    case AMVP_AES_ECB:
    case AMVP_AES_CBC:
    case AMVP_AES_CBC_CS1:
    case AMVP_AES_CBC_CS2:
    case AMVP_AES_CBC_CS3:
    case AMVP_AES_CFB1:
    case AMVP_AES_CFB8:
    case AMVP_AES_CFB128:
    case AMVP_AES_OFB:
    case AMVP_AES_CTR:
    case AMVP_AES_XTS:
    case AMVP_AES_KW:
    case AMVP_AES_KWP:
    case AMVP_AES_GMAC:
    case AMVP_AES_XPN:
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
        break;
    case AMVP_CIPHER_START:
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
    case AMVP_RSA_SIGPRIM:
    case AMVP_RSA_DECPRIM:
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
    case AMVP_KAS_FFC_SSC:
    case AMVP_KAS_IFC_SSC:
    case AMVP_KTS_IFC:
    case AMVP_SAFE_PRIMES_KEYGEN:
    case AMVP_SAFE_PRIMES_KEYVER:
    case AMVP_CIPHER_END:
    default:
        return AMVP_INVALID_ARG;
    }

    /*
     * Locate this cipher in the caps array
     */
    cap = amvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        AMVP_LOG_ERR("Cap entry not found, use amvp_enable_sym_cipher_cap() first.");
        return AMVP_NO_CAP;
    }
    symcap = cap->cap.sym_cap;
    if (!symcap) {
        AMVP_LOG_ERR("Error retrieving sym cipher capabilities object");
        return AMVP_NO_CAP;
    }

    switch (parm) {
    case AMVP_SYM_CIPH_DOMAIN_IVLEN:
        if (symcap->ivlen) {
            AMVP_LOG_ERR("ivLen already defined using amvp_sym_cipher_set_parm. Please set ivLen using only one function "
                         "(Using set_parm for ivLen will eventually be depreciated).");
            return AMVP_INVALID_ARG;
        }
        rv = amvp_validate_sym_cipher_domain_value(cipher, parm, min, max, increment);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Unable to validate given domain value (cipher=%d, param=%d)", cipher, parm);
            return AMVP_INVALID_ARG;
        }
        symcap->iv_len.min = min;
        symcap->iv_len.max = max;
        symcap->iv_len.increment = increment;
        break;
    case AMVP_SYM_CIPH_DOMAIN_PTLEN:
        if (symcap->ptlen) {
            AMVP_LOG_ERR("ptLen already defined using amvp_sym_cipher_set_parm. Please set ptLen using only one function "
                         "(Using set_parm for ptLen will eventually be depreciated).");
            return AMVP_INVALID_ARG;
        }
        rv = amvp_validate_sym_cipher_domain_value(cipher, parm, min, max, increment);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Unable to validate given domain value (cipher=%d, param=%d)", cipher, parm);
            return AMVP_INVALID_ARG;
        }
        symcap->payload_len.min = min;
        symcap->payload_len.max = max;
        symcap->payload_len.increment = increment;
        break;
    case AMVP_SYM_CIPH_DOMAIN_AADLEN:
        if (symcap->aadlen) {
            AMVP_LOG_ERR("aadLen already defined using amvp_sym_cipher_set_parm. Please set aadLen using only one function "
                         "(Using set_parm for aadLen will eventually be depreciated).");
            return AMVP_INVALID_ARG;
        }
        rv = amvp_validate_sym_cipher_domain_value(cipher, parm, min, max, increment);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Unable to validate given domain value (cipher=%d, param=%d)", cipher, parm);
            return AMVP_INVALID_ARG;
        }
        symcap->aad_len.min = min;
        symcap->aad_len.max = max;
        symcap->aad_len.increment = increment;
        break;
    case AMVP_SYM_CIPH_DOMAIN_DULEN:
        if (symcap->dulen_matches_paylen) {
            AMVP_LOG_ERR("AMVP_SYM_CIPH_DOMAIN_DULEN can only be set if "
                         "AMVP_SYM_CIPH_PARM_DULEN_MATCHES_PAYLOADLEN is already set to 0 (false)");
            return AMVP_INVALID_ARG;
        }
        if (cipher != AMVP_AES_XTS) {
            AMVP_LOG_ERR("Data Unit Length may only be set for AES-XTS.");
            return AMVP_INVALID_ARG;
        }
        rv = amvp_validate_sym_cipher_domain_value(cipher, parm, min, max, increment);
        if (rv != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Unable to validate given domain value (cipher=%d, param=%d)", cipher, parm);
            return AMVP_INVALID_ARG;
        }
        symcap->du_len.min = min;
        symcap->du_len.max = max;
        symcap->du_len.increment = increment;
        break;
    default:
        AMVP_LOG_ERR("Invalid parameter for symmetric cipher");
        return AMVP_INVALID_ARG;
    }

    return AMVP_SUCCESS;
}

/*
 * The user should call this after invoking amvp_enable_sym_cipher_cap()
 * to specify the supported key lengths, direction, etc. This is called by the 
 * user multiple times, for different parms.
 */
AMVP_RESULT amvp_cap_sym_cipher_set_parm(AMVP_CTX *ctx,
                                         AMVP_CIPHER cipher,
                                         AMVP_SYM_CIPH_PARM parm,
                                         int value) {
    AMVP_CAPS_LIST *cap = NULL;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    switch (cipher) {
    case AMVP_AES_GCM:
    case AMVP_AES_GCM_SIV:
    case AMVP_AES_CCM:
    case AMVP_AES_ECB:
    case AMVP_AES_CBC:
    case AMVP_AES_CBC_CS1:
    case AMVP_AES_CBC_CS2:
    case AMVP_AES_CBC_CS3:
    case AMVP_AES_CFB1:
    case AMVP_AES_CFB8:
    case AMVP_AES_CFB128:
    case AMVP_AES_OFB:
    case AMVP_AES_CTR:
    case AMVP_AES_XTS:
    case AMVP_AES_KW:
    case AMVP_AES_KWP:
    case AMVP_AES_GMAC:
    case AMVP_AES_XPN:
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
        break;
    case AMVP_CIPHER_START:
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
    case AMVP_RSA_SIGPRIM:
    case AMVP_RSA_DECPRIM:
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
    case AMVP_KAS_FFC_SSC:
    case AMVP_KAS_IFC_SSC:
    case AMVP_KTS_IFC:
    case AMVP_SAFE_PRIMES_KEYGEN:
    case AMVP_SAFE_PRIMES_KEYVER:
    case AMVP_CIPHER_END:
    default:
        return AMVP_INVALID_ARG;
    }

    /*
     * Locate this cipher in the caps array
     */
    cap = amvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        AMVP_LOG_ERR("Cap entry not found, use amvp_cap_sym_cipher_enable() first.");
        return AMVP_NO_CAP;
    }

    /*
     * Check is this is a non-length related value.
     */
    switch (parm) {
    case AMVP_SYM_CIPH_KW_MODE:
        if (value < AMVP_SYM_KW_MAX) {
            cap->cap.sym_cap->kw_mode |= value;
            return AMVP_SUCCESS;
        } else {
            AMVP_LOG_ERR("Invalid parameter 'value' for param AMVP_SYM_CIPH_KW_MODE");
            return AMVP_INVALID_ARG;
        }

    case AMVP_SYM_CIPH_PARM_DIR:
        if (value > 0 && value < AMVP_SYM_CIPH_DIR_MAX) {
            cap->cap.sym_cap->direction = value;
            return AMVP_SUCCESS;
        } else {
            AMVP_LOG_ERR("Invalid parameter 'value' for param AMVP_SYM_CIPH_PARM_DIR");
            return AMVP_INVALID_ARG;
        }

    case AMVP_SYM_CIPH_PARM_KO:
        if (value > 0 && value < AMVP_SYM_CIPH_KO_MAX) {
            cap->cap.sym_cap->keying_option = value;
            return AMVP_SUCCESS;
        } else {
            AMVP_LOG_ERR("Invalid parameter 'value' for param AMVP_SYM_CIPH_PARM_KO");
            return AMVP_INVALID_ARG;
        }

    case AMVP_SYM_CIPH_PARM_PERFORM_CTR:
        if (value == 0 || value == 1) {
            if (value == 0 && (cap->cap.sym_cap->ctr_incr || cap->cap.sym_cap->ctr_ovrflw)) {
                AMVP_LOG_WARN("Perform counter test set to false, but value for ctr increment or ctr overflow already set. Server will ignore other values. Continuing...");
            }
            cap->cap.sym_cap->perform_ctr_tests = value;
            return AMVP_SUCCESS;
        } else {
            AMVP_LOG_ERR("Invalid parameter 'value' for param AMVP_SYM_CIPH_PARM_PERFORM_CTR");
            return AMVP_INVALID_ARG;
        }

    case AMVP_SYM_CIPH_PARM_CTR_INCR:
        if (cap->cap.sym_cap->perform_ctr_tests == 0) {
            AMVP_LOG_WARN("Perform counter test set to false, but value for ctr increment being set; server will ignore this. Continuing...");
        }
        if (value == 0 || value == 1) {
            cap->cap.sym_cap->ctr_incr = value;
            return AMVP_SUCCESS;
        } else {
            AMVP_LOG_ERR("Invalid parameter 'value' for param AMVP_SYM_CIPH_PARM_CTR_INCR");
            return AMVP_INVALID_ARG;
        }

    case AMVP_SYM_CIPH_PARM_CTR_OVRFLW:
        if (cap->cap.sym_cap->perform_ctr_tests == 0) {
            AMVP_LOG_WARN("Perform counter test set to false, but value for ctr overflow being set; server will ignore this. Continuing...");
        }
        if (value == 0 || value == 1) {
            cap->cap.sym_cap->ctr_ovrflw = value;
            return AMVP_SUCCESS;
        } else {
            AMVP_LOG_ERR("Invalid parameter 'value' for param AMVP_SYM_CIPH_PARM_CTR_OVRFLW");
            return AMVP_INVALID_ARG;
        }

    case AMVP_SYM_CIPH_PARM_IVGEN_SRC:
        if (value > 0 && value < AMVP_SYM_CIPH_IVGEN_SRC_MAX) {
            if (value == AMVP_SYM_CIPH_IVGEN_SRC_EITHER) {
                /* This will generate two vector sets, one for internal ivgen and one for external */
                ctx->vs_count++;
            }
            cap->cap.sym_cap->ivgen_source = value;
            return AMVP_SUCCESS;
        } else {
            AMVP_LOG_ERR("Invalid parameter 'value' for param AMVP_SYM_CIPH_PARM_IVGEN_SRC");
            return AMVP_INVALID_ARG;
        }

    case AMVP_SYM_CIPH_PARM_IVGEN_MODE:
        if (value > 0 && value < AMVP_SYM_CIPH_IVGEN_MODE_MAX) {
            cap->cap.sym_cap->ivgen_mode = value;
            return AMVP_SUCCESS;
        } else {
            AMVP_LOG_ERR("Invalid parameter 'value' for param AMVP_SYM_CIPH_PARM_IVGEN_MODE");
            return AMVP_INVALID_ARG;
        }
    case AMVP_SYM_CIPH_PARM_SALT_SRC:
        if  (cipher == AMVP_AES_XPN && value > 0 && value < AMVP_SYM_CIPH_SALT_SRC_MAX) {
            cap->cap.sym_cap->salt_source = value;
            return AMVP_SUCCESS;
        } else {
            AMVP_LOG_ERR("Invalid parameter 'value' for parm AMVP_SYM_CIPH_PARM_SALT_SRC");
            return AMVP_INVALID_ARG;
        }
    case AMVP_SYM_CIPH_PARM_CONFORMANCE:
        if (cipher == AMVP_AES_CTR && value == AMVP_CONFORMANCE_RFC3686) {
            cap->cap.sym_cap->conformance = AMVP_CONFORMANCE_RFC3686;
            return AMVP_SUCCESS;
        } else {
            AMVP_LOG_ERR("Invalid parameter 'value' for parm AMVP_SYM_CIPH_PARM_CONFORMANCE");
            return AMVP_INVALID_ARG;
        }
    case AMVP_SYM_CIPH_PARM_DULEN_MATCHES_PAYLOADLEN:
        if (cipher != AMVP_AES_XTS) {
            AMVP_LOG_ERR("AMVP_SYM_CIPH_PARM_DULEN_MATCHES_PAYLOADLEN can only be set for AES-XTS");
            return AMVP_INVALID_ARG;
        }
        if ((cap->cap.sym_cap->du_len.max != 0 || cap->cap.sym_cap->du_len.increment != 0)) {
            AMVP_LOG_ERR("AMVP_SYM_CIPH_DULEN_MATCHES_PAYLOADLEN cannot be changed after setting "
                         "AMVP_SYM_CIPH_DOMAIN_DULEN");
            return AMVP_INVALID_ARG;
        } else if (value == 0 || value == 1) {
            cap->cap.sym_cap->dulen_matches_paylen = value;
            return AMVP_SUCCESS;
        } else {
            AMVP_LOG_ERR("Invalid parameter 'value' for parm AMVP_SYM_CIPH_PARM_DULEN_MATCHES_PAYLOADLEN");
            return AMVP_INVALID_ARG;
        }
    case AMVP_SYM_CIPH_KEYLEN:
    case AMVP_SYM_CIPH_TAGLEN:
    case AMVP_SYM_CIPH_IVLEN:
    case AMVP_SYM_CIPH_PTLEN:
    case AMVP_SYM_CIPH_TWEAK:
    case AMVP_SYM_CIPH_AADLEN:
    default:
        break;
    }

    if (amvp_validate_sym_cipher_parm_value(cipher, parm, value) != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Unable to validate given parameter (cipher=%d, value=%d)", cipher, value);
        return AMVP_INVALID_ARG;
    }

    switch (parm) {
    case AMVP_SYM_CIPH_KEYLEN:
        amvp_append_sl_list(&cap->cap.sym_cap->keylen, value);
        break;
    case AMVP_SYM_CIPH_TAGLEN:
        amvp_append_sl_list(&cap->cap.sym_cap->taglen, value);
        break;
    case AMVP_SYM_CIPH_IVLEN:
        if (amvp_is_domain_already_set(&cap->cap.sym_cap->iv_len)) {
            AMVP_LOG_ERR("ivLen already defined using amvp_sym_cipher_set_domain. Please set ivLen using only one function "
                        "(Using set_parm for ivLen will eventually be depreciated).");
            return AMVP_INVALID_ARG;
        }
        amvp_append_sl_list(&cap->cap.sym_cap->ivlen, value);
        break;
    case AMVP_SYM_CIPH_PTLEN:
        if (amvp_is_domain_already_set(&cap->cap.sym_cap->payload_len)) {
            AMVP_LOG_ERR("payloadLen already defined using amvp_sym_cipher_set_domain. Please set payloadLen using only one function "
                         "(Using set_parm for payloadLen will eventually be depreciated).");
            return AMVP_INVALID_ARG;
        }
        amvp_append_sl_list(&cap->cap.sym_cap->ptlen, value);
        break;
    case AMVP_SYM_CIPH_TWEAK:
        amvp_append_sl_list(&cap->cap.sym_cap->tweak, value);
        break;
    case AMVP_SYM_CIPH_AADLEN:
        if (amvp_is_domain_already_set(&cap->cap.sym_cap->aad_len)) {
            AMVP_LOG_ERR("aadLen already defined using amvp_sym_cipher_set_domain. Please set aadLen using only one function "
                         "(Using set_parm for aadLen will eventually be depreciated).");
            return AMVP_INVALID_ARG;
        }
        amvp_append_sl_list(&cap->cap.sym_cap->aadlen, value);
        break;
    case AMVP_SYM_CIPH_KW_MODE:
    case AMVP_SYM_CIPH_PARM_DIR:
    case AMVP_SYM_CIPH_PARM_KO:
    case AMVP_SYM_CIPH_PARM_PERFORM_CTR:
    case AMVP_SYM_CIPH_PARM_CTR_INCR:
    case AMVP_SYM_CIPH_PARM_CTR_OVRFLW:
    case AMVP_SYM_CIPH_PARM_IVGEN_MODE:
    case AMVP_SYM_CIPH_PARM_IVGEN_SRC:
    case AMVP_SYM_CIPH_PARM_CONFORMANCE:
    case AMVP_SYM_CIPH_PARM_SALT_SRC:
    case AMVP_SYM_CIPH_PARM_DULEN_MATCHES_PAYLOADLEN:
    default:
        return AMVP_INVALID_ARG;
    }

    return AMVP_SUCCESS;
}

/*
 * This function is called by the application to register a crypto
 * capability for symmetric ciphers, along with a handler that the
 * application implements when that particular crypto operation is
 * needed by libamvp.
 *
 * This function should be called one or more times for each crypto
 * capability supported by the crypto module being validated.  This
 * needs to be called after amvp_create_test_session() and prior to
 * calling amvp_register().
 *
 */
AMVP_RESULT amvp_cap_sym_cipher_enable(AMVP_CTX *ctx,
                                       AMVP_CIPHER cipher,
                                       int (*crypto_handler)(AMVP_TEST_CASE *test_case)) {
    AMVP_RESULT result = AMVP_SUCCESS;

    if (!ctx) {
        return AMVP_NO_CTX;
    }
    if (!crypto_handler) {
        AMVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return AMVP_INVALID_ARG;
    }

    switch (cipher) {
    case AMVP_AES_GCM:
    case AMVP_AES_GCM_SIV:
    case AMVP_AES_CCM:
    case AMVP_AES_ECB:
    case AMVP_AES_CBC:
    case AMVP_AES_CBC_CS1:
    case AMVP_AES_CBC_CS2:
    case AMVP_AES_CBC_CS3:
    case AMVP_AES_CFB1:
    case AMVP_AES_CFB8:
    case AMVP_AES_CFB128:
    case AMVP_AES_OFB:
    case AMVP_AES_CTR:
    case AMVP_AES_XTS:
    case AMVP_AES_KW:
    case AMVP_AES_KWP:
    case AMVP_AES_GMAC:
    case AMVP_AES_XPN:
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
        break;
    case AMVP_CIPHER_START:
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
    case AMVP_RSA_SIGPRIM:
    case AMVP_RSA_DECPRIM:
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
    case AMVP_KAS_FFC_SSC:
    case AMVP_KAS_IFC_SSC:
    case AMVP_KTS_IFC:
    case AMVP_SAFE_PRIMES_KEYGEN:
    case AMVP_SAFE_PRIMES_KEYVER:
    case AMVP_CIPHER_END:
    default:
        return AMVP_INVALID_ARG;
    }

    result = amvp_cap_list_append(ctx, AMVP_SYM_TYPE, cipher, crypto_handler);

    if (result == AMVP_DUP_CIPHER) {
        AMVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == AMVP_MALLOC_FAIL) {
        AMVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

AMVP_RESULT amvp_cap_hash_enable(AMVP_CTX *ctx,
                                 AMVP_CIPHER cipher,
                                 int (*crypto_handler)(AMVP_TEST_CASE *test_case)) {
    AMVP_RESULT result = AMVP_SUCCESS;
    AMVP_SUB_HASH alg;

    if (!ctx) {
        return AMVP_NO_CTX;
    }
    if (!crypto_handler) {
        AMVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return AMVP_INVALID_ARG;
    }

    alg = amvp_get_hash_alg(cipher);
    if (alg == 0) {
        AMVP_LOG_ERR("Invalid cipher value");
        return AMVP_INVALID_ARG;
    }

    switch (alg) {
    case AMVP_SUB_HASH_SHA1:
    case AMVP_SUB_HASH_SHA2_224:
    case AMVP_SUB_HASH_SHA2_256:
    case AMVP_SUB_HASH_SHA2_384:
    case AMVP_SUB_HASH_SHA2_512:
    case AMVP_SUB_HASH_SHA2_512_224:
    case AMVP_SUB_HASH_SHA2_512_256:
    case AMVP_SUB_HASH_SHA3_224:
    case AMVP_SUB_HASH_SHA3_256:
    case AMVP_SUB_HASH_SHA3_384:
    case AMVP_SUB_HASH_SHA3_512:
    case AMVP_SUB_HASH_SHAKE_128:
    case AMVP_SUB_HASH_SHAKE_256:
        break;
    default:
        AMVP_LOG_ERR("Invalid parameter 'cipher'");
        return AMVP_INVALID_ARG;
    }

    result = amvp_cap_list_append(ctx, AMVP_HASH_TYPE, cipher, crypto_handler);

    if (result == AMVP_DUP_CIPHER) {
        AMVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == AMVP_MALLOC_FAIL) {
        AMVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

static AMVP_RESULT amvp_validate_hash_parm_value(AMVP_HASH_PARM parm, int value) {
    AMVP_RESULT retval = AMVP_INVALID_ARG;

    switch (parm) {
    case AMVP_HASH_IN_BIT:
    case AMVP_HASH_IN_EMPTY:
    case AMVP_HASH_OUT_BIT:
        retval = is_valid_tf_param(value);
        break;
    case AMVP_HASH_OUT_LENGTH:
    case AMVP_HASH_MESSAGE_LEN:
    default:
        break;
    }

    return retval;
}

AMVP_RESULT amvp_cap_hash_set_parm(AMVP_CTX *ctx,
                                   AMVP_CIPHER cipher,
                                   AMVP_HASH_PARM param,
                                   int value) {
    AMVP_CAPS_LIST *cap;
    AMVP_HASH_CAP *hash_cap;
    AMVP_SUB_HASH alg;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    alg = amvp_get_hash_alg(cipher);
    if (alg == 0) {
        AMVP_LOG_ERR("Invalid cipher value");
        return AMVP_INVALID_ARG;
    }

    switch (alg) {
    case AMVP_SUB_HASH_SHA3_224:
    case AMVP_SUB_HASH_SHA3_256:
    case AMVP_SUB_HASH_SHA3_384:
    case AMVP_SUB_HASH_SHA3_512:
    case AMVP_SUB_HASH_SHAKE_128:
    case AMVP_SUB_HASH_SHAKE_256:
        break;
    case AMVP_SUB_HASH_SHA1:
    case AMVP_SUB_HASH_SHA2_224:
    case AMVP_SUB_HASH_SHA2_256:
    case AMVP_SUB_HASH_SHA2_384:
    case AMVP_SUB_HASH_SHA2_512:
    case AMVP_SUB_HASH_SHA2_512_224:
    case AMVP_SUB_HASH_SHA2_512_256:
    default:
        return AMVP_INVALID_ARG;
    }

    cap = amvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        return AMVP_NO_CAP;
    }

    hash_cap = cap->cap.hash_cap;
    if (!hash_cap) {
        return AMVP_NO_CAP;
    }

    if (amvp_validate_hash_parm_value(param, value) != AMVP_SUCCESS) {
        return AMVP_INVALID_ARG;
    }

    switch (param) {
    case AMVP_HASH_IN_BIT:
        hash_cap->in_bit = value;
        break;
    case AMVP_HASH_IN_EMPTY:
        hash_cap->in_empty = value;
        break;
    case AMVP_HASH_OUT_BIT:
        switch (alg) {
        case AMVP_SUB_HASH_SHAKE_128:
        case AMVP_SUB_HASH_SHAKE_256:
            break;
        case AMVP_SUB_HASH_SHA3_224:
        case AMVP_SUB_HASH_SHA3_256:
        case AMVP_SUB_HASH_SHA3_384:
        case AMVP_SUB_HASH_SHA3_512:
        case AMVP_SUB_HASH_SHA1:
        case AMVP_SUB_HASH_SHA2_224:
        case AMVP_SUB_HASH_SHA2_256:
        case AMVP_SUB_HASH_SHA2_384:
        case AMVP_SUB_HASH_SHA2_512:
        case AMVP_SUB_HASH_SHA2_512_224:
        case AMVP_SUB_HASH_SHA2_512_256:
        default:
            AMVP_LOG_ERR("parm 'AMVP_HASH_OUT_BIT' only allowed for AMVP_HASH_SHAKE_* ");
            return AMVP_INVALID_ARG;
        }

        hash_cap->out_bit = value;
        break;
    case AMVP_HASH_OUT_LENGTH:
    case AMVP_HASH_MESSAGE_LEN:
    default:
        return AMVP_INVALID_ARG;
    }

    return AMVP_SUCCESS;
}

/*
 * Add HASH(SHA) parameters
 */
AMVP_RESULT amvp_cap_hash_set_domain(AMVP_CTX *ctx,
                                     AMVP_CIPHER cipher,
                                     AMVP_HASH_PARM parm,
                                     int min,
                                     int max,
                                     int increment) {
    AMVP_CAPS_LIST *cap;
    AMVP_HASH_CAP *hash_cap;
    AMVP_JSON_DOMAIN_OBJ *domain;
    AMVP_SUB_HASH alg;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    alg = amvp_get_hash_alg(cipher);
    if (alg == 0) {
        AMVP_LOG_ERR("Invalid cipher value");
        return AMVP_INVALID_ARG;
    }

    switch (alg) {
    case AMVP_SUB_HASH_SHA3_224:
    case AMVP_SUB_HASH_SHA3_256:
    case AMVP_SUB_HASH_SHA3_384:
    case AMVP_SUB_HASH_SHA3_512:
    case AMVP_SUB_HASH_SHAKE_128:
    case AMVP_SUB_HASH_SHAKE_256:
    case AMVP_SUB_HASH_SHA1:
    case AMVP_SUB_HASH_SHA2_224:
    case AMVP_SUB_HASH_SHA2_256:
    case AMVP_SUB_HASH_SHA2_384:
    case AMVP_SUB_HASH_SHA2_512:
    case AMVP_SUB_HASH_SHA2_512_224:
    case AMVP_SUB_HASH_SHA2_512_256:
        break;
    default:
        return AMVP_INVALID_ARG;
    }

    cap = amvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    }

    hash_cap = cap->cap.hash_cap;
    if (!hash_cap) {
        return AMVP_NO_CAP;
    }

    switch (parm) {
    case AMVP_HASH_MESSAGE_LEN:
        if (cipher == AMVP_HASH_SHAKE_128 || cipher == AMVP_HASH_SHAKE_256) {
            AMVP_LOG_ERR("AMVP_HASH_MSG_LEN cannot be set for SHAKE ciphers");
            return AMVP_INVALID_ARG;
        }
        if (min < AMVP_HASH_MSG_BIT_MIN ||  max > AMVP_HASH_MSG_BIT_MAX) {
            AMVP_LOG_ERR("min or max outside of acceptable range");
            return AMVP_INVALID_ARG;
        }
        domain = &hash_cap->msg_length;
        break;
    case AMVP_HASH_OUT_LENGTH:
        if (cipher != AMVP_HASH_SHAKE_128 && cipher != AMVP_HASH_SHAKE_256) {
            AMVP_LOG_ERR("Only SHAKE_128 or SHAKE_256 allowed for AMVP_HASH_OUT_LENGTH");
            return AMVP_INVALID_ARG;
        }
        if (min < AMVP_HASH_XOF_MD_BIT_MIN ||  max > AMVP_HASH_XOF_MD_BIT_MAX) {
            AMVP_LOG_ERR("'AMVP_HASH_OUT_LENGTH' min or max outside of acceptable range");
            return AMVP_INVALID_ARG;
        }
        if (increment + min > AMVP_HASH_XOF_MD_BIT_MAX) {
            AMVP_LOG_ERR("'AMVP_HASH_OUT_LENGTH' increment(%d) + min(%d) > max(%d)",
                         increment, min, AMVP_HASH_XOF_MD_BIT_MAX);
            return AMVP_INVALID_ARG;
        }
        domain = &hash_cap->out_len;
        break;
    case AMVP_HASH_IN_BIT:
    case AMVP_HASH_IN_EMPTY:
    case AMVP_HASH_OUT_BIT:
    default:
        AMVP_LOG_ERR("Invalid 'parm'");
        return AMVP_INVALID_ARG;
    }
    
    if (increment <= 0) {
        AMVP_LOG_ERR("Invalid increment (%d) for hash set domain", increment);
        return AMVP_INVALID_ARG;
    }

    if (min % increment != 0) {
        AMVP_LOG_ERR("min(%d) MODULO increment(%d) must equal 0", min, increment);
        return AMVP_INVALID_ARG;
    }
    if (max % increment != 0) {
        AMVP_LOG_ERR("max(%d) MODULO increment(%d) must equal 0", max, increment);
        return AMVP_INVALID_ARG;
    }

    domain->min = min;
    domain->max = max;
    domain->increment = increment;

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_validate_hmac_parm_value(AMVP_CIPHER cipher,
                                                 AMVP_HMAC_PARM parm,
                                                 int value) {
    AMVP_RESULT retval = AMVP_INVALID_ARG;
    int max_val = 0;
    AMVP_SUB_HMAC alg;

    switch (parm) {
    case AMVP_HMAC_KEYLEN:
        if (value >= AMVP_HMAC_KEY_BIT_MIN &&
            value <= AMVP_HMAC_KEY_BIT_MAX &&
            value % 8 == 0) {
            retval = AMVP_SUCCESS;
        }
        break;
    case AMVP_HMAC_MACLEN:
        alg = amvp_get_hmac_alg(cipher);
        if (alg == 0) {
            return AMVP_INVALID_ARG;
        }

        switch (alg) {
        case AMVP_SUB_HMAC_SHA1:
            max_val = 160;
            break;
        case AMVP_SUB_HMAC_SHA2_224:
        case AMVP_SUB_HMAC_SHA2_512_224:
        case AMVP_SUB_HMAC_SHA3_224:
            max_val = 224;
            break;
        case AMVP_SUB_HMAC_SHA2_256:
        case AMVP_SUB_HMAC_SHA2_512_256:
        case AMVP_SUB_HMAC_SHA3_256:
            max_val = 256;
            break;
        case AMVP_SUB_HMAC_SHA2_384:
        case AMVP_SUB_HMAC_SHA3_384:
            max_val = 384;
            break;
        case AMVP_SUB_HMAC_SHA2_512:
        case AMVP_SUB_HMAC_SHA3_512:
            max_val = 512;
            break;
        default:
            break;
        }
        if (value >= AMVP_HMAC_MAC_BIT_MIN &&
            value <= max_val &&
            value % 8 == 0) {
            retval = AMVP_SUCCESS;
        }
        break;
    case AMVP_HMAC_KEYBLOCK:
    default:
        break;
    }

    return retval;
}

AMVP_RESULT amvp_cap_hmac_enable(AMVP_CTX *ctx,
                                 AMVP_CIPHER cipher,
                                 int (*crypto_handler)(AMVP_TEST_CASE *test_case)) {
    AMVP_RESULT result = AMVP_SUCCESS;
    AMVP_SUB_HMAC alg;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (!crypto_handler) {
        AMVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return AMVP_INVALID_ARG;
    }

    alg = amvp_get_hmac_alg(cipher);
    if (alg == 0) {
        AMVP_LOG_ERR("Invalid cipher value");
        return AMVP_INVALID_ARG;
    }
    switch (alg) {
    case AMVP_SUB_HMAC_SHA1:
    case AMVP_SUB_HMAC_SHA2_224:
    case AMVP_SUB_HMAC_SHA2_256:
    case AMVP_SUB_HMAC_SHA2_384:
    case AMVP_SUB_HMAC_SHA2_512:
    case AMVP_SUB_HMAC_SHA2_512_224:
    case AMVP_SUB_HMAC_SHA2_512_256:
    case AMVP_SUB_HMAC_SHA3_224:
    case AMVP_SUB_HMAC_SHA3_256:
    case AMVP_SUB_HMAC_SHA3_384:
    case AMVP_SUB_HMAC_SHA3_512:
        break;
    default:
        return AMVP_INVALID_ARG;
    }

    result = amvp_cap_list_append(ctx, AMVP_HMAC_TYPE, cipher, crypto_handler);

    if (result == AMVP_DUP_CIPHER) {
        AMVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == AMVP_MALLOC_FAIL) {
        AMVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

AMVP_RESULT amvp_cap_hmac_set_domain(AMVP_CTX *ctx,
                                     AMVP_CIPHER cipher,
                                     AMVP_HMAC_PARM parm,
                                     int min,
                                     int max,
                                     int increment) {
    AMVP_CAPS_LIST *cap_list;
    AMVP_JSON_DOMAIN_OBJ *domain;
    AMVP_HMAC_CAP *current_hmac_cap;

    cap_list = amvp_locate_cap_entry(ctx, cipher);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    }
    current_hmac_cap = cap_list->cap.hmac_cap;

    switch (parm) {
    case AMVP_HMAC_KEYLEN:
        if (min < AMVP_HMAC_KEY_BIT_MIN ||
            max > AMVP_HMAC_KEY_BIT_MAX) {
            AMVP_LOG_ERR("min or max outside of acceptable range");
            return AMVP_INVALID_ARG;
        }
        domain = &current_hmac_cap->key_len;
        break;
    case AMVP_HMAC_MACLEN:
        if (min < AMVP_HMAC_MAC_BIT_MIN ||
            max > AMVP_HMAC_MAC_BIT_MAX) {
            AMVP_LOG_ERR("min or max outside of acceptable range");
            return AMVP_INVALID_ARG;
        }
        domain = &current_hmac_cap->mac_len;
        break;
    case AMVP_HMAC_KEYBLOCK:
    default:
        return AMVP_INVALID_ARG;
    }

    if (increment % 8 != 0) {
        AMVP_LOG_ERR("increment must be mod 8");
        return AMVP_INVALID_ARG;
    }

    domain->min = min;
    domain->max = max;
    domain->increment = increment;

    return AMVP_SUCCESS;
}

/*
 * The user should call this after invoking amvp_enable_hmac_cap()
 * to specify the supported key ranges, keyblock value, and
 * suuported mac lengths. This is called by the user multiple times,
 * once for each length supported.
 */
AMVP_RESULT amvp_cap_hmac_set_parm(AMVP_CTX *ctx,
                                   AMVP_CIPHER cipher,
                                   AMVP_HMAC_PARM parm,
                                   int value) {
    AMVP_CAPS_LIST *cap;

    /*
     * Locate this cipher in the caps array
     */
    cap = amvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        AMVP_LOG_ERR("Cap entry not found, use amvp_enable_hmac_cipher_cap() first.");
        return AMVP_NO_CAP;
    }

    if (amvp_validate_hmac_parm_value(cipher, parm, value) != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Invalid parm or value");
        return AMVP_INVALID_ARG;
    }

    switch (parm) {
    case AMVP_HMAC_KEYLEN:
        if (amvp_append_sl_list(&cap->cap.hmac_cap->key_len.values, value) != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Error adding HMAC key length to list");
            return AMVP_MALLOC_FAIL;
        }
        break;
    case AMVP_HMAC_MACLEN:
        if (amvp_append_sl_list(&cap->cap.hmac_cap->mac_len.values, value) != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Error adding HMAC mac length to list");
            return AMVP_MALLOC_FAIL;
        }
        break;
    case AMVP_HMAC_KEYBLOCK:
    default:
        return AMVP_INVALID_ARG;
    }

    return AMVP_SUCCESS;
}

static AMVP_RESULT amvp_validate_cmac_parm_value(AMVP_CMAC_PARM parm, int value) {
    AMVP_RESULT retval = AMVP_INVALID_ARG;

    switch (parm) {
    case AMVP_CMAC_MACLEN:
        if (value >= AMVP_CMAC_MACLEN_MIN &&
            value <= AMVP_CMAC_MACLEN_MAX &&
            value % 8 == 0) {
            retval = AMVP_SUCCESS;
        }
        break;
    case AMVP_CMAC_MSGLEN:
        if (value >= AMVP_CMAC_MSGLEN_MIN &&
            value <= AMVP_CMAC_MSGLEN_MAX &&
            value % 8 == 0) {
            retval = AMVP_SUCCESS;
        }
        break;
    case AMVP_CMAC_KEYLEN:
        if (value == AMVP_CMAC_KEYLEN_128 ||
            value == AMVP_CMAC_KEYLEN_192 ||
            value == AMVP_CMAC_KEYLEN_256) {
            retval = AMVP_SUCCESS;
        }
        break;
    case AMVP_CMAC_KEYING_OPTION:
        if (value == AMVP_CMAC_KEYING_OPTION_1 || value == AMVP_CMAC_KEYING_OPTION_2) {
            retval = AMVP_SUCCESS;
        }
        break;
    case AMVP_CMAC_DIRECTION_GEN:
    case AMVP_CMAC_DIRECTION_VER:
        return is_valid_tf_param(value);

    default:
        break;
    }

    return retval;
}

AMVP_RESULT amvp_cap_cmac_enable(AMVP_CTX *ctx,
                                 AMVP_CIPHER cipher,
                                 int (*crypto_handler)(AMVP_TEST_CASE *test_case)) {
    AMVP_RESULT result = AMVP_SUCCESS;
    AMVP_SUB_CMAC alg;

    if (!ctx) {
        return AMVP_NO_CTX;
    }
    if (!crypto_handler) {
        AMVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return AMVP_INVALID_ARG;
    }

    alg = amvp_get_cmac_alg(cipher);
    if (alg == 0) {
        AMVP_LOG_ERR("Invalid cipher value");
        return AMVP_INVALID_ARG;
    }
    switch (alg) {
    case AMVP_SUB_CMAC_AES:
    case AMVP_SUB_CMAC_TDES:
        break;
    default:
        return AMVP_INVALID_ARG;
    }

    result = amvp_cap_list_append(ctx, AMVP_CMAC_TYPE, cipher, crypto_handler);

    if (result == AMVP_DUP_CIPHER) {
        AMVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == AMVP_MALLOC_FAIL) {
        AMVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

AMVP_RESULT amvp_cap_cmac_set_domain(AMVP_CTX *ctx,
                                     AMVP_CIPHER cipher,
                                     AMVP_CMAC_PARM parm,
                                     int min,
                                     int max,
                                     int increment) {
    AMVP_CAPS_LIST *cap_list;
    AMVP_JSON_DOMAIN_OBJ *domain;
    AMVP_CMAC_CAP *current_cmac_cap;

    cap_list = amvp_locate_cap_entry(ctx, cipher);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    }
    current_cmac_cap = cap_list->cap.cmac_cap;

    switch (parm) {
    case AMVP_CMAC_MSGLEN:
        if (min < AMVP_CMAC_MSGLEN_MIN ||
            max > AMVP_CMAC_MSGLEN_MAX) {
            AMVP_LOG_ERR("min or max outside of acceptable range");
            return AMVP_INVALID_ARG;
        }
        domain = &current_cmac_cap->msg_len;
        break;
    case AMVP_CMAC_MACLEN:
        if (min < AMVP_CMAC_MACLEN_MIN ||
            max > AMVP_CMAC_MACLEN_MAX) {
            AMVP_LOG_ERR("min or max outside of acceptable range");
            return AMVP_INVALID_ARG;
        }
        domain = &current_cmac_cap->mac_len;
        break;
    case AMVP_CMAC_KEYLEN:
    case AMVP_CMAC_KEYING_OPTION:
    case AMVP_CMAC_DIRECTION_GEN:
    case AMVP_CMAC_DIRECTION_VER:
    default:
        return AMVP_INVALID_ARG;
    }
    if (increment % 8 != 0) {
        AMVP_LOG_ERR("increment must be mod 8");
        return AMVP_INVALID_ARG;
    }

    domain->min = min;
    domain->max = max;
    domain->increment = increment;

    return AMVP_SUCCESS;
}

/*
 * The user should call this after invoking amvp_enable_cmac_cap()
 * to specify the supported msg lengths and mac lengths.
 * This is called by the user multiple times,
 * once for each length supported.
 */
AMVP_RESULT amvp_cap_cmac_set_parm(AMVP_CTX *ctx,
                                   AMVP_CIPHER cipher,
                                   AMVP_CMAC_PARM parm,
                                   int value) {
    AMVP_CAPS_LIST *cap;
    AMVP_CMAC_CAP *current_cmac_cap;

    /*
     * Locate this cipher in the caps array
     */
    cap = amvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        AMVP_LOG_ERR("Cap entry not found, use amvp_enable_cmac_cipher_cap() first.");
        return AMVP_NO_CAP;
    }
    current_cmac_cap = cap->cap.cmac_cap;
    if (amvp_validate_cmac_parm_value(parm, value) != AMVP_SUCCESS) {
        return AMVP_INVALID_ARG;
    }

    switch (parm) {
    case AMVP_CMAC_MSGLEN:
        if (amvp_append_sl_list(&current_cmac_cap->msg_len.values, value) != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Error adding CMAC msg len to list");
            return AMVP_MALLOC_FAIL;
        }
        break;
    case AMVP_CMAC_MACLEN:
        if (amvp_append_sl_list(&current_cmac_cap->mac_len.values, value) != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Error adding CMAC mac len to list");
            return AMVP_MALLOC_FAIL;
        }
        break;
    case AMVP_CMAC_DIRECTION_GEN:
        cap->cap.cmac_cap->direction_gen = value;
        break;
    case AMVP_CMAC_DIRECTION_VER:
        cap->cap.cmac_cap->direction_ver = value;
        break;
    case AMVP_CMAC_KEYLEN:
        amvp_append_sl_list(&cap->cap.cmac_cap->key_len, value);
        break;
    case AMVP_CMAC_KEYING_OPTION:
        if (cipher == AMVP_CMAC_TDES) {
            amvp_append_sl_list(&cap->cap.cmac_cap->keying_option, value);
            break;
        }
        return AMVP_INVALID_ARG;
    default:
        return AMVP_INVALID_ARG;
    }

    return AMVP_SUCCESS;
}

AMVP_RESULT amvp_cap_kmac_enable(AMVP_CTX *ctx,
                                 AMVP_CIPHER cipher,
                                 int (*crypto_handler)(AMVP_TEST_CASE *test_case)) {
    AMVP_RESULT result = AMVP_SUCCESS;
    AMVP_SUB_KMAC alg;

    if (!ctx) {
        return AMVP_NO_CTX;
    }
    if (!crypto_handler) {
        AMVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return AMVP_INVALID_ARG;
    }

    alg = amvp_get_kmac_alg(cipher);
    if (alg == 0) {
        AMVP_LOG_ERR("Invalid cipher value");
        return AMVP_INVALID_ARG;
    }
    switch (alg) {
    case AMVP_SUB_KMAC_128:
    case AMVP_SUB_KMAC_256:
        break;
    default:
        return AMVP_INVALID_ARG;
    }

    result = amvp_cap_list_append(ctx, AMVP_KMAC_TYPE, cipher, crypto_handler);

    if (result == AMVP_DUP_CIPHER) {
        AMVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == AMVP_MALLOC_FAIL) {
        AMVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

AMVP_RESULT amvp_cap_kmac_set_parm(AMVP_CTX *ctx,
                                   AMVP_CIPHER cipher,
                                   AMVP_KMAC_PARM parm,
                                   int value) {
    AMVP_CAPS_LIST *cap;
    AMVP_KMAC_CAP *kmac_cap;

    /*
     * Locate this cipher in the caps array
     */
    cap = amvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        AMVP_LOG_ERR("Cap entry not found, use amvp_enable_kmac_cipher_cap() first.");
        return AMVP_NO_CAP;
    }
    kmac_cap = cap->cap.kmac_cap;

    switch (parm) {
    case AMVP_KMAC_XOF_SUPPORT:
        switch (value) {
        case AMVP_XOF_SUPPORT_FALSE:
        case AMVP_XOF_SUPPORT_TRUE:
        case AMVP_XOF_SUPPORT_BOTH:
            kmac_cap->xof = value;
            break;
        default:
            AMVP_LOG_ERR("Invalid value for KMAC XOF support");
            return AMVP_INVALID_ARG;
        }
        break;
    case AMVP_KMAC_HEX_CUSTOM_SUPPORT:
        if (is_valid_tf_param(value) == AMVP_SUCCESS) {
            kmac_cap->hex_customization = value;
        } else {
            AMVP_LOG_ERR("Invalid boolean for KMAC hex customization support");
            return AMVP_INVALID_ARG;
        }
        break;
    case AMVP_KMAC_MACLEN:
    case AMVP_KMAC_MSGLEN:
    case AMVP_KMAC_KEYLEN:
    default:
        AMVP_LOG_ERR("Invalid KMAC parameter given");
        return AMVP_INVALID_ARG;
    }

    return AMVP_SUCCESS;

}

AMVP_RESULT amvp_cap_kmac_set_domain(AMVP_CTX *ctx,
                                     AMVP_CIPHER cipher,
                                     AMVP_KMAC_PARM parm,
                                     int min,
                                     int max,
                                     int increment) {
    AMVP_CAPS_LIST *cap;
    AMVP_KMAC_CAP *kmac_cap;

    /*
     * Locate this cipher in the caps array
     */
    cap = amvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        AMVP_LOG_ERR("Cap entry not found, use amvp_enable_kmac_cipher_cap() first.");
        return AMVP_NO_CAP;
    }
    kmac_cap = cap->cap.kmac_cap;

    if (validate_domain_range(min, max, increment) != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Invalid domain given for KMAC");
        return AMVP_INVALID_ARG;
    }

    switch (parm) {
    case AMVP_KMAC_MACLEN:
        if (max > 65536 || min < 32 || increment != 8) {
            AMVP_LOG_ERR("Out of bounds maclen given for KMAC");
            return AMVP_INVALID_ARG;
        }
        kmac_cap->mac_len.min = min;
        kmac_cap->mac_len.max = max;
        kmac_cap->mac_len.increment = increment;
        break;
    case AMVP_KMAC_MSGLEN:
        if (max > 65536) {
            AMVP_LOG_ERR("Out of bounds msglen given for KMAC");
            return AMVP_INVALID_ARG;
        }
        kmac_cap->msg_len.min = min;
        kmac_cap->msg_len.max = max;
        kmac_cap->msg_len.increment = increment;
        break;
    case AMVP_KMAC_KEYLEN:
        if (max > 524288 || min < 128 || increment != 8) {
            AMVP_LOG_ERR("Out of bounds keylen given for KMAC");
            return AMVP_INVALID_ARG;
        }
        kmac_cap->key_len.min = min;
        kmac_cap->key_len.max = max;
        kmac_cap->key_len.increment = increment;
        break;
    case AMVP_KMAC_XOF_SUPPORT:
    case AMVP_KMAC_HEX_CUSTOM_SUPPORT:
    default:
        AMVP_LOG_ERR("Invalid KMAC parameter given");
        return AMVP_INVALID_ARG;
    }

    return AMVP_SUCCESS;

}

/*
 * Add DRBG Length Range
 */
static AMVP_RESULT amvp_add_drbg_length_range(AMVP_DRBG_CAP_GROUP *cap_group,
                                              AMVP_DRBG_PARM param,
                                              int min,
                                              int step,
                                              int max) {
    if (!cap_group) {
        return AMVP_INVALID_ARG;
    }

    switch (param) {
    case AMVP_DRBG_ENTROPY_LEN:
        cap_group->entropy_len_min = min;
        cap_group->entropy_len_step = step;
        cap_group->entropy_len_max = max;
        break;
    case AMVP_DRBG_NONCE_LEN:
        cap_group->nonce_len_min = min;
        cap_group->nonce_len_step = step;
        cap_group->nonce_len_max = max;
        break;
    case AMVP_DRBG_PERSO_LEN:
        cap_group->perso_len_min = min;
        cap_group->perso_len_step = step;
        cap_group->perso_len_max = max;
        break;
    case AMVP_DRBG_ADD_IN_LEN:
        cap_group->additional_in_len_min = min;
        cap_group->additional_in_len_step = step;
        cap_group->additional_in_len_max = max;
        break;
    case AMVP_DRBG_RET_BITS_LEN:
    case AMVP_DRBG_PRE_REQ_VALS:
    case AMVP_DRBG_DER_FUNC_ENABLED:
    case AMVP_DRBG_PRED_RESIST_ENABLED:
    case AMVP_DRBG_RESEED_ENABLED:
    default:
        return AMVP_INVALID_ARG;

        break;
    }

    return AMVP_SUCCESS;
}

AMVP_RESULT amvp_cap_drbg_set_length(AMVP_CTX *ctx,
                                     AMVP_CIPHER cipher,
                                     AMVP_DRBG_MODE mode,
                                     int group,
                                     AMVP_DRBG_PARM param,
                                     int min,
                                     int step,
                                     int max) {
    AMVP_DRBG_MODE_LIST *drbg_cap_mode = NULL;
    AMVP_DRBG_CAP_GROUP *grp = NULL;
    AMVP_CAPS_LIST *cap_list = NULL;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    /*
     * Locate this cipher in the caps array
     */
    cap_list = amvp_locate_cap_entry(ctx, cipher);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    }

    /*
     * Locate cap mode from array
     * if the mode does not exist yet then create it.
     */
    drbg_cap_mode  = amvp_locate_drbg_mode_entry(cap_list, mode);
    if (!drbg_cap_mode) {
        drbg_cap_mode = amvp_create_drbg_mode_entry(cap_list, mode);
        if (!drbg_cap_mode) {
            AMVP_LOG_ERR("Malloc Failed.");
            return AMVP_MALLOC_FAIL;
        }
    }

    grp = amvp_locate_drbg_group_entry(drbg_cap_mode, group);
    if (!grp) {
        grp = amvp_create_drbg_group(drbg_cap_mode, group);
        if (!grp) {
            AMVP_LOG_ERR("Error creating group for DRBG capabilities");
            return AMVP_MALLOC_FAIL;
        }
    }

    switch (param) {
    case AMVP_DRBG_ENTROPY_LEN:
        if (max > AMVP_DRBG_ENTPY_IN_BIT_MAX) {
            AMVP_LOG_ERR("Parameter 'max'(%d) > AMVP_DRBG_ENTPY_IN_BIT_MAX(%d). "
                         "Please reduce the integer.",
                         max, AMVP_DRBG_ENTPY_IN_BIT_MAX);
            return AMVP_INVALID_ARG;
        }
        break;
    case AMVP_DRBG_NONCE_LEN:
        if (max > AMVP_DRBG_NONCE_BIT_MAX) {
            AMVP_LOG_ERR("Parameter 'max'(%d) > AMVP_DRBG_NONCE_BIT_MAX(%d). "
                         "Please reduce the integer.",
                         max, AMVP_DRBG_NONCE_BIT_MAX);
            return AMVP_INVALID_ARG;
        }
        break;
    case AMVP_DRBG_PERSO_LEN:
        if (max > AMVP_DRBG_PER_SO_BIT_MAX) {
            AMVP_LOG_ERR("Parameter 'max'(%d) > AMVP_DRBG_PER_SO_BIT_MAX(%d). "
                         "Please reduce the integer.",
                         max, AMVP_DRBG_PER_SO_BIT_MAX);
            return AMVP_INVALID_ARG;
        }
        break;
    case AMVP_DRBG_ADD_IN_LEN:
        if (max > AMVP_DRBG_ADDI_IN_BIT_MAX) {
            AMVP_LOG_ERR("Parameter 'max'(%d) > AMVP_DRBG_ADDI_IN_BIT_MAX(%d). "
                         "Please reduce the integer.",
                         max, AMVP_DRBG_ADDI_IN_BIT_MAX);
            return AMVP_INVALID_ARG;
        }
    case AMVP_DRBG_DER_FUNC_ENABLED:
    case AMVP_DRBG_PRED_RESIST_ENABLED:
    case AMVP_DRBG_RESEED_ENABLED:
    case AMVP_DRBG_RET_BITS_LEN:
    case AMVP_DRBG_PRE_REQ_VALS:
    default:
        break;
    }

    /*
     * Add the length range to the cap
     */
    return amvp_add_drbg_length_range(grp, param, min, step, max);
}

static AMVP_RESULT amvp_validate_drbg_parm_value(AMVP_DRBG_PARM parm, int value) {
    AMVP_RESULT retval = AMVP_INVALID_ARG;

    switch (parm) {
    case AMVP_DRBG_DER_FUNC_ENABLED:
    case AMVP_DRBG_PRED_RESIST_ENABLED:
    case AMVP_DRBG_RESEED_ENABLED:
        retval = is_valid_tf_param(value);
        break;
    case AMVP_DRBG_ENTROPY_LEN:
        if (value >= AMVP_DRBG_ENTPY_IN_BIT_MIN &&
            value <= AMVP_DRBG_ENTPY_IN_BIT_MAX) {
            retval = AMVP_SUCCESS;
        }
        break;
    case AMVP_DRBG_NONCE_LEN:
        if (value >= AMVP_DRBG_NONCE_BIT_MIN &&
            value <= AMVP_DRBG_NONCE_BIT_MAX) {
            retval = AMVP_SUCCESS;
        }
        break;
    case AMVP_DRBG_PERSO_LEN:
        if (value <= AMVP_DRBG_PER_SO_BIT_MAX) {
            retval = AMVP_SUCCESS;
        }
        break;
    case AMVP_DRBG_ADD_IN_LEN:
        if (value <= AMVP_DRBG_ADDI_IN_BIT_MAX) {
            retval = AMVP_SUCCESS;
        }
        break;
    case AMVP_DRBG_RET_BITS_LEN:
        if (value <= AMVP_DRB_BIT_MAX) {
            retval = AMVP_SUCCESS;
        }
        break;
    case AMVP_DRBG_PRE_REQ_VALS:
        retval = AMVP_SUCCESS;
        break;
    default:
        break;
    }

    return retval;
}

/* The user should call this after invoking amvp_enable_drbg_cap_parm(). */
AMVP_RESULT amvp_cap_drbg_set_parm(AMVP_CTX *ctx,
                                   AMVP_CIPHER cipher,
                                   AMVP_DRBG_MODE mode,
                                   int group,
                                   AMVP_DRBG_PARM param,
                                   int value) {
    AMVP_DRBG_MODE_LIST *cap_mode = NULL;
    AMVP_DRBG_CAP_GROUP *grp = NULL;
    AMVP_CAPS_LIST *cap_list = NULL;
    AMVP_SUB_DRBG alg;

    /*
     * Validate input
     */
    if (!ctx) {
        return AMVP_NO_CTX;
    }

    /*
     * Locate this cipher in the caps array
     */
    cap_list = amvp_locate_cap_entry(ctx, cipher);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    }

    /*
     * Locate cap mode from array
     * if the mode does not exist yet then create it.
     */
    if (!cap_list->cap.drbg_cap) {
        AMVP_LOG_ERR("DRBG Cap entry not found.");
        return AMVP_NO_CAP;
    }

    cap_mode = amvp_locate_drbg_mode_entry(cap_list, mode);
    if (!cap_mode) {
        cap_mode = amvp_create_drbg_mode_entry(cap_list, mode);
        if (!cap_mode) {
            AMVP_LOG_ERR("Malloc Failed.");
            return AMVP_MALLOC_FAIL;
        }
    }

    grp = amvp_locate_drbg_group_entry(cap_mode, group);
    if (!grp) {
        grp = amvp_create_drbg_group(cap_mode, group);
        if (!grp) {
            AMVP_LOG_ERR("Error creating group for DRBG capabilities");
            return AMVP_MALLOC_FAIL;
        }
    }

    /*
     * Add the value to the cap
     */
    alg = amvp_get_drbg_alg(cipher);
    if (alg == 0) {
        AMVP_LOG_ERR("Invalid cipher value");
        return AMVP_INVALID_ARG;
    }

    if (amvp_validate_drbg_parm_value(param, value) != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Error validating DRBG paramater value (param = %d, value = %d", param, value);
        return AMVP_INVALID_ARG;
    }

    switch (param) {
    case AMVP_DRBG_DER_FUNC_ENABLED:
        grp->der_func_enabled = value;
        break;
    case AMVP_DRBG_PRED_RESIST_ENABLED:
        cap_list->cap.drbg_cap->pred_resist_enabled = value;
        break;
    case AMVP_DRBG_RESEED_ENABLED:
        cap_list->cap.drbg_cap->reseed_implemented = value;
        break;
    case AMVP_DRBG_ENTROPY_LEN:
        grp->entropy_input_len = value;
        break;
    case AMVP_DRBG_NONCE_LEN:
        grp->nonce_len = value;
        break;
    case AMVP_DRBG_PERSO_LEN:
        grp->perso_string_len = value;
        break;
    case AMVP_DRBG_ADD_IN_LEN:
        grp->additional_input_len = value;
        break;
    case AMVP_DRBG_RET_BITS_LEN:
        grp->returned_bits_len = value;
        break;
    case AMVP_DRBG_PRE_REQ_VALS:
    default:
        AMVP_LOG_ERR("Invalid DRBG param supplied");
        return AMVP_INVALID_ARG;
        break;
    }


    return AMVP_SUCCESS;
}

AMVP_RESULT amvp_cap_drbg_enable(AMVP_CTX *ctx,
                                 AMVP_CIPHER cipher,
                                 int (*crypto_handler)(AMVP_TEST_CASE *test_case)) {
    AMVP_RESULT result = AMVP_SUCCESS;

    if (!ctx) {
        return AMVP_NO_CTX;
    }
    if (!crypto_handler) {
        AMVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return AMVP_INVALID_ARG;
    }

    result = amvp_cap_list_append(ctx, AMVP_DRBG_TYPE, cipher, crypto_handler);

    if (result == AMVP_DUP_CIPHER) {
        AMVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == AMVP_MALLOC_FAIL) {
        AMVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

/*
 * The user should call this after invoking amvp_enable_rsa_keygen_cap().
 */
AMVP_RESULT amvp_cap_rsa_keygen_set_mode(AMVP_CTX *ctx,
                                         AMVP_RSA_KEYGEN_MODE value) {
    AMVP_CAPS_LIST *cap_list;
    AMVP_RSA_KEYGEN_CAP *keygen_cap;
    AMVP_RESULT result = AMVP_SUCCESS;

    cap_list = amvp_locate_cap_entry(ctx, AMVP_RSA_KEYGEN);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    }

    if (!cap_list->cap.rsa_keygen_cap) {
        cap_list->cap.rsa_keygen_cap = calloc(1, sizeof(AMVP_RSA_KEYGEN_CAP));
    }
    keygen_cap = cap_list->cap.rsa_keygen_cap;

    while (keygen_cap) {
        if (keygen_cap->rand_pq != AMVP_RSA_KEYGEN_B32 &&
            keygen_cap->rand_pq != AMVP_RSA_KEYGEN_B33 &&
            keygen_cap->rand_pq != AMVP_RSA_KEYGEN_B34 &&
            keygen_cap->rand_pq != AMVP_RSA_KEYGEN_B35 &&
            keygen_cap->rand_pq != AMVP_RSA_KEYGEN_B36) {
            break;
        }
        if (keygen_cap->rand_pq == value) {
            return AMVP_DUP_CIPHER;
        }
        if (!keygen_cap->next) {
            keygen_cap->next = calloc(1, sizeof(AMVP_RSA_KEYGEN_CAP));
            keygen_cap = keygen_cap->next;
            break;
        }
        keygen_cap = keygen_cap->next;
    }

    keygen_cap->rand_pq = value;
    switch (value) {
    case AMVP_RSA_KEYGEN_B32:
        keygen_cap->rand_pq_str = AMVP_RSA_RANDPQ32_STR;
        break;
    case AMVP_RSA_KEYGEN_B33:
        keygen_cap->rand_pq_str = AMVP_RSA_RANDPQ33_STR;
        break;
    case AMVP_RSA_KEYGEN_B34:
        keygen_cap->rand_pq_str = AMVP_RSA_RANDPQ34_STR;
        break;
    case AMVP_RSA_KEYGEN_B35:
        keygen_cap->rand_pq_str = AMVP_RSA_RANDPQ35_STR;
        break;
    case AMVP_RSA_KEYGEN_B36:
        keygen_cap->rand_pq_str = AMVP_RSA_RANDPQ36_STR;
        break;
    default:
        break;
    }

    return result;
}

/*
 * The user should call this after invoking amvp_enable_rsa_keygen_cap().
 */
AMVP_RESULT amvp_cap_rsa_keygen_set_parm(AMVP_CTX *ctx,
                                         AMVP_RSA_PARM param,
                                         int value) {
    AMVP_CAPS_LIST *cap_list;
    AMVP_RESULT rv = AMVP_SUCCESS;

    cap_list = amvp_locate_cap_entry(ctx, AMVP_RSA_KEYGEN);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    }

    switch (param) {
    case AMVP_RSA_PARM_PUB_EXP_MODE:
        cap_list->cap.rsa_keygen_cap->pub_exp_mode = value;
        break;
    case AMVP_RSA_PARM_INFO_GEN_BY_SERVER:
        rv = is_valid_tf_param(value);
        if (rv != AMVP_SUCCESS) {
            break;
        }
        cap_list->cap.rsa_keygen_cap->info_gen_by_server = value;
        break;
    case AMVP_RSA_PARM_KEY_FORMAT_CRT:
        rv = is_valid_tf_param(value);
        if (rv != AMVP_SUCCESS) {
            break;
        }
        cap_list->cap.rsa_keygen_cap->key_format_crt = value;
        break;
    case AMVP_RSA_PARM_RAND_PQ:
    case AMVP_RSA_PARM_FIXED_PUB_EXP_VAL:
        rv = AMVP_INVALID_ARG;
        AMVP_LOG_ERR("Use amvp_enable_rsa_keygen_mode() or amvp_enable_rsa_keygen_exp_parm() API to enable a new randPQ or exponent.");
        break;
    default:
        rv = AMVP_INVALID_ARG;
        break;
    }
    return rv;
}

AMVP_RESULT amvp_cap_rsa_keygen_enable(AMVP_CTX *ctx,
                                       AMVP_CIPHER cipher,
                                       int (*crypto_handler)(AMVP_TEST_CASE *test_case)) {
    AMVP_RESULT result;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (!crypto_handler) {
        AMVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return AMVP_INVALID_ARG;
    }

    if (cipher != AMVP_RSA_KEYGEN) {
        AMVP_LOG_ERR("Invalid parameter 'cipher'");
        return AMVP_INVALID_ARG;
    }

    result = amvp_cap_list_append(ctx, AMVP_RSA_KEYGEN_TYPE, cipher, crypto_handler);

    if (result == AMVP_DUP_CIPHER) {
        AMVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == AMVP_MALLOC_FAIL) {
        AMVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

/*
 * The user should call this after invoking amvp_enable_rsa_sigver_cap().
 */
AMVP_RESULT amvp_cap_rsa_sigver_set_parm(AMVP_CTX *ctx,
                                         AMVP_RSA_PARM param,
                                         int value) {
    AMVP_CAPS_LIST *cap_list;

    cap_list = amvp_locate_cap_entry(ctx, AMVP_RSA_SIGVER);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    }

    switch (param) {
    case AMVP_RSA_PARM_PUB_EXP_MODE:
        cap_list->cap.rsa_sigver_cap->pub_exp_mode = value;
        break;
    case AMVP_RSA_PARM_FIXED_PUB_EXP_VAL:
    case AMVP_RSA_PARM_KEY_FORMAT_CRT:
    case AMVP_RSA_PARM_RAND_PQ:
    case AMVP_RSA_PARM_INFO_GEN_BY_SERVER:
    default:
        return AMVP_INVALID_ARG;

        break;
    }
    return AMVP_SUCCESS;
}

/*
 * The user should call this after invoking amvp_enable_rsa_sigver_cap().
 */
AMVP_RESULT amvp_cap_rsa_sigver_set_type(AMVP_CTX *ctx,
                                         AMVP_RSA_SIG_TYPE value) {
    AMVP_CAPS_LIST *cap_list;
    AMVP_RSA_SIG_CAP *sigver_cap;
    AMVP_RESULT result = AMVP_SUCCESS;

    cap_list = amvp_locate_cap_entry(ctx, AMVP_RSA_SIGVER);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    }

    if (!cap_list->cap.rsa_sigver_cap) {
        cap_list->cap.rsa_sigver_cap = calloc(1, sizeof(AMVP_RSA_SIG_CAP));
    }
    sigver_cap = cap_list->cap.rsa_sigver_cap;

    while (sigver_cap) {
        if (!sigver_cap->sig_type) {
            break;
        }
        if (sigver_cap->sig_type == value) {
            return AMVP_DUP_CIPHER;
        }
        if (!sigver_cap->next) {
            sigver_cap->next = calloc(1, sizeof(AMVP_RSA_SIG_CAP));
            sigver_cap = sigver_cap->next;
            break;
        }
        sigver_cap = sigver_cap->next;
    }

    sigver_cap->sig_type = value;
    switch (value) {
    case AMVP_RSA_SIG_TYPE_X931:
        sigver_cap->sig_type_str = AMVP_RSA_SIG_TYPE_X931_STR;
        break;
    case AMVP_RSA_SIG_TYPE_PKCS1V15:
        sigver_cap->sig_type_str = AMVP_RSA_SIG_TYPE_PKCS1V15_STR;
        break;
    case AMVP_RSA_SIG_TYPE_PKCS1PSS:
        sigver_cap->sig_type_str = AMVP_RSA_SIG_TYPE_PKCS1PSS_STR;
        break;
    default:
        break;
    }

    return result;
}

/*
 * The user should call this after invoking amvp_enable_rsa_siggen_cap().
 */
AMVP_RESULT amvp_cap_rsa_siggen_set_type(AMVP_CTX *ctx,
                                         AMVP_RSA_SIG_TYPE value) {
    AMVP_CAPS_LIST *cap_list;
    AMVP_RSA_SIG_CAP *siggen_cap;
    AMVP_RESULT result = AMVP_SUCCESS;

    cap_list = amvp_locate_cap_entry(ctx, AMVP_RSA_SIGGEN);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    }

    if (!cap_list->cap.rsa_siggen_cap) {
        cap_list->cap.rsa_siggen_cap = calloc(1, sizeof(AMVP_RSA_SIG_CAP));
    }
    siggen_cap = cap_list->cap.rsa_siggen_cap;

    while (siggen_cap) {
        if (!siggen_cap->sig_type) {
            break;
        }
        if (siggen_cap->sig_type == value) {
            return AMVP_DUP_CIPHER;
        }
        if (!siggen_cap->next) {
            siggen_cap->next = calloc(1, sizeof(AMVP_RSA_SIG_CAP));
            siggen_cap = siggen_cap->next;
            break;
        }
        siggen_cap = siggen_cap->next;
    }

    siggen_cap->sig_type = value;
    switch (value) {
    case AMVP_RSA_SIG_TYPE_X931:
        siggen_cap->sig_type_str = AMVP_RSA_SIG_TYPE_X931_STR;
        break;
    case AMVP_RSA_SIG_TYPE_PKCS1V15:
        siggen_cap->sig_type_str = AMVP_RSA_SIG_TYPE_PKCS1V15_STR;
        break;
    case AMVP_RSA_SIG_TYPE_PKCS1PSS:
        siggen_cap->sig_type_str = AMVP_RSA_SIG_TYPE_PKCS1PSS_STR;
        break;
    default:
        break;
    }

    return result;
}

/*
 * The user should call this after invoking amvp_enable_rsa_keygen_cap_parm().
 */
AMVP_RESULT amvp_cap_rsa_keygen_set_exponent(AMVP_CTX *ctx,
                                             AMVP_RSA_PARM param,
                                             char *value) {
    AMVP_CAPS_LIST *cap_list = NULL;
    AMVP_RSA_KEYGEN_CAP *cap = NULL;

    cap_list = amvp_locate_cap_entry(ctx, AMVP_RSA_KEYGEN);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    }

    /* Get pointer to rsa keygen cap */
    cap = cap_list->cap.rsa_keygen_cap;

    /*
     * Add the value to the cap
     */
    switch (param) {
    case AMVP_RSA_PARM_FIXED_PUB_EXP_VAL:
        if (cap->pub_exp_mode == AMVP_RSA_PUB_EXP_MODE_FIXED) {
            if (cap->fixed_pub_exp == NULL) {
                unsigned int len = strnlen_s(value, AMVP_CAPABILITY_STR_MAX + 1);

                if (len > AMVP_CAPABILITY_STR_MAX) {
                    AMVP_LOG_ERR("Parameter 'value' string is too long. "
                                 "max allowed is (%d) characters.",
                                 AMVP_CAPABILITY_STR_MAX);
                    return AMVP_INVALID_ARG;
                }

                cap->fixed_pub_exp = calloc(len + 1, sizeof(char));
                strcpy_s(cap->fixed_pub_exp, len + 1, value);
            } else {
                AMVP_LOG_ERR("AMVP_FIXED_PUB_EXP_VAL has already been set.");
                return AMVP_UNSUPPORTED_OP;
            }
        }
        break;
    case AMVP_RSA_PARM_PUB_EXP_MODE:
    case AMVP_RSA_PARM_KEY_FORMAT_CRT:
    case AMVP_RSA_PARM_RAND_PQ:
    case AMVP_RSA_PARM_INFO_GEN_BY_SERVER:
    default:
        return AMVP_INVALID_ARG;
    }

    return AMVP_SUCCESS;
}

/*
 * The user should call this after invoking amvp_enable_rsa_sigver_cap_parm().
 */
AMVP_RESULT amvp_cap_rsa_sigver_set_exponent(AMVP_CTX *ctx,
                                             AMVP_RSA_PARM param,
                                             char *value) {
    AMVP_CAPS_LIST *cap_list = NULL;
    AMVP_RSA_SIG_CAP *cap = NULL;

    cap_list = amvp_locate_cap_entry(ctx, AMVP_RSA_SIGVER);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    }

    /* Get pointer to rsa keygen cap */
    cap = cap_list->cap.rsa_sigver_cap;

    /*
     * Add the value to the cap
     */
    switch (param) {
    case AMVP_RSA_PARM_FIXED_PUB_EXP_VAL:
        if (cap->pub_exp_mode == AMVP_RSA_PUB_EXP_MODE_FIXED) {
            if (cap->fixed_pub_exp == NULL) {
                unsigned int len = strnlen_s(value, AMVP_CAPABILITY_STR_MAX + 1);

                if (len > AMVP_CAPABILITY_STR_MAX) {
                    AMVP_LOG_ERR("Parameter 'value' string is too long. "
                                 "max allowed is (%d) characters.",
                                 AMVP_CAPABILITY_STR_MAX);
                    return AMVP_INVALID_ARG;
                }

                cap->fixed_pub_exp = calloc(len + 1, sizeof(char));
                strcpy_s(cap->fixed_pub_exp, len + 1, value);
            } else {
                AMVP_LOG_ERR("AMVP_FIXED_PUB_EXP_VAL has already been set.");
                return AMVP_UNSUPPORTED_OP;
            }
        }
        break;
    case AMVP_RSA_PARM_PUB_EXP_MODE:
    case AMVP_RSA_PARM_KEY_FORMAT_CRT:
    case AMVP_RSA_PARM_RAND_PQ:
    case AMVP_RSA_PARM_INFO_GEN_BY_SERVER:
    default:
        return AMVP_INVALID_ARG;
    }

    return AMVP_SUCCESS;
}

/*
 * The user should call this after invoking amvp_enable_rsa_cap_parm()
 * and setting the randPQ value.
 */
AMVP_RESULT amvp_cap_rsa_keygen_set_primes(AMVP_CTX *ctx,
                                           AMVP_RSA_KEYGEN_MODE mode,
                                           unsigned int mod,
                                           AMVP_RSA_PRIME_PARAM param,
                                           int value) {
    AMVP_RSA_KEYGEN_CAP *keygen_cap;
    AMVP_CAPS_LIST *cap_list;
    AMVP_RSA_MODE_CAPS_LIST *current_prime = NULL;
    AMVP_RESULT result = AMVP_SUCCESS;
    int found = 0;
    const char *string = NULL;

    cap_list = amvp_locate_cap_entry(ctx, AMVP_RSA_KEYGEN);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    }

    if (!cap_list->cap.rsa_keygen_cap) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    }

    keygen_cap = cap_list->cap.rsa_keygen_cap;
    while (keygen_cap) {
        if (keygen_cap->rand_pq == mode) {
            break;
        } else {
            keygen_cap = keygen_cap->next;
        }
    }

    if (!keygen_cap) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    }

    if (!keygen_cap->mode_capabilities) {
        keygen_cap->mode_capabilities = calloc(1, sizeof(AMVP_RSA_MODE_CAPS_LIST));
        if (!keygen_cap->mode_capabilities) {
            AMVP_LOG_ERR("Malloc Failed -- enable rsa cap parm");
            return AMVP_MALLOC_FAIL;
        }
        keygen_cap->mode_capabilities->modulo = mod;
        current_prime = keygen_cap->mode_capabilities;
    } else {
        current_prime = keygen_cap->mode_capabilities;

        found = 0;
        do {
            if (current_prime->modulo != mod) {
                if (current_prime->next == NULL) {
                    current_prime->next = calloc(1, sizeof(AMVP_RSA_MODE_CAPS_LIST));
                    if (!current_prime->next) {
                        AMVP_LOG_ERR("Malloc Failed -- enable rsa cap parm");
                        return AMVP_MALLOC_FAIL;
                    }
                    current_prime = current_prime->next;
                    current_prime->modulo = mod;
                    found = 1;
                } else {
                    current_prime = current_prime->next;
                }
            } else {
                found = 1;
            }
        } while (!found);
    }

    if (param == AMVP_RSA_PRIME_HASH_ALG) {
        string = amvp_lookup_hash_alg_name(value);
        if (!string) {
            AMVP_LOG_ERR("Invalid 'value' for AMVP_RSA_HASH_ALG");
            return AMVP_INVALID_ARG;
        }
        result = amvp_append_name_list(&current_prime->hash_algs, string);
    } else if (param == AMVP_RSA_PRIME_TEST) {
        string = amvp_lookup_rsa_prime_test_name(value);
        if (!string) {
            AMVP_LOG_ERR("Invalid 'value' for AMVP_RSA_PRIME_TEST");
            return AMVP_INVALID_ARG;
        }
        result = amvp_append_name_list(&current_prime->prime_tests, string);
    } else {
        AMVP_LOG_ERR("Invalid parameter 'param'");
        return AMVP_INVALID_ARG;
    }

    return result;
}

/*
 * The user should call this after invoking amvp_enable_rsa_sigver_cap()
 * and setting the randPQ value.
 *
 * Set parameters for a specific modulo value.
 */
AMVP_RESULT amvp_cap_rsa_sigver_set_mod_parm(AMVP_CTX *ctx,
                                             AMVP_RSA_SIG_TYPE sig_type,
                                             unsigned int mod,
                                             int hash_alg,
                                             int salt_len) {
    AMVP_RSA_SIG_CAP *sigver_cap;
    AMVP_CAPS_LIST *cap_list;
    AMVP_RSA_MODE_CAPS_LIST *current_cap = NULL;
    AMVP_RSA_HASH_PAIR_LIST *current_hash = NULL;
    const char *string = NULL;
    int found = 0;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (!hash_alg || !mod) {
        AMVP_LOG_ERR("Must specify mod and hash_alg");
        return AMVP_INVALID_ARG;
    }

    cap_list = amvp_locate_cap_entry(ctx, AMVP_RSA_SIGVER);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    }

    sigver_cap = cap_list->cap.rsa_sigver_cap;
    while (sigver_cap) {
        if (sigver_cap->sig_type != sig_type) {
            sigver_cap = sigver_cap->next;
        } else {
            break;
        }
    }
    if (!sigver_cap) {
        return AMVP_NO_CAP;
    }

    if (!sigver_cap->mode_capabilities) {
        sigver_cap->mode_capabilities = calloc(1, sizeof(AMVP_RSA_MODE_CAPS_LIST));
        if (!sigver_cap->mode_capabilities) {
            AMVP_LOG_ERR("Malloc Failed -- enable rsa cap parm");
            return AMVP_MALLOC_FAIL;
        }
        sigver_cap->mode_capabilities->modulo = mod;
        current_cap = sigver_cap->mode_capabilities;
    } else {
        current_cap = sigver_cap->mode_capabilities;

        found = 0;
        do {
            if (current_cap->modulo != mod) {
                if (current_cap->next == NULL) {
                    current_cap->next = calloc(1, sizeof(AMVP_RSA_MODE_CAPS_LIST));
                    if (!current_cap->next) {
                        AMVP_LOG_ERR("Malloc Failed -- enable rsa cap parm");
                        return AMVP_MALLOC_FAIL;
                    }
                    current_cap = current_cap->next;
                    current_cap->modulo = mod;
                    found = 1;
                } else {
                    current_cap = current_cap->next;
                }
            } else {
                found = 1;
            }
        } while (!found);
    }

    string = amvp_lookup_hash_alg_name(hash_alg);
    if (!string) {
        AMVP_LOG_ERR("Invalid parameter 'hash_alg'");
    }

    if (!current_cap->hash_pair) {
        current_cap->hash_pair = calloc(1, sizeof(AMVP_RSA_HASH_PAIR_LIST));
        if (!current_cap->hash_pair) {
            AMVP_LOG_ERR("Malloc Failed -- enable rsa cap parm");
            return AMVP_MALLOC_FAIL;
        }
        current_cap->hash_pair->name = string;
        if (salt_len) {
            current_cap->hash_pair->salt = salt_len;
        }
    } else {
        current_hash = current_cap->hash_pair;
        while (current_hash->next != NULL) {
            current_hash = current_hash->next;
        }
        current_hash->next = calloc(1, sizeof(AMVP_RSA_HASH_PAIR_LIST));
        if (!current_hash->next) {
            AMVP_LOG_ERR("Malloc Failed -- enable rsa cap parm");
            return AMVP_MALLOC_FAIL;
        }
        current_hash->next->name = string;
        if (salt_len) {
            current_hash->next->salt = salt_len;
        }
    }

    return AMVP_SUCCESS;
}

/*
 * The user should call this after invoking amvp_enable_rsa_siggen_cap()
 * and setting the randPQ value.
 */
AMVP_RESULT amvp_cap_rsa_siggen_set_mod_parm(AMVP_CTX *ctx,
                                             AMVP_RSA_SIG_TYPE sig_type,
                                             unsigned int mod,
                                             int hash_alg,
                                             int salt_len) {
    AMVP_RSA_SIG_CAP *siggen_cap;
    AMVP_CAPS_LIST *cap_list;
    AMVP_RSA_MODE_CAPS_LIST *current_cap = NULL;
    AMVP_RSA_HASH_PAIR_LIST *current_hash = NULL;
    const char *string = NULL;
    int found = 0;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (!hash_alg || !mod) {
        AMVP_LOG_ERR("Must specify mod and hash_alg");
        return AMVP_INVALID_ARG;
    }

    cap_list = amvp_locate_cap_entry(ctx, AMVP_RSA_SIGGEN);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    }

    siggen_cap = cap_list->cap.rsa_siggen_cap;
    while (siggen_cap) {
        if (siggen_cap->sig_type != sig_type) {
            siggen_cap = siggen_cap->next;
        } else {
            break;
        }
    }
    if (!siggen_cap) {
        return AMVP_NO_CAP;
    }

    if (!siggen_cap->mode_capabilities) {
        siggen_cap->mode_capabilities = calloc(1, sizeof(AMVP_RSA_MODE_CAPS_LIST));
        if (!siggen_cap->mode_capabilities) {
            AMVP_LOG_ERR("Malloc Failed -- enable rsa cap parm");
            return AMVP_MALLOC_FAIL;
        }
        siggen_cap->mode_capabilities->modulo = mod;
        current_cap = siggen_cap->mode_capabilities;
    } else {
        current_cap = siggen_cap->mode_capabilities;

        found = 0;
        do {
            if (current_cap->modulo != mod) {
                if (current_cap->next == NULL) {
                    current_cap->next = calloc(1, sizeof(AMVP_RSA_MODE_CAPS_LIST));
                    if (!current_cap->next) {
                        AMVP_LOG_ERR("Malloc Failed -- enable rsa cap parm");
                        return AMVP_MALLOC_FAIL;
                    }
                    current_cap = current_cap->next;
                    current_cap->modulo = mod;
                    found = 1;
                } else {
                    current_cap = current_cap->next;
                }
            } else {
                found = 1;
            }
        } while (!found);
    }

    string = amvp_lookup_hash_alg_name(hash_alg);
    if (!string) {
        AMVP_LOG_ERR("Invalid parameter 'hash_alg'");
    }

    if (!current_cap->hash_pair) {
        current_cap->hash_pair = calloc(1, sizeof(AMVP_RSA_HASH_PAIR_LIST));
        if (!current_cap->hash_pair) {
            AMVP_LOG_ERR("Malloc Failed -- enable rsa cap parm");
            return AMVP_MALLOC_FAIL;
        }
        current_cap->hash_pair->name = string;
        if (salt_len) {
            current_cap->hash_pair->salt = salt_len;
        }
    } else {
        current_hash = current_cap->hash_pair;
        while (current_hash->next != NULL) {
            current_hash = current_hash->next;
        }
        current_hash->next = calloc(1, sizeof(AMVP_RSA_HASH_PAIR_LIST));
        if (!current_hash->next) {
            AMVP_LOG_ERR("Malloc Failed -- enable rsa cap parm");
            return AMVP_MALLOC_FAIL;
        }
        current_hash->next->name = string;
        if (salt_len) {
            current_hash->next->salt = salt_len;
        }
    }

    return AMVP_SUCCESS;
}

static AMVP_RESULT internal_cap_rsa_sig_enable(AMVP_CTX *ctx,
                                               AMVP_CIPHER cipher,
                                               int (*crypto_handler)(AMVP_TEST_CASE *test_case)) {
    AMVP_CAP_TYPE type = 0;
    AMVP_RESULT result = AMVP_SUCCESS;
    AMVP_SUB_RSA alg;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (!crypto_handler) {
        return AMVP_INVALID_ARG;
    }

    alg = amvp_get_rsa_alg(cipher);
    if (alg == 0) {
        AMVP_LOG_ERR("Invalid cipher value");
        return AMVP_INVALID_ARG;
    }
    switch (alg) {
    case AMVP_SUB_RSA_SIGGEN:
        type = AMVP_RSA_SIGGEN_TYPE;
        break;
    case AMVP_SUB_RSA_SIGVER:
        type = AMVP_RSA_SIGVER_TYPE;
        break;
    case AMVP_SUB_RSA_SIGPRIM:
    case AMVP_SUB_RSA_DECPRIM:
        type = AMVP_RSA_PRIM_TYPE;
        break;
    case AMVP_SUB_RSA_KEYGEN:
    default:
        return AMVP_INVALID_ARG;
    }

    result = amvp_cap_list_append(ctx, type, cipher, crypto_handler);

    return result;
}

AMVP_RESULT amvp_cap_rsa_sig_enable(AMVP_CTX *ctx,
                                    AMVP_CIPHER cipher,
                                    int (*crypto_handler)(AMVP_TEST_CASE *test_case)) {
    AMVP_RESULT result = AMVP_SUCCESS;
    const char *cap_message_str = NULL;
    AMVP_SUB_RSA alg;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (!crypto_handler) {
        AMVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return AMVP_INVALID_ARG;
    }

    alg = amvp_get_rsa_alg(cipher);
    if (alg == 0) {
        AMVP_LOG_ERR("Invalid cipher value");
        return AMVP_INVALID_ARG;
    }
    switch (alg) {
    case AMVP_SUB_RSA_SIGGEN:
        cap_message_str = "AMVP_RSA_SIGGEN";
        break;
    case AMVP_SUB_RSA_SIGVER:
        cap_message_str = "AMVP_RSA_SIGVER";
        break;
    case AMVP_SUB_RSA_KEYGEN:
    case AMVP_SUB_RSA_DECPRIM:
    case AMVP_SUB_RSA_SIGPRIM:
    default:
        AMVP_LOG_ERR("Invalid parameter 'cipher'");
        return AMVP_INVALID_ARG;
    }

    result = internal_cap_rsa_sig_enable(ctx, cipher, crypto_handler);

    if (result == AMVP_DUP_CIPHER) {
        AMVP_LOG_ERR("Capability (%s) previously enabled. Duplicate not allowed.",
                     cap_message_str);
    } else if (result == AMVP_MALLOC_FAIL) {
        AMVP_LOG_ERR("Failed to allocate (%s) capability object",
                     cap_message_str);
    }

    return result;
}
AMVP_RESULT amvp_cap_rsa_prim_enable(AMVP_CTX *ctx,
                                     AMVP_CIPHER cipher,
                                     int (*crypto_handler)(AMVP_TEST_CASE *test_case)) {
    AMVP_RESULT result;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (!crypto_handler) {
        AMVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return AMVP_INVALID_ARG;
    }

    if ((cipher != AMVP_RSA_SIGPRIM) && (cipher != AMVP_RSA_DECPRIM)) {
        AMVP_LOG_ERR("Invalid parameter 'cipher'");
        return AMVP_INVALID_ARG;
    }

    result = amvp_cap_list_append(ctx, AMVP_RSA_PRIM_TYPE, cipher, crypto_handler);

    if (result == AMVP_DUP_CIPHER) {
        AMVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == AMVP_MALLOC_FAIL) {
        AMVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

/*
 * The user should call this after invoking amvp_enable_rsa_prim_cap().
 */
AMVP_RESULT amvp_cap_rsa_prim_set_parm(AMVP_CTX *ctx,
                                       AMVP_RSA_PARM param,
                                       int value) {
    AMVP_CAPS_LIST *cap_list;
    AMVP_RESULT rv = AMVP_SUCCESS;

    cap_list = amvp_locate_cap_entry(ctx, AMVP_RSA_SIGPRIM);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    }

    switch (param) {
    case AMVP_RSA_PARM_PUB_EXP_MODE:
        cap_list->cap.rsa_prim_cap->pub_exp_mode = value;
        break;
    case AMVP_RSA_PARM_KEY_FORMAT_CRT:
        rv = is_valid_tf_param(value);
        if (rv != AMVP_SUCCESS) {
            break;
        }
        cap_list->cap.rsa_prim_cap->key_format_crt = value;
        break;
    case AMVP_RSA_PARM_FIXED_PUB_EXP_VAL:
    case AMVP_RSA_PARM_RAND_PQ:
    case AMVP_RSA_PARM_INFO_GEN_BY_SERVER:
    default:
        rv = AMVP_INVALID_ARG;
        break;
    }
    return rv;
}

/*
 * The user should call this after invoking amvp_enable_rsa_prim_cap_parm().
 */
AMVP_RESULT amvp_cap_rsa_prim_set_exponent(AMVP_CTX *ctx,
                                             AMVP_RSA_PARM param,
                                             char *value) {
    AMVP_CAPS_LIST *cap_list = NULL;
    AMVP_RSA_PRIM_CAP *cap = NULL;

    cap_list = amvp_locate_cap_entry(ctx, AMVP_RSA_SIGPRIM);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    }

    /* Get pointer to rsa prim cap */
    cap = cap_list->cap.rsa_prim_cap;

    /*
     * Add the value to the cap
     */
    switch (param) {
    case AMVP_RSA_PARM_FIXED_PUB_EXP_VAL:
        if (cap->pub_exp_mode == AMVP_RSA_PUB_EXP_MODE_FIXED) {
            if (cap->fixed_pub_exp == NULL) {
                unsigned int len = strnlen_s(value, AMVP_CAPABILITY_STR_MAX + 1);

                if (len > AMVP_CAPABILITY_STR_MAX) {
                    AMVP_LOG_ERR("Parameter 'value' string is too long. "
                                 "max allowed is (%d) characters.",
                                 AMVP_CAPABILITY_STR_MAX);
                    return AMVP_INVALID_ARG;
                }

                cap->fixed_pub_exp = calloc(len + 1, sizeof(char));
                strcpy_s(cap->fixed_pub_exp, len + 1, value);
            } else {
                AMVP_LOG_ERR("AMVP_FIXED_PUB_EXP_VAL has already been set.");
                return AMVP_UNSUPPORTED_OP;
            }
        }
        break;
    case AMVP_RSA_PARM_PUB_EXP_MODE:
    case AMVP_RSA_PARM_KEY_FORMAT_CRT:
    case AMVP_RSA_PARM_RAND_PQ:
    case AMVP_RSA_PARM_INFO_GEN_BY_SERVER:
    default:
        return AMVP_INVALID_ARG;
    }

    return AMVP_SUCCESS;
}


/*
 * The user should call this after invoking amvp_enable_ecdsa_cap().
 */
AMVP_RESULT amvp_cap_ecdsa_set_parm(AMVP_CTX *ctx,
                                    AMVP_CIPHER cipher,
                                    AMVP_ECDSA_PARM param,
                                    int value) {
    AMVP_CAPS_LIST *cap_list;
    AMVP_CURVE_ALG_COMPAT_LIST *current_curve;
    AMVP_ECDSA_CAP *cap;
    const char *string = NULL;
    AMVP_SUB_ECDSA alg;
    AMVP_RESULT result = AMVP_SUCCESS;

    cap_list = amvp_locate_cap_entry(ctx, cipher);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    }

    alg = amvp_get_ecdsa_alg(cipher);
    if (alg == 0) {
        AMVP_LOG_ERR("Invalid cipher value");
        return AMVP_INVALID_ARG;
    }
    switch (alg) {
    case AMVP_SUB_ECDSA_KEYGEN:
        cap = cap_list->cap.ecdsa_keygen_cap;
        break;
    case AMVP_SUB_ECDSA_KEYVER:
        cap = cap_list->cap.ecdsa_keyver_cap;
        break;
    case AMVP_SUB_ECDSA_SIGGEN:
        cap = cap_list->cap.ecdsa_siggen_cap;
        break;
    case AMVP_SUB_ECDSA_SIGVER:
        cap = cap_list->cap.ecdsa_sigver_cap;
        break;
    default:
        return AMVP_INVALID_ARG;
    }

    if (!value) {
        return AMVP_MISSING_ARG;
    }

    switch (param) {
    case AMVP_ECDSA_CURVE:
        if (value <= AMVP_EC_CURVE_START || value >= AMVP_EC_CURVE_END) {
            AMVP_LOG_ERR("Invalid 'value' for AMVP_ECDSA_CURVE");
            return AMVP_INVALID_ARG;
        }

        current_curve = cap->curves;
        if (current_curve) {
            while (current_curve->next) {
                current_curve = current_curve->next;
            }
            current_curve->next = calloc(1, sizeof(AMVP_CURVE_ALG_COMPAT_LIST));
            current_curve->next->curve = value;
        } else {
            cap->curves = calloc(1, sizeof(AMVP_CURVE_ALG_COMPAT_LIST));
            cap->curves->curve = value;
        }
        break;
    case AMVP_ECDSA_SECRET_GEN:
        if (cipher != AMVP_ECDSA_KEYGEN) {
            return AMVP_INVALID_ARG;
        }

        switch (value) {
        case AMVP_ECDSA_SECRET_GEN_EXTRA_BITS:
            string = AMVP_ECDSA_EXTRA_BITS_STR;
            break;
        case AMVP_ECDSA_SECRET_GEN_TEST_CAND:
            string = AMVP_ECDSA_TESTING_CANDIDATES_STR;
            break;
        default:
            AMVP_LOG_ERR("Invalid 'value' for AMVP_ECDSA_SECRET_GEN");
            return AMVP_INVALID_ARG;
        }

        result = amvp_append_name_list(&cap->secret_gen_modes, string);
        break;
    case AMVP_ECDSA_HASH_ALG:
        if (cipher != AMVP_ECDSA_SIGGEN && cipher != AMVP_ECDSA_SIGVER) {
            return AMVP_INVALID_ARG;
        }

        if (value <= AMVP_NO_SHA || value >= AMVP_HASH_ALG_MAX || (value & (value - 1)) != 0) {
            AMVP_LOG_ERR("Invalid 'value' for AMVP_ECDSA_HASH_ALG");
            return AMVP_INVALID_ARG;
        }

        cap->hash_algs[value] = 1;
        break;
    case AMVP_ECDSA_COMPONENT_TEST:
        if (cipher == AMVP_ECDSA_SIGGEN || cipher == AMVP_ECDSA_SIGVER) {
            if (value >= AMVP_ECDSA_COMPONENT_MODE_NO && value <= AMVP_ECDSA_COMPONENT_MODE_BOTH) {
                if (value == AMVP_ECDSA_COMPONENT_MODE_BOTH) {
                    /* This will generate two vector sets, one for and one not for component mode */
                    ctx->vs_count++;
                }
                cap->component = value;
            } else {
                AMVP_LOG_ERR("Invalid value given for ECDSA component test mode");
                return AMVP_INVALID_ARG;
            }
        } else {
            AMVP_LOG_ERR("ECDSA Component Tests only apply to siggen and sigver");
            return AMVP_INVALID_ARG;
        }
        break;
    default:
        return AMVP_INVALID_ARG;
        break;
    }

    return result;
}

AMVP_RESULT amvp_cap_ecdsa_set_curve_hash_alg(AMVP_CTX *ctx, AMVP_CIPHER cipher, AMVP_EC_CURVE curve, AMVP_HASH_ALG alg) {
    AMVP_CAPS_LIST *cap;
    AMVP_ECDSA_CAP *ecdsa_cap;
    AMVP_CURVE_ALG_COMPAT_LIST *list;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (curve <= AMVP_EC_CURVE_START || curve >= AMVP_EC_CURVE_END) {
        AMVP_LOG_ERR("Invalid 'curve' argument for amvp_cap_ecdsa_set_curve_hash_alg");
        return AMVP_INVALID_ARG;
    }

    if (alg <= AMVP_NO_SHA || alg >= AMVP_HASH_ALG_MAX || (alg & (alg - 1)) != 0) {
        AMVP_LOG_ERR("Invalid 'alg' argument for amvp_cap_ecdsa_set_curve_hash_alg");
        return AMVP_INVALID_ARG;
    }

    cap = amvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        return AMVP_NO_CAP;
    }

    if (cipher == AMVP_ECDSA_SIGGEN) {
        ecdsa_cap = cap->cap.ecdsa_siggen_cap;
    } else if (cipher == AMVP_ECDSA_SIGVER) {
        ecdsa_cap = cap->cap.ecdsa_sigver_cap;
    } else {
        AMVP_LOG_ERR("Invalid 'cipher' argument for amvp_cap_ecdsa_set_curve_hash_alg");
        return AMVP_INVALID_ARG;
    }

    list = ecdsa_cap->curves;

    while (list) {
        if (curve == list->curve) {
            list->algs[alg] = 1;
            return AMVP_SUCCESS;
        }
        list = list->next;
    }

    AMVP_LOG_ERR("Curve not yet enabled. Please enable the given curve before setting its hash algs");
    return AMVP_UNSUPPORTED_OP;
}

AMVP_RESULT amvp_cap_ecdsa_enable(AMVP_CTX *ctx,
                                  AMVP_CIPHER cipher,
                                  int (*crypto_handler)(AMVP_TEST_CASE *test_case)) {
    AMVP_CAP_TYPE type = 0;
    AMVP_RESULT result = AMVP_SUCCESS;
    AMVP_SUB_ECDSA alg;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (!crypto_handler) {
        AMVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return AMVP_INVALID_ARG;
    }

    alg = amvp_get_ecdsa_alg(cipher);
    if (alg == 0) {
        AMVP_LOG_ERR("Invalid cipher value");
        return AMVP_INVALID_ARG;
    }
    switch (alg) {
    case AMVP_SUB_ECDSA_KEYGEN:
        type = AMVP_ECDSA_KEYGEN_TYPE;
        break;
    case AMVP_SUB_ECDSA_KEYVER:
        type = AMVP_ECDSA_KEYVER_TYPE;
        break;
    case AMVP_SUB_ECDSA_SIGGEN:
        type = AMVP_ECDSA_SIGGEN_TYPE;
        break;
    case AMVP_SUB_ECDSA_SIGVER:
        type = AMVP_ECDSA_SIGVER_TYPE;
        break;
    default:
        AMVP_LOG_ERR("Invalid parameter 'cipher'");
        return AMVP_INVALID_ARG;
    }

    result = amvp_cap_list_append(ctx, type, cipher, crypto_handler);

    if (result == AMVP_DUP_CIPHER) {
        AMVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == AMVP_MALLOC_FAIL) {
        AMVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

/*
 * The user should call this after invoking amvp_enable_dsa_cap().
 */
AMVP_RESULT amvp_cap_dsa_set_parm(AMVP_CTX *ctx,
                                  AMVP_CIPHER cipher,
                                  AMVP_DSA_MODE mode,
                                  AMVP_DSA_PARM param,
                                  int value) {
    AMVP_DSA_CAP_MODE *dsa_cap_mode;
    AMVP_DSA_CAP *dsa_cap;
    AMVP_CAPS_LIST *cap_list;
    AMVP_RESULT result;


    /*
     * Locate this cipher in the caps array
     */
    cap_list = amvp_locate_cap_entry(ctx, cipher);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    }
    dsa_cap = cap_list->cap.dsa_cap;

    /* range check mode */
    dsa_cap_mode = &dsa_cap->dsa_cap_mode[mode - 1];
    dsa_cap_mode->defined = 1;

    /*
     * Add the value to the cap
     */
    switch (mode) {
    case AMVP_DSA_MODE_PQGGEN:
        result = amvp_add_dsa_pqggen_parm(ctx, dsa_cap_mode, param, value);
        if (result != AMVP_SUCCESS)
            AMVP_LOG_ERR("Invalid param to enable_dsa_cap_parm.");
        break;
    case AMVP_DSA_MODE_PQGVER:
        result = amvp_add_dsa_pqggen_parm(ctx, dsa_cap_mode, param, value);
        if (result != AMVP_SUCCESS)
            AMVP_LOG_ERR("Invalid param to enable_dsa_cap_parm.");
        break;
    case AMVP_DSA_MODE_KEYGEN:
        result = amvp_add_dsa_keygen_parm(ctx, dsa_cap_mode, param, value);
        if (result != AMVP_SUCCESS)
            AMVP_LOG_ERR("Invalid param to enable_dsa_cap_parm.");
        break;
    case AMVP_DSA_MODE_SIGGEN:
        result = amvp_add_dsa_pqggen_parm(ctx, dsa_cap_mode, param, value);
        if (result != AMVP_SUCCESS)
            AMVP_LOG_ERR("Invalid param to enable_dsa_cap_parm.");
        break;
    case AMVP_DSA_MODE_SIGVER:
        result = amvp_add_dsa_pqggen_parm(ctx, dsa_cap_mode, param, value);
        if (result != AMVP_SUCCESS)
            AMVP_LOG_ERR("Invalid param to enable_dsa_cap_parm.");
        break;
    default:
        return AMVP_INVALID_ARG;
    }

    return result;
}

/*
 * The user should call this after invoking amvp_enable_kdf135_snmp_cap()
 * to specify kdf parameters
 */
AMVP_RESULT amvp_cap_kdf135_snmp_set_parm(AMVP_CTX *ctx,
                                          AMVP_CIPHER kcap,
                                          AMVP_KDF135_SNMP_PARAM param,
                                          int value) {
    AMVP_CAPS_LIST *cap;
    AMVP_KDF135_SNMP_CAP *kdf135_snmp_cap;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (param != AMVP_KDF135_SNMP_PASS_LEN) {
        return AMVP_INVALID_ARG;
    }

    if (value < AMVP_KDF135_SNMP_PASS_LEN_MIN ||
        value > AMVP_KDF135_SNMP_PASS_LEN_MAX) {
        AMVP_LOG_ERR("Invalid pass len");
        return AMVP_INVALID_ARG;
    }

    cap = amvp_locate_cap_entry(ctx, kcap);
    if (!cap) {
        return AMVP_NO_CAP;
    }

    kdf135_snmp_cap = cap->cap.kdf135_snmp_cap;
    if (!kdf135_snmp_cap) {
        return AMVP_NO_CAP;
    }

    amvp_append_sl_list(&kdf135_snmp_cap->pass_lens, value);

    return AMVP_SUCCESS;
}

/*
 * The user should call this after invoking amvp_enable_kdf135_snmp_cap()
 * to specify the hex string engine id. amvp_enable_kdf135_snmp_cap_parm()
 * should be used to specify password length
 */
AMVP_RESULT amvp_cap_kdf135_snmp_set_engid(AMVP_CTX *ctx,
                                           AMVP_CIPHER kcap,
                                           const char *engid) {
    AMVP_CAPS_LIST *cap;
    AMVP_KDF135_SNMP_CAP *kdf135_snmp_cap;
    AMVP_RESULT result = AMVP_SUCCESS;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (!engid) {
        return AMVP_INVALID_ARG;
    }
    if (strnlen_s(engid, AMVP_KDF135_SNMP_ENGID_MAX_STR + 1) > AMVP_KDF135_SNMP_ENGID_MAX_STR) {
        AMVP_LOG_ERR("engid too long");
        return AMVP_INVALID_ARG;
    }

    cap = amvp_locate_cap_entry(ctx, kcap);
    if (!cap) {
        return AMVP_NO_CAP;
    }

    kdf135_snmp_cap = cap->cap.kdf135_snmp_cap;
    if (!kdf135_snmp_cap) {
        return AMVP_NO_CAP;
    }

    result = amvp_append_name_list(&kdf135_snmp_cap->eng_ids, engid);

    return result;
}

AMVP_RESULT amvp_cap_kdf135_srtp_enable(AMVP_CTX *ctx,
                                        int (*crypto_handler)(AMVP_TEST_CASE *test_case)) {
    AMVP_RESULT result = AMVP_SUCCESS;

    if (!ctx) {
        return AMVP_NO_CTX;
    }
    if (!crypto_handler) {
        AMVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return AMVP_INVALID_ARG;
    }

    result = amvp_cap_list_append(ctx, AMVP_KDF135_SRTP_TYPE, AMVP_KDF135_SRTP, crypto_handler);

    if (result == AMVP_DUP_CIPHER) {
        AMVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == AMVP_MALLOC_FAIL) {
        AMVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

AMVP_RESULT amvp_cap_kdf135_ikev2_enable(AMVP_CTX *ctx,
                                         int (*crypto_handler)(AMVP_TEST_CASE *test_case)) {
    AMVP_RESULT result = AMVP_SUCCESS;

    if (!ctx) {
        return AMVP_NO_CTX;
    }
    if (!crypto_handler) {
        AMVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return AMVP_INVALID_ARG;
    }

    result = amvp_cap_list_append(ctx, AMVP_KDF135_IKEV2_TYPE, AMVP_KDF135_IKEV2, crypto_handler);

    if (result == AMVP_DUP_CIPHER) {
        AMVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == AMVP_MALLOC_FAIL) {
        AMVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}


AMVP_RESULT amvp_cap_kdf135_x942_enable(AMVP_CTX *ctx,
                                        int (*crypto_handler)(AMVP_TEST_CASE *test_case)) {
    AMVP_RESULT result = AMVP_SUCCESS;

    if (!ctx) {
        return AMVP_NO_CTX;
    }
    if (!crypto_handler) {
        AMVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return AMVP_INVALID_ARG;
    }

    result = amvp_cap_list_append(ctx, AMVP_KDF135_X942_TYPE, AMVP_KDF135_X942, crypto_handler);

    if (result == AMVP_DUP_CIPHER) {
        AMVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == AMVP_MALLOC_FAIL) {
        AMVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}


AMVP_RESULT amvp_cap_kdf135_x963_enable(AMVP_CTX *ctx,
                                        int (*crypto_handler)(AMVP_TEST_CASE *test_case)) {
    AMVP_RESULT result = AMVP_SUCCESS;

    if (!ctx) {
        return AMVP_NO_CTX;
    }
    if (!crypto_handler) {
        AMVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return AMVP_INVALID_ARG;
    }

    result = amvp_cap_list_append(ctx, AMVP_KDF135_X963_TYPE, AMVP_KDF135_X963, crypto_handler);

    if (result == AMVP_DUP_CIPHER) {
        AMVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == AMVP_MALLOC_FAIL) {
        AMVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

AMVP_RESULT amvp_cap_kdf135_ikev1_enable(AMVP_CTX *ctx,
                                         int (*crypto_handler)(AMVP_TEST_CASE *test_case)) {
    AMVP_RESULT result = AMVP_SUCCESS;

    if (!ctx) {
        return AMVP_NO_CTX;
    }
    if (!crypto_handler) {
        AMVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return AMVP_INVALID_ARG;
    }

    result = amvp_cap_list_append(ctx, AMVP_KDF135_IKEV1_TYPE, AMVP_KDF135_IKEV1, crypto_handler);

    if (result == AMVP_DUP_CIPHER) {
        AMVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == AMVP_MALLOC_FAIL) {
        AMVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

AMVP_RESULT amvp_cap_kdf108_enable(AMVP_CTX *ctx,
                                   int (*crypto_handler)(AMVP_TEST_CASE *test_case)) {
    AMVP_RESULT result = AMVP_SUCCESS;

    if (!ctx) {
        return AMVP_NO_CTX;
    }
    if (!crypto_handler) {
        AMVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return AMVP_INVALID_ARG;
    }

    result = amvp_cap_list_append(ctx, AMVP_KDF108_TYPE, AMVP_KDF108, crypto_handler);

    if (result == AMVP_DUP_CIPHER) {
        AMVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == AMVP_MALLOC_FAIL) {
        AMVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

AMVP_RESULT amvp_cap_kdf135_snmp_enable(AMVP_CTX *ctx,
                                        int (*crypto_handler)(AMVP_TEST_CASE *test_case)) {
    AMVP_RESULT result = AMVP_SUCCESS;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (!crypto_handler) {
        AMVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return AMVP_INVALID_ARG;
    }

    result = amvp_cap_list_append(ctx, AMVP_KDF135_SNMP_TYPE, AMVP_KDF135_SNMP, crypto_handler);

    if (result == AMVP_DUP_CIPHER) {
        AMVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == AMVP_MALLOC_FAIL) {
        AMVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

AMVP_RESULT amvp_cap_kdf135_ssh_enable(AMVP_CTX *ctx,
                                       int (*crypto_handler)(AMVP_TEST_CASE *test_case)) {
    AMVP_RESULT result = AMVP_SUCCESS;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (!crypto_handler) {
        AMVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return AMVP_INVALID_ARG;
    }

    result = amvp_cap_list_append(ctx, AMVP_KDF135_SSH_TYPE, AMVP_KDF135_SSH, crypto_handler);

    if (result == AMVP_DUP_CIPHER) {
        AMVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == AMVP_MALLOC_FAIL) {
        AMVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

AMVP_RESULT amvp_cap_pbkdf_enable(AMVP_CTX *ctx,
                                  int (*crypto_handler) (AMVP_TEST_CASE *test_case)) {
    AMVP_RESULT result = AMVP_SUCCESS;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (!crypto_handler) {
        AMVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return AMVP_INVALID_ARG;
    }

    result = amvp_cap_list_append(ctx, AMVP_PBKDF_TYPE, AMVP_PBKDF, crypto_handler);

    if (result == AMVP_DUP_CIPHER) {
        AMVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == AMVP_MALLOC_FAIL) {
        AMVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

AMVP_RESULT amvp_cap_pbkdf_set_domain(AMVP_CTX *ctx,
                                      AMVP_PBKDF_PARM param,
                                      int min, int max, 
                                      int increment) {
    AMVP_CAPS_LIST *cap_list;
    AMVP_JSON_DOMAIN_OBJ *domain;

    cap_list = amvp_locate_cap_entry(ctx, AMVP_PBKDF);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    } else if (max < min || increment < 1) {
        AMVP_LOG_ERR("Invalid domain values given");
        return AMVP_INVALID_ARG;
    }

    switch (param) {
    case AMVP_PBKDF_ITERATION_COUNT:
        if (min < AMVP_PBKDF_ITERATION_MIN ||
            max > AMVP_PBKDF_ITERATION_MAX) {
            AMVP_LOG_ERR("min or max outside of acceptable range");
            return AMVP_INVALID_ARG;
        }
        domain = &cap_list->cap.pbkdf_cap->iteration_count_domain;
        break;
    case AMVP_PBKDF_KEY_LEN:
        if (min < AMVP_PBKDF_KEY_BIT_MIN ||
            max > AMVP_PBKDF_KEY_BIT_MAX) {
            AMVP_LOG_ERR("min or max outside of acceptable range");
            return AMVP_INVALID_ARG;
        }
        domain = &cap_list->cap.pbkdf_cap->key_len_domain;
        break;
    case AMVP_PBKDF_PASSWORD_LEN:
        if (min < AMVP_PBKDF_PASS_LEN_MIN ||
            max > AMVP_PBKDF_PASS_LEN_MAX) {
            AMVP_LOG_ERR("min or max outside of acceptable range");
            return AMVP_INVALID_ARG;
        }
        domain = &cap_list->cap.pbkdf_cap->password_len_domain;
        break;
    case AMVP_PBKDF_SALT_LEN:
        if (min < AMVP_PBKDF_SALT_LEN_BIT_MIN ||
            max > AMVP_PBKDF_SALT_LEN_BIT_MAX) {
            AMVP_LOG_ERR("min or max outside of acceptable range");
            return AMVP_INVALID_ARG;
        }
        domain = &cap_list->cap.pbkdf_cap->salt_len_domain;
        break;
    case AMVP_PBKDF_PARAM_MIN:
    case AMVP_PBKDF_HMAC_ALG:
    default:
        return AMVP_INVALID_ARG;
    }

    domain->min = min;
    domain->max = max;
    domain->increment = increment;

    return AMVP_SUCCESS;

}

AMVP_RESULT amvp_cap_pbkdf_set_parm(AMVP_CTX *ctx,
                                    AMVP_PBKDF_PARM param,
                                    int value) {
    AMVP_CAPS_LIST *cap_list = NULL;
    AMVP_PBKDF_CAP *cap = NULL;
    const char *alg_str = NULL;
    AMVP_RESULT result = AMVP_SUCCESS;

    cap_list = amvp_locate_cap_entry(ctx, AMVP_PBKDF);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found. You must enable algorithm before setting parameters.");
        return AMVP_NO_CAP;
    }
    cap = cap_list->cap.pbkdf_cap;

    if (param != AMVP_PBKDF_HMAC_ALG) {
        AMVP_LOG_ERR("Invalid param.");
        return AMVP_INVALID_ARG;
    }

    alg_str = amvp_lookup_hash_alg_name(value);
    if (!alg_str) {
        AMVP_LOG_ERR("Invalid value specified for PBKDF hmac alg.");
        return AMVP_INVALID_ARG;
    }
    if (amvp_is_in_name_list(cap->hmac_algs, alg_str)) {
        AMVP_LOG_WARN("Attempting to register an hmac alg with PBKDF that has already been registered, skipping.");
    } else {
        result = amvp_append_name_list(&cap->hmac_algs, alg_str);
    }
    return result;
}

/*
 * The user should call this after invoking amvp_enable_kdf135_ssh_cap()
 * to specify the kdf parameters.
 */
AMVP_RESULT amvp_cap_kdf135_ssh_set_parm(AMVP_CTX *ctx,
                                         AMVP_CIPHER kcap,
                                         AMVP_KDF135_SSH_METHOD method,
                                         AMVP_HASH_ALG param) {
    AMVP_CAPS_LIST *cap;
    AMVP_KDF135_SSH_CAP *kdf135_ssh_cap;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    cap = amvp_locate_cap_entry(ctx, kcap);
    if (!cap) {
        return AMVP_NO_CAP;
    }

    kdf135_ssh_cap = cap->cap.kdf135_ssh_cap;
    if (!kdf135_ssh_cap) {
        return AMVP_NO_CAP;
    }

    if (amvp_validate_kdf135_ssh_param_value(method, param) != AMVP_SUCCESS) {
        return AMVP_INVALID_ARG;
    }

    /* only support two method types so just use whichever is available */
    switch (method) {
    case AMVP_SSH_METH_TDES_CBC:
        kdf135_ssh_cap->method[0] = AMVP_SSH_METH_TDES_CBC;
        break;
    case AMVP_SSH_METH_AES_128_CBC:
        kdf135_ssh_cap->method[1] = AMVP_SSH_METH_AES_128_CBC;
        break;
    case AMVP_SSH_METH_AES_192_CBC:
        kdf135_ssh_cap->method[2] = AMVP_SSH_METH_AES_192_CBC;
        break;
    case AMVP_SSH_METH_AES_256_CBC:
        kdf135_ssh_cap->method[3] = AMVP_SSH_METH_AES_256_CBC;
        break;
    case AMVP_SSH_METH_MAX:
    default:
        return AMVP_INVALID_ARG;
    }

    kdf135_ssh_cap->sha = kdf135_ssh_cap->sha | param;

    return AMVP_SUCCESS;
}

/*
 * The user should call this after invoking amvp_enable_kdf108_cap()
 * to specify the kdf parameters.
 */
AMVP_RESULT amvp_cap_kdf108_set_parm(AMVP_CTX *ctx,
                                     AMVP_KDF108_MODE mode,
                                     AMVP_KDF108_PARM param,
                                     int value) {
    AMVP_CAPS_LIST *cap;
    AMVP_KDF108_CAP *kdf108_cap;
    AMVP_KDF108_MODE_PARAMS *mode_obj;
    AMVP_RESULT result = AMVP_SUCCESS;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    cap = amvp_locate_cap_entry(ctx, AMVP_KDF108);

    if (!cap) {
        return AMVP_NO_CAP;
    }

    kdf108_cap = cap->cap.kdf108_cap;
    if (!kdf108_cap) {
        return AMVP_NO_CAP;
    }

    if (amvp_validate_kdf108_param_value(ctx, param, value) != AMVP_SUCCESS) {
        return AMVP_INVALID_ARG;
    }

    switch (mode) {
    case AMVP_KDF108_MODE_COUNTER:
        mode_obj = &cap->cap.kdf108_cap->counter_mode;
        if (!mode_obj->kdf_mode) {
            mode_obj->kdf_mode = AMVP_MODE_COUNTER;
        }
        break;
    case AMVP_KDF108_MODE_FEEDBACK:
        mode_obj = &cap->cap.kdf108_cap->feedback_mode;
        if (!mode_obj->kdf_mode) {
            mode_obj->kdf_mode = AMVP_MODE_FEEDBACK;
        }
        break;
    case AMVP_KDF108_MODE_DPI:
        mode_obj = &cap->cap.kdf108_cap->dpi_mode;
        if (!mode_obj->kdf_mode) {
            mode_obj->kdf_mode = AMVP_MODE_DPI;
        }
        break;
    default:
        return AMVP_INVALID_ARG;
    }

    /* only support two method types so just use whichever is available */
    switch (param) {
    case AMVP_KDF108_MAC_MODE:
        switch (value) {
        case AMVP_KDF108_MAC_MODE_CMAC_AES128:
            result = amvp_append_name_list(&mode_obj->mac_mode, AMVP_ALG_CMAC_AES_128);
            break;
        case AMVP_KDF108_MAC_MODE_CMAC_AES192:
            result = amvp_append_name_list(&mode_obj->mac_mode, AMVP_ALG_CMAC_AES_192);
            break;
        case AMVP_KDF108_MAC_MODE_CMAC_AES256:
            result = amvp_append_name_list(&mode_obj->mac_mode, AMVP_ALG_CMAC_AES_256);
            break;
        case AMVP_KDF108_MAC_MODE_CMAC_TDES:
            result = amvp_append_name_list(&mode_obj->mac_mode, AMVP_ALG_CMAC_TDES);
            break;
        case AMVP_KDF108_MAC_MODE_HMAC_SHA1:
            result = amvp_append_name_list(&mode_obj->mac_mode, AMVP_ALG_HMAC_SHA1);
            break;
        case AMVP_KDF108_MAC_MODE_HMAC_SHA224:
            result = amvp_append_name_list(&mode_obj->mac_mode, AMVP_ALG_HMAC_SHA2_224);
            break;
        case AMVP_KDF108_MAC_MODE_HMAC_SHA256:
            result = amvp_append_name_list(&mode_obj->mac_mode, AMVP_ALG_HMAC_SHA2_256);
            break;
        case AMVP_KDF108_MAC_MODE_HMAC_SHA384:
            result = amvp_append_name_list(&mode_obj->mac_mode, AMVP_ALG_HMAC_SHA2_384);
            break;
        case AMVP_KDF108_MAC_MODE_HMAC_SHA512:
            result = amvp_append_name_list(&mode_obj->mac_mode, AMVP_ALG_HMAC_SHA2_512);
            break;
        case AMVP_KDF108_MAC_MODE_HMAC_SHA512_224:
        case AMVP_KDF108_MAC_MODE_HMAC_SHA512_256:
        case AMVP_KDF108_MAC_MODE_HMAC_SHA3_224:
        case AMVP_KDF108_MAC_MODE_HMAC_SHA3_256:
        case AMVP_KDF108_MAC_MODE_HMAC_SHA3_384:
        case AMVP_KDF108_MAC_MODE_HMAC_SHA3_512:
        default:
            return AMVP_INVALID_ARG;
        }
        break;
    case AMVP_KDF108_COUNTER_LEN:
        amvp_append_sl_list(&mode_obj->counter_lens, value);
        break;
    case AMVP_KDF108_FIXED_DATA_ORDER:
        switch (value) {
        case AMVP_KDF108_FIXED_DATA_ORDER_AFTER:
            result = amvp_append_name_list(&mode_obj->data_order, AMVP_FIXED_DATA_ORDER_AFTER_STR);
            break;
        case AMVP_KDF108_FIXED_DATA_ORDER_BEFORE:
            result = amvp_append_name_list(&mode_obj->data_order, AMVP_FIXED_DATA_ORDER_BEFORE_STR);
            break;
        case AMVP_KDF108_FIXED_DATA_ORDER_MIDDLE:
            result = amvp_append_name_list(&mode_obj->data_order, AMVP_FIXED_DATA_ORDER_MIDDLE_STR);
            break;
        case AMVP_KDF108_FIXED_DATA_ORDER_NONE:
            result = amvp_append_name_list(&mode_obj->data_order, AMVP_FIXED_DATA_ORDER_NONE_STR);
            break;
        case AMVP_KDF108_FIXED_DATA_ORDER_BEFORE_ITERATOR:
            result = amvp_append_name_list(&mode_obj->data_order, AMVP_FIXED_DATA_ORDER_BEFORE_ITERATOR_STR);
            break;
        default:
            return AMVP_INVALID_ARG;
        }
        break;
    case AMVP_KDF108_SUPPORTS_EMPTY_IV:
        mode_obj->empty_iv_support = value;
        break;
    case AMVP_KDF108_REQUIRES_EMPTY_IV:
       if (mode_obj->empty_iv_support == 0) {
           AMVP_LOG_ERR("REQUIRES_EMPTY_IV for KDF108 can only be set if SUPPORTS_EMPTY_IV is true");
           return AMVP_INVALID_ARG;
       } else {
            mode_obj->requires_empty_iv = value;
       }
       break;
    case AMVP_KDF108_SUPPORTED_LEN:
        if (amvp_append_sl_list(&mode_obj->supported_lens.values, value) != AMVP_SUCCESS) {
            AMVP_LOG_ERR("Error adding supported length for KDF108 to list");
            return AMVP_MALLOC_FAIL;
        }
        break;
    case AMVP_KDF108_PARAM_MIN:
    case AMVP_KDF108_PARAM_MAX:
    case AMVP_KDF108_KDF_MODE:
    default:
        return AMVP_INVALID_ARG;
    }

    return result;
}

/*
 * The user should call this after invoking amvp_enable_kdf135_ssh_cap()
 * to specify the kdf parameters.
 */
AMVP_RESULT amvp_cap_kdf135_srtp_set_parm(AMVP_CTX *ctx,
                                          AMVP_CIPHER cipher,
                                          AMVP_KDF135_SRTP_PARAM param,
                                          int value) {
    AMVP_CAPS_LIST *cap;
    AMVP_KDF135_SRTP_CAP *kdf135_srtp_cap;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (cipher != AMVP_KDF135_SRTP) {
        return AMVP_INVALID_ARG;
    }

    cap = amvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        return AMVP_NO_CAP;
    }

    kdf135_srtp_cap = cap->cap.kdf135_srtp_cap;
    if (!kdf135_srtp_cap) {
        return AMVP_NO_CAP;
    }

    if (amvp_validate_kdf135_srtp_param_value(param, value) != AMVP_SUCCESS) {
        return AMVP_INVALID_ARG;
    }

    /* only support two method types so just use whichever is available */
    switch (param) {
    case AMVP_SRTP_AES_KEYLEN:
        if (value != 128 && value != 192 && value != 256) {
            AMVP_LOG_ERR("invalid aes keylen");
            return AMVP_INVALID_ARG;
        }
        amvp_append_sl_list(&kdf135_srtp_cap->aes_keylens, value);
        break;
    case AMVP_SRTP_SUPPORT_ZERO_KDR:
        if (is_valid_tf_param(value) != AMVP_SUCCESS) {
            AMVP_LOG_ERR("invalid boolean for zero kdr support");
            return AMVP_INVALID_ARG;
        }
        kdf135_srtp_cap->supports_zero_kdr = value;
        break;
    case AMVP_SRTP_KDF_EXPONENT:
        if (!value || value > AMVP_KDF135_SRTP_KDR_MAX) {
            AMVP_LOG_ERR("invalid srtp exponent");
            return AMVP_INVALID_ARG;
        }
        kdf135_srtp_cap->kdr_exp[value - 1] = 1;
        break;
    default:
        return AMVP_INVALID_ARG;
    }

    return AMVP_SUCCESS;
}

AMVP_RESULT amvp_cap_dsa_enable(AMVP_CTX *ctx,
                                AMVP_CIPHER cipher,
                                int (*crypto_handler)(AMVP_TEST_CASE *test_case)) {
    AMVP_RESULT result = AMVP_SUCCESS;

    if (!ctx) {
        return AMVP_NO_CTX;
    }
    if (!crypto_handler) {
        AMVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return AMVP_INVALID_ARG;
    }

    result = amvp_cap_list_append(ctx, AMVP_DSA_TYPE, cipher, crypto_handler);

    if (result == AMVP_DUP_CIPHER) {
        AMVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == AMVP_MALLOC_FAIL) {
        AMVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

AMVP_RESULT amvp_cap_kdf135_ikev2_set_parm(AMVP_CTX *ctx,
                                           AMVP_KDF135_IKEV2_PARM param,
                                           int value) {
    AMVP_CAPS_LIST *cap_list = NULL;
    AMVP_KDF135_IKEV2_CAP *cap = NULL;
    AMVP_RESULT result = AMVP_SUCCESS;

    cap_list = amvp_locate_cap_entry(ctx, AMVP_KDF135_IKEV2);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    }
    cap = cap_list->cap.kdf135_ikev2_cap;

    if (param != AMVP_KDF_HASH_ALG) {
        AMVP_LOG_ERR("Invalid param.");
        return AMVP_INVALID_ARG;
    }

    switch (value) {
    case AMVP_SHA1:
        result = amvp_append_name_list(&cap->hash_algs, AMVP_STR_SHA_1);
        break;
    case AMVP_SHA224:
        result = amvp_append_name_list(&cap->hash_algs, AMVP_STR_SHA2_224);
        break;
    case AMVP_SHA256:
        result = amvp_append_name_list(&cap->hash_algs, AMVP_STR_SHA2_256);
        break;
    case AMVP_SHA384:
        result = amvp_append_name_list(&cap->hash_algs, AMVP_STR_SHA2_384);
        break;
    case AMVP_SHA512:
        result = amvp_append_name_list(&cap->hash_algs, AMVP_STR_SHA2_512);
        break;
    default:
        AMVP_LOG_ERR("Invalid hash algorithm.");
        return AMVP_INVALID_ARG;
    }

    return result;
}

AMVP_RESULT amvp_cap_kdf135_ikev2_set_length(AMVP_CTX *ctx,
                                             AMVP_KDF135_IKEV2_PARM param,
                                             int value) {
    AMVP_CAPS_LIST *cap_list;
    AMVP_KDF135_IKEV2_CAP *cap;
    AMVP_JSON_DOMAIN_OBJ *domain;

    cap_list = amvp_locate_cap_entry(ctx, AMVP_KDF135_IKEV2);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    }
    cap = cap_list->cap.kdf135_ikev2_cap;

    switch (param) {
    case AMVP_INIT_NONCE_LEN:
        if (value < AMVP_KDF135_IKEV2_INIT_NONCE_BIT_MIN ||
            value > AMVP_KDF135_IKEV2_INIT_NONCE_BIT_MAX) {
            AMVP_LOG_ERR("min or max outside of acceptable range");
            return AMVP_INVALID_ARG;
        }
        domain = &cap->init_nonce_len_domain;
        break;
    case AMVP_RESPOND_NONCE_LEN:
        if (value < AMVP_KDF135_IKEV2_RESP_NONCE_BIT_MIN ||
            value > AMVP_KDF135_IKEV2_RESP_NONCE_BIT_MAX) {
            AMVP_LOG_ERR("min or max outside of acceptable range");
            return AMVP_INVALID_ARG;
        }
        domain = &cap->respond_nonce_len_domain;
        break;
    case AMVP_DH_SECRET_LEN:
        if (value < AMVP_KDF135_IKEV2_DH_SHARED_SECRET_BIT_MIN ||
            value > AMVP_KDF135_IKEV2_DH_SHARED_SECRET_BIT_MAX) {
            AMVP_LOG_ERR("min or max outside of acceptable range");
            return AMVP_INVALID_ARG;
        }
        domain = &cap->dh_secret_len;
        break;
    case AMVP_KEY_MATERIAL_LEN:
        if (value < AMVP_KDF135_IKEV2_DKEY_MATERIAL_BIT_MIN ||
            value > AMVP_KDF135_IKEV2_DKEY_MATERIAL_BIT_MAX) {
            AMVP_LOG_ERR("min or max outside of acceptable range");
            return AMVP_INVALID_ARG;
        }
        domain = &cap->key_material_len;
        break;
    case AMVP_KDF_HASH_ALG:
    default:
        return AMVP_INVALID_ARG;
    }

    if (amvp_append_sl_list(&domain->values, value) != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Error adding provided length to list for IKEV2");
        return AMVP_MALLOC_FAIL;
    }

    return AMVP_SUCCESS;
}

AMVP_RESULT amvp_cap_kdf135_ikev1_set_parm(AMVP_CTX *ctx,
                                           AMVP_KDF135_IKEV1_PARM param,
                                           int value) {
    AMVP_CAPS_LIST *cap_list;
    AMVP_RESULT result = AMVP_SUCCESS;
    AMVP_KDF135_IKEV1_CAP *cap;

    cap_list = amvp_locate_cap_entry(ctx, AMVP_KDF135_IKEV1);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    }
    cap = cap_list->cap.kdf135_ikev1_cap;

    if (param == AMVP_KDF_IKEv1_HASH_ALG) {
        switch (value) {
        case AMVP_SHA1:
            result = amvp_append_name_list(&cap->hash_algs, AMVP_STR_SHA_1);
            break;
        case AMVP_SHA224:
            result = amvp_append_name_list(&cap->hash_algs, AMVP_STR_SHA2_224);
            break;
        case AMVP_SHA256:
            result = amvp_append_name_list(&cap->hash_algs, AMVP_STR_SHA2_256);
            break;
        case AMVP_SHA384:
            result = amvp_append_name_list(&cap->hash_algs, AMVP_STR_SHA2_384);
            break;
        case AMVP_SHA512:
            result = amvp_append_name_list(&cap->hash_algs, AMVP_STR_SHA2_512);
            break;
        default:
            AMVP_LOG_ERR("Invalid hash algorithm.");
            return AMVP_INVALID_ARG;
        }
    } else if (param == AMVP_KDF_IKEv1_AUTH_METHOD) {
        switch (value) {
        case AMVP_KDF135_IKEV1_AMETH_DSA:
            strcpy_s(cap->auth_method, AMVP_AUTH_METHOD_STR_MAX_PLUS,
                     AMVP_AUTH_METHOD_DSA_STR);
            break;
        case AMVP_KDF135_IKEV1_AMETH_PSK:
            strcpy_s(cap->auth_method, AMVP_AUTH_METHOD_STR_MAX_PLUS,
                     AMVP_AUTH_METHOD_PSK_STR);
            break;
        case AMVP_KDF135_IKEV1_AMETH_PKE:
            strcpy_s(cap->auth_method, AMVP_AUTH_METHOD_STR_MAX_PLUS,
                     AMVP_AUTH_METHOD_PKE_STR);
            break;
        default:
            AMVP_LOG_ERR("Invalid authentication method.");
            return AMVP_INVALID_ARG;
        }
    } else {
        AMVP_LOG_ERR("Invalid param.");
        return AMVP_INVALID_ARG;
    }

    return result;
}

AMVP_RESULT amvp_cap_kdf135_x942_set_domain(AMVP_CTX *ctx,
                                             AMVP_KDF135_X942_PARM param,
                                             int min,
                                             int max,
                                             int increment) {
    AMVP_CAPS_LIST *cap_list = NULL;
    AMVP_KDF135_X942_CAP *cap = NULL;
    AMVP_JSON_DOMAIN_OBJ *domain = NULL;

    cap_list = amvp_locate_cap_entry(ctx, AMVP_KDF135_X942);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    }
    cap = cap_list->cap.kdf135_x942_cap;

    if (amvp_validate_kdf135_x942_domain_value(param, min, max, increment) != AMVP_SUCCESS) {
        AMVP_LOG_ERR("Invalid domain range provided for param %d in kdf135-x942", param);
        return AMVP_INVALID_ARG;
    }

    switch (param) {
    case AMVP_KDF_X942_KEY_LEN:
        domain = &cap->key_len;
        break;
    case AMVP_KDF_X942_OTHER_INFO_LEN:
        domain = &cap->other_len;
        break;
    case AMVP_KDF_X942_SUPP_INFO_LEN:
        domain = &cap->supp_len;
        break;
    case AMVP_KDF_X942_ZZ_LEN:
        domain = &cap->zz_len;
        break;
    case AMVP_KDF_X942_KDF_TYPE:
    case AMVP_KDF_X942_OID:
    case AMVP_KDF_X942_HASH_ALG:
    default:
        AMVP_LOG_ERR("Invalid domain parameter provided for kdf135-x942");
        return AMVP_INVALID_ARG;
    }

    domain->min = min;
    domain->max = max;
    domain->increment = increment;

    return AMVP_SUCCESS;
}

AMVP_RESULT amvp_cap_kdf135_x942_set_parm(AMVP_CTX *ctx,
                                          AMVP_KDF135_X942_PARM param,
                                          int value) {
    AMVP_CAPS_LIST *cap_list;
    AMVP_KDF135_X942_CAP *cap;
    const char *alg = NULL;

    cap_list = amvp_locate_cap_entry(ctx, AMVP_KDF135_X942);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    }
    cap = cap_list->cap.kdf135_x942_cap;

    switch (param) {
    case AMVP_KDF_X942_KDF_TYPE:
        if (value == AMVP_KDF_X942_KDF_TYPE_DER || value == AMVP_KDF_X942_KDF_TYPE_CONCAT) {
            cap->type = value;
        } else {
            AMVP_LOG_ERR("Invalid KDF type provided for kdf135-x942");
            return AMVP_INVALID_ARG;
        }
        break;
    case AMVP_KDF_X942_HASH_ALG:
        alg = amvp_lookup_hash_alg_name(value);
        if (!alg) {
            AMVP_LOG_ERR("Invalid hash alg provided for kdf135-x942");
            return AMVP_INVALID_ARG;
        }
        amvp_append_name_list(&cap->hash_algs, alg);
        break;
    case AMVP_KDF_X942_OID:
        switch (value) {
        case AMVP_KDF_X942_OID_TDES:
            amvp_append_name_list(&cap->oids, "TDES");
            break;
        case AMVP_KDF_X942_OID_AES128KW:
            amvp_append_name_list(&cap->oids, "AES-128-KW");
            break;
        case AMVP_KDF_X942_OID_AES192KW:
            amvp_append_name_list(&cap->oids, "AES-192-KW");
            break;
        case AMVP_KDF_X942_OID_AES256KW:
            amvp_append_name_list(&cap->oids, "AES-256-KW");
            break;
        default:
            AMVP_LOG_ERR("Invalid OID provided for kdf135-x942");
            return AMVP_INVALID_ARG;
        break;
        }
        break;
    case AMVP_KDF_X942_KEY_LEN:
    case AMVP_KDF_X942_OTHER_INFO_LEN:
    case AMVP_KDF_X942_SUPP_INFO_LEN:
    case AMVP_KDF_X942_ZZ_LEN:
    default:
        AMVP_LOG_ERR("Invalid parameter provided for kdf135-x942");
        return AMVP_INVALID_ARG;
    }

    return AMVP_SUCCESS;
}

AMVP_RESULT amvp_cap_kdf135_x963_set_parm(AMVP_CTX *ctx,
                                          AMVP_KDF135_X963_PARM param,
                                          int value) {
    AMVP_CAPS_LIST *cap_list;
    AMVP_KDF135_X963_CAP *cap;
    AMVP_RESULT result = AMVP_SUCCESS;

    cap_list = amvp_locate_cap_entry(ctx, AMVP_KDF135_X963);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    }
    cap = cap_list->cap.kdf135_x963_cap;

    if (param == AMVP_KDF_X963_HASH_ALG) {
        switch (value) {
        case AMVP_SHA224:
            result = amvp_append_name_list(&cap->hash_algs, AMVP_STR_SHA2_224);
            break;
        case AMVP_SHA256:
            result = amvp_append_name_list(&cap->hash_algs, AMVP_STR_SHA2_256);
            break;
        case AMVP_SHA384:
            result = amvp_append_name_list(&cap->hash_algs, AMVP_STR_SHA2_384);
            break;
        case AMVP_SHA512:
            result = amvp_append_name_list(&cap->hash_algs, AMVP_STR_SHA2_512);
            break;
        default:
            AMVP_LOG_ERR("Invalid hash alg");
            return AMVP_INVALID_ARG;
        }
    } else {
        switch (param) {
        case AMVP_KDF_X963_KEY_DATA_LEN:
            if (value < AMVP_KDF135_X963_KEYDATA_MIN_BITS ||
                value > AMVP_KDF135_X963_KEYDATA_MAX_BITS) {
                AMVP_LOG_ERR("invalid key len value");
                return AMVP_INVALID_ARG;
            }
            amvp_append_sl_list(&cap->key_data_lengths, value);
            break;
        case AMVP_KDF_X963_FIELD_SIZE:
            if (value != AMVP_KDF135_X963_FIELD_SIZE_224 &&
                value != AMVP_KDF135_X963_FIELD_SIZE_233 &&
                value != AMVP_KDF135_X963_FIELD_SIZE_256 &&
                value != AMVP_KDF135_X963_FIELD_SIZE_283 &&
                value != AMVP_KDF135_X963_FIELD_SIZE_384 &&
                value != AMVP_KDF135_X963_FIELD_SIZE_409 &&
                value != AMVP_KDF135_X963_FIELD_SIZE_521 &&
                value != AMVP_KDF135_X963_FIELD_SIZE_571) {
                AMVP_LOG_ERR("invalid field size value");
                return AMVP_INVALID_ARG;
            }
            amvp_append_sl_list(&cap->field_sizes, value);
            break;
        case AMVP_KDF_X963_SHARED_INFO_LEN:
            if (value < AMVP_KDF135_X963_SHARED_INFO_LEN_MIN ||
                value > AMVP_KDF135_X963_SHARED_INFO_LEN_MAX) {
                AMVP_LOG_ERR("invalid shared info len value");
                return AMVP_INVALID_ARG;
            }
            amvp_append_sl_list(&cap->shared_info_lengths, value);
            break;
        case AMVP_KDF_X963_HASH_ALG:
        default:
            return AMVP_INVALID_ARG;
        }
    }

    return result;
}

AMVP_RESULT amvp_cap_kdf135_ikev2_set_domain(AMVP_CTX *ctx,
                                             AMVP_KDF135_IKEV2_PARM param,
                                             int min,
                                             int max,
                                             int increment) {
    AMVP_CAPS_LIST *cap_list;
    AMVP_JSON_DOMAIN_OBJ *domain;

    cap_list = amvp_locate_cap_entry(ctx, AMVP_KDF135_IKEV2);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    }

    switch (param) {
    case AMVP_INIT_NONCE_LEN:
        if (min < AMVP_KDF135_IKEV2_INIT_NONCE_BIT_MIN ||
            max > AMVP_KDF135_IKEV2_INIT_NONCE_BIT_MAX) {
            AMVP_LOG_ERR("min or max outside of acceptable range");
            return AMVP_INVALID_ARG;
        }
        domain = &cap_list->cap.kdf135_ikev2_cap->init_nonce_len_domain;
        break;
    case AMVP_RESPOND_NONCE_LEN:
        if (min < AMVP_KDF135_IKEV2_RESP_NONCE_BIT_MIN ||
            max > AMVP_KDF135_IKEV2_RESP_NONCE_BIT_MAX) {
            AMVP_LOG_ERR("min or max outside of acceptable range");
            return AMVP_INVALID_ARG;
        }
        domain = &cap_list->cap.kdf135_ikev2_cap->respond_nonce_len_domain;
        break;
    case AMVP_DH_SECRET_LEN:
        if (min < AMVP_KDF135_IKEV2_DH_SHARED_SECRET_BIT_MIN ||
            max > AMVP_KDF135_IKEV2_DH_SHARED_SECRET_BIT_MAX) {
            AMVP_LOG_ERR("min or max outside of acceptable range");
            return AMVP_INVALID_ARG;
        }
        domain = &cap_list->cap.kdf135_ikev2_cap->dh_secret_len;
        break;
    case AMVP_KEY_MATERIAL_LEN:
        if (min < AMVP_KDF135_IKEV2_DKEY_MATERIAL_BIT_MIN ||
            max > AMVP_KDF135_IKEV2_DKEY_MATERIAL_BIT_MAX) {
            AMVP_LOG_ERR("min or max outside of acceptable range");
            return AMVP_INVALID_ARG;
        }
        domain = &cap_list->cap.kdf135_ikev2_cap->key_material_len;
        break;
    case AMVP_KDF_HASH_ALG:
    default:
        return AMVP_INVALID_ARG;
    }

    domain->min = min;
    domain->max = max;
    domain->increment = increment;

    return AMVP_SUCCESS;
}

AMVP_RESULT amvp_cap_kdf135_ikev1_set_domain(AMVP_CTX *ctx,
                                             AMVP_KDF135_IKEV1_PARM param,
                                             int min,
                                             int max,
                                             int increment) {
    AMVP_CAPS_LIST *cap_list;
    AMVP_JSON_DOMAIN_OBJ *domain;

    cap_list = amvp_locate_cap_entry(ctx, AMVP_KDF135_IKEV1);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    }

    switch (param) {
    case AMVP_KDF_IKEv1_INIT_NONCE_LEN:
        if (min < AMVP_KDF135_IKEV1_INIT_NONCE_BIT_MIN ||
            max > AMVP_KDF135_IKEV1_INIT_NONCE_BIT_MAX) {
            AMVP_LOG_ERR("min or max outside of acceptable range");
            return AMVP_INVALID_ARG;
        }
        domain = &cap_list->cap.kdf135_ikev1_cap->init_nonce_len_domain;
        break;
    case AMVP_KDF_IKEv1_RESPOND_NONCE_LEN:
        if (min < AMVP_KDF135_IKEV1_RESP_NONCE_BIT_MIN ||
            max > AMVP_KDF135_IKEV1_RESP_NONCE_BIT_MAX) {
            AMVP_LOG_ERR("min or max outside of acceptable range");
            return AMVP_INVALID_ARG;
        }
        domain = &cap_list->cap.kdf135_ikev1_cap->respond_nonce_len_domain;
        break;
    case AMVP_KDF_IKEv1_DH_SECRET_LEN:
        if (min < AMVP_KDF135_IKEV1_DH_SHARED_SECRET_BIT_MIN ||
            max > AMVP_KDF135_IKEV1_DH_SHARED_SECRET_BIT_MAX) {
            AMVP_LOG_ERR("min or max outside of acceptable range");
            return AMVP_INVALID_ARG;
        }
        domain = &cap_list->cap.kdf135_ikev1_cap->dh_secret_len;
        break;
    case AMVP_KDF_IKEv1_PSK_LEN:
        if (min < AMVP_KDF135_IKEV1_PSK_BIT_MIN ||
            max > AMVP_KDF135_IKEV1_PSK_BIT_MAX) {
            AMVP_LOG_ERR("min or max outside of acceptable range");
            return AMVP_INVALID_ARG;
        }
        domain = &cap_list->cap.kdf135_ikev1_cap->psk_len;
        break;
    case AMVP_KDF_IKEv1_HASH_ALG:
    case AMVP_KDF_IKEv1_AUTH_METHOD:
    default:
        return AMVP_INVALID_ARG;
    }
    domain->min = min;
    domain->max = max;
    domain->increment = increment;

    return AMVP_SUCCESS;
}

AMVP_RESULT amvp_cap_kdf108_set_domain(AMVP_CTX *ctx,
                                       AMVP_KDF108_MODE mode,
                                       AMVP_KDF108_PARM param,
                                       int min,
                                       int max,
                                       int increment) {
    AMVP_CAPS_LIST *cap_list;
    AMVP_JSON_DOMAIN_OBJ *domain;
    AMVP_KDF108_MODE_PARAMS *mode_obj;

    cap_list = amvp_locate_cap_entry(ctx, AMVP_KDF108);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    }

    if (!min || max > AMVP_KDF108_KEYIN_BIT_MAX) {
        AMVP_LOG_ERR("min and/or max outside acceptable range");
        return AMVP_INVALID_ARG;
    }

    switch (mode) {
    case AMVP_KDF108_MODE_COUNTER:
        mode_obj = &cap_list->cap.kdf108_cap->counter_mode;
        break;
    case AMVP_KDF108_MODE_FEEDBACK:
        mode_obj = &cap_list->cap.kdf108_cap->feedback_mode;
        break;
    case AMVP_KDF108_MODE_DPI:
        mode_obj = &cap_list->cap.kdf108_cap->dpi_mode;
        break;
    default:
        return AMVP_INVALID_ARG;
    }
    switch (param) {
    case AMVP_KDF108_SUPPORTED_LEN:
        domain = &mode_obj->supported_lens;
        break;
    case AMVP_KDF108_KDF_MODE:
    case AMVP_KDF108_MAC_MODE:
    case AMVP_KDF108_FIXED_DATA_ORDER:
    case AMVP_KDF108_COUNTER_LEN:
    case AMVP_KDF108_SUPPORTS_EMPTY_IV:
    case AMVP_KDF108_REQUIRES_EMPTY_IV:
    case AMVP_KDF108_PARAM_MIN:
    case AMVP_KDF108_PARAM_MAX:
    default:
        return AMVP_INVALID_ARG;
    }
    domain->min = min;
    domain->max = max;
    domain->increment = increment;

    return AMVP_SUCCESS;
}

AMVP_RESULT amvp_cap_kdf_tls12_enable(AMVP_CTX *ctx,
                                       int (*crypto_handler)(AMVP_TEST_CASE *test_case)) {
    AMVP_RESULT result = AMVP_SUCCESS;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (!crypto_handler) {
        return AMVP_INVALID_ARG;
        AMVP_LOG_ERR("NULL parameter 'crypto_handler'");
    }

    result = amvp_cap_list_append(ctx, AMVP_KDF_TLS12_TYPE, AMVP_KDF_TLS12, crypto_handler);

    if (result == AMVP_DUP_CIPHER) {
        AMVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == AMVP_MALLOC_FAIL) {
        AMVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

/*
 * The user should call this after invoking amvp_cap_kdf_tls12_enable()
 * to specify the kdf parameters.
 */
AMVP_RESULT amvp_cap_kdf_tls12_set_parm(AMVP_CTX *ctx,
                                         AMVP_KDF_TLS12_PARM param,
                                         int value) {
    AMVP_CAPS_LIST *cap_list;
    AMVP_KDF_TLS12_CAP *cap;
    AMVP_RESULT result = AMVP_SUCCESS;
    const char *alg_str = NULL;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    cap_list = amvp_locate_cap_entry(ctx, AMVP_KDF_TLS12);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found. You must enable algorithm before setting parameters.");
        return AMVP_NO_CAP;
    }

    cap = cap_list->cap.kdf_tls12_cap;
    if (!cap) {
        return AMVP_NO_CAP;
    }    

    switch(param) {
    case AMVP_KDF_TLS12_HASH_ALG:
        alg_str = amvp_lookup_hash_alg_name(value);
        if ((value != AMVP_SHA256 && value != AMVP_SHA384 && value != AMVP_SHA512) || !alg_str) {
            AMVP_LOG_ERR("Invalid value specified for TLS 1.2 alg.");
            return AMVP_INVALID_ARG;
        }
        if (amvp_is_in_name_list(cap->hash_algs, alg_str)) {
            AMVP_LOG_WARN("Attempting to register a hash alg with TLS 1.2 KDF that has already been registered, skipping.");
            return AMVP_SUCCESS;
        } else {
            result = amvp_append_name_list(&cap->hash_algs, alg_str);
        }
        break;
    case AMVP_KDF_TLS12_PARAM_MIN:
    default:
        return AMVP_INVALID_ARG;
    }

    return result;
}



AMVP_RESULT amvp_cap_kdf_tls13_enable(AMVP_CTX *ctx,
                                      int (*crypto_handler) (AMVP_TEST_CASE *test_case)) {
    AMVP_RESULT result = AMVP_SUCCESS;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (!crypto_handler) {
        AMVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return AMVP_INVALID_ARG;
    }

    result = amvp_cap_list_append(ctx, AMVP_KDF_TLS13_TYPE, AMVP_KDF_TLS13, crypto_handler);

    if (result == AMVP_DUP_CIPHER) {
        AMVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == AMVP_MALLOC_FAIL) {
        AMVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

AMVP_RESULT amvp_cap_kdf_tls13_set_parm(AMVP_CTX *ctx,
                                        AMVP_KDF_TLS13_PARM param,
                                        int value) {
    AMVP_CAPS_LIST *cap_list = NULL;
    AMVP_KDF_TLS13_CAP *cap = NULL;
    AMVP_RESULT result = AMVP_SUCCESS;
    const char *alg_str = NULL;

    cap_list = amvp_locate_cap_entry(ctx, AMVP_KDF_TLS13);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found. You must enable algorithm before setting parameters.");
        return AMVP_NO_CAP;
    }
    cap = cap_list->cap.kdf_tls13_cap;

    switch(param) {
    case AMVP_KDF_TLS13_HMAC_ALG:
        alg_str = amvp_lookup_hash_alg_name(value);
        if ((value != AMVP_SHA256 && value != AMVP_SHA384) || !alg_str) {
            AMVP_LOG_ERR("Invalid value specified for TLS 1.3 hmac alg.");
            return AMVP_INVALID_ARG;
        }
        if (amvp_is_in_name_list(cap->hmac_algs, alg_str)) {
            AMVP_LOG_WARN("Attempting to register an hmac alg with TLS 1.3 KDF that has already been registered, skipping.");
            return AMVP_SUCCESS;
        } else {
            result = amvp_append_name_list(&cap->hmac_algs, alg_str);
        }
        break;
    case AMVP_KDF_TLS13_RUNNING_MODE:
        if (value <= AMVP_KDF_TLS13_RUN_MODE_MIN || value >= AMVP_KDF_TLS13_RUN_MODE_MAX) {
            AMVP_LOG_ERR("Invalid TLS 1.3 KDF running mode provided");
            return AMVP_INVALID_ARG;
        }
        result = amvp_append_param_list(&cap->running_mode, value);
        break;
    case AMVP_KDF_TLS13_PARAM_MIN:
    default:
        return AMVP_INVALID_ARG;
    }

    return result;

}
/*
 * Append a KAS-ECC pre req val to the capabilities
 */
static AMVP_RESULT amvp_add_kas_ecc_prereq_val(AMVP_CTX *ctx, AMVP_KAS_ECC_CAP_MODE *kas_ecc_mode,
                                               AMVP_KAS_ECC_MODE mode,
                                               AMVP_PREREQ_ALG pre_req,
                                               char *value) {
    AMVP_PREREQ_LIST *prereq_entry, *prereq_entry_2;

    AMVP_LOG_INFO("KAS-ECC mode %d", mode);
    prereq_entry = calloc(1, sizeof(AMVP_PREREQ_LIST));
    if (!prereq_entry) {
        return AMVP_MALLOC_FAIL;
    }
    prereq_entry->prereq_alg_val.alg = pre_req;
    prereq_entry->prereq_alg_val.val = value;

    /*
     * 1st entry
     */
    if (!kas_ecc_mode->prereq_vals) {
        kas_ecc_mode->prereq_vals = prereq_entry;
    } else {
        /*
         * append to the last in the list
         */
        prereq_entry_2 = kas_ecc_mode->prereq_vals;
        while (prereq_entry_2->next) {
            prereq_entry_2 = prereq_entry_2->next;
        }
        prereq_entry_2->next = prereq_entry;
    }
    return AMVP_SUCCESS;
}

AMVP_RESULT amvp_cap_kas_ecc_set_prereq(AMVP_CTX *ctx,
                                        AMVP_CIPHER cipher,
                                        AMVP_KAS_ECC_MODE mode,
                                        AMVP_PREREQ_ALG pre_req,
                                        char *value) {
    AMVP_KAS_ECC_CAP_MODE *kas_ecc_mode;
    AMVP_KAS_ECC_CAP *kas_ecc_cap;
    AMVP_CAPS_LIST *cap_list;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    switch (pre_req) {
    case AMVP_PREREQ_CCM:
    case AMVP_PREREQ_CMAC:
    case AMVP_PREREQ_DRBG:
    case AMVP_PREREQ_ECDSA:
    case AMVP_PREREQ_HMAC:
    case AMVP_PREREQ_SHA:
        break;
    case AMVP_PREREQ_AES:
    case AMVP_PREREQ_DSA:
    case AMVP_PREREQ_KAS:
    case AMVP_PREREQ_SAFE_PRIMES:
    case AMVP_PREREQ_TDES:
    case AMVP_PREREQ_RSADP:
    case AMVP_PREREQ_RSA:
    case AMVP_PREREQ_KMAC:
    default:
        AMVP_LOG_ERR("\nUnsupported KAS-ECC prereq %d", pre_req);
        return AMVP_INVALID_ARG;
    }

    /*
     * Locate this cipher in the caps array
     */
    cap_list = amvp_locate_cap_entry(ctx, cipher);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    }

    /*
     * Locate cap mode from array
     */
    kas_ecc_cap = cap_list->cap.kas_ecc_cap;
    kas_ecc_mode = &kas_ecc_cap->kas_ecc_mode[mode - 1];

    /*
     * Add the value to the cap
     */
    return amvp_add_kas_ecc_prereq_val(ctx, kas_ecc_mode, mode, pre_req, value);
}

AMVP_RESULT amvp_cap_kas_ecc_enable(AMVP_CTX *ctx,
                                    AMVP_CIPHER cipher,
                                    int (*crypto_handler)(AMVP_TEST_CASE *test_case)) {
    AMVP_CAP_TYPE type = 0;
    AMVP_RESULT result = AMVP_SUCCESS;
    AMVP_SUB_KAS alg;

    if (!ctx) {
        return AMVP_NO_CTX;
    }
    if (!crypto_handler) {
        AMVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return AMVP_INVALID_ARG;
    }

    alg = amvp_get_kas_alg(cipher);
    if (alg == 0) {
        AMVP_LOG_ERR("Invalid cipher value");
        return AMVP_INVALID_ARG;
    }
    switch (alg) {
    case AMVP_SUB_KAS_ECC_CDH:
        type = AMVP_KAS_ECC_CDH_TYPE;
        break;
    case AMVP_SUB_KAS_ECC_COMP:
        type = AMVP_KAS_ECC_COMP_TYPE;
        break;
    case AMVP_SUB_KAS_ECC_NOCOMP:
        type = AMVP_KAS_ECC_NOCOMP_TYPE;
        break;
    case AMVP_SUB_KAS_ECC_SSC:
        type = AMVP_KAS_ECC_SSC_TYPE;
        break;
    case AMVP_SUB_KAS_FFC_COMP:
    case AMVP_SUB_KAS_FFC_NOCOMP:
    case AMVP_SUB_KAS_FFC_SSC: 
    case AMVP_SUB_KAS_IFC_SSC: 
    case AMVP_SUB_KTS_IFC: 
    case AMVP_SUB_KDA_ONESTEP:
    case AMVP_SUB_KDA_TWOSTEP:
    case AMVP_SUB_KDA_HKDF:
    case AMVP_SUB_SAFE_PRIMES_KEYGEN:
    case AMVP_SUB_SAFE_PRIMES_KEYVER:
    default:
        AMVP_LOG_ERR("Invalid parameter 'cipher'");
        return AMVP_INVALID_ARG;
    }

    result = amvp_cap_list_append(ctx, type, cipher, crypto_handler);

    if (result == AMVP_DUP_CIPHER) {
        AMVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == AMVP_MALLOC_FAIL) {
        AMVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

AMVP_RESULT amvp_cap_kas_ecc_set_parm(AMVP_CTX *ctx,
                                      AMVP_CIPHER cipher,
                                      AMVP_KAS_ECC_MODE mode,
                                      AMVP_KAS_ECC_PARAM param,
                                      int value) {
    AMVP_CAPS_LIST *cap;
    AMVP_KAS_ECC_CAP *kas_ecc_cap;
    AMVP_KAS_ECC_CAP_MODE *kas_ecc_cap_mode;
    AMVP_SUB_KAS alg;
    AMVP_RESULT result = AMVP_SUCCESS;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    alg = amvp_get_kas_alg(cipher);
    if (alg == 0) {
        AMVP_LOG_ERR("Invalid cipher value");
        return AMVP_INVALID_ARG;
    }
    switch (alg) {
    case AMVP_SUB_KAS_ECC_CDH:
    case AMVP_SUB_KAS_ECC_COMP:
    case AMVP_SUB_KAS_ECC_NOCOMP:
    case AMVP_SUB_KAS_ECC_SSC:
        break;
    case AMVP_SUB_KAS_FFC_COMP:
    case AMVP_SUB_KAS_FFC_NOCOMP:
    case AMVP_SUB_KAS_FFC_SSC: 
    case AMVP_SUB_KAS_IFC_SSC: 
    case AMVP_SUB_KTS_IFC: 
    case AMVP_SUB_KDA_ONESTEP:
    case AMVP_SUB_KDA_TWOSTEP:
    case AMVP_SUB_KDA_HKDF:
    case AMVP_SUB_SAFE_PRIMES_KEYGEN:
    case AMVP_SUB_SAFE_PRIMES_KEYVER:
    default:
        AMVP_LOG_ERR("Invalid cipher");
        return AMVP_INVALID_ARG;
    }

    cap = amvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        return AMVP_NO_CAP;
    }

    kas_ecc_cap = cap->cap.kas_ecc_cap;
    if (!kas_ecc_cap) {
        return AMVP_NO_CAP;
    }
    kas_ecc_cap_mode = &kas_ecc_cap->kas_ecc_mode[mode - 1];
    switch (mode) {
    case AMVP_KAS_ECC_MODE_CDH:
    case AMVP_KAS_ECC_MODE_NONE:
        switch (param) {
        case AMVP_KAS_ECC_FUNCTION:
            if (!value || value > AMVP_KAS_ECC_MAX_FUNCS) {
                AMVP_LOG_ERR("invalid kas ecc function");
                return AMVP_INVALID_ARG;
            }
            result = amvp_append_param_list(&kas_ecc_cap_mode->function, value);
            break;
        case AMVP_KAS_ECC_REVISION:
            if (cipher == AMVP_KAS_ECC_CDH) {
                if (value == AMVP_REVISION_SP800_56AR3) {
                    kas_ecc_cap_mode->revision = value;
                } else {
                    AMVP_LOG_ERR("Invalid revision value for KAS-ECC-CDH");
                    return AMVP_INVALID_ARG;
                }
            } else {
                AMVP_LOG_ERR("Unsupported KAS-ECC param %d", param);
                return AMVP_INVALID_ARG;
            }
            break;
        case AMVP_KAS_ECC_HASH:
            if ((value < AMVP_NO_SHA || value >= AMVP_HASH_ALG_MAX) && !(value & (value - 1))) {
                AMVP_LOG_ERR("Invalid hash alg value for KAS-ECC hash Z function");
                return AMVP_INVALID_ARG;
            }
            kas_ecc_cap_mode->hash = value;
            break;
        case AMVP_KAS_ECC_CURVE:
            if (value <= AMVP_EC_CURVE_START || value >= AMVP_EC_CURVE_END) {
                AMVP_LOG_ERR("invalid kas ecc curve attr");
                return AMVP_INVALID_ARG;
            }
            result = amvp_append_param_list(&kas_ecc_cap_mode->curve, value);
            break;
        case AMVP_KAS_ECC_NONE:
            if (cipher == AMVP_KAS_ECC_SSC) {
                break;
            } else {
                AMVP_LOG_ERR("\nUnsupported KAS-ECC param %d", param);
                return AMVP_INVALID_ARG;
            }
        case AMVP_KAS_ECC_ROLE:
        case AMVP_KAS_ECC_KDF:
        case AMVP_KAS_ECC_EB:
        case AMVP_KAS_ECC_EC:
        case AMVP_KAS_ECC_ED:
        case AMVP_KAS_ECC_EE:
        default:
            AMVP_LOG_ERR("\nUnsupported KAS-ECC param %d", param);
            return AMVP_INVALID_ARG;

            break;
        }
        break;
    case AMVP_KAS_ECC_MODE_COMPONENT:
        switch (param) {
        case AMVP_KAS_ECC_FUNCTION:
            if (!value || value > AMVP_KAS_ECC_MAX_FUNCS) {
                AMVP_LOG_ERR("invalid kas ecc function");
                return AMVP_INVALID_ARG;
            }
            result = amvp_append_param_list(&kas_ecc_cap_mode->function, value);
            break;
        case AMVP_KAS_ECC_REVISION:
        case AMVP_KAS_ECC_CURVE:
        case AMVP_KAS_ECC_ROLE:
        case AMVP_KAS_ECC_KDF:
        case AMVP_KAS_ECC_EB:
        case AMVP_KAS_ECC_EC:
        case AMVP_KAS_ECC_ED:
        case AMVP_KAS_ECC_EE:
        case AMVP_KAS_ECC_NONE:
        case AMVP_KAS_ECC_HASH:
        default:
            AMVP_LOG_ERR("\nUnsupported KAS-ECC param %d", param);
            return AMVP_INVALID_ARG;

            break;
        }
        break;
    case AMVP_KAS_ECC_MODE_NOCOMP:
    case AMVP_KAS_ECC_MAX_MODES:
    default:
        AMVP_LOG_ERR("\nUnsupported KAS-ECC mode %d", mode);
        return AMVP_INVALID_ARG;

        break;
    }
    return result;
}

AMVP_RESULT amvp_cap_kas_ecc_set_scheme(AMVP_CTX *ctx,
                                        AMVP_CIPHER cipher,
                                        AMVP_KAS_ECC_MODE mode,
                                        AMVP_KAS_ECC_SCHEMES scheme,
                                        AMVP_KAS_ECC_PARAM param,
                                        int option,
                                        int value) {
    AMVP_CAPS_LIST *cap;
    AMVP_KAS_ECC_CAP *kas_ecc_cap;
    AMVP_KAS_ECC_CAP_MODE *kas_ecc_cap_mode;
    AMVP_KAS_ECC_SCHEME *current_scheme;
    AMVP_KAS_ECC_PSET *current_pset;
    AMVP_KAS_ECC_PSET *last_pset = NULL;
    AMVP_SUB_KAS alg;
    AMVP_RESULT result = AMVP_SUCCESS;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    alg = amvp_get_kas_alg(cipher);
    if (alg == 0) {
        AMVP_LOG_ERR("Invalid cipher value");
        return AMVP_INVALID_ARG;
    }
    switch (alg) {
    case AMVP_SUB_KAS_ECC_CDH:
    case AMVP_SUB_KAS_ECC_COMP:
    case AMVP_SUB_KAS_ECC_NOCOMP:
    case AMVP_SUB_KAS_ECC_SSC:
        break;
    case AMVP_SUB_KAS_FFC_COMP:
    case AMVP_SUB_KAS_FFC_NOCOMP:
    case AMVP_SUB_KAS_FFC_SSC:
    case AMVP_SUB_KAS_IFC_SSC: 
    case AMVP_SUB_KTS_IFC: 
    case AMVP_SUB_KDA_ONESTEP:
    case AMVP_SUB_KDA_TWOSTEP:
    case AMVP_SUB_KDA_HKDF:
    case AMVP_SUB_SAFE_PRIMES_KEYGEN:
    case AMVP_SUB_SAFE_PRIMES_KEYVER:
    default:
        AMVP_LOG_ERR("Invalid cipher");
        return AMVP_INVALID_ARG;
    }

    cap = amvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        return AMVP_NO_CAP;
    }

    kas_ecc_cap = cap->cap.kas_ecc_cap;
    if (!kas_ecc_cap) {
        return AMVP_NO_CAP;
    }
    kas_ecc_cap_mode = &kas_ecc_cap->kas_ecc_mode[mode - 1];
    switch (mode) {
    case AMVP_KAS_ECC_MODE_COMPONENT:
    case AMVP_KAS_ECC_MODE_NOCOMP:
    case AMVP_KAS_ECC_MODE_NONE:
        if (!scheme || scheme >= AMVP_KAS_ECC_SCHEMES_MAX) {
            AMVP_LOG_ERR("Invalid ecc scheme");
            return AMVP_INVALID_ARG;
        }
        current_scheme = kas_ecc_cap_mode->scheme;
        while (current_scheme) {
            if (current_scheme->scheme == scheme) {
                break;
            } else {
                current_scheme = current_scheme->next;
            }
        }
        /* if there are none or didn't find the one we're looking for... */
        if (current_scheme == NULL) {
            kas_ecc_cap_mode->scheme = calloc(1, sizeof(AMVP_KAS_ECC_SCHEME));
            kas_ecc_cap_mode->scheme->scheme = scheme;
            current_scheme = kas_ecc_cap_mode->scheme;
        }
        switch (param) {
        case AMVP_KAS_ECC_KDF:
            if (!value || value > AMVP_KAS_ECC_PARMSET) {
                return AMVP_INVALID_ARG;
            }
            current_scheme->kdf = (AMVP_KAS_ECC_SET)value;
            break;
        case AMVP_KAS_ECC_ROLE:
            if (value != AMVP_KAS_ECC_ROLE_INITIATOR &&
                value != AMVP_KAS_ECC_ROLE_RESPONDER) {
                return AMVP_INVALID_ARG;
            }
            result = amvp_append_param_list(&current_scheme->role, value);
            break;
        case AMVP_KAS_ECC_EB:
        case AMVP_KAS_ECC_EC:
        case AMVP_KAS_ECC_ED:
        case AMVP_KAS_ECC_EE:
            current_pset = current_scheme->pset;
            while (current_pset) {
                if (current_pset->set == param) {
                    break;
                } else {
                    last_pset = current_pset;
                    current_pset = current_pset->next;
                }
            }
            if (!current_pset) {
                current_pset = calloc(1, sizeof(AMVP_KAS_ECC_PSET));
                if (current_scheme->pset == NULL) {
                    current_scheme->pset = current_pset;
                } else {
                    last_pset->next = current_pset;
                }
                current_pset->set = param;
                current_pset->curve = option;
            }
            //then set sha in a param list
            result = amvp_append_param_list(&current_pset->sha, value);
            break;
        case AMVP_KAS_ECC_NONE:
            break;
        case AMVP_KAS_ECC_REVISION:
        case AMVP_KAS_ECC_CURVE:
        case AMVP_KAS_ECC_FUNCTION:
        case AMVP_KAS_ECC_HASH:
        default:
            AMVP_LOG_ERR("\nUnsupported KAS-ECC param %d", param);
            return AMVP_INVALID_ARG;

            break;
        }
        break;
    case AMVP_KAS_ECC_MODE_CDH:
    case AMVP_KAS_ECC_MAX_MODES:
    default:
        AMVP_LOG_ERR("Scheme parameter sets not supported for this mode %d\n", mode);
        return AMVP_INVALID_ARG;

        break;
    }
    return result;
}

/*
 * Append a KAS-FFC pre req val to the capabilities
 */
static AMVP_RESULT amvp_add_kas_ffc_prereq_val(AMVP_CTX *ctx, AMVP_KAS_FFC_CAP_MODE *kas_ffc_mode,
                                               AMVP_KAS_FFC_MODE mode,
                                               AMVP_PREREQ_ALG pre_req,
                                               char *value) {
    AMVP_PREREQ_LIST *prereq_entry, *prereq_entry_2;

    AMVP_LOG_INFO("KAS-FFC mode %d", mode);
    prereq_entry = calloc(1, sizeof(AMVP_PREREQ_LIST));
    if (!prereq_entry) {
        return AMVP_MALLOC_FAIL;
    }
    prereq_entry->prereq_alg_val.alg = pre_req;
    prereq_entry->prereq_alg_val.val = value;

    /*
     * 1st entry
     */
    if (!kas_ffc_mode->prereq_vals) {
        kas_ffc_mode->prereq_vals = prereq_entry;
    } else {
        /*
         * append to the last in the list
         */
        prereq_entry_2 = kas_ffc_mode->prereq_vals;
        while (prereq_entry_2->next) {
            prereq_entry_2 = prereq_entry_2->next;
        }
        prereq_entry_2->next = prereq_entry;
    }
    return AMVP_SUCCESS;
}

AMVP_RESULT amvp_cap_kas_ffc_set_prereq(AMVP_CTX *ctx,
                                        AMVP_CIPHER cipher,
                                        AMVP_KAS_FFC_MODE mode,
                                        AMVP_PREREQ_ALG pre_req,
                                        char *value) {
    AMVP_KAS_FFC_CAP_MODE *kas_ffc_mode;
    AMVP_KAS_FFC_CAP *kas_ffc_cap;
    AMVP_CAPS_LIST *cap_list;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    switch (pre_req) {
    case AMVP_PREREQ_CCM:
    case AMVP_PREREQ_CMAC:
    case AMVP_PREREQ_DRBG:
    case AMVP_PREREQ_DSA:
    case AMVP_PREREQ_HMAC:
    case AMVP_PREREQ_SHA:
    case AMVP_PREREQ_SAFE_PRIMES:
        break;
    case AMVP_PREREQ_AES:
    case AMVP_PREREQ_ECDSA:
    case AMVP_PREREQ_KAS:
    case AMVP_PREREQ_TDES:
    case AMVP_PREREQ_RSADP:
    case AMVP_PREREQ_RSA:
    case AMVP_PREREQ_KMAC:
    default:
        AMVP_LOG_ERR("\nUnsupported KAS-FFC prereq %d", pre_req);
        return AMVP_INVALID_ARG;
    }

    /*
     * Locate this cipher in the caps array
     */
    cap_list = amvp_locate_cap_entry(ctx, cipher);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    }

    /*
     * Locate cap mode from array
     */
    kas_ffc_cap = cap_list->cap.kas_ffc_cap;
    kas_ffc_mode = &kas_ffc_cap->kas_ffc_mode[mode - 1];

    /*
     * Add the value to the cap
     */
    return amvp_add_kas_ffc_prereq_val(ctx, kas_ffc_mode, mode, pre_req, value);
}

AMVP_RESULT amvp_cap_kas_ffc_enable(AMVP_CTX *ctx,
                                    AMVP_CIPHER cipher,
                                    int (*crypto_handler)(AMVP_TEST_CASE *test_case)) {
    AMVP_CAP_TYPE type = 0;
    AMVP_RESULT result = AMVP_SUCCESS;
    AMVP_SUB_KAS alg;

    if (!ctx) {
        return AMVP_NO_CTX;
    }
    if (!crypto_handler) {
        AMVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return AMVP_INVALID_ARG;
    }

    alg = amvp_get_kas_alg(cipher);
    if (alg == 0) {
        AMVP_LOG_ERR("Invalid cipher value");
        return AMVP_INVALID_ARG;
    }
    switch (alg) {
    case AMVP_SUB_KAS_FFC_SSC:
        type = AMVP_KAS_FFC_SSC_TYPE;
        break;
    case AMVP_SUB_KAS_FFC_COMP:
        type = AMVP_KAS_FFC_COMP_TYPE;
        break;
    case AMVP_SUB_KAS_FFC_NOCOMP:
        type = AMVP_KAS_FFC_NOCOMP_TYPE;
        break;
    case AMVP_SUB_KAS_ECC_CDH:
    case AMVP_SUB_KAS_ECC_COMP:
    case AMVP_SUB_KAS_ECC_NOCOMP:
    case AMVP_SUB_KAS_ECC_SSC:
    case AMVP_SUB_KAS_IFC_SSC: 
    case AMVP_SUB_KTS_IFC: 
    case AMVP_SUB_SAFE_PRIMES_KEYGEN:
    case AMVP_SUB_SAFE_PRIMES_KEYVER:
    case AMVP_SUB_KDA_ONESTEP:
    case AMVP_SUB_KDA_TWOSTEP:
    case AMVP_SUB_KDA_HKDF:
    default:
        AMVP_LOG_ERR("Invalid parameter 'cipher'");
        return AMVP_INVALID_ARG;
    }

    result = amvp_cap_list_append(ctx, type, cipher, crypto_handler);

    if (result == AMVP_DUP_CIPHER) {
        AMVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == AMVP_MALLOC_FAIL) {
        AMVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

AMVP_RESULT amvp_cap_kas_ffc_set_parm(AMVP_CTX *ctx,
                                      AMVP_CIPHER cipher,
                                      AMVP_KAS_FFC_MODE mode,
                                      AMVP_KAS_FFC_PARAM param,
                                      int value) {
    AMVP_CAPS_LIST *cap;
    AMVP_KAS_FFC_CAP *kas_ffc_cap;
    AMVP_KAS_FFC_CAP_MODE *kas_ffc_cap_mode;
    AMVP_SUB_KAS alg;
    AMVP_RESULT result = AMVP_SUCCESS;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    alg = amvp_get_kas_alg(cipher);
    if (alg == 0) {
        AMVP_LOG_ERR("Invalid cipher value");
        return AMVP_INVALID_ARG;
    }
    switch (alg) {
    case AMVP_SUB_KAS_FFC_COMP:
    case AMVP_SUB_KAS_FFC_NOCOMP:
    case AMVP_SUB_KAS_FFC_SSC:
        break;
    case AMVP_SUB_KAS_ECC_CDH:
    case AMVP_SUB_KAS_ECC_COMP:
    case AMVP_SUB_KAS_ECC_NOCOMP:
    case AMVP_SUB_KAS_ECC_SSC: 
    case AMVP_SUB_KAS_IFC_SSC: 
    case AMVP_SUB_KTS_IFC: 
    case AMVP_SUB_KDA_ONESTEP:
    case AMVP_SUB_KDA_TWOSTEP:
    case AMVP_SUB_KDA_HKDF:
    case AMVP_SUB_SAFE_PRIMES_KEYGEN:
    case AMVP_SUB_SAFE_PRIMES_KEYVER:
    default:
        AMVP_LOG_ERR("Invalid cipher");
        return AMVP_INVALID_ARG;
    }

    cap = amvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        return AMVP_NO_CAP;
    }

    kas_ffc_cap = cap->cap.kas_ffc_cap;
    if (!kas_ffc_cap) {
        return AMVP_NO_CAP;
    }
    kas_ffc_cap_mode = &kas_ffc_cap->kas_ffc_mode[mode - 1];
    switch (mode) {
    case AMVP_KAS_FFC_MODE_COMPONENT:
        switch (param) {
        case AMVP_KAS_FFC_FUNCTION:
            if (!value || value > AMVP_KAS_FFC_MAX_FUNCS) {
                AMVP_LOG_ERR("invalid kas ffc function");
                return AMVP_INVALID_ARG;
            }
            result = amvp_append_param_list(&kas_ffc_cap_mode->function, value);
            break;
        case AMVP_KAS_FFC_CURVE:
        case AMVP_KAS_FFC_ROLE:
        case AMVP_KAS_FFC_KDF:
        case AMVP_KAS_FFC_FB:
        case AMVP_KAS_FFC_FC:
        case AMVP_KAS_FFC_MODP2048:
        case AMVP_KAS_FFC_MODP3072:
        case AMVP_KAS_FFC_MODP4096:
        case AMVP_KAS_FFC_MODP6144:
        case AMVP_KAS_FFC_MODP8192:
        case AMVP_KAS_FFC_FFDHE2048:
        case AMVP_KAS_FFC_FFDHE3072:
        case AMVP_KAS_FFC_FFDHE4096:
        case AMVP_KAS_FFC_FFDHE6144:
        case AMVP_KAS_FFC_FFDHE8192:
        case AMVP_KAS_FFC_HASH:
        case AMVP_KAS_FFC_GEN_METH:
        default:
            AMVP_LOG_ERR("\nUnsupported KAS-FFC param %d", param);
            return AMVP_INVALID_ARG;

            break;
        }
        break;
    case AMVP_KAS_FFC_MODE_NONE:
        switch (param) {
        case AMVP_KAS_FFC_GEN_METH:
            result = amvp_append_param_list(&kas_ffc_cap_mode->genmeth, value);
            break;
        case AMVP_KAS_FFC_HASH:
            if ((value < AMVP_NO_SHA || value >= AMVP_HASH_ALG_MAX) && !(value & (value - 1))) {
                AMVP_LOG_ERR("Invalid hash alg value for KAS-FFC hash Z function");
                return AMVP_INVALID_ARG;
            }
            kas_ffc_cap_mode->hash = value;
            break;
        case AMVP_KAS_FFC_FUNCTION:
        case AMVP_KAS_FFC_CURVE:
        case AMVP_KAS_FFC_ROLE:
        case AMVP_KAS_FFC_KDF:
        case AMVP_KAS_FFC_FB:
        case AMVP_KAS_FFC_FC:
        case AMVP_KAS_FFC_MODP2048:
        case AMVP_KAS_FFC_MODP3072:
        case AMVP_KAS_FFC_MODP4096:
        case AMVP_KAS_FFC_MODP6144:
        case AMVP_KAS_FFC_MODP8192:
        case AMVP_KAS_FFC_FFDHE2048:
        case AMVP_KAS_FFC_FFDHE3072:
        case AMVP_KAS_FFC_FFDHE4096:
        case AMVP_KAS_FFC_FFDHE6144:
        case AMVP_KAS_FFC_FFDHE8192:
        default:
            AMVP_LOG_ERR("\nUnsupported KAS-FFC param %d", param);
            return AMVP_INVALID_ARG;

            break;
        }
        break;
    case AMVP_KAS_FFC_MODE_NOCOMP:
    case AMVP_KAS_FFC_MAX_MODES:
    default:
        AMVP_LOG_ERR("\nUnsupported KAS-FFC mode %d", mode);
        return AMVP_INVALID_ARG;

        break;
    }
    return result;
}

AMVP_RESULT amvp_cap_kas_ffc_set_scheme(AMVP_CTX *ctx,
                                        AMVP_CIPHER cipher,
                                        AMVP_KAS_FFC_MODE mode,
                                        AMVP_KAS_FFC_SCHEMES scheme,
                                        AMVP_KAS_FFC_PARAM param,
                                        int value) {
    AMVP_CAPS_LIST *cap;
    AMVP_KAS_FFC_CAP *kas_ffc_cap;
    AMVP_KAS_FFC_CAP_MODE *kas_ffc_cap_mode;
    AMVP_KAS_FFC_SCHEME *current_scheme;
    AMVP_KAS_FFC_PSET *current_pset;
    AMVP_KAS_FFC_PSET *last_pset = NULL;
    AMVP_RESULT result = AMVP_SUCCESS;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    cap = amvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        return AMVP_NO_CAP;
    }

    kas_ffc_cap = cap->cap.kas_ffc_cap;
    if (!kas_ffc_cap) {
        return AMVP_NO_CAP;
    }
    kas_ffc_cap_mode = &kas_ffc_cap->kas_ffc_mode[mode - 1];
    switch (mode) {
    case AMVP_KAS_FFC_MODE_COMPONENT:
    case AMVP_KAS_FFC_MODE_NOCOMP:
    case AMVP_KAS_FFC_MODE_NONE:
        if (!scheme || scheme >= AMVP_KAS_FFC_MAX_SCHEMES) {
            AMVP_LOG_ERR("Invalid kas ffc scheme");
            return AMVP_INVALID_ARG;
        }
        current_scheme = kas_ffc_cap_mode->scheme;
        while (current_scheme) {
            if (current_scheme->scheme == scheme) {
                break;
            } else {
                current_scheme = current_scheme->next;
            }
        }
        /* if there are none or didn't find the one we're looking for... */
        if (current_scheme == NULL) {
            kas_ffc_cap_mode->scheme = calloc(1, sizeof(AMVP_KAS_FFC_SCHEME));
            kas_ffc_cap_mode->scheme->scheme = scheme;
            current_scheme = kas_ffc_cap_mode->scheme;
        }
        switch (param) {
        case AMVP_KAS_FFC_KDF:
            if (!value || value > AMVP_KAS_FFC_PARMSET) {
                return AMVP_INVALID_ARG;
            }
            current_scheme->kdf = (AMVP_KAS_FFC_SET)value;
            break;
        case AMVP_KAS_FFC_ROLE:
            if (value != AMVP_KAS_FFC_ROLE_INITIATOR &&
                value != AMVP_KAS_FFC_ROLE_RESPONDER) {
                return AMVP_INVALID_ARG;
            }
            result = amvp_append_param_list(&current_scheme->role, value);
            break;
        case AMVP_KAS_FFC_FB:
        case AMVP_KAS_FFC_FC:
        case AMVP_KAS_FFC_MODP2048:
        case AMVP_KAS_FFC_MODP3072:
        case AMVP_KAS_FFC_MODP4096:
        case AMVP_KAS_FFC_MODP6144:
        case AMVP_KAS_FFC_MODP8192:
        case AMVP_KAS_FFC_FFDHE2048:
        case AMVP_KAS_FFC_FFDHE3072:
        case AMVP_KAS_FFC_FFDHE4096:
        case AMVP_KAS_FFC_FFDHE6144:
        case AMVP_KAS_FFC_FFDHE8192:
            current_pset = current_scheme->pset;
            while (current_pset) {
                if (current_pset->set == param) {
                    break;
                } else {
                    last_pset = current_pset;
                    current_pset = current_pset->next;
                }
            }
            if (!current_pset) {
                current_pset = calloc(1, sizeof(AMVP_KAS_FFC_PSET));
                if (current_scheme->pset == NULL) {
                    current_scheme->pset = current_pset;
                } else {
                    last_pset->next = current_pset;
                }
                current_pset->set = param;
            }
            //then set sha in a param list
            result = amvp_append_param_list(&current_pset->sha, value);
            break;
        case AMVP_KAS_FFC_FUNCTION:
        case AMVP_KAS_FFC_CURVE:
        case AMVP_KAS_FFC_HASH:
        case AMVP_KAS_FFC_GEN_METH:
        default:
            AMVP_LOG_ERR("\nUnsupported KAS-FFC param %d", param);
            return AMVP_INVALID_ARG;

            break;
        }
        break;
    case AMVP_KAS_FFC_MAX_MODES:
    default:
        AMVP_LOG_ERR("Scheme parameter sets not supported for this mode %d\n", mode);
        return AMVP_INVALID_ARG;

        break;
    }
    return result;
}

AMVP_RESULT amvp_cap_kas_ifc_enable(AMVP_CTX *ctx,
                                    AMVP_CIPHER cipher,
                                    int (*crypto_handler)(AMVP_TEST_CASE *test_case)) {
    AMVP_CAP_TYPE type = 0;
    AMVP_RESULT result = AMVP_SUCCESS;

    if (!ctx) {
        return AMVP_NO_CTX;
    }
    if (!crypto_handler) {
        AMVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return AMVP_INVALID_ARG;
    }
    type = AMVP_KAS_IFC_TYPE;
    result = amvp_cap_list_append(ctx, type, cipher, crypto_handler);

    if (result == AMVP_DUP_CIPHER) {
        AMVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == AMVP_MALLOC_FAIL) {
        AMVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

AMVP_RESULT amvp_cap_kas_ifc_set_parm(AMVP_CTX *ctx,
                                      AMVP_CIPHER cipher,
                                      AMVP_KAS_IFC_PARAM param,
                                      int value) {

    AMVP_KAS_IFC_CAP *kas_ifc_cap = NULL;
    AMVP_CAPS_LIST *cap;
    AMVP_RESULT result = AMVP_SUCCESS;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    cap = amvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        return AMVP_NO_CAP;
    }

    kas_ifc_cap = cap->cap.kas_ifc_cap;
    if (!kas_ifc_cap) {
        return AMVP_NO_CAP;
    }

    switch (param)
    {
    case AMVP_KAS_IFC_KAS1:
        result = amvp_append_param_list(&kas_ifc_cap->kas1_roles, value);
        break;
    case AMVP_KAS_IFC_KAS2:
        result = amvp_append_param_list(&kas_ifc_cap->kas2_roles, value);
        break;
    case AMVP_KAS_IFC_KEYGEN_METHOD:
        result = amvp_append_param_list(&kas_ifc_cap->keygen_method, value);
        break;
    case AMVP_KAS_IFC_MODULO:
        amvp_append_sl_list(&kas_ifc_cap->modulo, value);
        break;
    case AMVP_KAS_IFC_HASH:
        if ((value < AMVP_NO_SHA || value >= AMVP_HASH_ALG_MAX) && !(value & (value - 1))) {
            AMVP_LOG_ERR("Invalid hash alg value for KAS-IFC hash Z function");
            return AMVP_INVALID_ARG;
        }
        kas_ifc_cap->hash = value;        
        break;
    case AMVP_KAS_IFC_FIXEDPUBEXP:
    default:
        AMVP_LOG_ERR("Invalid param");
        return AMVP_INVALID_ARG;
        break;
    }
    return result;
}

AMVP_RESULT amvp_cap_kas_ifc_set_exponent(AMVP_CTX *ctx,
                                          AMVP_CIPHER cipher,
                                          AMVP_KAS_IFC_PARAM param,
                                          char *value) {
    unsigned int len = strnlen_s(value, AMVP_CAPABILITY_STR_MAX + 1);
    AMVP_KAS_IFC_CAP *kas_ifc_cap = NULL;
    AMVP_CAPS_LIST *cap;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    cap = amvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        return AMVP_NO_CAP;
    }

    kas_ifc_cap = cap->cap.kas_ifc_cap;
    if (!kas_ifc_cap) {
        return AMVP_NO_CAP;
    }

    if (len > AMVP_CAPABILITY_STR_MAX) {
        AMVP_LOG_ERR("Parameter 'value' string is too long. "
                     "max allowed is (%d) characters.",
                      AMVP_CAPABILITY_STR_MAX);
        return AMVP_INVALID_ARG;
    }

    if (param != AMVP_KAS_IFC_FIXEDPUBEXP) {
        return AMVP_INVALID_ARG;
    }        
    kas_ifc_cap->fixed_pub_exp = calloc(len + 1, sizeof(char));
    strcpy_s(kas_ifc_cap->fixed_pub_exp, len + 1, value);
    return AMVP_SUCCESS;
}

AMVP_RESULT amvp_cap_kda_enable(AMVP_CTX *ctx,
                                    AMVP_CIPHER cipher,
                                    int (*crypto_handler)(AMVP_TEST_CASE *test_case)) {
    AMVP_CAP_TYPE type = 0;
    AMVP_RESULT result = AMVP_SUCCESS;
    AMVP_SUB_KAS alg;

    if (!ctx) {
        return AMVP_NO_CTX;
    }
    if (!crypto_handler) {
        AMVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return AMVP_INVALID_ARG;
    }

    alg = amvp_get_kas_alg(cipher);
    if (alg == 0) {
        AMVP_LOG_ERR("Invalid cipher value");
        return AMVP_INVALID_ARG;
    }
    switch (alg) {
    case AMVP_SUB_KDA_ONESTEP:
        type = AMVP_KDA_ONESTEP_TYPE;
        break;
    case AMVP_SUB_KDA_TWOSTEP:
        type = AMVP_KDA_TWOSTEP_TYPE;
        break;
    case AMVP_SUB_KDA_HKDF:
        type = AMVP_KDA_HKDF_TYPE;
        break;
    case AMVP_SUB_KAS_ECC_CDH:
    case AMVP_SUB_KAS_ECC_COMP:
    case AMVP_SUB_KAS_ECC_NOCOMP:
    case AMVP_SUB_KAS_ECC_SSC:
    case AMVP_SUB_KAS_FFC_COMP:
    case AMVP_SUB_KAS_FFC_NOCOMP:
    case AMVP_SUB_KAS_FFC_SSC:
    case AMVP_SUB_KAS_IFC_SSC:
    case AMVP_SUB_KTS_IFC:
    case AMVP_SUB_SAFE_PRIMES_KEYGEN:
    case AMVP_SUB_SAFE_PRIMES_KEYVER:
    default:
        AMVP_LOG_ERR("Invalid parameter 'cipher'");
        return AMVP_INVALID_ARG;
    }

    result = amvp_cap_list_append(ctx, type, cipher, crypto_handler);

    if (result == AMVP_DUP_CIPHER) {
        AMVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == AMVP_MALLOC_FAIL) {
        AMVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

AMVP_RESULT amvp_cap_kda_set_parm(AMVP_CTX *ctx, AMVP_CIPHER cipher, AMVP_KDA_PARM param,
                                      int value, const char* string) {
    AMVP_CAPS_LIST *cap_list = NULL;
    AMVP_RESULT result = AMVP_SUCCESS;
    const char* tmp = NULL;
    AMVP_SUB_KAS alg;
    AMVP_KDA_HKDF_CAP *hkdf_cap = NULL;
    AMVP_KDA_ONESTEP_CAP *os_cap = NULL;

    /*
     * Validate input
     */
    if (!ctx) {
        return AMVP_NO_CTX;
    }

    if (param == AMVP_KDA_PATTERN && value == AMVP_KDA_PATTERN_LITERAL && !string) {
        AMVP_LOG_ERR("string must not be null when setting literal pattern for KDA algorithms.");
        return AMVP_INVALID_ARG;
    } 
    if (string && (param != AMVP_KDA_PATTERN || value != AMVP_KDA_PATTERN_LITERAL)) {
        AMVP_LOG_WARN("String parameter should only be used when setting literal pattern. Ignoring value...");
    }

    /*
     * Locate this cipher in the caps array
     */
    cap_list = amvp_locate_cap_entry(ctx, cipher);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    }

    alg = amvp_get_kas_alg(cipher);
    if (alg == 0) {
        AMVP_LOG_ERR("Invalid cipher value");
        return 1;
    }

    switch (alg) {
    case AMVP_SUB_KDA_ONESTEP:
        os_cap = cap_list->cap.kda_onestep_cap;
        if (!os_cap) {
            AMVP_LOG_ERR("KDA onestep cap entry not found.");
            return AMVP_NO_CAP;
        }
        switch (param) {
        case AMVP_KDA_PATTERN:
            if (value == AMVP_KDA_PATTERN_LITERAL && os_cap->literal_pattern_candidate) {
                AMVP_LOG_WARN("Literal pattern candidate was already previously set. Replacing...");
                free(os_cap->literal_pattern_candidate);
                os_cap->literal_pattern_candidate = NULL;
            }
            if (value == AMVP_KDA_PATTERN_LITERAL) {
                int len = strnlen_s(string, AMVP_KDA_PATTERN_LITERAL_STR_LEN_MAX + 1);
                if (len > AMVP_KDA_PATTERN_LITERAL_STR_LEN_MAX) {
                    AMVP_LOG_ERR("Provided literal string too long");
                    return AMVP_INVALID_ARG;
                } else if (len < 1) {
                    AMVP_LOG_ERR("Provided literal string empty");
                    return AMVP_INVALID_ARG;
                }
                os_cap->literal_pattern_candidate = calloc(AMVP_KDA_PATTERN_LITERAL_STR_LEN_MAX + 1, sizeof(char));
                if (!os_cap->literal_pattern_candidate) {
                    AMVP_LOG_ERR("Unable to allocate memory for literal pattern candidate");
                    return AMVP_MALLOC_FAIL;
                }
                strncpy_s(os_cap->literal_pattern_candidate, 
                          AMVP_KDA_PATTERN_LITERAL_STR_LEN_MAX, string, len);
            }
            if (value > AMVP_KDA_PATTERN_NONE && value < AMVP_KDA_PATTERN_MAX) {
                result = amvp_append_param_list(&os_cap->patterns, value);
            } else {
                AMVP_LOG_ERR("Invalid pattern type specified when setting param for KDA onestep.");
                return AMVP_INVALID_ARG;
            }
            break;
        case AMVP_KDA_REVISION:
            if (value != AMVP_REVISION_SP800_56CR1) {
                AMVP_LOG_ERR("Invalid revision for KDA specified.");
                return AMVP_INVALID_ARG;
            }
            os_cap->revision = value;
            break;
        case AMVP_KDA_ENCODING_TYPE:
            if (value > AMVP_KDA_ENCODING_NONE && value < AMVP_KDA_ENCODING_MAX) {
                result = amvp_append_param_list(&os_cap->encodings, value);
            } else {
                AMVP_LOG_ERR("Invalid encoding type specified when setting param for KDA onestep.");
                return AMVP_INVALID_ARG;
            }
            break;
        case AMVP_KDA_L:
            if (value <= 0) {
                AMVP_LOG_ERR("Valid for l must be > 0");
                return AMVP_INVALID_ARG;
            } else  if (value % 8 != 0) {
                AMVP_LOG_ERR("Value for l for KDA onestep must be convertable to exact bytes (mod 8)");
                return AMVP_INVALID_ARG;
            } else {
                os_cap->l = value;
            }
            break;
        case AMVP_KDA_MAC_SALT:
            if (value == AMVP_KDA_MAC_SALT_METHOD_DEFAULT) {
                result = amvp_append_name_list(&os_cap->mac_salt_methods,
                                               AMVP_KDA_MAC_SALT_METHOD_DEFAULT_STR);
            } else if (value == AMVP_KDA_MAC_SALT_METHOD_RANDOM) {
                result = amvp_append_name_list(&os_cap->mac_salt_methods,
                                               AMVP_KDA_MAC_SALT_METHOD_RANDOM_STR);
            } else {
                AMVP_LOG_ERR("Invalid value for ACVK_KDA_MAC_SALT");
                return AMVP_INVALID_ARG;
            }
            break;
        case AMVP_KDA_ONESTEP_AUX_FUNCTION:
            tmp = amvp_lookup_aux_function_alg_str(value);
            if (!tmp) {
                AMVP_LOG_ERR("Invalid aux function cipher provided");
                return AMVP_INVALID_ARG;
            }
            result = amvp_append_name_list(&os_cap->aux_functions, tmp);
            break;
        case AMVP_KDA_Z:
        case AMVP_KDA_USE_HYBRID_SECRET:
        case AMVP_KDA_PERFORM_MULTIEXPANSION_TESTS:
        case AMVP_KDA_MAC_ALG:
        case AMVP_KDA_TWOSTEP_SUPPORTED_LEN:
        case AMVP_KDA_TWOSTEP_FIXED_DATA_ORDER:
        case AMVP_KDA_TWOSTEP_COUNTER_LEN:
        case AMVP_KDA_TWOSTEP_SUPPORTS_EMPTY_IV:
        case AMVP_KDA_TWOSTEP_REQUIRES_EMPTY_IV:
        default:
            AMVP_LOG_ERR("Invalid parameter specified");
            return AMVP_INVALID_ARG;
        }
        break;
    case AMVP_SUB_KDA_HKDF:
        hkdf_cap = cap_list->cap.kda_hkdf_cap;
        if (!hkdf_cap) {
            AMVP_LOG_ERR("KDA-HKDF entry not found.");
            return AMVP_NO_CAP;
        }
        switch (param) {
        case AMVP_KDA_PATTERN:
            if (value == AMVP_KDA_PATTERN_LITERAL && hkdf_cap->literal_pattern_candidate) {
                AMVP_LOG_WARN("Literal pattern candidate was already previously set. Replacing...");
                free(hkdf_cap->literal_pattern_candidate);
                hkdf_cap->literal_pattern_candidate = NULL;
            }
            if (value == AMVP_KDA_PATTERN_LITERAL) {
                int len = strnlen_s(string, AMVP_KDA_PATTERN_LITERAL_STR_LEN_MAX + 1);
                if (len > AMVP_KDA_PATTERN_LITERAL_STR_LEN_MAX) {
                    AMVP_LOG_ERR("Provided literal string too long");
                    return AMVP_INVALID_ARG;
                } else if (len < 1) {
                    AMVP_LOG_ERR("Provided literal string empty");
                    return AMVP_INVALID_ARG;
                }
                hkdf_cap->literal_pattern_candidate = calloc(AMVP_KDA_PATTERN_LITERAL_STR_LEN_MAX + 1, sizeof(char));
                if (!hkdf_cap->literal_pattern_candidate) {
                    AMVP_LOG_ERR("Unable to allocate memory for literal pattern candidate");
                    return AMVP_MALLOC_FAIL;
                }
                strncpy_s(hkdf_cap->literal_pattern_candidate, 
                          AMVP_KDA_PATTERN_LITERAL_STR_LEN_MAX, string, len);
            }
            if (value == AMVP_KDA_PATTERN_T) {
                AMVP_LOG_ERR("T is only a valid pattern for KDA onestep");
                return AMVP_INVALID_ARG;
            }
            if (value > AMVP_KDA_PATTERN_NONE && value < AMVP_KDA_PATTERN_MAX) {
                result = amvp_append_param_list(&hkdf_cap->patterns, value);
            } else {
                AMVP_LOG_ERR("Invalid pattern type specified when setting param for KDA-HKDF.");
                return AMVP_INVALID_ARG;
            }
            break;
        case AMVP_KDA_REVISION:
            if (value != AMVP_REVISION_SP800_56CR1) {
                AMVP_LOG_ERR("Invalid revision for KDA specified.");
                return AMVP_INVALID_ARG;
            }
            hkdf_cap->revision = value;
            break;
        case AMVP_KDA_ENCODING_TYPE:
            if (value > AMVP_KDA_ENCODING_NONE && value < AMVP_KDA_ENCODING_MAX) {
                result = amvp_append_param_list(&hkdf_cap->encodings, value);
            } else {
                AMVP_LOG_ERR("Invalid encoding type specified when setting param for KDA-HKDF.");
                return AMVP_INVALID_ARG;
            }
            break;
        case AMVP_KDA_L:
            if (value <= 0) {
                AMVP_LOG_ERR("Valid for l must be > 0");
                return AMVP_INVALID_ARG;
            } else  if (value % 8 != 0) {
                AMVP_LOG_ERR("Value for l for KDA-HKDF must be convertable to exact bytes (mod 8)");
                return AMVP_INVALID_ARG;
            } else {
                hkdf_cap->l = value;
            }
            break;
        case AMVP_KDA_MAC_SALT:
            if (value == AMVP_KDA_MAC_SALT_METHOD_DEFAULT) {
                result = amvp_append_name_list(&hkdf_cap->mac_salt_methods,
                                               AMVP_KDA_MAC_SALT_METHOD_DEFAULT_STR);
            } else if (value == AMVP_KDA_MAC_SALT_METHOD_RANDOM) {
                result = amvp_append_name_list(&hkdf_cap->mac_salt_methods,
                                               AMVP_KDA_MAC_SALT_METHOD_RANDOM_STR);
            } else {
                AMVP_LOG_ERR("Invalid value for ACVK_KDA_MAC_SALT");
                return AMVP_INVALID_ARG;
            }
            break;
        case AMVP_KDA_MAC_ALG:
            tmp = amvp_lookup_hash_alg_name(value);
            if (!tmp) {
                AMVP_LOG_ERR("Invalid value for hmac alg for KDA-HKDF");
                return AMVP_INVALID_ARG;
            }
            result = amvp_append_name_list(&hkdf_cap->hmac_algs, tmp);
            break;
        case AMVP_KDA_USE_HYBRID_SECRET:
            /* revision is only set for non-default revisions */
            if (cap_list->cap.kda_hkdf_cap->revision) {
                AMVP_LOG_ERR("Hybrid secrets for HKDF can only be set for revision SP800-56Cr2");
                return AMVP_INVALID_ARG;
            }
            result = amvp_append_sl_list(&cap_list->cap.kda_hkdf_cap->aux_secret_len.values, value);
            if (result == AMVP_SUCCESS) {
                cap_list->cap.kda_hkdf_cap->use_hybrid_shared_secret = 1;
            }
            break;
        case AMVP_KDA_PERFORM_MULTIEXPANSION_TESTS:
            if (value > 0) {
                hkdf_cap->perform_multi_expansion_tests = 1;
            } else {
                hkdf_cap->perform_multi_expansion_tests = 0;
            }
            break;
        case AMVP_KDA_Z:
        case AMVP_KDA_ONESTEP_AUX_FUNCTION:
        case AMVP_KDA_TWOSTEP_SUPPORTED_LEN:
        case AMVP_KDA_TWOSTEP_FIXED_DATA_ORDER:
        case AMVP_KDA_TWOSTEP_COUNTER_LEN:
        case AMVP_KDA_TWOSTEP_SUPPORTS_EMPTY_IV:
        case AMVP_KDA_TWOSTEP_REQUIRES_EMPTY_IV:
        default:
            AMVP_LOG_ERR("Invalid parameter specified");
            return AMVP_INVALID_ARG;
        }
        break;
    case AMVP_SUB_KDA_TWOSTEP:
    case AMVP_SUB_KAS_ECC_CDH:
    case AMVP_SUB_KAS_ECC_COMP:
    case AMVP_SUB_KAS_ECC_NOCOMP:
    case AMVP_SUB_KAS_ECC_SSC:
    case AMVP_SUB_KAS_FFC_COMP:
    case AMVP_SUB_KAS_FFC_NOCOMP:
    case AMVP_SUB_KAS_FFC_SSC:
    case AMVP_SUB_KAS_IFC_SSC:
    case AMVP_SUB_KTS_IFC:
    case AMVP_SUB_SAFE_PRIMES_KEYGEN:
    case AMVP_SUB_SAFE_PRIMES_KEYVER:
    default:
        AMVP_LOG_ERR("Invalid cipher specified");
        return AMVP_INVALID_ARG;
    }
    return result;
}

AMVP_RESULT amvp_cap_kda_twostep_set_parm(AMVP_CTX *ctx, AMVP_KDA_PARM param,
                                      int value, int kdf_mode, const char* string) {
    AMVP_CAPS_LIST *cap_list = NULL;
    AMVP_RESULT result = AMVP_SUCCESS;
    AMVP_KDA_TWOSTEP_CAP *cap = NULL;
    AMVP_KDF108_MODE_PARAMS *mode_obj = NULL;

    /* Validate input */
    if (!ctx) {
        return AMVP_NO_CTX;
    }

    cap_list = amvp_locate_cap_entry(ctx, AMVP_KDA_TWOSTEP);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found. You must enable algorithm before setting parameters.");
        return AMVP_NO_CAP;
    }

    cap = cap_list->cap.kda_twostep_cap;
    if (!cap) {
        return AMVP_NO_CAP;
    }

    /* check if a valid KDF108 mode has been provided if needed */
    switch (param) {
    case AMVP_KDA_TWOSTEP_SUPPORTED_LEN:
    case AMVP_KDA_TWOSTEP_FIXED_DATA_ORDER:
    case AMVP_KDA_TWOSTEP_COUNTER_LEN:
    case AMVP_KDA_TWOSTEP_SUPPORTS_EMPTY_IV:
    case AMVP_KDA_TWOSTEP_REQUIRES_EMPTY_IV:
    case AMVP_KDA_MAC_ALG: 
        switch (kdf_mode) {
        case AMVP_KDF108_MODE_COUNTER:
            mode_obj = &cap->kdf_params.counter_mode;
            if (!mode_obj->kdf_mode) {
                mode_obj->kdf_mode = AMVP_MODE_COUNTER;
            }
            break;
        case AMVP_KDF108_MODE_DPI:
            mode_obj = &cap->kdf_params.dpi_mode;
            if (!mode_obj->kdf_mode) {
                mode_obj->kdf_mode = AMVP_MODE_DPI;
            }
            break;
        case AMVP_KDF108_MODE_FEEDBACK:
            mode_obj = &cap->kdf_params.feedback_mode;
            if (!mode_obj->kdf_mode) {
                mode_obj->kdf_mode = AMVP_MODE_FEEDBACK;
            }
            break;
        default:
            AMVP_LOG_ERR("Must use a valid KDF108 mode when setting certain parameters in KDA twostep");
            return AMVP_INVALID_ARG;
        }
        break;
    case AMVP_KDA_PATTERN:
    case AMVP_KDA_ENCODING_TYPE:
    case AMVP_KDA_MAC_SALT:
    case AMVP_KDA_REVISION:
    case AMVP_KDA_L:
    case AMVP_KDA_PERFORM_MULTIEXPANSION_TESTS:
    case AMVP_KDA_USE_HYBRID_SECRET:
    case AMVP_KDA_Z:
    case AMVP_KDA_ONESTEP_AUX_FUNCTION:
    default:
        break;
    }

    if (param == AMVP_KDA_PATTERN && value == AMVP_KDA_PATTERN_LITERAL && !string) {
        AMVP_LOG_ERR("string must not be null when setting literal pattern for KDA algorithms.");
        return AMVP_INVALID_ARG;
    } 
    if (string && (param != AMVP_KDA_PATTERN || value != AMVP_KDA_PATTERN_LITERAL)) {
        AMVP_LOG_WARN("String parameter should only be used when setting literal pattern. Ignoring value...");
    }

    switch (param) {
    case AMVP_KDA_PATTERN:
        if (value == AMVP_KDA_PATTERN_LITERAL && cap->literal_pattern_candidate) {
            AMVP_LOG_WARN("Literal pattern candidate was already previously set. Replacing...");
            free(cap->literal_pattern_candidate);
            cap->literal_pattern_candidate = NULL;
        }
        if (value == AMVP_KDA_PATTERN_LITERAL) {
            int len = strnlen_s(string, AMVP_KDA_PATTERN_LITERAL_STR_LEN_MAX + 1);
            if (len > AMVP_KDA_PATTERN_LITERAL_STR_LEN_MAX) {
                AMVP_LOG_ERR("Provided literal string too long");
                return AMVP_INVALID_ARG;
            } else if (len < 1) {
                AMVP_LOG_ERR("Provided literal string empty");
                return AMVP_INVALID_ARG;
            }
            cap->literal_pattern_candidate = calloc(AMVP_KDA_PATTERN_LITERAL_STR_LEN_MAX + 1, sizeof(char));
            if (!cap->literal_pattern_candidate) {
                AMVP_LOG_ERR("Unable to allocate memory for literal pattern candidate");
                return AMVP_MALLOC_FAIL;
            }
            strncpy_s(cap->literal_pattern_candidate, 
                        AMVP_KDA_PATTERN_LITERAL_STR_LEN_MAX, string, len);
        }
        if (value > AMVP_KDA_PATTERN_NONE && value < AMVP_KDA_PATTERN_MAX) {
            result = amvp_append_param_list(&cap->patterns, value);
        } else {
            AMVP_LOG_ERR("Invalid pattern type specified when setting param for KDA twostep.");
            return AMVP_INVALID_ARG;
        }
        break;
    case AMVP_KDA_REVISION:
        if (value != AMVP_REVISION_SP800_56CR1) {
            AMVP_LOG_ERR("Invalid revision for KDA specified.");
            return AMVP_INVALID_ARG;
        }
        cap->revision = value;
        break;
    case AMVP_KDA_ENCODING_TYPE:
        if (value > AMVP_KDA_ENCODING_NONE && value < AMVP_KDA_ENCODING_MAX) {
            result = amvp_append_param_list(&cap->encodings, value);
        } else {
            AMVP_LOG_ERR("Invalid encoding type specified when setting param for KDA twostep.");
            return AMVP_INVALID_ARG;
        }
        break;
    case AMVP_KDA_L:
        if (value <= 0) {
            AMVP_LOG_ERR("Valid for l must be > 0");
            return AMVP_INVALID_ARG;
        } else  if (value % 8 != 0) {
            AMVP_LOG_ERR("Value for l for KDA twostep must be convertable to exact bytes (mod 8)");
            return AMVP_INVALID_ARG;
        } else {
            cap->l = value;
        }
        break;
    case AMVP_KDA_MAC_SALT:
        if (value == AMVP_KDA_MAC_SALT_METHOD_DEFAULT) {
            result = amvp_append_name_list(&cap->mac_salt_methods,
                                            AMVP_KDA_MAC_SALT_METHOD_DEFAULT_STR);
        } else if (value == AMVP_KDA_MAC_SALT_METHOD_RANDOM) {
            result = amvp_append_name_list(&cap->mac_salt_methods,
                                            AMVP_KDA_MAC_SALT_METHOD_RANDOM_STR);
        } else {
            AMVP_LOG_ERR("Invalid value for ACVK_KDA_MAC_SALT");
            return AMVP_INVALID_ARG;
        }
        break;
    case AMVP_KDA_MAC_ALG:
        switch (value) {
            case AMVP_KDF108_MAC_MODE_CMAC_AES128:
                result = amvp_append_name_list(&mode_obj->mac_mode, AMVP_ALG_CMAC_AES_128);
                break;
            case AMVP_KDF108_MAC_MODE_CMAC_AES192:
                result = amvp_append_name_list(&mode_obj->mac_mode, AMVP_ALG_CMAC_AES_192);
                break;
            case AMVP_KDF108_MAC_MODE_CMAC_AES256:
                result = amvp_append_name_list(&mode_obj->mac_mode, AMVP_ALG_CMAC_AES_256);
                break;
            case AMVP_KDF108_MAC_MODE_HMAC_SHA1:
                result = amvp_append_name_list(&mode_obj->mac_mode, AMVP_ALG_HMAC_SHA1);
                break;
            case AMVP_KDF108_MAC_MODE_HMAC_SHA224:
                result = amvp_append_name_list(&mode_obj->mac_mode, AMVP_ALG_HMAC_SHA2_224);
                break;
            case AMVP_KDF108_MAC_MODE_HMAC_SHA256:
                result = amvp_append_name_list(&mode_obj->mac_mode, AMVP_ALG_HMAC_SHA2_256);
                break;
            case AMVP_KDF108_MAC_MODE_HMAC_SHA384:
                result = amvp_append_name_list(&mode_obj->mac_mode, AMVP_ALG_HMAC_SHA2_384);
                break;
            case AMVP_KDF108_MAC_MODE_HMAC_SHA512:
                result = amvp_append_name_list(&mode_obj->mac_mode, AMVP_ALG_HMAC_SHA2_512);
                break;
            case AMVP_KDF108_MAC_MODE_HMAC_SHA512_224:
                result = amvp_append_name_list(&mode_obj->mac_mode, AMVP_ALG_HMAC_SHA2_512_224);
                break;
            case AMVP_KDF108_MAC_MODE_HMAC_SHA512_256:
                result = amvp_append_name_list(&mode_obj->mac_mode, AMVP_ALG_HMAC_SHA2_512_256);
                break;
            case AMVP_KDF108_MAC_MODE_HMAC_SHA3_224:
                result = amvp_append_name_list(&mode_obj->mac_mode, AMVP_ALG_HMAC_SHA3_224);
                break;
            case AMVP_KDF108_MAC_MODE_HMAC_SHA3_256:
                result = amvp_append_name_list(&mode_obj->mac_mode, AMVP_ALG_HMAC_SHA3_256);
                break;
            case AMVP_KDF108_MAC_MODE_HMAC_SHA3_384:
                result = amvp_append_name_list(&mode_obj->mac_mode, AMVP_ALG_HMAC_SHA3_384);
                break;
            case AMVP_KDF108_MAC_MODE_HMAC_SHA3_512:
                result = amvp_append_name_list(&mode_obj->mac_mode, AMVP_ALG_HMAC_SHA3_512);
                break;
            case AMVP_KDF108_MAC_MODE_CMAC_TDES:
            default:
                AMVP_LOG_ERR("Given MAC mode not supported for KDA Twostep");
                return AMVP_INVALID_ARG;
            }
        break;
    case AMVP_KDA_USE_HYBRID_SECRET:
        if (cap_list->cap.kda_twostep_cap->revision) {
            AMVP_LOG_ERR("Hybrid secrets for twostep can only be set for revision SP800-56Cr2");
            return AMVP_INVALID_ARG;
        }
        amvp_append_sl_list(&cap_list->cap.kda_twostep_cap->aux_secret_len.values, value);
        cap_list->cap.kda_twostep_cap->use_hybrid_shared_secret = 1;
        break;
    case AMVP_KDA_PERFORM_MULTIEXPANSION_TESTS:
        if (value > 0) {
            cap->perform_multi_expansion_tests = 1;
        } else {
            cap->perform_multi_expansion_tests = 0;
        }
        break;
    /* For these, a KDF108 mode must be provided */
    case AMVP_KDA_TWOSTEP_FIXED_DATA_ORDER:
        switch (value) {
        case AMVP_KDF108_FIXED_DATA_ORDER_AFTER:
            result = amvp_append_name_list(&mode_obj->data_order, AMVP_FIXED_DATA_ORDER_AFTER_STR);
            break;
        case AMVP_KDF108_FIXED_DATA_ORDER_BEFORE:
            result = amvp_append_name_list(&mode_obj->data_order, AMVP_FIXED_DATA_ORDER_BEFORE_STR);
            break;
        case AMVP_KDF108_FIXED_DATA_ORDER_MIDDLE:
            result = amvp_append_name_list(&mode_obj->data_order, AMVP_FIXED_DATA_ORDER_MIDDLE_STR);
            break;
        case AMVP_KDF108_FIXED_DATA_ORDER_NONE:
            result = amvp_append_name_list(&mode_obj->data_order, AMVP_FIXED_DATA_ORDER_NONE_STR);
            break;
        case AMVP_KDF108_FIXED_DATA_ORDER_BEFORE_ITERATOR:
            result = amvp_append_name_list(&mode_obj->data_order, AMVP_FIXED_DATA_ORDER_BEFORE_ITERATOR_STR);
            break;
        default:
            AMVP_LOG_ERR("Invalid fixed data order provided for KDA Twostep");
            return AMVP_INVALID_ARG;
        }
        break;
    case AMVP_KDA_TWOSTEP_COUNTER_LEN:
        if (value < 1 || value > AMVP_KDF108_KEYIN_BIT_MAX) {
            printf("Invalid value provided for KDA twostep supported length");
            return AMVP_INVALID_ARG;
        }
        amvp_append_sl_list(&mode_obj->counter_lens, value);
        break;
    case AMVP_KDA_TWOSTEP_SUPPORTS_EMPTY_IV:
        mode_obj->empty_iv_support = value;
        break;
    case AMVP_KDA_TWOSTEP_REQUIRES_EMPTY_IV:
        if (mode_obj->empty_iv_support == 0) {
            AMVP_LOG_ERR("REQUIRES_EMPTY_IV for twostep modes can only be set if SUPPORTS_EMPTY_IV is true");
            return AMVP_INVALID_ARG;
        } else {
            mode_obj->requires_empty_iv = value;
        }
        break;
    case AMVP_KDA_TWOSTEP_SUPPORTED_LEN:
        result = amvp_append_sl_list(&mode_obj->supported_lens.values, value);
        break;
    case AMVP_KDA_Z:
    case AMVP_KDA_ONESTEP_AUX_FUNCTION:
    default:
        AMVP_LOG_ERR("Invalid parameter specified %d", param);
        return AMVP_INVALID_ARG;
    }

    return result;
}

AMVP_RESULT amvp_cap_kda_twostep_set_domain(AMVP_CTX *ctx, AMVP_KDA_PARM param,
                                      int min, int max, int increment, int kdf_mode) {
    AMVP_CAPS_LIST *cap_list = NULL;
    AMVP_RESULT result = AMVP_SUCCESS;
    AMVP_KDA_TWOSTEP_CAP *cap = NULL;
    AMVP_KDF108_MODE_PARAMS *mode_obj = NULL;

    /* Validate input */
    if (!ctx) {
        return AMVP_NO_CTX;
    }

    cap_list = amvp_locate_cap_entry(ctx, AMVP_KDA_TWOSTEP);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found. You must enable algorithm before setting parameters.");
        return AMVP_NO_CAP;
    }

    cap = cap_list->cap.kda_twostep_cap;
    if (!cap) {
        return AMVP_NO_CAP;
    }

    switch (param) {
    case AMVP_KDA_TWOSTEP_SUPPORTED_LEN:
        switch (kdf_mode) {
        case AMVP_KDF108_MODE_COUNTER:
            mode_obj = &cap->kdf_params.counter_mode;
            if (!mode_obj->kdf_mode) {
                mode_obj->kdf_mode = AMVP_MODE_COUNTER;
            }
            break;
        case AMVP_KDF108_MODE_DPI:
            mode_obj = &cap->kdf_params.dpi_mode;
            if (!mode_obj->kdf_mode) {
                mode_obj->kdf_mode = AMVP_MODE_DPI;
            }
            break;
        case AMVP_KDF108_MODE_FEEDBACK:
            mode_obj = &cap->kdf_params.feedback_mode;
            if (!mode_obj->kdf_mode) {
                mode_obj->kdf_mode = AMVP_MODE_FEEDBACK;
            }
            break;
        default:
            AMVP_LOG_ERR("Must use a valid KDF108 mode when setting certain parameters in KDA twostep");
            return AMVP_INVALID_ARG;
        }
        if (!increment) {
            AMVP_LOG_ERR("Invalid domain provided for KDA twostep supported len");
            return AMVP_INVALID_ARG;
        }
        mode_obj->supported_lens.min = min;
        mode_obj->supported_lens.max = max;
        mode_obj->supported_lens.increment = increment;
        break;
    case AMVP_KDA_Z:
        if (min < 224 || max > 65536 || increment % 8 != 0) {
            AMVP_LOG_ERR("Invalid Z domain provided for KDA twostep");
            return AMVP_INVALID_ARG;
        }
        cap->z.min = min;
        cap->z.max = max;
        cap->z.increment = increment;
        break;
    case AMVP_KDA_USE_HYBRID_SECRET:
        if (cap_list->cap.kda_twostep_cap->revision) {
            AMVP_LOG_ERR("Hybrid secrets for twostep can only be set for revision SP800-56Cr2");
            return AMVP_INVALID_ARG;
        }
        if (min < 112 || max > 65536 || increment % 8 != 0) {
            AMVP_LOG_ERR("Invalid aux secret len domain provided for twostep");
            return AMVP_INVALID_ARG;
        }
        cap->aux_secret_len.min = min;
        cap->aux_secret_len.max = max;
        cap->aux_secret_len.increment = increment;
        cap->use_hybrid_shared_secret = 1;
        break;
    case AMVP_KDA_PATTERN:
    case AMVP_KDA_REVISION:
    case AMVP_KDA_ENCODING_TYPE:
    case AMVP_KDA_L:
    case AMVP_KDA_MAC_SALT:
    case AMVP_KDA_MAC_ALG:
    case AMVP_KDA_PERFORM_MULTIEXPANSION_TESTS:
    case AMVP_KDA_TWOSTEP_FIXED_DATA_ORDER:
    case AMVP_KDA_TWOSTEP_COUNTER_LEN:
    case AMVP_KDA_TWOSTEP_SUPPORTS_EMPTY_IV:
    case AMVP_KDA_TWOSTEP_REQUIRES_EMPTY_IV:
    case AMVP_KDA_ONESTEP_AUX_FUNCTION:
    default:
        AMVP_LOG_ERR("Invalid parameter specified %d", param);
        return AMVP_INVALID_ARG;
    }

    return result;
}

AMVP_RESULT amvp_cap_kda_set_domain(AMVP_CTX *ctx, AMVP_CIPHER cipher, AMVP_KDA_PARM param,
                                        int min, int max, int increment) {
    AMVP_CAPS_LIST *cap_list = NULL;
    AMVP_RESULT result = AMVP_SUCCESS;
    AMVP_SUB_KAS alg;
    /*
     * Validate input
     */  
    if (!ctx) {
        return AMVP_NO_CTX;
    }

    /*
     * Locate this cipher in the caps array
     */
    cap_list = amvp_locate_cap_entry(ctx, cipher);
    if (!cap_list) {
        AMVP_LOG_ERR("Cap entry not found.");
        return AMVP_NO_CAP;
    }

    if (min < 0 || max < min || max - min < 8) {
        AMVP_LOG_ERR("Invalid domain given");
    }

    alg = amvp_get_kas_alg(cipher);
    if (alg == 0) {
        AMVP_LOG_ERR("Invalid cipher value");
        return 1;
    }

    switch (alg) {
    case AMVP_SUB_KDA_ONESTEP:
        if (!cap_list->cap.kda_onestep_cap) {
            AMVP_LOG_ERR("KDA onestep cap entry not found.");
            return AMVP_NO_CAP;
        }

        switch(param) {
        case AMVP_KDA_Z:
            if (min < 224 || max > 65536 || increment % 8 != 0) {
                AMVP_LOG_ERR("Invalid Z domain provided for KDA onestep");
                return AMVP_INVALID_ARG;
            }
            cap_list->cap.kda_onestep_cap->z.min = min;
            cap_list->cap.kda_onestep_cap->z.max = max;
            cap_list->cap.kda_onestep_cap->z.increment = increment;
            break;
        case AMVP_KDA_USE_HYBRID_SECRET:
            AMVP_LOG_ERR("Hybrid secret only applies to HKDF and twostep, not onestep");
            return AMVP_INVALID_ARG;
        case AMVP_KDA_PATTERN:
        case AMVP_KDA_REVISION:
        case AMVP_KDA_ENCODING_TYPE:
        case AMVP_KDA_L:
        case AMVP_KDA_MAC_SALT:
        case AMVP_KDA_MAC_ALG:
        case AMVP_KDA_ONESTEP_AUX_FUNCTION:
        case AMVP_KDA_PERFORM_MULTIEXPANSION_TESTS:
        case AMVP_KDA_TWOSTEP_SUPPORTED_LEN:
        case AMVP_KDA_TWOSTEP_FIXED_DATA_ORDER:
        case AMVP_KDA_TWOSTEP_COUNTER_LEN:
        case AMVP_KDA_TWOSTEP_SUPPORTS_EMPTY_IV:
        case AMVP_KDA_TWOSTEP_REQUIRES_EMPTY_IV:
        default:
            AMVP_LOG_ERR("Invalid domain param provided for KDA");
            return AMVP_INVALID_ARG;
        }
        break;
    case AMVP_SUB_KDA_HKDF:
        if (!cap_list->cap.kda_hkdf_cap) {
            AMVP_LOG_ERR("KDA-HKDF entry not found.");
            return AMVP_NO_CAP;
        }

        switch(param) {
        case AMVP_KDA_Z:
            if (min < 224 || max > 65536 || increment % 8 != 0) {
                AMVP_LOG_ERR("Invalid Z domain provided for HKDF");
                return AMVP_INVALID_ARG;
            }
            cap_list->cap.kda_hkdf_cap->z.min = min;
            cap_list->cap.kda_hkdf_cap->z.max = max;
            cap_list->cap.kda_hkdf_cap->z.increment = increment;
            break;
        case AMVP_KDA_USE_HYBRID_SECRET:
            if (cap_list->cap.kda_hkdf_cap->revision) {
                AMVP_LOG_ERR("Hybrid secrets for HKDF can only be set for revision SP800-56Cr2");
                return AMVP_INVALID_ARG;
            }
            if (min < 112 || max > 65536 || increment % 8 != 0) {
                AMVP_LOG_ERR("Invalid aux secret len domain provided for HKDF");
                return AMVP_INVALID_ARG;
            }
            cap_list->cap.kda_hkdf_cap->aux_secret_len.min = min;
            cap_list->cap.kda_hkdf_cap->aux_secret_len.max = max;
            cap_list->cap.kda_hkdf_cap->aux_secret_len.increment = increment;
            cap_list->cap.kda_hkdf_cap->use_hybrid_shared_secret = 1;
            break;
        case AMVP_KDA_PATTERN:
        case AMVP_KDA_REVISION:
        case AMVP_KDA_ENCODING_TYPE:
        case AMVP_KDA_L:
        case AMVP_KDA_MAC_SALT:
        case AMVP_KDA_MAC_ALG:
        case AMVP_KDA_ONESTEP_AUX_FUNCTION:
        case AMVP_KDA_PERFORM_MULTIEXPANSION_TESTS:
        case AMVP_KDA_TWOSTEP_SUPPORTED_LEN:
        case AMVP_KDA_TWOSTEP_FIXED_DATA_ORDER:
        case AMVP_KDA_TWOSTEP_COUNTER_LEN:
        case AMVP_KDA_TWOSTEP_SUPPORTS_EMPTY_IV:
        case AMVP_KDA_TWOSTEP_REQUIRES_EMPTY_IV:
        default:
            AMVP_LOG_ERR("Invalid domain param provided for KDA");
            return AMVP_INVALID_ARG;
        }
        break;
    case AMVP_SUB_KDA_TWOSTEP:
    case AMVP_SUB_KAS_ECC_CDH:
    case AMVP_SUB_KAS_ECC_COMP:
    case AMVP_SUB_KAS_ECC_NOCOMP:
    case AMVP_SUB_KAS_ECC_SSC:
    case AMVP_SUB_KAS_FFC_COMP:
    case AMVP_SUB_KAS_FFC_NOCOMP:
    case AMVP_SUB_KAS_FFC_SSC:
    case AMVP_SUB_KAS_IFC_SSC:
    case AMVP_SUB_KTS_IFC:
    case AMVP_SUB_SAFE_PRIMES_KEYGEN:
    case AMVP_SUB_SAFE_PRIMES_KEYVER:
    default:
        AMVP_LOG_ERR("Invalid cipher specified");
        return AMVP_INVALID_ARG;
    }
    return result;
}

AMVP_RESULT amvp_cap_kts_ifc_enable(AMVP_CTX *ctx,
                                    AMVP_CIPHER cipher,
                                    int (*crypto_handler)(AMVP_TEST_CASE *test_case)) {
    AMVP_CAP_TYPE type = 0;
    AMVP_RESULT result = AMVP_SUCCESS;

    if (!ctx) {
        return AMVP_NO_CTX;
    }
    if (!crypto_handler) {
        AMVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return AMVP_INVALID_ARG;
    }

    type = AMVP_KTS_IFC_TYPE;

    result = amvp_cap_list_append(ctx, type, cipher, crypto_handler);

    if (result == AMVP_DUP_CIPHER) {
        AMVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == AMVP_MALLOC_FAIL) {
        AMVP_LOG_ERR("Failed to allocate capability object");
    }

    return result;
}

AMVP_RESULT amvp_cap_kts_ifc_set_parm(AMVP_CTX *ctx,
                                      AMVP_CIPHER cipher,
                                      AMVP_KTS_IFC_PARAM param,
                                      int value) {

    AMVP_KTS_IFC_CAP *kts_ifc_cap = NULL;
    AMVP_CAPS_LIST *cap;
    AMVP_KTS_IFC_SCHEMES *current_scheme;
    AMVP_RESULT result = AMVP_SUCCESS;
    if (!ctx) {
        return AMVP_NO_CTX;
    }

      cap = amvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        return AMVP_NO_CAP;
    }

    kts_ifc_cap = cap->cap.kts_ifc_cap;
    if (!kts_ifc_cap) {
        return AMVP_NO_CAP;
    }

    switch (param)
    {
    case AMVP_KTS_IFC_KEYGEN_METHOD:
        result = amvp_append_param_list(&kts_ifc_cap->keygen_method, value);
        break;
    case AMVP_KTS_IFC_FUNCTION:
        result = amvp_append_param_list(&kts_ifc_cap->functions, value);
        break;
    case AMVP_KTS_IFC_MODULO:
        amvp_append_sl_list(&kts_ifc_cap->modulo, value);
        break;
    case AMVP_KTS_IFC_SCHEME:
        current_scheme = kts_ifc_cap->schemes;
        if (current_scheme) {
            while (current_scheme->next) {
                current_scheme = current_scheme->next;
            }
            current_scheme->next = calloc(1, sizeof(AMVP_KTS_IFC_SCHEMES));
            current_scheme->next->scheme = value;
        } else {
            kts_ifc_cap->schemes = calloc(1, sizeof(AMVP_KTS_IFC_SCHEMES));
            kts_ifc_cap->schemes->scheme = value;
        }
        break;
    case AMVP_KTS_IFC_IUT_ID:
    case AMVP_KTS_IFC_FIXEDPUBEXP:
    case AMVP_KTS_IFC_KEYPAIR_GEN:
    case AMVP_KTS_IFC_PARTIAL_VAL:
    default:
        AMVP_LOG_ERR("Invalid param");
        return AMVP_INVALID_ARG;
        break;
    }
    return result;
}

AMVP_RESULT amvp_cap_kts_ifc_set_scheme_parm(AMVP_CTX *ctx,
                                             AMVP_CIPHER cipher,
                                             AMVP_KTS_IFC_SCHEME_TYPE scheme,
                                             AMVP_KTS_IFC_SCHEME_PARAM param,
                                             int value) {

    AMVP_KTS_IFC_CAP *kts_ifc_cap = NULL;
    AMVP_CAPS_LIST *cap;
    AMVP_KTS_IFC_SCHEMES *current_scheme;
    AMVP_RESULT result = AMVP_SUCCESS;
    if (!ctx) {
        return AMVP_NO_CTX;
    }

    cap = amvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        return AMVP_NO_CAP;
    }

    kts_ifc_cap = cap->cap.kts_ifc_cap;
    if (!kts_ifc_cap) {
        return AMVP_NO_CAP;
    }

    current_scheme = kts_ifc_cap->schemes;
    if (!current_scheme) {
        return AMVP_NO_CAP;
    }

    while (current_scheme) {
        if (current_scheme->scheme != scheme) {
            current_scheme = current_scheme->next;
        }
        break;
    }
    if (!current_scheme) {
        return AMVP_NO_CAP;
    }

    switch (param)
    {
    case AMVP_KTS_IFC_NULL_ASSOC_DATA:
        current_scheme->null_assoc_data = value;
        break;
    case AMVP_KTS_IFC_L:
        current_scheme->l = value;
        break;
    case AMVP_KTS_IFC_ROLE:
        result = amvp_append_param_list(&current_scheme->roles, value);
        break;
    case AMVP_KTS_IFC_HASH:
        result = amvp_append_param_list(&current_scheme->hash, value);
        break;
    case AMVP_KTS_IFC_AD_PATTERN:
    case AMVP_KTS_IFC_ENCODING:
    case AMVP_KTS_IFC_MAC_METHODS:
    default:
        AMVP_LOG_ERR("Invalid param");
        return AMVP_INVALID_ARG;
        break;
    }
    return result;
}

AMVP_RESULT amvp_cap_kts_ifc_set_param_string(AMVP_CTX *ctx,
                                              AMVP_CIPHER cipher,
                                              AMVP_KTS_IFC_PARAM param,
                                              char *value) {
    unsigned int len = strnlen_s(value, AMVP_CAPABILITY_STR_MAX + 1);
    AMVP_KTS_IFC_CAP *kts_ifc_cap = NULL;
    AMVP_CAPS_LIST *cap;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    cap = amvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        return AMVP_NO_CAP;
    }

    kts_ifc_cap = cap->cap.kts_ifc_cap;
    if (!kts_ifc_cap) {
        return AMVP_NO_CAP;
    }

    if (len > AMVP_CAPABILITY_STR_MAX) {
        AMVP_LOG_ERR("Parameter 'value' string is too long. "
                     "max allowed is (%d) characters.",
                      AMVP_CAPABILITY_STR_MAX);
        return AMVP_INVALID_ARG;
    }
    switch (param)
    {
    case AMVP_KTS_IFC_FIXEDPUBEXP:
        kts_ifc_cap->fixed_pub_exp = calloc(len + 1, sizeof(char));
        strcpy_s(kts_ifc_cap->fixed_pub_exp, len + 1, value);
        break;
    case AMVP_KTS_IFC_IUT_ID:
        kts_ifc_cap->iut_id = calloc(len + 1, sizeof(char));
        strcpy_s(kts_ifc_cap->iut_id, len + 1, value);
        break;
    case AMVP_KTS_IFC_KEYGEN_METHOD:
    case AMVP_KTS_IFC_SCHEME:
    case AMVP_KTS_IFC_FUNCTION:
    case AMVP_KTS_IFC_MODULO:
    case AMVP_KTS_IFC_KEYPAIR_GEN:
    case AMVP_KTS_IFC_PARTIAL_VAL:
    default:
        AMVP_LOG_ERR("Invalid param");
        return AMVP_INVALID_ARG;
        break;
    }

    return AMVP_SUCCESS;
}

AMVP_RESULT amvp_cap_kts_ifc_set_scheme_string(AMVP_CTX *ctx,
                                               AMVP_CIPHER cipher,
                                               AMVP_KTS_IFC_SCHEME_TYPE scheme,
                                               AMVP_KTS_IFC_PARAM param,
                                               char *value) {
    unsigned int len = strnlen_s(value, AMVP_CAPABILITY_STR_MAX + 1);
    AMVP_KTS_IFC_CAP *kts_ifc_cap = NULL;
    AMVP_CAPS_LIST *cap;
    AMVP_KTS_IFC_SCHEMES *current_scheme;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    cap = amvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        return AMVP_NO_CAP;
    }

    kts_ifc_cap = cap->cap.kts_ifc_cap;
    if (!kts_ifc_cap) {
        return AMVP_NO_CAP;
    }

    if (len > AMVP_CAPABILITY_STR_MAX) {
        AMVP_LOG_ERR("Parameter 'value' string is too long. "
                     "max allowed is (%d) characters.",
                      AMVP_CAPABILITY_STR_MAX);
        return AMVP_INVALID_ARG;
    }

    current_scheme = kts_ifc_cap->schemes;
    if (!current_scheme) {
        return AMVP_NO_CAP;
    }

    while (current_scheme) {
        if (current_scheme->scheme != scheme) {
            current_scheme = current_scheme->next;
        }
        break;
    }
    if (!current_scheme) {
        return AMVP_NO_CAP;
    }


    switch (param)
    {
    case AMVP_KTS_IFC_AD_PATTERN:
        current_scheme->assoc_data_pattern = calloc(len + 1, sizeof(char));
        strcpy_s(current_scheme->assoc_data_pattern, len + 1, value);
        break;
    case AMVP_KTS_IFC_ENCODING:
        current_scheme->encodings = calloc(len + 1, sizeof(char));
        strcpy_s(current_scheme->encodings, len + 1, value);
        break;
    case AMVP_KTS_IFC_NULL_ASSOC_DATA:
    case AMVP_KTS_IFC_HASH:
    case AMVP_KTS_IFC_ROLE:
    case AMVP_KTS_IFC_L:
    case AMVP_KTS_IFC_MAC_METHODS:
    case AMVP_KTS_IFC_FIXEDPUBEXP:
    default:
        AMVP_LOG_ERR("Invalid param");
        return AMVP_INVALID_ARG;
        break;
    }

    return AMVP_SUCCESS;
}

AMVP_RESULT amvp_cap_safe_primes_enable(AMVP_CTX *ctx,
                                        AMVP_CIPHER cipher,
                                        int (*crypto_handler)(AMVP_TEST_CASE *test_case)) {
    AMVP_RESULT result = AMVP_NO_CAP;

    if (!ctx) {
        return AMVP_NO_CTX;
    }
    if (!crypto_handler) {
        AMVP_LOG_ERR("NULL parameter 'crypto_handler'");
        return AMVP_INVALID_ARG;
    }

    if (cipher == AMVP_SAFE_PRIMES_KEYGEN) {
        result = amvp_cap_list_append(ctx, AMVP_SAFE_PRIMES_KEYGEN_TYPE, cipher, crypto_handler);
    } else if (cipher == AMVP_SAFE_PRIMES_KEYVER) {
        result = amvp_cap_list_append(ctx, AMVP_SAFE_PRIMES_KEYVER_TYPE, cipher, crypto_handler);
    } 
    if (result == AMVP_DUP_CIPHER) {
        AMVP_LOG_ERR("Capability previously enabled. Duplicate not allowed.");
    } else if (result == AMVP_MALLOC_FAIL) {
        AMVP_LOG_ERR("Failed to allocate capability object");
    } else if (result == AMVP_NO_CAP) {
        AMVP_LOG_ERR("Invalid capability");
        return AMVP_NO_CAP;
    }

    return result;
}

AMVP_RESULT amvp_cap_safe_primes_set_parm(AMVP_CTX *ctx,
                                          AMVP_CIPHER cipher,
                                          AMVP_SAFE_PRIMES_PARAM param,
                                          AMVP_SAFE_PRIMES_MODE mode) {
    AMVP_CAPS_LIST *cap;
    AMVP_SAFE_PRIMES_CAP *safe_primes_cap;
    AMVP_SAFE_PRIMES_CAP_MODE *safe_primes_cap_mode;
    AMVP_SUB_KAS alg;
    AMVP_RESULT result = AMVP_SUCCESS;

    if (!ctx) {
        return AMVP_NO_CTX;
    }

    cap = amvp_locate_cap_entry(ctx, cipher);
    if (!cap) {
        return AMVP_NO_CAP;
    }

    if (cipher == AMVP_SAFE_PRIMES_KEYGEN) {
        safe_primes_cap = cap->cap.safe_primes_keygen_cap;
    } else if (cipher == AMVP_SAFE_PRIMES_KEYVER) {
        safe_primes_cap = cap->cap.safe_primes_keyver_cap;
    } else {
        AMVP_LOG_ERR("Invalid capability");
        return AMVP_NO_CAP;
    }

    if (!safe_primes_cap) {
        return AMVP_NO_CAP;
    }
    if (!safe_primes_cap->mode) {
        safe_primes_cap->mode = calloc(1, sizeof(AMVP_SAFE_PRIMES_CAP_MODE));
    }

    safe_primes_cap_mode = safe_primes_cap->mode;
    if (!safe_primes_cap_mode) {
        return AMVP_NO_CAP;
    }
    alg = amvp_get_kas_alg(cipher);
    if (alg == 0) {
        AMVP_LOG_ERR("Invalid cipher value");
        return AMVP_INVALID_ARG;
    }
    
    switch (alg) {
    case AMVP_SUB_SAFE_PRIMES_KEYVER:
        switch (param) {
        case AMVP_SAFE_PRIMES_GENMETH:
            result = amvp_append_param_list(&safe_primes_cap_mode->genmeth, mode);
            break;
        default:
            break;
        }
        break;
    case AMVP_SUB_SAFE_PRIMES_KEYGEN:
        switch (param) {
        case AMVP_SAFE_PRIMES_GENMETH:
            result = amvp_append_param_list(&safe_primes_cap_mode->genmeth, mode);
            break;
        default:
            break;
        }
        break;
    case AMVP_SUB_KAS_ECC_CDH:
    case AMVP_SUB_KAS_ECC_COMP:
    case AMVP_SUB_KAS_ECC_NOCOMP:
    case AMVP_SUB_KAS_ECC_SSC:
    case AMVP_SUB_KAS_FFC_SSC:
    case AMVP_SUB_KAS_FFC_COMP:
    case AMVP_SUB_KAS_FFC_NOCOMP:
    case AMVP_SUB_KAS_IFC_SSC:
    case AMVP_SUB_KTS_IFC:
    case AMVP_SUB_KDA_ONESTEP:
    case AMVP_SUB_KDA_TWOSTEP:
    case AMVP_SUB_KDA_HKDF:
    default:
        break;
    }
    return result;
}
