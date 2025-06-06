/*
 * Copyright (c) 2021, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libamvp/LICENSE
 */


#include <stdio.h>
#include "ketopt.h"
#include "app_lcl.h"
#include "amvp/amvp.h"
#include "safe_lib.h"

#define AMVP_APP_HELP_MSG "Use amvp_app --help for more information."

static void print_usage(int code) {
    if (code == -1) {
        printf("\nInvalid usage...\n");
    } else {
        printf("\n===========================");
        printf("\n===== AMVP_APP USAGE ======");
        printf("\n===========================\n");
    }
    printf("To output version of library and of AMVP spec:\n");
    printf("      --version\n");
    printf("      -v\n");
    printf("Logging level decides the amount of information output by the library. Logging level\n");
    printf("can be controlled using:\n");
    printf("      --none\n");
    printf("      --error\n");
    printf("      --warn\n");
    printf("      --status(default)\n");
    printf("      --info\n");
    printf("      --verbose\n");
    printf("\n");
    if (code >= AMVP_LOG_LVL_VERBOSE) {
        printf("-The warn logging level logs events that should be acted upon but do not halt\n");
        printf("the progress of the application running.\n");
        printf("-The default logging level provides basic information about the progress of the test\n");
        printf("session or the task being performed. This includes the possibility of logging large\n");
        printf("amounts of data IF the data is specifically requested.\n");
        printf("-The info logging level provides more information about the information being\n");
        printf("exchanged, including HTTP actions (get, put, etc). Data in/from these actions is\n");
        printf("logged but usually truncated.\n");
        printf("-The verbose logging level is substantially more detailed than even info level, and\n");
        printf("includes information about each vector set, test group,and even test case being\n");
        printf("processed. it also will automatically fetch the results of all test cases of a\n");
        printf("vector set in the event of it failing.\n");
        printf("\n");
        printf("For any activity requiring the creation of a test session and/or the processing\n");
        printf("of test cases, amvp_app requires the specification of at least one algorithm\n");
        printf("suite. Algorithm suites are enabled or disabled at build time depending on the\n");
        printf("capabilities of the provided cryptographic library.\n\n");
    }

    printf("To GET status of request, such as validation or metadata:\n");
    printf("      --get <request string URL including ID>\n");
    printf("\n");
    printf("To POST metadata for vendor, person, etc.:\n");
    printf("      --post <metadata file>\n");
    printf("\n");
    printf("To PUT(modify)  metadata for vendor, person, etc. or PUT for validation:\n");
    printf("      --put <metadata file>\n");
    printf("\n");
    printf("To request to DELETE a resource you have created on the server:\n");
    printf("      --delete <url>\n");
    printf("\n");
    printf("Some other options may support outputting to log OR saving to a file. To save to a file:\n");
    printf("      --save_to <file>\n");
    printf("      -s <file>\n");
    printf("\n");
    printf("To create a module on the AMVP server:\n");
    printf("      --create_module <module_file>\n");
    printf("To get info about a created module from the AMVP server:\n");
    printf("      --check_module_request <module_info_file>\n");
    printf("To request module certificate using a predefined request file:\n");
    printf("      --module_cert_req --with_module <module_id_number> --with_vendor <vendor_id_number> --with-contact <CMVP contact ID> ...\n");
    printf("Optionally, the following fields can also be added to module_cert_req:\n");
    printf("      --with_acv_cert <CAVP algorithm certificate ID> --with_esv_cert <ESVP certificate ID>\n");
    printf("These options can also be used independently with --for_cert_request to add certs to an existing request.\n");
    printf("\n");

    printf("In addition some options are passed to amvp_app using\n");
    printf("environment variables.  The following variables can be set:\n\n");
    printf("    AMV_SERVER (when not set, defaults to %s)\n", DEFAULT_SERVER);
    printf("    AMV_PORT (when not set, defaults to %d)\n", DEFAULT_PORT);
    printf("    AMV_URI_PREFIX (when not set, defaults to %s)\n", DEFAULT_URI_PREFIX);
    printf("    AMV_TOTP_SEED (when not set, client will not use Two-factor authentication)\n");
    printf("    AMV_CA_FILE\n");
    printf("    AMV_CERT_FILE\n");
    printf("    AMV_KEY_FILE\n");
    printf("The CA certificates, cert and key should be PEM encoded. There should be no\n");
    printf("password on the key file.\n\n");
    printf("Some options can be passed to the library itself with environment variables:\n\n");
    printf("    AMV_SESSION_SAVE_PATH (Location where test session info files are saved)\n");
    printf("    AMV_SESSION_SAVE_PREFIX (Determines file name of info file, followed by ID number\n");
    printf("    The following are used by the library for an HTTP user-agent string, only when\n");
    printf("    the information cannot be automatically collected:\n");
    printf("        AMV_OE_OSNAME\n");
    printf("        AMV_OE_OSVERSION\n");
    printf("        AMV_OE_ARCHITECTURE\n");
    printf("        AMV_OE_PROCESSOR\n");
    printf("        AMV_OE_COMPILER\n\n");
}

static void print_version_info(void) {
    printf("\nAMVP library version(protocol version): %s(%s)\n\n", amvp_version(), amvp_protocol_version());
}

static ko_longopt_t longopts[] = {
    { "version", ko_no_argument, 301 },
    { "help", ko_optional_argument, 302 },
    { "info", ko_no_argument, 303 },
    { "status", ko_no_argument, 304 },
    { "warn", ko_no_argument, 305 },
    { "error", ko_no_argument, 306 },
    { "verbose", ko_no_argument, 307 },
    { "none", ko_no_argument, 308 },
    { "manual_registration", ko_required_argument, 400 },
    { "fips_validation", ko_required_argument, 402 },
    { "get", ko_required_argument, 406 },
    { "post", ko_required_argument, 407 },
    { "put", ko_required_argument, 408 },
    { "certnum", ko_required_argument, 410 },
    { "save_to", ko_required_argument, 413 },
    { "delete", ko_required_argument, 414 },
    { "cancel_session", ko_required_argument, 415 },
    { "debug", ko_no_argument, 417 },
    { "module_cert_req", ko_no_argument, 419 },
    { "create_module", ko_required_argument, 421 },
    { "check_module_request", ko_required_argument, 422 },
    { "with_module", ko_required_argument, 423 },
    { "with_vendor", ko_required_argument, 424} ,
    { "with_contact", ko_required_argument, 425 } ,
    { "submit_ft_evidence", ko_required_argument, 426 },
    { "submit_security_policy", ko_required_argument, 427 },
    { "for_cert_request", ko_required_argument, 428 },
    { "get_security_policy", ko_no_argument, 429 } ,
    { "with_acv_cert", ko_required_argument, 430 },
    { "with_esv_cert", ko_required_argument, 431 },
    { "submit_sc_evidence", ko_required_argument, 432 },
    { "finalize", ko_no_argument, 433 },
    { "check_cert_req_status", ko_no_argument, 434 },
    { NULL, 0, 0 }
};


static void default_config(APP_CONFIG *cfg) {
    cfg->level = AMVP_LOG_LVL_STATUS;
}

static const char* lookup_arg_name(int c) {
    int i = 0;
    int arrlen = sizeof(longopts) / sizeof(ko_longopt_t);
    for (i = 0; i < arrlen; i++) {
        if (longopts[i].val == c) {
            return longopts[i].name;
        }
    }
    return NULL;
}

//return 0 if fails check, 1 if passes
static int check_option_length(const char *opt, int c, int maxAllowed) {
    if ((int)strnlen_s(opt, maxAllowed + 1) > maxAllowed) {
        const char *argName = lookup_arg_name(c);
        printf(ANSI_COLOR_RED "Command error... "ANSI_COLOR_RESET
                "\nThe argument given for option %s is too long."
                "\nMax length allowed: %d"
                "\n%s\n", argName, maxAllowed, AMVP_APP_HELP_MSG);
        return 0;
    }
    return 1;
}

int ingest_cli(APP_CONFIG *cfg, int argc, char **argv) {
    ketopt_t opt = KETOPT_INIT;
    int c = 0, diff = 0, tmp = 0;

    cfg->empty_alg = 1;

    /* Set the default configuration values */
    default_config(cfg);

    while ((c = ketopt(&opt, argc, argv, 1, "vhas:u:r:p:", longopts)) >= 0) {
        diff = 1;

        switch (c) {
        case 'v':
        case 301:
            print_version_info();
            return 1;
        case 'h':
        case 302:
            if (opt.arg) {
                tmp = strnlen_s(opt.arg, JSON_FILENAME_LENGTH + 1);
                if (tmp > JSON_FILENAME_LENGTH || tmp <= 0) {
                    printf("invalid help option length\n");
                    return 1;
                }
                strncmp_s(opt.arg, tmp, "--verbose", 9, &diff);
                if (!diff) {
                    print_usage(AMVP_LOG_LVL_VERBOSE);
                } else {
                    print_usage(0);
                }
            } else {
                print_usage(0);
            }
            return 1;
        case 303:
            cfg->level = AMVP_LOG_LVL_INFO;
            break;
        case 304:
            cfg->level = AMVP_LOG_LVL_STATUS;
            break;
        case 305:
            cfg->level = AMVP_LOG_LVL_WARN;
            break;
        case 306:
            cfg->level = AMVP_LOG_LVL_ERR;
            break;
        case 307:
            cfg->level = AMVP_LOG_LVL_VERBOSE;
            break;
        case 308:
            cfg->level = AMVP_LOG_LVL_NONE;
            break;

        case 400:
            cfg->manual_reg = 1;
            if (!check_option_length(opt.arg, c, JSON_FILENAME_LENGTH)) {
                return 1;
            }
            strcpy_s(cfg->reg_file, JSON_FILENAME_LENGTH + 1, opt.arg);
            break;

        case 402:
            cfg->fips_validation = 1;
            if (!check_option_length(opt.arg, c, JSON_FILENAME_LENGTH)) {
                return 1;
            }
            strcpy_s(cfg->validation_metadata_file, JSON_FILENAME_LENGTH + 1, opt.arg);
            break;

        case 406:
            cfg->get = 1;
            if (!check_option_length(opt.arg, c, JSON_REQUEST_LENGTH)) {
                return 1;
            }
            strcpy_s(cfg->get_string, JSON_REQUEST_LENGTH + 1, opt.arg);
            break;

        case 407:
            cfg->post = 1;
            if (!check_option_length(opt.arg, c, JSON_FILENAME_LENGTH)) {
                return 1;
            }
            strcpy_s(cfg->post_filename, JSON_FILENAME_LENGTH + 1, opt.arg);
            break;

        case 408:
            cfg->put = 1;
            if (!check_option_length(opt.arg, c, JSON_FILENAME_LENGTH)) {
                return 1;
            }
            strcpy_s(cfg->put_filename, JSON_FILENAME_LENGTH + 1, opt.arg);
            break;

        case 410:
            if (!check_option_length(opt.arg, c, JSON_STRING_LENGTH)) {
                return 1;
            }
            strcpy_s(value, JSON_STRING_LENGTH, opt.arg);
            break;

        case 's':
        case 413:
            cfg->save_to = 1;
            if (!check_option_length(opt.arg, c, JSON_FILENAME_LENGTH)) {
                return 1;
            }
            strcpy_s(cfg->save_file, JSON_FILENAME_LENGTH + 1, opt.arg);
            break;

        case 414:
            cfg->delete = 1;
            if (!check_option_length(opt.arg, c, JSON_REQUEST_LENGTH)) {
                return 1;
            }
            strcpy_s(cfg->delete_url, JSON_REQUEST_LENGTH + 1, opt.arg);
            break;

        case 415:
            cfg->cancel_session = 1;
            if (!check_option_length(opt.arg, c, JSON_FILENAME_LENGTH)) {
                return 1;
            }
            strcpy_s(cfg->session_file, JSON_FILENAME_LENGTH + 1, opt.arg);
            break;

        case 417:
            cfg->level = AMVP_LOG_LVL_DEBUG;
            break;

        case 419:
            cfg->mod_cert_req = 1;
            break;

        case 421:
            cfg->create_module = 1;
            if (!check_option_length(opt.arg, c, JSON_FILENAME_LENGTH)) {
                return 1;
            }
            strcpy_s(cfg->create_module_file, JSON_FILENAME_LENGTH + 1, opt.arg);
            break;

        case 422:
            cfg->get_module = 1;
            if (!check_option_length(opt.arg, c, JSON_FILENAME_LENGTH)) {
                return 1;
            }
            strcpy_s(cfg->get_module_file, JSON_FILENAME_LENGTH + 1, opt.arg);
            break;

        case 423:
            tmp = atoi(opt.arg);
            if (!tmp) {
                printf("Invalid module ID format\n");
                return 1;
            }
            cfg->module_id = tmp;
            break;

        case 424:
            tmp = atoi(opt.arg);
            if (!tmp) {
                printf("Invalid vendor ID format\n");
                return 1;
            }
            cfg->vendor_id = tmp;
            break;

        case 425:
            if (cfg->num_contacts >= AMVP_MAX_CONTACTS_PER_CERT_REQ) {
                printf("Too many contacts provided for cert req\n");
                return 1;
            }
            if (!check_option_length(opt.arg, c, AMVP_CONTACT_STR_MAX_LEN)) {
                return 1;
            }
            strcpy_s(cfg->contact_ids[cfg->num_contacts], AMVP_CONTACT_STR_MAX_LEN + 1, opt.arg);
            cfg->num_contacts++;
            break;

        case 426:
            cfg->submit_ft_ev = 1;
            if (!check_option_length(opt.arg, c, JSON_FILENAME_LENGTH)) {
                return 1;
            }
            strcpy_s(cfg->ev_file, JSON_FILENAME_LENGTH + 1, opt.arg);
            break;

        case 427:
            cfg->submit_sp = 1;
            if (!check_option_length(opt.arg, c, JSON_FILENAME_LENGTH)) {
                return 1;
            }
            strcpy_s(cfg->sp_file, JSON_FILENAME_LENGTH + 1, opt.arg);
            break;

        case 428:
            cfg->ingest_cert_info = 1;
            if (!check_option_length(opt.arg, c, JSON_FILENAME_LENGTH)) {
                return 1;
            }
            strcpy_s(cfg->mod_cert_req_file, JSON_FILENAME_LENGTH + 1, opt.arg);
            break;

        case 429:
            cfg->get_sp = 1;
            break;

        case 430:
            if (cfg->num_acv_certs >= AMVP_MAX_ACV_CERTS_PER_CERT_REQ) {
                printf("Too many algorithm certs provided for cert req\n");
                return 1;
            }
            if (!check_option_length(opt.arg, c, AMVP_CERT_STR_MAX_LEN)) {
                return 1;
            }
            strcpy_s(cfg->acv_certs[cfg->num_acv_certs], AMVP_CERT_STR_MAX_LEN + 1, opt.arg);
            cfg->num_acv_certs++;
            break;

        case 431:
            if (cfg->num_esv_certs >= AMVP_MAX_ESV_CERTS_PER_CERT_REQ) {
                printf("Too many algorithm certs provided for cert req\n");
                return 1;
            }
            if (!check_option_length(opt.arg, c, AMVP_CERT_STR_MAX_LEN)) {
                return 1;
            }
            strcpy_s(cfg->esv_certs[cfg->num_esv_certs], AMVP_CERT_STR_MAX_LEN + 1, opt.arg);
            cfg->num_esv_certs++;
            break;

        case 432:
            cfg->submit_sc_ev = 1;
            if (!check_option_length(opt.arg, c, JSON_FILENAME_LENGTH)) {
                return 1;
            }
            strcpy_s(cfg->ev_file, JSON_FILENAME_LENGTH + 1, opt.arg);
            break;

        case 433:
            cfg->finalize = 1;
            break;

        case 434:
            cfg->check_status = 1;
            break;

        case '?':
            printf(ANSI_COLOR_RED "unknown option: %s\n"ANSI_COLOR_RESET, *(argv + opt.ind - !(opt.pos > 0)));
            printf("%s\n", AMVP_APP_HELP_MSG);
            return 1;

        case ':':
            printf(ANSI_COLOR_RED "option missing arg: %s\n"ANSI_COLOR_RESET, *(argv + opt.ind - 1));
            printf("%s\n", AMVP_APP_HELP_MSG);
            return 1;

        default:
            printf("An unknown error occurred while parsing arguments.\n");
            break;
        }
    }

    //If there are still arguments that were not permuted, they are invalid
    if (opt.ind < argc) {
        for (c = opt.ind; c < argc; c++) {
            printf(ANSI_COLOR_RED "unknown option: %s\n" ANSI_COLOR_RESET, argv[c]);
        }
        printf("%s\n", AMVP_APP_HELP_MSG);
        return 1;
    }

    if (cfg->mod_cert_req && (!cfg->module_id || !cfg->vendor_id || !cfg->num_contacts)) {
        printf("Module cert request requires module module ID, vendor ID, and at least one contact ID to be provided\n");
        return 1;
    }

    if (!cfg->mod_cert_req && (cfg->module_id || cfg->vendor_id || cfg->num_contacts)) {
        printf("Warning: Module ID/Vendor ID/Contact ID provided, but not performing a cert request. These options will be ignored\n");
    }

    if ((cfg->submit_ft_ev || cfg->submit_sc_ev || cfg->submit_sp) && !cfg->ingest_cert_info) {
        printf("Submitting evidence or security policy info requires specifying a cert request info file\n");
        return 1;
    }

    printf("\n");

    return 0;
}

