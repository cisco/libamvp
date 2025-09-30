/** @file */
/*
 * Copyright (c) 2025, Cisco Systems, Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/cisco/libamvp/LICENSE
 */

/*
 * HTTP user agent generation utilities
 * Platform-specific OS/hardware detection for building user agent strings.
 * Supports Windows, Linux, and macOS platforms.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#elif defined __linux__
#if defined __x86_64__ || defined __i386__
#include <cpuid.h>
#endif
#include <sys/utsname.h>
#elif defined __APPLE__
#include <TargetConditionals.h>
#if TARGET_OS_MAC == 1 && TARGET_OS_IPHONE == 0 && !defined(__aarch64__)
#include <cpuid.h>
#endif
#include <sys/utsname.h>
#endif

#include "amvp.h"
#include "amvp_lcl.h"
#include "amvp_error.h"
#include "safe_lib.h"

/*
 * Constants used by transport utility functions
 */
#define HTTP_OK    200
#define HTTP_UNAUTH    401
#define HTTP_BAD_REQ 400

#define AMVP_URL_ENCODE_BUFFER_SIZE     4
#define AMVP_HTTP_SUCCESS_MIN           200
#define AMVP_HTTP_SUCCESS_MAX           300

#define JWT_EXPIRED_STR "JWT expired"
#define JWT_EXPIRED_STR_LEN 11
#define JWT_INVALID_STR "JWT signature does not match"
#define JWT_INVALID_STR_LEN 28

/*
 * User agent related constants
 */
typedef enum amvp_user_agent_env_type {
    AMVP_USER_AGENT_OSNAME = 1,
    AMVP_USER_AGENT_OSVER,
    AMVP_USER_AGENT_ARCH,
    AMVP_USER_AGENT_PROC,
    AMVP_USER_AGENT_COMP,
    AMVP_USER_AGENT_NONE,
} AMVP_OE_ENV_VAR;

/*
 * Helper function for checking environment variables for user agent
 */
static void amvp_http_user_agent_check_env_for_var(AMVP_CTX *ctx, char *var_string, AMVP_OE_ENV_VAR var_to_check) {
    unsigned int maxLength = 0;
    const char *var;

    switch(var_to_check) {
    case AMVP_USER_AGENT_OSNAME:
        var = AMVP_USER_AGENT_OSNAME_ENV;
        maxLength = AMVP_USER_AGENT_OSNAME_STR_MAX;
        break;
    case AMVP_USER_AGENT_OSVER:
        var = AMVP_USER_AGENT_OSVER_ENV;
        maxLength = AMVP_USER_AGENT_OSVER_STR_MAX;
        break;
    case AMVP_USER_AGENT_ARCH:
        var = AMVP_USER_AGENT_ARCH_ENV;
        maxLength = AMVP_USER_AGENT_ARCH_STR_MAX;
        break;
    case AMVP_USER_AGENT_PROC:
        var = AMVP_USER_AGENT_PROC_ENV;
        maxLength = AMVP_USER_AGENT_PROC_STR_MAX;
        break;
    case AMVP_USER_AGENT_COMP:
        var = AMVP_USER_AGENT_COMP_ENV;
        maxLength = AMVP_USER_AGENT_COMP_STR_MAX;
        break;
    case AMVP_USER_AGENT_NONE:
    default:
        return;
    }

    //Check presence and length of variable's value, concatenate if valid, warn and ignore if not
    char *envVal = getenv(var);
    if (envVal) {
        if (strnlen_s(envVal, maxLength + 1) > maxLength) {
            AMVP_LOG_WARN("Environment-provided %s string too long! (%d char max.) Omitting...\n", var, maxLength);
        } else {
            strncpy_s(var_string, maxLength + 1, envVal, maxLength);
        }
    } else {
        AMVP_LOG_INFO("Unable to collect info for HTTP user-agent - consider defining %s (%d char max.) This is optional and will not affect testing.", var, maxLength);
    }
}

/*
 * Helper function for compiler version detection
 */
static void amvp_http_user_agent_check_compiler_ver(char *comp_string) {
    char versionBuffer[16];

#ifdef __GNUC__
    strncpy_s(comp_string, AMVP_USER_AGENT_COMP_STR_MAX + 1, "GCC/", AMVP_USER_AGENT_COMP_STR_MAX);

    snprintf(versionBuffer, sizeof(versionBuffer), "%d", __GNUC__);
    strncat_s(comp_string, AMVP_USER_AGENT_COMP_STR_MAX + 1, versionBuffer, AMVP_USER_AGENT_COMP_STR_MAX);

#ifdef __GNUC_MINOR__
    snprintf(versionBuffer, sizeof(versionBuffer), "%d", __GNUC_MINOR__);
    strncat_s(comp_string, AMVP_USER_AGENT_COMP_STR_MAX + 1, ".", AMVP_USER_AGENT_COMP_STR_MAX);
    strncat_s(comp_string, AMVP_USER_AGENT_COMP_STR_MAX + 1, versionBuffer, AMVP_USER_AGENT_COMP_STR_MAX);
#endif

#ifdef __GNUC_PATCHLEVEL__
    snprintf(versionBuffer, sizeof(versionBuffer), "%d", __GNUC_PATCHLEVEL__);
    strncat_s(comp_string, AMVP_USER_AGENT_COMP_STR_MAX + 1, ".", AMVP_USER_AGENT_COMP_STR_MAX);
    strncat_s(comp_string, AMVP_USER_AGENT_COMP_STR_MAX + 1, versionBuffer, AMVP_USER_AGENT_COMP_STR_MAX);
#endif

#elif defined _MSC_FULL_VER
    strncpy_s(comp_string, AMVP_USER_AGENT_COMP_STR_MAX + 1, "MSVC/", AMVP_USER_AGENT_COMP_STR_MAX);

    snprintf(versionBuffer, sizeof(versionBuffer), "%d", _MSC_FULL_VER);
    strncat_s(comp_string, AMVP_USER_AGENT_COMP_STR_MAX + 1, versionBuffer, AMVP_USER_AGENT_COMP_STR_MAX);
#else
    amvp_http_user_agent_check_env_for_var(ctx, comp_string, AMVP_USER_AGENT_COMP);
#endif
}

/*
 * Helper function for cleaning user agent strings
 */
static void amvp_http_user_agent_string_clean(char *str) {
    int i = 0;
    if (!str) {
        return;
    }
    int len = strnlen_s(str, AMVP_USER_AGENT_STR_MAX);
    if (len <= 0) {
        return;
    }
    //remove any leading or trailing whitespace
    strremovews_s(str, len);
    len = strnlen_s(str, AMVP_USER_AGENT_STR_MAX);

    for (i = 0; i < len; i++) {
        if (str[i] == AMVP_USER_AGENT_DELIMITER) {
            str[i] = AMVP_USER_AGENT_CHAR_REPLACEMENT;
        }
    }
}

/*
 * HTTP user agent handler - generates user agent string based on OS/hardware info
 */
void amvp_http_user_agent_handler(AMVP_CTX *ctx) {
    if (!ctx || ctx->http_user_agent) {
        AMVP_LOG_WARN("Error generating HTTP user-agent - no CTX or string already exists\n");
        return;
    } else {
        ctx->http_user_agent = calloc(AMVP_USER_AGENT_STR_MAX + 1, sizeof(char));
        if (!ctx->http_user_agent) {
            AMVP_LOG_ERR("Unable to allocate memory for user agent, skipping...");
            return;
        }
    }

    char *libver = calloc(AMVP_USER_AGENT_AMVP_STR_MAX + 1, sizeof(char));
    char *osname = calloc(AMVP_USER_AGENT_OSNAME_STR_MAX + 1, sizeof(char));
    char *osver = calloc(AMVP_USER_AGENT_OSVER_STR_MAX + 1, sizeof(char));
    char *arch = calloc(AMVP_USER_AGENT_ARCH_STR_MAX + 1, sizeof(char));
    char *proc = calloc(AMVP_USER_AGENT_PROC_STR_MAX + 1, sizeof(char));
    char *comp = calloc(AMVP_USER_AGENT_COMP_STR_MAX + 1, sizeof(char));

    if (!libver || !osname || !osver || !arch || !proc || !comp) {
        AMVP_LOG_ERR("Unable to allocate memory for HTTP user-agent, skipping...\n");
        goto end;
    }

    snprintf(libver, AMVP_USER_AGENT_AMVP_STR_MAX, "libamvp/%s", AMVP_LIBRARY_VERSION_NUMBER);

#if defined __linux__ || defined __APPLE__

    //collects basic OS/hardware info
    struct utsname info;
    if (uname(&info) != 0) {
        amvp_http_user_agent_check_env_for_var(ctx, osname, AMVP_USER_AGENT_OSNAME);
        amvp_http_user_agent_check_env_for_var(ctx, osver, AMVP_USER_AGENT_OSVER);
        amvp_http_user_agent_check_env_for_var(ctx, arch, AMVP_USER_AGENT_ARCH);
    } else {
        //usually Linux/Darwin
        strncpy_s(osname, AMVP_USER_AGENT_OSNAME_STR_MAX + 1, info.sysname, AMVP_USER_AGENT_OSNAME_STR_MAX);

        //usually linux kernel version/darwin version
        strncpy_s(osver, AMVP_USER_AGENT_OSVER_STR_MAX + 1, info.release, AMVP_USER_AGENT_OSVER_STR_MAX);

        //hardware architecture
        strncpy_s(arch, AMVP_USER_AGENT_ARCH_STR_MAX + 1, info.machine, AMVP_USER_AGENT_ARCH_STR_MAX);
    }

#if defined __x86_64__ || defined __i386__
    /* 48 byte CPU brand string, obtained via CPUID opcode in x86/amd64 processors.
    The 0x8000000X values are specifically for that opcode.
    Each __get_cpuid call gets 16 bytes, or 1/3 of the brand string */
    unsigned int registers[4];
    char brandString[48];

    if (!__get_cpuid(0x80000002, &registers[0], &registers[1], &registers[2], &registers[3])) {
        amvp_http_user_agent_check_env_for_var(ctx, proc, AMVP_USER_AGENT_PROC);
    } else {
        memcpy_s(brandString, 16, &registers, 16);
    }
    if (!__get_cpuid(0x80000003, &registers[0], &registers[1], &registers[2], &registers[3])) {
        amvp_http_user_agent_check_env_for_var(ctx, proc, AMVP_USER_AGENT_PROC);
    } else {
        memcpy_s(brandString + 16, 16, &registers, 16);
    }
    if (!__get_cpuid(0x80000004, &registers[0], &registers[1], &registers[2], &registers[3])) {
        amvp_http_user_agent_check_env_for_var(ctx, proc, AMVP_USER_AGENT_PROC);
    } else {
        memcpy_s(brandString + 32, 16, &registers, 16);
        strncpy_s(proc, AMVP_USER_AGENT_PROC_STR_MAX + 1, brandString, AMVP_USER_AGENT_PROC_STR_MAX);
    }
#else
    amvp_http_user_agent_check_env_for_var(ctx, proc, AMVP_USER_AGENT_PROC);
#endif

    //gets compiler version, or checks environment for it
    amvp_http_user_agent_check_compiler_ver(comp);

#elif defined WIN32

    HKEY key;
    LONG status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0,
                  KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key);
    if (status != ERROR_SUCCESS) {
        amvp_http_user_agent_check_env_for_var(ctx, osname, AMVP_USER_AGENT_OSNAME);
        amvp_http_user_agent_check_env_for_var(ctx, osver, AMVP_USER_AGENT_OSVER);
    } else {
        //product name string, containing general version of windows
        DWORD bufferLength;
        if (RegQueryValueExW(key, L"ProductName", NULL, NULL, NULL, &bufferLength) != ERROR_SUCCESS) {
            AMVP_LOG_WARN("Unable to access Windows OS name, checking environment or omitting from HTTP user-agent...\n");
            amvp_http_user_agent_check_env_for_var(ctx, osname, AMVP_USER_AGENT_OSNAME);
        } else {
            //get string - registry strings not garuanteed to be null terminated
            wchar_t *productNameBuffer = calloc(bufferLength + 1, sizeof(wchar_t));
            if (!productNameBuffer) {
                AMVP_LOG_ERR("Unable to allocate memory while generating windows OS name, skipping...\n");
            } else if (RegQueryValueExW(key, L"ProductName", NULL, NULL, productNameBuffer, &bufferLength) != ERROR_SUCCESS) {
                AMVP_LOG_WARN("Unable to access Windows OS name, checking environment or omitting from HTTP user-agent...\n");
                free(productNameBuffer);
                amvp_http_user_agent_check_env_for_var(ctx, osname, AMVP_USER_AGENT_OSNAME);
            } else {
                //Windows uses UTF16, and everyone else uses UTF8
                char *utf8String = calloc(bufferLength + 1, sizeof(char));
                if (!utf8String || !WideCharToMultiByte(CP_UTF8, 0, productNameBuffer, -1, utf8String, bufferLength + 1, NULL, NULL)) {
                    AMVP_LOG_ERR("Error converting Windows version to UTF8, checking environment or omitting from HTTP user-agent...\n");
                    amvp_http_user_agent_check_env_for_var(ctx, osver, AMVP_USER_AGENT_OSVER);
                } else {
                    strncpy_s(osname, AMVP_USER_AGENT_OSNAME_STR_MAX + 1, utf8String, AMVP_USER_AGENT_OSNAME_STR_MAX);
                }
                free(utf8String);
                free(productNameBuffer);
            }

        }

        //get the "BuildLab" string, which contains more specific windows build information
        if (RegQueryValueExW(key, L"BuildLab", NULL, NULL, NULL, &bufferLength) != ERROR_SUCCESS) {
            AMVP_LOG_WARN("Unable to access Windows version, checking environment or omitting from HTTP user-agent...\n");
            amvp_http_user_agent_check_env_for_var(ctx, osver, AMVP_USER_AGENT_OSVER);
        } else {
            //get string - registry strings not garuanteed to be null terminated
            wchar_t *buildLabBuffer = calloc(bufferLength + 1, sizeof(wchar_t));
            if (!buildLabBuffer) {
                AMVP_LOG_ERR("Unable to allocate memory while generating windows OS version, skipping...\n");
            } else if (RegQueryValueExW(key, L"BuildLab", NULL, NULL, buildLabBuffer, &bufferLength) != ERROR_SUCCESS) {
                AMVP_LOG_WARN("Unable to access Windows version, checking environment or omitting from HTTP user-agent...\n");
                amvp_http_user_agent_check_env_for_var(ctx, osver, AMVP_USER_AGENT_OSVER);
                free(buildLabBuffer);
            } else {
                //Windows uses UTF16, and everyone else uses UTF8
                char *utf8String = calloc(bufferLength + 1, sizeof(char));
                if (!utf8String || !WideCharToMultiByte(CP_UTF8, 0, buildLabBuffer, -1, utf8String, bufferLength + 1, NULL, NULL)) {
                    AMVP_LOG_ERR("Error converting Windows build info to UTF8, checking environment or omitting from HTTP user-agent...\n");
                    amvp_http_user_agent_check_env_for_var(ctx, osver, AMVP_USER_AGENT_OSVER);
                } else {
                    strncpy_s(osver, AMVP_USER_AGENT_OSVER_STR_MAX + 1, utf8String, AMVP_USER_AGENT_OSVER_STR_MAX);
                }
                free(utf8String);
                free(buildLabBuffer);
            }
        }
        RegCloseKey(key);
    }

    SYSTEM_INFO sysInfo;
    GetNativeSystemInfo(&sysInfo);
    if (!sysInfo.dwOemId) {
        amvp_http_user_agent_check_env_for_var(ctx, arch, AMVP_USER_AGENT_ARCH);
        amvp_http_user_agent_check_env_for_var(ctx, proc, AMVP_USER_AGENT_PROC);
    } else {
        char brandString[48];
        int brandString_resp[4];
        switch(sysInfo.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64:
            strncpy_s(arch, AMVP_USER_AGENT_ARCH_STR_MAX + 1, "x86_64", AMVP_USER_AGENT_ARCH_STR_MAX);
             //get CPU model string
            __cpuid(brandString_resp, 0x80000002);
            memcpy_s(brandString, 16, &brandString_resp, 16);
            __cpuid(brandString_resp, 0x80000003);
            memcpy_s(brandString + 16, 16, &brandString_resp, 16);
            __cpuid(brandString_resp, 0x80000004);
            memcpy_s(brandString + 32, 16, &brandString_resp, 16);
            strncpy_s(proc, AMVP_USER_AGENT_PROC_STR_MAX + 1, brandString, AMVP_USER_AGENT_PROC_STR_MAX);
            break;
        case PROCESSOR_ARCHITECTURE_INTEL:
            strncpy_s(arch, AMVP_USER_AGENT_ARCH_STR_MAX + 1, "x86", AMVP_USER_AGENT_ARCH_STR_MAX);
            //get CPU model string
            __cpuid(brandString_resp, 0x80000002);
            memcpy_s(brandString, 16, &brandString_resp, 16);
            __cpuid(brandString_resp, 0x80000003);
            memcpy_s(brandString + 16, 16, &brandString_resp, 16);
            __cpuid(brandString_resp, 0x80000004);
            memcpy_s(brandString + 32, 16, &brandString_resp, 16);
            strncpy_s(proc, AMVP_USER_AGENT_PROC_STR_MAX + 1, brandString, AMVP_USER_AGENT_PROC_STR_MAX);
            break;
        case PROCESSOR_ARCHITECTURE_ARM64:
            strncpy_s(arch, AMVP_USER_AGENT_ARCH_STR_MAX + 1, "aarch64", AMVP_USER_AGENT_ARCH_STR_MAX);
            amvp_http_user_agent_check_env_for_var(ctx, proc, AMVP_USER_AGENT_PROC);
            break;
        case PROCESSOR_ARCHITECTURE_ARM:
            strncpy_s(arch, AMVP_USER_AGENT_ARCH_STR_MAX + 1, "arm", AMVP_USER_AGENT_ARCH_STR_MAX);
            amvp_http_user_agent_check_env_for_var(ctx, proc, AMVP_USER_AGENT_PROC);
            break;
        case PROCESSOR_ARCHITECTURE_PPC:
            strncpy_s(arch, AMVP_USER_AGENT_ARCH_STR_MAX + 1, "ppc", AMVP_USER_AGENT_ARCH_STR_MAX);
            amvp_http_user_agent_check_env_for_var(ctx, proc, AMVP_USER_AGENT_PROC);
            break;
        case PROCESSOR_ARCHITECTURE_MIPS:
            strncpy_s(arch, AMVP_USER_AGENT_ARCH_STR_MAX + 1, "mips", AMVP_USER_AGENT_ARCH_STR_MAX);
            amvp_http_user_agent_check_env_for_var(ctx, proc, AMVP_USER_AGENT_PROC);
            break;
        default:
            amvp_http_user_agent_check_env_for_var(ctx, arch, AMVP_USER_AGENT_ARCH);
            amvp_http_user_agent_check_env_for_var(ctx, proc, AMVP_USER_AGENT_PROC);
            break;
        }
    }

    //gets compiler version
    amvp_http_user_agent_check_compiler_ver(comp);

#else
    /*******************************************************
     * Code for getting OE information on platforms that   *
     * are not Windows, Linux, or Mac OS can be added here *
     *******************************************************/
    amvp_http_user_agent_check_env_for_var(ctx, osname, AMVP_USER_AGENT_OSNAME);
    amvp_http_user_agent_check_env_for_var(ctx, osver, AMVP_USER_AGENT_OSVER);
    amvp_http_user_agent_check_env_for_var(ctx, arch, AMVP_USER_AGENT_ARCH);
    amvp_http_user_agent_check_env_for_var(ctx, proc, AMVP_USER_AGENT_PROC);
    amvp_http_user_agent_check_compiler_ver(comp);
#endif

    amvp_http_user_agent_string_clean(osname);
    amvp_http_user_agent_string_clean(osver);
    amvp_http_user_agent_string_clean(arch);
    amvp_http_user_agent_string_clean(proc);
    amvp_http_user_agent_string_clean(comp);

    snprintf(ctx->http_user_agent, AMVP_USER_AGENT_STR_MAX, "%s;%s;%s;%s;%s;%s", libver, osname, osver, arch, proc, comp);
    AMVP_LOG_INFO("HTTP User-Agent: %s\n", ctx->http_user_agent);

end:
    free(libver);
    free(osname);
    free(osver);
    free(arch);
    free(proc);
    free(comp);
}
