noinst_PROGRAMS = runtest
runtest_SOURCES = ut_common.c
tmp_cflags = -g -O0 -Wall -DNO_SSL_DL $(SAFEC_CFLAGS) $(CRITERION_CFLAGS) $(LIBAMVP_CFLAGS) -I../include
tmp_ldflags= $(CRITERION_LDFLAGS) $(SAFEC_LDFLAGS) $(LIBAMVP_LDFLAGS)

if ! LIB_NOT_SUPPORTED
runtest_SOURCES += create_session.c \
      test_amvp_utils.c \
      test_amvp_drbg.c \
      test_amvp_dsa.c \
      test_amvp_hmac.c \
      test_amvp_kdf135_ssh.c \
      test_amvp_kdf135_snmp.c \
      test_amvp_kdf135_x963.c \
      test_amvp_kdf135_srtp.c \
      test_amvp_kdf135_ikev2.c \
      test_amvp_kdf135_ikev1.c \
      test_amvp_kdf108.c \
      test_amvp_pbkdf.c \
      test_amvp_kdf_tls12.c \
      test_amvp_kdf_tls13.c \
      test_amvp_rsa_keygen.c \
      test_amvp_rsa_sig.c \
      test_amvp_rsa_prim.c \
      test_amvp_cmac.c \
      test_amvp_des.c \
      test_amvp_capabilities.c \
      test_amvp_hash.c \
      test_amvp_build_register.c \
      test_amvp_aes.c \
      test_amvp.c \
      test_amvp_transport.c \
      test_amvp_operating_env.c \
      test_amvp_ecdsa.c \
      test_amvp_kas_ecc.c \
      test_amvp_kas_ifc.c \
      test_amvp_kts_ifc.c \
      test_amvp_kas_ffc.c \
      test_amvp_safe_primes.c \
      test_amvp_kda.c 

tmp_cflags += $(LIBCURL_CFLAGS)
tmp_ldflags += $(LIBCURL_LDFLAGS)
endif

if ! APP_NOT_SUPPORTED
runtest_SOURCES += app_common.c \
      test_app_aes.c \
      test_app_cmac.c \
      test_app_des.c \
      test_app_drbg.c \
      test_app_ecdsa.c \
      test_app_hmac.c \
      test_app_kas_ecc.c \
      test_app_kas_ffc.c \
      test_app_kas_ifc.c \
      test_app_rsa_keygen.c \
      test_app_rsa_sig.c \
      test_app_sha.c \
      test_app_safe_primes.c \
      test_app_kda.c

APP_LINK = ../app/amvp_app-app_utils.o \
           ../app/amvp_app-app_sha.o \
           ../app/amvp_app-app_hmac.o \
           ../app/amvp_app-app_aes.o \
           ../app/amvp_app-app_des.o \
           ../app/amvp_app-app_cmac.o \
           ../app/amvp_app-app_kdf.o \
           ../app/amvp_app-app_dsa.o \
           ../app/amvp_app-app_kas.o \
           ../app/amvp_app-app_rsa.o \
           ../app/amvp_app-app_ecdsa.o \
           ../app/amvp_app-app_drbg.o \
           ../app/amvp_app-app_kda.o

tmp_cflags += $(SSL_CFLAGS) $(FOM_CFLAGS) -I../app
tmp_ldflags += $(SSL_LDFLAGS) $(FOM_LDFLAGS)
endif

runtest_CFLAGS = ${tmp_cflags}
runtest_LDFLAGS = ${tmp_ldflags}

if ! APP_NOT_SUPPORTED
runtest_LDADD = $(APP_LINK)
endif

runtestdir=
runtest_HEADERS = ut_common.h
if ! APP_NOT_SUPPORTED
runtest_HEADERS += app_common.h
endif

