tmp_sources = app_main.c \
              app_aes.c \
              app_cli.c \
              app_cmac.c \
              app_des.c \
              app_drbg.c \
              app_dsa.c \
              app_ecdsa.c \
              app_hmac.c \
              app_kas.c \
              app_kdf.c \
              app_kda.c \
              app_kmac.c \
              app_rsa.c \
              app_sha.c \
              app_utils.c \
              app_fips_lcl.h \
              app_fips_init_lcl.h \
              app_lcl.h \
              ketopt.h

if !BUILD_APP_AS_LIB
bin_PROGRAMS = amvp_app

amvp_app_includedir=$(includedir)/amvp
amvp_app_SOURCES = ${tmp_sources}
amvp_app_CFLAGS = -g -fPIE $(LIBAMVP_CFLAGS) $(SSL_CFLAGS) $(FOM_CFLAGS) $(SAFEC_CFLAGS) $(COND_ALG_CFLAGS)
amvp_app_LDFLAGS = $(LIBAMVP_LDFLAGS) $(SSL_LDFLAGS) $(FOM_LDFLAGS)
amvp_app_LDADD = $(ADDL_LIB_DEPENDENCIES)

if FORCE_STATIC
amvp_app_LDFLAGS += -all-static
endif

if ! BUILDING_OFFLINE
amvp_app_LDFLAGS += $(LIBCURL_LDFLAGS)
amvp_app_CFLAGS += $(LIBCURL_CFLAGS)
endif

if USE_FOM_OBJ
amvp_app_LDADD += $(FOM_OBJ_DIR)/fipscanister.o
endif

else
lib_LTLIBRARIES = libamvp_app.la
libamvp_app_includedir=${includedir}/amvp
libamvp_app_la_SOURCES = ${tmp_sources}

AM_CFLAGS = -g -fPIE $(LIBAMVP_CFLAGS) $(SSL_CFLAGS) $(FOM_CFLAGS) $(SAFEC_CFLAGS) $(COND_ALG_CFLAGS) -DAMVP_APP_LIB_WRAPPER
libamvp_app_la_LIBADD = $(LIBAMVP_LDFLAGS) $(SSL_LDFLAGS) $(FOM_LDFLAGS)

libamvp_app_include_HEADERS = $(top_srcdir)/app/libamvp_app.h

if USE_FOM_OBJ
libamvp_app_la_LIBADD += $(FOM_OBJ_DIR)/fipscanister.o
endif
endif
