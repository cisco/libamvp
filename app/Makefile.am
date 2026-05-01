tmp_sources = app_main.c \
              app_cli.c \
              app_lcl.h \
              ketopt.h \
              totp/totp.c \
              totp/hmac_sha256.c \
              totp/sha256.c \
              totp/hmac_sha256.h \
              totp/sha256.h


bin_PROGRAMS = amvp_app

amvp_app_includedir=$(includedir)/amvp
amvp_app_SOURCES = ${tmp_sources}
amvp_app_CFLAGS = -g -fPIE $(LIBAMVP_CFLAGS) $(SSL_CFLAGS) $(SAFEC_CFLAGS) $(COND_ALG_CFLAGS) $(LIBCURL_CFLAGS)
amvp_app_LDFLAGS = $(LIBAMVP_LDFLAGS) $(SSL_LDFLAGS) $(LIBCURL_LDFLAGS)
amvp_app_LDADD = $(ADDL_LIB_DEPENDENCIES)
