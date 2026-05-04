noinst_PROGRAMS = runtest
runtest_SOURCES = ut_common.c
tmp_cflags = -g -O0 -Wall $(SAFEC_CFLAGS) $(CRITERION_CFLAGS) $(LIBAMVP_CFLAGS) -I../include
tmp_ldflags= $(CRITERION_LDFLAGS) $(SAFEC_LDFLAGS) $(LIBAMVP_LDFLAGS)

if ! LIB_NOT_SUPPORTED
runtest_SOURCES += create_session.c \
      test_amvp_utils.c \
      test_amvp_build_register.c \
      test_amvp.c \
      test_amvp_transport.c \
      test_amvp_operating_env.c

tmp_cflags += $(LIBCURL_CFLAGS)
tmp_ldflags += $(LIBCURL_LDFLAGS)
endif

if ! APP_NOT_SUPPORTED
runtest_SOURCES += app_common.c

tmp_cflags += -I../app
endif

runtest_CFLAGS = ${tmp_cflags}
runtest_LDFLAGS = ${tmp_ldflags}

runtestdir=
runtest_HEADERS = ut_common.h
if ! APP_NOT_SUPPORTED
runtest_HEADERS += app_common.h
endif

