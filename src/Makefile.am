lib_LTLIBRARIES = libamvp.la
AM_CFLAGS = -I$(top_srcdir)/include/amvp $(SAFEC_CFLAGS) $(LIBCURL_CFLAGS)

libamvp_la_SOURCES =  amvp.c \
                    amvp_build_register.c \
                    amvp_operating_env.c \
                    amvp_transport.c \
                    amvp_endpoints.c \
                    amvp_util.c \
                    amvp_error.c \
                    amvp_base64.c \
                    amvp_display.c \
                    parson.c

libamvp_la_LIBADD = $(SAFEC_LDFLAGS) $(LIBCURL_LDFLAGS)
libamvp_includedir=$(includedir)/amvp
libamvp_include_HEADERS = $(top_srcdir)/include/amvp/amvp.h
noinst_HEADERS = $(top_srcdir)/include/amvp/amvp_lcl.h \
                 $(top_srcdir)/include/amvp/amvp_error.h \
				 $(top_srcdir)/include/amvp/parson.h

