lib_LTLIBRARIES = libamvp.la
AM_CFLAGS = -I$(top_srcdir)/include/amvp $(SAFEC_CFLAGS) $(LIBCURL_CFLAGS)

if BUILDING_OFFLINE
AM_CFLAGS+= -DAMVP_OFFLINE
endif

libamvp_la_SOURCES =  amvp.c \
                    amvp_build_register.c \
                    amvp_capabilities.c \
                    amvp_operating_env.c \
                    amvp_aes.c \
                    amvp_des.c \
                    amvp_hash.c \
                    amvp_drbg.c \
                    amvp_transport.c \
                    amvp_util.c \
                    amvp_error.c \
                    parson.c \
                    amvp_hmac.c \
                    amvp_cmac.c \
                    amvp_kmac.c \
                    amvp_rsa_keygen.c \
                    amvp_rsa_sig.c \
                    amvp_rsa_prim.c \
                    amvp_dsa.c \
                    amvp_kdf135_snmp.c \
                    amvp_kdf135_ssh.c \
                    amvp_kdf135_srtp.c \
                    amvp_kdf135_ikev2.c \
                    amvp_kdf135_ikev1.c \
                    amvp_kdf135_x942.c \
                    amvp_kdf135_x963.c \
                    amvp_kdf108.c \
                    amvp_pbkdf.c \
                    amvp_kdf_tls12.c \
                    amvp_kdf_tls13.c \
                    amvp_kas_ecc.c \
                    amvp_kas_ffc.c \
                    amvp_kas_ifc.c \
                    amvp_kda.c \
                    amvp_kts_ifc.c \
                    amvp_safe_primes.c \
                    amvp_ecdsa.c

libamvp_la_LIBADD = $(SAFEC_LDFLAGS) $(LIBCURL_LDFLAGS)
libamvp_includedir=$(includedir)/amvp
libamvp_include_HEADERS = $(top_srcdir)/include/amvp/amvp.h
noinst_HEADERS = $(top_srcdir)/include/amvp/amvp_lcl.h \
                 $(top_srcdir)/include/amvp/amvp_error.h \
				 $(top_srcdir)/include/amvp/parson.h

