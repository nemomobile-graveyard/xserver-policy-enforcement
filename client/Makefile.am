AM_CFLAGS = -O0 -g3

bin_PROGRAMS = videoipc-client

videoipc_client_SOURCES = client.c
videoipc_client_CFLAGS = @XLIB_CFLAGS@ -I$(top_srcdir)/src
videoipc_client_LDADD = @XLIB_LIBS@ -lrt


