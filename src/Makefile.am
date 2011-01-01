# this is obnoxious:
# -module lets us name the module exactly how we want
# -avoid-version prevents gratuitous .0.0.0 version numbers on the end
# _ladir passes a dummy rpath to libtool so the thing will actually link
# TODO: -nostdlib/-Bstatic/-lgcc platform magic, not installing the .a, etc.

AM_CFLAGS = $(XORG_CFLAGS) $(CWARNFLAGS)
AM_CPPFLAGS =-I$(top_srcdir)/include

configdir = /etc/X11/xorg.conf.d
config_DATA = policy.conf  

AM_CFLAGS += -DDEBUG

lib@MODULE_NAME@_la_LTLIBRARIES = lib@MODULE_NAME@.la
lib@MODULE_NAME@_la_LDFLAGS = -module -avoid-version
lib@MODULE_NAME@_ladir = @extdir@

lib@MODULE_NAME@_la_SOURCES = policy.c client.c authorize.c winprop.c \
                              xvideo.c xrandr.c
