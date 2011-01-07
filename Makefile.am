AUTOMAKE_OPTIONS = foreign
SUBDIRS = src client # doc

ACLOCAL_AMFLAGS=-I m4

MAINTAINERCLEANFILES = ChangeLog INSTALL
DISTCLEANFILES = videoipc.pc 

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = videoipc.pc

.PHONY: ChangeLog INSTALL

INSTALL:
	$(INSTALL_CMD)

ChangeLog:
	$(CHANGELOG_CMD)

dist-hook: ChangeLog INSTALL
