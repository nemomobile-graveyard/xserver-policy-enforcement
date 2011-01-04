# Initialize Autoconf
AC_PREREQ([2.60])
AC_INIT([xserver-policy-enforcement],
        [0.0.1],
        [https://projects.maemo.org/bugzilla/],
        [policy])
AC_CONFIG_SRCDIR([Makefile.am])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR(.)

AC_CONFIG_MACRO_DIR([m4])

# Initialize Automake
AM_INIT_AUTOMAKE([foreign dist-bzip2])
AM_MAINTAINER_MODE


# Initialize libtool
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

# Initialize X.Org macros
m4_ifndef([XORG_MACROS_VERSION], 
          [m4_fatal([must install xorg-macros 1.4 or later before running autoconf/autogen])])
XORG_MACROS_VERSION(1.4)
XORG_DEFAULT_OPTIONS

# Checks for programs.
AC_PROG_INSTALL
AC_PROG_SED

# Obtain compiler/linker options from server and required extensions
PKG_CHECK_MODULES(XORG, xorg-server xproto)

# Define a configure option for an alternate input module directory
AC_ARG_WITH(xorg-module-dir,
            AC_HELP_STRING([--with-xorg-module-dir=DIR],
                           [Default xorg module directory [[default=$libdir/xorg/modules]]]),
            [moduledir="$withval"],
            [moduledir="$libdir/xorg/modules"])
extdir=${moduledir}/extensions
AC_SUBST([extdir])

# X Server SDK location is required
# This location is also relayed in the xorg-evdev.pc file
sdkdir=`$PKG_CONFIG --variable=sdkdir xorg-server`

# Workaround overriding sdkdir to be able to create a tarball when user has no
# write permission in sdkdir. See DISTCHECK_CONFIGURE_FLAGS in Makefile.am
AC_ARG_WITH([sdkdir], [], [sdkdir="$withval"])
AC_SUBST([sdkdir])

MODULE_NAME=policy
AC_SUBST([MODULE_NAME])

# shave
SHAVE_INIT([build-aux], [enable])

AC_CONFIG_FILES([build-aux/shave
		 build-aux/shave-libtool
                 Makefile
                 src/Makefile])
AC_OUTPUT
