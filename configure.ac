#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])

AC_INIT([p11tools],[0.0.1])
AM_INIT_AUTOMAKE

AC_CONFIG_SRCDIR([src/p11_enum_keys.c])
AC_CONFIG_HEADERS([config.h])

AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_HOST

# Checks for programs.
AC_PROG_CC
PKG_PROG_PKG_CONFIG

# Checks for libraries.
PKG_CHECK_MODULES(P11TOOLS,
[
	libp11 >= 0.2.8
	libssl >= 1.0.1f
])

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
if test "$GCC" = "yes"; then
  CFLAGS="$CFLAGS -Wall -Wunused -funsigned-char -Wno-pointer-sign -Wno-unused-result"
fi
AC_CHECK_HEADERS([stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([strchr strndup])

AC_ARG_ENABLE(onboard-keygen,
[ --enable-onboard-keygen [[diabled]]],,[enable_onboard_keygen="no"])
if  test "x$enable_onboard_keygen" = "xyes";then
	AC_DEFINE(HAVE_ONBOARD_KEYGEN,1,"")
fi

AC_CONFIG_FILES([
	Makefile
	src/Makefile
])
AC_OUTPUT
