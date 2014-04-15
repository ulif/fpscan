AC_INIT([fpscan], [0.1dev], [uli@gnufix.de])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
AC_CONFIG_HEADERS([config.h])

AC_CONFIG_FILES([
  Makefile
  src/Makefile
])

# check for libfprint
PKG_CHECK_MODULES(FPRINT, libfprint)
AC_SUBST(FPRINT_CFLAGS)
AC_SUBST(FPRINT_LIBS)

AC_OUTPUT
