AC_INIT([pam-once], [0.1], [rmccorkell@karoshi.org.uk])
AC_PREREQ([2.61])

AC_CONFIG_SRCDIR([src/pam-once.c])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_FILES([Makefile pam-once.pc])

AC_PROG_CC
AC_PROG_INSTALL

AM_INIT_AUTOMAKE([subdir-objects])
LT_INIT

AM_PROG_CC_C_O
AM_CONFIG_HEADER([config.h])

AC_ARG_WITH([rundir], AS_HELP_STRING([--with-rundir=PATH],
	[Path to the run directory [[/run]]]),
	[rundir="$withval"], [rundir="/run"])
AC_SUBST([rundir])

AC_OUTPUT
