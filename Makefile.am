ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -std=c99
AM_CPPFLAGS = -I$(top_srcdir)/include -D_GNU_SOURCE \
              -DRUNDIR=\"$(rundir)\" -DPKGLIBEXECDIR=\"$(pkglibexecdir)\"

lib_LTLIBRARIES = libpam-once.la

libpam_once_la_SOURCES = src/pam-once.c
libpam_once_la_LIBADD = -lpam
libpam_once_la_LDFLAGS = -version-info 0:0:0

include_HEADERS = include/pam-once.h

pkglibexec_PROGRAMS = po_count

po_count_SOURCES = src/po_count.c

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = pam-once.pc
