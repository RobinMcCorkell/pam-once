ACLOCAL_AMFLAGS = -I m4

moduledir = $(libdir)/security

AM_CFLAGS = -std=c99
AM_CPPFLAGS = -D_GNU_SOURCE -DRUNDIR=\"$(rundir)\" \
              -DMODULEDIR=\"$(moduledir)\"

module_LTLIBRARIES = pam_once.la

pam_once_la_SOURCES = src/pam_once.c
pam_once_la_LIBADD = -lpam
pam_once_la_LDFLAGS = -module -avoid-version

module_PROGRAMS = po_count

po_count_SOURCES = src/po_count.c
