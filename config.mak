# Global configuration, included in top Makefile and exported from there.
#
# ./configure


CONFIG_HOST=x86_64-linux-gnu
CONFIG_HOST_OS=linux-gnu

CONFIG_PREFIX=/usr/local
CONFIG_DOCDIR=$(DESTDIR)/usr/local/share/doc/n3n
CONFIG_MANDIR=$(DESTDIR)/usr/local/share/man
CONFIG_RUNDIR=$(DESTDIR)/run
CONFIG_SYSTEMDDIR=$(DESTDIR)/usr/local/lib/systemd/system

CONFIG_WITH_OPENSSL=no

CC=gcc
AR=ar
WINDRES=windres
EXE=

CFLAGS+=-g -O2
LDFLAGS+=
LDLIBS_EXTRA+=
