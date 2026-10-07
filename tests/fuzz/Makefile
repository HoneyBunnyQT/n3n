#
# Copyright (C) Honey Bunny QT
# SPDX-License-Identifier: GPL-3.0-only
#
# The fuzz targets, see README.md.  Not a standalone makefile: the
# toplevel one calls it ("make test.fuzz", "make fuzz", "make fuzz.run").
#
# FUZZ=libfuzzer links the targets with libFuzzer (clang, and the library
# built with -fsanitize=fuzzer-no-link); without it, with driver.c, which
# runs them on files - with any compiler.

LDLIBS+=-ln3n
LDLIBS+=$(LDLIBS_LOCAL)
LDLIBS+=$(LDLIBS_EXTRA)
CFLAGS+=-I$(abspath ../../src)

TARGETS=fuzz-wire fuzz-header fuzz-transop

ifeq ($(FUZZ),libfuzzer)
TARGET_LINK=-fsanitize=fuzzer
else
TARGET_DRIVER=driver.c
endif

.PHONY: all clean
all: $(TARGETS) fuzz-seeds

$(TARGETS) fuzz-seeds: ../../src/libn3n.a fuzz.h

$(TARGETS): %: %.c fuzz-common.c $(TARGET_DRIVER)
	@echo "  CC      $@"
	@$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $(TARGET_LINK) $(filter %.c,$^) $(LDLIBS) -o $@

fuzz-seeds: fuzz-seeds.c fuzz-common.c
	@echo "  CC      $@"
	@$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $(filter %.c,$^) $(LDLIBS) -o $@

clean:
	rm -f $(TARGETS) fuzz-seeds *.o *.d
	rm -rf seeds work
