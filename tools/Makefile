#
# This is not a standalone makefile, it must be called from the toplevel
# makefile to inherit the correct environment

LDLIBS+=-ln3n
LDLIBS+=$(LDLIBS_LOCAL)
LDLIBS+=$(LDLIBS_EXTRA)

TOOLS_OPTIONAL+=n3n-benchmark

TOOLS+=n3n-route
TOOLS+=n3n-portfwd
TOOLS+=n3n-decode
TOOLS+=crypto_helper

# when ./configure found libqrencode and libpng
ifneq ($(LDLIBS_QR),)
TOOLS+=n3n-qr
endif

TESTS=tests-compress
TESTS+=tests-elliptic
TESTS+=tests-transform
TESTS+=tests-wire
TESTS+=tests-auth
TESTS+=tests-peers
TESTS+=tests-aes
TESTS+=tests-cc20
TESTS+=tests-wire-fuzz
TESTS+=tests-wire-numsn
TESTS+=tests-regex

.PHONY: all clean install
all: $(TOOLS) $(TESTS)

optional: $(TOOLS_OPTIONAL)

# As in apps/Makefile: without this, a changed library does not relink
# the tools, and "make test" runs the old test binaries
$(TOOLS) $(TOOLS_OPTIONAL) $(TESTS): ../src/libn3n.a

%: %.c
	@echo "  CC      $@"
	@$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $^ $(LDLIBS) -o $@

# not the core, only its libraries
n3n-qr: n3n-qr.c
	@echo "  CC      $@"
	@$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $< $(LDLIBS_QR) -o $@

# See comments in the topdir Makefile about how to generate coverage
# data.  The notes are x.gcno or, compiled and linked in one step with
# the library, x-x.gcno: whichever there are.
gcov:
	gcov $(basename $(wildcard *.gcno))

clean:
	rm -rf $(TOOLS) *.o *.dSYM *~
	rm -f $(TESTS) *.gcno *.gcda

install: $(TOOLS)
	$(INSTALL) -d $(CONFIG_SBINDIR)
	$(INSTALL_PROG) $(addsuffix $(EXE),$(TOOLS)) $(CONFIG_SBINDIR)/
