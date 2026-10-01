#
# Copyright (C) Hamish Coleman
#
# This makefile shows how to build applications using the libn3n library.
#
# The examples programs are intended to show how to use the libn3n as an
# embedded service within other software.
#

# If using this makefile outside of the n3n build environment, you will
# need to setup the correct include paths.
#
# eg:
# CFLAGS+=-I../include
# LDFLAGS+=-L../src
#
# CFLAGS+=-I../libs
# LDFLAGS+=-L../libs/connslot
# LDLIBS_LOCAL+=-lconnslot

# One binary for all the roles, see n3n.c
APPS+=n3n

# and its names for each role: links to it, copies where there are no links
LINKS+=n3n-edge
ifneq ($(CONFIG_RELAY),no)
LINKS+=n3n-supernode
ROLES+=n3n-supernode.c
endif

EXAMPLES+=example_edge_embed_quick_edge_init
EXAMPLES+=example_edge_embed
ifneq ($(CONFIG_RELAY),no)
EXAMPLES+=example_sn_embed
endif

LDLIBS+=-ln3n
LDLIBS+=$(LDLIBS_LOCAL)
LDLIBS+=$(LDLIBS_EXTRA)

all: $(APPS) $(LINKS)

examples: $(EXAMPLES)

# TODO: a better path for this lib, as it would need to change to use this
# makefile outside the build environment
$(APPS) $(EXAMPLES): ../src/libn3n.a

n3n: n3n.c n3n-edge.c $(ROLES)

$(LINKS): n3n
	@echo "  LN      $@"
ifeq ($(EXE),)
	@ln -sf n3n $@
else
	@cp n3n$(EXE) $@$(EXE)
endif

.PHONY: install
install: $(addsuffix $(EXE),$(APPS))
	$(INSTALL) -d $(CONFIG_SBINDIR)
	$(INSTALL_PROG) n3n$(EXE) $(CONFIG_SBINDIR)/
ifeq ($(EXE),)
	for l in $(LINKS); do ln -sf n3n $(CONFIG_SBINDIR)/$$l; done
else
	for l in $(LINKS); do $(INSTALL_PROG) n3n$(EXE) $(CONFIG_SBINDIR)/$$l$(EXE); done
endif

%: %.c
	@echo "  CC      $@"
	@$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $(filter %.c %.a,$^) $(LDLIBS) -o $@

# See comments in the topdir Makefile about how to generate coverage data.
# gcc names the coverage data of a binary built in one step <binary>-<source>
gcov:
	gcov n3n-n3n n3n-n3n-edge $(ROLES:%.c=n3n-%)

clean:
	rm -f $(APPS) $(LINKS) $(EXAMPLES)
