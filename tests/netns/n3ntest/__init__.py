#
# Copyright (C) Honey Bunny QT
# SPDX-License-Identifier: GPL-3.0-only
#
"""Network namespace test harness for n3n edges and supernodes.

Builds a small internet in Linux network namespaces - two federated
supernodes, sites behind NAT routers of different kinds - starts real
n3n-edge and n3n-supernode binaries in it, sends counted frames through
the VPN and checks the frame counts, the p2p/relay counters and the path
the edges ended up on.  See docs/develop/netns_testing.md.
"""
