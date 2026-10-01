SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright 2022 n2n contributors
SPDX-FileCopyrightText: Copyright Hamish Coleman

# n3n

[![Testing](https://github.com/n42n/n3n/actions/workflows/tests.yml/badge.svg)](https://github.com/n42n/n3n/actions/workflows/tests.yml)
[![Latest Release](https://img.shields.io/github/v/release/n42n/n3n)](https://github.com/n42n/n3n/releases/latest)

n3n is a lightweight Peer-to-Peer VPN that creates virtual networks.

In order to start using n3n, two elements are required:

- A _supernode_: it allows edge nodes to announce and discover other nodes. It
  must have a port publicly accessible on internet.
- _edge_ nodes: the nodes which will be a part of the virtual networks

A virtual network shared between multiple edge nodes in n3n is called a
_community_. A single supernode can relay multiple communities and a single
computer can be part of multiple communities at the same time (by running
multiple _edge_ daemons). An encryption key can be used by the edge nodes to
encrypt the packets within their community.

Both daemons are one program, `n3n`, installed under the names `n3n-edge` and
`n3n-supernode` as well.  Started under one of those names it is that daemon;
started as `n3n`, its first argument says which: `n3n edge start` is the same
as `n3n-edge start`.

n3n tries to establish a direct peer-to-peer connection via udp between the
edge nodes when possible. When this is not possible (usually due to special NAT
devices), the supernode is also used to relay the packets.

```
    [edge-A] ──────────────────── [edge-B]
          \      direct p2p        /
           \                      /
            └──── [supernode] ────┘
                (discovery + relay)
```

n3n was originally based on an older n2n project and hopes to keep protocol
compatibility with that.

Note that some distributions have very old versions of n2n packaged that are
incompatible with the protocol used by n3n.  At the least, Debian has a n2n
version 1.3.1 which uses a protocol from 2008 and has not been compatible with
the stable releases of n2n for many years - thus will definitely not
interoperate with n3n)

# Documentation

- [Quick Start Guides](quick_start/Config.md): a first configuration, and
  [on Debian or Ubuntu](quick_start/Debian.md)
- [Configuration](configure/index.md): edges, supernodes, communities, all
  [options](configure/Options.md)
- [Advanced Topics](advanced/index.md): NAT traversal, threads, routing,
  bridging, filtering
- [Building from Source](build/index.md), with the options of `./configure`
- [Tools](Tools.md) and [Scripts](Scripts.md), like `n3nctl`
- [Internals](internals/index.md): the management API, cryptography, design
- [Developing](develop/index.md): coding style, tests, the roadmap
- Answers to [frequently asked questions](FAQ.md) (FAQ)
- [Contributing](Contributing.md) and the [License](LICENSE.md)

The man pages `n3n(8)`, `n3n-edge(8)`, `n3n-supernode(8)` and `n3n(7)` come
with the package.
