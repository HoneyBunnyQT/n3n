SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright Honey Bunny QT

# Mobile and TUN: design notes

Ideas for two things that belong together: an edge with a TUN device (layer
3) instead of a TAP device (layer 2), and an Android app built on it.
Nothing of this is code yet; it is here to be discussed and refined.  See
the [Roadmap](Roadmap.md) for where it stands.

Both keep the v3 protocol: on the wire there are Ethernet frames as before,
so a TUN edge and a TAP edge are in the same community and reach each other.

## TUN mode

### Why

A TAP device carries Ethernet frames; a TUN device carries IP packets.  Some
systems only offer TUN to programs: Android (`VpnService`), iOS, macOS
(`utun`, without a third party driver), and Windows with wintun.  On Linux
TUN also saves the work of ARP and Ethernet headers for edges that only
need IP.

### What the edge does

The edge keeps its MAC address and its view of the community as a layer 2
segment; a thin layer between the TUN device and the rest of the edge plays
the part of the kernel's Ethernet and ARP:

- From the device (an IP packet):
  - IPv4 unicast in the community's subnet: the destination MAC comes from
    a table of IP to MAC.  It is filled from the ARP replies the edge gets,
    and from what peers tell about themselves: REGISTER and REGISTER_SUPER
    carry the sender's address (`dev_addr`).  If the address is not in the
    table, the edge sends an ARP request (broadcast) and drops or queues
    the packet, as the kernel does.
  - Broadcast and multicast: to the broadcast or multicast MAC.
  - The edge puts an Ethernet header in front (its own MAC as source,
    EtherType 0x0800 or 0x86DD) and sends the frame as now.
- From the network (an Ethernet frame):
  - An ARP request for the edge's own address: the edge answers with an ARP
    reply, sent over the network as if the device had answered.
  - An ARP reply: goes into the table.
  - IPv4 or IPv6 for this edge's MAC, or broadcast or multicast: the
    Ethernet header comes off and the packet goes to the device.
  - Anything else (other EtherTypes, frames for other MACs): dropped.

This is what hin2n, the Android app of n2n, does as well.

### Configuration

- `tuntap.mode = tap | tun`, `tap` by default.
- `tuntap.fd = N`: use an already open device (from Android's `VpnService`,
  or a parent process), instead of opening one.
- The device setup (address, MTU, routes) is up to the platform: on Linux
  as now with `ip`, on Android by `VpnService.Builder`.

### Limits

- No bridging (`filter.allow_routing` with a bridge) and no non-IP traffic:
  they need layer 2.
- Routing other subnets through the tunnel (n3n-route) needs a next hop
  per route: a later step.
- IPv6 needs neighbour discovery answered like ARP (neighbour solicitation
  and advertisement), and an IPv6 address on the device, which the TAP
  device does not have either yet (see the Roadmap).  So: IPv4 first.

### Steps

1. The layer between device and edge (ARP table, header in and out), with
   unit tests over captured frames.
2. `tuntap.mode = tun` on Linux, and a netns scenario with one TUN edge and
   one TAP edge, traffic both ways.
3. `tuntap.fd`, for Android and for tests.
4. IPv6 (neighbour discovery), later.

## Android app

### The parts

- **libn3n**: the edge, built with the Android NDK as a shared library: the
  edge-only build (`./configure --disable-relay`) for arm64-v8a, armeabi-v7a
  and x86_64.  CI builds it, as it cross-builds for other systems now.
- **A small C entry point**, called through JNI:
  - `n3n_edge_run(config_text, tun_fd, callbacks)`: runs the edge (its main
    loop) on the thread that calls it, until it is stopped;
  - `n3n_edge_stop()`;
  - callbacks for the log, for "address assigned" (with automatic
    addresses the edge only knows its address after registering), and for
    every socket the edge opens, see below.
- **The app** (Kotlin): a `VpnService` that builds the TUN device and runs
  the edge in a foreground service with its notification, and a few
  screens: the networks, their state, the peers.

### What the edge needs to change for it

- **Sockets**: every socket the edge opens (the UDP sockets of
  `connection.bind`, the extra sockets of NAT traversal, the TCP connection,
  the UDP probe of the TCP fallback, multicast) has to be passed to
  `VpnService.protect()`, or its packets go back into the VPN.  One hook
  in `open_socket()` and the few other places that make sockets does it.
- **No daemon**: no fork, no dropping of privileges, no `/run/n3n`: the
  session directory and the management socket go to the app's private
  directory.  The app reads the state with the management API over that
  socket (`get_info`, `get_edges`, `get_packetstats`), as `n3nctl` does.
- **Network changes**: when the phone moves from WiFi to mobile data, the
  sockets have to be opened anew and the edge has to register again; the
  app gets told by Android (`ConnectivityManager`) and tells the edge, for
  example with a management method `reconnect`.  The TCP fallback already
  covers networks that block UDP.
- **Battery**: the registrations every `register_interval` keep the NAT
  mappings open, and they wake the phone.  A longer interval on mobile
  networks (their NATs mostly keep mappings longer) is a setting to try.

### Configuration and QR codes

The app takes the same configuration files as the edge on other systems,
so a network can be set up once and shared:

- **Import a file**: an `.conf` file as for Linux (`[community]`,
  `[connection]`, ...).
- **Scan a QR code**: the configuration in a QR code.  A suggestion for its
  content: `n3n:1:` followed by the configuration file, compressed with
  deflate and in base64url.  A usual configuration (community, supernodes,
  key, address) is a few hundred bytes, well within what a QR code holds
  (around 2900 bytes in binary).
- **Secrets in the code**: the key or password is the secret of the whole
  community, and a QR code is easily photographed.  So the generator should
  be able to leave them out (the app asks for them on import), or encrypt
  the content with a PIN (a key derived from it with a slow KDF, such as
  scrypt or Argon2, and ChaCha20-Poly1305).
- **Making the codes**: a command `n3n-edge tools qr [session]`, or a
  script `scripts/n3n-qr`, prints the code of a configuration in the
  terminal or as a PNG; the supernode could offer one per community on its
  management page later.

What the app adds on top of the file: a name for the network, which apps
use it (`VpnService.Builder.addAllowedApplication`), and whether it starts
with the phone (always-on VPN).

### Steps

1. TUN mode on Linux, with tests (see above).
2. The library entry point and the socket hook, tried from a small C
   program on Linux with a TUN fd handed over.
3. libn3n built by the NDK in CI.
4. A minimal app: import a file or a QR code, connect, disconnect, state.
5. Then: several networks, always-on, a quick settings tile, per-app VPN,
   F-Droid (the app would be GPL-3.0 like n3n).

hin2n (the n2n app) is worth a look before starting, both for what works
and for whether it could take n3n as its library instead.
