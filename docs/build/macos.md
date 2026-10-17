<!--
SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright 2020 n2n contributors
SPDX-FileCopyrightText: Copyright Hamish Coleman
SPDX-FileCopyrightText: Copyright Honey Bunny QT
-->

# Build on macOS

The macOS build can use the generic build instructions, but first needs
automake:

```bash
brew install automake
./autogen.sh && ./configure && make
```

## Run on macOS

macOS has a TUN device of its own, `utun`: no driver to install, nothing
to allow in the system settings, no signing.  The edge uses it with
`tuntap.type = tun` (see [TAP or TUN](../configure/TapConfiguration.md#tap-or-tun)),
and needs root for it, as for any tunnel:

```bash
sudo apps/n3n-edge -O tuntap.type=tun -c mynet -k secret \
    -l sn.example.org:7654 -a 10.0.0.5/24 start
```

or `type = tun` in the `[tuntap]` section of the config file.  The edge
takes the next free `utunN` (or the one `tuntap.name = utunN` names), puts
the address on it, adds the route of the community's subnet into it, and
the IPv6 address and prefix with `tuntap.address6`; all of it goes away
with the device when the edge stops.  The device carries IP, not Ethernet:
no bridging, and the edge does ARP for it, so it shares a community with
the TAP edges of other systems.  `n3nctl` finds the edge under `/var/run/n3n`.

A TAP device (the default, `tuntap.type = tap`) needs a third-party kernel
extension on macOS (`tuntaposx`, `/dev/tapN`), which recent versions make
hard to install, and Apple Silicon only with reduced security; for most,
`tun` is the way.  The supernode needs no device at all.

Binaries downloaded with a browser carry the quarantine attribute, which
Gatekeeper stops unsigned programs for; `xattr -d com.apple.quarantine`
on them, or downloading with `curl`, avoids that.
