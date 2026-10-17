n3n-be for macOS (universal: Apple Silicon and Intel)
=====================================================

n3n-be (Bunny Edition) is a peer to peer VPN, a fork of n3n:
https://github.com/HoneyBunnyQT/n3n-be

What is in here
---------------

- n3n, the program, and the links n3n-edge and n3n-supernode to it, which
  start it as an edge or a supernode
- edge.conf.sample and supernode.conf.sample, configurations to start from
- n3nctl, the management client (a Python 3 script)
- LICENSES: n3n-be is free software under the GNU GPL, version 3 (some
  parts version 2); its source is on the page above

Running an edge
---------------

macOS has a TUN device of its own, utun, which the edge uses with
tuntap.type = tun: nothing to install, nothing to allow in the system
settings.  It needs root, as any tunnel does:

    sudo ./n3n-edge -O tuntap.type=tun -c mynet -k secret \
        -l sn.example.org:7654 -a 10.0.0.5/24 start

or with a config file (from edge.conf.sample, "type = tun" in its
[tuntap] section): sudo ./n3n-edge start edge.conf.  The edge takes the
next free utun device, puts the address on it and routes the community's
subnet into it.  The default, tuntap.type = tap, needs a third-party
kernel extension on macOS.

"./n3n-edge help config" lists the options; the documentation is on the
project's page.

The programs are not notarized by Apple.  Downloaded with a browser, they
carry the quarantine attribute, and macOS refuses to start them; this
takes it off:

    xattr -dr com.apple.quarantine n3n-be-*-macos-universal
