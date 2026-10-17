n3n-be for Windows (x86_64)
===========================

n3n-be (Bunny Edition) is a peer to peer VPN, a fork of n3n:
https://github.com/HoneyBunnyQT/n3n-be

What is in here
---------------

- n3n.exe, the program: "n3n.exe edge" starts it as an edge, "n3n.exe
  supernode" as a supernode
- edge.conf.sample and supernode.conf.sample, configurations to start from
- n3nctl, the management client (a Python 3 script)
- LICENSES: n3n-be is free software under the GNU GPL, version 3 (some
  parts version 2); its source is on the page above.  n3n.exe has
  winpthreads of the MinGW-w64 project linked in, under its own licence
  (winpthreads.txt)

Before the first start
----------------------

The edge needs a TAP adapter, which Windows does not have on its own: the
tap-windows6 driver of the OpenVPN project.  It comes with OpenVPN, or on
its own from https://build.openvpn.net/downloads/releases/ (the
"tap-windows" installers).

Running an edge
---------------

1. Copy edge.conf.sample to %USERPROFILE%\n3n\edge.conf and fill in the
   community, its key and the supernode.
2. In a command prompt run as administrator (the edge sets the address of
   the TAP adapter): n3n.exe edge

A supernode takes %USERPROFILE%\n3n\supernode.conf, started with
"n3n.exe supernode".  The management interface listens on a TCP port
(management.port), as Windows has no Unix sockets.  "n3n.exe edge -h"
lists the options; the documentation is on the project's page.

Coming from n3n or n2n
----------------------

There are no n3n-edge.exe and n3n-supernode.exe any more: "n3n.exe edge"
and "n3n.exe supernode" take their place, with the same options and the
same configuration files.  Scripts, shortcuts and services that start
the old programs need the new command.

The programs are not signed: Windows SmartScreen may warn on the first
start ("More info", "Run anyway").
