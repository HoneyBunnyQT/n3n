SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright Logan oos Even
SPDX-FileCopyrightText: Copyright Hamish Coleman

# n3n Frequently Asked Questions


## Releases

### Where can I find binaries for Windows?

We do not have a Windows package, but EXE files for modern Windows can be
found as part of the latest release.

If you want to use with Windows XP - eg, for retro gaming - those binaries
are not part of the standard release package.  The automated test workflow
does create them and they can be downloaded from the _Actions_ tab, at the
_Testing_ workflow, select the newest run, scroll down to the _Artifacts_
sections where the _binaries_ file contains the Windows binaries in its
`i686-w64-mingw32/usr/local/sbin/` folder.

## Supernode


### I want to setup a supernode that only I can use. Perhaps even password protected?

Please think of the community-name as password and give the supernode just
that one community, either as a section of its config file:

```
[community mySecretCommunity]
```

or with the `supernode.community_file` option pointing at a simple text file
containing a single line with the name of your secret community. It will be
the only community allowed. Only edge nodes from that community can join
(`-c <community name>` at the edge).  See [Communities](configure/Communities.md).

If you additionally want to prevent open transmission of your secret community
name via the network, **all** edge nodes should use
`community.header_encryption=true` config option for header encryption.

Also, please see the `community.list` file coming with n3n for advanced use of that file.

Beyond this access barrier you may want to use payload encryption (with the
`community.cipher` option) at the edges. Only the edges – not the supernode –
are able to decipher the payload data. So, even if anyone would be able to
break the access barrier to the supernode, the payload remains protected by
the payload crypto, see [this document](internals/Crypto.md) for details.


### Can I get a list of connected edge nodes and their community and source IP address from the supernode?

How to get this information is described in [the management
API](internals/ManagementAPI.md) doc.

If enabled (by giving a `management.port` option), it can be simply seen with
any web browser:

eg.
- with `-Omanagement.port=5645`
- navigate to http://localhost:5645

### Is there support for multiple supernodes?

Yes, there is. Please [read](configure/Federation.md) about how several
supernodes can form a Federation to increase network resilience.


### Can a supernode listen on multiple ports?

Yes: `connection.bind` takes several addresses, separated by spaces, for
example `bind = [::]:7654 [::]:443`.  The supernode answers edges on each of
them alike, on UDP and TCP.  A second port also lets the edges see how their
NAT maps them, see [NAT Traversal](advanced/NatTraversal.md).


### Can the machine of the supernode be part of the network too?

Yes, without a separate edge: with `supernode.tap = true` the supernode joins
`community.name` with a TAP device of its own, see [Setting up a Custom
Supernode](configure/Supernode.md#a-supernode-that-is-an-edge-too).


### How to handle the error message "process_udp dropped a packet with seemingly encrypted header for which no matching community which uses encrypted headers was found"?

This error message means that the supernode is not able to identify a packet as unencrypted. It does check for a sane packet format. If it fails the header is assumed encrypted (thus, "_seemingly_ encrypted header") and the supernode tries all communities that would make a key (some have already been ruled out as they definitely are unenecrypted). If no matching community is found, the error occurs.

If all edges use the same `community.header_encryption` setting (all edges
either with it or without it) and restarting the supernode does not help, most
probably one of the components (an edge or the supernode) is outdated, i.e.
uses a different packet format – from time to time, a lot of changes happen to
the packet format in a very short period of time, especially in branches or
main for unreleased versions.

So, please make sure that all edges **and** the supernode have the exact same
built version.


## Edge


### How can I know if peer-to-peer connection has successfully been established?

How to get this information is described in [the management
API](internals/ManagementAPI.md) doc.

`n3nctl edges`

Since the `n3nctl` tool needs python, it may not always be possible to use.
It is also possible to use a suitable `curl` command with the `--unix-socket`
option.

Alternatively, the edge can be started with a `management.port` config option
to specify a TCP port, and any web browser can be used to inspect the status.
(from localhost only)


### UDP is blocked where I am. Can the edge still connect?

Yes, if the supernode is reachable over TCP, and without changing anything:
when no supernode answers over UDP, for a round over all of them (twice
with one supernode), the edge connects to them over TCP instead
(`connection.tcp_fallback`, on by default).  Over TCP all its traffic goes
through the supernode, as peer-to-peer connections need UDP.  Every three
`connection.register_interval`s (a minute by default) it sends a UDP ping
to its supernode, and goes back to UDP as soon as one gets an answer - after
leaving the airport, say.  `n3nctl get_info` shows the transport in use
(`transport`: `udp` or `tcp`), and the log says when it changes.  With the
default settings the switch to TCP takes about half a minute.

To use TCP from the start, set `connection.connect_tcp = true`, or give all
supernodes with `tcp://` in front; the edge then stays on TCP.  Every
supernode listens on TCP on the ports of its `connection.bind` (apart from
one built for Windows).  Port 443 gets through most firewalls that only let
web traffic out; a supernode can take TCP there and UDP on its usual port,
with `bind = udp://[::]:7654 tcp://[::]:443`, and its edges learn it from
two lines for that host:

```
[community]
supernode = sn.example.org:7654
supernode = tcp://sn.example.org:443
```

`n3nctl get_supernodes` shows each supernode's `transports` and
`tcp_sockaddr`.  The fallback does
not work with several packet threads (`daemon.threads`), which need UDP.


### Does n3n work together with n2n?

The protocol is that of n2n 3.x, so n3n edges and supernodes work together
with those of n2n 3.0 and later; n2n 2.x and older use other protocols.


### The edge repeatedly throws an "Authentication error. MAC or IP address already in use or not released yet by supernode" message. What is wrong?

The edge encountered n3n's protection against spoofing. It prevents that one
edge's identity, MAC and IP address, can be impersonated by some other while
the original one is still online, see some
[details](configure/Authentication.md). Mostly, there are two situations which
can trigger this:

If you use a MAC or IP address that already is in use, just change those parameters.

If the edge prematurely has ended in a non-regular way, i.e. by killing it using `kill -9 ...` or `kill -SIGKILL ...`, it did not have a chance to un-register with the supernode which still counts the edge for online. A re-registration with the same MAC or IP address will be unsuccessful then. After two minutes or so the supernode will have forgotten. A new registration with the same parameters will be possible then. So, either wait two minutes or chose different parameters to restart with.

And, as a matter of principal, always end an edge by either pressing `CTRL` + `C` or by sending SIGTERM or SIGINT by using `kill -SIGTERM ...` or `kill -SIGINT ...`! A plain `kill ...` without `-9` will do, too. And finally, a `stop` command to the management port peacefully ends the edge as well.
