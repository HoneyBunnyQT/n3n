<!--
SPDX-License-Identifier: GPL-2.0-only
SPDX-FileCopyrightText: Copyright Logan oos Even
SPDX-FileCopyrightText: Copyright Hamish Coleman
-->

# Management API

Both the edge and the supernode provide a JsonRPC management interface, and
a web page built from the same data.  A process has one management
interface, whatever runs in it: a supernode with its own edge
(`supernode.tap`) answers for both, see "Roles" below.

A Quick start example query:
```
curl --unix-socket /run/n3n/edge/mgmt http://x/v1 -d '{"jsonrpc": "2.0", "method": "get_edges", "id": 1}' |jq
```
or
```
n3nctl edges
```

The supernode listens the same way, at `/run/n3n/supernode/mgmt` for the
default session name: `n3nctl -s supernode edges`.  A TCP port is opened as
well with the `management.port` option.

In addition to the main JsonRPC interface, there are a small number of simple
HTTP pages.  These are not intended for complex data, being mainly for
human UI or interoperation with other systems.

Example fetching the list of HTTP pages:
```
curl --unix-socket /run/n3n/edge/mgmt http://x/help
```

## The web page

`http://localhost:5644/` (with `management.port = 5644`), or
`curl --unix-socket /run/n3n/edge/mgmt http://x/`, is one page for whatever
runs in the process: a section "Edge" and a section "Supernode", each where
it runs, and on top what belongs to the whole process - the log level, with
buttons for more and less, and a button to stop n3n.

- The daemon builds the page completely, so it reads in a text browser as
  well (`lynx http://localhost:5644/`), and with `curl`.  A small stylesheet
  (with a dark variant) and a few lines of script, which refresh the page
  every five seconds, come along for browsers that take them; nothing is
  loaded from elsewhere.
- Everything other peers say about themselves (descriptions, versions,
  community names) is shown as text.
- The buttons are plain forms, posted to `/page`; they ask for the management
  password (HTTP Basic, any user name).  A form or a request from another
  site, which browsers mark with an `Origin` header, is refused, here and
  for the JsonRPC calls.
- Names of communities with header encryption show as `***`: with header
  encryption, the name is the key of the headers.  On a supernode this
  also goes for communities whose kind is not known yet (no edge of them
  has registered).  The same goes for a supernode's federation name,
  which is the key of the federation.  The link *unlock* (`/unlock`) asks for the management
  password and shows them; the browser then sends the password along, so
  the page stays unlocked as it refreshes.  The JsonRPC methods do the
  same, see Authentication below.
- A table shows at most 250 rows; the JsonRPC methods have them all.
- Clients that speak HTTP/1.0, like lynx, get the connection closed after
  the reply.

## Roles

`/v1` is the JsonRPC interface of the process, as it always was: the
supernode of a supernode, the edge of an edge.  The roles can be asked for
by name as well:

- `/v1/edge`: the edge - also the edge of a supernode with `supernode.tap`,
  which has no interface of its own: its peers, its counters, `get_info`.
- `/v1/supernode`: the supernode.

Asking for a role that does not run in the process gets an error.
`n3nctl -r edge get_info` asks the edge.

## Listening sockets

When the daemon is started, it is either given a session name or uses the
default (simply "edge" for the edge and "supernode" for the supernode)

This session name is used to calculate the path to use for the Unix Domain
socket:

- `/run/n3n/$sessionname/mgmt`

This directory is created if is does not exist, and is created with the
same owner/group that the daemon will run as.  The administrator can adjust
permissions and group memberships as needed.

On exit, the daemon will attempt to remove its socket and session directory,
allowing this to be used as a simple way to see which session names are
running.

Note that since Windows does not support Unix Domain sockets, it listens on
TCP/5644 by default (and creates an empty session directory in
%USERPROFILE%\n3n)

## List the HTTP endpoints

Make a request to `/help` to get a list of the HTTP endpoints.

eg:
```
curl --unix-socket /run/n3n/edge/mgmt http://x/help
```

## List the JsonRPC Methods

Make a call to the "help" method and a list of all known methods will be
returned, along with a short description.

eg:
```
curl --unix-socket /run/n3n/edge/mgmt http://x/v1 -d '{"jsonrpc": "2.0", "method": "help", "id": 1}' |jq
```
or
```
n3nctl help
```

## The Methods

Every method answers a JsonRPC request; `n3nctl` passes any method on,
`n3nctl <method>`, and prints the answer as a table, or as JSON with
`--raw`.  It has short names for some: `edges`, `supernodes` and `mac`.
Those marked with a key need the password (see Authentication below):
`n3nctl -k <password> stop`.

| method | edge | supernode | what |
|--------|------|-----------|------|
| `help` | yes | yes | the methods, each with a short description |
| `help.events` | yes | yes | the event topics, see Events Stream |
| `get_info` | yes | yes | version, build date, `is_edge`/`is_supernode`, the edge's MAC and address, how its NAT maps it (`nat4`, `nat6`: `unknown`, `easy (port kept)`, `easy (port changed)`, `hard (ports 40100-40180)`, `several addresses`), `transport`, how it reaches its supernode now (`udp` or `tcp`, see `connection.tcp_fallback`; empty on a supernode), and `registered` (1 while the edge counts as registered at its supernode, also while a periodic re-registration is on its way; 0 on a supernode) |
| `get_edges` | yes | yes | the edge: its peers; the supernode: the edges registered at it, with community, address, MAC, `mode` (`p2p`, `pSp` or `sn`), `nat`, `sockaddr`, `other_sockaddr` (the supernode: an edge's address of the other family, where it registered one too, see Federation.md), `last_seen` |
| `get_supernodes` | yes | yes | the edge: its supernodes, `current` the one it is registered at, `selection` the criterion, `transports` (`udp`, `tcp` or `udp tcp`) and `tcp_sockaddr`, where it is reached over TCP, `load` (what it reported) and `rtt_us` (the round trip of its last answer to a PING, in microseconds, 0 for none yet), whatever `connection.supernode_selection` uses; the supernode: the other supernodes of the federation |
| `get_communities` | yes | yes | the edge: its community; the supernode: its communities with their address range of the auto ip service, the federation shown as `-/-` |
| `get_packetstats` | yes | yes | counters of received and sent packets by kind: `transop`, `p2p`, `super`, `super_broadcast`, `tuntap_error`, `multicast_drop`, and on a supernode `sn_fwd`, `sn_broadcast`, `sn_reg` (with `nak`), `sn_errors` |
| `get_timestamps` | yes | yes | when things last happened, as Unix times: `start_time`, `last_register_req`, `last_rx_p2p`, `last_rx_super`, `last_sn_fwd`, `last_sn_reg`, `last_sweep` |
| `get_mac` | yes | | the MAC addresses the edge has seen behind its peers (with routing and bridging) |
| `get_verbose` | yes | yes | the log level |
| `set_verbose` (key) | yes | yes | set the log level: `n3nctl -k n3n set_verbose 3` |
| `reload` (key) | yes | yes | read the configuration again and apply what can change while running: `{"loaded": true, "applied": [...], "restart": [...]}`, the options changed and those waiting for a restart, see [Configuration Files](../configure/ConfigurationFiles.md#reloading) |
| `reload_communities` (key) | | yes | read the community file again, see [Communities](../configure/Communities.md) |
| `stop` (key) | yes | yes | stop the daemon |
| `post.test` | yes | yes | send an event on the topic `test` |

The edge of a supernode with `supernode.tap` is asked at `/v1/edge` of the
supernode's interface (`n3nctl -r edge ...`); it also shows in the
supernode's `get_edges`, at `127.0.0.1:0`.

Each daemon also has metrics in the Prometheus text format at `/metrics`,
for example
```
curl --unix-socket /run/n3n/edge/mgmt http://x/metrics
```

## Events Stream

An event stream is available at the "/events/$topic" URL.  Making a request
to that endpoint will switch that connection to streaming JSON packets,
formatted as described in RFC7464.

Once a connection has been made, any events published on that topic will be
forwarded to the client.

Only one client can be subscribed to any given event topic, with newer
subscriptions replacing older ones.

The special topic "debug" will receive copies of all events published.
Note that this is for debugging of events!

A list of event topics is returned by the JsonRPC method "help.events"

## Authentication

Some API requests will make global changes to the running daemon and may
affect the availability of the n3n networking.  In this case, the daemon
will check for a standard HTTP Authorization header in the request.

The authentication is a simple password that the client must provide. It
defaults to 'n3n' and can be set with the config option
`management.password`.  Change it wherever other users of the machine, or
anyone who can reach `management.port`, should not stop the daemon.

The names of communities with header encryption are hidden from requests
without the password: `get_edges`, `get_communities` and `get_supernodes`
show `***` for them, and the edge's `get_communities` answers 403.  With
the password (`n3nctl -k <password> get_communities`) they show.

## Pagination

If the result of an API call will overrun the size of the internal buffer,
the response will indicate an "overflow" condition by returning a 507 result
and a JsonRPC error object.

When an overflow condition is returned, the error object may contain the
count of the number of items that could be added before the overflow occurred.
The request can be retried with pagination parameters to avoid the overflow.
(Note that this also opens up a window for the internal data to change during
the paginated request).

For performance and or implementation simplicity, the returned items may
include empty items in the returned result array (Generally with an empty
dictionaty) - these are included in counting, but should be ignored by the
requester.

Add the offset and limit values to the param dictionary.

The n3nctl tool has an example on how to use this implemented in its
JsonRPC.get() method
