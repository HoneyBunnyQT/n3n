SPDX-License-Identifier: GPL-2.0-only
SPDX-FileCopyrightText: Copyright Logan oos Even
SPDX-FileCopyrightText: Copyright Hamish Coleman

# Management API

Both the edge and the supernode provide a JsonRPC management interface.

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
| `get_info` | yes | yes | version, build date, `is_edge`/`is_supernode`, the edge's MAC and address, and how its NAT maps it (`nat4`, `nat6`: `unknown`, `easy (port kept)`, `easy (port changed)`, `hard (ports 40100-40180)`, `several addresses`) |
| `get_edges` | yes | yes | the edge: its peers; the supernode: the edges registered at it, with community, address, MAC, `mode` (`p2p`, `pSp` or `sn`), `nat`, `sockaddr`, `last_seen` |
| `get_supernodes` | yes | yes | the edge: its supernodes, `current` the one it is registered at, `selection` the criterion; the supernode: the other supernodes of the federation |
| `get_communities` | yes | yes | the edge: its community; the supernode: its communities with their address range of the auto ip service, the federation shown as `-/-` |
| `get_packetstats` | yes | yes | counters of received and sent packets by kind: `transop`, `p2p`, `super`, `super_broadcast`, `tuntap_error`, `multicast_drop`, and on a supernode `sn_fwd`, `sn_broadcast`, `sn_reg` (with `nak`), `sn_errors` |
| `get_timestamps` | yes | yes | when things last happened, as Unix times: `start_time`, `last_register_req`, `last_rx_p2p`, `last_rx_super`, `last_sn_fwd`, `last_sn_reg`, `last_sweep` |
| `get_mac` | yes | | the MAC addresses the edge has seen behind its peers (with routing and bridging) |
| `get_verbose` | yes | yes | the log level |
| `set_verbose` (key) | yes | yes | set the log level: `n3nctl -k n3n set_verbose 3` |
| `reload_communities` (key) | | yes | read the community file again, see [Communities](../configure/Communities.md) |
| `stop` (key) | yes | yes | stop the daemon |
| `post.test` | yes | yes | send an event on the topic `test` |

The edge of a supernode with `supernode.tap` has no management interface of
its own yet: it shows in the supernode's `get_edges`, at `127.0.0.1:0`.

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
