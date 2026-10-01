SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright Honey Bunny QT

# Where the Code Lives

An n3n node has roles: an edge is a _client_ of the supernodes and has a
_tap_ device, a supernode _relays_ for the edges and is part of a
_federation_ of supernodes.  The code of the daemons is in `src/`, split by
role and by concern.

## The parts both roles share

| file | what |
|------|------|
| `mainloop.c` | the one `select()` loop: file descriptors, TCP connections, the management connections, ticks for the regular work |
| `sock.c` | the sockets of `connection.bind`, sending from the right one |
| `pdu_in.c` | the first steps with a received PDU: header decryption, `struct pdu_ctx`, the dispatch to the handler of its message type |
| `wire.c` | encoding and decoding the PDUs |
| `edge_threads.c` | the packet threads, and the queue to the main thread |
| `local_link.c` | the link between a supernode and its own edge (`supernode.tap`) in the same process: PDUs without sockets |
| `peer_info.c` | the tables of peers |
| `management.c` | the JSON-RPC management interface |
| `conffile.c`, `conffile_defs.c` | the configuration: file, environment, command line |

## The edge

| file | what |
|------|------|
| `edge_utils.c` | init and term, the sockets, the front end for received PDUs (`edge_process_pdu()`), the events of the peer tables, the ticks and the loop; `edge_start_local()` for the edge of a supernode |
| `role_client.c` | registering with the supernodes and the peers, the NAT classification, the handlers of the control messages (`edge_rx_register()` ...) |
| `punch.c` | hole punching through the NATs between two edges |
| `role_tap.c` | the TAP device, encoding and sending its frames, the handler of a PACKET (`edge_rx_packet()`) |

## The supernode

| file | what |
|------|------|
| `sn_utils.c` | init and term, the sockets and TCP connections, the front end for received PDUs (`process_pdu_body()`), the tick and the loop |
| `role_relay.c` | the PDUs of the edges: registering and authenticating them, passing their PACKETs on, the handlers `sn_rx_*()` of what edges send |
| `role_federate.c` | the other supernodes: registering with them, the handlers of their REGISTER_SUPER_ACK, _NAK and PEER_INFO |
| `sn_communities.c` | the table of communities: from the configuration and the community file, the keys of user/password authentication, the address ranges of the auto ip service |

Each of these has a header of the same name for what the others use of it.
The handlers of each role are listed in a table by message type,
`edge_pdu_handlers` in `edge_utils.c` and `sn_pdu_handlers` in `sn_utils.c`.
