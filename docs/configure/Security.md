<!--
SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright 2020 n2n contributors
SPDX-FileCopyrightText: Copyright Hamish Coleman
SPDX-FileCopyrightText: Copyright Honey Bunny QT
-->

# Security Considerations

When payload encryption is enabled (provide a key using `community.key`), the
supernode will not be able to decrypt the traffic exchanged between two edge
nodes but it will know that edge A is talking with edge B.

There are multiple encryption options to choose from. Please have a look at
[Crypto description](../internals/Crypto.md) for a quick comparison chart to
help make a choice.  Without a key, edges send the payload unencrypted; with
a key and no `community.cipher`, they use AES.  ChaCha20 and Speck are the
fastest on most machines, and the ones user/password authentication needs.

`n3n-edge help transform` lists the ciphers and compressions of a build,
with the implementation each one uses (OpenSSL, AES-NI, AVX2, NEON, plain
C, ...): which one depends on the CPU and options the build was made for.
A built-in benchmark of the encryption methods is available with the
`n3n-edge test benchmark` tool.

The header which contains some metadata like the virtual MAC address of the
edge nodes, their IP address, their real hostname and the community name
optionally can be encrypted applying the `community.header_encryption=true`
option to the edges.

Without header encryption, anyone on the path who knows the community name
can register at the supernode as a member of it.  With header encryption,
the community name works as a shared password; with
[user/password authentication](Authentication.md) each edge has its own,
and the supernode decides who gets in.

The supernode only takes the communities it is given, if it is given any -
see [Communities](Communities.md) - and otherwise any community name.

The management interface (see [Management API](../internals/ManagementAPI.md))
listens on a Unix domain socket, which only the user the daemon runs as and
root can use by default (`management.unix_sock_perms`).  Its password, for the
methods that change things like `stop`, defaults to `n3n`: change it with
`management.password`, and above all before opening a TCP port with
`management.port`.  While it is the default, the daemons say so in the log
when they start, and the management page shows a warning.  The names of
communities with header encryption - the keys of their headers - are shown
by the management page and the API only to requests with the password.

The daemons drop their privileges after setting up the TAP device and the
sockets, to the user n3n (or nobody) by default, see `daemon.userid` and
`daemon.groupid`.
