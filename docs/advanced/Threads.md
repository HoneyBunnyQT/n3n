SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright Honey Bunny QT

# Threads

By default, an edge handles every packet on one thread.  On a fast link, that
one thread can end up using a whole CPU core on encryption, decryption and
system calls while the other cores sit idle.  With the `daemon.threads` option
the edge handles packets on several threads at once.

This is worth it where there is a lot of traffic for one edge - for example an
edge in a well connected data centre used as the exit into the internet for
many other edges - or where a single core is slow, as on small ARM boards.  On
a typical desktop link, one thread is plenty.

## Requirements

- Linux
- a build with `./configure --enable-pthread`
- UDP to the supernode (not `connection.connect_tcp`)

If any of these is missing, the edge warns and uses one thread.

Threads are only supported by the edge so far, not by the supernode.

## Configuration

In the config file:

```
[daemon]
threads=4
```

or on the command line: `-Odaemon.threads=4`.  The value counts the main
thread too, so `threads=4` starts three more.  At most 16 are used.

A good starting point is the number of physical cores, minus one for
everything else the machine does.  More threads than cores do not help.

## How it works

The main thread keeps doing everything it did before: registering with the
supernode, finding and keeping track of the peers, and every control message.
The extra threads only handle `PACKET`s, the ones that carry ethernet frames.

Each thread has its own UDP socket, all bound to the same port with
`SO_REUSEPORT`.  The kernel hands all packets from one sender address to the
same socket, so the traffic from one peer always stays on one thread and in
order.

The tap device is opened with one queue per thread (`IFF_MULTI_QUEUE`).  The
kernel hands each flow of outgoing frames to one queue, and the thread reading
that queue encrypts the frames and sends them.  The frames a thread receives
are written into its own queue, and the kernel then hands the replies of that
flow to the same queue.

When a thread learns something that changes the edge's state - a new peer, a
peer that moved, a control message - it hands it over to the main thread,
which applies it.  Nothing is dropped on the way; if the main thread falls
behind, the threads wait for it.

## Things to be aware of

- The traffic from one peer is handled by one thread, so a single peer
  sending at full speed does not get faster.  Threads help when there are
  several peers.
- Everything relayed by a supernode comes from the supernode's address, and
  so lands on one thread.
- When a flow gets its first reply, the kernel moves it to the queue the
  reply came from.  A few of its frames still waiting in the old queue can be
  overtaken at that moment.  For TCP this happens during the handshake, when
  there is only one packet in flight.
- A busy edge may need bigger socket buffers
  (`sysctl net.core.rmem_default`), with or without threads.

## Measuring

The built-in benchmark runs every test in several threads at once and
reports the total:

```
n3n-edge test benchmark -Otest.benchmark_threads=4
```

Run it with 1, 2, 4 and so on up to the number of cores.  Where the total
stops growing is about the most threads worth using on that machine.  The
`pdu2tun` line comes closest to what the edge does for a received packet.
