SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright Honey Bunny QT

# Threads

By default, edges and supernodes handle every packet on one thread.  On a
fast link, that one thread can end up using a whole CPU core on encryption,
decryption and system calls while the other cores sit idle.  With the
`daemon.threads` option they handle packets on several threads at once.

This is worth it where there is a lot of traffic in one place - for example
an edge in a well connected data centre used as the exit into the internet
for many other edges, or a supernode that has to relay much of its
communities' traffic because the edges cannot reach each other directly - or
where a single core is slow, as on small ARM boards.  On a typical desktop
link, one thread is plenty.

## Requirements

- Linux
- a build with `./configure --enable-pthread`
- for an edge: UDP to the supernode (not `connection.connect_tcp`)

If any of these is missing, a warning is printed and one thread is used.

A supernode with an edge of its own (`supernode.tap`) can have threads too;
the PACKETs to and from its own edge are handled by the main thread.

## Configuration

The option is the same for edges and supernodes.  In the config file:

```
[daemon]
threads=4
```

or on the command line: `-Odaemon.threads=4`.  The value counts the main
thread too, so `threads=4` starts three more.  At most 16 are used.

`threads=0` picks the number itself: half the physical cores the process
may run on, rounded up - so 4 on an 8 core machine, 2 on a Raspberry Pi 4
and 1 on a VM with 2 vCPUs.  The other half is left for the kernel, which
does much of the work of every packet.  Where threads do not work, it
quietly uses one.

To choose the number yourself, a good starting point is the number of
physical cores, minus one for everything else the machine does.  More
threads than cores do not help.

## How it works

The main thread keeps doing everything it did before: registrations,
keeping track of peers and communities, the management interface, and every
control message.  The extra threads only handle `PACKET`s, the ones that
carry ethernet frames.  When a thread finds something that would change the
state - a new peer, a peer that moved, a control message - it hands it over
to the main thread, which applies it.  Nothing is dropped on the way; if the
main thread falls behind, the threads wait for it.

Each thread has its own UDP socket, all bound to the same port with
`SO_REUSEPORT`.  The kernel hands all packets from one sender address to the
same socket, so the traffic from one peer always stays on one thread and in
order.

### In an edge

The tap device is opened with one queue per thread (`IFF_MULTI_QUEUE`).  The
kernel hands each flow of outgoing frames to one queue, and the thread
reading that queue encrypts the frames and sends them.  The frames a thread
receives are written into its own queue, and the kernel then hands the
replies of that flow to the same queue.

### In a supernode

A thread relays a `PACKET` itself when it goes to a single edge that is
reachable over UDP, or to the federated supernode that edge is registered
with.  That is nearly all of the traffic of a busy supernode.  Everything
else - registrations, broadcasts, packets to edges connected over TCP - is
handed to the main thread, as it may change the supernode's state or has to
go out on a TCP connection.

## Things to be aware of

- The traffic from one peer is handled by one thread, so a single peer
  sending at full speed does not get faster.  Threads help when there are
  several peers.
- An edge receives everything relayed by a supernode from the supernode's
  address, so all of that lands on one of its threads.
- In an edge, when a flow gets its first reply, the kernel moves it to the
  queue the reply came from.  A few of its frames still waiting in the old
  queue can be overtaken at that moment.  For TCP this happens during the
  handshake, when there is only one packet in flight.
- A supernode relays packets to edges connected over TCP on its main thread
  only.
- A busy edge or supernode may need bigger socket buffers
  (`sysctl net.core.rmem_default`), with or without threads.

## Measuring

The built-in benchmark runs every test in several threads at once and
reports the total:

```
n3n-edge test benchmark -Otest.benchmark_threads=4
```

Run it with 1, 2, 4 and so on up to the number of cores.  Where the total
stops growing is about the most threads worth using on that machine.  The
cipher lines show what encryption and decryption cost; the `pdu2tun` line
comes closest to what an edge does for a received packet.
