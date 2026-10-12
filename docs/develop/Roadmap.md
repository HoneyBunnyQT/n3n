<!--
SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright Honey Bunny QT
-->

# Roadmap and Scratchpad

One place to see where n3n is going, what is being worked on, and the notes
and commands that go with it.  The TODO list deliberately reaches far into
the future: knowing the far goals helps to decide the small things now.

Keep it current: tick things off as they land (with the commit or branch),
move ideas from the Scratchpad into the TODO once they are decided, and
write down decisions with a line on why.

## Where we are going

Today n3n has two programs: the _edge_, which has a TAP device and joins a
community, and the _supernode_, which edges register with, which tells them
about each other and relays what they cannot send directly.

The aim is one program, the _peer_, whose roles are switched on by its
configuration:

| Role       | Today's equivalent | What it does                                        |
|------------|--------------------|-----------------------------------------------------|
| `tap`      | edge               | has a TAP (later also TUN) device                   |
| `client`   | edge               | registers with relays, finds peers, punches holes   |
| `relay`    | supernode          | lets clients register, tells them about each other, forwards |
| `federate` | supernode          | talks to other relays                               |

A peer on a public VM can then be a relay and have a TAP device at the same
time; a laptop behind NAT is `tap` + `client`.  Later the roles become
capabilities that peers announce, see "Far future".

The way there keeps the current protocol (v3) working at every step: first
the code of edge and supernode is merged, then both roles run in one
process, and only then does a new protocol come on top - with the relay role
still serving v3 edges.

## TODO

Status: `[ ]` open, `[~]` in progress, `[x]` done.

### Now: merge edge and supernode code (branch `peer`, protocol unchanged)

Each step is a commit (or a few) of its own and changes no behaviour; all
tests and `make lint` pass after each.

- [x] Format the C code as uncrustify 0.77.1 does, and check it so in CI
- [x] Step 1: one send layer, `src/sock.c`: picking the socket of
      connection.bind for a family or the calling thread, and sending from
      it.  (`get_local_auth()` and `handle_remote_auth()`, found in both
      files, are no duplicates but the two halves of the handshake - edge and
      supernode side; they move with their roles in step 7)
- [x] Step 2: the supernode runs on `mainloop.c` like the edge, instead of its
      own `select()` loop in `run_sn_loop()`.  The mainloop's tables grow
      (up to `FD_SETSIZE`), it accepts v3tcp connections, tells the upper
      layer which fd closed, and hands over every complete PDU in a TCP
      buffer.  Management connections of the supernode go through it too
- [x] Step 3: periodic work (registrations, purges, sorting, resolving)
      registered as ticks in the mainloop (`mainloop_register_tick()`), for
      both; `run_edge_loop()` and `run_sn_loop()` set up, register their
      ticks and call `mainloop_run()`
- [x] Step 4: role parts in `struct n3n_runtime_data` and `n2n_edge_conf_t`
      (`rt->client`, `rt->tap`, `rt->relay`, `conf.client` ...).  Embedded
      structs rather than pointers: the same order, no allocation and no
      NULL checks; a role that is off leaves its part zero.  The community
      settings of the config wait for the community table (step 5)
- [x] Step 5: one front end for received PDUs (`pdu_in`): length check,
      community lookup and header decryption, replay check, giving a
      `struct pdu_ctx`.  The edge's single community becomes a community
      table with one entry
  - [x] 5a: header decryption in one place (`pdu_header_decrypt()`)
  - [x] 5c: communities in the config, `[community NAME]` sections (see
        Scratchpad); `struct n3n_conf_community`, `conf.communities`
  - [x] 5b: `struct pdu_ctx` (`pdu_in.h`) for both roles, also what a
        packet thread hands to the main thread
  - [x] Later (2026-10-11): the steps before the dispatch in one place,
        `pdu_in_common()` (decode the common header, the static key check,
        the supernode lookup), with what differs between the roles as its
        arguments; the community check (edge) and the TTL (supernode) stay
        with the role.  The handlers read the `pdu_ctx` instead of copies
        of its fields in locals (c07b12b, 27128bb)
- [x] Step 6: dispatch through a table per message type with a handler per
      role instead of the two big `switch` statements: `edge_pdu_handlers`,
      `sn_pdu_handlers`, `pdu_dispatch()`
- [x] Step 7: split `edge_utils.c` / `sn_utils.c` by role and by concern,
      see docs/develop/SourceLayout.md: `role_client.c`, `punch.c`,
      `role_tap.c` for the edge, `role_relay.c`, `role_federate.c`,
      `sn_communities.c` for the supernode; `edge_utils.c` and
      `sn_utils.c` keep init, sockets, front end and loop of each
- [x] Step 8: one binary `n3n` (`apps/n3n.c`); `n3n-edge` and
      `n3n-supernode` are links to it (copies on Windows) that pick their
      roles from `argv[0]`, with unchanged options, help and config dumps;
      `n3n edge ...` and `n3n supernode ...` work too.  The binary holds both
      roles, so an edge-only package grows a little until
      `--disable-relay`
- [x] Step 9: relay and tap in one process, still v3: `supernode.tap`.
      The supernode's edge is a runtime of its own, without sockets, that
      talks to its supernode over the local link (`local_link.c`): the
      same PDUs, queued in the process, handed on by the mainloop.  netns
      scenarios `sn-tap`, `sn-tap-fed`, `sn-tap-userpw`.  Open:
  - [x] the management API of the supernode's edge: `/v1/edge` of the
        supernode's interface (`n3nctl -r edge`), and one web page with a
        section for each role, built by the daemon (`management_page.c`),
        readable in lynx
  - [ ] Windows (the TAP reader thread)
  - [~] the supernode's edge on packet threads: not planned for v3.  Its
        PACKETs stay on the main thread, which keeps the two roles'
        runtimes apart and the change small; it makes `supernode.tap` a
        convenience for the supernode's own light membership, not a
        heavily used edge (noted in configure/Supernode.md).  The full
        merge - one executable, one main code path, the same handling
        (packet threads included) for edge and supernode alike - is a v4
        goal, where the wire version opens up anyway
  - [x] after step 9: asked; we stay on v3 for now, with compatible work
        only (--disable-relay, tests, docs, the TCP fallback)
- [x] `./configure --disable-relay` for small builds that only need an edge;
      the `#ifdef` only where the roles are registered (c55ed77)

### Next

- [x] Communities configured the same way for both roles (see Scratchpad)
- [x] netns scenarios where a supernode fails over with user/password
      authentication, header encryption, TCP and `supernode.tap` (db91c09)
- [x] Automatic transport: UDP, TCP when no supernode answers over UDP,
      back to UDP once a probe gets through (`connection.tcp_fallback`,
      netns scenarios `tcp-fallback*`).  Open: with packet threads
- [x] `udp://` and `tcp://` in front of addresses of `connection.bind` and
      `community.supernode`: UDP and TCP on different ports (netns
      scenarios `tcp-port`, `tcp-only`).  Not planned for now: `udp4://`,
      `tcp6://` and the like, which would only matter for names to resolve.
      Supernodes the federation tells about (v3 tells their UDP address
      only) are tried over TCP at their UDP port; one that refuses there,
      or does not answer while others do, is reached over UDP only from
      then on (`sn_tcp_failed()`); over TCP the configured ones come first,
      the edge goes round them in turn and stays where it is registered
      (netns scenarios `tcp-learned`, `tcp-learned-refused`, 2026-10-11)
- [x] The page and get_supernodes show each supernode's load and round
      trip, and the selection strategy; a warning while the management
      password is the default.  Found on the way: the supernode's load
      never got across (0 from n3n supernodes, swapped from n2n ones) -
      fixed, also on `fixes`
- [x] systemd: Type=notify units (ready, status line, watchdog,
      stopping), without libsystemd and only when NOTIFY_SOCKET is set
- [x] IPv4 and IPv6: a peer stays at its address while it answers there,
      ranked LAN > IPv6 > IPv4; each address of a supernode is an entry of
      its own; the edge registers its address of the other family too, and
      the supernode tells each peer the address of a family both have
      (`N3N_REG_SUPER_OTHER_FAMILY`, v3 compatible); selection counts IPv4
      half again, the current supernode by round trip a quarter less.
      netns scenarios `dual-stack`, `hard-hard-v6`, `v6-v4only`, in
      User-Mode Linux (`tests/netns/uml.sh`), which runs the integration
      tests too; the page and get_edges show the other address
- [x] Network changes: the edge watches netlink (address, link, default
      route) and wake-up (CLOCK_BOOTTIME), and registers again at once,
      everywhere; a peer the supernode reports at another public address
      while it is quiet has moved; Android tells the edge through
      `n3n_edge_network_changed()`.  netns scenario `roam`: ~1s without a
      frame instead of ~10s.  Open: `dual-stack` fails in UML now and then
      (a few frames relayed when the measured flow starts, before this
      work too: 3 of 6)
- [x] Supernode outage and path MTU: netns scenarios `sn-outage`,
      `sn-outage-idle`, `sn-outage-restart`, `mtu-1280`, and (tagged
      `limits`, failing on purpose) `sn-outage-roam`,
      `sn-outage-restart-userpw`, `mtu-1280-nofrag`, `mtu-1280-df`.  Found and fixed: with all supernodes gone, the TCP
      fallback took the edge off UDP and so off its peers, for good (direct
      traffic stopped ~10s into the outage) - it now stays on UDP while a
      peer is heard directly; a peer idle for half its timeout was dropped
      and looked up through the supernode - kept at its address while the
      supernode misses a re-registration; start-up without an answering
      supernode took ~33s (each PING round waited the main loop's 10s)
- [x] Half-cold rejoin: an edge (re)started while no supernode answers
      lets frames pass once its device is open, so the peers that still
      know it get it back (`sn-outage-restart`, ~11s gap with the restart).
      Not with user/password authentication, where the supernode vouches
      first and gives out the header keys (`sn-outage-restart-userpw`,
      limits).  Left as is: a peer that moves during an outage stays out
      behind the other's NAT (inherent without a third party)
- [ ] Open from the MTU scenarios: on a 1280 byte path, frames that do not
      fit get fragmented (works) - lost where fragments are dropped, and
      refused with `connection.pmtu_discovery` ("Message too long", no
      ICMP back into the TAP).  Moved to v4 (see Decisions 2026-10-11 and
      [Path MTU](PathMtu.md)); in v3 a smaller `tuntap.mtu` is the way,
      see configure/TapConfiguration.md
- [x] Reload: SIGHUP (not in a terminal), `n3nctl reload` (method
      `reload`), `ExecReload` in the units (`RELOADING=1`/`READY=1`).
      `src/reload.c` loads the configuration as at the start, compares
      the dumps option by option with what runs, applies the live ones
      (supernodes, register interval, password, verbosity, a supernode's
      communities, ...) and reports the rest as waiting for a restart.
      netns scenario `reload`.  Since 2026-10-11 also the filter rules (in
      the dump now, a new filter swapped in; with packet threads at a
      restart), the edge of a supernode (`supernode.tap`) takes what of
      its own changes in the supernode's configuration (`sn-tap-reload`),
      and a new description reaches the peers at once
- [ ] Ideas to pick from (all v3 compatible): names for peers (DNS); IPv6
      on the TAP device from a prefix derived from the community; fewer
      privileges (CAP_NET_ADMIN only, Landlock); packages for the single
      binary; tools init / tools qr.  (Learned supernodes on disk wait for
      v4, see Decisions 2026-10-04; epoll, batched I/O, no alloc per
      packet and UDP GSO/GRO are done, below)
- [~] Releases of n3n BE (see [Releasing](Releasing.md)): the packages
      are `n3n-be` (.deb, .rpm, and a PKGBUILD for Arch), the user `n3n`
      from sysusers.d, the app's version that of the core and its release
      build signed from the environment; `release.yml`, started by hand,
      builds them all from a tag, with a draft GitHub Release if asked;
      `tests.yml` no longer reacts to releases.  Not run yet.  Open: the
      app's ID (`dev.n3n.android` is upstream's domain), the signing key,
      the channels (apt repository, AUR, COPR, Obtainium / IzzyOnDroid),
      OpenWrt, Windows and macOS in the release
- [x] TUN mode (layer 3 device): `tuntap.type = tun`, `src/tun.c`, netns
      scenarios `tun-tap` and `tun-tun`.  Open: IPv6 unicast out (neighbour
      discovery), other systems than Linux; see [Mobile and TUN](MobileAndTun.md)
- [ ] Android app (`VpnService`, configuration by QR code), see
      [Mobile and TUN](MobileAndTun.md).  Done: `android/` next to the
      core, built from `src/` by the NDK, CI artifact; import a file or a
      QR code (`tools/n3n-qr`), connect, log, state view, network
      changes.  Open: auto addresses, IPv6.  The revamp (asked
      2026-10-11), done: the state in one place, the service, which asks
      the edge; the notification follows it (it said "connected" before
      the edge was registered), with a Disconnect action and a small
      icon of its own; the connect button holds the state and what it is
      doing, looks raised, and has an LED (dark, running yellow stripes,
      lit green) so that the state does not hang on colour, which a black
      and white night mode does not show; an adaptive launcher icon with
      a monochrome layer; icons on the tiles.  Open: try it on a phone;
      the QR code again, with a fuzz target for `qr_seal` and the
      configuration it opens (postponed, 2026-10-11, see Decisions); maybe a
      navigation bar instead of the four tiles, should the app get more
      screens (several networks, peers)
- [x] `n3n-edge help transform`: lists the ciphers and compressions built
      in, with the implementation of each (`*_IMPL` in `src/crypto/*.h`,
      `desc` of the transforms); also on `fixes`
- [x] `-O` on the command line for a section with a name: `-O "community
      home.key=x"` or `-O community.home.key=x`, the option after the last
      dot, so that a community's name may have dots
      (`n3n_config_set_arg()`); over the file's section of that name, or
      one of the command line only - for simple setups no community file
      and no configuration file (configure/Communities.md).  On the way:
      `-O` and `-a` cut up the command line, which a reload parses again,
      so a reload lost what they set; and an edge whose community is a
      named section dropped a `-k` / `N3N_KEY` key without a word, now it
      stops.  netns scenario `userpw-cli`
- [x] Unit tests for the parts that become shared: the send layer's
      batches and `udp_drain()` (`tests-sock`); `pdu_in` (`tests-pdu-in`),
      the plain header check, the decryption with the dynamic and the
      static keys, what `pdu_in_common()` drops, and the dispatch
- [x] Integration test: a supernode with a TAP device next to plain edges:
      the netns scenarios `sn-tap`, `sn-tap-fed`, `sn-tap-userpw`,
      `sn-tap-failover`, `sn-tap-reload` and `cross-ARCH-sn-tap`
- [x] Run the netns NAT scenarios in CI: all of them on every push
      (`netns.yml`), plain build
- [x] Flaky netns scenarios (see Scratchpad): the hard-range NAT never
      shows both supernodes one port; edges behind hard NATs on both
      sides that get through directly pass (`PASS+`); `/run/n3n` made
      before the daemons for 3.4.6; what is left gets `--retry 1` in CI
      and shows as `FLAKY`.  Open: `dual-stack`, `sn-tap-userpw` (ASan)
- [~] Fuzzing: libFuzzer targets for header decryption, the PDU
      decoders and the transforms (`tests/fuzz`), which found the
      receive-path bugs of 3.4.7 (GHSA); their inputs in the regression
      corpus, replayed by `make test` and under the sanitizers, libFuzzer
      in CI on every push (`fuzz.yml`).  The handlers with their state:
      `fuzz-spray`, mutated PDUs at running daemons over UDP and TCP, in
      the netns scenarios tagged `spray`, which found a supernode's NAK
      encoded with a token from the stack (a crash; upstream since 3.4.6)
      and a negative shift in `bitlen2mask()`.  The TCP framing: `fuzz-tcp`.
      The management interface: `fuzz-mgmt`, which found an out-of-bounds
      read and several NULL dereferences on malformed local requests (all
      local only), and a base64 decode bug.  The TUN edge's Ethernet and
      ARP: `fuzz-tun` (nothing found).  Postponed: `qr_seal` with the
      configuration it opens (see Decisions 2026-10-11)
- [x] Interop: netns scenarios with edges and supernodes of the last
      release of upstream n3n (3.4.6) next to this tree: old edge, old
      supernodes (also with port guessing), a mixed federation, relayed,
      encrypted headers, user/password - all pass (in UML; 3.4.6 needs
      IPv6 in the kernel).  `tests/netns/versions.sh`, `interop.yml`.
      And n2n 3.1.1 (IPv4 only): its edge, its supernodes, a mixed
      federation, relayed, encrypted headers - all pass; the harness gives
      n2n its command line and reads its UDP management interface.  Found:
      n2n 3.1.1's `-F` leaves the federation's header key at the default
      name's (its `N2N_FEDERATION` does not)
- [x] Peers without a description on the edge's page: who a peer is comes
      only with its REGISTER, not with the ACK to ours; a peer lost and
      found again (idle, moved, restarted) came back by the ACK alone, and
      a moved one twice (one entry by its old address).  Now the edge keeps
      what REGISTERs told by MAC, answers a REGISTER from a peer it knows
      with one of its own, and keeps one entry per MAC.  netns checks
      `description:` and `description after:`.  And one that comes back
      relayed - as when the edge went on TCP - takes what the REGISTERs
      told too (2026-10-11, found by `tcp-learned`)  The federation's name (its
      key) shows on the management page only when unlocked
- [x] The supernode's own edge (`supernode.tap`) showed without its name
      and address on the other edges: an edge without p2p sent no
      REGISTER at all, not even the one through the supernode that tells
      who it is (c5b7346; upstream has it too, for any edge with
      `allow_p2p=false` - a candidate for `fixes`, but its code is in
      `edge_utils.c` there, so not a cherry-pick); and peers got its
      local link, 127.0.0.1:0, as its address (30b7b26).  The netns
      description check takes relayed peers now
- [x] ASan/UBSan in CI on every push (`sanitizers.yml`): unit, builtin,
      integration and netns tests, findings fatal.  Found and fixed:
      unaligned loads and stores (Speck SIMD, header encryption, memxor,
      connslot, ...), signed shifts (Twofish, bitlen2mask, wire), the
      PEER_INFO uptime decoded into half a time_t, the benchmarks'
      contexts not zeroed, a reload's configuration not freed and the
      metrics left with the freed session name
- [x] TSan in CI (`sanitizers.yml`, job `tsan`): unit and builtin tests,
      the quick netns scenarios and the `*-threads` ones (packet threads,
      and the resolver thread of every daemon).  Nothing found so far
- [x] Big endian, 32 bit and strict alignment: unit and builtin tests under
      qemu for s390x, mips and aarch64 in CI (`scripts/test_qemu.sh`).
      Found and fixed: Speck (also header encryption) and ChaCha20 broken
      on big endian, unaligned loads in AES, Pearson, the tap path, the
      benchmarks' key length on 32 bit, libatomic for 64 bit atomics
- [ ] Endianness of the hand written SIMD versions (NEON on big endian ARM
      is rare); `src/crypto/speck.c`, which was not built at all, is
      gone
- [x] netns scenarios between byte orders: an edge and a supernode of
      this tree built for s390x, mips or arm64 (with the ARMv8 AES
      instructions and NEON), under qemu-user, next to the host's - each
      cipher, relayed, encrypted headers, user/password, TCP, TUN,
      `supernode.tap` (`versions.sh cross`, tag `cross`, `netns.yml` job
      `cross`).  Found and fixed: federated supernodes of different byte
      order made other dynamic keys of a user/password community from the
      same key time (`calculate_dynamic_key()` hashed it in the host's
      order), so the edges of the one could not read what came from the
      other (b00db25); also an upstream bug
- [x] ARM: AES with the ARMv8 Cryptography Extension (`aes_armce.c`),
      ChaCha20 with NEON (`cc20_neon.c`), known answer tests for both
      (`tests-aes`, `tests-cc20`), CI under qemu for both
- [ ] ARM: benchmark on real boards (Pi 3/4 without AES instructions, Pi 5
      with): `n3n-edge test benchmark`, with and without the flags; decide
      whether Speck NEON can be on by default on newer cores
- [ ] Runtime selection of the implementations (Hamish is working on it):
      then distribution builds get the ARMv8 AES too, without the flag
- [x] epoll in the mainloop instead of `select()` on Linux (`mainloop.c`),
      which lifts the limit of FD_SETSIZE (1024) on its fds - a
      supernode's TCP connections - to what the process may open; other
      systems keep `select()`.  The supernode raises its soft limit of
      open files to the hard one, which systemd leaves at 1024 for
      programs that use `select()`; netns scenario `sn-tcp-1100` (1100
      connections, all taken; 1001 without the raise)
- [x] Batched I/O: `recvmmsg()` / `sendmmsg()` on Linux (`sock.c`,
      `udp_drain()`, `sock_batch_begin()`), the edge's sends of a tap batch
      and all receives on the sockets of `connection.bind`: up to a third
      more throughput, a third less CPU per packet for small packets
      (4102317).  Not batched: what a supernode forwards (no difference
      measured).
- [x] UDP GSO and GRO on Linux (`sock.c`): a batch's runs of datagrams
      for one destination, of one size, go to the kernel as one send
      (`UDP_SEGMENT`), and the sockets of `connection.bind` take joined
      datagrams (`UDP_GRO`) and cut them apart; the datagrams on the wire
      are the same.  Asked of each socket before it is used; a run the
      kernel refuses (too big for the path, a device without checksum
      offload) goes datagram by datagram.  `bench.py` (2026-10-12, in a
      VM with 4 cores): TCP direct 1.11 -> 1.32 Gbit/s with AES in plain
      C, 2.06 -> 4.39 Gbit/s with AES-NI; relayed with AES-NI 2.22 ->
      2.80 Gbit/s; at a fixed rate the CPU per packet direct -50 % (64
      byte frames) and -17 % (1200 byte).  The lab overstates the sending
      side (see testing.md, "Reading the numbers").  Open: what a
      supernode forwards, still one by one, with GSO too
- [x] No `alloc()` on the packet path: so already (the pktbuf pool, the tap
      batch once per thread); counted with a malloc wrapper, 9x the frames
      add at most two allocations over a daemon's life
- [x] A benchmark of the whole packet path: `tests/netns/bench.py`, iperf3
      through the tunnel with the CPU per packet of each daemon, see
      testing.md
- [ ] IPv6 address on the TAP device, from the config or assigned by the relay
- [ ] Supernode lookup by DNS SRV (`resolve.c` TODO): moved to v4, see
      Decisions

### Later: the peer protocol (v4)

Where v3 compatibility ends: everything above keeps the v3 wire format, so
`peer` stays able to talk to today's edges and supernodes, and to n2n 3.x.
The first item below that changes what goes over the wire - peer identities
in REGISTER, the handshake, signed records - starts the branch `peer-v4`
off `peer`.  From there, v3 lives on in the relay role (the v3 bridge),
while `peer` keeps getting what does not touch the wire, merged into
`peer-v4` from time to time.

- [ ] Peer identity: a Curve25519 key per peer, node ID = hash of the
      public key (`auth.c` has the curve already)
- [ ] Who a peer is (name, address, description) in its signed record,
      sent with every answer that makes it known - not only with one of
      the messages, as v3's REGISTER, where an edge that knows a peer by
      the ACK alone has to remember it on the side (`peer_who` in
      `role_client.c`, a workaround: the description came late to n2n,
      in REGISTER only).  A negative example to keep in mind
- [ ] Encryption between each pair of peers: X25519 handshake, then
      ChaCha20-Poly1305 or AES-GCM, replay window per peer, rekeying.  A
      prerequisite for letting any peer relay
- [ ] Membership: peer certificates signed by the community, revocation,
      groups usable in the traffic filter
- [ ] Signed peer records: addresses with scope (host / site / global), NAT
      type, capabilities, home relays, network coordinate
- [ ] Capabilities instead of fixed roles: `tap`, `relay`, `directory`
- [ ] Directory behind an interface (`publish`, `lookup`, `subscribe`);
      first full replication by gossip among `directory` peers (the
      federation, generalised)
- [ ] Path manager: candidates direct / same host / same site / hole
      punched / via relay / via two relays, probed continuously, cost from
      RTT, loss and load, switching while running.  Keep in mind that the
      direct path can be the lossy one: a real case had an edge's own
      ISP spread traffic across two peering legs (ECMP), one dropping
      packets, so the direct p2p path lost 20-30% while the relay through
      the supernode's datacentre was clean - plain ping to the peer's real
      address lost too, so not n3n's doing.  v3 picks a direct path and
      keeps it however bad it gets; v4 should measure per-path loss and
      be willing to fall back to a clean relay even when a direct path
      exists, and prefer another family/transport when one underlay leg
      is bad
- [ ] Transports as first-class citizens: every way a peer can be reached
      (UDP, TCP, later others) is announced in its record with the same
      standing, and any peer may use any of them towards any other - edges
      and relays alike.  Choosing among them is the path manager's job,
      preferring UDP; TCP and the rest are what it falls back on, not
      something only edges get.  (v3 today: TCP only from edge to
      supernode, the federation over UDP, and the federation's supernode
      list carries no transport - its entry has a spare byte for it.)
- [ ] Two layers: connections, and what goes over them.  A connection
      (a UDP path, a TCP connection, later others) to a relay or a peer is
      opened, kept and measured on its own, without being a registration:
      a peer may hold a few to relays it is not registered with - warm, so
      that moving to one is a hot swap, not a new start through all the
      steps - and registering, the community's traffic, the frames, go over
      whichever connection the path manager picks.  How many to hold open
      is a question of its own: each costs keep-alives and, at a relay,
      state; perhaps one or two warm ones, the rest opened on demand.  In
      v3 these are one thing: the edge's TCP connection is its
      registration, and a supernode the federation tells about has to be
      tried by registering with it (see `sn_tcp_failed()`, 2026-10-11)
- [ ] A peer store behind an interface, not files spread around: the
      relays and peers a peer has learned, with their addresses and keys,
      kept across restarts.  From it, a peer that finds no relay tries the
      peers it knew directly, to get back to them without any relay - only
      with authenticated, replay protected packets (in v3 terms: header
      encryption), as anything replayed from an old address must not get in.
      Decided 2026-10-02: not in v3, no local files for it there
- [ ] Learned relays survive: keep the relays a peer has learned (with
      all their transports) on disk, so that a laptop woken up behind a
      network that blocks its usual relay - an airport abroad - still knows
      others to try; records age, but are not purged just for being old.
      Until relays announce their TCP addresses, a guess for a learned one
      is the TCP port the configured ones use
- [ ] Vivaldi network coordinates to estimate RTTs without probing
- [ ] Nested NAT (VM in a laptop in a home network): scopes plus a "parent
      relay" chosen like any other relay
- [ ] Broadcast without a central node: answer ARP from the directory
      (proxy ARP) or a tree among relays
- [ ] v3 bridge: the relay role keeps serving v3 edges
- [ ] Path MTU, from v3's `mtu-1280*` scenarios (see [Path MTU](PathMtu.md)):
      the same packet the same size on any path - direct or relayed, IPv4
      or IPv6, so that a path that changes under a flow (a flip between
      the families, a move to a relay) does not change what fits - or
      else explicit packets for finding the MTU of a path, which v4 can
      have.  Then ICMP "fragmentation needed" / "packet too big" into the
      TAP and TCP MSS clamping per peer on what is known
- [ ] Communities handled the same for every role: one way to give them
      (sections, a file, or what replaces both), the same for a peer
      with a TAP device as for a relay, instead of v3's edge with one
      community from the configuration and supernode with sections and a
      community file (see Decisions 2026-10-12)
- [ ] Relay lookup by DNS SRV (from v3's `resolve.c` TODO; waits for
      v4, see Decisions 2026-10-11)
- [ ] Signed configurations: a QR code (or file) signed by who may hand
      out the community's configuration, checked before it is taken

### Far future

- [ ] TUN / L3 mode, `utun` on macOS (the tap kext is gone there)
- [ ] Kademlia directory for large networks, preferring low-RTT nodes in the
      buckets; NATed peers only as clients of the directory
- [ ] Android (VpnService) and iOS (NetworkExtension) on a stable libn3n API
- [ ] Peer names in DNS (`laptop.mycommunity`), answered by the peer itself
- [ ] Prometheus endpoint for the metrics
- [ ] Relay quotas, rate limits against floods of registrations
- [ ] Windows on par with Linux

## Decisions

- 2026-10-01: The C code is formatted by uncrustify 0.77.1, built from source
  in CI.  0.78.1 (Ubuntu 24.04) gives the same result today.
- 2026-10-01: The peer work happens on the branch `peer`, branched off
  `main`.  It does not wait for upstream (n42n/n3n).
- 2026-10-01: Tables of peers, communities, connections etc. use the uthash
  structures and macros (`HASH_ADD`, `HASH_FIND`, `HASH_ITER`, ...) as the
  rest of the code does, wherever they fit: their loops read more easily
  than hand-written ones.
- 2026-10-01: Fixes found along the way are commits of their own, with
  messages that stand alone, so that they can be taken upstream; the
  branch `fixes` collects them on top of `main`.
- 2026-10-01: The PDU length checks of the branch pdu-len-check are on
  `fixes` (and `peer`), ported onto the current code; the other old side
  branches (chachacha, drain, phase-a, speck-avx512, trace-level-check,
  twofish) are in main already, apart from the AES burst benchmark of
  `drain`, which is on `fixes` too.
- 2026-10-01: The wire format stays v3 until the peer protocol; it gets
  the branch `peer-v4` off `peer` (see "Later: the peer protocol").
- 2026-10-01: Roles are chosen at run time; leaving the relay code out of a
  build is an option for later, decided in one place.
- 2026-10-04: `fixes` takes real bugs that upstream has too - no features,
  nothing of the fork's own.  Porting them onto upstream's code is no
  effort we spend for now: upstream can cherry-pick, or we do it later.
- 2026-10-04: PRs for upstream: one topic each, the project's conventions
  as they are (a .gitignore per directory, comments as in the sibling
  files, explicit names over wildcards), and a look at the existing
  issues and PRs on a topic first.  The fork keeps purging peer tables of
  any size (upstream keeps tables of fewer than 16 on purpose, #142).

- 2026-10-04: Nothing of the edge's learned state goes to disk in v3.
  Learned supernodes on disk come with v4 (peer store, "Learned relays
  survive"), the file encrypted with the community's data key - which
  some setups may hold elsewhere, e.g. on a smart card, not in the config.
  Performance work (epoll, batched I/O, no alloc per packet) from
  2026-10-11 on.
- 2026-10-11: Fuzzing `qr_seal` and the configuration a QR code opens is
  postponed: the code's text is read in as a configuration typed in
  would be, so a malicious code is a malicious configuration, which no
  fuzzing makes harmless.  Codes signed by who may hand out the
  community's configuration are an idea for v4 (with peer identities).
- 2026-10-11: The path MTU waits for v4.  In v3 the size of a frame on the
  wire depends on the path (relayed PACKETs carry the sender's address, 8
  or 20 bytes; IPv6 has 20 bytes more of header than IPv4), and paths
  change under a flow - IPv4 and IPv6 flip, peers move to a relay and
  back - so a per-peer MTU learned in-band would chase a moving target,
  and the questions of the draft (PathMtu.md) have no good answer within
  v3's wire format.  v4 is to keep the same packet the same size on any
  path, or have explicit packets for finding the MTU.  Until then: a
  smaller `tuntap.mtu` where a path is small.
- 2026-10-11: Supernode lookup by DNS SRV waits for v4: in v3, and with
  header encryption above all, a community can live from not showing its
  supernodes' ports as n3n's, which `_n3n._udp` records would give away.
- 2026-10-12: The edge does not read the community file in v3: for a
  simple setup `-O "community NAME.option=value"` makes a file needless,
  and a peer whose roles share one configuration is v4's matter, with the
  rest of handling communities the same for all roles.
- 2026-10-10: Development goes on on `main`, which has all of `peer`;
  `peer` is not worked on any more and goes.  The fork's packages are
  named `n3n-be`.

## Scratchpad

Current ideas, half-decided things, commands worth keeping.

### Where things stand (2026-10-12)

Recently on `main` and done: epoll and batched I/O (`recvmmsg()` /
`sendmmsg()`), with `tests/netns/bench.py` for the whole packet path; the
packages of n3n BE and `release.yml` (not run yet); fuzzing of the receive
path, the TCP framing, the management interface and the TUN edge, plus
`fuzz-spray` at running daemons, which found and fixed several bugs (see
Fuzzing above); netns scenarios with builds for other CPUs under
qemu-user; the steps before the dispatch in one place for both roles
(`pdu_in_common()`); over TCP, the configured supernodes first and the
learned ones marked once they turn out to be UDP only; a reload that
compares and applies the filter rules and reaches the edge of a supernode
(`supernode.tap`).  Android: the revamp - the state in the service, the
notification following it, the connect button with its LED.  Postponed to
v4: the path MTU, DNS SRV, fuzzing the QR code (see Decisions).

Open, in rough order:

- IPv6 on the TAP device (to discuss first: addresses for the auto ip
  service); fewer privileges (Landlock, CAP_NET_ADMIN only is there);
  the supernode's forwards with GSO.
- Releases: the app's ID, the signing key, the channels - decisions to
  take, then the first run of `release.yml`.
- On real hardware: the Android app on a phone, the ARM benchmarks, the
  benchmarks for the parked upstream PRs.
- Keep in mind a real finding: the direct path between two edges can be
  the lossy one (an ISP spreading traffic over two peering legs, one
  dropping) while the relay is clean - see the v4 path-manager note above.

Picking up in a new session: read this file and `docs/develop/*.md`, build
with `./autogen.sh && ./configure && make`, and the tests are `make test`
(and `tests/netns/` for the NAT scenarios, `tests/netns/uml.sh` where
there is no IPv6).

### Parked: the fixes as PRs for upstream

Nine branches `pr/*` on honeybunnyqt/n3n, cut from n42n/n3n main, one per
topic of the `fixes` branch; each builds and passes its tests and
upstream's lint alone, and all nine merge into upstream main without
conflict.  Branch `pr-notes` has the PR texts, the state, and
`bench-prs.sh` for the before/after benchmarks the performance commits
need (on a real machine, with the CPU counters).  Then: benchmarks into
the commit messages, open the PRs one or two at a time.

### Communities for both roles

Today the edge has one community from `community.name`, `community.key`,
`community.cipher`, ... while the supernode reads `supernode.community_file`:
one name or regular expression per line, optionally with a network, plus
`*` lines with user names and public keys.

Decided (2026-10-01): a config section per community, and the community file
stays for long lists.  The config can say all the file can, so that the
file becomes optional:

- The communities are the union of the sections and the file.
- A community in both: the section's options win, the file fills in what the
  section does not set (network, users); a line in the log says so.
- Regular expressions in both: a list of rules in the config as well as in
  the file.  They are no community of their own but say which names are
  welcome.
- A reload (SIGHUP) re-reads the file; the sections stay as they were
  started.
- A peer with only the `tap` role takes exactly one community: one section,
  or the first entry of the file; more is an error at start, not a silent
  choice.  (Several TAP devices, one per community, could come later.)
- The `community.*` options of today stay as the short form of a single
  section, so existing edge configs keep working.

Done (2026-10-01), see docs/configure/Communities.md:

```
[community home]                # "home" is the community's name ...
name = my home!                 # ... unless this says otherwise
network = 10.77.0.0/24          # supernode: the auto ip range
user = alice <public key>       # supernode: may repeat, no leading '*'
header_encryption = true

[supernode]
community_regex = net[0-9]+     # may repeat
```

- The parser keeps the word after the section name as the instance name;
  a section registered with `n3n_config_register_section_instanced()` gets
  its options relative to what its `instance()` callback returns.
  `[community]` is `conf.community`, `[community NAME]` an entry of the
  uthash table `conf.communities`.  `n3n_conf_strlist` is the option type
  for repeatable options.
- The supernode list stays one global list, whichever section adds to it.
- The edge does not read the community file (not in v3, see Decisions
  2026-10-12); its one community is `[community]` or the only
  `[community NAME]` (`edge_conf_one_community()`).  On the command line:
  `-O "community NAME.option=value"` (2026-10-12).
- netns scenario `userpw-conf` runs with sections on both sides.

### Old branches on honeybunnyqt/n3n

Gone: the pull requests at n42n/n3n from `chachacha` (#155), `crash` (#158),
`drain` (#157), `pdu-len-check` (#152), `speck-avx512` (#161),
`trace-level-check` (#153) and `twofish` (#154) are closed, with notes that
point to where their work is now (`main`, or `fixes` for the length checks
and the AES burst benchmark), and the branches deleted, as `phase-a` and
`phase-b` before them.  The fork has `main`, `fixes` and `peer`.

### Flaky netns scenarios (NAT work)

Looked into 2026-10-10, from all the red runs of `netns.yml`,
`sanitizers.yml` and `interop.yml` since they run on every push (11 of 56
runs, one scenario each), and reproduced with `-v 3` in a loop:

- Most of them (`no-punch`, `easy-hard-threads`, `hard-hard`,
  `hard-hard-threads`, `tun-tun` locally): an edge behind `hard-range`
  took its NAT for "easy (port changed)".  The guess from before was
  right: both supernodes saw the same port, which happens one time in 256
  with a random port per destination from 256 - and the edge, seeing just
  those two, rightly calls that easy.  With some 25 such edges in a full
  run, about every tenth run.  Fixed in the harness: the `hard-range`
  router takes the port towards each supernode from a slice of the block
  of its own (`nat.py`).
- Edges behind hard NATs on both sides that went direct (`userpw-relayed`,
  `failover-userpw`, `interop-relayed`, earlier `easy-wide`): n3n getting
  through after all.  An edge that knows its NAT is hard, while the
  peer's REGISTERs do not tell the peer's class yet (user/password makes
  that window longer) or never do (3.4.6), opens a pool of 32 sockets
  towards it, and now and then one meets the port the peer's NAT opened.
  Such a scenario now passes with a plus (`PASS+`, see netns_testing.md).
- `interop`: a 3.4.6 supernode died with "cannot mkdir /run/n3n" - its
  mkdir_p() checks first and then makes the directory, so of two daemons
  starting at once one may give up.  Fixed in n3n since 3.4.7 (7c5817b);
  the harness now makes `/run/n3n` before the daemons start.
- `userpw` (quick tests, 2026-10-10): both edges stayed "unknown" and
  relayed.  With user/password, the header key of a community changes
  with a key time, at first the second the supernode started in; two
  federated supernodes agree on the newer one.  But the supernode made
  the keys at start before it knew the federation's name, with a name of
  zeros, and the one that took the newer time made them again with the
  name: a key no edge had.  Its PINGs dropped, the edges heard one
  supernode only.  Locally both supernodes started in the same second
  and never made the keys again.  Fixed in n3n-supernode.c (also an
  upstream bug); `userpw` now starts its supernodes 1.1 s apart.  Maybe
  the `sn-tap-userpw` ASan case below as well.
- Not explained yet, the logs of CI were not at hand: `dual-stack` (2 moves
  of the peer, 1 allowed, the last from IPv4 to IPv6; once in 23 runs,
  and see "Network changes" above for UML) and `sn-tap-userpw` under
  ASan (the edge never registered; once in 16).
- `sn-tcp-1100` under ASan (2026-10-11, twice, on commits that changed
  only the Android app and the edge): "tcp burst: the connections did
  not get through" - the harness gave the 1100 connections 60s, and the
  client makes them one after the other, each with a timeout of 5s, so a
  supernode slowed down by ASan that leaves a dozen of them waiting runs
  out of time.  Fixed in the harness: the client tells how far it got
  every 50 connections, and the harness waits as long as it gets on (no
  further for 30s is a failure); and as long as the supernode takes
  more of them (it had 15s, and once took 513 by then).  But the cause
  was another: the supernode's listen backlog was 3, so with the client
  connecting one after the other and the supernode slowed down by ASan,
  the kernel dropped SYNs, the client waited for the retries, and the
  burst took over 200s - longer than the supernode's idle timeout of
  60s, which closed the first connections before the last came ("0
  taken").  Now the backlog is 128, and the client opens them 50 every
  quarter second, waited for together - all at once, they overran the
  accept queue, and those the kernel left half open came in only with
  its retries of the SYN-ACK, seconds apart.

What is left gets one more try in CI (`--retry 1`): a scenario that passes
then is `FLAKY`, which does not turn the run red but shows as an
annotation on the run's page and in its summary, with the logs of the
failed try uploaded.

Earlier, seen once each in a few full runs, passing on re-runs:
`roam-nowatch` (a few frames relayed as the burst starts) and
`sn-tap-failover` (the check ran before the failover settled), in a full
run with the outage scenarios (100s each) four at a time.

### ARM

- AES: `aes_armce.c` uses AESE/AESMC/AESD/AESIMC when the compiler may
  (`-march=armv8-a+crypto`, `-march=native` on a Pi 5); the key schedule
  uses AESE for SubWord, so there is no table.  CBC decryption and
  `aes_cbc_encrypt_multi()` run four blocks side by side
- ChaCha20: `cc20_neon.c`, on by default wherever NEON is (all aarch64):
  four blocks side by side on aarch64, two on 32 bit ARM.  NEON ChaCha20 is
  what Linux and OpenSSL use on arm64, but numbers from our boards are
  missing - if it turns out slower somewhere, it gets a switch like Speck's
- Speck: `speck_neon.c` stays opt-in (`-DSPECK_ARM_NEON`), as on the Pi 3B+
  it was slower than the scalar code; worth measuring again on newer cores
- Twofish: table lookups, little to gain from NEON
- Pearson hash (header encryption): 64 bit multiplies, scalar is fine

### Commands

Build and test:

```sh
./autogen.sh && ./configure --enable-pthread && make -j"$(nproc)"
make test.builtin test.units test.integration    # quick
sudo make test.netns                             # NAT scenarios, needs root
sudo tests/netns/run.py -q                       # all of them
sudo tests/netns/run.py -q --wrap 'valgrind --error-exitcode=99 --leak-check=full --errors-for-leak-kinds=definite' tcp-tcp hard-hard
make lint                                        # everything CI lints
scripts/test_qemu.sh qemu-mips -L /usr/mips-linux-gnu   # cross built tree, see testing.md
scripts/indent.sh -i src/edge_utils.c            # reformat one file
```

### Git, step by step

Where am I, what changed:

```sh
git status                      # branch, changed files
git log --oneline -10           # the last 10 commits
git log --oneline main..peer    # commits on peer that main does not have
git diff                        # changes not yet added
git diff --staged               # changes added for the next commit
```

Get the latest from GitHub and switch branches:

```sh
git fetch origin                # download, changes nothing locally
git switch peer                 # go to the branch peer
git pull                        # fetch + bring the current branch up to date
git switch -c new-idea          # new branch from where you are
git switch -c peer origin/main  # new branch "peer" from GitHub's main
```

Commit and push:

```sh
git add path/to/file            # or: git add -p   (pick the pieces)
git commit                      # opens the editor for the message
git push -u origin peer         # first push of a branch; later just: git push
```

Bring `main`'s new commits into `peer` (keeps history, safe on shared
branches):

```sh
git switch peer
git fetch origin
git merge origin/main           # on conflicts: edit the files, then
git add <file> && git commit    # ... to finish the merge
git merge --abort               # ... or to give up and go back
```

Undo things:

```sh
git restore file.c              # throw away uncommitted changes of a file
git restore --staged file.c     # un-add, keeps the changes
git commit --amend              # fix the last commit (only if not pushed!)
git revert <commit>             # new commit that undoes <commit> (safe)
git reset --hard origin/peer    # local branch = GitHub's (loses local work!)
git reflog                      # where HEAD has been: finds "lost" commits
```

Look at one commit or one file's history:

```sh
git show <commit>               # what a commit changed
git log -p -- src/mainloop.c    # every change to one file
git blame src/mainloop.c        # who changed which line last
```

Take a single commit from another branch:

```sh
git cherry-pick <commit>
```

Clean up branches:

```sh
git fetch --prune origin        # forget origin/... of branches deleted on GitHub
git branch -vv                  # local branches; "gone" = deleted on GitHub
git log --oneline BR --not main fixes peer   # what only BR has (empty: nothing)
git branch -d BR                # delete, refuses if BR has commits nowhere else
git branch -D BR                # delete anyway ("not fully merged")
git reflog | grep BR            # find it again; then: git branch BR <hash>
```
