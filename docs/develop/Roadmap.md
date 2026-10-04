SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright Honey Bunny QT

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
  - [ ] Later: the steps before the dispatch (decode the common header,
        static key check, supernode lookup, TTL) are still one function per
        role, `process_pdu()` and `process_pdu_body()`; the handlers still
        copy the fields of the `pdu_ctx` into locals of the old names
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
  - [ ] the supernode's edge on packet threads; for now its PACKETs are
        handled by the main thread
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
      Open: supernodes the federation tells about are tried over TCP at
      their UDP port
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
- [ ] Ideas to pick from (all v3 compatible): react to network changes and
      wake-up (netlink, clock jumps); keep learned supernodes on disk;
      names for peers (DNS); IPv6 on the TAP device from a prefix derived
      from the community; reload on SIGHUP; interop tests against n2n 3.x
      and older n3n in the netns lab; epoll and batched I/O; no alloc per
      packet; fewer privileges (CAP_NET_ADMIN only, Landlock); packages for
      the single binary; tools init / tools qr
- [x] TUN mode (layer 3 device): `tuntap.type = tun`, `src/tun.c`, netns
      scenarios `tun-tap` and `tun-tun`.  Open: IPv6 unicast out (neighbour
      discovery), other systems than Linux; see [Mobile and TUN](MobileAndTun.md)
- [ ] Android app (`VpnService`, configuration by QR code), see
      [Mobile and TUN](MobileAndTun.md).  Done: `android/` next to the
      core, built from `src/` by the NDK, CI artifact; import a file or a
      QR code (`tools/n3n-qr`), connect, log.  Open: state view, auto addresses, network
      changes, IPv6
- [ ] `n3n-edge help transform`: list the ciphers and compressions built in,
      with the implementation of each (says "Not implemented" so far)
- [ ] `-O` on the command line for an instance (`-O "community home.key=x"`)
- [ ] The edge reading the community file (the first entry), for a peer
      whose roles share one config
- [ ] Unit tests for the parts that become shared (send layer, `pdu_in`)
- [ ] Integration test: a supernode with a TAP device next to plain edges
- [ ] Run the netns NAT scenarios in CI (`make test.netns`)
- [ ] Fuzzing of the PDU decoders (`wire.c`) and of header decryption
- [ ] ASan/UBSan builds in CI, TSan for the threads
- [x] Big endian, 32 bit and strict alignment: unit and builtin tests under
      qemu for s390x, mips and aarch64 in CI (`scripts/test_qemu.sh`).
      Found and fixed: Speck (also header encryption) and ChaCha20 broken
      on big endian, unaligned loads in AES, Pearson, the tap path, the
      benchmarks' key length on 32 bit, libatomic for 64 bit atomics
- [ ] Endianness of the hand written SIMD versions (NEON on big endian ARM
      is rare) and of `src/crypto/speck.c`, which is not built at all -
      remove it?
- [ ] Run a netns scenario between a big endian and a little endian edge
      (qemu-user binaries in one namespace)
- [x] ARM: AES with the ARMv8 Cryptography Extension (`aes_armce.c`),
      ChaCha20 with NEON (`cc20_neon.c`), known answer tests for both
      (`tests-aes`, `tests-cc20`), CI under qemu for both
- [ ] ARM: benchmark on real boards (Pi 3/4 without AES instructions, Pi 5
      with): `n3n-edge test benchmark`, with and without the flags; decide
      whether Speck NEON can be on by default on newer cores
- [ ] Runtime selection of the implementations (Hamish is working on it):
      then distribution builds get the ARMv8 AES too, without the flag
- [ ] epoll in the mainloop instead of `select()` (`mainloop.c` TODO), lifts
      the limit on TCP connections
- [ ] Batched I/O: `recvmmsg()` / `sendmmsg()`, later UDP GSO/GRO
- [ ] No `alloc()` on the packet path (`edge_utils.c`, TODO in the send path)
- [ ] IPv6 address on the TAP device, from the config or assigned by the relay
- [ ] Supernode lookup by DNS SRV (`resolve.c` TODO)

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
      RTT, loss and load, switching while running
- [ ] Transports as first-class citizens: every way a peer can be reached
      (UDP, TCP, later others) is announced in its record with the same
      standing, and any peer may use any of them towards any other - edges
      and relays alike.  Choosing among them is the path manager's job,
      preferring UDP; TCP and the rest are what it falls back on, not
      something only edges get.  (v3 today: TCP only from edge to
      supernode, the federation over UDP, and the federation's supernode
      list carries no transport - its entry has a spare byte for it.)
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

## Scratchpad

Current ideas, half-decided things, commands worth keeping.

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
- The edge does not read the community file (yet); its one community is
  `[community]` or the only `[community NAME]`
  (`edge_conf_one_community()`).
- netns scenario `userpw-conf` runs with sections on both sides.

### Old branches on honeybunnyqt/n3n

Gone: the pull requests at n42n/n3n from `chachacha` (#155), `crash` (#158),
`drain` (#157), `pdu-len-check` (#152), `speck-avx512` (#161),
`trace-level-check` (#153) and `twofish` (#154) are closed, with notes that
point to where their work is now (`main`, or `fixes` for the length checks
and the AES burst benchmark), and the branches deleted, as `phase-a` and
`phase-b` before them.  The fork has `main`, `fixes` and `peer`.

### Flaky netns scenarios (NAT work)

Was about one or two per full run with four scenarios at a time, more than a
chance of 1 in 256 explains; worth a closer look (TODO).  Not seen in three
full runs in a row (34 of 34 each) after the failover work.
Then once each in a full run with the TCP fallback: `easy-wide` and
`userpw-relayed` (hard-range / hard-range) went direct; both passed three
re-runs.

Seen once each in a few full runs, passing on re-runs:

- `no-punch` went direct although port guessing is off on the easy side: the
  hard side's own REGISTERs may get through the easy NAT
- `easy-hard-pool`, `hard-hard-threads`, `failover-relayed`, `hard-easy`: an edge behind `hard-range` took its
  NAT for "easy (port changed)" - perhaps both supernodes saw the same port
  drawn from the range of 240

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
