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
- [ ] Step 3: periodic work (registrations, purges, sorting, resolving)
      registered as timers in the mainloop, for both
- [ ] Step 4: role sub-structs in `struct n3n_runtime_data` and
      `n2n_edge_conf_t` (`rt->tap`, `rt->client`, `rt->relay`, ...), NULL when
      the role is off
- [ ] Step 5: one front end for received PDUs (`pdu_in`): length check,
      community lookup and header decryption, replay check, giving a
      `struct pdu_ctx`.  The edge's single community becomes a community
      table with one entry
- [ ] Step 6: dispatch through a table per message type with a handler per
      role instead of the two big `switch` statements
- [ ] Step 7: split `edge_utils.c` / `sn_utils.c` by role and by concern:
      core (`loop`, `sock`, `pdu_in`, `peers`) and `role_tap`,
      `role_client`, `role_relay`, `role_federate`
- [ ] Step 8: one binary `n3n`; `n3n-edge` and `n3n-supernode` stay as
      names (links) that pick their roles from `argv[0]`, with unchanged
      options, help and config dumps
- [ ] Step 9: relay and tap in one process, still v3: the client role
      registers with the local relay role without packets, and a PACKET for
      the local MAC goes straight to the TAP device
- [ ] `./configure --disable-relay` for small builds that only need an edge;
      the `#ifdef` only where the roles are registered

### Next

- [ ] Communities configured the same way for both roles (see Scratchpad)
- [ ] Unit tests for the parts that become shared (send layer, `pdu_in`)
- [ ] Integration test: a supernode with a TAP device next to plain edges
- [ ] Run the netns NAT scenarios in CI (`make test.netns`)
- [ ] Fuzzing of the PDU decoders (`wire.c`) and of header decryption
- [ ] ASan/UBSan builds in CI, TSan for the threads
- [ ] ARM NEON: look where the ciphers could gain (see Scratchpad)
- [ ] epoll in the mainloop instead of `select()` (`mainloop.c` TODO), lifts
      the limit on TCP connections
- [ ] Batched I/O: `recvmmsg()` / `sendmmsg()`, later UDP GSO/GRO
- [ ] No `alloc()` on the packet path (`edge_utils.c`, TODO in the send path)
- [ ] IPv6 address on the TAP device, from the config or assigned by the relay
- [ ] Supernode lookup by DNS SRV (`resolve.c` TODO)

### Later: the peer protocol (v4)

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
- 2026-10-01: Roles are chosen at run time; leaving the relay code out of a
  build is an option for later, decided in one place.

## Scratchpad

Current ideas, half-decided things, commands worth keeping.

### Communities for both roles

Today the edge has one community from `community.name`, `community.key`,
`community.cipher`, ... while the supernode reads `supernode.community_file`:
one name or regular expression per line, optionally with a network, plus
`*` lines with user names and public keys.

Idea: one way for both.  Options:

1. The community file grows per-community settings (key, cipher, header
   encryption, network, users) and both roles read it; a peer with only the
   `tap` role takes the first entry and no regular expressions.
2. Config file sections per community, e.g. `[community "home"]`, with
   `community_file` kept for the supernode's long lists.
3. Keep `community.*` options for the first community and the file for any
   more.

Leaning towards 2 or 3: a single edge stays a few lines of config, a relay
with many communities keeps its file.  To decide before step 4, since it
shapes `rt->relay` and the community table of step 5.

### ARM NEON

- Speck has a NEON version already (`src/crypto/speck_neon.c`)
- ChaCha20: a NEON version like `cc20_sse2.c` is feasible; OpenSSL has one,
  so measure against `--with-openssl` first
- AES: ARMv8 has the crypto extension (`vaeseq_u8` ...), much faster than
  plain C; worth it on Raspberry Pi 5 / most ARMv8 boards (not on the Pi 4,
  which lacks the extension)
- Twofish: table lookups, little to gain from NEON
- Test with `qemu-aarch64` for correctness, on real boards for speed

### Commands

Build and test:

```sh
./autogen.sh && ./configure --enable-pthread && make -j"$(nproc)"
make test.builtin test.units test.integration    # quick
sudo make test.netns                             # NAT scenarios, needs root
sudo tests/netns/run.py -q                       # all of them
sudo tests/netns/run.py -q --wrap 'valgrind --error-exitcode=99 --leak-check=full --errors-for-leak-kinds=definite' tcp-tcp hard-hard
make lint                                        # everything CI lints
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
