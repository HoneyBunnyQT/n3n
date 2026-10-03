# PR texts for n42n/n3n

Each one: open the compare link, check that the base is `n42n/n3n` `main`,
paste the title and the text, create.  The commits carry the details; the
texts are kept short on purpose.

---

## 1. `pr/build-housekeeping`

https://github.com/n42n/n3n/compare/main...HoneyBunnyQT:n3n:pr/build-housekeeping

**Title:** Build fixes: relink the tools, survive removed headers, build without bridging

Small build fixes, one commit each:

- The tools did not depend on `libn3n.a`, so after a library change `make test` ran test binaries built from the old code.
- A removed header broke the build until the `.d` files were deleted by hand (`-MP`).
- A build without `HAVE_BRIDGING_SUPPORT` failed to compile.
- `.gitignore` hid everything under `docs/configure/`, and `indent.sh -i` left backup files behind.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## 2. `pr/edge-runtime`

https://github.com/n42n/n3n/compare/main...HoneyBunnyQT:n3n:pr/edge-runtime

**Title:** Edge: purge small peer tables, resolve names as a daemon, start without an answering supernode

- Peer tables of fewer than 16 entries were never purged, so edges that had gone stayed for good (#142). New unit test `tests-peers`.
- With `--daemon`, the resolver thread stayed behind in the parent: supernode names were never resolved again.
- With several supernodes of which none answered, the edge never got past its startup; it now carries on after three rounds of pings, as with a single supernode.
- Frees the `connection.bind` addresses on exit (valgrind).

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## 3. `pr/community-file`

https://github.com/n42n/n3n/compare/main...HoneyBunnyQT:n3n:pr/community-file

**Title:** Community file: keep regex character classes, no leaks on reload, read user lines as users

- Compiling the next rule overwrote the character classes of the rules before it, so with two rules `net[0-9]+` no longer matched `net4`. New unit test `tests-regex`.
- Reloading the file leaked the compiled rules and each user's cipher context.
- A malformed user line could be read as the community regex `*`.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## 4. `pr/pdu-length-checks`

https://github.com/n42n/n3n/compare/main...HoneyBunnyQT:n3n:pr/pdu-length-checks

**Title:** Drop PDUs that are too short or too long for their fields

The decoders skipped fields the buffer had no room for, and their callers then used what was left in the struct from before - e.g. a short `REGISTER_SUPER_ACK` made the edge add backup supernodes built from stale bytes. The decoders now report short input, and edge and supernode drop PDUs with missing or extra bytes (the hash of user/password auth is allowed for).

Also: `PEER_INFO` and `REGISTER_SUPER` no longer send uninitialised stack bytes. New unit test `tests-wire-fuzz` feeds every truncation of every PDU type to its decoder.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## 5. `pr/management`

https://github.com/n42n/n3n/compare/main...HoneyBunnyQT:n3n:pr/management

**Title:** Management: escape what peers send, close HTTP/1.0 replies, no crash on an empty Authorization header

- Descriptions and versions come from other peers, and went into the page as HTML and into the JSON unescaped: a peer could run script in the page that has the stop button, or break the JSON.
- An `Authorization` header without credentials crashed n3n before the password was checked.
- HTTP/1.0 clients such as lynx never saw the end of a reply.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## 6. `pr/big-endian`

https://github.com/n42n/n3n/compare/main...HoneyBunnyQT:n3n:pr/big-endian

**Title:** Ciphers on big endian and strict alignment hosts, tested under qemu

On big endian hosts, the plain C Speck and ChaCha20 and the Twofish decryption gave wrong results, so such an edge could not talk to a little endian one. Unaligned word access in AES, Pearson, Twofish and the edge traps on MIPS (a bus error under qemu). Also libatomic for 32 bit MIPS/PowerPC, and the same test outputs on every host.

CI now runs the unit and builtin tests on s390x, mips and aarch64 under qemu-user. Benchmarks are in the commit messages.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## 7. `pr/arm-speck`

https://github.com/n42n/n3n/compare/main...HoneyBunnyQT:n3n:pr/arm-speck

**Title:** Speck: no maybe-uninitialized warnings, remove the unbuilt speck.c

The SSE2, AVX2 and NEON CTR code stored its blocks after the branches that computed them, which GCC warns about; each branch now stores its own blocks, and the Makefile's `-Wno-maybe-uninitialized` goes. Same output, benchmarks in the commit message. `src/crypto/speck.c` was not built any more.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## 8. `pr/crypto-tests`

https://github.com/n42n/n3n/compare/main...HoneyBunnyQT:n3n:pr/crypto-tests

**Title:** Known-answer tests for AES and ChaCha20

New unit tests: FIPS-197 vectors for AES-128/192/256 and CBC (also in place), the RFC 8439 vector for ChaCha20 and every length from 0 to 1100 bytes (also unaligned and in place). So far only 128 bit AES keys were tested.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---

## 9. `pr/sn-load-wire`

https://github.com/n42n/n3n/compare/main...HoneyBunnyQT:n3n:pr/sn-load-wire

**Title:** Send the supernode's load as the 32 bit number it is on the wire

The load went out as a 64 bit big endian number cut to its 32 bit field - 0 from every little endian supernode - and the edge swapped what it read once more, so an n2n supernode's load of 5 read as 83886080. Selection by load (the default) never had the real load. Now 32 bit, network order, as n2n has it.

This changes what goes on the wire: older n3n edges will misread a fixed supernode's load, as they already misread n2n supernodes; a fixed edge reads 0 from an older supernode, as all edges do today.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
