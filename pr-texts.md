# PR texts for n42n/n3n - round 2 (after Hamish's review)

All branches are rebased on upstream main 6d837f2, each verified alone
(build, unit and builtin tests, lint with uncrustify 0.78.1), and all of
them merge together without conflict.  The new test programs are
GPL-3.0-only now, as upstream's tools/tests-*.c since c280535;
scripts/test_qemu.sh stays GPL-2.0-only.

C = compare link to open a new PR.  E = edit title/description of an open PR.

---

## 1. PR 164 - reply, title and description

Reply (to the review):

> Thanks for the review. I've dropped the indent.sh change, taken the TODO
> comment from apps/Makefile, made the tools compile to objects and then
> link (so `make gcov` finds the expected names without a wildcard), and
> reduced the .gitignore change to `/configure`.

E - Title: **Build fixes: relink the tools, coverage names, removed headers, no bridging**

E - Description:

> Small build fixes, one commit each:
>
> - The tools did not depend on `libn3n.a`, so after a library change `make test` ran test binaries built from the old code.
> - The tools are compiled to objects and then linked, so their coverage notes have the names `make gcov` expects.
> - `.gitignore` hid everything under `docs/configure/`, so new pages there could not be added.
> - A removed header broke the build until the `.d` files were deleted by hand (`-MP`).
> - A build without `HAVE_BRIDGING_SUPPORT` failed to compile.

## 2. PR 165 - comment, then close

> Fair point. I'll close this one and split it: one PR for the edge startup
> issues, one for a small leak fix. The purge of small peer tables I'm
> dropping: I had missed that keeping them is intentional (#142, #143).

## 3. (dropped) purge small peer tables

Not opened: Hamish considers the `< 16` rule intentional, and #143
(Sugarfarmeriod, earlier than ours) already covers the topic, now going
for removing peers after terminal send errors instead.  The branch
pr/peer-purge stays, unused; the fork (peer) keeps the purge.

## 4. New: edge startup

C: https://github.com/n42n/n3n/compare/main...HoneyBunnyQT:n3n:pr/edge-startup

Title: **Edge startup: resolve names after daemonizing, do not wait forever for a supernode**

> - With `--daemon`, the resolver thread stayed behind in the parent: the edge never resolved its supernodes' names again.
> - With several supernodes of which none answered, the edge never got past its startup; it now carries on after three rounds of pings, as with a single supernode.

## 5. New: leak

C: https://github.com/n42n/n3n/compare/main...HoneyBunnyQT:n3n:pr/bind-leak

Title: **Free the connection.bind addresses when the edge ends**

> Loading the config allocates them, and nothing freed them (valgrind).

## 6. PR 167 - description (title stays)

E - Description:

> The decoders skipped fields the buffer had no room for, and their callers
> then used what was left in the struct from before - e.g. a short
> `REGISTER_SUPER_ACK` made the edge add backup supernodes built from stale
> bytes. The decoders now report short input, and edge and supernode drop
> PDUs with missing or extra bytes (the hash of user/password auth is allowed
> for). New unit test `tests-wire-fuzz` feeds every truncation of every PDU
> type to its decoder.

## 7. New: uninitialised bytes

C: https://github.com/n42n/n3n/compare/main...HoneyBunnyQT:n3n:pr/uninit-bytes

Title: **Send no uninitialised bytes in PEER_INFO and REGISTER_SUPER**

> The supernode's `PEER_INFO` (answering `QUERY_PEER`) left load, uptime and
> version unset, and its `REGISTER_SUPER` to the federation some fields:
> stack contents went out on the wire. Found with valgrind.

## 8. PR 168 - title and description

E - Title: **Management: escape what peers send**

E - Description:

> Descriptions and versions come from other peers, and went into the page as
> HTML and into the JSON unescaped: a peer could run script in the page that
> has the stop button, or break the JSON.

## 9. New: management HTTP handling

C: https://github.com/n42n/n3n/compare/main...HoneyBunnyQT:n3n:pr/mgmt-http

Title: **Management HTTP: close HTTP/1.0 replies, no crash on an empty Authorization header**

> - An `Authorization` header without credentials crashed n3n before the password was checked.
> - HTTP/1.0 clients such as lynx never saw the end of a reply: the connection is closed after it now, unless the client asks to keep it alive.

## 10. PR 170 - title and description

E - Title: **Speck: no maybe-uninitialized warnings**

E - Description:

> The SSE2, AVX2 and NEON CTR code stored its blocks after the branches that
> computed them, which GCC warns about; each branch now stores its own
> blocks, and the Makefile's `-Wno-maybe-uninitialized` goes. Same output,
> benchmarks in the commit message.

## 11. New: remove speck.c

C: https://github.com/n42n/n3n/compare/main...HoneyBunnyQT:n3n:pr/speck-unbuilt

Title: **Remove src/crypto/speck.c, which is not built**

> The all-platforms Speck from before the split into speck_plainc.c,
> speck_sse2.c, speck_avx2.c, speck_avx512.c and speck_neon.c; the Makefile
> builds only those.

---

Unchanged in content (only rebased, test headers GPL-3.0-only): 166, 169,
171, 172.
