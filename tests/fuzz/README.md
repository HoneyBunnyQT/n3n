<!--
Copyright (C) Honey Bunny QT
SPDX-License-Identifier: GPL-3.0-only
-->
# Fuzz targets

The fuzz targets of the receive path; the first three found the
out-of-bounds bugs fixed in 3.4.7.  Each is a [libFuzzer](https://llvm.org/docs/LibFuzzer.html) target
(`LLVMFuzzerTestOneInput`), over a different layer of what an edge or a
supernode does with a packet it receives:

| target         | what it feeds                                                        |
|----------------|----------------------------------------------------------------------|
| `fuzz-header`  | a PDU's first steps: is the header plain, else the header decryption with a community's keys (`src/pdu_in.c`, `src/header_encryption.c`), then the decoders on what comes out |
| `fuzz-transop` | the payload of a PACKET as a transform's `rev()` takes it apart — first byte picks the cipher or compression, the rest is its input (`src/transform_*.c`) |
| `fuzz-wire`    | the PDU decoders on an already-plain header (`src/wire.c`); whatever decodes is encoded again |
| `fuzz-tcp`     | a v3tcp connection: bytes in pieces through a socket, put together by `conn_read()` (`libs/connslot`) and split into PDUs by `mainloop_v3tcp_pdus()` (`src/mainloop.c`), which then go to the decoders |
| `fuzz-mgmt`    | a request to the management interface (local only): the HTTP request and, for the JSON-RPC endpoints, the body (`src/management.c`, `libs/connslot/jsonrpc.c`); first byte picks the edge's or the supernode's runtime |
| `fuzz-tun`     | the TUN edge playing kernel for Ethernet and ARP (`src/tun.c`): a frame from a peer in, or an IP packet from the device out; first byte picks the direction |

## Running

Two ways to build, both driven from the top level:

```sh
# 1. Replay the committed regression corpus and the generated seeds with
#    the normal compiler (no libFuzzer needed).  Part of "make test", and
#    good under the sanitizers.
make test.fuzz

# 2. Fuzz for real: build with libFuzzer (clang, and its runtime: on
#    Debian and Ubuntu libclang-rt-dev) and let it search.  The library
#    is built with the fuzzer's instrumentation too.
F="-fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=all -g -O1"
./configure CC=clang CFLAGS="$F" LDFLAGS="$F"
make fuzz FUZZ=libfuzzer
tests/fuzz/fuzz-seeds tests/fuzz/seeds
mkdir -p tests/fuzz/work/transop
tests/fuzz/fuzz-transop tests/fuzz/work/transop tests/fuzz/seeds/transop   # ^C to stop
```

In CI, `make test` replays them on every build, `sanitizers.yml` with
AddressSanitizer and UndefinedBehaviorSanitizer, and `fuzz.yml` searches
with libFuzzer a minute per target on every push and pull request, going
on from the corpus of the runs before (kept in the cache).  What crashes
a target there is uploaded as the artifact `fuzz-crash`, with libFuzzer's
log (its seed is in the line `INFO: Seed:`).  The long nightly searches,
and `fuzz-spray` (see below), run in a private repository, so a crash is
not made public before its fix; that workflow checks this tree out as it
is, nothing of it lives here.

`make test.fuzz` builds the targets with `driver.c` instead of libFuzzer —
`driver.c` runs each target over the files it is given (a file, or every
file in a directory). It replays `regress/<target>/` (minimised inputs that
once crashed — add new ones here) and the `seeds/` that `fuzz-seeds`
generates. Each input is copied to its own buffer first, so a read past the
end shows up under AddressSanitizer.

## At running daemons

`fuzz-spray` sends mutated PDUs over the network instead, at running
edges and supernodes, for the netns scenarios tagged `spray` (see
docs/develop/netns_testing.md): from the seeds below, with a community,
its header keys and the daemons' MACs put in, so that the changes reach
the handlers and their state, which the targets above do not.  It uses
n3n's own random numbers, seeded with `-s`: the same seed, the same PDUs.

## Seeds

`fuzz-seeds DIR` writes valid starting inputs into `DIR/header`,
`DIR/transop`, `DIR/wire` and `DIR/tcp` — PDUs of every message type, the
same with encrypted headers, payloads as each transform makes them, and
PDUs with their length in front, cut into pieces (a piece is a byte with
its length, then as many bytes). They are
generated, not committed; `make clean` removes them.

## Regression corpus

`regress/<target>/` holds inputs that once triggered a crash, kept so the
fix stays fixed. When a fuzzer finds one, minimise it
(`tests/fuzz/fuzz-TARGET -minimize_crash=1 -runs=100000 FILE`) and drop
the file in the matching directory, under a name that says what it was;
`make test.fuzz` then replays it every run.

What is there, each crashing the code before its fix under
AddressSanitizer:

| file | the bug | fixed in |
|------|---------|----------|
| `header/header-len-4` | a header whose decrypted magic gives a length below 16: the header decryption wrapped and ran past the packet | 3.4.7, 053b220 |
| `transop/cc20-iv-in-length` | ChaCha20 decrypted the IV's 16 bytes more than the cipher text | 3.4.7, dce44be |
| `transop/aes-past-assembly`, `transop/tf-past-assembly` | AES and Twofish took a cipher text a block longer than their work buffer | after 3.4.7, 24681cd |
