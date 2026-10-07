<!--
Copyright (C) Honey Bunny QT
SPDX-License-Identifier: GPL-3.0-only
-->
# Fuzz targets

The targets that found the receive-path out-of-bounds bugs fixed in 3.4.7.
Each is a [libFuzzer](https://llvm.org/docs/LibFuzzer.html) target
(`LLVMFuzzerTestOneInput`), over a different layer of what an edge or a
supernode does with a packet it receives:

| target         | what it feeds                                                        |
|----------------|----------------------------------------------------------------------|
| `fuzz-header`  | a PDU's first steps: is the header plain, else the header decryption with a community's keys (`src/pdu_in.c`, `src/header_encryption.c`), then the decoders on what comes out |
| `fuzz-transop` | the payload of a PACKET as a transform's `rev()` takes it apart — first byte picks the cipher or compression, the rest is its input (`src/transform_*.c`) |
| `fuzz-wire`    | the PDU decoders on an already-plain header (`src/wire.c`); whatever decodes is encoded again |

## Running

Two ways to build, both driven from the top level:

```sh
# 1. Replay the committed regression corpus and the generated seeds with
#    the normal compiler (no libFuzzer needed).  Good under the sanitizers.
make test.fuzz

# 2. Fuzz for real: build with libFuzzer (needs clang) and let it search.
make fuzz FUZZ=libfuzzer
./tests/fuzz/fuzz-transop tests/fuzz/seeds/transop     # ^C to stop
```

`make test.fuzz` builds the targets with `driver.c` instead of libFuzzer —
`driver.c` runs each target over the files it is given (a file, or every
file in a directory). It replays `regress/<target>/` (minimised inputs that
once crashed — add new ones here) and the `seeds/` that `fuzz-seeds`
generates. Each input is copied to its own buffer first, so a read past the
end shows up under AddressSanitizer.

## Seeds

`fuzz-seeds DIR` writes valid starting inputs into `DIR/header`,
`DIR/transop` and `DIR/wire` — PDUs of every message type, the same with
encrypted headers, and payloads as each transform makes them. They are
generated, not committed; `make clean` removes them.

## Regression corpus

`regress/<target>/` holds inputs that once triggered a crash, kept so the
fix stays fixed. When a fuzzer finds one, minimise it and drop the file
in the matching directory; `make test.fuzz` then replays it every run.
