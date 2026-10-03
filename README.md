# Upstream PRs: ready to open

State (2026-10-03): nine branches `pr/*`, on n42n/n3n main 7e528e3, each
verified alone (clean build, unit and builtin tests, upstream lint with
uncrustify 0.78.1); all nine merge into upstream main without conflict.
big-endian also tested under qemu on s390x, mips and aarch64.

- New files are GPL-2.0-only, as upstream's docs/LICENSE.md expects, with
  `SPDX-FileCopyrightText: Copyright Honey Bunny QT`.
- Benchmarks (x86-64, bench-prs.sh) are in the commit messages of the
  performance relevant commits.  No ARM numbers: the NEON commit and the
  plain C Speck/ChaCha20 commit change no code an x86 build runs.
- Integration tests (integ-prs.sh, on a host with IPv6): upstream main
  and all nine branches ok.

Next: open the PRs with pr-texts.md.
