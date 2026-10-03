# Upstream PRs: parked

State (2026-10-03): nine branches `pr/*`, cut from n42n/n3n main 732467d,
each verified alone (clean build, unit and builtin tests, upstream lint
with uncrustify 0.72); all nine merge into upstream main without conflict.
big-endian also tested under qemu on s390x, mips and aarch64.

Open:
- Integration tests: not run here (the container has no IPv6, which
  upstream's supernode needs by default).
- Benchmarks: run bench-prs.sh on a real machine (root, or
  perf_event_paranoid=1), put the output into the commit messages it
  names (also the PASTE placeholder in pr/arm-speck).
- Then open the PRs with pr-texts.md.
