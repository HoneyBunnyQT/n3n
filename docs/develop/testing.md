SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright Hamish Coleman

# Testing

## What there is, and where it runs

| what | how | in CI |
|------|-----|-------|
| lint: C style (uncrustify 0.77.1), python, shell, yaml, man pages | `make lint` | yes |
| unit tests: the programs `tools/tests-*`, against `tests/*.expected` | `make test.units` | yes |
| builtin tests: commands of the program itself, see below | `make test.builtin` | yes |
| integration tests: supernodes and edges on this host, checked with `n3nctl` | `make test.integration` | yes |
| NAT tests: edges and supernodes in network namespaces behind emulated NATs, see [Testing behind NATs](netns_testing.md) | `make test.netns` (the quick ones), `make test.netns.full` (needs root) | no |
| other CPUs: big endian, 32 bit, ARM, under qemu-user | `scripts/test_qemu.sh`, see below | yes |
| an edge-only build (`./configure --disable-relay`) | the unit and builtin tests | yes |
| the options reference is up to date | `make options.check` | yes |
| sanitizers: all of the above but lint and qemu, with AddressSanitizer and UndefinedBehaviorSanitizer built in, every finding fatal | see below | yes, on every push (`sanitizers.yml`), the NAT tests too |

`make test` runs the first four and the quick NAT tests (which skip
themselves without root).  A change that touches the protocol, NAT
traversal, the threads or the supernode should also pass
`make test.netns.full`, with and without `./configure --enable-pthread`.

### With the sanitizers

```
F="-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g -O1"
./configure --enable-pthread CFLAGS="$F" LDFLAGS="$F" && make -j4
mkdir -p /tmp/san
export ASAN_OPTIONS=log_path=/tmp/san/asan UBSAN_OPTIONS=log_path=/tmp/san/ubsan
make test.units test.builtin test.integration
sudo -E tests/netns/run.py
ls /tmp/san          # empty: nothing found
```

The reports go to files of their own: a daemon that leaks exits with 1,
and its report may come after its log is closed.  AddressSanitizer does not
run in the User-Mode Linux kernel of `tests/netns/uml.sh` (its shadow
memory does not fit there), UndefinedBehaviorSanitizer alone does.  The
bundled minilzo reads unaligned on purpose, so the Makefile leaves out
the alignment check for it.

# Built in Testing and Benchmarking framework

There is a built in framework that is compiled into the code.  This allows the
binary to be compiled for multiple environments, OS and architectures and
still have the functionality tested easily and in-situ.

The built in tests are also run as part of the `make test` command.

Since a significant proportion of the users of n3n do not have a build
environment (eg because they were cross compiled for an embedded system, they
are running in field on a end user system or for a number of other reasons)
it is useful to be able to ship and run tests.

These tests can also be timed, allowing a benchmark of system performance to
be gathered.

## Adding new tests to the code

Note that some of these details are still under development and are expected
to change.

Each test uses a `static struct bench_item` to describe the test.

These are then hooked into the framework with the `n3n_benchmark_register()`
function.  This is expected to be called from the module's initfunc.

## Running built in tests

`n3n-edge test check`

This can optionally be followed by a list of the test names to run.

If all the tests that run were successful, an "OK" is output on stdout and the
program exitcode is set to zero. 

More details about each test can be shown by adding the
`-Otest.output_format=raw` option.  This will show the internal ID of which
data buffer was passed into the test and then show the hexdump of the result
from the test and can be used for further debugging of tests.

## Running benchmarks

To run the preferred benchmarking, use:

`n3n-edge test benchmark`

This can optionally be followed by a list of the test names to run.

On supported systems and with high enough permissions, this will track the CPU
instructions and clock cycles (currently, only Linux supports this.  You will
need to either run it as root or change the sysctl to allow perf access for
regular users)

This information can also be output as CSV to allow easy storage and analysis.
Add the `-Otest.output_format=raw` option.

Due to the lack of Performance Management Unit (PMU) virtualisation in many
CI/CD pipelines, the regular benchmark cannot be used in those cases.  Since
one key reason to have this benchmark is to allow tracking of performance
regressions, an alternative (worse) benchmark has been added that works
without the need for a PMU.  This uses ptrace to single-step the tests and is
less accurate, takes longer to run and only supports Linux.

`n3n-edge test fakebench`

This "fakebench" generates fake numbers and should not be used for precise
measurements. It should be considered a hack that has been cobbled together as
a last resort to allow a minimal CI testing.

### Contributing performance changes

When contributing changes that may have a performance impact, it is very
useful to be able to characterise those changes.

To this end, the before and after benchmark results (Not fakebench) should be
included in a commit message.  This allows others to see the size of the
performance change and hopefully provide the information needed for the
results to be replicated and compared.

Pasting the exact text from the builtin benchmarks is important as this
makes it easy for people to see and compare with a standard format.  If the
benchmark settings have been changed from the defaults, that should also be
explained.

It is intended that the benchmark outputs will be improved to give better
information on the environment used and the statistics and confidence levels
in them to help with replicating any tests.

## Testing on other architectures

Most development happens on 64 bit little endian x86, but n3n also runs on
big endian hosts (some MIPS, PowerPC, s390x), on 32 bit ones and on CPUs that
trap on unaligned memory accesses - typically routers.  The expected outputs
of the unit tests and of `n3n-edge test check` are the same for all of them,
so a cross compiled tree can run them under qemu-user:

```
sudo apt install gcc-mips-linux-gnu libc6-dev-mips-cross qemu-user
./configure --host=mips-linux-gnu
make apps tools
scripts/test_qemu.sh qemu-mips -L /usr/mips-linux-gnu
```

Only the pattern tests of `tests-wire` are left out: they fill structs with
byte patterns, which naturally come out differently on a big endian host.

CI runs this for s390x (big endian, 64 bit), mips (big endian, 32 bit),
aarch64 (also with the ARMv8 AES instructions and Speck with NEON) and 32
bit ARM with NEON.  `tests-aes` and `tests-cc20` check known answers of
whichever implementation of AES and ChaCha20 a build has.
