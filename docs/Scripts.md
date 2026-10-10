<!--
SPDX-License-Identifier: GPL-2.0-only
SPDX-FileCopyrightText: Copyright Hamish Coleman
-->

# Scripts

There are a number of useful scripts included with the distribution.
Some of these scripts are only useful during build and development, but
other scripts are intended for end users to be able to use.  These scripts
may be installed with n3n as part of your operating system package.

Most scripts can be found in the `scripts` directory.

Short descriptions of these scripts are below.

## End user scripts

### `n3nctl`

This python script provides an easy command line interface to the running
n3n processes.  It uses the management API and if there is only one daemon
running on the system, it will attempt to automatically locate it and talk
to its Unix domain socket.  it can talk to both the edge and the supernode
daemons.

Example:
- `scripts/n3nctl --help`
- `scripts/n3nctl help`
- `scripts/n3nctl -s supernode edges`
- `scripts/n3nctl -s supernode -r edge edges`: the peers of the supernode's
  own edge (`supernode.tap`)
- `scripts/n3nctl -k PASSWORD reload`: read the configuration again, see
  [Configuration Files](configure/ConfigurationFiles.md#reloading)

The methods it can call are described in the
[Management API](internals/ManagementAPI.md).

### `n3n-convert_old_conf`

Converts the edge config file of n2n, with command line style options, to
the INI style of n3n.  Not installed by the packages: it is only needed once.

## Build and Development scripts

### `hack_fakeautoconf.sh`

This shell script is used during development to help build on Windows
systems.  An example of how to use it is shown in
the [Build documentation](build/index.md)

### `indent.sh`

This shell script is a wrapper for the `uncrustify` C code style checker
which checks or applies a set of rules to the code.  It is used during
the automated lint checks.

### `gen_options_md.py`

Writes [the reference of all options](configure/Options.md) from what the
built program says about them: `make options` runs it, `make options.check` tells
whether the reference is up to date.

### `version.sh`

This script is used to determine the current version number during the
build process.

It looks at both the VERSION file and the GIT tags and outputs the
version number to use.

## Monitoring and statistics

### `munin/n3n_`

This is a simple monitoring script that can be used with the munin-node
system to monitor the n3n daemons.

This is a fully autoconfigurable wildcard munin plugin, but to get a quick
sample:

get a list of suggested plugin names:
```
munin/n3n_ suggest
```

Enable some of those names:

```
ln -s /usr/share/munin/plugins/n3n_ /etc/munin/plugins/n3n_supernode_pkts
ln -s /usr/share/munin/plugins/n3n_ /etc/munin/plugins/n3n_supernode_counts
```

Manually test fetching and config:

```
/etc/munin/plugins/n3n_supernode_pkts
/etc/munin/plugins/n3n_supernode_pkts config
```

## Testing scripts

### `test_harness.sh`

This shell script is used to run automated tests during development.  It is
run with a testlist filename - pointing at a file containing the list of
tests to run.

Each test needs a file containing the expected output `${TESTNAME}.expected`
which is expected to exist in the same directory as the testlist (this dir is
referred to as `${listdir}` below).

Each test is a program, searched for in several locations, including the
`${listdir}/../scripts` dir.

Each test is run with its output being sent to `*.out` files in the `listdir`
and compared with the expected output.

### `test_builtin_edge.sh`, `test_integration_*.sh`

The builtin tests run commands of the program itself (`test config
roundtrip`, a config with community sections, `tools keygen`); the
integration tests start supernodes and edges on this host and check them
through the management API with `n3nctl`, also over TCP and with the web
UI.

### `test_qemu.sh`

Runs the unit and builtin tests of a cross build under qemu-user, for big
endian and other CPUs, see [Testing](develop/testing.md).

## Example or Documentation scripts

### `n3n-gateway.sh`

A sample script to route all the host traffic towards a remote gateway,
which is reachable via the n3n virtual interface.  This can be found in
the `docs/advanced/n3n-gateway.sh`
