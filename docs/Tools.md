<!--
SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright 2023 n2n contributors
SPDX-FileCopyrightText: Copyright Hamish Coleman
SPDX-FileCopyrightText: Copyright Honey Bunny QT
-->

# Tools

There are a number of handy tools coming with n3n extending fumction and
user experience or just prove helpful during build and development.

All tools can be found in the `tools` directory.

## End User Tools

### `n3n-benchmark`

This tool is deprecated as the function is now built-in to the n3n-edge with
the `n3n-edge test benchmark` command.

It is not built by default, and no longer builds as it stands; use
`n3n-edge test benchmark` (or `n3n edge test benchmark`), which also runs
in several threads at once with `test.threads`.

This C tool has n3n's basic transforms (the ciphers, compression, hash)
crunch a test packet and outputs the measured throughput. You might observe
differences depending on compiler optimizations or enabled hardware support,
see [build configuration](build/BuildConfig.md).

Example:
- `tools/n3n-benchmark`

### `n3n-qr`

Makes a QR code of an edge's configuration file, for the Android app to
scan (see [android/README.md](../android/README.md)).  It is built when
`./configure` finds libqrencode and libpng (on Debian and Ubuntu
`libqrencode-dev` and `libpng-dev`); `--without-qrencode` leaves it out.

```
tools/n3n-qr phone.conf          # writes phone.qr.png in the current directory
tools/n3n-qr -t phone.conf       # shows the code in the terminal, e.g. over ssh
tools/n3n-qr -o code.png -s 12 phone.conf
tools/n3n-qr -p phone.conf       # prints the text that goes into the code
```

The code holds the configuration as text, as any QR reader shows it:
without comments and the spaces around `=`, and with at most one blank
line in a row, otherwise as it
is, so the edge reads it as it reads the file.  A typical configuration is
well below the 2900 or so bytes a code can hold.

- The code holds the community's key, if the file has one: share the image
  like the key itself.
- The app needs a static `address` in `[tuntap]`, and each phone its own;
  `n3n-qr` notes when there is none.  One configuration file per phone is
  the simple way.

`make test.qr` checks that `zbarimg` (zbar-tools) reads back what went in.

### `n3n-route`

This tool has not been converted to work with the JsonRPC API interface.

This C tool sets new routes for all the traffic to be routed via a VPN gateway
(another edge) and polls the management port of a local n3n edge for adding
appropriate routes to supernodes and peers via the original default gateway.

The tool can auto-detect the default gateway and also has options to only route
traffic to some specified networks through the VPN gateway.

Make sure to run with sufficient rights to let the tool add and delete routes.

More general information can be found in the [routing
document](advanced/Routing.md)
including hints how to setup the remote edge (IP routing, masquerading).

Example:
- `tools/n3n-route <remote edge address>`
- `tools/n3n-route -n 10.10.10.0/24 <remote edge address>`
- `tools/n3n-route -n 8.8.8.8/32:192.168.0.5  <some (other) remote edge address>`

### `n3n-portfwd`

This tool has not been converted to work with the JsonRPC API interface.

This C tool uses UPnP and/or PMP to have a local router forward the edge port.
The program polls a local edge's management port and takes apporpriate action.

Note that n3n needs to be compiled with the corresponding options enabled, e.g.

```
./configure --enable-miniupnp --enable-natpmp
```

Also see [build configuration](build/BuildConfig.md).

Example:
- `tools/n3n-portfwd`


## Build and Development Tools

### `tests-*`

These C programs run certain parts of n3n with pre-defined data and output
the results. The expected results can be found in the `tests/` directory
following the `tests-*.expected` naming scheme.

The `test_*` [scripts](Scripts.md) residing inside the `scripts/` directory
compare test output and expected results to quickly show deviations, helpful
when on bug hunt.

Example:
- `tools/tests-transform`

The unit tests are listed in `tests/tests_units.list` and run with
`make test.units`; among them `tests-aes` and `tests-cc20` (the published test
vectors of AES and ChaCha20, for whichever implementation is built),
`tests-wire-fuzz` (the decoders against every truncation of every PDU) and
`tests-regex` (the regular expressions of the community rules).  See
[Testing](develop/testing.md).

### `n3n-decode`

This C tool intends to decrypt captured n3n traffic when all keys are provided.
Its development unfortunately did not follow main n3n's pace after version 2.8 
and thus is not up to date.

Contributions to help lifting it to match version 3.x traffic are very welcome.
