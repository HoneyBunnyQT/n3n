SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright Honey Bunny QT

# Running as a Service

n3n runs under any service manager, or none: it does not depend on systemd,
and is not built differently for it.

## systemd

The packages bring units for systemd: `n3n-edge.service` (session "edge"),
`n3n-edge@NAME.service` (session NAME, `/etc/n3n/NAME.conf`) and
`n3n-supernode.service`.

```
sudo systemctl enable --now n3n-edge@home
systemctl status n3n-edge@home
```

The units are of `Type=notify`: n3n tells systemd

- when it is up - the TAP device configured, the supernode asked for - so
  that units ordered after it start only then;
- how it is doing, as the status line of `systemctl status`, e.g.
  `Status: "registered at 203.0.113.1:7654 over UDP, 3 peers (2 direct)"`
  or, for a supernode, `"supernode: 12 edges in 3 communities"`;
- that its main loop still runs (`WatchdogSec=60`): if it hangs, systemd
  restarts it.  Its main loop comes round at least every ten seconds, so a
  `WatchdogSec` below 30 seconds is too short.
- when it is stopping.

`systemctl reload` sends SIGHUP (`ExecReload`): n3n reads its configuration
again and applies what can change while running, see [Configuration
Files](ConfigurationFiles.md#reloading); it tells systemd so (`RELOADING=1`,
then `READY=1`).

This is systemd's notification protocol: a datagram to the socket that
systemd names in `NOTIFY_SOCKET`.  n3n does it itself, without libsystemd.
Run n3n in the foreground under systemd (the default, `daemon.background =
false`): a daemon that forks is not the process systemd watches.

## Other service managers, containers, a shell

Without `NOTIFY_SOCKET` in its environment, n3n does none of the above, and
behaves as it always did: OpenRC, runit, s6, a container's entry point or a
terminal start it in the foreground (`n3n-edge start NAME`), or in the
background with `daemon.background = true`.

With a unit of your own of `Type=simple`, systemd does not set
`NOTIFY_SOCKET` either.

## Watching n3n otherwise

The management interface tells the same and more: `n3nctl -s NAME get_info`,
`n3nctl -s NAME supernodes`, and the web page (see
[Management API](../internals/ManagementAPI.md)).
