<!--
SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright Logan oos Even
SPDX-FileCopyrightText: Copyright Hamish Coleman
SPDX-FileCopyrightText: Copyright Honey Bunny QT
-->

# Configuration Files

To help deployment and better handle locally different configurations, n3n
supports the use of configuration files for `n3n-edge` and `n3n-supernode`.

The daemon will attempt to locate a configuration file based on the
"sessionname" - which defaults to "edge" for the edge daemon.  This would
result in a config file called "edge.conf", which is located in "/etc/n3n" (or
the %USERPROFILE%\n3n directory on Windows)

They are plain text files formatted very similar to INI files.

To generate the help documentation for all current options:
```bash
n3n-edge help config
```

If you created the following `/etc/n3n/testing.conf` file:

```
[community]
cipher = Speck
key = mysecretpass
name = mynetwork
supernode = supernode.n3n.dev:7654

[daemon]
background = false

[tuntap]
address = 192.168.100.1
address_mode = static
```

which can be loaded by

```
sudo ./n3n-edge start testing
```

If needed, the settings from the config file can all be overridden using a
command line parameter:

If required, additional command line parameters can also be supplied:

```
sudo n3n-edge start testing \
    -Oconnection.description=myComputer \
    -O community.compression=lzo
```

Some of the most common options also have a shortcut version, you can see all
these with:

```
n3n-edge help options
```

All the options, with their defaults, are in [Configuration
Options](Options.md), generated from what the program says about them -
`n3n-edge help config` shows the same.

## Where the Settings Come From

On start, the daemon takes its settings in this order, each one overriding
what came before:

1. the defaults; for the supernode, `N3N_FEDERATION` in the environment
   sets the default of `supernode.federation`
2. the config file of the session name, `/etc/n3n/<sessionname>.conf`
   (or a path given instead of a session name, starting with `/` or `./`)
3. the environment: `N3N_KEY` (also sets the cipher to AES), `N3N_COMMUNITY`,
   `N3N_PASSWORD`
4. the command line, `-O section.option=value` and the shortcuts

To see the result:

```
n3n-edge debug config load_dump mysession
```

## Sections with a Name

Some sections can be there more than once, each with a name after the
section's own: `[community home]`.  A supernode takes each such
`[community NAME]` as a community it allows, see
[Communities](Communities.md#communities-in-the-configuration-file); an edge
takes its one community from `[community]` or from its only named section.

## Options Given More Than Once

Some options make a list: each line adds to it, for example
`community.supernode`, `supernode.peer`, `supernode.community_regex` and
`community.user`.  `connection.bind` takes several addresses in one line,
separated by spaces.

## Reloading

A running edge or supernode reads its configuration again on `n3nctl -k
PASSWORD reload`, on `systemctl reload` of the packaged units, or on SIGHUP
- but not while it runs in a terminal: there SIGHUP says that the terminal
is gone, and n3n stops, as before.  Ctrl-C (SIGINT) and SIGTERM stop it as
always.

It loads the configuration as at its start - the file, the environment,
the same command line - and compares it, option by option, with what runs.
What differs and can change while running is applied at once:

- `community.supernode` (an edge): new supernodes are tried, those given no
  more are dropped; the edge moves on if its current one is gone
- `connection.allow_p2p`, `connection.description` (not with user/password
  authentication, where it is the user name), `connection.local_discovery`,
  `connection.punch_ports`, `connection.punch_ttl`,
  `connection.register_interval`, `connection.register_pkt_ttl`,
  `connection.supernode_selection`, `connection.tcp_fallback`,
  `connection.watch_network`
- `filter.allow_multicast`, `filter.allow_routing`
- `logging.verbose`, `management.password`
- a supernode's communities: `[community NAME]` sections,
  `supernode.community_file` and `supernode.community_regex`; the
  community file is read again in any case, as `reload_communities` does

Everything else - the community, its key and cipher, `connection.bind`, the
TAP device and its address, `daemon.*` and so on - waits for a restart: the
log, and the answer of `n3nctl reload`, name those options, and the next
reload names them again until then:

```
$ n3nctl -k PASSWORD reload
{
    "applied": ["connection.register_interval"],
    "loaded": true,
    "restart": ["tuntap.address"]
}
```

Filter rules (`filter.rule`) are not compared yet: changing them needs a
restart, and a reload does not say so.

If the configuration cannot be loaded, nothing changes (`"loaded": false`).
Note that n3n drops its privileges after the start (`daemon.userid`, 65534
by default): the configuration file has to be readable for that user then,
or a reload finds none.
