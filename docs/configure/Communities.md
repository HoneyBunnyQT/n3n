<!--
SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright 2022 n2n contributors
SPDX-FileCopyrightText: Copyright Logan oos Even
SPDX-FileCopyrightText: Copyright Hamish Coleman
-->

# Communities


## Names

As communities designate virtual networks, they must be distinguishable from
each other. Its their name that makes them distinguishable and which therefore
should be unique per network. The community name is composed of 19 byte-sized
characters, terminated with one additional NUL byte - totalling up to a maximum
of 20 bytes.  Hence, the community name can never contain a NUL byte.  There
are some other characters that cannot be used, namely `. * + ? [ ] \`.

To make full use of character space, hex values could be used, e.g. from Linux
bash applying something like `n3n-edge … -c $(echo -en '\x3a\x3b\x4a\x6a\xfa') …`
as the command line syntax. If used with a configuration file, the bytes must
be directly filled as characters into the corresponding `community.name` option

Apart from command line `-c` and configuration file, the community name can be
supplied through the `N3N_COMMUNITY` environment variable. This might prove
useful to hide the community name from command line if used with header
encryption enabled, see below.


## Restrict Supernode Access

By default, a supernode offers its service to all communities and allows them to connect. If a self-setup supernode shall handle certain communities only, the supernode can be given a list of allowed communities. This list is a simple text file containg the allowed community names, one per line:

```
 # community.list (a text file)
 -----------------------------------------------------
 myCommunity
 yourCommunity
```

This file is provided to the supernode through the `supernode.community_file`
option. This example would allow the supernode to only accept connections from
communities called "myCommunity" and "yourCommunity", these are fixed-name
communities.


## Communities in the Configuration File

Instead of the community file, or along with it, the communities can be given
in the supernode's configuration file, one section each, with the name of the
community after the section name:

```
[community myCommunity]

[community yourCommunity]
network = 10.77.0.0/24
user = logan nHWum+r42k1qDXdIeH-WFKeylK5UyLStRzxofRNAgpG

[supernode]
community_regex = myCommunity[0-9][0-9]
```

- `network` is the address range the auto ip address service hands out
  addresses from, as the range after a name in the community file.  Without
  it, the supernode chooses one between `supernode.auto_ip_min` and
  `supernode.auto_ip_max`.
- `user` allows a user, as the `* <username> <public key>` lines of the
  community file do, only without the `*`; see
  [Authentication](Authentication.md).  It may be given more than once.
- `community_regex` in the `[supernode]` section allows the communities
  matching a regular expression, see below.  It may be given more than once.
- `header_encryption = true` marks the community as one with
  [header encryption](#header-encryption) from the start, instead of when the
  first packet shows it.

A section name can only have letters and digits, and in the community name
after it also `_ - .` (but not at its start).  For any other community name, a
`name` option in the section gives the actual name:

```
[community lab]
name = my lab!
```

The supernode joins the communities of the sections with those of the
community file.  If a community is in both, the section wins and the
supernode logs so; the file only gives what the section leaves out, its
address range if the section has no `network`, its users if the section has
no `user`.  Issuing the `reload_communities` command to
the management port reads the community file again, but not the
configuration file.

An edge joins exactly one community: the one of `[community]`, or of its only
`[community NAME]` section.  More than one community makes the edge stop with
an error.


## Somewhat Flexible Community Names

If you want to allow all community names from a certain name range, e.g. from "myCommunity00" to "myCommunity99", the `community.list` file (or whatever you name it) could look as follows:

```
 # community.list (a text file)
 -----------------------------------------------------
 myCommunity[0-9][0-9]
```

Advanced users recognize the so called regular expression. To prevent users from stop reading, the author did not dare to name this section "Regular Expressions". Anyway, community names can be provided as regular expressions using the following placeholders:

```
 '.'        Dot, matches any character
 '*'        Asterisk, match zero or more of previous element (greedy)
 '+'        Plus, match one or more of previous element (greedy)
 '?'        Question, match zero or one (non-greedy)
 '[abc]'    Character class, match if one of {'a', 'b', 'c'}
 '[^abc]'   Inverted class, match if NOT one of {'a', 'b', 'c'}  (feature is currently broken)
 '[a-zA-Z]' Character ranges, the character set of the ranges { a-z | A-Z }
 '\s'       Whitespace, \t \f \r \n \v and spaces
 '\S'       Non-whitespace
 '\w'       Alphanumeric, [a-zA-Z0-9_]
 '\W'       Non-alphanumeric
 '\d'       Digits, [0-9]
 '\D'       Non-digits
```

Knowing this, we can as well express the exemplary `community.list` above the following way:

```
 # community.list (a text file)
 -----------------------------------------------------
 myCommunity\d\d
```

Also, as the `. * + ? [ ] \` characters indicate parts of regular expressions, we now understand why those are not allowed in fixed-name community names.


## Header Encryption

By default, the community name is transmitted in plain witch each packet. So, a fixed-name community might keep your younger siblings out of your community (as long as they do not know the community name) but sniffing attackers will find out the community name. Using this name, they will be able to access it by just connecting to the supernode then.

[Header encryption](../internals/Crypto.md#header) can be enabled to prevent plain transmission. It is important to understand that header encryption, if enabled, only works on fixed-name communities. It will not work on community names described by regular expressions.

On the other hand, the provision of fixed-name communities blocks all other, non-listed communities. To allow a mixed operation of certain encrypted and hence fixed-name communities along with all other open communities, the following "trick" can be applied:

```
 # community.list (a text file)
 -----------------------------------------------------
 mySecretCom
 .*
```

This is not really a trick but just making use of a very permissive regular expression at the second line.
