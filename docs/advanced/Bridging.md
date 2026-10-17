<!--
SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright Dylan Yee
SPDX-FileCopyrightText: Copyright Hamish Coleman
-->

# Bridging (Linux)

## General Remarks

`edge`s can be part of network bridges. As such, n3n can connect otherwise un-connected LANs.

## How To Use with `brctl`

... requires `-r`
... general syntax 
... one example connecting two remote sites' LANs, including commands

## How it works

... remembers peer info MAC
... ageing
... internal MAC replaced inside usually encrypted packet data (no disclosure then)
... initial learning

## Broadcasts

The community is one broadcast domain: a broadcast from a device behind one
edge's bridge reaches every edge, and the devices behind their bridges.
Multicast does the same where the edges allow it
(`filter.allow_multicast`), also that of protocols without IP, such as the
discovery of PROFINET devices (DCP); the IEEE 802.1 link-local frames
(spanning tree, LLDP and the like) never pass, as through any bridge.  See
[Multicast](../configure/TapConfiguration.md#multicast).

## Compile Time Option

The `-r`option at edge does not differentiate between the use cases _routing_ and _bridging_. In case the MAC-learning and MAC-replacing bridging code
interfers with some special routing scenario, removal of the `-DHAVE_BRIDGING_SUPPORT` from `Makefile` file disables it at compile time.
