/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The edge with a TUN device, see tun.c
 */

#ifndef N3N_TUN_H
#define N3N_TUN_H

#include <stddef.h>
#include <stdint.h>

struct n3n_runtime_data;

// An IP packet read from the device, at buf + 14 with len bytes, made a
// frame at buf: its length, or 0 if there is nothing to send.  Instead of a
// packet to an address whose MAC is unknown, the frame is an ARP request.
size_t tun_to_frame (struct n3n_runtime_data *eee, uint8_t *buf, size_t len);

// A frame for the device: its IP packet written with write_fn, ARP answered
// or learned from, the rest dropped.  Returns len when it is done with the
// frame, else what write_fn returned.
int tun_from_frame (struct n3n_runtime_data *eee, const uint8_t *frame, int len,
                    int (*write_fn)(struct n3n_runtime_data *eee, uint8_t *buf, int len));

#endif
