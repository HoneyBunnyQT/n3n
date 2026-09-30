/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * How the edge's NAT maps its sockets, as its supernodes see it - see
 * natclass.h
 */

#include <stdio.h>           // for snprintf
#include <string.h>          // for memset, memcmp

#include "n2n.h"             // for sock_equal
#include "natclass.h"


void nat_view_reset (struct nat_view *view, uint16_t local_port) {

    memset(view, 0, sizeof(*view));
    view->local_port = local_port;
}


static bool same_address (const n3n_sock_t *a, const n3n_sock_t *b) {

    if(a->family != b->family) {
        return false;
    }
    if(a->family == AF_INET) {
        return memcmp(a->addr.v4, b->addr.v4, IPV4_SIZE) == 0;
    }
    return memcmp(a->addr.v6, b->addr.v6, IPV6_SIZE) == 0;
}


// Sort the fresh samples into a class. With too few of them to tell, the class
// stays what it was: the NAT is the same, the supernodes just did not all
// answer lately.
static bool classify (struct nat_view *view, time_t now) {

    const struct nat_sample *first = NULL;
    int count = 0;
    int destinations = 0;   // distinct supernode addresses, whatever the port
    bool several = false;
    bool kept = true;
    uint16_t lo = UINT16_MAX;
    uint16_t hi = 0;
    enum nat_class nat_class;

    for(int i = 0; i < NAT_SAMPLES; i++) {
        const struct nat_sample *s = &view->sample[i];
        if(!s->when || (now - s->when > NAT_SAMPLE_AGE)) {
            continue;
        }
        count++;
        if(!first) {
            first = s;
        } else if(!same_address(&s->seen, &first->seen)) {
            several = true;
        }
        int j;
        for(j = 0; j < i; j++) {
            const struct nat_sample *t = &view->sample[j];
            if(t->when && (now - t->when <= NAT_SAMPLE_AGE) && same_address(&t->to, &s->to)) {
                break;
            }
        }
        if(j == i) {
            destinations++;
        }
        lo = (s->seen.port < lo) ? s->seen.port : lo;
        hi = (s->seen.port > hi) ? s->seen.port : hi;
        kept = kept && (s->seen.port == view->local_port);
    }

    if(!count) {
        nat_class = NAT_UNKNOWN;
    } else if(several) {
        nat_class = NAT_SEVERAL_ADDRESSES;
    } else if(lo != hi) {
        // a different port even for another port of the same supernode
        nat_class = NAT_HARD;
    } else if(destinations >= 2) {
        // Only one port towards two addresses: towards two ports of one
        // address, a NAT that maps per destination address would show one
        // port too
        nat_class = NAT_EASY;
    } else {
        return false;
    }

    bool changed = (nat_class != view->nat_class) ||
                   ((nat_class == NAT_EASY) && (kept != view->port_kept));
    view->nat_class = nat_class;
    view->port_kept = (nat_class == NAT_EASY) && kept;
    view->port_lo = (nat_class == NAT_HARD) ? lo : 0;
    view->port_hi = (nat_class == NAT_HARD) ? hi : 0;
    return changed;
}


bool nat_view_add (struct nat_view *view, const n3n_sock_t *to, const n3n_sock_t *seen, time_t now) {

    struct nat_sample *slot = NULL;

    for(int i = 0; i < NAT_SAMPLES; i++) {
        if(view->sample[i].when && sock_equal(&view->sample[i].to, to)) {
            slot = &view->sample[i];
            break;
        }
    }
    if(slot && !sock_equal(&slot->seen, seen)) {
        // The NAT maps the socket anew towards this supernode: the mapping
        // timed out, or there is a new public address. The other samples are
        // as old as the old mapping, so they go too, and the class waits
        // for the next PONGs.
        memset(view->sample, 0, sizeof(view->sample));
        slot = &view->sample[0];
    }
    if(!slot) {
        // an unused slot, or else the oldest
        slot = &view->sample[0];
        for(int i = 1; i < NAT_SAMPLES; i++) {
            if(view->sample[i].when < slot->when) {
                slot = &view->sample[i];
            }
        }
    }
    slot->to = *to;
    slot->seen = *seen;
    slot->when = now;

    return classify(view, now);
}


const char *nat_view_str (char *buf, size_t size, const struct nat_view *view) {

    switch(view->nat_class) {
        case NAT_EASY:
            snprintf(buf, size, "easy (port %s)", view->port_kept ? "kept" : "changed");
            break;
        case NAT_HARD:
            snprintf(buf, size, "hard (ports %u-%u)", view->port_lo, view->port_hi);
            break;
        case NAT_SEVERAL_ADDRESSES:
            snprintf(buf, size, "several addresses");
            break;
        default:
            snprintf(buf, size, "unknown");
            break;
    }
    return buf;
}
