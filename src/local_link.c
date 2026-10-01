/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The link between an edge and the supernode in the same process - see
 * local_link.h
 */

#include <n3n/logging.h>        // for traceEvent
#include <string.h>             // for memcpy, memset

#include "edge_utils.h"         // for edge_process_pdu
#include "local_link.h"
#include "n2n_define.h"         // for N2N_PKT_BUF_SIZE

#ifdef _WIN32
#include "win32/defs.h"
#else
#include <arpa/inet.h>          // for htonl
#include <netinet/in.h>         // for sockaddr_in, INADDR_LOOPBACK
#endif

// PDUs that are on their way.  A registration and its answer, the PDUs of
// a burst of frames from the TAP device: the queue needs little room, as it
// is emptied every time round the mainloop.
#define LOCAL_LINK_SLOTS 64

// Rounds of handing on PDUs in one go, in case two handlers keep answering
// each other
#define LOCAL_LINK_DRAIN_MAX (4 * LOCAL_LINK_SLOTS)

static struct n3n_runtime_data *link_relay;
static struct n3n_runtime_data *link_edge;

static struct local_link_pdu {
    bool to_edge;
    size_t size;
    uint8_t buf[N2N_PKT_BUF_SIZE];
} queue[LOCAL_LINK_SLOTS];
static unsigned int queue_head;     // the next to hand on
static unsigned int queue_tail;     // the next free one


void local_link_init (struct n3n_runtime_data *relay, struct n3n_runtime_data *edge) {

    link_relay = relay;
    link_edge = edge;
    queue_head = queue_tail = 0;
}


void local_link_sock (n3n_sock_t *out) {

    uint32_t addr = htonl(INADDR_LOOPBACK);

    memset(out, 0, sizeof(*out));
    out->family = AF_INET;
    out->type = SOCK_DGRAM;
    out->port = 0;
    memcpy(out->addr.v4, &addr, IPV4_SIZE);
}


bool local_link_is_sock (const n3n_sock_t *sock) {

    n3n_sock_t link;

    local_link_sock(&link);
    return (sock->family == AF_INET) && (sock->port == 0)
           && !memcmp(sock->addr.v4, link.addr.v4, IPV4_SIZE);
}


static bool queue_pdu (bool to_edge, const uint8_t *buf, size_t size) {

    struct local_link_pdu *p;

    if(!link_relay || !link_edge) {
        return false;
    }
    if((size > sizeof(p->buf)) || (queue_tail - queue_head >= LOCAL_LINK_SLOTS)) {
        traceEvent(TRACE_DEBUG, "local link: dropped a PDU of %u bytes to the %s",
                   (unsigned int)size, to_edge ? "edge" : "supernode");
        return false;
    }

    // a copy: the receiving side decrypts the header in place, and the
    // sender may use its buffer again, e.g. for the next edge of a broadcast
    p = &queue[queue_tail % LOCAL_LINK_SLOTS];
    p->to_edge = to_edge;
    p->size = size;
    memcpy(p->buf, buf, size);
    queue_tail++;
    return true;
}


bool local_link_to_relay (const uint8_t *buf, size_t size) {

    return queue_pdu(false, buf, size);
}


bool local_link_to_edge (const uint8_t *buf, size_t size) {

    return queue_pdu(true, buf, size);
}


void local_link_drain (time_t now) {

    struct sockaddr_in sa;
    struct local_link_pdu pdu;

    if(queue_head == queue_tail) {
        return;
    }

    // what either side sees as the address of the other
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;

    for(int n = 0; (n < LOCAL_LINK_DRAIN_MAX) && (queue_head != queue_tail); n++) {
        // the slot may be used again by what the handler sends
        pdu = queue[queue_head % LOCAL_LINK_SLOTS];
        queue_head++;

        if(pdu.to_edge) {
            edge_process_pdu(link_edge, (struct sockaddr *)&sa, LOCAL_LINK_FD, pdu.buf, pdu.size, now);
        } else {
            link_relay->ops->local_pdu(link_relay, (struct sockaddr *)&sa, sizeof(sa), pdu.buf, pdu.size, now);
        }
    }
}
