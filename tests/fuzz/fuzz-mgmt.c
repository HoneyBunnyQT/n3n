/*
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Fuzz target: a request to the management interface (src/management.c),
 * as the main loop hands a complete one over: the HTTP request line and
 * headers (the endpoint, Authorization, Origin, Connection), and for the
 * JSON-RPC endpoints the body (libs/connslot/jsonrpc.c) with its method
 * and params.  See README.md.
 *
 * The management interface is reachable only locally (a unix socket, or a
 * TCP port the operator opens), so this is about not crashing on a bad
 * local request, not a path a remote peer can take.
 *
 * The first byte of the input picks the runtime it goes to - a supernode's
 * or an edge's, both as their configuration defaults make them, without
 * sockets or peers - the rest is the request.  The connection has no
 * socket (fd -1): the handlers build their reply as always, but it is not
 * flushed - the main loop and connslot do that, and fuzz-tcp drives the
 * connection's own reading and writing.  Without the socket the endpoints
 * that hand their fd off (the event stream) behave as they do once the
 * main loop has taken it: a reply flush to fd -1 is a no-op, as after the
 * handoff.
 */

#include <connslot/connslot.h>   // for conn_t, conn_init
#include <n3n/edge.h>            // for edge_init_conf_defaults
#include <n3n/initfuncs.h>       // for n3n_initfuncs
#include <n3n/logging.h>         // for setTraceLevel
#include <n3n/supernode.h>       // for sn_init_conf_defaults
#include <stdbool.h>             // for bool
#include <string.h>              // for memcpy
#include "fuzz.h"
#include "management.h"          // for mgmt_api_handler
#include "n2n.h"                 // for struct n3n_runtime_data

static struct n3n_runtime_data relay;
static struct n3n_runtime_data edge;
static const struct n3n_role_ops no_ops;
static bool keep_running = true;
static conn_t conn;

int LLVMFuzzerInitialize (int *argc, char ***argv) {

    // what the code logs about bad input: not the point here, and slow
    setTraceLevel(-1);
    n3n_initfuncs();

    sn_init_conf_defaults(&relay, "_FUZZ");
    relay.keep_running = &keep_running;

    edge_init_conf_defaults(&edge.conf, "_FUZZ");
    edge.conf.is_edge = true;
    edge.ops = &no_ops;
    edge.keep_running = &keep_running;

    // the sizes the main loop gives its connections (connlist_alloc())
    return conn_init(&conn, 4000, 1000);
}

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size) {

    struct n3n_runtime_data *rt;

    if(size < 1) {
        return 0;
    }
    rt = (data[0] & 1) ? &edge : &relay;
    data++;
    size--;

    // as conn_read() leaves a request ready: in the buffer, with a NUL
    // after it; no socket, see the note above
    conn_zero(&conn);
    conn.proto = CONN_PROTO_HTTP;
    conn.fd = -1;
    if(size > conn.request->capacity_max - 1) {
        size = conn.request->capacity_max - 1;
    }
    if(size >= conn.request->capacity) {
        sb_realloc(&conn.request, size + 1);
    }
    memcpy(conn.request->str, data, size);
    conn.request->wr_pos = size;
    conn.request->str[size] = '\0';
    conn.state = CONN_READY;

    mgmt_api_handler(rt, &conn);

    // the page's buttons change the verbosity; the stop ones the flag
    setTraceLevel(-1);
    keep_running = true;
    return 0;
}
