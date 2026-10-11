/*
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Fuzz target: a v3tcp connection as the main loop reads it - the bytes
 * come in pieces through a socket, conn_read() (libs/connslot) puts them
 * together until a PDU with its length in front is complete, and
 * mainloop_v3tcp_pdus() (src/mainloop.c) hands over each one in the buffer
 * and keeps the start of the next.  What comes out goes to the decoders,
 * as from a supernode's or an edge's TCP connection.  See README.md.
 *
 * The input is pieces, each a byte with its length and then as many bytes:
 * each piece is written to the socket and read by the connection at once,
 * so that the fuzzer picks where the PDUs are cut.
 */

#include <connslot/connslot.h>   // for conn_t, conn_init, conn_read
#include <n3n/logging.h>         // for setTraceLevel
#include <n3n/mainloop.h>        // for mainloop_v3tcp_pdus
#include <stdlib.h>              // for malloc, free
#include <string.h>              // for memcpy
#include <sys/socket.h>          // for socketpair
#include <unistd.h>              // for close, write
#include "fuzz.h"
#include "pdu_in.h"              // for pdu_header_plain

static conn_t conn;

int LLVMFuzzerInitialize (int *argc, char ***argv) {

    // what the code logs about bad input: not the point here, and slow
    setTraceLevel(-1);

    // the sizes the main loop gives its connections (connlist_alloc())
    return conn_init(&conn, 4000, 1000);
}

static int pdu (void *arg, uint8_t *pdu, int size) {

    uint8_t *copy;

    // what is handed over has to lie within what was received
    if((size < 0) || ((pdu - (uint8_t *)conn.request->str) + (size_t)size > sb_len(conn.request))) {
        __builtin_trap();
    }
    // a copy of its own, so that a read past the end shows with ASan
    copy = malloc(size ? size : 1);
    memcpy(copy, pdu, size);
    if(pdu_header_plain(copy, size) || (size < 24)) {
        fuzz_decode_pdu(copy, size);
    }
    free(copy);
    return 0;
}

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size) {

    int fds[2];
    size_t at = 0;

    if(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        return 0;
    }
    conn_zero(&conn);
    conn_accept(&conn, fds[1], CONN_PROTO_BE16LEN);

    while(at < size) {
        size_t piece = data[at++];

        if(piece > size - at) {
            piece = size - at;
        }
        if(piece && (write(fds[0], data + at, piece) != (ssize_t)piece)) {
            break;
        }
        at += piece;

        // all of it, as the main loop would over several rounds
        while(conn_read(&conn, fds[1]) > 0) {
            if(conn.state == CONN_READY) {
                mainloop_v3tcp_pdus(&conn, pdu, NULL);
            }
        }
        if((conn.state == CONN_ERROR) || (conn.state == CONN_CLOSED)) {
            break;
        }
    }
    close(fds[0]);
    close(fds[1]);
    return 0;
}
