/*
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Decoding a whole PDU, for the fuzz targets - see fuzz.h
 */

#include <string.h>        // for memset
#include "fuzz.h"
#include "n2n.h"           // for N2N_PKT_BUF_SIZE
#include "n2n_wire.h"      // for decode_*, encode_*

const uint8_t fuzz_community[N2N_COMMUNITY_SIZE] = FUZZ_COMMUNITY;

int fuzz_decode_pdu (const uint8_t *buf, size_t size) {

    static uint8_t out[N2N_PKT_BUF_SIZE * 2];
    uint8_t tmpbuf[REG_SUPER_ACK_PAYLOAD_SPACE];
    n2n_common_t cmn;
    size_t rem = size;
    size_t idx = 0;
    size_t oidx = 0;
    int rc;

    memset(&cmn, 0, sizeof(cmn));
    if(decode_common(&cmn, buf, &rem, &idx) < 0) {
        return -1;
    }

    switch(cmn.pc) {
        case MSG_TYPE_REGISTER: {
            n2n_REGISTER_t m;
            rc = decode_REGISTER(&m, &cmn, buf, &rem, &idx);
            if(rc >= 0) {
                encode_REGISTER(out, &oidx, &cmn, &m);
            }
            break;
        }
        case MSG_TYPE_REGISTER_ACK: {
            n2n_REGISTER_ACK_t m;
            rc = decode_REGISTER_ACK(&m, &cmn, buf, &rem, &idx);
            if(rc >= 0) {
                encode_REGISTER_ACK(out, &oidx, &cmn, &m);
            }
            break;
        }
        case MSG_TYPE_PACKET: {
            n2n_PACKET_t m;
            rc = decode_PACKET(&m, &cmn, buf, &rem, &idx);
            if(rc >= 0) {
                encode_PACKET(out, &oidx, &cmn, &m);
            }
            break;
        }
        case MSG_TYPE_REGISTER_SUPER: {
            n2n_REGISTER_SUPER_t m;
            rc = decode_REGISTER_SUPER(&m, &cmn, buf, &rem, &idx);
            if(rc >= 0) {
                encode_REGISTER_SUPER(out, &oidx, &cmn, &m);
            }
            break;
        }
        case MSG_TYPE_UNREGISTER_SUPER: {
            n2n_UNREGISTER_SUPER_t m;
            rc = decode_UNREGISTER_SUPER(&m, &cmn, buf, &rem, &idx);
            if(rc >= 0) {
                encode_UNREGISTER_SUPER(out, &oidx, &cmn, &m);
            }
            break;
        }
        case MSG_TYPE_REGISTER_SUPER_ACK: {
            n2n_REGISTER_SUPER_ACK_t m;
            rc = decode_REGISTER_SUPER_ACK(&m, &cmn, buf, &rem, &idx, tmpbuf);
            if(rc >= 0) {
                // the supernodes it lists, as the edge and a federation
                // member read them
                n2n_REGISTER_SUPER_ACK_payload_t *p = (n2n_REGISTER_SUPER_ACK_payload_t *)tmpbuf;
                int i;

                for(i = 0; i < m.num_sn; i++, p++) {
                    n3n_sock_t sock;
                    size_t prem = sizeof(p->sock);
                    size_t pidx = 0;

                    decode_sock_payload(&sock, p->sock, &prem, &pidx);
                }
                encode_REGISTER_SUPER_ACK(out, &oidx, &cmn, &m, tmpbuf);
            }
            break;
        }
        case MSG_TYPE_REGISTER_SUPER_NAK: {
            n2n_REGISTER_SUPER_NAK_t m;
            rc = decode_REGISTER_SUPER_NAK(&m, &cmn, buf, &rem, &idx);
            if(rc >= 0) {
                encode_REGISTER_SUPER_NAK(out, &oidx, &cmn, &m);
            }
            break;
        }
        case MSG_TYPE_PEER_INFO: {
            n2n_PEER_INFO_t m;
            rc = decode_PEER_INFO(&m, &cmn, buf, &rem, &idx);
            if(rc >= 0) {
                encode_PEER_INFO(out, &oidx, &cmn, &m);
            }
            break;
        }
        case MSG_TYPE_QUERY_PEER: {
            n2n_QUERY_PEER_t m;
            rc = decode_QUERY_PEER(&m, &cmn, buf, &rem, &idx);
            if(rc >= 0) {
                encode_QUERY_PEER(out, &oidx, &cmn, &m);
            }
            break;
        }
        default:
            return -1;
    }

    // a decoder must never claim more than there was
    if((idx > size) || (rem > size)) {
        __builtin_trap();
    }
    return rc;
}
