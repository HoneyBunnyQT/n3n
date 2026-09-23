/**
 * (C) 2007-22 - ntop.org and contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */

#if !defined( N2N_WIRE_H_ )
#define N2N_WIRE_H_

#include <stdlib.h>
#ifndef _MSC_VER
/* Not included in Visual Studio 2008 */
#include <stdint.h>
#endif

#ifndef _WIN32
#include <netinet/in.h>
#include <sys/socket.h> /* AF_INET and AF_INET6 */
#endif /* #ifndef _WIN32 */


int encode_buf (uint8_t * base,
                size_t * idx,
                const void * p,
                size_t s);

int decode_buf (uint8_t * out,
                size_t bufsize,
                const uint8_t * base,
                size_t * rem,
                size_t * idx);

int encode_common (uint8_t * base,
                   size_t * idx,
                   const n2n_common_t * common);

#define N2N_COMMON_SIZE ( sizeof(uint8_t)    /* version   */ \
                        + sizeof(uint8_t)    /* ttl       */ \
                        + sizeof(uint16_t)   /* flags     */ \
                        + N2N_COMMUNITY_SIZE /* community */ )

int decode_common (n2n_common_t * out,
                   const uint8_t * base,
                   size_t * rem,
                   size_t * idx);

// bugfix for https://github.com/ntop/n2n/issues/1029
// REVISIT: best to be removed with 4.0
int encode_sock_payload (uint8_t * base,
                         size_t * idx,
                         const n3n_sock_t * sock);

// bugfix for https://github.com/ntop/n2n/issues/1029
// REVISIT: best to be removed with 4.0
int decode_sock_payload (n3n_sock_t * sock,
                         const uint8_t * base,
                         size_t * rem,
                         size_t * idx);

int encode_REGISTER (uint8_t * base,
                     size_t * idx,
                     const n2n_common_t * common,
                     const n2n_REGISTER_t * reg);

#define N2N_SOCK_V4_SIZE ( sizeof(uint16_t) /* flags   */ \
                         + sizeof(uint16_t) /* port    */ \
                         + IPV4_SIZE        /* address */ )

#define N2N_SOCK_V6_SIZE ( N2N_SOCK_V4_SIZE        /* V4 size              */ \
                         + (IPV6_SIZE - IPV4_SIZE) /* type size difference */ )

#define N2N_REGISTER_SIZE ( sizeof(uint32_t) /* cookie      */ \
                          + N2N_MAC_SIZE     /* dst mac     */ \
                          + N2N_MAC_SIZE     /* src mac     */ \
                          + sizeof(uint32_t) /* net addr    */ \
                          + sizeof(uint8_t)  /* net bitlen  */ \
                          + N2N_DESC_SIZE    /* dev desc    */ )

int decode_REGISTER (n2n_REGISTER_t * pkt,
                     const n2n_common_t * cmn, /* info on how to interpret it */
                     const uint8_t * base,
                     size_t * rem,
                     size_t * idx);

int encode_REGISTER_SUPER (uint8_t * base,
                           size_t * idx,
                           const n2n_common_t * common,
                           const n2n_REGISTER_SUPER_t * reg);

int decode_REGISTER_SUPER (n2n_REGISTER_SUPER_t * pkt,
                           const n2n_common_t * cmn, /* info on how to interpret it */
                           const uint8_t * base,
                           size_t * rem,
                           size_t * idx);

int encode_UNREGISTER_SUPER (uint8_t *base,
                             size_t *idx,
                             const n2n_common_t *common,
                             const n2n_UNREGISTER_SUPER_t *unreg);

int decode_UNREGISTER_SUPER (n2n_UNREGISTER_SUPER_t *unreg,
                             const n2n_common_t *cmn, /* info on how to interpret it */
                             const uint8_t *base,
                             size_t *rem,
                             size_t *idx);

int encode_REGISTER_ACK (uint8_t * base,
                         size_t * idx,
                         const n2n_common_t * common,
                         const n2n_REGISTER_ACK_t * reg);

#define N2N_REGISTER_ACK_SIZE ( sizeof(uint32_t) /* cookie      */ \
                              + N2N_MAC_SIZE     /* dst mac     */ \
                              + N2N_MAC_SIZE     /* src mac     */ )

int decode_REGISTER_ACK (n2n_REGISTER_ACK_t * pkt,
                         const n2n_common_t * cmn, /* info on how to interpret it */
                         const uint8_t * base,
                         size_t * rem,
                         size_t * idx);

int encode_REGISTER_SUPER_ACK (uint8_t * base,
                               size_t * idx,
                               const n2n_common_t * cmn,
                               const n2n_REGISTER_SUPER_ACK_t * reg,
                               uint8_t * tmpbuf);

#define N2N_REGISTER_SUPER_ACK_SIZE ( sizeof(uint32_t) /* cookie      */ \
                                    + N2N_MAC_SIZE     /* src mac     */ \
                                    + sizeof(uint32_t) /* net addr    */ \
                                    + sizeof(uint8_t)  /* net bitlen  */ \
                                    + sizeof(uint16_t) /* life time   */ \
                                    + sizeof(uint16_t) /* auth scheme */ \
                                    + sizeof(uint16_t) /* token size  */ \
                                    + sizeof(uint8_t)  /* num sn      */ \
                                    + sizeof(uint32_t) /* key time    */ )

int decode_REGISTER_SUPER_ACK (n2n_REGISTER_SUPER_ACK_t * reg,
                               const n2n_common_t * cmn, /* info on how to interpret it */
                               const uint8_t * base,
                               size_t * rem,
                               size_t * idx,
                               uint8_t * tmpbuf);

int encode_REGISTER_SUPER_NAK (uint8_t * base,
                               size_t * idx,
                               const n2n_common_t * cmn,
                               const n2n_REGISTER_SUPER_NAK_t * nak);

int decode_REGISTER_SUPER_NAK (n2n_REGISTER_SUPER_NAK_t * nak,
                               const n2n_common_t * cmn, /* info on how to interpret it */
                               const uint8_t * base,
                               size_t * rem,
                               size_t * idx);

socklen_t fill_sockaddr (struct sockaddr * addr,
                         socklen_t addrlen,
                         const n3n_sock_t * sock);

int fill_n3nsock (n3n_sock_t* sock, const struct sockaddr* sa);

int encode_PACKET (uint8_t * base,
                   size_t * idx,
                   const n2n_common_t * common,
                   const n2n_PACKET_t * pkt);

#define N2N_PACKET_SIZE ( N2N_MAC_SIZE    /* src mac     */ \
                        + N2N_MAC_SIZE    /* dst mac     */ \
                        + sizeof(uint8_t) /* compression */ \
                        + sizeof(uint8_t) /* transfrom   */ )

int decode_PACKET (n2n_PACKET_t * pkt,
                   const n2n_common_t * cmn, /* info on how to interpret it */
                   const uint8_t * base,
                   size_t * rem,
                   size_t * idx);

int encode_PEER_INFO (uint8_t * base,
                      size_t * idx,
                      const n2n_common_t * common,
                      const n2n_PEER_INFO_t * pkt);

int decode_PEER_INFO (n2n_PEER_INFO_t * pkt,
                      const n2n_common_t * cmn, /* info on how to interpret it */
                      const uint8_t * base,
                      size_t * rem,
                      size_t * idx);

int encode_QUERY_PEER (uint8_t * base,
                       size_t * idx,
                       const n2n_common_t * common,
                       const n2n_QUERY_PEER_t * pkt);

int decode_QUERY_PEER (n2n_QUERY_PEER_t * pkt,
                       const n2n_common_t * cmn, /* info on how to interpret it */
                       const uint8_t * base,
                       size_t * rem,
                       size_t * idx);

#endif /* #if !defined( N2N_WIRE_H_ ) */
