/**
 * SPDX-License-Identifier: GPL-3.0-only
 * SPDX-FileCopyrightText: Copyright n2n contributors
 * SPDX-FileCopyrightText: Copyright Hamish Coleman
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


#include <errno.h>           // for errno
#include <n3n/ethernet.h>    // for is_null_mac, N2N_MACSTR_SIZE
#include <n3n/logging.h>     // for traceEvent
#include <n3n/random.h>      // for n3n_rand
#include <n3n/strings.h>     // for ip_subnet_to_str, sock_to_cstr
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>          // for free, atoi, calloc, strtol
#include <string.h>          // for memcmp, memcpy, memset, strlen, strerror
#include <sys/time.h>        // for gettimeofday, timeval

#include "n2n.h"
#include "n2n_define.h"
#include "n2n_typedefs.h"
#include "n2n_wire.h"        // for fill_n3nsock

#ifdef _WIN32
#include "win32/defs.h"

#include <ws2def.h>
#else
#include <arpa/inet.h>       // for inet_ntop
#include <netinet/in.h>
#include <sys/socket.h>      // for AF_INET, PF_INET, bind, setsockopt, shut...
#endif

#ifndef _WIN32
#define closesocket(a) close(a)
#endif


/* ************************************** */

SOCKET open_socket (struct sockaddr *local_address, socklen_t addrlen, int type /* 0 = UDP, TCP otherwise */) {

    SOCKET sock_fd;
    int sockopt;
    int family;


    if(local_address) {
        family = local_address->sa_family;
    } else {
        // If no bind details provided, assume IPv4.
        family = AF_INET;
    }

    if((int)(sock_fd = socket(family, ((type == 0) ? SOCK_DGRAM : SOCK_STREAM), 0)) < 0) {
        traceEvent(TRACE_ERROR, "Unable to create socket for family %d [%s][%d]\n",
                   family, strerror(errno), sock_fd);
        return -1;
    }

#ifndef _WIN32
    /* fcntl(sock_fd, F_SETFL, O_NONBLOCK); */
#endif

    int result;

    sockopt = 1;
    result = setsockopt(
        sock_fd,
        SOL_SOCKET,
        SO_REUSEADDR,
        (char *)&sockopt,
        sizeof(sockopt)
    );
    if(result == -1) {
        traceEvent(
            TRACE_ERROR,
            "SO_REUSEADDR fd=%i, error=%s\n",
            sock_fd,
            strerror(errno)
        );
    }
#ifdef SO_REUSEPORT /* no SO_REUSEPORT in Windows / old linux versions */
    result = setsockopt(
        sock_fd,
        SOL_SOCKET,
        SO_REUSEPORT,
        (char *)&sockopt,
        sizeof(sockopt)
    );
    if(result == -1) {
        traceEvent(
            TRACE_ERROR,
            "SO_REUSEPORT fd=%i, error=%s\n",
            sock_fd,
            strerror(errno)
        );
    }
#endif
    // also allow IPv4 on IPv6 sockets
    if(family == AF_INET6) {
        sockopt = 0;
        result = setsockopt(
            sock_fd,
            IPPROTO_IPV6,
            IPV6_V6ONLY,
            (char *)&sockopt,
            sizeof(sockopt)
        );
        if(result == -1) {
            traceEvent(
                TRACE_ERROR,
                "IPV6_V6ONLY fd=%i, error=%s\n",
                sock_fd,
                strerror(errno)
            );
        }
    }

    if(!local_address) {
        // skip binding if we dont have the right details
        return(sock_fd);
    }

    if(bind(sock_fd,local_address, addrlen) == -1) {
        traceEvent(TRACE_ERROR, "Bind error on local addr [%s]\n", strerror(errno));
        // TODO: use a generic sockaddr stringify to show which bind failed
        return(-1);
    }

    return(sock_fd);
}


// the port of an IPv4 or IPv6 address, host order
static uint16_t sockaddr_port (const struct sockaddr *sa) {

    if(sa->sa_family == AF_INET) {
        return ntohs(((const struct sockaddr_in *)sa)->sin_port);
    }
    return ntohs(((const struct sockaddr_in6 *)sa)->sin6_port);
}


void close_bind_sockets (struct n3n_runtime_data *sss) {

    for(int i = 0; i < sss->bind_count; i++) {
        closesocket(sss->bind_sock[i]);
    }
    for(int i = 0; i < sss->bind_tcp_count; i++) {
        closesocket(sss->bind_tcp[i]);
    }
    sss->bind_count = 0;
    sss->bind_tcp_count = 0;
    sss->sock = -1;
    sss->relay.tcp_sock = -1;
}


// is there an IPv4 address with this port in the list, for one of these
// transports?
static bool v4_on_port (const struct n3n_bind *list, int count, uint16_t port, int transports) {

    for(int i = 0; i < count; i++) {
        if((list[i].sa.ss_family == AF_INET) && (list[i].transports & transports)
           && (sockaddr_port((const struct sockaddr *)&list[i].sa) == port)) {
            return true;
        }
    }
    return false;
}


// A UDP or TCP socket for one address of connection.bind, with SO_REUSEPORT
// for the threads to share its port
static SOCKET open_bind_socket (const struct sockaddr *sa, int type, int v6only) {

    socklen_t len = (sa->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    int one = 1;
    SOCKET fd = socket(sa->sa_family, type, 0);
#ifdef _WIN32
    if(fd == INVALID_SOCKET) {
        return -1;
    }
#else
    if(fd < 0) {
        return -1;
    }
#endif

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(one));
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (char *)&one, sizeof(one));
#endif
    if(sa->sa_family == AF_INET6) {
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&v6only, sizeof(v6only));
    }
    if(bind(fd, sa, len) != 0) {
#ifdef _WIN32
        closesocket(fd);
#else
        close(fd);
#endif
        return -1;
    }
    return fd;
}


// The sockets for the addresses of the list from connection.bind: a UDP
// socket for each address for UDP, and on the supernode (with_tcp) a TCP one
// for each address for TCP - without "udp://" or "tcp://" in front, an
// address is for both.  The first ones are also sock and tcp_sock.  The list
// needs room for N3N_BIND_MAX addresses and its end.  A [::] gets a 0.0.0.0
// on its port beside it, and an IPv6 address is IPv6 only when an IPv4 one
// has the same port and transport - the IPv4 edges on that port belong to
// that one.  Without IPv6 on the system its addresses are left out, but a
// [::] whose port no IPv4 address has listens on 0.0.0.0 instead, as the
// default [::] always did, logged at missing_v6_level.  Anything else that
// stops a socket from opening is an error, and so is a list without an
// address for UDP.
int n3n_open_bind_sockets (struct n3n_runtime_data *sss, struct n3n_bind *list,
                           bool with_tcp, int missing_v6_level) {

    int count = 0;
    n3n_sock_str_t sockbuf;
    n3n_sock_t sock;

    while((count < N3N_BIND_MAX) && list[count].sa.ss_family) {
        count++;
    }

    SOCKET probe = socket(AF_INET6, SOCK_DGRAM, 0);
    if((probe == -1) && (errno == EAFNOSUPPORT)) {
        for(int i = 0; i < count;) {
            struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&list[i].sa;
            uint16_t port;

            if(sa6->sin6_family != AF_INET6) {
                i++;
                continue;
            }
            port = ntohs(sa6->sin6_port);
            if(IN6_IS_ADDR_UNSPECIFIED(&sa6->sin6_addr) && !v4_on_port(list, count, port, list[i].transports)) {
                struct sockaddr_in *sa4 = (struct sockaddr_in *)&list[i].sa;

                memset(&list[i].sa, 0, sizeof(list[i].sa));
                sa4->sin_family = AF_INET;
                sa4->sin_port = htons(port);
                sa4->sin_addr.s_addr = htonl(INADDR_ANY);
                traceEvent(missing_v6_level, "no IPv6 on this system, listening on 0.0.0.0:%u instead of [::]", port);
                i++;
                continue;
            }
            fill_n3nsock(&sock, (struct sockaddr *)&list[i].sa);
            traceEvent(missing_v6_level, "no IPv6 on this system, leaving out %s", sock_to_cstr(sockbuf, &sock));
            memmove(&list[i], &list[i + 1], (count - i) * sizeof(list[i]));   // with the end of the list
            count--;
        }
    } else if(probe != -1) {
#ifdef _WIN32
        closesocket(probe);
#else
        close(probe);
#endif
    }
    if(!count) {
        traceEvent(TRACE_ERROR, "no address of connection.bind can be used");
        return -1;
    }

    // [::] - also the default, and what a port alone stands for - is for
    // IPv4 as well: on a socket of its own at 0.0.0.0, so that IPv4 edges
    // are no mapped IPv6 addresses to it, unless an IPv4 address with that
    // port and transport is given already
    for(int i = 0; i < count; i++) {
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&list[i].sa;
        uint16_t port;

        if((sa6->sin6_family != AF_INET6) || !IN6_IS_ADDR_UNSPECIFIED(&sa6->sin6_addr)) {
            continue;
        }
        port = ntohs(sa6->sin6_port);
        if(v4_on_port(list, count, port, list[i].transports) || (count == N3N_BIND_MAX)) {
            continue;
        }
        memmove(&list[i + 2], &list[i + 1], (count - i) * sizeof(list[i]));   // with the end of the list
        struct sockaddr_in *sa4 = (struct sockaddr_in *)&list[i + 1].sa;
        memset(&list[i + 1], 0, sizeof(list[i + 1]));
        sa4->sin_family = AF_INET;
        sa4->sin_port = htons(port);
        sa4->sin_addr.s_addr = htonl(INADDR_ANY);
        list[i + 1].transports = list[i].transports;
        count++;
        i++;
    }

    for(int i = 0; i < count; i++) {
        struct sockaddr *sa = (struct sockaddr *)&list[i].sa;
        int transports = list[i].transports;
        bool udp = transports & N3N_TRANSPORT_UDP;
        bool tcp = false;
        // one per transport: an IPv4 address for UDP only does not make
        // an IPv6 one for TCP only IPv6 only
        int v6only_udp = (sa->sa_family == AF_INET6) && v4_on_port(list, count, sockaddr_port(sa), N3N_TRANSPORT_UDP);
        int v6only_tcp = (sa->sa_family == AF_INET6) && v4_on_port(list, count, sockaddr_port(sa), N3N_TRANSPORT_TCP);

        fill_n3nsock(&sock, sa);
        sock_to_cstr(sockbuf, &sock);

        if(udp) {
            int n = sss->bind_count;
            sss->bind_sock[n] = open_bind_socket(sa, SOCK_DGRAM, v6only_udp);
            if(sss->bind_sock[n] < 0) {
                // e.g. a port another program has
                traceEvent(TRACE_ERROR, "cannot listen on UDP %s: %s", sockbuf, strerror(errno));
                close_bind_sockets(sss);
                return -1;
            }
            sss->bind_family[n] = sa->sa_family;
            sss->bind_v6only[n] = v6only_udp;
            sss->bind_count++;
        }
#ifdef N2N_HAVE_TCP
        if(with_tcp && (transports & N3N_TRANSPORT_TCP)) {
            int n = sss->bind_tcp_count;
            sss->bind_tcp[n] = open_bind_socket(sa, SOCK_STREAM, v6only_tcp);
            if((sss->bind_tcp[n] < 0) || (listen(sss->bind_tcp[n], N2N_TCP_BACKLOG_QUEUE_SIZE) != 0)) {
                traceEvent(TRACE_ERROR, "cannot listen on TCP %s: %s", sockbuf, strerror(errno));
                if(sss->bind_tcp[n] >= 0) {
                    closesocket(sss->bind_tcp[n]);
                }
                close_bind_sockets(sss);
                return -1;
            }
            sss->bind_tcp_count++;
            tcp = true;
        }
#endif
        if(udp || tcp) {
            traceEvent(TRACE_NORMAL, "listening on %s %s%s",
                       (udp && tcp) ? "UDP and TCP" : udp ? "UDP" : "TCP", sockbuf,
                       ((udp && v6only_udp) || (tcp && v6only_tcp)) ? " (IPv6 only)" : "");
        }
    }
    if(!sss->bind_count) {
        traceEvent(TRACE_ERROR, "connection.bind has no address for UDP");
        close_bind_sockets(sss);
        return -1;
    }
    sss->sock = sss->bind_sock[0];
    sss->relay.tcp_sock = sss->bind_tcp_count ? sss->bind_tcp[0] : -1;
    return 0;
}


// TO: instead of this 'output control' for every packet, move towards
//     ingress control so incoming sockets get checked befored being stored
//     and can be used with confidence (and no further checks)
socklen_t prepare_sockaddr_for_send (struct sockaddr_storage *out_sa,
                                     int sending_family,
                                     const struct sockaddr *src_sa) {

    // easy case first
    if(sending_family == src_sa->sa_family) {
        if(src_sa->sa_family == AF_INET) {
            //
            *(struct sockaddr_in *)out_sa = *(const struct sockaddr_in *)src_sa;
            return sizeof(struct sockaddr_in);
        } else if(src_sa->sa_family == AF_INET6) {
            *(struct sockaddr_in6 *)out_sa = *(const struct sockaddr_in6 *)src_sa;
            return sizeof(struct sockaddr_in6);
        }
    }

    // assumption: every IPv6 socket is opened dual-stack
    if(sending_family == AF_INET6 && src_sa->sa_family == AF_INET) {
        struct sockaddr_in6 sa6 = {0};
        const struct sockaddr_in *sa4 = (const struct sockaddr_in *)src_sa;

        sa6.sin6_family = AF_INET6;
        sa6.sin6_port = sa4->sin_port;

        // construct the ::ffff:x.x.x.x mapped address
        sa6.sin6_addr.s6_addr[10] = 0xff;
        sa6.sin6_addr.s6_addr[11] = 0xff;
        *(uint32_t *)&sa6.sin6_addr.s6_addr[12] = sa4->sin_addr.s_addr;

        *(struct sockaddr_in6 *)out_sa = sa6;

        return sizeof(struct sockaddr_in6);
    }

    // special case...
    if(sending_family == AF_INET && src_sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sa6 = (const struct sockaddr_in6 *)src_sa;
        // ... where the IPv6 address actually is a mapped IPv4 address and hence usuable
        if(IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
            struct sockaddr_in sa4 = {0};

            sa4.sin_family = AF_INET;
            sa4.sin_port = sa6->sin6_port;

            // Extract the mapped IPv4
            memcpy(&sa4.sin_addr.s_addr, &sa6->sin6_addr.s6_addr[12], 4);

            // update the output sock
            memcpy(out_sa, &sa4, sizeof(sa4));
            return sizeof(sa4);
        }
    }

    // anything else is an error
    traceEvent(TRACE_WARNING, "cannot prepare sockaddr: sending family (%d) is incompatible with destination family (%d)",
               sending_family, src_sa->sa_family);

    return 0;
}

/* *********************************************** */


/** Convert subnet prefix bit length to host order subnet mask. */
uint32_t bitlen2mask (uint8_t bitlen) {

    uint8_t i;
    uint32_t mask = 0;

    for(i = 1; i <= bitlen; ++i) {
        mask |= 1 << (32 - i);
    }

    return mask;
}


/* *********************************************** */

// TODO: move to a ethernet helper source file
char * macaddr_str (macstr_t buf,
                    const n2n_mac_t mac) {

    snprintf(buf, N2N_MACSTR_SIZE, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0] & 0xFF, mac[1] & 0xFF, mac[2] & 0xFF,
             mac[3] & 0xFF, mac[4] & 0xFF, mac[5] & 0xFF);

    return(buf);
}

/* ************************************************ */


/* http://www.faqs.org/rfcs/rfc908.html */
uint8_t is_multi_broadcast (const n2n_mac_t dest_mac) {

    int is_broadcast = (memcmp(broadcast_mac, dest_mac, N2N_MAC_SIZE) == 0);
    int is_multicast = (memcmp(multicast_mac, dest_mac, 3) == 0) && !(dest_mac[3] >> 7);
    int is_ipv6_multicast = (memcmp(ipv6_multicast_mac, dest_mac, 2) == 0);

    return is_broadcast || is_multicast || is_ipv6_multicast;
}


// TODO: move to a ethernet helper source file
uint8_t is_null_mac (const n2n_mac_t dest_mac) {

    int is_null_mac = (memcmp(null_mac, dest_mac, N2N_MAC_SIZE) == 0);

    return is_null_mac;
}


/* *********************************************** */

void print_n3n_version () {

    printf("n3n v%s, configured %s\n"
           "Copyright n2n contributors\n"
           "Copyright Hamish Coleman\n"
           "\n",
           VERSION, BUILDDATE);
}

/* *********************************************** */

// TODO: move to a strings helper source file
static uint8_t hex2byte (const char * s) {

    char tmp[3];
    tmp[0] = s[0];
    tmp[1] = s[1];
    tmp[2] = 0; /* NULL term */

    return((uint8_t)strtol(tmp, NULL, 16));
}

// TODO: move to a ethernet/strings helper source file
extern int str2mac (uint8_t * outmac /* 6 bytes */, const char * s) {

    size_t i;

    /* break it down as one case for the first "HH", the 5 x through loop for
     * each ":HH" where HH is a two hex nibbles in ASCII. */

    *outmac = hex2byte(s);
    ++outmac;
    s += 2; /* don't skip colon yet - helps generalise loop. */

    for(i = 1; i < 6; ++i) {
        s += 1;
        *outmac = hex2byte(s);
        ++outmac;
        s += 2;
    }

    return 0; /* ok */
}

// TODO: move to a strings helper source file
extern char * sock_to_cstr (n3n_sock_str_t out,
                            const n3n_sock_t * sock) {

    if(!sock) {
        return NULL;
    }
    if(NULL == out) {
        return NULL;
    }
    memset(out, 0, N3N_SOCKBUF_SIZE);

    bool is_tcp = (sock->type == SOCK_STREAM);

    if(AF_INET6 == sock->family) {
        char tmp[INET6_ADDRSTRLEN+1];

        tmp[0] = '\0';
        inet_ntop(AF_INET6, sock->addr.v6, tmp, sizeof(tmp));
        snprintf(
            out,
            N3N_SOCKBUF_SIZE,
            "%s[%s]:%hu",
            is_tcp ? "TCP/" : "",
            tmp[0] ? tmp : "",
            sock->port
        );
        return out;
    }

    const uint8_t * a = sock->addr.v4;

    snprintf(out, N3N_SOCKBUF_SIZE, "%s%hu.%hu.%hu.%hu:%hu",
             is_tcp ? "TCP/" : "",
             (unsigned short)(a[0] & 0xff),
             (unsigned short)(a[1] & 0xff),
             (unsigned short)(a[2] & 0xff),
             (unsigned short)(a[3] & 0xff),
             (unsigned short)sock->port);
    return out;
}

// TODO: move to a strings helper source file
char *ip_subnet_to_str (dec_ip_bit_str_t buf, const n2n_ip_subnet_t *ipaddr) {

    snprintf(buf, sizeof(dec_ip_bit_str_t), "%u.%u.%u.%u/%u",
             (uint8_t) ((ipaddr->net_addr >> 24) & 0xFF),
             (uint8_t) ((ipaddr->net_addr >> 16) & 0xFF),
             (uint8_t) ((ipaddr->net_addr >> 8) & 0xFF),
             (uint8_t) (ipaddr->net_addr & 0xFF),
             ipaddr->net_bitlen);

    return buf;
}

// TODO: move to a strings helper source file
const char *sockaddr_to_str (char *s, size_t len, const struct sockaddr *sa) {
    if(sa->sa_family == AF_INET) {
        return inet_ntop(
            AF_INET,
            &(((struct sockaddr_in *)sa)->sin_addr),
            s,
            len
        );
    }

    if(sa->sa_family == AF_INET6) {
        return inet_ntop(
            AF_INET6,
            &(((struct sockaddr_in6 *)sa)->sin6_addr),
            s,
            len
        );
    }

    snprintf(s, len, "AF(%i)", sa->sa_family);
    return s;
}

// TODO: move to a strings helper source file
// splitting host:port parts
int n3n_transport_prefix (const char *spec, const char **rest) {

    const char *sep = strstr(spec, "://");
    int transports = N3N_TRANSPORT_BOTH;

    if(sep) {
        if((sep - spec == 3) && !strncasecmp(spec, "udp", 3)) {
            transports = N3N_TRANSPORT_UDP;
        } else if((sep - spec == 3) && !strncasecmp(spec, "tcp", 3)) {
            transports = N3N_TRANSPORT_TCP;
        } else {
            return -1;
        }
        spec = sep + 3;
    }
    if(rest) {
        *rest = spec;
    }
    return transports;
}


int parse_address_spec (n3n_parsed_address_t *out, const n3n_sock_str_t spec_in) {

    // work_buffer is of same type as the input as it will only hodl substring
    n3n_sock_str_t work_buffer;
    const char *spec_start;

    // "udp://" or "tcp://" in front tells the transport, not the address
    if(n3n_transport_prefix(spec_in, &spec_start) < 0) {
        return -1;
    }

    // initialize output
    memset(out, 0, sizeof(n3n_parsed_address_t));

    // caller is responsible to set socktype
    out->socktype = 0;

    // just to be on the safe side
    size_t length = strlen(spec_start);
    if(length >= sizeof(work_buffer)) {
        // should not happen if input is valid n3n_sock_str_t
        return -1;
    }
    memcpy(work_buffer, spec_start, length + 1); /* +1 for null terminator */

    // parse the host and port from the local work_buffer
    char *host_part = work_buffer;
    char *port_part = NULL;

    char *last_colon = strrchr(host_part, ':');
    char *closing_bracket = strrchr(host_part, ']');

    // a colon is ONLY a port separator if brackets are present OR if it's the ONLY colon
    if(last_colon) {
        if(closing_bracket) {
            if(last_colon > closing_bracket) {
                *last_colon = '\0';
                port_part = last_colon + 1;
            }
        } else {
            char *first_colon = strchr(host_part, ':');
            if(first_colon == last_colon) {
                *last_colon = '\0';
                port_part = last_colon + 1;
            }
        }
    }

    // handle IPv6 address' brackets '[' ... ']' around the host part
    if((*host_part == '[') && closing_bracket) {
        *closing_bracket = '\0'; /* terminate the host_part at the bracket */
        host_part++;
    }

    // safely copy the results from the temporary parts into the output struct
    snprintf(out->host, sizeof(out->host), "%s", host_part);
    // copy the port if it exists
    if(port_part) {
        snprintf(out->port, sizeof(out->port), "%s", port_part);
    }

    return 0;
}


/* @return 1 if the two sockets are equivalent. */
int sock_equal (const n3n_sock_t * a,
                const n3n_sock_t * b) {

    if(a->port != b->port) {
        return 0;
    }

    if(a->family == AF_INET && b->family == AF_INET) {
        return(memcmp(a->addr.v4, b->addr.v4, IPV4_SIZE) == 0);
    }

    if(a->family == AF_INET6 && b->family == AF_INET6) {
        return(memcmp(a->addr.v6, b->addr.v6, IPV6_SIZE) == 0);
    }

    if(a->family == AF_INET6 && b->family == AF_INET) {
        // is 'a' IPv4-mapped address?
        if(IN6_IS_ADDR_V4MAPPED((const struct in6_addr *)a->addr.v6)) {
            // compare the last 4
            return(memcmp(a->addr.v6 + 12, b->addr.v4, IPV4_SIZE) == 0);
        }
    }
    // reverse case
    if(a->family == AF_INET && b->family == AF_INET6) {
        if(IN6_IS_ADDR_V4MAPPED((const struct in6_addr *)b->addr.v6)) {
            return(memcmp(a->addr.v4, b->addr.v6 + 12, IPV4_SIZE) == 0);
        }
    }

    // not equal
    return 0;
}


/* *********************************************** */

// exclusive-ors a specified memory area with another
int memxor (uint8_t *destination, const uint8_t *source, size_t len) {

    for(; len >= 4; len -= 4) {
        *(uint32_t*)destination ^= *(uint32_t*)source;
        source += 4;
        destination += 4;
    }

    for(; len > 0; len--) {
        *destination ^= *source;
        source++;
        destination++;
    }

    return 0;
}

/* *********************************************** */

// stores the previously issued time stamp, shared by all threads: every stamp
// is issued with a compare-and-swap on it, so that they stay unique and
// rising across threads, as the receiver's replay protection expects
static uint64_t previously_issued_time_stamp = 0;


// returns a time stamp for use with replay protection (branchless code)
//
// depending on the self-detected accuracy, it has the following format
//
// MMMMMMMMCCCCCCCF or
//
// MMMMMMMMSSSSSCCF
//
// with M being the 32-bit second time stamp
//      S       the 20-bit sub-second (microsecond) time stamp part, if applicable
//      C       a counter (8 bit or 24 bit) reset to 0 with every MMMMMMMM(SSSSS) turn-over
//      F       a 4-bit flag field with
//      ...c    being the accuracy indicator (if set, only counter and no sub-second accuracy)
//
// the stamp to issue after "previous" at time "micro_seconds"
static uint64_t time_stamp_next (uint64_t previous, uint64_t micro_seconds) {

    uint64_t co, mask_lo, mask_hi, hi_unchanged, counter, new_co;

    // extract "counter only" flag (lowest bit)
    co = (previous << 63) >> 63;
    // set mask accordingly
    mask_lo   = -co;
    mask_lo >>= 32;
    // either 0x00000000FFFFFFFF (if co flag set) or 0x0000000000000000 (if co flag not set)

    mask_lo  |= (~mask_lo) >> 52;
    // either 0x00000000FFFFFFFF (unchanged)      or 0x0000000000000FFF (lowest 12 bit set)

    mask_hi   = ~mask_lo;

    hi_unchanged = ((previous & mask_hi) == (micro_seconds & mask_hi));
    // 0 if upper bits unchanged (compared to previous stamp), 1 otherwise

    // read counter and shift right for flags
    counter   = (previous & mask_lo) >> 4;

    counter  += hi_unchanged;
    counter  &= -hi_unchanged;
    // either counter++ if upper part of timestamp unchanged, 0 otherwise

    // back to time stamp format
    counter <<= 4;

    // set new co flag if counter overflows while upper bits unchanged or if it was set before
    new_co   = (((counter & mask_lo) == 0) & hi_unchanged) | co;

    // in case co flag changed, masks need to be recalculated
    mask_lo   = -new_co;
    mask_lo >>= 32;
    mask_lo  |= (~mask_lo) >> 52;
    mask_hi   = ~mask_lo;

    // assemble new timestamp
    micro_seconds &= mask_hi;
    micro_seconds |= counter;
    micro_seconds |= new_co;

    return micro_seconds;
}


uint64_t time_stamp (void) {

    struct timeval tod;
    uint64_t micro_seconds;
    uint64_t previous, stamp;

    // If another thread issued a stamp in between, start over - including
    // reading the clock again: a stamp worked out from an older reading on
    // top of that thread's newer stamp could be lower than it. With one
    // thread the first attempt always succeeds.
    previous = __atomic_load_n(&previously_issued_time_stamp, __ATOMIC_RELAXED);
    do {
        gettimeofday(&tod, NULL);

        // (roughly) calculate the microseconds since 1970, leftbound
        micro_seconds = ((uint64_t)(tod.tv_sec) << 32) + ((uint64_t)tod.tv_usec << 12);
        // more exact but more costly due to the multiplication:
        // micro_seconds = ((uint64_t)(tod.tv_sec) * 1000000ULL + tod.tv_usec) << 12;

        stamp = time_stamp_next(previous, micro_seconds);
    } while(!__atomic_compare_exchange_n(&previously_issued_time_stamp, &previous, stamp, 1,
                                         __ATOMIC_RELAXED, __ATOMIC_RELAXED));

    return stamp;
}
