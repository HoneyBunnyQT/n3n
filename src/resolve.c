/*
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023-25 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The resolver thread code and functions
 */

#include <errno.h>           // for EBUSY
#include <n3n/logging.h>
#include <n3n/metrics.h>
#include <n3n/resolve.h>     // for n3n_resolve_parameter_t
#include <n3n/strings.h>     // for sock_to_cstr, parse_address_spec
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>            // for clock_gettime

#include "config.h"          // for HAVE_LIBPTHREAD
#include "resolve.h"
#include "n2n.h"             // for sock_equal, parse_address_spec
#include "n2n_define.h"
#include "n2n_typedefs.h"
#include "n2n_wire.h"        // for fill_n3nsock

struct peer_info;

#ifdef HAVE_LIBPTHREAD
#include <pthread.h>
#endif

#ifdef _WIN32
#include "win32/defs.h"
#include <ws2def.h>
#else
#include <netdb.h>           // for addrinfo, freeaddrinfo, gai_strerror
#include <netinet/in.h>
#include <sys/socket.h>      // for AF_INET, PF_INET
#include <sys/time.h>        // for gettimeofday, timersub
#endif

#ifndef _WIN32
#define closesocket(a) close(a)
#endif

#define N2N_RESOLVE_INTERVAL            300 /* seconds until edge and supernode try to resolve supernode names again */
#define N2N_RESOLVE_CHECK_INTERVAL       30 /* seconds until main loop checking in on changes from resolver thread */

/**********************************************************/

static struct metrics {
    uint32_t count;
    uint32_t total_usec;
    uint32_t longest_usec;
} metrics;

static struct n3n_metrics_items_uint32 metrics_items[] = {
    {
        .name = "count",
        .desc = "Incremented for each name resolve",
        .offset = offsetof(struct metrics, count),
    },
    {
        .name = "total_usec",
        .desc = "Accumulated useconds waiting for name resolve results",
        .offset = offsetof(struct metrics, total_usec),
    },
    {
        .name = "longest_usec",
        .desc = "Time taken for longest resolve",
        .offset = offsetof(struct metrics, longest_usec),
    },
    { },
};

static struct n3n_metrics_module metrics_module = {
    .name = "resolve",
    .data = &metrics,
    .items_uint32 = metrics_items,
    .type = n3n_metrics_type_uint32,
};

/**********************************************************/

enum request_pkt_type {
    request_pkt_type_none = 0, // buf is unused
    request_pkt_type_error,    // contains an error result
    request_pkt_type_prep,     // preparing a request
    request_pkt_type_request,  // contains a request
    request_pkt_type_result,   // contains a non error result
};

struct request_pkt {
    enum request_pkt_type type;
    uint64_t id;               // Opaque data from requestor
    union {
        int error;
        n3n_sock_str_t hostname;
        struct sockaddr_storage sa[15];
    };
};

static struct request_pkt request_pkt;

struct hostname_list_item {
    struct hostname_list_item *next;
    uint32_t next_resolve;  // Use 0 for "now"
    char s[];
};

// TODO: zeroth item unused
static struct hostname_list_item *hostname_lists[3];
// static struct supernode_str *supernode_next_resolve;

// Whether this host has a route to the address; connect() on a UDP socket
// only looks the route up and sends nothing. Having an address of the family
// is not enough: once the edge's TAP device is up, its IPv4 address makes an
// IPv6 only host look as if it had IPv4 too.
static bool have_route_to (const struct addrinfo *ai) {
    SOCKET sock = n3n_socket(ai->ai_family, SOCK_DGRAM, 0);
#ifdef _WIN32
    if(sock == INVALID_SOCKET) {
        return false;
    }
#else
    if(sock < 0) {
        return false;
    }
#endif
    bool reachable = (connect(sock, ai->ai_addr, ai->ai_addrlen) == 0);
    closesocket(sock);
    return reachable;
}

/** Resolve the supernode IP address.
 *
 */
int supernode2sock (n3n_sock_t *sn, const char *addrIn) {

    n3n_parsed_address_t parsed_addr;
    char supernode_default_port[N3N_PORTBUF_SIZE];
    int nameerr;
    struct addrinfo aihints = {0};
    struct addrinfo * ainfo = NULL;

    // default to invalid output
    sn->family = AF_INVALID;

    if(!addrIn) {
        traceEvent(TRACE_DEBUG, "supernode2sock got NULL addrIn");
        return -6;
    }

    // parse
    if(parse_address_spec(&parsed_addr, addrIn) != 0) {
        traceEvent(TRACE_WARNING, "failed to parse supernode spec: %s", addrIn);
        return -5;
    }

    // a specific rules for supernode
    // host part must be present
    if(parsed_addr.host[0] == '\0') {
        traceEvent(
            TRACE_WARNING,
            "malformed supernode parameter (missing host) '%s'",
            addrIn
        );
        return -4;
    }

    // a port part is optional, use the default port if it's missing
    // TODO: check DNS SRV before defaulting
    char *port_to_resolve = parsed_addr.port;
    if(port_to_resolve[0] == '\0') {
        snprintf(supernode_default_port, sizeof(supernode_default_port), "%d", N2N_SN_LPORT_DEFAULT);
        port_to_resolve = supernode_default_port;
        traceEvent(
            TRACE_INFO,
            "no port specified, assuming default %s",
            port_to_resolve);
    }

    aihints.ai_socktype = SOCK_DGRAM;
    aihints.ai_family = AF_UNSPEC;
    // TODO: this (and further down below) would be the place to enforce
    //       IPv4 only for external use if ever required, maybe by config option
    //       hints.ai_family = AF_INET; /* enforce IPv4 */

    // resolve
    struct timeval time1;
    struct timeval time2;

    gettimeofday(&time1, NULL);
    nameerr = getaddrinfo(parsed_addr.host, port_to_resolve, &aihints, &ainfo);
    gettimeofday(&time2, NULL);

    struct timeval elapsed;
    timersub(&time2, &time1, &elapsed);

    uint64_t elapsed_usec = elapsed.tv_sec * 1000000 + elapsed.tv_usec;

    metrics.count++;
    metrics.total_usec += elapsed_usec;
    if(metrics.longest_usec < elapsed_usec) {
        metrics.longest_usec = elapsed_usec;
    }

    if(nameerr != 0) {
        traceEvent(
            TRACE_WARNING,
            "supernode2sock fails to resolve supernode host %s, %d: %s",
            parsed_addr.host,
            nameerr,
            gai_strerror(nameerr)
        );
#ifdef EAI_SYSTEM
        // One day, I hope to stop writing plaintive missives to Windows about
        // how incompatible they are
        if(nameerr == EAI_SYSTEM) {
            traceEvent(
                TRACE_WARNING,
                "getaddrinfo returned EAI_SYSTEM, errno: %i",
                errno
            );
        }
#endif
        return -2;
    }

    if(!ainfo) {
        // shouldnt happen - if nameerr is zero, ainfo should not be NULL
        traceEvent(TRACE_WARNING, "supernode2sock unexpected error");
        return -1;
    }

    /* ainfo is the head of a linked list if non-NULL. */
    // loop through the results to find suitable one: for compatibility
    // reasons, we will prefer any IPv4 result, but first only among the
    // results this host has a route to. Only if it has a route to none, e.g.
    // while the network is not up yet, any IPv4 result, then any IPv6 one
    int found = 0;
    for(int pass = 0; (pass < 4) && !found; pass++) {
        int family = (pass & 1) ? AF_INET6 : AF_INET;
        bool need_route = (pass < 2);

        for(struct addrinfo *p = ainfo; p != NULL; p = p->ai_next) {
            if(p->ai_family != family) {
                continue;
            }
            if(need_route && !have_route_to(p)) {
                continue;
            }
            if(fill_n3nsock(sn, p->ai_addr) == 0) {
                // successfully filled the n3n_sock_t
                traceEvent(
                    TRACE_INFO,
                    "supernode2sock resolved %s address for '%s'%s",
                    (family == AF_INET) ? "IPv4" : "IPv6",
                    parsed_addr.host,
                    need_route ? "" : " (no route to any of its addresses yet)"
                );
                found = 1;
                break;
            }
        }
    }

    // if we got this far and haven't got a valid socket...
    if((sn->family == AF_INVALID) || !found) {
        // ... there is no valid address
        traceEvent(TRACE_WARNING, "supernode2sock resolved host '%s', but no usable address was found.", parsed_addr.host);
        freeaddrinfo(ainfo);
        return -1;
    }

    freeaddrinfo(ainfo); /* free everything allocated by getaddrinfo(). */

    return 0;
}


#ifdef HAVE_LIBPTHREAD

#ifdef _MSC_VER
// FIXME: this code may not work as expected - see also src/win32/n2n_win32.h
//
#define N2N_THREAD_RETURN_DATATYPE       DWORD WINAPI
#define N2N_THREAD_PARAMETER_DATATYPE    LPVOID
#else
#define N2N_THREAD_RETURN_DATATYPE        void*
#define N2N_THREAD_PARAMETER_DATATYPE     void*
#endif

N2N_THREAD_RETURN_DATATYPE resolve_thread (N2N_THREAD_PARAMETER_DATATYPE p) {

    n3n_resolve_parameter_t *param = (n3n_resolve_parameter_t*)p;
    struct n3n_resolve_ip_sock *entry;
    struct n3n_resolve_ip_sock *tmp_entry;
    time_t rep_time = N2N_RESOLVE_INTERVAL / 10;
    time_t now;

    pthread_mutex_lock(&param->access);

    while(!param->stop) {
        struct timespec wake;

        // wake up in-between to check for signaled requests, or straight
        // away when resolve_cancel_thread() asks to stop.  The wait lets go
        // of the lock while it waits.  (No pthread_cancel(): Android has
        // none, and a program that runs the edge inside itself should not
        // see threads cancelled in its C library.)
        clock_gettime(CLOCK_REALTIME, &wake);
        wake.tv_sec += N2N_RESOLVE_INTERVAL / 60;
        pthread_cond_timedwait(&param->wake, &param->access, &wake);
        if(param->stop) {
            break;
        }

        // what's the time?
        now = time(NULL);

        // is it time to resolve yet?
        if(((param->request)) || ((now - param->last_resolved) > rep_time)) {
            HASH_ITER(hh, param->list, entry, tmp_entry) {
                // resolve
                entry->error_code = supernode2sock(&entry->sock, entry->org_ip);
                // if socket changed and no error
                if(!sock_equal(&entry->sock, entry->org_sock)
                   && (!entry->error_code)) {
                    // flag the change
                    param->changed = true;
                }
            }
            param->last_resolved = now;

            // any request fulfilled
            param->request = false;

            // determine next resolver repetition (shorter time if resolver errors occured)
            rep_time = N2N_RESOLVE_INTERVAL;
            HASH_ITER(hh, param->list, entry, tmp_entry) {
                if(entry->error_code) {
                    rep_time = N2N_RESOLVE_INTERVAL / 10;
                    break;
                }
            }
        }
    }

    pthread_mutex_unlock(&param->access);

    return 0;
}

int resolve_create_thread (n3n_resolve_parameter_t **param, struct peer_info *sn_list) {
    struct peer_info        *sn, *tmp_sn;
    struct n3n_resolve_ip_sock *entry;
    int ret;

    // create parameter structure
    *param = (n3n_resolve_parameter_t*)calloc(1, sizeof(n3n_resolve_parameter_t));
    if(*param) {
        HASH_ITER(hh, sn_list, sn, tmp_sn) {
            // create entries for those peers that come with hostname string (from command-line)
            if(sn->hostname) {
                entry = (struct n3n_resolve_ip_sock*)calloc(1, sizeof(struct n3n_resolve_ip_sock));
                if(entry) {
                    entry->org_ip = sn->hostname;
                    entry->org_sock = &(sn->sock);
                    memcpy(&(entry->sock), &(sn->sock), sizeof(n3n_sock_t));
                    HASH_ADD(hh, (*param)->list, org_ip, sizeof(char*), entry);
                } else
                    traceEvent(
                        TRACE_WARNING,
                        "resolve_create_thread was unable to add list entry for supernode '%s'",
                        sn->hostname
                    );
            }
            // and its address for TCP, if it has one of its own
            if(sn->tcp_hostname) {
                entry = (struct n3n_resolve_ip_sock*)calloc(1, sizeof(struct n3n_resolve_ip_sock));
                if(entry) {
                    entry->org_ip = sn->tcp_hostname;
                    entry->org_sock = &(sn->tcp_sock);
                    memcpy(&(entry->sock), &(sn->tcp_sock), sizeof(n3n_sock_t));
                    HASH_ADD(hh, (*param)->list, org_ip, sizeof(char*), entry);
                }
            }
        }
        (*param)->check_interval = N2N_RESOLVE_CHECK_INTERVAL;
    } else {
        traceEvent(TRACE_WARNING, "resolve_create_thread was unable to create list of supernodes");
        return -1;
    }

    // the thread takes the mutex straight away, so it has to exist first
    pthread_mutex_init(&((*param)->access), NULL);
    pthread_cond_init(&((*param)->wake), NULL);

    // create thread
    ret = pthread_create(&((*param)->id), NULL, resolve_thread, (void *)*param);
    if(ret) {
        traceEvent(TRACE_WARNING, "resolve_create_thread failed to create resolver thread with error number %d", ret);
        return -1;
    }

    return 0;
}


// After a fork() - the edge becoming a daemon - the child has none of the
// parent's threads: start the resolver anew there.  The lock and the
// condition are made anew too, the thread could have held the lock just
// when the fork happened.
void resolve_forked (n3n_resolve_parameter_t *param) {
    int ret;

    if(!param) {
        return;
    }

    pthread_mutex_init(&param->access, NULL);
    pthread_cond_init(&param->wake, NULL);
    param->stop = false;

    ret = pthread_create(&param->id, NULL, resolve_thread, (void *)param);
    if(ret) {
        traceEvent(TRACE_WARNING, "resolve_forked failed to create resolver thread with error number %d", ret);
    }
}


void resolve_cancel_thread (n3n_resolve_parameter_t *param) {
    struct n3n_resolve_ip_sock *entry, *tmp_entry;

    if(!param) {
        return;
    }

    // Ask the thread to stop, and wait until it has, before freeing what
    // it works on - and before the caller frees the supernode list, whose
    // host names the entries point to.  If it is resolving names just now,
    // that is as long as the lookups take.
    pthread_mutex_lock(&param->access);
    param->stop = true;
    pthread_cond_signal(&param->wake);
    pthread_mutex_unlock(&param->access);
    pthread_join(param->id, NULL);
    pthread_cond_destroy(&param->wake);
    pthread_mutex_destroy(&param->access);

    HASH_ITER(hh, param->list, entry, tmp_entry) {
        HASH_DEL(param->list, entry);
        free(entry);
    }
    free(param);
}


bool resolve_check (n3n_resolve_parameter_t *param, bool requires_resolution, time_t now) {

    bool ret = requires_resolution; /* if trylock fails, it still requires resolution */

    struct n3n_resolve_ip_sock *entry;
    struct n3n_resolve_ip_sock *tmp_entry;
    n3n_sock_str_t sock_buf;

    if(NULL == param)
        return ret;

    // check_interval and last_check do not need to be guarded by the mutex because
    // their values get changed and evaluated only here

    if((now - param->last_checked > param->check_interval) || (requires_resolution)) {
        // try to lock access
        if(pthread_mutex_trylock(&param->access) == 0) {
            // any changes?
            if(param->changed) {
                // reset flag
                param->changed = false;
                // unselectively copy all socks (even those with error code, that would be the old one because
                // sockets do not get overwritten in case of error in resolve_thread) from list to supernode list
                HASH_ITER(hh, param->list, entry, tmp_entry) {
                    memcpy(entry->org_sock, &entry->sock, sizeof(n3n_sock_t));
                    traceEvent(TRACE_INFO, "resolve_check renews ip address of supernode '%s' to %s",
                               entry->org_ip, sock_to_cstr(sock_buf, &(entry->sock)));
                }
            }

            // let the resolver thread know eventual difficulties in reaching the supernode
            if(requires_resolution) {
                param->request = true;
                ret = false;
            }

            param->last_checked = now;

            // next appointment
            if(param->request)
                // earlier if resolver still working on fulfilling a request
                param->check_interval = N2N_RESOLVE_CHECK_INTERVAL / 10;
            else
                param->check_interval = N2N_RESOLVE_CHECK_INTERVAL;

            // unlock access
            pthread_mutex_unlock(&param->access);
        }
    }

    return ret;
}


int maybe_supernode2sock (n3n_sock_t * sn, const char *addrIn) {
    return 0;
}

#else // HAVE_LIBPTHREAD

int resolve_create_thread (n3n_resolve_parameter_t **param, struct peer_info *sn_list) {
    return -1;
}

void resolve_forked (n3n_resolve_parameter_t *param) {
}

void resolve_cancel_thread (n3n_resolve_parameter_t *param) {
    return;
}


bool resolve_check (n3n_resolve_parameter_t *param, bool requires_resolution, time_t now) {
    return requires_resolution;
}

int maybe_supernode2sock (n3n_sock_t * sn, const char *addrIn) {
    return supernode2sock(sn, addrIn);
}
#endif

/*
 * Remove all entries from a hostnames list
 *
 */
void resolve_hostnames_free (int listnr) {
    struct hostname_list_item *p = hostname_lists[listnr];
    while(p) {
        struct hostname_list_item *p_next = p->next;
        free(p);
        p = p_next;
    }
    hostname_lists[listnr] = NULL;
}

/*
 * Add a string to our list of resolvable supernodes
 */
void resolve_hostnames_str_add (int listnr, const char *s) {
    int len = sizeof(struct hostname_list_item) + strlen(s) + 1;
    struct hostname_list_item *p = malloc(len);
    if(!p) {
        return;
    }

    strcpy((char *)&(p->s), s);
    p->next_resolve = 0;    // mark as "Now"
    p->next = hostname_lists[listnr];
    hostname_lists[listnr] = p;
}

/*
 * For config dumping, provide a way to access the list
 * (Not intended to be called often, so not performant)
 */
const char *resolve_hostnames_str_get (int listnr, int index) {
    struct hostname_list_item *p = hostname_lists[listnr];
    while(index) {
        if(!p) {
            return NULL;
        }
        p = p->next;
        index--;
    }
    if(!p) {
        return NULL;
    }
    return p->s;
}

// Just dump the whole hostname list to the log
void resolve_log_hostnames (int listnr) {
    traceEvent(TRACE_INFO, "hostname list %i:", listnr);

    int count = 0;
    struct hostname_list_item *p = hostname_lists[listnr];
    while(p) {
        count++;
        traceEvent(TRACE_INFO, "name %i = %s\n", count, p->s);
        p = p->next;
    }
    traceEvent(TRACE_INFO, "number of hostnames in this list: %i\n", count);
}

// Whether two supernode addresses name the same host, whatever their
// "udp://" or "tcp://" and port
static bool same_host (const char *a, const char *b) {

    n3n_parsed_address_t pa, pb;

    if(!a || !b || parse_address_spec(&pa, a) || parse_address_spec(&pb, b)) {
        return false;
    }
    return !strcmp(pa.host, pb.host);
}


// A supernode for UDP of the same host as s, which a "tcp://" entry s gives
// its TCP address to
static struct peer_info *sn_for_tcp_of (struct peer_info *list, const char *s) {

    struct peer_info *peer, *tmp;

    HASH_ITER(hh, list, peer, tmp) {
        if((!peer->transports || (peer->transports & N3N_TRANSPORT_UDP)) && same_host(peer->hostname, s)) {
            return peer;
        }
    }
    return NULL;
}


// A supernode that has only a "tcp://" entry of the same host as s, which
// becomes the TCP address of the supernode s is for UDP
static struct peer_info *sn_tcp_only_of (struct peer_info *list, const char *s) {

    struct peer_info *peer, *tmp;

    HASH_ITER(hh, list, peer, tmp) {
        if((peer->transports == N3N_TRANSPORT_TCP) && same_host(peer->hostname, s)) {
            return peer;
        }
    }
    return NULL;
}


/*
 * Convert one string into an added peer_info
 * (This is a refactor of n3n_peer_add_by_hostname)
 *
 * A "udp://" or "tcp://" in front makes the supernode one for that transport
 * only - unless another entry names the same host for the other one: then
 * it is one supernode, reached over TCP at the address of the "tcp://" one.
 */
static int resolve_hostnames_str_to_peer_info_one (
    struct peer_info **list,
    const char *s
) {

    n3n_sock_t sock;
    memset(&sock, 0, sizeof(sock));

    traceEvent(TRACE_DEBUG, "resolving %s", s);

    if(!s) {
        // With no hostname, cannot do anything
        return 1;
    }

    int transports = n3n_transport_prefix(s, NULL);
    if(transports < 0) {
        traceEvent(TRACE_WARNING, "supernode %s: only udp:// or tcp:// can come before the address", s);
        return 1;
    }

    // WARN: this function could block for a name resolution
    int rv = supernode2sock(&sock, s);

    if(rv < 0) {
        /* just warn, since it might resolve next time */
        traceEvent(TRACE_WARNING, "could not resolve %s", s);
        return 1;
    }

    struct peer_info *other;
    if(transports == N3N_TRANSPORT_TCP) {
        other = sn_for_tcp_of(*list, s);
        if(other) {
            if(!other->tcp_hostname) {
                other->tcp_hostname = strdup(s);
            }
            other->tcp_sock = sock;
            other->transports = 0;
            traceEvent(TRACE_INFO, "supernode %s over TCP at %s", peer_info_get_hostname(other), s);
            return 0;
        }
    } else {
        other = sn_tcp_only_of(*list, s);
        if(other) {
            // that one is this supernode's TCP address
            other->tcp_hostname = other->hostname;
            other->tcp_sock = other->sock;
            other->hostname = strdup(s);
            other->sock = sock;
            other->transports = 0;
            traceEvent(TRACE_INFO, "supernode %s over TCP at %s", s, other->tcp_hostname);
            return 0;
        }
    }

    int skip_add = SN_ADD;
    struct peer_info *peer = add_sn_to_list_by_mac_or_sock(
        list,
        &sock,
        null_mac,
        &skip_add
    );

    if(!peer) {
        return 1;
    }

    if(!peer_info_get_hostname(peer)) {
        // We dup the string here because the peer_info_free() thinks it owns
        // the hostname and wants to free() it
        // TODO: refactor
        peer->hostname = strdup(s);
    }

    memcpy(&(peer->sock), &sock, sizeof(n3n_sock_t));

    // If a new peer was added, it has already been init, but we want to reset
    // the state of any old peer object
    if(skip_add != SN_ADD_ADDED) {
        peer_info_init(peer, null_mac);
    }

    // This is the only peer_info where the default purgeable=true
    // is overwritten
    peer->purgeable = false;

    // 0 for both; two entries for one address make it for both of theirs
    if(skip_add == SN_ADD_ADDED) {
        peer->transports = transports;
    } else if(peer->transports) {
        peer->transports |= transports;
    }
    if(peer->transports == N3N_TRANSPORT_BOTH) {
        peer->transports = 0;
    }

    // TODO: say something different if we updated an existing record?
    traceEvent(
        TRACE_INFO,
        "adding supernode = %s",
        peer_info_get_hostname(peer)
    );

    return 0;
}

/*
 * Convert the entire supernode list into peer_info structs
 *
 * TODO:
 * - update the next_resolve field, also use it to skip fast resolves
 * - support multiple hostname results (both A and AAAA as well)
 * - eventually, support SRV
 */
// One string of such a list, added to peers
int resolve_hostname_str_to_peer_info (struct peer_info **peers, const char *s) {
    return resolve_hostnames_str_to_peer_info_one(peers, s);
}

int resolve_hostnames_str_to_peer_info (int listnr, struct peer_info **peers) {
    if(!peers) {
        return 1;
    }
    struct hostname_list_item *p = hostname_lists[listnr];
    int rv = 0;
    while(p) {
        rv += resolve_hostnames_str_to_peer_info_one(peers, p->s);
        p = p->next;
    }
    return rv;
}

// This function is the main thread processor
static void request_pkt_process () {
    if(request_pkt.type != request_pkt_type_request) {
        // The request buf is not owned by us, return to sleep
        return;
    }

    char *p = (char *)&request_pkt.hostname;
    char *node = p;
    char *service;

    if(*p == '[') {
        // This is a IPv6 raw address
        node = p + 1;

        // find the end of the raw address
        p = strchr(p, ']');
        if(!p) {
            traceEvent(
                TRACE_ERROR,
                "Bad end of IPv6 address: %s",
                node - 1
            );
            request_pkt.type = request_pkt_type_error;
            request_pkt.error = 1000;
            return;
        }

        // and mark the raw addr end
        *p = '\0';

        // Point at the start of any possible port
        p++;
    }

    service = strchr(p, ':');
    if(service) {
        // mark the end of node name
        *service = '\0';
        // skip to the port
        service++;
    } else {
        service = "7654";   // The default port if none is specified
    }

    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,     // Allow both
        .ai_socktype = SOCK_DGRAM,  // TODO: address this for TCP support
#ifdef AI_ADDRCONFIG
        // Another wierd Windows ifdef
        // TODO: understand and fix
        .ai_flags = AI_ADDRCONFIG,
#endif
        .ai_protocol = 0,
    };
    struct addrinfo *result;

    struct timeval time1;
    struct timeval time2;

    gettimeofday(&time1, NULL);
    int rc = getaddrinfo(node, service, &hints, &result);
    gettimeofday(&time2, NULL);

    struct timeval elapsed;
    timersub(&time2, &time1, &elapsed);

    uint64_t elapsed_usec = elapsed.tv_sec * 1000000 + elapsed.tv_usec;

    metrics.count++;
    metrics.total_usec += elapsed_usec;
    if(metrics.longest_usec < elapsed_usec) {
        metrics.longest_usec = elapsed_usec;
    }

    if(rc != 0) {
        // Since network disconnection events can happen, a failure to resolve
        // is not a TRACE_ERROR
        traceEvent(
            TRACE_WARNING,
            "getaddrinfo(%s, %s, ..) returned error %i",
            node,
            service,
            rc
        );
        request_pkt.error = rc;
        request_pkt.type = request_pkt_type_error;
        return;
    }

    struct addrinfo *rp;
    for(rp = result; rp != NULL; rp = rp->ai_next) {
        // append to results
        // if n > count of request_buf.sa
        // if rp->ai_addrlen > sizeof(request_buf.sa[0]) then error
        // memcpy to request_buf.sa[n] from rp->ai_addr size rp->ai_addrlen
        traceEvent(
            TRACE_ERROR,
            "rp %i %i %i %i %i sa %s",
            rp->ai_flags,
            rp->ai_family,
            rp->ai_socktype,
            rp->ai_protocol,
            rp->ai_addrlen,
            // sa
            rp->ai_canonname
        );
    }
    freeaddrinfo(result);
}

static int request_pkt_send (uint64_t id, char *hostname) {
    if(request_pkt.type != request_pkt_type_none) {
        // If the buf is already busy, we cannot add more to it
        return EBUSY;
    }

    // Mark it as incomplete
    request_pkt.type = request_pkt_type_prep;

    // Fill in the details
    request_pkt.id = id;
    strncpy(
        (char *)&request_pkt.hostname,
        hostname,
        N3N_SOCKBUF_SIZE - 1
    );
    // request_pkt.hostname[sizeof(&request_pkt.hostname)] = 0;
    request_pkt.hostname[N3N_SOCKBUF_SIZE - 1] = 0;

    // Mark it for processing by the resolve thread
    request_pkt.type = request_pkt_type_request;

    // TODO:
    // ifdef HAVE_LIBPTHREAD
    //   wake up the thread
    // else
    request_pkt_process();
    // endif

    // no error
    return 0;
}

static void request_pkt_init () {
    request_pkt.type = request_pkt_type_none;
}

void n3n_initfuncs_resolve () {
    n3n_metrics_register(&metrics_module);
    request_pkt_init();
}

void n3n_deinitfuncs_resolve () {
    // TODO: there chould be a _del() function that the original callers
    // can use to remove their entries in their own
    resolve_hostnames_free(RESOLVE_LIST_SUPERNODE);
    resolve_hostnames_free(RESOLVE_LIST_PEER);
}
