/**
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023-25 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
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

#ifdef _WIN32
#include "win32/defs.h"
#endif

#include <errno.h>                   // for errno, EAFNOSUPPORT, EINPROGRESS
#include <fcntl.h>                   // for fcntl, F_SETFL, O_NONBLOCK
#include <n3n/conffile.h>            // for n3n_config_load_env, n3n_config_free_...
#include <n3n/edge.h>                // for edge_init_conf_defaults
#include <n3n/initfuncs.h>           // for n3n_deinitfuncs
#include <n3n/logging.h>             // for traceEvent
#include <n3n/mainloop.h>            // for mainloop_runonce, mainloop_regis...
#include <n3n/metrics.h>
#include <n3n/random.h>              // for n3n_rand, n3n_rand_sqr, memrnd
#include <n3n/strings.h>             // for sock_to_cstr
#include <stdbool.h>
#include <stdint.h>                  // for uint8_t, uint16_t, uint32_t, uin...
#include <stdio.h>                   // for snprintf, sprintf
#include <stdlib.h>                  // for free, calloc, getenv
#include <string.h>                  // for memcpy, memset, NULL, memcmp
#include <sys/types.h>               // for time_t, ssize_t, u_int
#include <time.h>                    // for time
#include <unistd.h>                  // for gethostname, sleep
#include <stddef.h>

#include "auth.h"                    // for generate_private_key, generate_shared_secret, ...
#include "config.h"                  // for HAVE_LIBZSTD
#include "edge_utils.h"
#include "header_encryption.h"       // for packet_header_encrypt, packet_he...
#include "management.h"              // for mgmt_event_post
#include "n2n_wire.h"                // for fill_sockaddr, decod...
#include "natclass.h"                // for nat_view_add, nat_view_reset, ...
#include "role_client.h"
#include "role_tap.h"
#include "punch.h"                   // for punch_round, punch_note_rx, ...
#include "resolve.h"                 // for resolve_create_thread, resolve_c...
#include "sn_selection.h"            // for sn_selection_criterion_common_da...
#include "local_link.h"              // for local_link_to_relay, local_link_is_sock
#include "sock.h"                    // for bind_entry_for_family, sendto_bind, ...
#include "edge_threads.h"            // for edge_threads_post_event, ...
#include "stats.h"                   // for STATS_INC, n3n_stats_sum
#include "n2n_define.h"

#ifdef _WIN32
#include <direct.h>                  // for _mkdir

#include "win32/edge_utils_win32.h"
#else
#include <arpa/inet.h>               // for inet_ntoa, inet_addr, inet_ntop
#include <netdb.h>                   // for EAFNOSUPPORT
#include <netinet/in.h>              // for sockaddr_in, ntohl, IPPROTO_IP, IPV6_ADD_MEMBERSHIP
#include <netinet/tcp.h>             // for TCP_NODELAY
#include <pwd.h>
#include <sys/select.h>              // for select, FD_SET, FD_ISSET, FD_ZERO
#include <sys/socket.h>              // for setsockopt, AF_INET, connect, ge...
#endif

#ifndef _WIN32
// Another wonderful gift from the world of POSIX compliance is not worth much
#define closesocket(a) close(a)
#endif

#ifndef IPV6_ADD_MEMBERSHIP
#define IPV6_ADD_MEMBERSHIP 12       // the standard value for this option
#endif

#ifndef MSG_DONTWAIT
// Winsock has no per call non blocking flag.  Asking for a blocking read is
// safe there because the mainloop only ever does one read per readiness event
#define MSG_DONTWAIT 0
#endif

/* ************************************** */

// TODO: most of these forward defs can be removed by re-ordering the code

static int edge_init_sockets (struct n3n_runtime_data *eee);

/* ************************************** */

static struct n3n_metrics_items_uint32 edge_utils_metrics_items1[] = {
    {
        .name = "tx_tuntap_error",
        .offset = offsetof(struct n2n_edge_stats, tx_tuntap_error),
    },
    { },
};

static struct n3n_metrics_items_llu32 edge_utils_metrics_items2 = {
    .name = "packets",
    .name1 = "direction",
    .name2 = "event",
    .items = {
        {
            .val1 = "tx",
            .val2 = "p2p",
            .offset = offsetof(struct n2n_edge_stats, tx_p2p),
        },
        {
            .val1 = "rx",
            .val2 = "p2p",
            .offset = offsetof(struct n2n_edge_stats, rx_p2p),
        },
        {
            .val1 = "tx",
            .val2 = "sup",
            .offset = offsetof(struct n2n_edge_stats, tx_sup),
        },
        {
            .val1 = "rx",
            .val2 = "sup",
            .offset = offsetof(struct n2n_edge_stats, rx_sup),
        },
        {
            .val1 = "tx",
            .val2 = "sup_broadcast",
            .offset = offsetof(struct n2n_edge_stats, tx_sup_broadcast),
        },
        {
            .val1 = "rx",
            .val2 = "sup_broadcast",
            .offset = offsetof(struct n2n_edge_stats, rx_sup_broadcast),
        },
        {
            .val1 = "tx",
            .val2 = "multicast_drop",
            .offset = offsetof(struct n2n_edge_stats, tx_multicast_drop),
        },
        {
            .val1 = "rx",
            .val2 = "multicast_drop",
            .offset = offsetof(struct n2n_edge_stats, rx_multicast_drop),
        },
        { },
    },
};

static struct n3n_metrics_module edge_metrics_module1 = {
    .name = "edge",
    .items_uint32 = edge_utils_metrics_items1,
    .type = n3n_metrics_type_uint32,
};

static struct n3n_metrics_module edge_metrics_module2 = {
    .name = "edge",
    .items_llu32 = &edge_utils_metrics_items2,
    .type = n3n_metrics_type_llu32,
};

/* addr should be in network order. Things are so much simpler that way. */
char* intoa (uint32_t /* host order */ addr, char* buf, uint16_t buf_len) {

    char *cp, *retStr;
    uint8_t byteval;
    int n;

    cp = &buf[buf_len];
    *--cp = '\0';

    n = 4;
    do {
        byteval = addr & 0xff;
        *--cp = byteval % 10 + '0';
        byteval /= 10;
        if(byteval > 0) {
            *--cp = byteval % 10 + '0';
            byteval /= 10;
            if(byteval > 0) {
                *--cp = byteval + '0';
            }
        }
        *--cp = '.';
        addr >>= 8;
    } while(--n > 0);

    /* Convert the string to lowercase */
    retStr = (char*)(cp + 1);

    return(retStr);
}


/* ************************************** */

/* An edge joins exactly one community: of [community], or of the only
 * [community NAME] section, whose settings then move to conf->community.
 * Returns 0, or -1 if there are more. */
int edge_conf_one_community (n2n_edge_conf_t *conf) {

    struct n3n_conf_community *comm = conf->communities;
    unsigned int count = HASH_COUNT(conf->communities);

    if(count == 0) {
        return 0;
    }
    if((count > 1) || conf->community.community_name[0]) {
        traceEvent(TRACE_ERROR, "an edge joins only one community, but the configuration has %u",
                   count + (conf->community.community_name[0] != 0));
        return -1;
    }

    if(comm->network.net_addr || comm->users) {
        traceEvent(TRACE_WARNING, "community.network and community.user are only for a supernode, ignoring");
    }

    HASH_DEL(conf->communities, comm);
    free(conf->community.encrypt_key);
    n3n_conf_strlist_free(&conf->community.users);
    conf->community = *comm;
    memset(&conf->community.hh, 0, sizeof(conf->community.hh));
    conf->community.users = NULL;
    n3n_conf_strlist_free(&comm->users);
    free(comm);

    traceEvent(TRACE_INFO, "joining community '%s' of section [community %s]",
               conf->community.community_name, conf->community.instance);
    return 0;
}


/* What follows from the settings of the community and of the user/password
 * authentication: the default cipher, the keys of the user, header
 * encryption.  Before edge_verify_conf() and edge_init(). */
void edge_conf_prepare (n2n_edge_conf_t *conf) {

    // payload
    if(conf->community.transop_id == N2N_TRANSFORM_ID_NULL) {
        if(conf->community.encrypt_key) {
            // make sure that AES is default cipher if key only (and no cipher) is specified
            traceEvent(TRACE_WARNING, "switching to AES as key was provided and no cipher set");
            conf->community.transop_id = N2N_TRANSFORM_ID_AES;
        }
    }
    // user auth
    if(conf->shared_secret /* containing private key only so far*/) {
        // if user-password auth and no federation public key provided, use default
        if(!conf->federation_public_key) {
            conf->federation_public_key = calloc(1, sizeof(n2n_private_public_key_t));
            if(conf->federation_public_key) {
                traceEvent(
                    TRACE_WARNING,
                    "using default federation public key; "
                    "FOR TESTING ONLY, usage of a custom federation name and "
                    "key (auth.pubkey) is highly recommended!"
                );
                generate_private_key(*(conf->federation_public_key), FEDERATION_NAME_DEFAULT);
                generate_public_key(*(conf->federation_public_key), *(conf->federation_public_key));
            }
        }
        // calculate public key and shared secret
        if(conf->federation_public_key) {
            traceEvent(TRACE_NORMAL, "using username and password for edge authentication");
            bind_private_key_to_username(*(conf->shared_secret), (char *)conf->dev_desc);
            conf->public_key = calloc(1, sizeof(n2n_private_public_key_t));
            if(conf->public_key)
                generate_public_key(*conf->public_key, *(conf->shared_secret));
            generate_shared_secret(*(conf->shared_secret), *(conf->shared_secret), *(conf->federation_public_key));
            // prepare (first 128 bit) for use as key
            speck_init(&conf->shared_secret_ctx, *(conf->shared_secret), 128);
        }
        // force header encryption
        if(conf->community.header_encryption != HEADER_ENCRYPTION_ENABLED) {
            traceEvent(TRACE_NORMAL, "enabling header encryption for edge authentication");
            conf->community.header_encryption = HEADER_ENCRYPTION_ENABLED;
        }
    }
}


int edge_verify_conf (const n2n_edge_conf_t *conf) {

    if(conf->community.community_name[0] == 0)
        return -1;

    if(!conf->client.local_link && !resolve_hostnames_str_get(RESOLVE_LIST_SUPERNODE, 0)) {
        // confirm that there is at least one supernode string provided
        return -5;
    }

    if(conf->client.register_interval < 1)
        return -3;

    if(((conf->community.encrypt_key == NULL) && (conf->community.transop_id != N2N_TRANSFORM_ID_NULL)) ||
       ((conf->community.encrypt_key != NULL) && (conf->community.transop_id == N2N_TRANSFORM_ID_NULL)))
        return -4;

    return 0;
}

/* ************************************** */

// Detect the local address by probing a connection to the supernode: the
// address the kernel would send from towards the supernode, of whichever
// family the supernode's address is, and the port of the socket for that
// family.
int detect_local_ip_address (n3n_sock_t* out_sock, const struct n3n_runtime_data* eee) {

    struct sockaddr_storage local_sock;
    struct sockaddr_storage sn_sock;
    socklen_t sock_len;
    socklen_t sn_len;
    n3n_sock_t main_sock;
    SOCKET probe_sock;

    memset(out_sock, 0, sizeof(*out_sock));
    out_sock->family = AF_INVALID;

    if(!eee->client.curr_sn) {
        // We dont have a current supernode, so we cannot use it to find our
        // local address
        // TODO: fall back to a different sample dest address?
        return -5;
    }

    // always detect local port even/especially if chosen by OS...
    SOCKET sock = eee->sock;
    int i = bind_entry_for_family(eee, eee->client.curr_sn->sock.family);
    if(i >= 0) {
        sock = eee->bind_sock[i];
    }
    sock_len = sizeof(local_sock);
    if(getsockname(sock, (struct sockaddr *)&local_sock, &sock_len) != 0) {
        return -1;
    }
    if(fill_n3nsock(&main_sock, (struct sockaddr *)&local_sock) != 0) {
        return -1;
    }

    memset(&sn_sock, 0, sizeof(sn_sock));
    sn_len = fill_sockaddr((struct sockaddr *)&sn_sock, sizeof(sn_sock), &eee->client.curr_sn->sock);
    if(sn_len == 0) {
        // supernode not resolved yet
        return -3;
    }

    // connecting the UDP socket makes getsockname read the local address it
    // uses to connect (to the sn in this case);  we cannot do it with the
    // real (eee->sock) socket because socket does not accept any conenction
    // from elsewhere then, e.g. from another edge instead of the supernode;
    // as re-connecting to AF_UNSPEC might not work to release the socket
    // on non-UNIXoids, we use a temporary socket

    probe_sock = socket(sn_sock.ss_family, SOCK_DGRAM, 0);
    if(probe_sock < 0) {
        return -2;
    }

    if(connect(probe_sock, (struct sockaddr *)&sn_sock, sn_len) != 0) {
        closesocket(probe_sock);
        return -3;
    }

    sock_len = sizeof(local_sock);
    if(getsockname(probe_sock, (struct sockaddr *)&local_sock, &sock_len) != 0) {
        closesocket(probe_sock);
        return -4;
    }
    closesocket(probe_sock);

    if(fill_n3nsock(out_sock, (struct sockaddr *)&local_sock) != 0) {
        return -4;
    }
    out_sock->port = main_sock.port;

    return 0;
}


// TOS and path MTU discovery, for a socket of either family; quiet for the
// many sockets opened behind a hard NAT
void set_sock_options (struct n3n_runtime_data *eee, SOCKET sock, int family, bool quiet) {

    int sockopt;

    if(eee->conf.tos) {
        /*
         * See https://www.tucny.com/Home/dscp-tos for a quick table of
         * the intended functions of each TOS value
         *
         * Note that the tos value is a byte and the manpage for IP_TOS
         * defines it as a byte, but we hand setsockopt() an int value.
         * This does work on linux, but - TODO, check this on other OS
         */
        sockopt = eee->conf.tos;
        int r = -1;
        if(family == AF_INET) {
            r = setsockopt(sock, IPPROTO_IP, IP_TOS, (char *)&sockopt, sizeof(sockopt));
        }
#ifdef IPV6_TCLASS
        if(family == AF_INET6) {
            r = setsockopt(sock, IPPROTO_IPV6, IPV6_TCLASS, (char *)&sockopt, sizeof(sockopt));
        }
#endif
        if(r != 0)
            traceEvent(TRACE_WARNING, "could not set TOS 0x%x[%d]: %s", eee->conf.tos, errno, strerror(errno));
        else if(!quiet)
            traceEvent(TRACE_INFO, "TOS set to 0x%x", eee->conf.tos);
    }

#ifdef IP_PMTUDISC_DO
    if(!quiet) {
        traceEvent(
            TRACE_INFO,
            "Setting pmtu_discovery %s",
            (eee->conf.pmtu_discovery) ? "true" : "false"
        );
    }

    int r = 0;
    if(family == AF_INET) {
        sockopt = eee->conf.pmtu_discovery ? IP_PMTUDISC_DO : IP_PMTUDISC_DONT;
        r = setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &sockopt, sizeof(sockopt));
    }
#ifdef IPV6_PMTUDISC_DO
    if(family == AF_INET6) {
        sockopt = eee->conf.pmtu_discovery ? IPV6_PMTUDISC_DO : IPV6_PMTUDISC_DONT;
        r = setsockopt(sock, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &sockopt, sizeof(sockopt));
    }
#endif
    if(r < 0) {
        traceEvent(
            TRACE_WARNING,
            "Setting pmtu_discovery failed: %s(%d)",
            strerror(errno),
            errno
        );
    }
#else
    if(!quiet)
        traceEvent(TRACE_INFO, "No platform support for setting pmtu_discovery");
#endif
}


// The UDP sockets, one for each address of connection.bind, by default [::]:0,
// which stands for an IPv6 and an IPv4 socket on ports of the system's choice.
// A family the system does not have is left out quietly, unless asked for.
int open_udp_sockets (struct n3n_runtime_data *eee) {

    struct sockaddr_storage list[N3N_BIND_MAX + 1];
    int count = 0;

    memset(list, 0, sizeof(list));
    if(eee->conf.bind_address) {
        const struct sockaddr_storage *conf_list = (const struct sockaddr_storage *)eee->conf.bind_address;
        while((count < N3N_BIND_MAX) && conf_list[count].ss_family) {
            list[count] = conf_list[count];
            count++;
        }
    } else {
        struct sockaddr_in6 *any = (struct sockaddr_in6 *)&list[0];
        any->sin6_family = AF_INET6;
        any->sin6_addr = in6addr_any;
    }

    if(n3n_open_bind_sockets(eee, list, false, eee->conf.bind_address ? TRACE_WARNING : TRACE_INFO) != 0) {
        return -1;
    }
    for(int i = 0; i < eee->bind_count; i++) {
        mainloop_register_fd(eee->bind_sock[i], fd_info_proto_v3udp);
        set_sock_options(eee, eee->bind_sock[i], eee->bind_family[i], false);
    }

    // the NAT maps new sockets anew; each family's samples are about the
    // socket that sends to that family
    for(int f = 0; f < 2; f++) {
        int i = bind_entry_for_family(eee, f ? AF_INET6 : AF_INET);
        struct sockaddr_storage sa;
        socklen_t len = sizeof(sa);
        uint16_t port = 0;
        if((i >= 0) && (getsockname(eee->bind_sock[i], (struct sockaddr *)&sa, &len) == 0)) {
            port = ntohs((sa.ss_family == AF_INET6) ? ((struct sockaddr_in6 *)&sa)->sin6_port
                                                     : ((struct sockaddr_in *)&sa)->sin_port);
        }
        nat_view_reset(&eee->client.nat[f], port);
    }
    return 0;
}


// the UDP sockets, or the TCP connection to the supernode
void close_sockets (struct n3n_runtime_data *eee) {

    punch_close_all(eee);
    if(eee->bind_count) {
        for(int i = 0; i < eee->bind_count; i++) {
            mainloop_unregister_fd(eee->bind_sock[i]);
        }
        close_bind_sockets(eee);
        return;
    }
    if(eee->sock >= 0) {
        mainloop_unregister_fd(eee->sock);
        closesocket(eee->sock);
        eee->sock = -1;
    }
}


/* ************************************** */

/** Initialise an edge to defaults.
 *
 *    This also initialises the NULL transform operation opstruct.
 */
struct n3n_runtime_data* edge_init (const n2n_edge_conf_t *conf, int *rv) {

    n2n_transform_t transop_id = conf->community.transop_id;
    struct n3n_runtime_data *eee = calloc(1, sizeof(struct n3n_runtime_data));
    int rc = -1;
    uint8_t tmp_key[N2N_AUTH_CHALLENGE_SIZE];

    if(!eee) {
        traceEvent(TRACE_ERROR, "cannot allocate memory");
        goto edge_init_error;
    }

    memcpy(&eee->conf, conf, sizeof(*conf));

#ifdef _WIN32
    // TODO: more investigations in interface naming/renaming on windows
#else
    if(eee->conf.tap.tuntap_dev_name[0] == 0) {
        snprintf(
            eee->conf.tap.tuntap_dev_name,
            sizeof(eee->conf.tap.tuntap_dev_name),
            "%s",
            conf->sessionname
        );
    }
#endif

    if(conf->client.local_link) {
        // the one supernode is that of this process
        struct peer_info *sn = peer_info_malloc(null_mac);
        if(!sn) {
            goto edge_init_error;
        }
        local_link_sock(&sn->sock);
        HASH_ADD_PEER(eee->client.supernodes, sn);
    } else {
        // Show the user what has been configured
        resolve_log_hostnames(RESOLVE_LIST_SUPERNODE);

        if(resolve_hostnames_str_to_peer_info(
               RESOLVE_LIST_SUPERNODE,
               &eee->client.supernodes)) {
            traceEvent(
                TRACE_WARNING,
                "resolve_hostnames_str_to_peer_info returned errors"
            );
        }
    }

    // Statically calculate how many packet buffers we need:
    // - one for resolver, one for rx, one for tx, one spare
    // (We might need more for multi-peer buffered TCP connections, or for
    // multi-queue / multi-thread
    n3n_pktbuf_initialise(eee->conf.tap.mtu, 4);

    eee->client.curr_sn = eee->client.supernodes;
    eee->start_time = time(NULL);

    eee->client.known_peers        = NULL;
    eee->client.pending_peers    = NULL;
    reset_sup_attempts(eee);

    sn_selection_criterion_common_data_default(eee);

    // always initialize compression transforms so we can at least decompress
    rc = n2n_transop_lzo_init(&eee->conf, &eee->client.transop_lzo);
    if(rc) goto edge_init_error; /* error message is printed in lzo_init */
#ifdef HAVE_LIBZSTD
    rc = n2n_transop_zstd_init(&eee->conf, &eee->client.transop_zstd);
    if(rc) goto edge_init_error; /* error message is printed in zstd_init */
#endif

    /* Set active transop */
    switch(transop_id) {
        case N2N_TRANSFORM_ID_TWOFISH:
            rc = n2n_transop_tf_init(&eee->conf, &eee->client.transop);
            break;

        case N2N_TRANSFORM_ID_AES:
            rc = n2n_transop_aes_init(&eee->conf, &eee->client.transop);
            break;

        case N2N_TRANSFORM_ID_CHACHA20:
            rc = n2n_transop_cc20_init(&eee->conf, &eee->client.transop);
            break;

        case N2N_TRANSFORM_ID_SPECK:
            rc = n2n_transop_speck_init(&eee->conf, &eee->client.transop);
            break;

        default:
            rc = n2n_transop_null_init(&eee->conf, &eee->client.transop);
    }

    if((rc < 0) || (eee->client.transop.fwd == NULL) || (eee->client.transop.transform_id != transop_id)) {
        traceEvent(TRACE_ERROR, "transop init failed");
        goto edge_init_error;
    }

    // set the key schedule (context) for header encryption if enabled
    if(conf->community.header_encryption == HEADER_ENCRYPTION_ENABLED) {
        traceEvent(TRACE_NORMAL, "Header encryption is enabled.");
        packet_header_setup_key((char *)(eee->conf.community.community_name),
                                &(eee->conf.header_encryption_ctx_static),
                                &(eee->conf.header_encryption_ctx_dynamic),
                                &(eee->conf.header_iv_ctx_static),
                                &(eee->conf.header_iv_ctx_dynamic));
        // in case of user/password auth, initialize a random dynamic key to prevent
        // unintentional communication with only-header-encrypted community; will be
        // overwritten by legit key later
        if(conf->shared_secret) {
            memrnd(tmp_key, N2N_AUTH_CHALLENGE_SIZE);
            packet_header_change_dynamic_key(tmp_key,
                                             &(eee->conf.header_encryption_ctx_dynamic),
                                             &(eee->conf.header_iv_ctx_dynamic));
        }
    }

    // setup authentication scheme
    if(!conf->shared_secret) {
        // id-based scheme
        eee->conf.client.auth.scheme = n2n_auth_simple_id;
        // random authentication token
        memrnd(eee->conf.client.auth.token, N2N_AUTH_ID_TOKEN_SIZE);
        eee->conf.client.auth.token_size = N2N_AUTH_ID_TOKEN_SIZE;
    } else {
        // user-password scheme
        eee->conf.client.auth.scheme = n2n_auth_user_password;
        // 'token' stores public key and the last random challenge being set upon sending REGISTER_SUPER
        memcpy(eee->conf.client.auth.token, eee->conf.public_key, N2N_PRIVATE_PUBLIC_KEY_SIZE);
        // random part of token (challenge) will be generated and filled in at each REGISTER_SUPER
        eee->conf.client.auth.token_size = N2N_AUTH_PW_TOKEN_SIZE;
        // make sure that only stream ciphers are being used
        if((transop_id != N2N_TRANSFORM_ID_CHACHA20)
           && (transop_id != N2N_TRANSFORM_ID_SPECK)) {
            traceEvent(TRACE_ERROR, "user-password authentication requires ChaCha20 or SPECK to be used.");
            goto edge_init_error;
        }
    }

    if(eee->client.transop.no_encryption)
        traceEvent(TRACE_WARNING, "encryption is disabled in edge");

    // first time calling edge_init_sockets needs -1 in the sockets for it does throw an error
    // on trying to close them (open_sockets does so for also being able to RE-open the sockets
    // if called in-between, see "Supernode not responding" in update_supernode_reg(...)
    eee->sock = -1;
    eee->client.advertised_sock.family = AF_INVALID;
#ifndef SKIP_MULTICAST_PEERS_DISCOVERY
    eee->client.udp_multicast_sock_v4 = -1;
    eee->client.udp_multicast_sock_v6 = -1;
#endif
    // the edge of a supernode has no sockets, nor names to resolve
    if(!conf->client.local_link) {
        if(edge_init_sockets(eee) < 0) {
            traceEvent(TRACE_ERROR, "socket setup failed");
            goto edge_init_error;
        }

        if(resolve_create_thread(&(eee->resolve_parameter), eee->client.supernodes) == 0) {
            traceEvent(TRACE_NORMAL, "successfully created resolver thread");
        }
    }

    // TODO: skip creating this if there are no filters to add
    eee->tap.network_traffic_filter = create_network_traffic_filter();
    network_traffic_filter_add_rule(eee->tap.network_traffic_filter, eee->conf.tap.network_traffic_filter_rules);

    //edge_init_success:
    *rv = 0;
    return(eee);

edge_init_error:
    if(eee)
        edge_term(eee);
    *rv = rc;
    return(NULL);
}

/* ************************************** */

/** Send a datagram to a socket defined by a n3n_sock_t */
void edge_sendto_sock (struct n3n_runtime_data *eee, const void * buf,
                       size_t len, const n3n_sock_t * dest) {

    // provides enough space for all protocol families per which it varies
    struct sockaddr_storage peer_addr_storage = {0};
    struct sockaddr_storage dest_addr = {0};
    socklen_t peer_addr_len = 0;

    if(!dest->family) {
        traceEvent(TRACE_ERROR, "bad dest->family");
        // invalid socket
        return;
    }

    if(eee->conf.client.local_link) {
        // without sockets, only to the supernode in this process
        if(local_link_is_sock(dest)) {
            local_link_to_relay(buf, len);
        } else {
            n3n_sock_str_t sockbuf;
            traceEvent(TRACE_DEBUG, "local edge: dropped a PDU to [%s], it reaches its peers through its supernode",
                       sock_to_cstr(sockbuf, dest));
        }
        return;
    }

    if(eee->sock < 0) {
        traceEvent(TRACE_DEBUG, "bad eee->sock");
        // invalid socket file descriptor, e.g. TCP unconnected has fd of '-1'
        return;
    }

    // TODO:
    // - also check n3n_sock_t type == SOCK_STREAM as a TCP indicator?

    // if the connection is tcp, i.e. not the regular sock...
    if(eee->conf.client.connect_tcp) {
        mainloop_send_v3tcp(eee->sock, buf, len);
        /*
         * TODO: metrics for errors
         */
        return;
    }

    // network order socket
    peer_addr_len = fill_sockaddr((struct sockaddr *) &peer_addr_storage, sizeof(peer_addr_storage), dest);
    if(peer_addr_len == 0) {
        traceEvent(TRACE_WARNING, "failed to prepare sockaddr for family %d", dest->family);
        return;
    }

    traceEvent(TRACE_DEBUG, "%s AF %i", __func__, dest->family);

    if(is_link_local(dest)) {
        traceEvent(TRACE_DEBUG, "not sending to a link-local address");
        return;
    }

    // behind a hard NAT, a peer that got through to a socket opened for it
    // can only be reached from that one, see punch_note_rx()
    if(eee->client.punch_bound_count) {
        const struct punch_bound *b = punch_bound_find(eee, dest);
        if(b) {
            peer_addr_len = fill_sockaddr((struct sockaddr *)&dest_addr, sizeof(dest_addr), &b->dest);
            sendto_logged(b->fd, buf, len, (struct sockaddr *)&dest_addr, peer_addr_len);
            return;
        }
    }

    int i = bind_entry_for_family(eee, dest->family);
    if(i < 0) {
        // e.g. an IPv6 peer, and this edge bound to an IPv4 address only
        traceEvent(TRACE_DEBUG, "no socket for address family %d", dest->family);
        return;
    }

    // a packet thread sends from its own socket for that address
    sendto_bind(eee, i, buf, len, (const struct sockaddr *)&peer_addr_storage);
}

/* ************************************** */

/** A PACKET has arrived containing an encapsulated ethernet datagram - usually
 *    encrypted. */
void edge_event_apply (struct n3n_runtime_data *eee, const struct edge_event *ev) {

    switch(ev->type) {
        case EDGE_EVENT_PENDING_REMOVE:
            find_and_remove_peer(&eee->client.pending_peers, ev->mac);
            break;

        case EDGE_EVENT_PEER_SEEN:
            check_peer_registration_needed(eee, ev->from_supernode, ev->via_multicast,
                                           ev->mac, ev->cookie, NULL, NULL, &ev->sock);
            break;

        case EDGE_EVENT_HOST_SEEN: {
#ifdef HAVE_BRIDGING_SUPPORT
            struct host_info *host = NULL;

            HASH_FIND(hh, eee->tap.known_hosts, ev->host, sizeof(n2n_mac_t), host);
            if(host == NULL) {
                host = calloc(1, sizeof(struct host_info));
                // TODO: alloc() on the packet path can cause bad latency

                memcpy(host->mac_addr, ev->host, sizeof(n2n_mac_t));
                HASH_ADD(hh, eee->tap.known_hosts, mac_addr, sizeof(n2n_mac_t), host);
            }
            memcpy(host->edge_addr, ev->mac, sizeof(n2n_mac_t));
            host->last_seen = ev->now;
#endif
            break;
        }

        case EDGE_EVENT_PEER_EXPIRE: {
            struct peer_info *scan;

            // a PACKET from the peer may have come in since the event was
            // posted, so check again
            HASH_FIND_PEER(eee->client.known_peers, ev->mac, scan);
            if(scan && (scan->last_seen > 0)
               && ((ev->now - scan->last_p2p) >= (scan->timeout / 2))) {
                HASH_DEL(eee->client.known_peers, scan);
                mgmt_event_post(N3N_EVENT_PEER,N3N_EVENT_PEER_P2P_EXPIRED,scan);
                peer_info_free(scan);
            }
            break;
        }

        case EDGE_EVENT_QUERY_PEER:
            check_query_peer_info(eee, ev->now, ev->mac);
            break;
    }
}


// hand a change to whoever changes the peer tables: the main thread applies
// it at once, a packet thread queues it for the main thread
void edge_event_post (struct n3n_runtime_data *eee, const struct edge_event *ev) {

    if(n3n_thread_slot) {
        edge_threads_post_event(eee, ev);
        return;
    }
    edge_event_apply(eee, ev);
}


// is this peer in the list of those we are still trying to reach?
int peer_is_pending (struct n3n_runtime_data *eee, const n2n_mac_t mac) {

    struct peer_info *scan;

    if(!eee->client.pending_peers) {
        return 0;
    }
    HASH_FIND_PEER(eee->client.pending_peers, mac, scan);

    return scan != NULL;
}


/* The part of check_peer_registration_needed() that nearly every packet
 * takes: the peer is known by its MAC and was already seen within this
 * second, so only its time stamps are refreshed. Returns 0 if more is needed
 * - anything that may change the peer tables - which then is an event. */
int peer_seen_fast (struct n3n_runtime_data *eee,
                    uint8_t from_supernode,
                    uint8_t via_multicast,
                    const n2n_mac_t mac,
                    const n2n_cookie_t cookie) {

    struct peer_info *scan;
    time_t now;

    HASH_FIND_PEER(eee->client.known_peers, mac, scan);
    if(!scan) {
        return 0;
    }

    now = time(NULL);
    if(((now - scan->last_seen) > 0 /* >= 1 sec */)
       ||(cookie > scan->last_cookie)) {
        return 0;
    }

    if(!from_supernode)
        SHARED_STORE(scan->last_p2p, now);

    if(via_multicast)
        SHARED_STORE(scan->local, 1);

    return 1;
}

/* ************************************** */

// what the workers of an edge do
static const struct edge_thread_ops edge_thread_ops = {
    .read_udp = edge_read_proto3_udp,
    .process_pdu = process_pdu_control,
    .tap = 1,
};


/* ************************************** */


/* The handlers of the PDUs an edge takes, by message type - see
 * edge_pdu_handlers below.  Each takes the locals it needs from the
 * struct pdu_ctx first.  All but PACKET run on the main thread. */

// The PDUs an edge takes
static const pdu_handlers_t edge_pdu_handlers = {
    [MSG_TYPE_REGISTER] = edge_rx_register,
    [MSG_TYPE_PACKET] = edge_rx_packet,
    [MSG_TYPE_REGISTER_ACK] = edge_rx_register_ack,
    [MSG_TYPE_REGISTER_SUPER_ACK] = edge_rx_register_super_ack,
    [MSG_TYPE_REGISTER_SUPER_NAK] = edge_rx_register_super_nak,
    [MSG_TYPE_PEER_INFO] = edge_rx_peer_info,
    [MSG_TYPE_RE_REGISTER_SUPER] = edge_rx_re_register_super,
};


// A control message a packet thread handed over, on the main thread
void process_pdu_control (struct n3n_runtime_data *eee, struct pdu_ctx *c) {

    struct peer_info *sn = NULL;

    // the supernode is looked up again rather than passed in: a pointer into
    // the list must not travel with the PDU. edge_process_pdu() has already
    // dropped the PDU if this lookup fails, so it only fails if the supernode
    // was removed in between.
    if(c->from_supernode) {
        int sn_skip_add = SN_ADD_SKIP;
        sn = add_sn_to_list_by_mac_or_sock(&(eee->client.supernodes), &c->sender, null_mac, &sn_skip_add);
        if(!sn) {
            traceEvent(TRACE_DEBUG, "dropped incoming data from unknown supernode");
            return;
        }
    }

    c->sn = sn;
    pdu_dispatch(eee, edge_pdu_handlers, c);
}


/** handle a datagram from the main UDP socket to the internet. */
void edge_process_pdu (struct n3n_runtime_data *eee,
                       const struct sockaddr *sender_sock,
                       const SOCKET in_sock,
                       uint8_t *udp_buf,
                       size_t udp_size,
                       time_t now
) {

    n2n_common_t cmn;          /* common fields in the packet header */
    n3n_sock_str_t sockbuf1;
    uint8_t hash_buf[16] = {0};
    size_t rem;
    size_t idx;
    size_t msg_type;
    uint8_t from_supernode;
    uint8_t via_multicast;
    struct peer_info *sn = NULL;
    n3n_sock_t sender;
    uint32_t header_enc = 0;
    uint64_t stamp = 0;
    int skip_add = 0;

    /* REVISIT: when UDP/IPv6 is supported we will need a flag to indicate which
     * IP transport version the packet arrived on. May need to UDP sockets. */

    // TODO: pass the sender to edge_process_pdu, dont calculate it here
    if(eee->conf.client.connect_tcp)
        // TCP expects that we know our comm partner and does not deliver the sender
        memcpy(&sender, &(eee->client.curr_sn->sock), sizeof(sender));
    else {
        // REVISIT: type conversion back and forth, choose a consistent approach throughout whole code,
        //          i.e. stick with more general sockaddr as long as possible and narrow only if required
        fill_n3nsock(&sender, sender_sock);
    }
#ifdef SKIP_MULTICAST_PEERS_DISCOVERY
    via_multicast = 0;
#else
    via_multicast = ((in_sock == eee->client.udp_multicast_sock_v4) ||
                     (in_sock == eee->client.udp_multicast_sock_v6));
#endif

    traceEvent(TRACE_DEBUG, "Rx VPN packet of size %d from [%s]",
               (signed int)udp_size, sock_to_cstr(sockbuf1, &sender));

    if(eee->conf.community.header_encryption == HEADER_ENCRYPTION_ENABLED) {
        // with the dynamic (2) or the static (1) keys?  The hash is only
        // checked with user/password authentication
        header_enc = pdu_header_decrypt(udp_buf, udp_size, (char *)eee->conf.community.community_name,
                                        eee->conf.header_encryption_ctx_dynamic, eee->conf.header_iv_ctx_dynamic,
                                        eee->conf.header_encryption_ctx_static, eee->conf.header_iv_ctx_static,
                                        eee->conf.shared_secret ? hash_buf : NULL, &stamp);
        if(!header_enc) {
            traceEvent(TRACE_DEBUG, "failed to decrypt header");
            return;
        }
        // time stamp verification follows in the packet specific section as it requires to determine the
        // sender from the hash list by its MAC, or the packet might be from the supernode, this all depends
        // on packet type, path taken (via supernode) and packet structure (MAC is not always in the same place)
    }

    rem = udp_size; /* Counts down bytes of packet to protect against buffer overruns. */
    idx = 0; /* marches through packet header as parts are decoded. */
    if(decode_common(&cmn, udp_buf, &rem, &idx) < 0) {
        if(via_multicast) {
            // from some other edge on local network, possibly header encrypted
            traceEvent(TRACE_DEBUG, "dropped packet arriving via multicast due to error while decoding N2N_UDP");
        } else {
            traceEvent(TRACE_INFO, "failed to decode common section in N2N_UDP");
        }
        return; /* failed to decode packet */
    }

    msg_type = cmn.pc; /* packet code */

    // special case for user/pw auth
    // community's auth scheme and message type need to match the used key (dynamic)
    if((eee->conf.shared_secret)
       && (msg_type != MSG_TYPE_REGISTER_SUPER_ACK)
       && (msg_type != MSG_TYPE_REGISTER_SUPER_NAK)) {
        if(header_enc != 2) {
            traceEvent(TRACE_INFO, "dropped packet encrypted with static key where dynamic key expected");
            return;
        }
    }

    // check if packet is from supernode and find the corresponding supernode in list
    from_supernode = cmn.flags & N2N_FLAGS_FROM_SUPERNODE;
    if(from_supernode) {
        skip_add = SN_ADD_SKIP;
        sn = add_sn_to_list_by_mac_or_sock(&(eee->client.supernodes), &sender, null_mac, &skip_add);
        if(!sn) {
            traceEvent(TRACE_DEBUG, "dropped incoming data from unknown supernode");
            return;
        }
    }

    if(0 != memcmp(cmn.community, eee->conf.community.community_name, N2N_COMMUNITY_SIZE)) {
        // The community in the packet is not matching ours

        if(from_supernode) {
            traceEvent(TRACE_INFO, "received packet with unknown community");
            // TODO:
            // stats.errors.community.supernode ++;
        } else {
            traceEvent(
                TRACE_INFO,
                "ignoring packet with unknown community (%s)",
                cmn.community
            );
            // TODO:
            // stats.errors.community.other ++;
        }

        return;
    }

    // The control messages - registrations, peer info, supernode answers -
    // change the tables, which only the main thread does: a packet thread
    // hands them over, with a copy of the PDU, while the buffer it arrived in
    // is reused.
    struct pdu_ctx c = {
        .buf = udp_buf,
        .size = udp_size,
        .cmn = cmn,
        .rem = rem,
        .idx = idx,
        .sender = sender,
        .header_enc = header_enc,
        .stamp = stamp,
        .from_supernode = from_supernode,
        .via_multicast = via_multicast,
        .socket_fd = in_sock,
        .now = now,
        .sender_sock = sender_sock,
        .sn = sn,
    };

    memcpy(c.hash_buf, hash_buf, sizeof(c.hash_buf));

    if(n3n_thread_slot && (msg_type != MSG_TYPE_PACKET)) {
        edge_threads_post_pdu(eee, &c);
        return;
    }
    pdu_dispatch(eee, edge_pdu_handlers, &c);
}


/* ************************************** */

/** Read a single datagram from a UDP socket and process it.
 *
 * Returns 1 if a datagram was taken off the socket queue, 0 if the queue was
 * empty and -1 if the socket is no good any more.  The caller can use this to
 * drain several datagrams from one readiness event.
 */
int edge_read_proto3_udp (struct n3n_runtime_data *eee,
                          SOCKET sock,
                          struct n3n_pktbuf *pktbuf,
                          time_t now) {
    struct sockaddr_storage sas;
    struct sockaddr *sender_sock = (struct sockaddr*)&sas;
    socklen_t ss_size = sizeof(sas);

    // The caller may hand us the same buffer several times while draining
    n3n_pktbuf_zero(pktbuf);

    ssize_t bread = recvfrom(
        sock,
        n3n_pktbuf_getbufptr(*pktbuf),
        n3n_pktbuf_getbufavail(*pktbuf),
        MSG_DONTWAIT,
        sender_sock,
        &ss_size
    );
    pktbuf->offset_end = pktbuf->offset_start + bread;

    if(bread < 0) {
#ifdef _WIN32
        unsigned int wsaerr = WSAGetLastError();
        if(wsaerr == WSAECONNRESET) {
            // On a UDP-datagram socket this error indicates a previous send
            // operation resulted in an ICMP Port Unreachable message.
            return 0;
        }
        if(wsaerr == WSAEWOULDBLOCK) {
            /* Nothing (more) queued for us */
            return 0;
        }
        traceEvent(TRACE_ERROR, "WSAGetLastError(): %u", wsaerr);
#else
        if((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
            /* We asked for a non blocking read, so this just means that
             * there is nothing (more) queued for us */
            return 0;
        }
#endif

        /* The fd is no good now. Maybe we lost our interface. */
        traceEvent(TRACE_ERROR, "recvfrom() failed %d errno %d (%s)", bread, errno, strerror(errno));
        *eee->keep_running = false;
        return -1;
    }
    if(bread == 0) {
        /* For UDP bread of zero just means no data (unlike TCP). */
        return 0;
    }

    // TODO:
    // - detect when pktbuf is too small for the packet and add that to stats
    //   (could switch to using recvmsg() for that)

    // behind a hard NAT, a peer may have got through to one of the sockets
    // opened for it, which only the main thread reads
    if((eee->client.punch_pool_fds || eee->client.punch_bound_count) && !n3n_thread_slot) {
        punch_note_rx(eee, sock, sender_sock, now);
    }

    // we have a datagram to process...
    // ...and the datagram has data (not just a header)
    //
    edge_process_pdu(
        eee,
        sender_sock,
        sock,
        n3n_pktbuf_getbufptr(*pktbuf),
        n3n_pktbuf_getbufsize(*pktbuf),
        now
    );
    return 1;
}

void edge_read_proto3_tcp (struct n3n_runtime_data *eee,
                           SOCKET sock,
                           uint8_t *pktbuf,
                           ssize_t pktbuf_len,
                           time_t now) {

    // tcp gets handed a pre filled pktbuf

    if(!pktbuf) {
        // the connection is gone, and the mainloop closed it already
        if(sock != eee->sock) {
            // not the one to the current supernode
            return;
        }
        traceEvent(TRACE_WARNING, "tcp connection to the supernode closed");
        eee->sock = -1;
        supernode_disconnect(eee);
        eee->client.sn_wait = 1;
        return;
    }

    // zero contents means an error
    if(pktbuf_len <= 0) {
        traceEvent(TRACE_ERROR, "tcp conn read error %i", pktbuf_len);
#ifdef _WIN32
        traceEvent(TRACE_ERROR, "WSAGetLastError(): %u", WSAGetLastError());
#endif
        supernode_disconnect(eee);
        eee->client.sn_wait = 1;
        return;
    }

    if(pktbuf_len > N2N_PKT_BUF_SIZE + 2) {
        supernode_disconnect(eee);
        eee->client.sn_wait = 1;
        traceEvent(TRACE_DEBUG, "too many bytes expected");
        return;
    }

    // have a valid packet read, handle it
    edge_process_pdu(
        eee,
        NULL,
        sock,
        pktbuf,
        pktbuf_len,
        now
    );
    return;
}

static void print_edge_stats (const struct n3n_runtime_data *eee) {

    struct n2n_edge_stats sum;
    const struct n2n_edge_stats *s = &sum;

    n3n_stats_sum(eee, &sum);

    traceEvent(TRACE_NORMAL, "**********************************");
    traceEvent(TRACE_NORMAL, "Packet stats:");
    traceEvent(TRACE_NORMAL, "      TX P2P: %u pkts", s->tx_p2p);
    traceEvent(TRACE_NORMAL, "      RX P2P: %u pkts", s->rx_p2p);
    traceEvent(TRACE_NORMAL, "      TX Supernode: %u pkts (%u broadcast)", s->tx_sup, s->tx_sup_broadcast);
    traceEvent(TRACE_NORMAL, "      RX Supernode: %u pkts (%u broadcast)", s->rx_sup, s->rx_sup_broadcast);
    traceEvent(TRACE_NORMAL, "**********************************");

    traceEvent(TRACE_INFO, "data structures tracked:");
    traceEvent(
        TRACE_INFO,
        "  traffic filter rules: %i",
        HASH_COUNT(eee->conf.tap.network_traffic_filter_rules)
    );
    traceEvent(
        TRACE_INFO,
        "  bridge known hosts: %i",
        HASH_COUNT(eee->tap.known_hosts)
    );
    traceEvent(
        TRACE_INFO,
        "  pending peers: %i",
        HASH_COUNT(eee->client.pending_peers)
    );
    traceEvent(
        TRACE_INFO,
        "  known peers: %i",
        HASH_COUNT(eee->client.known_peers)
    );
    traceEvent(
        TRACE_INFO,
        "  supernodes: %i",
        HASH_COUNT(eee->client.supernodes)
    );
    traceEvent(TRACE_INFO, "**********************************");
}


/* ************************************** */


// The regular work of the edge, done by the mainloop after each round, see
// mainloop_register_tick()

// a packet thread could not write to its queue of the tap device
static void edge_tick_tap (struct n3n_runtime_data *eee, time_t now) {

    if(edge_threads_tap_failed(eee)) {
        edge_tap_reopen(eee);
    }
}

static void edge_tick_registrations (struct n3n_runtime_data *eee, time_t now) {

    update_supernode_reg(eee, now);
    punch_sweep(eee, now);
}

// every PURGE_REGISTRATION_FREQUENCY seconds
static void edge_tick_purge (struct n3n_runtime_data *eee, time_t now) {

    size_t numPurged = 0;

    // keep, i.e. do not purge, the known peers while no supernode supernode connection
    if(!eee->client.sn_wait) {
        numPurged = purge_peer_list(&eee->client.known_peers, eee->sock, NULL, now - REGISTRATION_TIMEOUT);
    }
    numPurged += purge_peer_list(&eee->client.pending_peers, eee->sock, NULL, now - REGISTRATION_TIMEOUT);

    if(numPurged > 0) {
        traceEvent(
            TRACE_INFO,
            "%u peers removed. now: pending=%u, operational=%u",
            numPurged,
            HASH_COUNT(eee->client.pending_peers),
            HASH_COUNT(eee->client.known_peers)
        );
    }
}

#ifdef HAVE_BRIDGING_SUPPORT
// every SWEEP_TIME seconds
static void edge_tick_purge_hosts (struct n3n_runtime_data *eee, time_t now) {

    struct host_info *host, *host_tmp;

    if(!eee->conf.tap.allow_routing) {
        return;
    }
    HASH_ITER(hh, eee->tap.known_hosts, host, host_tmp) {
        if(now > host->last_seen + HOSTINFO_TIMEOUT) {
            HASH_DEL(eee->tap.known_hosts, host);
            free(host);
        }
    }
}
#endif

// every IFACE_UPDATE_INTERVAL seconds
static void edge_tick_dhcp (struct n3n_runtime_data *eee, time_t now) {

    // TODO:
    // - a static ip address mode
    // - a notifier so we dont need to poll for changes
    // - ipv6 support
    // - multi-homing support
    if(eee->conf.tap.tuntap_ip_mode == TUNTAP_IP_MODE_DHCP) {
        traceEvent(TRACE_INFO, "re-checking dynamic IP address");
        tuntap_get_address(&(eee->tap.device));
    }
}

static void edge_tick_supernodes (struct n3n_runtime_data *eee, time_t now) {

    sort_supernodes(eee, now);

    eee->client.resolution_request = resolve_check(
        eee->resolve_parameter,
        eee->client.resolution_request,
        now
    );

    if(eee->client.resolution_request) {
        // This currently gets signaled in update_supernode_reg when a
        // supernode is not responding
        //
        // TODO: update this once we have the new async resolving
        if(resolve_hostnames_str_to_peer_info(
               RESOLVE_LIST_SUPERNODE,
               &eee->client.supernodes)) {
            traceEvent(
                TRACE_WARNING,
                "resolve_hostnames_str_to_peer_info returned errors"
            );
        } else {
            // No errors, so clear the request
            eee->client.resolution_request = false;
        }
    }
}


// The regular work of an edge; rt NULL for the runtime of mainloop_run()
static void edge_register_ticks (struct n3n_runtime_data *rt) {

    mainloop_register_tick_rt(edge_tick_tap, 0, rt);
    mainloop_register_tick_rt(edge_tick_registrations, 0, rt);
    mainloop_register_tick_rt(edge_tick_purge, PURGE_REGISTRATION_FREQUENCY, rt);
#ifdef HAVE_BRIDGING_SUPPORT
    mainloop_register_tick_rt(edge_tick_purge_hosts, SWEEP_TIME, rt);
#endif
    mainloop_register_tick_rt(edge_tick_dhcp, IFACE_UPDATE_INTERVAL, rt);
    mainloop_register_tick_rt(edge_tick_supernodes, 0, rt);
}


int run_edge_loop (struct n3n_runtime_data *eee) {

#ifdef _WIN32
    struct tunread_arg arg;
    arg.eee = eee;
    HANDLE tun_read_thread = startTunReadThread(&arg);
#endif

    *eee->keep_running = true;
    update_supernode_reg(eee, time(NULL));

    // more threads for PACKETs, if asked for; from here on the main thread
    // holds their lock whenever it is awake
    edge_threads_start(eee, edge_threads_wanted(&eee->conf), &edge_thread_ops);

    edge_metrics_module1.data = &eee->stats_sum;
    edge_metrics_module2.data = &eee->stats_sum;
    n3n_metrics_register(&edge_metrics_module1);
    n3n_metrics_register(&edge_metrics_module2);

    edge_register_ticks(NULL);

    /* Main loop
     *
     * select() is used to wait for input on either the TAP fd or the UDP/TCP
     * socket. When input is present the data is read and processed by either
     * readFromIPSocket() or edge_read_from_tap()
     */
    mainloop_run(eee);

    edge_threads_stop(eee);

    send_unregister_super(eee);

#ifdef _WIN32
    // No, I dont want to wait for the thread to receive a tap packet
    // and unblock to read it.  So I kill it.  The MSDN warns against
    // using this function, but we are on the way to exit the program,
    // so I believe that the risk is low
    TerminateThread(tun_read_thread, 1);

    WaitForSingleObject(tun_read_thread, INFINITE);
#endif

    supernode_disconnect(eee);

    return 0;
}

/* ************************************** */

/* The edge of a supernode with supernode.tap: a runtime of its own in the
 * supernode's process, with the supernode's settings of the community and
 * of the TAP device.  It has no sockets: it reaches the supernode, and through
 * it all its peers, over the local link, see local_link.h.  It registers and
 * opens the TAP device here, so before the privileges are dropped; from then
 * on the mainloop of the supernode runs it, in its own runtime.
 * NULL on failure. */
struct n3n_runtime_data *edge_start_local (struct n3n_runtime_data *relay) {

    n2n_edge_conf_t conf = relay->conf;     // a copy, see edge_term()
    struct n3n_runtime_data *eee;
    macstr_t mac_buf;
    int rc;

#ifdef _WIN32
    traceEvent(TRACE_ERROR, "supernode.tap is not supported on Windows yet");
    return NULL;
#endif

    conf.is_supernode = false;
    conf.is_edge = true;
    conf.client.local_link = true;
    // only through the supernode, which is as direct as it gets for its
    // own edges; see edge_sendto_sock()
    conf.client.connect_tcp = false;
    conf.client.allow_p2p = false;
    conf.client.local_discovery = false;
    conf.client.punch_ports = 0;
    conf.threads = 1;
    conf.mgmt_port = 0;

    // with user/password authentication, the public key of the federation
    // is that of this supernode's
    if(conf.shared_secret && !conf.federation_public_key) {
        conf.federation_public_key = calloc(1, sizeof(n2n_private_public_key_t));
        if(conf.federation_public_key) {
            generate_private_key(*conf.federation_public_key, conf.relay.sn_federation);
            generate_public_key(*conf.federation_public_key, *conf.federation_public_key);
        }
    }

    edge_conf_prepare(&conf);
    if((rc = edge_verify_conf(&conf)) != 0) {
        traceEvent(TRACE_ERROR, "supernode.tap: missing or incomplete settings of the community (%d)", rc);
        return NULL;
    }

    eee = edge_init(&conf, &rc);
    if(!eee) {
        traceEvent(TRACE_ERROR, "supernode.tap: failed in edge_init");
        return NULL;
    }
    eee->keep_running = relay->keep_running;
    local_link_init(relay, eee);
    relay->relay.local_edge = eee;

    // register, to be given an address if the supernode hands them out;
    // the supernode answers right away
    eee->client.last_sup = 0;
    eee->client.sn_wait = 1;
    send_register_super(eee);
    local_link_drain(time(NULL));
    if((eee->conf.tap.tuntap_ip_mode == TUNTAP_IP_MODE_SN_ASSIGN) && eee->client.sn_wait) {
        traceEvent(TRACE_ERROR, "supernode.tap: the supernode did not take its own edge into community '%s'",
                   eee->conf.community.community_name);
        relay->relay.local_edge = NULL;
        edge_stop_local(eee);
        return NULL;
    }

    if(edge_tap_open(eee) < 0) {
        relay->relay.local_edge = NULL;
        edge_stop_local(eee);
        return NULL;
    }
#ifndef _WIN32
    mainloop_register_fd_rt(eee->tap.device.fd, fd_info_proto_tuntap, eee);
#endif
    in_addr_t addr = eee->conf.tap.tuntap_v4.net_addr;
    struct in_addr *tmp = (struct in_addr *)&addr;
    traceEvent(TRACE_NORMAL, "supernode.tap: tap device of community '%s', IPv4: %s/%u, MAC: %s",
               eee->conf.community.community_name,
               inet_ntoa(*tmp),
               eee->conf.tap.tuntap_v4.net_bitlen,
               macaddr_str(mac_buf, eee->tap.device.mac_addr));

    // as an edge after its bootstrap: register with the MAC of the TAP
    // device now, and keep doing so
    eee->client.sn_wait = 1;
    eee->client.last_register_req = 0;
    update_supernode_reg(eee, time(NULL));
    edge_register_ticks(eee);

    return eee;
}


// The edge of edge_start_local() goes
void edge_stop_local (struct n3n_runtime_data *eee) {

    local_link_init(NULL, NULL);
#ifndef _WIN32
    if(eee->tap.device.fd > 0) {
        mainloop_unregister_fd(eee->tap.device.fd);
        tuntap_close(&eee->tap.device);
    }
#endif
    edge_term(eee);
}


/** Deinitialise the edge conf structure and deallocate any memory */

void edge_term_conf (n2n_edge_conf_t *conf) {

    if(conf->tap.network_traffic_filter_rules) {
        filter_rule_t *el = 0, *tmp = 0;
        HASH_ITER(hh, conf->tap.network_traffic_filter_rules, el, tmp) {
            HASH_DEL(conf->tap.network_traffic_filter_rules, el);
            free(el);
        }
    }

    // - have a helper to calculate/remember the socket pathname
#ifndef _WIN32
    char unixsock[1024];
    snprintf(unixsock, sizeof(unixsock), "%s/mgmt", conf->sessiondir);
    unlink(unixsock);
    if(conf->sessiondir) {
        rmdir(conf->sessiondir);
    }
#else
    _rmdir(conf->sessiondir);
#endif
    // Ignore errors in the unlink/rmdir as they could simply be that the
    // paths were chown/chmod by the administrator


    speck_deinit((speck_context_t*)conf->header_encryption_ctx_dynamic);
    speck_deinit((speck_context_t*)conf->header_encryption_ctx_static);
    speck_deinit((speck_context_t*)conf->header_iv_ctx_dynamic);
    speck_deinit((speck_context_t*)conf->header_iv_ctx_static);
    speck_deinit(conf->shared_secret_ctx);

    free(conf->relay.community_file);
    free(conf->community.encrypt_key);
    n3n_config_free_communities(conf);
    free(conf->federation_public_key);
    free(conf->mgmt_password);
    free(conf->public_key);
    free(conf->sessiondir);
    // FIXME: sometimes this points at illegal-to-free memory
    // free(conf->sessionname);
    free(conf->shared_secret);
}

/** Deinitialise the edge and deallocate any owned memory. */
void edge_term (struct n3n_runtime_data * eee) {
    bool local = eee->conf.client.local_link;

    print_edge_stats(eee);

    if(local) {
        // The conf is a copy of the supernode's, see edge_start_local(): what
        // the supernode frees, it frees
        eee->conf.bind_address = NULL;
        eee->conf.relay.community_file = NULL;
        eee->conf.relay.community_regex = NULL;
        eee->conf.mgmt_password = NULL;
        eee->conf.sessiondir = NULL;
        eee->conf.communities = NULL;
        eee->conf.community.users = NULL;
    }
    edge_term_conf(&eee->conf);

    resolve_cancel_thread(eee->resolve_parameter);

    close_sockets(eee);

#ifndef SKIP_MULTICAST_PEERS_DISCOVERY
    if(eee->client.udp_multicast_sock_v4 >= 0) {
        closesocket(eee->client.udp_multicast_sock_v4);
        mainloop_unregister_fd(eee->client.udp_multicast_sock_v4);
        eee->client.udp_multicast_sock_v4 = -1;
    }
    if(eee->client.udp_multicast_sock_v6 >= 0) {
        closesocket(eee->client.udp_multicast_sock_v6);
        mainloop_unregister_fd(eee->client.udp_multicast_sock_v6);
        eee->client.udp_multicast_sock_v6 = -1;
    }
#endif

    clear_peer_list(&eee->client.pending_peers);
    clear_peer_list(&eee->client.known_peers);
    clear_peer_list(&eee->client.supernodes);

#ifdef HAVE_BRIDGING_SUPPORT
    if(eee->conf.tap.allow_routing) {
        struct host_info *host, *host_tmp;
        HASH_ITER(hh, eee->tap.known_hosts, host, host_tmp) {
            HASH_DEL(eee->tap.known_hosts, host);
            free(host);
        }
    }
#endif

    eee->client.transop.deinit(&eee->client.transop);
    eee->client.transop_lzo.deinit(&eee->client.transop_lzo);
#ifdef HAVE_LIBZSTD
    eee->client.transop_zstd.deinit(&eee->client.transop_zstd);
#endif

    destroy_network_traffic_filter(eee->tap.network_traffic_filter);

    // TODO:
    // - slots_close(eee->mgmt_slots)

    free(eee);

    if(local) {
        // the process goes on, the supernode ends it
        return;
    }

    closeTraceFile();

    n3n_deinitfuncs();

#ifdef _WIN32
    destroyWin32();
#endif

}


/* ************************************** */

#ifdef _WIN32
// HACK!
// Remove this once the mainloop supports stopping on windows
int windows_stop_fd;
#endif

static int edge_init_sockets (struct n3n_runtime_data *eee) {

    if(eee->conf.mgmt_port) {
        int fd = slots_create_listen_tcp(eee->conf.mgmt_port, false);
        if(fd < 0) {
            perror("slots_listen_tcp");
            exit(1);
        }
        mainloop_register_fd(fd, fd_info_proto_listen_http);
#ifdef _WIN32
        // HACK!
        windows_stop_fd = fd;
#endif
    }

    n3n_config_setup_sessiondir(&eee->conf);

#ifndef _WIN32
    char unixsock[1024];
    snprintf(unixsock, sizeof(unixsock), "%s/mgmt", eee->conf.sessiondir);

    int fd = slots_create_listen_unix(
        unixsock,
        eee->conf.mgmt_sock_perms,
        eee->conf.userid,
        eee->conf.groupid
    );
    // TODO:
    // - do we actually want to tie the user/group to the running pid?

    if(fd < 0) {
        perror("slots_listen_unix");
        edge_term(eee);
        exit(1);
    }
    mainloop_register_fd(fd, fd_info_proto_listen_http);
#endif

#ifndef SKIP_MULTICAST_PEERS_DISCOVERY
    // TODO:
    // We used to gate multicast listening on:
    // if((eee->conf.client.allow_p2p)
    //    && (eee->conf.client.preferred_sock.family == (uint8_t)AF_INVALID))
    // So, perhaps we should do that here?

    if(eee->client.udp_multicast_sock_v4 >= 0) {
        closesocket(eee->client.udp_multicast_sock_v4);
        mainloop_unregister_fd(eee->client.udp_multicast_sock_v4);
        eee->client.udp_multicast_sock_v4 = -1;
    }
    if(eee->client.udp_multicast_sock_v6 >= 0) {
        closesocket(eee->client.udp_multicast_sock_v6);
        mainloop_unregister_fd(eee->client.udp_multicast_sock_v6);
        eee->client.udp_multicast_sock_v6 = -1;
    }

    // Without the sockets, nothing sent to the multicast group reaches this
    // edge either - not even what another n3n on this host has joined it for
    if(!eee->conf.client.local_discovery) {
        traceEvent(TRACE_NORMAL, "local peer discovery is switched off");
        return 0;
    }

    /* Populate the multicast group for local edge */
    eee->client.multicast_peer_v4.family     = AF_INET;
    eee->client.multicast_peer_v4.port       = N2N_MULTICAST_PORT;
    inet_pton(AF_INET, N2N_MULTICAST_GROUP, &eee->client.multicast_peer_v4.addr.v4);

    struct sockaddr_in local_address_v4;
    memset(&local_address_v4, 0, sizeof(local_address_v4));
    local_address_v4.sin_family = AF_INET;
    local_address_v4.sin_port = htons(N2N_MULTICAST_PORT);
    local_address_v4.sin_addr.s_addr = htonl(INADDR_ANY);

    eee->client.udp_multicast_sock_v4 = open_socket(
        (struct sockaddr *)&local_address_v4,
        sizeof(local_address_v4),
        0 /* UDP */
    );
    if(eee->client.udp_multicast_sock_v4 >= 0) {
        u_int enable_reuse = 1;
        /* allow multiple sockets to use the same PORT number */
        setsockopt(eee->client.udp_multicast_sock_v4, SOL_SOCKET, SO_REUSEADDR, (char *)&enable_reuse, sizeof(enable_reuse));
#ifdef SO_REUSEPORT /* no SO_REUSEPORT in Windows / old linux versions */
        setsockopt(eee->client.udp_multicast_sock_v4, SOL_SOCKET, SO_REUSEPORT, &enable_reuse, sizeof(enable_reuse));
#endif
        mainloop_register_fd(eee->client.udp_multicast_sock_v4, fd_info_proto_v3udp);
    } else {
        traceEvent(TRACE_WARNING, "failed to create IPv4 multicast socket.");
    }

    // IPv6
    eee->client.multicast_peer_v6.family = AF_INET6;
    eee->client.multicast_peer_v6.port = N2N_MULTICAST_PORT;
    inet_pton(AF_INET6, N3N_MULTICAST_GROUP_V6, &eee->client.multicast_peer_v6.addr.v6);

    struct sockaddr_in6 local_address_v6 = {0};
    local_address_v6.sin6_family = AF_INET6;
    local_address_v6.sin6_port = htons(N2N_MULTICAST_PORT);
    local_address_v6.sin6_addr = in6addr_any;

    eee->client.udp_multicast_sock_v6 = open_socket(
        (struct sockaddr *)&local_address_v6,
        sizeof(local_address_v6),
        0 /* UDP */
    );
    if(eee->client.udp_multicast_sock_v6 >= 0) {
        u_int enable_reuse = 1;
        setsockopt(eee->client.udp_multicast_sock_v6, SOL_SOCKET, SO_REUSEADDR, (char *)&enable_reuse, sizeof(enable_reuse));
#ifdef SO_REUSEPORT
        setsockopt(eee->client.udp_multicast_sock_v6, SOL_SOCKET, SO_REUSEPORT, &enable_reuse, sizeof(enable_reuse));
#endif
        // not required but best practice
        int off = 0;
        setsockopt(eee->client.udp_multicast_sock_v6, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&off, sizeof(off));
        mainloop_register_fd(eee->client.udp_multicast_sock_v6, fd_info_proto_v3udp);
    } else {
        traceEvent(TRACE_WARNING, "failed to create IPv6 multicast socket.");
    }
#endif /* SKIP_MULTICAST_PEERS_DISCOVERY */

    return 0;
}


/* ************************************** */


/* The defaults of the community, client and tap settings: of an edge, and
 * of a supernode, which may have an edge of its own (supernode.tap) */
void edge_conf_role_defaults (n2n_edge_conf_t *conf) {

    conf->client.preferred_sock.family = AF_INVALID;
    conf->community.transop_id = N2N_TRANSFORM_ID_NULL;
    conf->community.header_encryption = HEADER_ENCRYPTION_NONE;
    conf->community.compression = N2N_COMPRESSION_ID_NONE;
    conf->client.allow_p2p = true;
    conf->client.local_discovery = true;
    conf->client.register_interval = REGISTER_SUPER_INTERVAL_DFL;
    conf->client.punch_ports = NAT_PUNCH_PORTS_DFL;
    conf->client.punch_sockets = NAT_PUNCH_SOCKETS_DFL;

    // Ensure we can notice if the config has set a dev name
    conf->tap.tuntap_dev_name[0] = '\0';

    conf->tap.tuntap_ip_mode = TUNTAP_IP_MODE_SN_ASSIGN;
    conf->tap.tuntap_v4.net_bitlen = N2N_EDGE_DEFAULT_V4MASKLEN;

    /* reserve possible last char as null terminator. */
    gethostname((char*)conf->dev_desc, N2N_DESC_SIZE-1);

    conf->client.sn_selection_strategy = SN_SELECTION_STRATEGY_LOAD;
    conf->tap.metric = 0;
    conf->tap.mtu = DEFAULT_MTU;
}


void edge_init_conf_defaults (n2n_edge_conf_t *conf, char *sessionname) {

    memset(conf, 0, sizeof(*conf));

    // Record the session name we used
    if(sessionname) {
        conf->sessionname = sessionname;
    } else {
        conf->sessionname = "NULL";
    }
    n3n_metrics_set_session(conf->sessionname);

    conf->is_edge = true;

    conf->bind_address = NULL;
#ifdef _WIN32
    // Cannot rely on having unix domain sockets on windows
    conf->mgmt_port = N2N_EDGE_MGMT_PORT;
#endif
    conf->threads = 1;

    edge_conf_role_defaults(conf);

    conf->mgmt_password = strdup(N3N_MGMT_PASSWORD);

    conf->test_benchmark_seconds = 1;
    conf->test_benchmark_threads = 1;
    conf->test_output_format = 0;

#ifndef _WIN32
    struct passwd *pw = NULL;
    // Search a couple of usernames for one to use
    pw = getpwnam("n3n");
    if(pw == NULL) {
        pw = getpwnam("nobody");
    }
    if(pw != NULL) {
        // If we find one, use that as our default
        conf->userid = pw->pw_uid;
        conf->groupid = pw->pw_gid;
    }
#endif
}

/* ************************************** */

int quick_edge_init (char *device_name, char *community_name,
                     char *encrypt_key, char *device_mac,
                     in_addr_t local_ip_address,
                     char *supernode_ip_address_port,
                     bool *keep_on_running) {

    tuntap_dev tuntap;
    struct n3n_runtime_data *eee;
    n2n_edge_conf_t conf;
    int rv;

    /* Setup the configuration */
    edge_init_conf_defaults(&conf,"edge");
    n3n_config_load_env(&conf);
    conf.community.encrypt_key = encrypt_key;
    conf.community.transop_id = N2N_TRANSFORM_ID_AES;
    conf.community.compression = N2N_COMPRESSION_ID_NONE;
    conf.tap.mtu = DEFAULT_MTU;
    snprintf((char*)conf.community.community_name, sizeof(conf.community.community_name), "%s", community_name);
    resolve_hostnames_str_add(
        RESOLVE_LIST_SUPERNODE,
        supernode_ip_address_port
    );

    /* Validate configuration */
    if(edge_verify_conf(&conf) != 0)
        return(-1);

    struct n2n_ip_subnet subnet;
    subnet.net_addr = htonl(local_ip_address);
    subnet.net_bitlen = N2N_EDGE_DEFAULT_V4MASKLEN;

    /* Open the tuntap device */
    if(tuntap_open(&tuntap, device_name, TUNTAP_IP_MODE_STATIC,
                   subnet,
                   device_mac, conf.tap.mtu,
                   0) < 0)
        return(-2);

    /* Init edge */
    if((eee = edge_init(&conf, &rv)) == NULL)
        goto quick_edge_init_end;

    eee->keep_running = keep_on_running;
    rv = run_edge_loop(eee);
    edge_term(eee);

quick_edge_init_end:
    tuntap_close(&tuntap);
    return(rv);
}

/* ************************************** */


/* The tap device failed: open it again, after a pause. The packet threads
 * read its queues, so they stop meanwhile. On the main thread.
 */
void edge_tap_reopen (struct n3n_runtime_data *eee) {

    edge_threads_stop(eee);

    sleep(3);
#ifndef _WIN32
    mainloop_unregister_fd(eee->tap.device.fd);
#endif
    tuntap_close(&(eee->tap.device));
    edge_tap_open(eee);
#ifndef _WIN32
    mainloop_register_fd(eee->tap.device.fd, fd_info_proto_tuntap);
#endif

    edge_threads_start(eee, edge_threads_wanted(&eee->conf), &edge_thread_ops);
}
