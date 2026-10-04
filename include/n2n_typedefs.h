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

#ifndef _N2N_TYPEDEFS_H_
#define _N2N_TYPEDEFS_H_

#include <n3n/ethernet.h>   // for n2n_mac_t
#include <n3n/network_traffic_filter.h>
#include <n3n/resolve.h>
#include <stdbool.h>
#include <stdint.h>     // for uint8_t and friends
#include <time.h>
#ifndef _WIN32
#include <arpa/inet.h>  // for in_addr_t
#include <sys/socket.h> // for sockaddr
#endif
#include <uthash.h>
#include <n2n_define.h>

// FIXME, including private headers
#include "../src/crypto/speck.h"  // for struct speck_context_t

typedef char n2n_community_t[N2N_COMMUNITY_SIZE];
typedef uint8_t n2n_private_public_key_t[N2N_PRIVATE_PUBLIC_KEY_SIZE];
typedef uint32_t n2n_cookie_t;
typedef uint8_t n2n_desc_t[N2N_DESC_SIZE];
typedef char n3n_sock_str_t[N3N_SOCKBUF_SIZE];     /* tracing string buffer */

#if defined(_MSC_VER) || defined(__MINGW32__)
#include "getopt.h"

/* Other Win environments are expected to support stdint.h */

/* stdint.h typedefs (C99) (not present in Visual Studio) */
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;

#ifndef __MINGW32__
typedef int ssize_t;
#endif

#include "../src/win32/n2n_win32.h"
// FIXME - continue untangling the build and includes - dont have a ".." here

#endif /* #if defined(_MSC_VER) || defined(__MINGW32__) */

/* *************************************** */

#ifdef __GNUC__
#define PACK_STRUCT __attribute__((__packed__))
#else
#define PACK_STRUCT
#endif

#if defined(_MSC_VER) || defined(__MINGW32__)
#pragma pack(push,1)
#endif

// those are definitely not typedefs (with a view to the filename) but neither are they defines
static const n2n_mac_t broadcast_mac      = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
static const n2n_mac_t multicast_mac      = { 0x01, 0x00, 0x5E, 0x00, 0x00, 0x00 }; /* First 3 bytes are meaningful */
static const n2n_mac_t ipv6_multicast_mac = { 0x33, 0x33, 0x00, 0x00, 0x00, 0x00 }; /* First 2 bytes are meaningful */
static const n2n_mac_t null_mac           = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };


#define ETH_ADDR_LEN 6

struct ether_hdr {
    uint8_t dhost[ETH_ADDR_LEN];
    uint8_t shost[ETH_ADDR_LEN];
    uint16_t type;                  /* higher layer protocol encapsulated */
} PACK_STRUCT;

typedef struct ether_hdr ether_hdr_t;


/* N2N packet header indicators. */
enum PACK_STRUCT n3n_msg_type {
    MSG_TYPE_PING =               0,  /* Not used */
    MSG_TYPE_REGISTER =           1,  /* Register edge to edge */
    MSG_TYPE_DEREGISTER =         2,  /* UNUSED */
    MSG_TYPE_PACKET =             3,  /* PACKET data content */
    MSG_TYPE_REGISTER_ACK =       4,  /* ACK of a registration peer to peer */
    MSG_TYPE_REGISTER_SUPER =     5,  /* Register edge to supernode */
    MSG_TYPE_UNREGISTER_SUPER =   6,  /* Deregister edge from supernode */
    MSG_TYPE_REGISTER_SUPER_ACK = 7,  /* ACK from sn to edge */
    MSG_TYPE_REGISTER_SUPER_NAK = 8,  /* NAK from sn to edge - reg refused */
    MSG_TYPE_FEDERATION =         9,  /* UNUSED */
    MSG_TYPE_PEER_INFO =         10,  /* Send info on a peer (sn to edge) */
    MSG_TYPE_QUERY_PEER =        11,  /* ask supernode for info on a peer */
    MSG_TYPE_RE_REGISTER_SUPER = 12   /* ask edge to re-register with sn */
};
#define MSG_TYPE_MAX_TYPE        12

#if defined(_MSC_VER) || defined(__MINGW32__)
#pragma pack(pop)
#endif

#undef PACK_STRUCT


/** Uncomment this to enable the MTU check, then try to ssh to generate a fragmented packet. */
/** NOTE: see doc/MTU.md for an explanation on the 1400 value */
//#define MTU_ASSERT_VALUE 1400

/** Common type used to hold stringified IP addresses. */
typedef char ipstr_t[INET_ADDRSTRLEN];

typedef char dec_ip_str_t[N2N_NETMASK_STR_SIZE];
typedef char dec_ip_bit_str_t[N2N_NETMASK_STR_SIZE + 4];
typedef char devstr_t[N2N_IFNAMSIZ];


typedef struct tuntap_dev {
    bool tun;                               /* a TUN device (IP packets), not a TAP one (Ethernet frames), see tun.c */
#ifndef _WIN32
    int fd;
    devstr_t dev_name;
#endif
#ifdef __linux__
    int queues;                             /* how many are open */
    int queue_fd[N2N_TUNTAP_QUEUES_MAX];    /* [0] is fd, -1 if not open */
#endif
    in_addr_t ip_addr;
    n2n_mac_t mac_addr;
    uint16_t mtu;
#ifdef _WIN32
    HANDLE device_handle;
    char            *device_name;
    char            *ifName;
    int if_idx;
    OVERLAPPED overlap_read, overlap_write;
    unsigned int metric;
    unsigned int metric_original;
#endif
} tuntap_dev;

#ifdef _WIN32
typedef u_short sa_family_t;
#else
#define SOCKET int
#endif


// This one bit higher than the largest used flag value.  It is used in the
// header encryption detection heuristic and is not a flag itself
#define N2N_FLAGS_OPTIONS_MAX            0x0080

#define N2N_FLAGS_SOCKET                 0x0040
#define N2N_FLAGS_FROM_SUPERNODE         0x0020

/* The bits in flag that are the packet type */
#define N2N_FLAGS_TYPE_MASK              0x001f  /* 0 - 31 */
#define N2N_FLAGS_BITS_MASK              0xffe0

#define IPV4_SIZE                        4
#define IPV6_SIZE                        16


#define N2N_AUTH_MAX_TOKEN_SIZE          48  /* max token size in bytes */
#define N2N_AUTH_CHALLENGE_SIZE          16  /* challenge always is of same size as dynamic key */
#define N2N_AUTH_ID_TOKEN_SIZE           16
#define N2N_AUTH_PW_TOKEN_SIZE           (N2N_PRIVATE_PUBLIC_KEY_SIZE + N2N_AUTH_CHALLENGE_SIZE)

#define N2N_EUNKNOWN                     -1
#define N2N_ENOTIMPL                     -2
#define N2N_EINVAL                       -3
#define N2N_ENOSPACE                     -4


#define N2N_VERSION_STRING_SIZE           20
typedef char n2n_version_t[N2N_VERSION_STRING_SIZE];


typedef struct n2n_ip_subnet {
    in_addr_t net_addr;             /* Host order IP address. */
    uint8_t net_bitlen;             /* Subnet prefix. */
} n2n_ip_subnet_t;

typedef struct n2n_sock {
    uint8_t family;                   /* AF_INET, AF_INET6 or AF_INVALID (0xff, a custom #define);
                                         mind that AF_UNSPEC (0) means auto IPv4 or IPv6 */
    uint8_t type;                     /* for later use, usually SOCK_STREAM (1) or SOCK_DGRAM (2) */
    uint16_t port;                    /* host order */
    union {
        uint8_t v6[IPV6_SIZE];        /* byte sequence */
        uint8_t v4[IPV4_SIZE];        /* byte sequence */
    } addr;
} n3n_sock_t;

typedef enum {
    n2n_auth_none =          0,
    n2n_auth_simple_id =     1,
    n2n_auth_user_password = 2
} n2n_auth_scheme_t;

typedef enum {
    update_edge_no_change =   0,
    update_edge_sock_change = 1,
    update_edge_new_sn =      2,
    update_edge_auth_fail =  -1
} update_edge_ret_value_t;

typedef struct n2n_auth {
    uint16_t scheme;                                /* What kind of auth */
    uint16_t token_size;                            /* Size of auth token */
    uint8_t token[N2N_AUTH_MAX_TOKEN_SIZE];         /* Auth data interpreted based on scheme */
} n2n_auth_t;

typedef struct n2n_common {
    /* NOTE: wire representation is different! */
    /* int             version; */

    uint8_t ttl;
    enum n3n_msg_type pc;
    uint16_t flags;
    n2n_community_t community;
} n2n_common_t;

typedef struct n2n_REGISTER {
    n2n_cookie_t cookie;            /**< Link REGISTER and REGISTER_ACK */
    n2n_mac_t srcMac;               /**< MAC of registering party */
    n2n_mac_t dstMac;               /**< MAC of target edge */
    n3n_sock_t sock;                /**< Supernode's view of edge socket OR edge's preferred local socket */
    n2n_ip_subnet_t dev_addr;       /**< IP address of the tuntap adapter. */
    n2n_desc_t dev_desc;            /**< Hint description correlated with the edge */
} n2n_REGISTER_t;

typedef struct n2n_REGISTER_ACK {
    n2n_cookie_t cookie;       /**< Return cookie from REGISTER */
    n2n_mac_t srcMac;          /**< MAC of acknowledging party (supernode or edge) */
    n2n_mac_t dstMac;          /**< Reflected MAC of registering edge from REGISTER */
    n3n_sock_t sock;           /**< Supernode's view of edge socket (IP Addr, port) */
} n2n_REGISTER_ACK_t;

typedef struct n2n_PACKET {
    n2n_mac_t srcMac;
    n2n_mac_t dstMac;
    n3n_sock_t sock;
    uint8_t transform;
    uint8_t compression;
} n2n_PACKET_t;

/* Linked with n2n_register_super via enum n3n_msg_type. Only from edge to supernode. */
typedef struct n2n_REGISTER_SUPER {
    n2n_cookie_t cookie;            /**< Link REGISTER_SUPER and REGISTER_SUPER_ACK */
    n2n_mac_t edgeMac;              /**< MAC to register with edge sending socket */
    n3n_sock_t sock;                /**< Sending socket associated with edgeMac */
    n2n_ip_subnet_t dev_addr;       /**< IP address of the tuntap adapter. */
    n2n_desc_t dev_desc;            /**< Hint description correlated with the edge */
    n2n_auth_t auth;                /**< Authentication scheme and tokens */
    uint32_t key_time;              /**< key time for dynamic key, used between federatred supernodes only */
} n2n_REGISTER_SUPER_t;


/* Linked with n2n_register_super_ack via enum n3n_msg_type. Only from supernode to edge. */
typedef struct n2n_REGISTER_SUPER_ACK {
    n2n_cookie_t cookie;            /**< Return cookie from REGISTER_SUPER */
    n2n_mac_t srcMac;               /**< MAC of answering supernode */
    n2n_ip_subnet_t dev_addr;       /**< Assign an IP address to the tuntap adapter of edge. */
    uint16_t lifetime;              /**< How long the registration will live */
    n3n_sock_t sock;                /**< Sending sockets associated with edge */
    n2n_auth_t auth;                /**< Authentication scheme and tokens */

    /** The packet format provides additional supernode definitions here.
     * uint8_t count, then for each count there is one
     * n3n_sock_t.
     */
    uint8_t num_sn;                 /**< Number of supernodes that were send
                                     * even if we cannot store them all. */

    uint32_t key_time;              /**< key time for dynamic key, used between federatred supernodes only */
} n2n_REGISTER_SUPER_ACK_t;


/* Linked with n2n_register_super_ack via enum n3n_msg_type. Only from supernode to edge. */
typedef struct n2n_REGISTER_SUPER_NAK {
    n2n_cookie_t cookie;       /* Return cookie from REGISTER_SUPER */
    n2n_mac_t srcMac;
    n2n_auth_t auth;           /* Authentication scheme and tokens */
} n2n_REGISTER_SUPER_NAK_t;


/* REGISTER_SUPER_ACK may contain extra payload (their number given by num_sn)
 * of following type describing a(nother) supernode */
typedef struct n2n_REGISTER_SUPER_ACK_payload {
    // REVISIT: interim for bugfix (https://github.com/ntop/n2n/issues/1029)
    //          remove with 4.0
    uint8_t sock[sizeof(uint16_t) + sizeof(uint16_t) + IPV6_SIZE];       /**< socket of supernode */
    n2n_mac_t mac;                                                       /**< MAC of supernode */
} n2n_REGISTER_SUPER_ACK_payload_t;


/* Linked with n2n_unregister_super via enum n3n_msg_type. */
typedef struct n2n_UNREGISTER_SUPER {
    n2n_auth_t auth;
    n2n_mac_t srcMac;
} n2n_UNREGISTER_SUPER_t;


typedef struct n2n_PEER_INFO {
    uint16_t aflags;
    n2n_mac_t srcMac;
    n2n_mac_t mac;
    n3n_sock_t sock;
    n3n_sock_t preferred_sock;
    uint32_t load;
    n2n_version_t version;
    time_t uptime;
} n2n_PEER_INFO_t;


typedef struct n2n_QUERY_PEER {
    uint16_t aflags;
    n2n_mac_t srcMac;
    n3n_sock_t sock;
    n2n_mac_t targetMac;

} n2n_QUERY_PEER_t;

typedef struct n2n_buf n2n_buf_t;

#ifdef HAVE_BRIDGING_SUPPORT
struct host_info {
    time_t last_seen;
    UT_hash_handle hh;     /* makes this structure hashable */
    n2n_mac_t mac_addr;
    n2n_mac_t edge_addr;
};
#endif

struct n3n_runtime_data;

/* *************************************************** */

// FIXME: this definition belongs in n3n/network_traffic_filter.h but
// it is tangled up.
// TODO: determine the value of using function pointers for these two
// definitions - this would allow untangling the definitions.  It would
// make it harder to write a custom packet filter function in a user
// application, but that might not be needed.
struct network_traffic_filter {
    n2n_verdict (*filter_packet_from_peer)(network_traffic_filter_t* filter, struct n3n_runtime_data *eee,
                                           const n3n_sock_t *peer, uint8_t *payload, uint16_t payload_size);

    n2n_verdict (*filter_packet_from_tap)(network_traffic_filter_t* filter, struct n3n_runtime_data *eee, uint8_t *payload, uint16_t payload_size);

    // set up once at start, only read afterwards
    filter_rule_t *rules;

    // tells the per-thread verdict caches which filter they belong to, see
    // network_traffic_filter.c
    uint32_t id;
};

/* *************************************************** */

typedef enum n2n_transform {
    N2N_TRANSFORM_ID_INVAL =    0,
    N2N_TRANSFORM_ID_NULL =     1,
    N2N_TRANSFORM_ID_TWOFISH =  2,
    N2N_TRANSFORM_ID_AES =      3,
    N2N_TRANSFORM_ID_CHACHA20 = 4,
    N2N_TRANSFORM_ID_SPECK =    5,
} n2n_transform_t;

struct n2n_trans_op; /* Circular definition */

typedef int (*n2n_transdeinit_f)(struct n2n_trans_op * arg);
typedef int (*n2n_transform_f)(struct n2n_trans_op * arg,
                               uint8_t * outbuf,
                               size_t out_len,
                               const uint8_t * inbuf,
                               size_t in_len,
                               const n2n_mac_t peer_mac);

/* One payload for the batched form of fwd: the arguments fwd() takes, plus
 * where to put what fwd() would have returned for it. */
typedef struct n2n_transform_job {
    uint8_t *          out;
    size_t out_len;
    const uint8_t *    in;
    size_t in_len;
    const uint8_t *    peer_mac;
    int result;
} n2n_transform_job_t;

/* Encode count payloads at once. Each job must come out exactly as fwd()
 * would have made it; the point is only that the transform can work on the
 * payloads side by side, which CBC encryption cannot do within one. */
typedef void (*n2n_transform_multi_f)(struct n2n_trans_op * arg,
                                      n2n_transform_job_t * job,
                                      int count);
/** Holds the info associated with a data transform plugin.
 *
 *  When a packet arrives the transform ID is extracted. This defines the code
 *  to use to decode the packet content. The transform code then decodes the
 *  packet and consults its internal key lookup.
 */
typedef struct n2n_trans_op {
    void *             priv;          /* opaque data. Key schedule goes here. */

    n2n_transdeinit_f deinit;         /* destructor function */
    n2n_transform_f fwd;              /* encode a payload */
    n2n_transform_f rev;              /* decode a payload */
    n2n_transform_multi_f fwd_multi;  /* optional: encode several payloads at
                                       * once, NULL if the transform has no
                                       * batched form */

    n2n_transform_t transform_id;
    uint8_t no_encryption;            /* 1 if this transop does not perform encryption */
} n2n_trans_op_t;


/* *************************************************** */

/* The transports an address is for: an address of connection.bind or a
 * supernode with "udp://" or "tcp://" in front is for that one only */
#define N3N_TRANSPORT_UDP    1
#define N3N_TRANSPORT_TCP    2
#define N3N_TRANSPORT_BOTH   (N3N_TRANSPORT_UDP | N3N_TRANSPORT_TCP)

/* An address of connection.bind */
struct n3n_bind {
    struct sockaddr_storage sa;
    uint8_t transports;                 /* N3N_TRANSPORT_* */
};

/* How the edge reaches its supernodes and the other edges: the client role */
struct n3n_conf_client {
    bool local_link;                    /* the supernode is the one of this process, see local_link.h */
    bool allow_p2p;                                  /**< Allow P2P connection */
    bool local_discovery;                            /**< Look for peers on the local network by multicast */
    bool watch_network;                              /**< Register again at once when the host's network changes, see netwatch.h */
    uint32_t register_interval;                      /**< Interval for supernode registration, also used for UDP NAT hole punching. */
    uint32_t register_ttl;                           /**< TTL for registration packet when UDP NAT hole punching through supernode. */
    uint32_t punch_ports;                            /**< ports to try per round towards a peer behind a hard NAT, 0: none */
    uint32_t punch_sockets;                          /**< behind a hard NAT: extra sockets towards a peer that guesses, 0: none */
    uint32_t punch_ttl;                              /**< the TTL of what those sockets send until one is reached, 0: the system's */
    n3n_sock_t preferred_sock;                       /**< propagated local sock for better p2p in LAN (-e) */
    n2n_auth_t auth;
    bool connect_tcp;                                /** connection to supernode 0 = UDP; 1 = TCP */
    bool tcp_fallback;                               /**< over UDP: try TCP when no supernode answers, see role_client.c */
    uint8_t sn_selection_strategy;                  /**< encodes currently chosen supernode selection strategy. */
    uint8_t number_max_sn_pings;                    /**< Number of maximum concurrently allowed supernode pings. */
};

/* The TAP device: the tap role */
struct n3n_conf_tap {
    bool allow_routing;                              /**< Accept packet no to interface address. */
    bool allow_multicast;                            /**< Multicast ethernet addresses. */
    uint32_t metric;                                /**< Network interface metric (Windows only). */
    int mtu;
    filter_rule_t            *network_traffic_filter_rules;
    char device_mac[N2N_MACNAMSIZ];
    devstr_t tuntap_dev_name;
    struct n2n_ip_subnet tuntap_v4;
    struct n2n_ip_subnet gateway;     // TUN: the peer for addresses outside the subnet, 0: none
    uint8_t tuntap_ip_mode;                          /**< Interface IP address allocated mode, eg. DHCP. */
    int type;                                        /**< N3N_TUNTAP_TAP or N3N_TUNTAP_TUN */
    uint32_t fd;                                     /**< a device opened already, 0: open one */
};

#define N3N_TUNTAP_TAP 0
#define N3N_TUNTAP_TUN 1

/* With a TUN device: the MAC address of an IPv4 address of the community,
 * see tun.c */
#define N3N_TUN_ARP_SLOTS 256
struct n3n_tun_arp {
    uint32_t ip;                    /* network order, 0: unused */
    n2n_mac_t mac;
    bool known;                     /* else only asked for */
    time_t asked;                   /* the last ARP request for it */
};

/* The communities, the federation, the addresses handed out: the relay role */
struct n3n_conf_relay {
    bool tap;                           /* also an edge of community.name, see edge_start_local() */
    n2n_mac_t sn_mac_addr;
    bool spoofing_protection;                                /* false if overriding MAC/IP spoofing protection (cli option '-M') */
    char *community_file;
    struct n3n_conf_strlist *community_regex;        /**< community names matching one of these are allowed */
    n2n_version_t version;                                  /* version string sent to edges along with PEER_INFO a.k.a. PONG */
    n2n_community_t sn_federation;
    struct peer_info *sn_edges;     // SN federation storage during configure
    n2n_ip_subnet_t sn_min_auto_ip_net;                        /* Address range of auto_ip service. */
    n2n_ip_subnet_t sn_max_auto_ip_net;                        /* Address range of auto_ip service. */
};

/* The settings of a community: of the one an edge joins, and of each one
 * a supernode knows by a section of the configuration */
struct n3n_conf_community {
    UT_hash_handle hh;                               /**< in conf.communities, by instance */
    char instance[N2N_COMMUNITY_SIZE];               /**< "home" of a [community home] section, "" for [community] */
    n2n_community_t community_name;                  /**< The community. 16 full octets. */
    uint8_t header_encryption;                       /**< Header encryption indicator. */
    uint8_t transop_id;                              /**< The transop to use. */
    uint8_t compression;                             /**< Compress outgoing data packets before encryption */
    char                     *encrypt_key;
    // only on a supernode
    n2n_ip_subnet_t network;                         /**< for the auto ip address service, network byte order; 0 to choose one */
    struct n3n_conf_strlist *users;                  /**< "name public-key" of each user allowed, see community.user */
};

typedef struct n2n_edge_conf {
    struct n3n_conf_community community;             /**< The community joined, or the unnamed one */
    struct n3n_conf_community *communities;          /**< The named ones */
    n2n_desc_t dev_desc;                             /**< The device description (hint) */
    n2n_private_public_key_t *public_key;            /**< edge's public key (for user/password based authentication) */
    n2n_private_public_key_t *shared_secret;         /**< shared secret derived from federation public key, username and password */
    speck_context_t *shared_secret_ctx;              /**< context holding the roundkeys derived from shared secret */
    n2n_private_public_key_t *federation_public_key; /**< federation public key provided by command line */
    struct speck_context_t *header_encryption_ctx_static;  /**< Header encryption cipher context. */
    struct speck_context_t *header_encryption_ctx_dynamic; /**< Header encryption cipher context. */
    struct speck_context_t *header_iv_ctx_static;    /**< Header IV ecnryption cipher context, REMOVE as soon as separate fileds for checksum and replay protection available */
    struct speck_context_t *header_iv_ctx_dynamic;   /**< Header IV ecnryption cipher context, REMOVE as soon as separate fileds for checksum and replay protection available */

    // What all roles use: sockets, the management interface, the daemon
    bool pmtu_discovery;                             /**< Enable the Path MTU discovery. */
    uint32_t tos;                                    /** TOS for sent packets */
    struct n3n_bind *bind_address;                   /**< connection.bind, if given: an array ended by family 0 */
    bool enable_debug_pages;
    uint32_t mgmt_port;     // TODO: ports are actually uint16_t
    uint32_t mgmt_sock_perms;
    char * mgmt_password;
    uint32_t userid;
    uint32_t groupid;
    bool background;
    bool is_edge;
    bool is_supernode;
    char *sessionname;              // the name of this session
    char *sessiondir;              // path to use for session files
    uint32_t threads;                                          /* threads handling received packets, see edge_threads.h */

    uint32_t test_benchmark_seconds;
    uint32_t test_benchmark_threads;
    int test_output_format;

    // The parts of the roles, see struct n3n_runtime_data
    struct n3n_conf_client client;
    struct n3n_conf_tap tap;
    struct n3n_conf_relay relay;
} n2n_edge_conf_t;


// Every member must be a uint32_t: n3n_stats_sum() adds the slots up word by
// word, and the metrics renderer reads them by offset as uint32_t
struct n2n_edge_stats {
    uint32_t tx_p2p;
    uint32_t rx_p2p;
    uint32_t tx_sup;
    uint32_t rx_sup;
    uint32_t tx_sup_broadcast;
    uint32_t rx_sup_broadcast;
    uint32_t tx_multicast_drop;
    uint32_t rx_multicast_drop;
    uint32_t tx_tuntap_error;
    uint32_t sn_errors;         /* Number of errors encountered. */
    uint32_t sn_reg;            /* Number of REGISTER_SUPER requests received. */
    uint32_t sn_reg_nak;        /* Number of REGISTER_SUPER requests declined. */
    uint32_t sn_fwd;            /* Number of messages forwarded. */
    uint32_t sn_broadcast;      /* Number of messages broadcast to a community. */
    uint32_t sn_drop;
    uint32_t transop_tx;        /* Payloads encoded by the transform. */
    uint32_t transop_rx;        /* Payloads decoded by the transform. */
};

// one slot of counters per packet thread, see stats.h - the same number as
// N3N_THREADS_MAX in src/thread_local.h, which stats.h checks
#define N3N_STATS_SLOTS 16

/* A TCP connection the supernode accepted.  Reading and writing it is up to
 * the mainloop, which has its buffers; this is the address it came from. */
typedef struct n2n_tcp_connection {
    int socket_fd;                                        /* file descriptor for tcp socket */
    socklen_t sock_len;                                   /* amount of actually used space (of the following) */
    union {
        struct sockaddr sock;                             /* network order socket */
        struct sockaddr_storage sas;                      /* memory for it, can be longer than sockaddr */
    };

    UT_hash_handle hh; /* makes this structure hashable */
} n2n_tcp_connection_t;


typedef struct slots slots_t;

struct edge_threads;

/* How the NAT maps one of the edge's sockets, from what its supernodes see of
 * it - see src/natclass.h */
#define NAT_SAMPLES 8

enum nat_class {
    NAT_UNKNOWN = 0,         /* too few supernodes to tell */
    NAT_EASY,                /* one public port for every destination */
    NAT_HARD,                /* a public port per destination */
    NAT_SEVERAL_ADDRESSES,   /* a public address per destination */
};

struct nat_sample {
    n3n_sock_t to;           /* the supernode, as its reply came from it */
    n3n_sock_t seen;         /* the edge, as that supernode saw it */
    time_t when;             /* 0: unused */
};

struct nat_view {
    struct nat_sample sample[NAT_SAMPLES];
    enum nat_class nat_class;
    bool port_kept;          /* NAT_EASY: the public port is the local one */
    uint16_t port_lo;        /* NAT_HARD: the lowest and the highest public port seen */
    uint16_t port_hi;
    uint16_t local_port;     /* of the socket, 0 if there is none */
};

/* What a peer told of its NAT in its last REGISTER through the supernode:
 * kept apart from the peer tables, whose entries come and go while two edges
 * try to reach each other */
#define NAT_PEERS 16

struct nat_peer {
    n2n_mac_t mac;
    time_t seen;             /* when it told; 0: unused */
    n2n_cookie_t hint;
    time_t punched;          /* the last round of REGISTERs towards it, see punch_round() */
    n3n_sock_t found;        /* behind a hard NAT: where it answered from (family 0: nowhere yet) */
    uint32_t tried;          /* how many ports of its range have been tried */
    uint16_t start;          /* where in the range, and in which steps */
    uint16_t stride;
};

/* Behind a hard NAT, the sockets opened towards one peer that guesses our
 * port: each sends a REGISTER to the peer's public socket every round, so the
 * NAT keeps a public port of its own for each, any of which the peer's guesses
 * can meet. See punch_pool_round() in punch.c. */
#define NAT_PUNCH_POOLS 4
#define NAT_PUNCH_POOL_MAX 64    /* sockets in all pools together */

struct punch_pool {
    n2n_mac_t mac;
    n3n_sock_t dest;         /* the peer's public socket, as the supernode saw it */
    time_t used;             /* the last round; 0: unused */
    int ttl0;                /* the system's TTL, to give back to the one that is reached */
    bool won;                /* one of them got through; the rest is to be closed */
    int count;
    int fd[NAT_PUNCH_POOL_MAX];      /* -1: closed, or taken over by a punch_bound (int, as eee->sock) */
};

/* A socket of a pool that the peer reached: everything to that peer leaves
 * from it from then on, see sendto_sock() */
#define NAT_PUNCH_BOUND 8

struct punch_bound {
    n3n_sock_t dest;         /* where the peer reached it from; family 0: unused */
    int fd;
    time_t last_rx;
};

/* What the edge needs to reach its supernodes and the other edges of its
 * community: the client role of a peer */
struct n3n_rt_client {
    struct peer_info                 *curr_sn;                           /**< Currently active supernode. */
    uint8_t sn_wait;                                                     /**< Whether we are waiting for a supernode response. */
    uint8_t sn_pong;                                                     /**< Whether we have seen a PONG since last time reset. */
    bool sn_other_family;                                                /**< the current supernode keeps an address of the other family, see N3N_REG_SUPER_OTHER_FAMILY */
    n2n_cookie_t other_family_cookie;                                    /**< of the last REGISTER_SUPER of the other family */
    bool resolution_request;                                             /**< Flag an immediate DNS resolution request */
    bool multicast_joined_v4;                                            /**< 1 if the IPV4 group has been joined.*/
    bool multicast_joined_v6;                                            /**< 1 if the IPV6 group has been joined.*/
    int close_socket_counter;                                            /**< counter for close-event before re-opening */
    size_t sup_attempts;                                                 /**< Number of remaining attempts to this supernode. */
    bool tcp;                                                            /**< the supernode is reached over TCP now, see transport_check() */
    uint8_t giveups;                                                     /**< supernodes given up on in a row, over the current transport */
    int probe_sock;                                                      /**< over TCP by fallback: a UDP socket to see whether UDP works again */
    bool probe_ok;                                                       /**< a supernode answered on it */
    time_t last_probe;
    uint64_t ping_sent_us;                                               /**< when the last PINGs to the supernodes went out (n3n_monotonic_us) */
    n2n_trans_op_t transop;                                              /**< The transop to use when encoding */
    n2n_trans_op_t transop_lzo;                                          /**< The transop for LZO  compression */
    n2n_trans_op_t transop_zstd;                                         /**< The transop for ZSTD compression */
    uint64_t sn_selection_criterion_common_data;

    /* supernode socket is in        eee->client.curr_sn->sock (of type n3n_sock_t) */
    n3n_sock_t advertised_sock;                                          /**< local socket told to the supernode, from advertise_addr (AF_INVALID: none) */
    struct nat_view nat[2];                                              /**< the NAT of the IPv4 [0] and the IPv6 [1] socket */
    struct nat_peer nat_peers[NAT_PEERS];                                /**< the NATs of the peers, as they told */
    struct punch_pool punch_pool[NAT_PUNCH_POOLS];                       /**< behind a hard NAT: sockets towards peers that guess */
    struct punch_bound punch_bound[NAT_PUNCH_BOUND];                     /**< the ones of them that got through */
    int punch_pool_fds;                                                  /**< how many sockets the pools hold */
    int punch_bound_count;                                               /**< how many entries of punch_bound are used */
    time_t punch_swept;                                                  /**< the last punch_sweep() */

#ifndef SKIP_MULTICAST_PEERS_DISCOVERY
    int udp_multicast_sock_v4;                                           /**< socket for local IPv4 multicast registrations. */
    int udp_multicast_sock_v6;                                           /**< socket for local IPv6 multicast registrations. */
    int netwatch_fd;                                                     /**< changes of the host's network, see netwatch.h; -1 for none */
    n3n_sock_t multicast_peer_v4;                                        /**< IPv4 multicast peer group (for local edges) */
    n3n_sock_t multicast_peer_v6;                                        /**< IPv6 multicast peer group (for local edges) */
#endif

    struct peer_info *supernodes;                                        /**< List of supernodes */
    struct peer_info *               known_peers;                        /**< Edges we are connected to. */
    struct peer_info *               pending_peers;                      /**< Edges we have tried to register with. */

    time_t last_register_req;                                            /**< Check if time to re-register with super*/
    time_t last_p2p;                                                     /**< Last time p2p traffic was received. */
    time_t last_sup;                                                     /**< Last time a packet arrived from supernode. */
    time_t last_sweep;                                                   /**< Last time a sweep was performed. */
};

/* The TAP device and what goes in and out of it: the tap role of a peer */
struct n3n_rt_tap {
    tuntap_dev device;                                                   /**< All about the TUNTAP device */
    struct n3n_tun_arp tun_arp[N3N_TUN_ARP_SLOTS];                       /**< with a TUN device, see tun.c */
    network_traffic_filter_t         *network_traffic_filter;
#ifdef HAVE_BRIDGING_SUPPORT
    struct host_info *               known_hosts;                        /**< hosts we know. */
#endif
};

/* What the supernode keeps about its communities and the other supernodes:
 * the relay and federate roles of a peer */
struct n3n_rt_relay {
    struct n3n_runtime_data *local_edge;    /* that edge, if there is one */
    int tcp_sock;                                           /* auxiliary socket for optional TCP connections */
    n2n_mac_t mac_addr;
    uint32_t dynamic_key_time;                                /* UTC time of last dynamic key generation (second accuracy) */
    n2n_tcp_connection_t                   *tcp_connections;/* list of established TCP connections */
    struct sn_community                    *communities;
    struct sn_community_regular_expression *rules;
    struct sn_community                    *federation;
    n2n_private_public_key_t private_key;                     /* private federation key derived from federation name */
    bool lock_communities;                                    /* If true, only loaded and matching communities can be used. */
    time_t last_sn_fwd;       /* Time when last message was forwarded. */
    time_t last_sn_reg;       /* Time when last REGISTER_SUPER was received. */
};

/* What the parts all roles share - the mainloop, the local link, the
* management API - call of the role of a runtime.  The edge's are set by
* edge_init(), the supernode's by sn_init_conf_defaults(); a build without
* the relay role (./configure --disable-relay) has no supernode's. */
struct n3n_pktbuf;
struct n3n_role_ops {
    // a PDU waits on a UDP socket: 1 if one was taken, 0 if not
    int (*read_udp)(struct n3n_runtime_data *rt, SOCKET sock,
                    struct n3n_pktbuf *pktbuf, time_t now);
    // a PDU came in on a TCP connection; buf NULL: the connection is gone
    void (*read_tcp)(struct n3n_runtime_data *rt, SOCKET sock,
                     uint8_t *buf, ssize_t size, time_t now);
    // the relay: a TCP connection was accepted
    void (*accepted_tcp)(struct n3n_runtime_data *rt, SOCKET sock,
                         const struct sockaddr *addr, socklen_t addr_len);
    // the relay: a PDU from its own edge over the local link
    void (*local_pdu)(struct n3n_runtime_data *rt,
                      const struct sockaddr *sender, socklen_t sender_len,
                      uint8_t *buf, size_t size, time_t now);
    // the relay: read the community file again
    int (*reload_communities)(struct n3n_runtime_data *rt);
};

struct n3n_runtime_data {
    n2n_edge_conf_t conf;
    const struct n3n_role_ops *ops;     /* of its role, see above */

    struct edge_threads *threads;       /* NULL unless PACKETs are handled by several threads, see edge_threads.h */

    bool                             *keep_running;                      /**< Pointer to edge loop stop/go flag */
    time_t start_time;                                                   /**< For calculating uptime */

    slots_t *mgmt_slots;
    int sock;

    // The sockets of connection.bind, on the supernode and on the edge
    SOCKET bind_sock[N3N_BIND_MAX];                         /* a UDP socket for each address of bind; sock is the first */
    SOCKET bind_tcp[N3N_BIND_MAX];                          /* on the supernode a TCP one for each address of bind for TCP; tcp_sock is the first */
    int bind_tcp_count;
    int bind_family[N3N_BIND_MAX];                          /* the family each of them was opened with */
    bool bind_v6only[N3N_BIND_MAX];                         /* IPv6 without mapped IPv4 */
    int bind_count;                                         /* 0 for an edge connected over TCP, which has only sock */

    struct n2n_edge_stats stats_slot[N3N_STATS_SLOTS];                   /**< Statistics, one slot per thread - see stats.h */
    struct n2n_edge_stats stats_sum;                                     /**< Sum of the slots, as last read by the metrics page */

    n3n_resolve_parameter_t          *resolve_parameter;                 /**< Pointer to name resolver's parameter block */

    /* The parts of the roles.  An edge has client and tap, a supernode
     * relay; what a role does not use stays zero. */
    struct n3n_rt_client client;
    struct n3n_rt_tap tap;
    struct n3n_rt_relay relay;
};

typedef struct node_supernode_association {

    union {
        struct sockaddr sock;               /* network order socket of that edge's supernode       */
        struct sockaddr_storage sas;        /* the actual memory for it, sockaddr can be too small */
    };
    time_t last_seen;                       /* time mark to keep track of purging requirements */

    UT_hash_handle hh;                      /* makes this structure hashable */
    socklen_t sock_len;                     /* amount of actually used space (of the following)    */
    n2n_mac_t mac;                          /* mac address of an edge                          */
} node_supernode_association_t;

typedef struct sn_user {
    n2n_private_public_key_t public_key;
    n2n_private_public_key_t shared_secret;
    struct speck_context_t *shared_secret_ctx;
    n2n_desc_t name;

    UT_hash_handle hh;
} sn_user_t;

struct sn_community {
    n2n_community_t community;
    bool is_federation;                                /* if true, then the current community is the federation of supernodes */
    bool purgeable;                                       /* indicates purgeable community (fixed-name, predetermined (-c parameter) communties usually are unpurgeable) */
    uint8_t header_encryption;                            /* Header encryption indicator. */
    struct speck_context_t *header_encryption_ctx_static;  /* Header encryption cipher context. */
    struct speck_context_t *header_encryption_ctx_dynamic; /* Header encryption cipher context. */
    struct speck_context_t *header_iv_ctx_static;          /* Header IV encryption cipher context, REMOVE as soon as separate fields for checksum and replay protection available */
    struct speck_context_t *header_iv_ctx_dynamic;         /* Header IV encryption cipher context, REMOVE as soon as separate fields for checksum and replay protection available */
    uint8_t dynamic_key[N2N_AUTH_CHALLENGE_SIZE];                       /* dynamic key */
    struct                        peer_info *edges;       /* Link list of registered edges. */
    node_supernode_association_t  *assoc;                 /* list of other edges from this community and their supernodes */
    sn_user_t                     *allowed_users;         /* list of allowed users */
    int64_t number_enc_packets[N3N_STATS_SLOTS];          /* Number of encrypted packets handled so far, per thread, required for sorting from time to time */
    n2n_ip_subnet_t auto_ip_net;                          /* Address range of auto ip address service. */

    UT_hash_handle hh;                                    /* makes this structure hashable */
};

/* Typedef'd pointer to get abstract datatype. */
typedef struct regex_t* re_t;

struct sn_community_regular_expression {
    re_t rule;         /* compiles regular expression */

    UT_hash_handle hh; /* makes this structure hashable */
};


/* *************************************************** */

#endif /* _N2N_TYPEDEFS_H_ */
