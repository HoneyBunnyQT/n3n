/**
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023-25 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The communities of a supernode: from the configuration and the community file, their keys and address ranges, purging and sorting them
 */

#include <errno.h>
#include <n3n/conffile.h>
#include <n3n/logging.h>
#include <n3n/strings.h>
#include <n3n/supernode.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <time.h>
#include <unistd.h>

#include "auth.h"
#include "header_encryption.h"
#include "n2n_define.h"
#include "n2n_regex.h"
#include "n2n_wire.h"
#include "pearson.h"
#include "sn_selection.h"
#include "role_federate.h"
#include "role_relay.h"
#include "sn_communities.h"
#include "sn_utils.h"

#ifdef _WIN32
#include "win32/defs.h"

#include <direct.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pwd.h>
#include <sys/socket.h>
#endif


/** Convert host order subnet mask to subnet prefix bit length. */
uint8_t mask2bitlen (uint32_t mask) {

    uint8_t i, bitlen = 0;

    for(i = 0; i < 32; ++i) {
        if((mask << i) & 0x80000000) {
            ++bitlen;
        } else {
            break;
        }
    }

    return bitlen;
}


// generate shared secrets for user authentication; can be done only after
// federation name is known and community list completely read
void calculate_shared_secrets (struct n3n_runtime_data *sss) {

    struct sn_community *comm, *tmp_comm;
    sn_user_t *user, *tmp_user;

    traceEvent(TRACE_INFO, "started shared secrets calculation for edge authentication");

    generate_private_key(sss->relay.private_key, sss->relay.federation->community + 1); /* skip '*' federation leading character */
    HASH_ITER(hh, sss->relay.communities, comm, tmp_comm) {
        if(comm->is_federation) {
            continue;
        }
        HASH_ITER(hh, comm->allowed_users, user, tmp_user) {
            // calculate common shared secret (ECDH)
            generate_shared_secret(user->shared_secret, sss->relay.private_key, user->public_key);
            // prepare for use as key; at start-up, this runs once more
            // when the federation name is known
            speck_deinit((speck_context_t*)user->shared_secret_ctx);
            speck_init((speck_context_t**)&user->shared_secret_ctx, user->shared_secret, 128);
        }
    }

    traceEvent(TRACE_INFO, "calculated shared secrets for edge authentication");
}


// calculate dynamic keys
void calculate_dynamic_keys (struct n3n_runtime_data *sss) {

    struct sn_community *comm, *tmp_comm = NULL;

    traceEvent(TRACE_INFO, "calculating dynamic keys");
    HASH_ITER(hh, sss->relay.communities, comm, tmp_comm) {
        // skip federation
        if(comm->is_federation) {
            continue;
        }

        // calculate dynamic keys if this is a user/pw auth'ed community
        if(comm->allowed_users) {
            calculate_dynamic_key(comm->dynamic_key,           /* destination */
                                  sss->relay.dynamic_key_time,       /* time - same for all */
                                  comm->community,  /* community name */
                                  sss->relay.federation->community); /* federation name */
            packet_header_change_dynamic_key(comm->dynamic_key,
                                             &(comm->header_encryption_ctx_dynamic),
                                             &(comm->header_iv_ctx_dynamic));
            traceEvent(TRACE_DEBUG, "calculated dynamic key for community '%s'", comm->community);
        }
    }
}


// send RE_REGISTER_SUPER to all edges from user/pw auth'ed communites
void send_re_register_super (struct n3n_runtime_data *sss) {

    struct sn_community *comm, *tmp_comm = NULL;
    struct peer_info *edge, *tmp_edge = NULL;
    n2n_common_t cmn;
    uint8_t rereg_buf[N2N_SN_PKTBUF_SIZE];
    size_t encx = 0;
    n3n_sock_str_t sockbuf;

    HASH_ITER(hh, sss->relay.communities, comm, tmp_comm) {
        if(comm->is_federation) {
            continue;
        }

        // send RE_REGISTER_SUPER to edges if this is a user/pw auth community
        if(comm->allowed_users) {
            // prepare
            cmn.ttl = N2N_DEFAULT_TTL;
            cmn.pc = MSG_TYPE_RE_REGISTER_SUPER;
            cmn.flags = N2N_FLAGS_FROM_SUPERNODE;
            memcpy(cmn.community, comm->community, N2N_COMMUNITY_SIZE);

            HASH_ITER(hh, comm->edges, edge, tmp_edge) {
                // encode
                encx = 0;
                encode_common(rereg_buf, &encx, &cmn);

                // send
                traceEvent(TRACE_DEBUG, "send RE_REGISTER_SUPER to %s",
                           sock_to_cstr(sockbuf, &(edge->sock)));

                packet_header_encrypt(rereg_buf, encx, encx,
                                      comm->header_encryption_ctx_dynamic, comm->header_iv_ctx_dynamic,
                                      time_stamp());

                /* sent = */ sn_sendto_peer(sss, edge, rereg_buf, encx);
            }
        }
    }
}


/* Whether net/bitlen (network byte order) can be the address range of a
 * community */
static bool community_network_ok (in_addr_t net, uint8_t bitlen, const char *community) {

    struct in_addr addr = { .s_addr = net };

    if((bitlen > 30) || (bitlen == 0)) {
        traceEvent(TRACE_WARNING, "bad prefix '%hhu' for community '%s', ignoring",
                   bitlen, community);
        return false;
    }
    if((net == (in_addr_t)(-1)) || (net == INADDR_NONE) || (net == INADDR_ANY)
       || ((ntohl(net) & ~bitlen2mask(bitlen)) != 0)) {
        traceEvent(TRACE_WARNING, "bad network '%s/%u' for community '%s', ignoring",
                   inet_ntoa(addr), bitlen, community);
        return false;
    }
    return true;
}


/* Add a community of fixed name, which is not purged; with the address
 * range net/bitlen (network byte order), or if net is 0, one the auto ip
 * address service chooses */
static struct sn_community *add_fixed_community (struct n3n_runtime_data *sss, const char *name,
                                                 in_addr_t net, uint8_t bitlen) {

    struct sn_community *comm = calloc(1, sizeof(struct sn_community));

    if(!comm) {
        return NULL;
    }
    comm_init(comm, (char *)name);
    comm->purgeable = false;
    /* we do not know if header encryption is used in this community,
     * first packet will show. just in case, setup the key. */
    comm->header_encryption = HEADER_ENCRYPTION_UNKNOWN;
    packet_header_setup_key(comm->community,
                            &(comm->header_encryption_ctx_static),
                            &(comm->header_encryption_ctx_dynamic),
                            &(comm->header_iv_ctx_static),
                            &(comm->header_iv_ctx_dynamic));
    HASH_ADD_STR(sss->relay.communities, community, comm);

    if(net) {
        struct in_addr addr = { .s_addr = net };

        comm->auto_ip_net.net_addr = ntohl(net);
        comm->auto_ip_net.net_bitlen = bitlen;
        traceEvent(TRACE_INFO, "assigned sub-network %s/%u to community '%s'",
                   inet_ntoa(addr), bitlen, comm->community);
    } else {
        assign_one_ip_subnet(sss, comm);
    }
    return comm;
}


/* Allow a user, "NAME PUBLICKEY", in a community; which then needs header
 * encryption */
static int add_user (struct sn_community *comm, const char *line) {

    char format[20];
    n2n_desc_t username;
    char ascii_public_key[(N2N_PRIVATE_PUBLIC_KEY_SIZE * 8 + 5) / 6 + 1];
    sn_user_t *user;

    snprintf(format, sizeof(format), "%%%ds %%%us",
             N2N_DESC_SIZE - 1, (uint32_t)sizeof(ascii_public_key) - 1);
    if(sscanf(line, format, username, ascii_public_key) != 2) {
        traceEvent(TRACE_WARNING, "bad user '%s' for community '%s', ignoring",
                   line, comm->community);
        return -1;
    }

    user = (sn_user_t*)calloc(1, sizeof(sn_user_t));
    if(!user) {
        return -1;
    }
    memcpy(user->name, username, sizeof(username));
    ascii_to_bin(user->public_key, ascii_public_key);

    sn_user_t *known;
    HASH_FIND(hh, comm->allowed_users, user->public_key, sizeof(n2n_private_public_key_t), known);
    if(known) {
        traceEvent(TRACE_WARNING, "user '%s' has the public key of user '%s' in community '%s', ignoring",
                   user->name, known->name, comm->community);
        free(user);
        return -1;
    }

    // common shared secret will be calculated later
    HASH_ADD(hh, comm->allowed_users, public_key, sizeof(n2n_private_public_key_t), user);
    traceEvent(TRACE_INFO, "added user '%s' with public key '%s' to community '%s'",
               user->name, ascii_public_key, comm->community);

    // the keys are set up already, the dynamic one follows later
    comm->header_encryption = HEADER_ENCRYPTION_ENABLED;
    return 0;
}


/* Allow the communities whose whole name matches a regular expression */
static int add_rule (struct n3n_runtime_data *sss, const char *pattern) {

    struct sn_community_regular_expression *re = calloc(1, sizeof(*re));

    if(!re) {
        return -1;
    }
    re->rule = re_compile(pattern);
    if(!re->rule) {
        traceEvent(TRACE_WARNING, "bad regular expression '%s', ignoring", pattern);
        free(re);
        return -1;
    }
    HASH_ADD_PTR(sss->relay.rules, rule, re);
    traceEvent(TRACE_INFO, "added regular expression for allowed communities '%s'", pattern);
    return 0;
}


/* The communities and rules of the configuration: [community NAME] sections
 * and supernode.community_regex */
static void load_conf_communities (struct n3n_runtime_data *sss, uint32_t *num_communities, uint32_t *num_regex) {

    struct n3n_conf_community *conf_comm, *tmp_conf_comm;
    struct n3n_conf_strlist *item;

    HASH_ITER(hh, sss->conf.communities, conf_comm, tmp_conf_comm) {
        const char *name = (const char *)conf_comm->community_name;
        in_addr_t net = conf_comm->network.net_addr;
        uint8_t bitlen = conf_comm->network.net_bitlen;
        struct sn_community *comm;

        HASH_FIND_STR(sss->relay.communities, name, comm);
        if(comm) {
            traceEvent(TRACE_WARNING, "community '%s' of section [community %s] is there already, ignoring",
                       name, conf_comm->instance);
            continue;
        }
        if(net && !community_network_ok(net, bitlen, name)) {
            net = 0;
        }
        comm = add_fixed_community(sss, name, net, bitlen);
        if(!comm) {
            continue;
        }
        (*num_communities)++;
        traceEvent(TRACE_INFO, "added allowed community '%s' of section [community %s]",
                   name, conf_comm->instance);

        if(conf_comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
            comm->header_encryption = HEADER_ENCRYPTION_ENABLED;
        }
        for(item = conf_comm->users; item; item = item->next) {
            add_user(comm, item->str);
        }
    }

    for(item = sss->conf.relay.community_regex; item; item = item->next) {
        if(add_rule(sss, item->str) == 0) {
            (*num_regex)++;
        }
    }
}


/* The [community NAME] section of a community, NULL if it has none */
static struct n3n_conf_community *conf_community (struct n3n_runtime_data *sss, const char *name) {

    struct n3n_conf_community *conf_comm, *tmp_conf_comm;

    HASH_ITER(hh, sss->conf.communities, conf_comm, tmp_conf_comm) {
        if(!strncmp((const char *)conf_comm->community_name, name, N2N_COMMUNITY_SIZE)) {
            return conf_comm;
        }
    }
    return NULL;
}


/* The communities and rules of the community file.  For a community of a
 * section of the configuration, the file only gives what the section does
 * not: the address range, the users. */
static void load_file_communities (struct n3n_runtime_data *sss, FILE *fd, uint32_t *num_communities, uint32_t *num_regex) {

    char buffer[4096], *line, *cmn_str, net_str[20];
    dec_ip_str_t ip_str = {'\0'};
    uint8_t bitlen;
    in_addr_t net;
    struct sn_community *comm, *last_added_comm = NULL;
    int has_net;

    while((line = fgets(buffer, sizeof(buffer), fd)) != NULL) {
        int len = strlen(line);

        if((len < 2) || line[0] == '#') {
            continue;
        }

        len--;
        while(len > 0) {
            if((line[len] == '\n') || (line[len] == '\r')) {
                line[len] = '\0';
                len--;
            } else {
                break;
            }
        }
        // the loop above does not always determine correct 'len'
        len = strlen(line);

        // user-key line for edge authentication?
        if(line[0] == N2N_USER_KEY_LINE_STARTER) { /* special first character */
            if(last_added_comm) { /* is there a valid community to add users to */
                add_user(last_added_comm, line + 1);
            }
            continue;
        }

        // --- community name or regular expression

        // cut off any IP sub-network upfront
        cmn_str = (char*)calloc(len + 1, sizeof(char));
        if(!cmn_str) {
            break;
        }
        has_net = (sscanf(line, "%s %19s", cmn_str, net_str) == 2);
        last_added_comm = NULL;

        // if it contains typical characters...
        if(NULL != strpbrk(cmn_str, ".*+?[]\\")) {
            // ...it is treated as regular expression
            if(add_rule(sss, cmn_str) == 0) {
                (*num_regex)++;
            }
            free(cmn_str);
            continue;
        }

        // check for sub-network address
        net = 0;
        if(has_net) {
            if(sscanf(net_str, "%15[^/]/%hhu", ip_str, &bitlen) != 2) {
                traceEvent(TRACE_WARNING, "bad net/bit format '%s' for community '%s', ignoring; see comments inside community.list file",
                           net_str, cmn_str);
            } else {
                net = inet_addr(ip_str);
                if(!community_network_ok(net, bitlen, cmn_str)) {
                    net = 0;
                }
            }
        }

        HASH_FIND_STR(sss->relay.communities, cmn_str, comm);
        if(comm) {
            struct n3n_conf_community *conf_comm = conf_community(sss, cmn_str);

            if(!conf_comm) {
                traceEvent(TRACE_WARNING, "community '%s' is in %s twice, ignoring the second",
                           cmn_str, sss->conf.relay.community_file);
                free(cmn_str);
                continue;
            }
            traceEvent(TRACE_NORMAL, "community '%s' is in section [community %s] and in %s, the section wins",
                       cmn_str, conf_comm->instance, sss->conf.relay.community_file);
            if(net && !conf_comm->network.net_addr) {
                struct in_addr addr = { .s_addr = net };

                comm->auto_ip_net.net_addr = ntohl(net);
                comm->auto_ip_net.net_bitlen = bitlen;
                traceEvent(TRACE_INFO, "assigned sub-network %s/%u of %s to community '%s'",
                           inet_ntoa(addr), bitlen, sss->conf.relay.community_file, comm->community);
            }
            if(!conf_comm->users) {
                // its users from the file
                last_added_comm = comm;
            }
            free(cmn_str);
            continue;
        }

        comm = add_fixed_community(sss, cmn_str, net, bitlen);
        if(comm) {
            last_added_comm = comm;
            (*num_communities)++;
            traceEvent(TRACE_INFO, "added allowed community '%s' [total: %u]",
                       (char*)comm->community, *num_communities);
        }
        free(cmn_str);
    }
}


/** Load the allowed communities: of the [community NAME] sections and
 *  supernode.community_regex of the configuration, and of the community
 *  file, which is read again.  Existing/previous ones will be removed.
 *  return 0 on success, -1 if there is nothing to load or the file is not
 *  found, -2 if no valid entries found
 */
int load_allowed_sn_community (struct n3n_runtime_data *sss) {

    sn_user_t *user, *tmp_user;
    FILE *fd = NULL;
    int rc = 0;

    struct sn_community *comm, *tmp_comm;
    struct peer_info *edge, *tmp_edge;
    node_supernode_association_t *assoc, *tmp_assoc;
    time_t any_time = 0;

    uint32_t num_communities = 0;

    struct sn_community_regular_expression *re, *tmp_re;
    uint32_t num_regex = 0;

    bool in_conf = sss->conf.communities || sss->conf.relay.community_regex;

    if(sss->conf.relay.community_file) {
        fd = fopen(sss->conf.relay.community_file, "r");
        if(fd == NULL) {
            traceEvent(TRACE_WARNING, "File %s not found", sss->conf.relay.community_file);
            rc = -1;
        }
    }
    if(!fd && !in_conf) {
        return -1;
    }

    // reset data structures ------------------------------

    // send RE_REGISTER_SUPER to all edges from user/pw auth communites, this is safe because
    // follow-up REGISTER_SUPER cannot be handled before this function ends
    send_re_register_super(sss);

    // remove communities (not: federation)
    HASH_ITER(hh, sss->relay.communities, comm, tmp_comm) {
        if(comm->is_federation) {
            continue;
        }

        // remove all edges from community
        HASH_ITER(hh, comm->edges, edge, tmp_edge) {
            // remove all edge associations (with other supernodes)
            HASH_ITER(hh, comm->assoc, assoc, tmp_assoc) {
                HASH_DEL(comm->assoc, assoc);
                free(assoc);
            }

            // close TCP connections, if any (also causes reconnect)
            // and delete edge from list
            remove_edge(sss, comm, edge);
        }

        // remove allowed users from community
        HASH_ITER(hh, comm->allowed_users, user, tmp_user) {
            speck_deinit((speck_context_t*)user->shared_secret_ctx);
            HASH_DEL(comm->allowed_users, user);
            free(user);
        }

        // remove community
        HASH_DEL(sss->relay.communities, comm);
        // remove header encryption keys
        free(comm->header_encryption_ctx_static);
        free(comm->header_iv_ctx_static);
        free(comm->header_encryption_ctx_dynamic);
        free(comm->header_iv_ctx_dynamic);
        free(comm);
    }

    // remove all regular expressions for allowed communities
    HASH_ITER(hh, sss->relay.rules, re, tmp_re) {
        HASH_DEL(sss->relay.rules, re);
        free(re->rule);
        free(re);
    }

    // prepare reading data -------------------------------

    // new key_time for all communities, requires dynamic keys to be recalculated (see further below),
    // and  edges to re-register (see above) and ...
    sss->relay.dynamic_key_time = time(NULL);
    // ... federated supernodes to re-register
    re_register_and_purge_supernodes(sss, sss->relay.federation, &any_time, any_time, 1 /* forced */);

    // the sections of the configuration first: they win over the file
    load_conf_communities(sss, &num_communities, &num_regex);
    if(in_conf) {
        traceEvent(TRACE_NORMAL, "loaded %u fixed-name communities and %u regular expressions from the configuration",
                   num_communities, num_regex);
    }

    if(fd) {
        uint32_t conf_communities = num_communities;
        uint32_t conf_regex = num_regex;

        load_file_communities(sss, fd, &num_communities, &num_regex);
        fclose(fd);

        traceEvent(TRACE_NORMAL, "loaded %u fixed-name communities from %s",
                   num_communities - conf_communities, sss->conf.relay.community_file);

        traceEvent(TRACE_NORMAL, "loaded %u regular expressions for community name matching from %s",
                   num_regex - conf_regex, sss->conf.relay.community_file);
    }

    if((num_regex + num_communities) == 0) {
        traceEvent(TRACE_WARNING, "no valid community names or regular expressions found");
        return -2;
    }

    // calculate allowed user's shared secrets (shared with federation)
    calculate_shared_secrets(sss);

    // calculcate communties' dynamic keys
    calculate_dynamic_keys(sss);

    // no new communities will be allowed
    sss->relay.lock_communities = true;

    return rc;
}


/** Initialise some fields of the community structure **/
int comm_init (struct sn_community *comm, char *cmn) {

    strncpy((char*)comm->community, cmn, N2N_COMMUNITY_SIZE);
    comm->community[N2N_COMMUNITY_SIZE - 1] = '\0';
    comm->is_federation = false;

    return 0; /* OK */
}


/** checks if a certain ip address is still available, i.e. not used by any other edge of a given community */
static int ip_addr_available (struct sn_community *comm, n2n_ip_subnet_t *ip_addr) {

    int success = 1;
    struct peer_info *peer, *tmp_peer;

    // prerequisite: list of peers is sorted according to peer's tap ip address
    HASH_ITER(hh, comm->edges, peer, tmp_peer) {
        if(peer->dev_addr.net_addr  > ip_addr->net_addr) {
            break;
        }
        if(peer->dev_addr.net_addr == ip_addr->net_addr) {
            success = 0;
            break;
        }
    }

    return success;
}


static signed int peer_tap_ip_sort (struct peer_info *a, struct peer_info *b) {

    uint32_t a_host_id = a->dev_addr.net_addr & (~bitlen2mask(a->dev_addr.net_bitlen));
    uint32_t b_host_id = b->dev_addr.net_addr & (~bitlen2mask(b->dev_addr.net_bitlen));

    return ((signed int)a_host_id - (signed int)b_host_id);
}


/** The IP address assigned to the edge by the auto ip address function of sn. */
int assign_one_ip_addr (struct sn_community *comm, n2n_desc_t dev_desc, n2n_ip_subnet_t *ip_addr) {

    uint32_t tmp, success, net_id, mask, max_host, host_id = 1;
    dec_ip_bit_str_t ip_bit_str = {'\0'};

    mask = bitlen2mask(comm->auto_ip_net.net_bitlen);
    net_id = comm->auto_ip_net.net_addr & mask;
    max_host = ~mask;

    // sorting is a prerequisite for more efficient availabilitiy check
    HASH_SORT(comm->edges, peer_tap_ip_sort);

    // first proposal derived from hash of mac address
    tmp = pearson_hash_32(dev_desc, sizeof(n2n_desc_t)) & max_host;
    if(tmp == 0) tmp++;        /* avoid 0 host */
    if(tmp == max_host) tmp--; /* avoid broadcast address */
    tmp |= net_id;

    // candidate
    ip_addr->net_bitlen = comm->auto_ip_net.net_bitlen;

    // check for availability starting from proposal, then downwards, ...
    for(host_id = tmp; host_id > net_id; host_id--) {
        ip_addr->net_addr = host_id;
        success = ip_addr_available(comm, ip_addr);
        if(success) {
            break;
        }
    }
    // ... then upwards
    if(!success) {
        for(host_id = tmp + 1; host_id < (net_id + max_host); host_id++) {
            ip_addr->net_addr = host_id;
            success = ip_addr_available(comm, ip_addr);
            if(success) {
                break;
            }
        }
    }

    if(success) {
        traceEvent(TRACE_INFO, "assign IP %s to tap adapter of edge", ip_subnet_to_str(ip_bit_str, ip_addr));
        return 0;
    } else {
        traceEvent(TRACE_WARNING, "no assignable IP to edge tap adapter");
        return -1;
    }
}


/** checks if a certain sub-network is still available, i.e. does not cut any other community's sub-network */
int subnet_available (struct n3n_runtime_data *sss,
                      struct sn_community *comm,
                      uint32_t net_id,
                      uint32_t mask) {

    struct sn_community *cmn, *tmpCmn;
    int success = 1;

    HASH_ITER(hh, sss->relay.communities, cmn, tmpCmn) {
        if(cmn == comm) {
            continue;
        }
        if(cmn->is_federation) {
            continue;
        }
        if((net_id <= (cmn->auto_ip_net.net_addr + ~bitlen2mask(cmn->auto_ip_net.net_bitlen)))
           &&(net_id + ~mask >= cmn->auto_ip_net.net_addr)) {
            success = 0;
            break;
        }
    }

    return success;
}


/** The IP address range (subnet) assigned to the community by the auto ip address function of sn. */
int assign_one_ip_subnet (struct n3n_runtime_data *sss,
                          struct sn_community *comm) {

    uint32_t net_id, net_id_i, mask, net_increment;
    uint32_t no_subnets;
    uint8_t success;
    in_addr_t net_min;
    in_addr_t net_max;
    in_addr_t net;


    mask = bitlen2mask(sss->conf.relay.sn_min_auto_ip_net.net_bitlen);
    net_min = ntohl(sss->conf.relay.sn_min_auto_ip_net.net_addr);
    net_max = ntohl(sss->conf.relay.sn_max_auto_ip_net.net_addr);

    // number of possible sub-networks
    no_subnets   = net_max - net_min;
    no_subnets >>= (32 - sss->conf.relay.sn_min_auto_ip_net.net_bitlen);
    no_subnets  += 1;

    // proposal for sub-network to choose
    net_id    = pearson_hash_32((const uint8_t *)comm->community, N2N_COMMUNITY_SIZE) % no_subnets;
    net_id    = net_min + (net_id << (32 - sss->conf.relay.sn_min_auto_ip_net.net_bitlen));

    // check for availability starting from net_id, then downwards, ...
    net_increment = (~mask+1);
    for(net_id_i = net_id; net_id_i >= net_min; net_id_i -= net_increment) {
        success = subnet_available(sss, comm, net_id_i, mask);
        if(success) {
            break;
        }
    }
    // ... then upwards
    if(!success) {
        for(net_id_i = net_id + net_increment; net_id_i <= net_max; net_id_i += net_increment) {
            success = subnet_available(sss, comm, net_id_i, mask);
            if(success) {
                break;
            }
        }
    }

    if(success) {
        comm->auto_ip_net.net_addr = net_id_i;
        comm->auto_ip_net.net_bitlen = sss->conf.relay.sn_min_auto_ip_net.net_bitlen;
        net = htonl(comm->auto_ip_net.net_addr);
        struct in_addr *tmp = (struct in_addr *)&net;
        traceEvent(TRACE_INFO, "assigned sub-network %s/%u to community '%s'",
                   inet_ntoa(*tmp),
                   comm->auto_ip_net.net_bitlen,
                   comm->community);
        return 0;
    } else {
        comm->auto_ip_net.net_addr = 0;
        comm->auto_ip_net.net_bitlen = 0;
        traceEvent(TRACE_WARNING, "no assignable sub-network left for community '%s'",
                   comm->community);
        return -1;
    }
}


int purge_expired_communities (struct n3n_runtime_data *sss,
                               time_t* p_last_purge,
                               time_t now) {

    struct sn_community *comm, *tmp_comm;
    node_supernode_association_t *assoc, *tmp_assoc;
    size_t num_reg = 0;
    size_t num_assoc = 0;

    if((now - (*p_last_purge)) < PURGE_REGISTRATION_FREQUENCY) {
        return 0;
    }

    traceEvent(TRACE_DEBUG, "purging old communities and edges");

    HASH_ITER(hh, sss->relay.communities, comm, tmp_comm) {
        // federation is taken care of in re_register_and_purge_supernodes()
        if(comm->is_federation)
            continue;

        // purge the community's local peers
        num_reg += purge_peer_list(&comm->edges, sss->sock, &sss->relay.tcp_connections, now - REGISTRATION_TIMEOUT);

        // purge the community's associated peers (connected to other supernodes)
        HASH_ITER(hh, comm->assoc, assoc, tmp_assoc) {
            if(comm->assoc->last_seen < (now - 3 * REGISTRATION_TIMEOUT)) {
                HASH_DEL(comm->assoc, assoc);
                free(assoc);
                num_assoc++;
            }
        }

        if((comm->edges == NULL) && (comm->purgeable)) {
            traceEvent(TRACE_INFO, "purging idle community %s", comm->community);
            if(NULL != comm->header_encryption_ctx_static) {
                /* this should not happen as 'purgeable' and thus only communities w/o encrypted header here */
                free(comm->header_encryption_ctx_static);
                free(comm->header_iv_ctx_static);
                free(comm->header_encryption_ctx_dynamic);
                free(comm->header_iv_ctx_dynamic);
            }
            // remove all associations
            HASH_ITER(hh, comm->assoc, assoc, tmp_assoc) {
                HASH_DEL(comm->assoc, assoc);
                free(assoc);
            }
            HASH_DEL(sss->relay.communities, comm);
            free(comm);
        }
    }
    (*p_last_purge) = now;

    traceEvent(TRACE_DEBUG, "purge_expired_communities removed %ld locally registered edges and %ld remotely associated edges",
               num_reg, num_assoc);

    return 0;
}


// what the packet threads of the supernode counted for this community
int64_t number_enc_packets (const struct sn_community *comm) {

    int64_t sum = 0;
    int slot;

    for(slot = 0; slot < N3N_STATS_SLOTS; slot++) {
        sum += comm->number_enc_packets[slot];
    }
    return sum;
}


static int number_enc_packets_sort (struct sn_community *a, struct sn_community *b) {

    // comparison function for sorting communities in descending order of their
    // number_enc_packets-fields
    return (number_enc_packets(b) - number_enc_packets(a));
}


int sort_communities (struct n3n_runtime_data *sss,
                      time_t* p_last_sort,
                      time_t now) {

    struct sn_community *comm, *tmp;

    if((now - (*p_last_sort)) < SORT_COMMUNITIES_INTERVAL) {
        return 0;
    }

    // this routine gets periodically called as defined in SORT_COMMUNITIES_INTERVAL
    // it sorts the communities in descending order of their number_enc_packets-fields...
    HASH_SORT(sss->relay.communities, number_enc_packets_sort);

    // ... and afterward resets the number_enc__packets-fields to zero
    // (other models could reset it to half of their value to respect history)
    HASH_ITER(hh, sss->relay.communities, comm, tmp) {
        memset(comm->number_enc_packets, 0, sizeof(comm->number_enc_packets));
    }

    (*p_last_sort) = now;

    return 0;
}
