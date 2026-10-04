/*
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Noticing that the host's network changed, see netwatch.h
 */

#include <stdio.h>          // for snprintf
#include <string.h>         // for strlen
#include "netwatch.h"

#ifdef __linux__

#include <errno.h>              // for errno, EAGAIN, ENOBUFS
#include <linux/netlink.h>      // for sockaddr_nl, nlmsghdr, NLMSG_*
#include <linux/rtnetlink.h>    // for RTM_*, RTMGRP_*, ifaddrmsg, rtmsg
#include <net/if.h>             // for if_nametoindex, IFF_*
#include <stdint.h>             // for int64_t
#include <sys/socket.h>         // for socket, bind, recv
#include <time.h>               // for clock_gettime
#include <unistd.h>             // for close
#include <n3n/logging.h>        // for traceEvent

#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP 0x10000    // linux/if.h, which does not go with net/if.h
#endif

// the edge's own device, whose changes are its own doing
static unsigned own_index;


int netwatch_open (const char *own_dev) {

    struct sockaddr_nl sa = {
        .nl_family = AF_NETLINK,
        .nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR
                     | RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE,
    };
    int fd;

    own_index = (own_dev && own_dev[0]) ? if_nametoindex(own_dev) : 0;

    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
    if(fd < 0) {
        traceEvent(TRACE_INFO, "netwatch: no netlink socket [%s]", strerror(errno));
        return -1;
    }
    if(bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        traceEvent(TRACE_INFO, "netwatch: netlink not allowed [%s]", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}


void netwatch_close (int fd) {

    if(fd >= 0) {
        close(fd);
    }
}


// The outgoing interface of a route, 0 for none
static unsigned route_oif (struct nlmsghdr *nh) {

    struct rtmsg *rt = NLMSG_DATA(nh);
    int len = RTM_PAYLOAD(nh);

    for(struct rtattr *a = RTM_RTA(rt); RTA_OK(a, len); a = RTA_NEXT(a, len)) {
        if(a->rta_type == RTA_OIF) {
            return *(unsigned *)RTA_DATA(a);
        }
    }
    return 0;
}


static unsigned message (struct nlmsghdr *nh) {

    switch(nh->nlmsg_type) {
        case RTM_NEWADDR:
        case RTM_DELADDR: {
            struct ifaddrmsg *ifa = NLMSG_DATA(nh);
            // its own device, loopback, link-local, or not yet usable
            if((ifa->ifa_index == own_index)
               || (ifa->ifa_scope == RT_SCOPE_HOST)
               || (ifa->ifa_scope == RT_SCOPE_LINK)
               || ((nh->nlmsg_type == RTM_NEWADDR) && (ifa->ifa_flags & IFA_F_TENTATIVE))) {
                return 0;
            }
            return NETWATCH_ADDRESS;
        }

        case RTM_NEWLINK:
        case RTM_DELLINK: {
            struct ifinfomsg *ifi = NLMSG_DATA(nh);
            if((ifi->ifi_index == (int)own_index) || (ifi->ifi_flags & IFF_LOOPBACK)) {
                return 0;
            }
            // whether it is up and has carrier: other changes do not matter
            if((nh->nlmsg_type == RTM_NEWLINK)
               && !(ifi->ifi_change & (IFF_UP | IFF_RUNNING | IFF_LOWER_UP))) {
                return 0;
            }
            return NETWATCH_LINK;
        }

        case RTM_NEWROUTE:
        case RTM_DELROUTE: {
            struct rtmsg *rt = NLMSG_DATA(nh);
            // the default route of the main table only, not one through
            // its own device
            if((rt->rtm_dst_len != 0) || (rt->rtm_table != RT_TABLE_MAIN)
               || (own_index && (route_oif(nh) == own_index))) {
                return 0;
            }
            return NETWATCH_ROUTE;
        }

        default:
            return 0;
    }
}


unsigned netwatch_read (int fd) {

    char buf[8192] __attribute__((aligned(__alignof__(struct nlmsghdr))));
    unsigned why = 0;

    for(;;) {
        ssize_t len = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if(len < 0) {
            if(errno == ENOBUFS) {
                // more came than fit in the socket's buffer: much changed
                why |= NETWATCH_LINK;
                continue;
            }
            break;  // EAGAIN: all read
        }
        if(len == 0) {
            break;
        }
        for(struct nlmsghdr *nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
            why |= message(nh);
        }
    }
    return why;
}


bool netwatch_resumed (void) {

    static int64_t last_gap = -1;
    struct timespec boot, mono;
    int64_t gap;
    bool slept;

    if((clock_gettime(CLOCK_BOOTTIME, &boot) != 0) || (clock_gettime(CLOCK_MONOTONIC, &mono) != 0)) {
        return false;
    }
    // milliseconds the host slept since it started
    gap = (int64_t)(boot.tv_sec - mono.tv_sec) * 1000 + (boot.tv_nsec - mono.tv_nsec) / 1000000;
    slept = (last_gap >= 0) && (gap - last_gap > 2000);
    last_gap = gap;
    return slept;
}

#else

int netwatch_open (const char *own_dev) {
    return -1;
}

void netwatch_close (int fd) {
}

unsigned netwatch_read (int fd) {
    return 0;
}

bool netwatch_resumed (void) {
    return false;
}

#endif


const char *netwatch_str (unsigned why, char *buf, int len) {

    static const char *names[] = {"address", "link", "route", "wake-up", "app"};
    int at = 0;

    buf[0] = 0;
    for(int i = 0; i < (int)(sizeof(names) / sizeof(names[0])); i++) {
        if((why & (1u << i)) && (at < len)) {
            at += snprintf(buf + at, len - at, "%s%s", at ? ", " : "", names[i]);
        }
    }
    return buf;
}
