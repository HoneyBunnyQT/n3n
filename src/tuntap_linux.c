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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */


#ifdef __linux__


#include <arpa/inet.h>                // for inet_addr, inet_pton
#include <sys/uio.h>                  // for iovec
#include <errno.h>                    // for errno
#include <fcntl.h>                    // for open, O_RDWR, O_NONBLOCK
#include <linux/if_tun.h>             // for IFF_NO_PI, IFF_TAP, TUNSETIFF
#include <linux/netlink.h>            // for sockaddr_nl, nlmsghdr, NETLINK_...
#include <linux/rtnetlink.h>          // for ifinfomsg, RTMGRP_LINK
#include <n3n/logging.h>              // for traceEvent
#include <n3n/random.h>               // for memrnd
#include <net/if.h>                   // for ifreq, IFNAMSIZ, ifr_name, ifr_...
#include <net/if_arp.h>               // for ARPHRD_ETHER
#include <netinet/in.h>               // for sockaddr_in, IPPROTO_IP, in_addr
#include <stdint.h>                   // for uint8_t
#include <string.h>                   // for strerror, memset, strncpy, memcpy
#include <sys/ioctl.h>                // for ioctl, SIOCGIFADDR, SIOCGIFFLAGS
#include <sys/param.h>                // for MIN
#include <sys/socket.h>               // for socket, msghdr, AF_INET, sockaddr
#include <sys/uio.h>                  // for iovec
#include <unistd.h>                   // for close, getpid, read, write, ssi...

#include "n2n.h"                      // for tuntap_dev, ...
#include "n2n_typedefs.h"
#include "n3n/ethernet.h"


static int setup_ifname (int fd, const char *ifname,
                         struct n2n_ip_subnet v4subnet,
                         uint8_t *mac, int mtu, bool tun) {

    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ-1] = '\0';

    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    memcpy(ifr.ifr_hwaddr.sa_data, mac, 6);

    // a TUN device has no MAC address: the edge's is its own, see tun.c
    if(!tun && (ioctl(fd, SIOCSIFHWADDR, &ifr) == -1)) {
        traceEvent(TRACE_ERROR, "ioctl(SIOCSIFHWADDR) failed [%d]: %s", errno, strerror(errno));
        return -1;
    }

    ifr.ifr_addr.sa_family = AF_INET;

    // interface address
    ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr = v4subnet.net_addr;
    if(ioctl(fd, SIOCSIFADDR, &ifr) == -1) {
        traceEvent(TRACE_ERROR, "ioctl(SIOCSIFADDR) failed [%d]: %s", errno, strerror(errno));
        return -2;
    }

    // netmask
    if(v4subnet.net_bitlen && (((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr != 0)) {
        ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr = htonl(bitlen2mask(v4subnet.net_bitlen));
        if(ioctl(fd, SIOCSIFNETMASK, &ifr) == -1) {
            traceEvent(TRACE_ERROR, "ioctl(SIOCSIFNETMASK, %u) failed [%d]: %s", v4subnet.net_bitlen, errno, strerror(errno));
            return -3;
        }
    }

    // MTU
    ifr.ifr_mtu = mtu;
    if(ioctl(fd, SIOCSIFMTU, &ifr) == -1) {
        traceEvent(TRACE_ERROR, "ioctl(SIOCSIFMTU) failed [%d]: %s", errno, strerror(errno));
        return -4;
    }

    // set up and running
    if(ioctl(fd, SIOCGIFFLAGS, &ifr) == -1) {
        traceEvent(TRACE_ERROR, "ioctl(SIOCGIFFLAGS) failed [%d]: %s", errno, strerror(errno));
        return -5;
    }

    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);

    if(ioctl(fd, SIOCSIFFLAGS, &ifr) == -1) {
        traceEvent(TRACE_ERROR, "ioctl(SIOCSIFFLAGS) failed [%d]: %s", errno, strerror(errno));
        return -6;
    }

    return 0;
}


/* Attach more queues to the device the first queue created, as far as that
 * works - the rest simply is not there. The device hands every flow to one of
 * the queues, and replies to what was written into a queue go back to the
 * same queue. */
static void open_more_queues (tuntap_dev *device, struct ifreq *ifr, int queues) {

    while(device->queues < queues) {
        int fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);

        if(fd < 0) {
            break;
        }
        if(ioctl(fd, TUNSETIFF, (void *)ifr) < 0) {
            close(fd);
            break;
        }
        device->queue_fd[device->queues++] = fd;
    }

    if(device->queues < queues) {
        traceEvent(TRACE_WARNING, "tuntap opened only %d of %d queues: %s[%d]",
                   device->queues, queues, strerror(errno), errno);
    }
}


/** @brief  Open and configure the TAP device for packet read/write.
 *
 *  This routine creates the interface via the tuntap driver and then
 *  configures it.
 *
 *  @param device      - [inout] a device info holder object
 *  @param queues      - how many queues to open, so that several threads can
 *                       each read and write their own. device->queues says
 *                       how many it got.
 *  @param dev         - user-defined name for the new iface,
 *                       if NULL system will assign a name
 *  @param v4subnet    - address and netmask of iface
 *  @param mtu         - MTU for device
 *
 *  @return - negative value on error
 *          - non-negative file-descriptor on success
 */
int tuntap_open_queues (tuntap_dev *device,
                        int queues,
                        char *dev, /* user-definable interface name, eg. edge0 */
                        uint8_t address_mode, /* unused! */
                        struct n2n_ip_subnet v4subnet,
                        const char * device_mac,
                        int mtu,
                        int ignored) {

    char *tuntap_device = "/dev/net/tun";
    int ioctl_fd;
    struct ifreq ifr;
    int rc;
    int nl_fd;
    char nl_buf[8192]; /* >= 8192 to avoid truncation, see "man 7 netlink" */
    struct iovec iov;
    struct sockaddr_nl sa;
    int up_and_running = 0;
    struct msghdr msg;
    int q;

    device->queues = 0;
    for(q = 0; q < N2N_TUNTAP_QUEUES_MAX; q++) {
        device->queue_fd[q] = -1;
    }
    if(queues > N2N_TUNTAP_QUEUES_MAX) {
        queues = N2N_TUNTAP_QUEUES_MAX;
    }

    device->fd = open(tuntap_device, O_RDWR | O_NONBLOCK);
    if(device->fd < 0) {
        traceEvent(TRACE_ERROR, "tuntap open() error: %s[%d]. Is the tun kernel module loaded?\n", strerror(errno), errno);
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));

    // a TAP device for layer 2 frames, or a TUN device for IP packets
    ifr.ifr_flags = (device->tun ? IFF_TUN : IFF_TAP) | IFF_NO_PI;
    if(queues > 1) {
        ifr.ifr_flags |= IFF_MULTI_QUEUE;
    }

    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    ifr.ifr_name[IFNAMSIZ-1] = '\0';
    rc = ioctl(device->fd, TUNSETIFF, (void *)&ifr);

    if((rc < 0) && (queues > 1)) {
        // a kernel older than 3.8, or a device created beforehand with one
        // queue
        traceEvent(TRACE_WARNING, "tuntap cannot open several queues: %s[%d], using one", strerror(errno), errno);
        queues = 1;
        ifr.ifr_flags = (device->tun ? IFF_TUN : IFF_TAP) | IFF_NO_PI;
        rc = ioctl(device->fd, TUNSETIFF, (void *)&ifr);
    }

    if(rc < 0) {
        traceEvent(TRACE_ERROR, "tuntap ioctl(TUNSETIFF, %s) error: %s[%d]\n", device->tun ? "IFF_TUN" : "IFF_TAP",
                   strerror(errno), rc);
        close(device->fd);
        return -1;
    }

    device->queue_fd[0] = device->fd;
    device->queues = 1;
    open_more_queues(device, &ifr, queues);

    // store the device name for later reuse
    strncpy(device->dev_name, ifr.ifr_name, MIN(IFNAMSIZ, sizeof(devstr_t)));

    if(device_mac && device_mac[0]) {
        // use the user-provided MAC
        str2mac(device->mac_addr, device_mac);
    } else {
        // set an explicit random MAC to know the exact MAC in use, manually
        // reading the MAC address is not safe as it may change internally
        // also after the TAP interface UP status has been notified

        memrnd(device->mac_addr, N2N_MAC_SIZE);

        // clear multicast bit
        device->mac_addr[0] &= ~0x01;

        // set locally-assigned bit
        device->mac_addr[0] |= 0x02;
    }

    // initialize netlink socket
    if((nl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) == -1) {
        traceEvent(TRACE_ERROR, "netlink socket creation failed [%d]: %s", errno, strerror(errno));
        return -1;
    }

    iov.iov_base = nl_buf;
    iov.iov_len = sizeof(nl_buf);

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = PF_NETLINK;
    sa.nl_groups = RTMGRP_LINK;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &sa;
    msg.msg_namelen = sizeof(sa);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    // subscribe to interface events
    if(bind(nl_fd, (struct sockaddr*)&sa, sizeof(sa)) == -1) {
        traceEvent(TRACE_ERROR, "netlink socket bind failed [%d]: %s", errno, strerror(errno));
        return -1;
    }

    if((ioctl_fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
        traceEvent(TRACE_ERROR, "socket creation failed [%d]: %s", errno, strerror(errno));
        close(nl_fd);
        return -1;
    }

    if(setup_ifname(ioctl_fd, device->dev_name, v4subnet, device->mac_addr, mtu, device->tun) < 0) {
        close(nl_fd);
        close(ioctl_fd);
        tuntap_close(device);
        return -1;
    }

    close(ioctl_fd);

    // wait for the up and running notification
    traceEvent(TRACE_INFO, "Waiting for TAP interface to be up and running...");

    while(!up_and_running) {
        ssize_t len = recvmsg(nl_fd, &msg, 0);
        struct nlmsghdr *nh;

        for(nh = (struct nlmsghdr *)nl_buf; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
            if(nh->nlmsg_type == NLMSG_ERROR) {
                traceEvent(TRACE_DEBUG, "nh->nlmsg_type == NLMSG_ERROR");
                break;
            }

            if(nh->nlmsg_type == NLMSG_DONE)
                break;

            if(nh->nlmsg_type == NETLINK_GENERIC) {
                struct ifinfomsg *ifi = NLMSG_DATA(nh);

                // NOTE: skipping interface name check, assuming it's our TAP
                if((ifi->ifi_flags & IFF_UP) && (ifi->ifi_flags & IFF_RUNNING)) {
                    up_and_running = 1;
                    traceEvent(TRACE_INFO, "Interface is up and running");
                    break;
                }
            }
        }
    }

    close(nl_fd);

    device->ip_addr = v4subnet.net_addr;

    return device->fd;
}


int tuntap_open (tuntap_dev *device,
                 char *dev,
                 uint8_t address_mode,
                 struct n2n_ip_subnet v4subnet,
                 const char * device_mac,
                 int mtu,
                 int metric) {

    return tuntap_open_queues(device, 1, dev, address_mode, v4subnet, device_mac, mtu, metric);
}


int tuntap_read (struct tuntap_dev *tuntap, unsigned char *buf, int len) {

    return read(tuntap->fd, buf, len);
}


int tuntap_write (struct tuntap_dev *tuntap, unsigned char *buf, int len) {

    return write(tuntap->fd, buf, len);
}


// only for a queue that is open
int tuntap_read_queue (struct tuntap_dev *tuntap, int queue, unsigned char *buf, int len) {

    return read(tuntap->queue_fd[queue], buf, len);
}


// Any queue will do for writing: if this one is not open, the first.
int tuntap_write_queue (struct tuntap_dev *tuntap, int queue, unsigned char *buf, int len) {

    int fd = tuntap->queue_fd[queue];

    return write((fd >= 0) ? fd : tuntap->fd, buf, len);
}


// Close all but the first keep queues. Whatever the device hands to a queue
// that nobody reads is lost, so the queues without a reader have to go.
void tuntap_close_queues (struct tuntap_dev *tuntap, int keep) {

    while(tuntap->queues > keep) {
        tuntap->queues--;
        close(tuntap->queue_fd[tuntap->queues]);
        tuntap->queue_fd[tuntap->queues] = -1;
    }
}


void tuntap_close (struct tuntap_dev *tuntap) {

    tuntap_close_queues(tuntap, 1);
    close(tuntap->fd);
}


// fill out the ip_addr value from the interface, called to pick up dynamic address changes
void tuntap_get_address (struct tuntap_dev *tuntap) {

    struct ifreq ifr;
    int fd;

    if((fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
        traceEvent(TRACE_ERROR, "socket creation failed [%d]: %s", errno, strerror(errno));
        return;
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, tuntap->dev_name, IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ-1] = '\0';

    if(ioctl(fd, SIOCGIFADDR, &ifr) != -1)
        tuntap->ip_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

    close(fd);
}


#endif /* #ifdef __linux__ */
