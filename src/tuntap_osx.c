/**
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023-25 Hamish Coleman
 * Copyright (C) Honey Bunny QT
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

#ifdef __APPLE__


#include <arpa/inet.h>          // for inet_ntop, htonl
#include <errno.h>              // for errno
#include <fcntl.h>
#include <n3n/ethernet.h>       // for str2mac
#include <n3n/logging.h>        // for traceEvent
#include <n3n/random.h>         // for memrnd
#include <signal.h>             // for sigaction, SIGCHLD
#include <spawn.h>              // for posix_spawn
#include <stdio.h>              // for snprintf, sscanf
#include <string.h>             // for memset, strerror, strlcpy
#include <sys/ioctl.h>          // for ioctl
#include <sys/kern_control.h>   // for ctl_info, sockaddr_ctl, CTLIOCGINFO
#include <sys/socket.h>         // for in_addr_t
#include <sys/sys_domain.h>     // for SYSPROTO_CONTROL, AF_SYS_CONTROL
#include <sys/uio.h>            // for iovec, readv, writev
#include <sys/wait.h>           // for waitpid
#include <unistd.h>             // for close, read, write
#include "n2n.h"



#define N2N_OSX_TAPDEVICE_SIZE 32

// from <net/if_utun.h>, which is not in every SDK
#ifndef UTUN_CONTROL_NAME
#define UTUN_CONTROL_NAME "com.apple.net.utun_control"
#endif
#ifndef UTUN_OPT_IFNAME
#define UTUN_OPT_IFNAME 2
#endif

extern char **environ;


void tun_close (tuntap_dev *device);


// The MAC address the edge uses: the one asked for, or a random one,
// locally administered and not multicast
static void choose_mac (tuntap_dev *device, const char *device_mac) {

    if(device_mac && device_mac[0]) {
        str2mac(device->mac_addr, device_mac);
    } else {
        memrnd(device->mac_addr, N2N_MAC_SIZE);
        device->mac_addr[0] &= ~0x01;
        device->mac_addr[0] |= 0x02;
    }
}


// Run a program (a full path) with its arguments, without a shell: 0 if it
// exited with 0, else -1 after a line in the log with the command
static int run (const char *const argv[]) {

    struct sigaction dfl, old;
    pid_t pid;
    int status = -1;
    int err;

    // the edge ignores SIGCHLD, which would take the exit status away
    memset(&dfl, 0, sizeof(dfl));
    dfl.sa_handler = SIG_DFL;
    sigemptyset(&dfl.sa_mask);
    sigaction(SIGCHLD, &dfl, &old);

    err = posix_spawn(&pid, argv[0], NULL, NULL, (char *const *)argv, environ);
    if(!err) {
        while((waitpid(pid, &status, 0) < 0) && (errno == EINTR)) {
        }
    }
    sigaction(SIGCHLD, &old, NULL);

    if(err || !WIFEXITED(status) || WEXITSTATUS(status)) {
        char line[256];
        size_t n = 0;

        line[0] = '\0';
        for(int i = 0; argv[i] && (n < sizeof(line)); i++) {
            n += snprintf(line + n, sizeof(line) - n, "%s%s", i ? " " : "", argv[i]);
        }
        traceEvent(TRACE_ERROR, "failed: %s%s%s", line, err ? ": " : "", err ? strerror(err) : "");
        return -1;
    }
    return 0;
}


// A utun device, macOS's own TUN (no driver to install, root needed): a
// kernel control socket, the interface utunN its unit.  The name utunN asks
// for that one, any other (the session's) for the next free one.  Set up as
// wg-quick does on macOS: the address on the point-to-point interface, and
// a route for the community's subnet into it.
static int open_utun (tuntap_dev *device, const char *dev,
                      struct n2n_ip_subnet v4subnet, const char *device_mac,
                      int mtu) {

    struct ctl_info info;
    struct sockaddr_ctl addr;
    socklen_t len;
    unsigned int unit;
    char rest;
    int fd;

    if(sscanf(dev, "utun%u%c", &unit, &rest) == 1) {
        unit++;
    } else {
        unit = 0;
    }

    fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if(fd < 0) {
        traceEvent(TRACE_ERROR, "utun: no control socket: %s", strerror(errno));
        return -1;
    }

    memset(&info, 0, sizeof(info));
    strlcpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name));
    if(ioctl(fd, CTLIOCGINFO, &info) < 0) {
        traceEvent(TRACE_ERROR, "utun: ioctl(CTLIOCGINFO): %s", strerror(errno));
        close(fd);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_id = info.ctl_id;
    addr.sc_unit = unit;
    if(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        traceEvent(TRACE_ERROR, "utun: cannot create %s: %s%s", unit ? dev : "a utun device",
                   strerror(errno), (errno == EPERM) ? " (needs root)" : "");
        close(fd);
        return -1;
    }

    len = sizeof(device->dev_name);
    if(getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, device->dev_name, &len) < 0) {
        traceEvent(TRACE_ERROR, "utun: no interface name: %s", strerror(errno));
        close(fd);
        return -1;
    }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    fcntl(fd, F_SETFD, FD_CLOEXEC);

    device->fd = fd;
    device->utun = true;
    device->ip_addr = v4subnet.net_addr;
    choose_mac(device, device_mac);

    // ip_addr is already in network order, bitlen2mask() is not
    in_addr_t net = v4subnet.net_addr & htonl(bitlen2mask(v4subnet.net_bitlen));
    char addr_buf[INET_ADDRSTRLEN];
    char net_buf[INET_ADDRSTRLEN];
    char cidr[INET_ADDRSTRLEN + 4];
    char net_cidr[INET_ADDRSTRLEN + 4];
    char mtu_buf[12];

    inet_ntop(AF_INET, &v4subnet.net_addr, addr_buf, sizeof(addr_buf));
    inet_ntop(AF_INET, &net, net_buf, sizeof(net_buf));
    snprintf(cidr, sizeof(cidr), "%s/%u", addr_buf, v4subnet.net_bitlen);
    snprintf(net_cidr, sizeof(net_cidr), "%s/%u", net_buf, v4subnet.net_bitlen);
    snprintf(mtu_buf, sizeof(mtu_buf), "%d", mtu);

    const char *const set_addr[] = {"/sbin/ifconfig", device->dev_name, "inet", cidr, addr_buf, "alias", NULL};
    const char *const set_mtu[] = {"/sbin/ifconfig", device->dev_name, "mtu", mtu_buf, "up", NULL};
    const char *const add_route[] = {"/sbin/route", "-q", "-n", "add", "-inet", net_cidr, "-interface", device->dev_name, NULL};

    if((run(set_addr) != 0) || (run(set_mtu) != 0) || (run(add_route) != 0)) {
        tuntap_close(device);
        return -1;
    }

    traceEvent(TRACE_NORMAL, "Interface %s up and running (%s, MTU %d)", device->dev_name, cidr, mtu);
    return fd;
}


int tuntap_open (tuntap_dev *device,
                 char *dev,
                 uint8_t address_mode, /* unused! */
                 struct n2n_ip_subnet v4subnet,
                 const char * device_mac,
                 int mtu,
                 int ignored) {

    int i;
    char tap_device[N2N_OSX_TAPDEVICE_SIZE];

    device->utun = false;
    if(device->tun) {
        return open_utun(device, dev, v4subnet, device_mac, mtu);
    }

    for(i = 0; i < 255; i++) {
        snprintf(tap_device, sizeof(tap_device), "/dev/tap%d", i);

        device->fd = open(tap_device, O_RDWR | O_NONBLOCK);
        if(device->fd > 0) {
            traceEvent(TRACE_NORMAL, "Succesfully open %s", tap_device);
            snprintf(device->dev_name, sizeof(device->dev_name), "tap%d", i);
            break;
        }
    }

    if(device->fd < 0) {
        traceEvent(TRACE_ERROR, "Unable to open any tap devices /dev/tap0 through /dev/tap254. Is this user properly authorized to access those descriptors?");
        traceEvent(TRACE_ERROR, "A TAP device needs a third-party driver on macOS: "
                   "tuntap.type = tun uses the system's own utun instead");
        return -1;
    } else {
        char buf[256];
        FILE *fd;

        device->ip_addr = v4subnet.net_addr;

        if(device_mac && device_mac[0] != '\0') {
            // FIXME - this is not tested. might be wrong syntax for OS X
            // set the hw address before bringing the if up
            snprintf(buf, sizeof(buf), "ifconfig tap%d ether %s", i, device_mac);
            system(buf);
        }

        // ip_addr is already in network order, bitlen2mask() is not
        in_addr_t addr = device->ip_addr;
        in_addr_t mask = htonl(bitlen2mask(v4subnet.net_bitlen));
        char addr_buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, &addr_buf, sizeof(addr_buf));

        snprintf(buf, sizeof(buf), "ifconfig tap%d %s netmask %s mtu %d up",
                 i,
                 addr_buf,
                 inet_ntoa(*(struct in_addr*)&mask),
                 mtu
        );
        system(buf);

        traceEvent(TRACE_NORMAL, "Interface tap%d up and running (%s/%u)", i, addr_buf, v4subnet.net_bitlen);

        // read MAC address
        snprintf(buf, sizeof(buf), "ifconfig tap%d |grep ether|cut -c 8-24", i);
        // traceEvent(TRACE_INFO, "%s", buf);

        fd = popen(buf, "r");
        if(fd < 0) {
            tuntap_close(device);
            return -1;
        } else {
            int a, b, c, d, e, f;

            buf[0] = 0;
            fgets(buf, sizeof(buf), fd);
            pclose(fd);

            if(buf[0] == '\0') {
                traceEvent(TRACE_ERROR, "Unable to read tap%d interface MAC address");
                exit(0);
            }

            traceEvent(TRACE_NORMAL, "Interface tap%d [MTU %d] mac %s", i, mtu, buf);
            if(sscanf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", &a, &b, &c, &d, &e, &f) == 6) {
                device->mac_addr[0] = a, device->mac_addr[1] = b;
                device->mac_addr[2] = c, device->mac_addr[3] = d;
                device->mac_addr[4] = e, device->mac_addr[5] = f;
            }
        }
    }

    // read_mac(dev, device->mac_addr);

    return(device->fd);
}


// A device that the program starting the edge opened and set up already
// (tuntap.fd): nothing to open or configure, only to take over.  Its packets
// come as they are, without utun's protocol family in front.
int tuntap_take_fd (tuntap_dev *device, int fd, struct n2n_ip_subnet v4subnet, const char *device_mac) {

    device->fd = fd;
    device->utun = false;
    snprintf(device->dev_name, sizeof(device->dev_name), "fd%d", fd);
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    choose_mac(device, device_mac);
    device->ip_addr = v4subnet.net_addr;
    traceEvent(TRACE_NORMAL, "using the %s device given as fd %d", device->tun ? "TUN" : "TAP", fd);
    return fd;
}


// An IPv6 address on the device, and on a utun device the route of its
// prefix, which a point-to-point interface does not get by itself
int tuntap_set_ipv6 (struct tuntap_dev *tuntap, const uint8_t addr[16], uint8_t len) {

    uint8_t prefix[16];
    char addr_buf[INET6_ADDRSTRLEN];
    char prefix_buf[INET6_ADDRSTRLEN];
    char cidr[INET6_ADDRSTRLEN + 4];
    char prefix_cidr[INET6_ADDRSTRLEN + 4];

    for(int i = 0; i < 16; i++) {
        int bits = len - 8 * i;
        prefix[i] = addr[i] & ((bits >= 8) ? 0xff : (bits <= 0) ? 0 : (uint8_t)(0xff << (8 - bits)));
    }
    inet_ntop(AF_INET6, addr, addr_buf, sizeof(addr_buf));
    inet_ntop(AF_INET6, prefix, prefix_buf, sizeof(prefix_buf));
    snprintf(cidr, sizeof(cidr), "%s/%u", addr_buf, len);
    snprintf(prefix_cidr, sizeof(prefix_cidr), "%s/%u", prefix_buf, len);

    const char *const set_addr[] = {"/sbin/ifconfig", tuntap->dev_name, "inet6", cidr, "alias", NULL};
    const char *const add_route[] = {"/sbin/route", "-q", "-n", "add", "-inet6", prefix_cidr, "-interface", tuntap->dev_name, NULL};

    if(run(set_addr) != 0) {
        return -1;
    }
    if(tuntap->utun && (run(add_route) != 0)) {
        return -1;
    }
    return 0;
}


// utun puts the protocol family (AF_INET, AF_INET6), 4 bytes in network
// order, in front of each packet
int tuntap_read (struct tuntap_dev *tuntap, unsigned char *buf, int len) {

    uint32_t family;
    struct iovec iov[2] = {
        {.iov_base = &family, .iov_len = sizeof(family)},
        {.iov_base = buf, .iov_len = len},
    };
    ssize_t n;

    if(!tuntap->utun) {
        return(read(tuntap->fd, buf, len));
    }
    n = readv(tuntap->fd, iov, 2);
    if(n < 0) {
        return -1;
    }
    return (n > (ssize_t)sizeof(family)) ? (int)(n - sizeof(family)) : 0;
}


int tuntap_write (struct tuntap_dev *tuntap, unsigned char *buf, int len) {

    uint32_t family = htonl(((len > 0) && ((buf[0] >> 4) == 6)) ? AF_INET6 : AF_INET);
    struct iovec iov[2] = {
        {.iov_base = &family, .iov_len = sizeof(family)},
        {.iov_base = buf, .iov_len = len},
    };
    ssize_t n;

    if(!tuntap->utun) {
        return(write(tuntap->fd, buf, len));
    }
    n = writev(tuntap->fd, iov, 2);
    if(n < 0) {
        return -1;
    }
    return (n > (ssize_t)sizeof(family)) ? (int)(n - sizeof(family)) : 0;
}


void tuntap_close (struct tuntap_dev *tuntap) {

    close(tuntap->fd);
}

// fill out the ip_addr value from the interface, called to pick up dynamic address changes
void tuntap_get_address (struct tuntap_dev *tuntap) {

    // no action
}


#endif /* __APPLE__ */
