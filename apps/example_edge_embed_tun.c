/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * An edge inside a program of its own, as the Android app runs it (see
 * n3n/embed.h): the program opens and sets up the TUN device - as Android's
 * VpnService does for the app - and hands it over with the configuration as
 * text; it sees every socket the edge opens, and stops the edge from
 * another thread.
 *
 * usage: example_edge_embed_tun CONFIG_FILE ADDRESS/BITS [SECONDS]
 *
 * The configuration needs tuntap.address = ADDRESS/BITS.  Needs root (for
 * the device), Linux.
 */

#include <stdio.h>
#include <stdlib.h>

#ifdef __linux__

#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <pthread.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <n3n/embed.h>

static int protected_count;
static int seconds = 30;


static bool protect (void *ctx, int fd) {

    struct stat st;

    // what VpnService.protect() is given: a socket
    if((fstat(fd, &st) != 0) || !S_ISSOCK(st.st_mode)) {
        fprintf(stderr, "protect: fd %d is no socket\n", fd);
        return false;
    }
    protected_count++;
    printf("protect: socket %d\n", fd);
    return true;
}


static void log_line (void *ctx, int level, const char *line) {

    printf("log %d: %s\n", level, line);
}


static void *stopper (void *arg) {

    sleep(seconds);
    printf("stopping\n");
    n3n_edge_stop();
    return NULL;
}


static int open_tun (const char *name, const char *address) {

    struct ifreq ifr;
    char cmd[256];
    int fd = open("/dev/net/tun", O_RDWR);

    if(fd < 0) {
        perror("/dev/net/tun");
        return -1;
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);
    if(ioctl(fd, TUNSETIFF, &ifr) < 0) {
        perror("TUNSETIFF");
        close(fd);
        return -1;
    }
    // what VpnService.Builder does: address, MTU, up
    snprintf(cmd, sizeof(cmd), "ip addr add %s dev %s && ip link set %s mtu 1290 up", address, name, name);
    if(system(cmd) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}


int main (int argc, char *argv[]) {

    struct n3n_embed e = {
        .protect = protect,
        .log = log_line,
        .rundir = "/tmp/n3n-embed",
        .session = "embedtest",
    };
    pthread_t thread;
    char *config;
    long size;
    FILE *f;
    int fd;
    int rc;

    if(argc < 3) {
        fprintf(stderr, "usage: %s CONFIG_FILE ADDRESS/BITS [SECONDS]\n", argv[0]);
        return 2;
    }
    if(argc > 3) {
        seconds = atoi(argv[3]);
    }

    f = fopen(argv[1], "r");
    if(!f) {
        perror(argv[1]);
        return 2;
    }
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    rewind(f);
    config = calloc(1, size + 1);
    if(!config || (fread(config, 1, size, f) != (size_t)size)) {
        return 2;
    }
    fclose(f);

    fd = open_tun("embtun0", argv[2]);
    if(fd < 0) {
        return 1;
    }

    pthread_create(&thread, NULL, stopper, NULL);
    rc = n3n_edge_run(config, fd, &e);
    pthread_join(thread, NULL);

    printf("n3n_edge_run returned %d, %d sockets protected\n", rc, protected_count);
    free(config);
    return rc ? 1 : 0;
}

#else

int main () {
    fprintf(stderr, "only on Linux\n");
    return 1;
}

#endif
