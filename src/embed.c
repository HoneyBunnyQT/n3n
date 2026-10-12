/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * An edge inside another program, see n3n/embed.h: what apps/n3n-edge.c
 * does as a daemon, without the parts a daemon needs and an app does not -
 * no command line, no config file to look for, no forking, no dropping of
 * privileges, no device to create, no PINGs before the main loop (it finds
 * the supernodes itself) - and with the TUN device the app gives: at the
 * start, or when the edge asks for it (n3n_embed.device), with the address
 * that a supernode handed out.
 */

#include <n3n/conffile.h>       // for n3n_config_load_text, n3n_config_set_rundir
#include <n3n/edge.h>           // for edge_init_conf_defaults, supernode_first
#include <n3n/embed.h>
#include <n3n/initfuncs.h>      // for n3n_initfuncs
#include <n3n/logging.h>        // for traceEvent, setTraceCallback
#include <n3n/mainloop.h>       // for mainloop_register_fd
#include <stdbool.h>
#include <stdio.h>              // for snprintf
#include <stdlib.h>             // for free
#include <string.h>
#include <time.h>               // for time
#include "n2n.h"                // for edge_init, edge_tap_open, run_edge_loop, n3n_set_socket_hook
#include "n2n_typedefs.h"
#include "netwatch.h"           // for NETWATCH_EXTERNAL
#include "peer_info.h"          // for peer_info_get_hostname
#include "role_client.h"        // for edge_network_change

#ifdef __linux__

#include <arpa/inet.h>          // for inet_ntop
#include <unistd.h>             // for pipe, write, getuid


static bool keep_running;
static int wake_pipe[2] = {-1, -1};


// An address from a supernode (address_mode auto), as the edge's bootstrap
// in apps/n3n-edge.c gets it before there is a device: REGISTER_SUPER
// without a MAC yet, the next supernode after a while without an answer,
// until one hands out an address - or the edge is stopped.  0 for one.
static int address_from_supernode (struct n3n_runtime_data *eee) {

    time_t asked = 0;

    eee->client.curr_sn = supernode_first(eee);
    supernode_connect(eee);
    while(__atomic_load_n(&keep_running, __ATOMIC_SEQ_CST)) {
        time_t now = time(NULL);

        if(eee->conf.tap.tuntap_v4.net_addr) {
            return 0;
        }
        if(!asked || (now - asked >= BOOTSTRAP_TIMEOUT)) {
            if(asked) {
                // no answer, or one without an address: the next one
                traceEvent(TRACE_NORMAL, "embed: no address from supernode %s, trying the next",
                           peer_info_get_hostname(eee->client.curr_sn));
                eee->client.curr_sn = supernode_next(eee, eee->client.curr_sn);
                supernode_connect(eee);
            }
            eee->client.sn_wait = 1;
            send_register_super(eee);
            asked = now;
        }
        mainloop_runonce(eee);
    }
    return -1;
}


int n3n_edge_run (const char *config, int tun_fd, const struct n3n_embed *e) {

    static char session[64];
    n2n_edge_conf_t conf;
    struct n3n_runtime_data *eee;
    int rc;

    if(!config || ((tun_fd <= 0) && !(e && e->device))) {
        return -1;
    }

    // from here on, n3n_edge_stop() ends this run: also while it is still
    // starting, before the main loop looks at the flag
    __atomic_store_n(&keep_running, true, __ATOMIC_SEQ_CST);

    if(e && e->log) {
        setTraceCallback(e->log, e->ctx);
    }
    n3n_set_socket_hook(e ? e->protect : NULL, e ? e->ctx : NULL);
    n3n_config_set_rundir(e ? e->rundir : NULL);

    // the process-global registries (config sections, metrics, ...):
    // edge_term() tears them down at the end of each run, so set them up
    // again here.  The registries skip what is already present, so a run
    // that returned early (before edge_term) does not double-register.
    n3n_initfuncs();

    snprintf(session, sizeof(session), "%s", (e && e->session) ? e->session : "edge");
    edge_init_conf_defaults(&conf, session);
    if(n3n_config_load_text(&conf, config) != 0) {
        traceEvent(TRACE_ERROR, "embed: the configuration cannot be read");
        return -2;
    }

    // the app's device, and the app's own user: nothing to drop to
    conf.tap.type = N3N_TUNTAP_TUN;
    conf.tap.fd = (tun_fd > 0) ? tun_fd : 0;
    conf.userid = getuid();
    conf.groupid = getgid();

    // the device has its address: the one given is static; without one,
    // the app's device comes once a supernode has handed one out
    if(conf.tap.tuntap_v4.net_addr) {
        conf.tap.tuntap_ip_mode = TUNTAP_IP_MODE_STATIC;
    } else if(tun_fd <= 0) {
        conf.tap.tuntap_ip_mode = TUNTAP_IP_MODE_SN_ASSIGN;
    }
    if(conf.tap.tuntap_ip_mode != TUNTAP_IP_MODE_STATIC && conf.tap.tuntap_ip_mode != TUNTAP_IP_MODE_SN_ASSIGN) {
        traceEvent(TRACE_ERROR, "embed: tuntap.address_mode is static or auto here");
        return -3;
    }
    if((tun_fd > 0) && (conf.tap.tuntap_ip_mode != TUNTAP_IP_MODE_STATIC)) {
        traceEvent(TRACE_ERROR, "embed: the device is set up already, so tuntap.address has to be given");
        return -3;
    }
    if(edge_conf_one_community(&conf) != 0) {
        return -3;
    }
    edge_conf_prepare(&conf);
    if(edge_verify_conf(&conf) != 0) {
        traceEvent(TRACE_ERROR, "embed: the configuration is incomplete");
        return -3;
    }

    traceEvent(TRACE_NORMAL, "starting n3n edge %s %s, embedded", VERSION, BUILDDATE);

    eee = edge_init(&conf, &rc);
    if(!eee) {
        traceEvent(TRACE_ERROR, "embed: edge_init failed");
        return -4;
    }
    eee->keep_running = &keep_running;

    // n3n_edge_stop() wakes the main loop through this, see mainloop.c
    if(pipe(wake_pipe) == 0) {
        mainloop_register_fd(wake_pipe[0], fd_info_proto_wakeup);
    }

    if(!eee->conf.tap.fd) {
        // the device from the app: with the address given, or with one that
        // a supernode hands out first
        char buf[INET_ADDRSTRLEN];

        eee->tap.device.fd = -1;
        if((eee->conf.tap.tuntap_ip_mode == TUNTAP_IP_MODE_SN_ASSIGN) && (address_from_supernode(eee) != 0)) {
            // stopped before there was one
            rc = 0;
            goto out;
        }
        inet_ntop(AF_INET, &eee->conf.tap.tuntap_v4.net_addr, buf, sizeof(buf));
        traceEvent(TRACE_NORMAL, "embed: the device for %s/%u", buf, eee->conf.tap.tuntap_v4.net_bitlen);
        int fd = e->device(e->ctx, buf, eee->conf.tap.tuntap_v4.net_bitlen);
        if(fd <= 0) {
            traceEvent(TRACE_ERROR, "embed: no device from the app");
            rc = -5;
            goto out;
        }
        eee->conf.tap.fd = fd;
    }

    if(edge_tap_open(eee) < 0) {
        traceEvent(TRACE_ERROR, "embed: the TUN device cannot be used");
        rc = -5;
        goto out;
    }
    mainloop_register_fd(eee->tap.device.fd, fd_info_proto_tuntap);

    // as the edge does after its bootstrap: on with the supernode that
    // answered, else from the first - and registered at once, now with the
    // device's MAC (the bootstrap's REGISTER_SUPER had none)
    if(eee->conf.tap.tuntap_ip_mode != TUNTAP_IP_MODE_SN_ASSIGN) {
        eee->client.curr_sn = supernode_first(eee);
    }
    supernode_connect(eee);
    eee->client.sn_wait = 1;
    eee->client.last_register_req = 0;

    rc = run_edge_loop(eee);
    tuntap_close(&eee->tap.device);

out:
    if(wake_pipe[0] >= 0) {
        mainloop_unregister_fd(wake_pipe[0]);
        close(wake_pipe[0]);
        close(wake_pipe[1]);
        wake_pipe[0] = wake_pipe[1] = -1;
    }
    edge_term(eee);
    free(conf.bind_address);

    traceEvent(TRACE_NORMAL, "embedded edge stopped");
    n3n_set_socket_hook(NULL, NULL);
    setTraceCallback(NULL, NULL);
    return rc;
}


void n3n_edge_stop (void) {

    __atomic_store_n(&keep_running, false, __ATOMIC_SEQ_CST);
    if(wake_pipe[1] >= 0) {
        ssize_t r = write(wake_pipe[1], "x", 1);
        (void)r;
    }
}

void n3n_edge_network_changed (void) {

    edge_network_change(NETWATCH_EXTERNAL);
    // the main loop acts on it with its next round, see edge_tick_network()
    if(wake_pipe[1] >= 0) {
        ssize_t r = write(wake_pipe[1], "x", 1);
        (void)r;
    }
}

#else

int n3n_edge_run (const char *config, int tun_fd, const struct n3n_embed *e) {
    return -1;
}

void n3n_edge_stop (void) {
}

void n3n_edge_network_changed (void) {
}

#endif
