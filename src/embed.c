/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * An edge inside another program, see n3n/embed.h: what apps/n3n-edge.c
 * does as a daemon, without the parts a daemon needs and an app does not -
 * no command line, no config file to look for, no forking, no dropping of
 * privileges, no device to create, no PINGs before the main loop (it finds
 * the supernodes itself) - and with the TUN device the app gives.
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
#include "n2n.h"                // for edge_init, edge_tap_open, run_edge_loop, n3n_set_socket_hook
#include "n2n_typedefs.h"

#ifdef __linux__

#include <unistd.h>             // for pipe, write, getuid


static bool initialised;
static bool keep_running;
static int wake_pipe[2] = {-1, -1};


int n3n_edge_run (const char *config, int tun_fd, const struct n3n_embed *e) {

    static char session[64];
    n2n_edge_conf_t conf;
    struct n3n_runtime_data *eee;
    int rc;

    if(!config || (tun_fd <= 0)) {
        return -1;
    }

    if(e && e->log) {
        setTraceCallback(e->log, e->ctx);
    }
    n3n_set_socket_hook(e ? e->protect : NULL, e ? e->ctx : NULL);
    n3n_config_set_rundir(e ? e->rundir : NULL);

    // the sections of the configuration, the metrics: once a process
    if(!initialised) {
        n3n_initfuncs();
        initialised = true;
    }

    snprintf(session, sizeof(session), "%s", (e && e->session) ? e->session : "edge");
    edge_init_conf_defaults(&conf, session);
    if(n3n_config_load_text(&conf, config) != 0) {
        traceEvent(TRACE_ERROR, "embed: the configuration cannot be read");
        return -2;
    }

    // the app's device, and the app's own user: nothing to drop to
    conf.tap.type = N3N_TUNTAP_TUN;
    conf.tap.fd = tun_fd;
    conf.userid = getuid();
    conf.groupid = getgid();

    if(conf.tap.tuntap_ip_mode != TUNTAP_IP_MODE_STATIC) {
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
    __atomic_store_n(&keep_running, true, __ATOMIC_SEQ_CST);
    eee->keep_running = &keep_running;

    // n3n_edge_stop() wakes the main loop through this, see mainloop.c
    if(pipe(wake_pipe) == 0) {
        mainloop_register_fd(wake_pipe[0], fd_info_proto_wakeup);
    }

    if(edge_tap_open(eee) < 0) {
        traceEvent(TRACE_ERROR, "embed: the TUN device cannot be used");
        rc = -5;
        goto out;
    }
    mainloop_register_fd(eee->tap.device.fd, fd_info_proto_tuntap);

    eee->client.curr_sn = supernode_first(eee);
    supernode_connect(eee);

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

#else

int n3n_edge_run (const char *config, int tun_fd, const struct n3n_embed *e) {
    return -1;
}

void n3n_edge_stop (void) {
}

#endif
