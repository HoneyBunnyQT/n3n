/*
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Reading the configuration again while running, see reload.h.
 *
 * The program loads its configuration anew, all the way as at its start
 * (defaults, file, environment, command line).  Both are dumped as text,
 * as "n3n-edge debug config load_dump" does, and compared option by
 * option: what differs from the start and can change while running is set
 * on the running configuration, the rest is reported as waiting for a
 * restart.  The comparison is with what runs: the start, then what each
 * reload applied - so what waits for a restart is reported again by the
 * next reload, and a value set back is set back.
 */

#include <n3n/conffile.h>       // for n3n_config_dump, n3n_config_set_option
#include <n3n/edge.h>           // for supernode_first
#include <n3n/logging.h>        // for traceEvent
#include <n3n/resolve.h>        // for RESOLVE_LIST_SUPERNODE, resolve_hostnames_str_add
#include <signal.h>             // for sig_atomic_t
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>             // for clock_gettime

#include "connslot/strbuf.h"
#include "edge_utils.h"         // for edge_netwatch_update
#include "n2n.h"
#include "notify.h"             // for n3n_notify
#include "peer_info.h"
#include "reload.h"
#include "resolve.h"            // for resolve_cancel_thread, resolve_hostname_str_to_peer_info
#include "role_client.h"        // for edge_supernodes_changed
#include "uthash.h"


static struct n3n_runtime_data *reload_rt;
static n3n_reload_load_fn reload_load;
static char *baseline;                  // what runs: a dump, later "key=value" lines
static volatile sig_atomic_t requested;


// What can change while running: set on the running configuration by its
// option, some with more to do, see apply()
static const char *const live_options[] = {
    "community.supernode",
    "connection.allow_p2p",
    "connection.description",
    "connection.local_discovery",
    "connection.punch_ports",
    "connection.punch_ttl",
    "connection.register_interval",
    "connection.register_pkt_ttl",
    "connection.supernode_selection",
    "connection.tcp_fallback",
    "connection.watch_network",
    "filter.allow_multicast",
    "filter.allow_routing",
    "logging.verbose",
    "management.password",
    NULL
};


// The dump of a configuration, as a string to free
static char *conf_dump (const void *conf) {

    FILE *f = tmpfile();
    char *buf;
    long len;

    if(!f) {
        return NULL;
    }
    n3n_config_dump((void *)conf, f, 1);
    len = ftell(f);
    buf = (len >= 0) ? malloc(len + 1) : NULL;
    if(buf) {
        rewind(f);
        len = (long)fread(buf, 1, len, f);
        buf[len] = 0;
    }
    fclose(f);
    return buf;
}


// "section.option=value" of a dump, an option given several times
// (community.supernode) once for each
struct setting {
    char key[96];
    const char *value;
};

static int setting_cmp (const void *a, const void *b) {

    const struct setting *x = a, *y = b;
    int r = strcmp(x->key, y->key);

    return r ? r : strcmp(x->value, y->value);
}

// The settings of a dump (which it changes), sorted; *count of them
static struct setting *settings_of (char *dump, int *count) {

    struct setting *list = NULL;
    char section[64] = "";
    int n = 0, size = 0;

    for(char *line = strtok(dump, "\n"); line; line = strtok(NULL, "\n")) {
        char *eq;

        if(line[0] == '[') {
            char *end = strchr(line, ']');
            if(end) {
                *end = 0;
                snprintf(section, sizeof(section), "%s", line + 1);
            }
            continue;
        }
        if((line[0] == '#') || !(eq = strchr(line, '='))) {
            continue;
        }
        if(n == size) {
            struct setting *more = realloc(list, (size = size ? 2 * size : 64) * sizeof(*list));
            if(!more) {
                break;
            }
            list = more;
        }
        *eq = 0;
        // outside a section, the key is a whole one
        snprintf(list[n].key, sizeof(list[n].key), "%s%s%s", section, section[0] ? "." : "", line);
        list[n].value = eq + 1;
        n++;
    }
    if(list) {
        qsort(list, n, sizeof(*list), setting_cmp);
    }
    *count = n;
    return list;
}

// Whether the values of key differ between the two sorted lists, from
// a[*i] and b[*j] on; moves both past key
static bool key_differs (const char *key, const struct setting *a, int na, int *i,
                         const struct setting *b, int nb, int *j) {

    bool differs = false;

    while((*i < na) && !strcmp(a[*i].key, key) && (*j < nb) && !strcmp(b[*j].key, key)) {
        differs |= strcmp(a[*i].value, b[*j].value) != 0;
        (*i)++;
        (*j)++;
    }
    while((*i < na) && !strcmp(a[*i].key, key)) {
        differs = true;
        (*i)++;
    }
    while((*j < nb) && !strcmp(b[*j].key, key)) {
        differs = true;
        (*j)++;
    }
    return differs;
}


// The settings from..to of a list, as "key=value" lines added to *buf
static void add_lines (char **buf, size_t *len, const struct setting *s, int from, int to) {

    for(int k = from; k < to; k++) {
        size_t more = strlen(s[k].key) + strlen(s[k].value) + 2;
        char *bigger = realloc(*buf, *len + more + 1);
        if(!bigger) {
            return;
        }
        *buf = bigger;
        *len += sprintf(*buf + *len, "%s=%s\n", s[k].key, s[k].value);
    }
}


static bool is_live (const char *key) {

    for(int i = 0; live_options[i]; i++) {
        if(!strcmp(live_options[i], key)) {
            return true;
        }
    }
    return false;
}


// Whether s is one of the supernodes given now
static bool sn_given (const char *s) {

    const char *given;

    for(int i = 0; s && (given = resolve_hostnames_str_get(RESOLVE_LIST_SUPERNODE, i)); i++) {
        if(!strcmp(given, s)) {
            return true;
        }
    }
    return false;
}

// Whether the edge has the supernode named s already
static bool sn_known (struct n3n_runtime_data *rt, const char *s) {

    struct peer_info *sn, *tmp;

    HASH_ITER(hh, rt->client.supernodes, sn, tmp) {
        if((sn->hostname && !strcmp(sn->hostname, s)) || (sn->tcp_hostname && !strcmp(sn->tcp_hostname, s))) {
            return true;
        }
    }
    return false;
}

// The edge's supernodes as given now: the ones given no more go (not those
// learned from the federation), new ones come.  The resolver thread keeps
// pointers into the entries, so it starts anew.
static void apply_supernodes (struct n3n_runtime_data *rt) {

    struct peer_info *sn, *tmp;
    bool curr_gone = false;
    const char *s;

    resolve_cancel_thread(rt->resolve_parameter);
    rt->resolve_parameter = NULL;

    HASH_ITER(hh, rt->client.supernodes, sn, tmp) {
        if(sn->purgeable || sn_given(sn->hostname) || sn_given(sn->tcp_hostname)) {
            continue;
        }
        traceEvent(TRACE_NORMAL, "reload: supernode %s given no more", peer_info_get_hostname(sn));
        HASH_DEL(rt->client.supernodes, sn);
        if(sn == rt->client.curr_sn) {
            rt->client.curr_sn = NULL;
            curr_gone = true;
        }
        peer_info_free(sn);
    }
    for(int i = 0; (s = resolve_hostnames_str_get(RESOLVE_LIST_SUPERNODE, i)); i++) {
        if(!sn_known(rt, s)) {
            traceEvent(TRACE_NORMAL, "reload: supernode %s given now", s);
            resolve_hostname_str_to_peer_info(&rt->client.supernodes, s);
        }
    }

    if(resolve_create_thread(&rt->resolve_parameter, rt->client.supernodes) != 0) {
        rt->resolve_parameter = NULL;
    }
    edge_supernodes_changed(rt, curr_gone);
}


// A supernode's communities: the [community NAME] sections, the community
// file and community_regex, which reload_communities() reads anew
static bool is_relay_community (const struct n3n_runtime_data *rt, const char *key) {

    return rt->conf.is_supernode
           && (!strncmp(key, "community ", strlen("community "))
               || !strcmp(key, "supernode.community_file")
               || !strcmp(key, "supernode.community_regex"));
}


// Sets key (a live one) as new has it, more where there is more to do;
// false if it cannot change after all
static bool apply (struct n3n_runtime_data *rt, const char *key, const struct setting *new, int nnew,
                   n2n_edge_conf_t *conf) {

    bool edge = rt->conf.is_edge && !rt->conf.client.local_link;
    char section[sizeof(new->key)], *option;
    const char *value = NULL;

    if(is_relay_community(rt, key)) {
        // all three from the new configuration, which keeps its strings
        rt->conf.communities = conf->communities;
        rt->conf.relay.community_file = conf->relay.community_file;
        rt->conf.relay.community_regex = conf->relay.community_regex;
        return true;
    }

    if(!strcmp(key, "community.supernode")) {
        // a supernode's federation is set up at its start; an edge needs one
        if(!edge || !resolve_hostnames_str_get(RESOLVE_LIST_SUPERNODE, 0)) {
            return false;
        }
        apply_supernodes(rt);
        return true;
    }
    // with user/password authentication, the description is the user name
    if(!strcmp(key, "connection.description") && rt->conf.shared_secret) {
        return false;
    }

    for(int i = 0; i < nnew; i++) {
        if(!strcmp(new[i].key, key)) {
            value = new[i].value;
            break;
        }
    }
    snprintf(section, sizeof(section), "%s", key);
    option = strchr(section, '.');
    if(!value || !option) {
        return false;
    }
    *option++ = 0;
    if(n3n_config_set_option(&rt->conf, section, option, (char *)value) != 0) {
        return false;
    }

    if(!strcmp(key, "connection.watch_network") && edge) {
        edge_netwatch_update(rt);
    }
    return true;
}


// The strings of a hostname list, to put back if loading fails
static char **list_save (int listnr, int *count) {

    char **v = NULL;
    const char *s;
    int n = 0;

    while(resolve_hostnames_str_get(listnr, n)) {
        n++;
    }
    v = calloc(n + 1, sizeof(*v));
    for(int i = 0; v && (s = resolve_hostnames_str_get(listnr, i)); i++) {
        v[i] = strdup(s);
    }
    *count = n;
    return v;
}

static void list_restore (int listnr, char **v, int n, bool put_back) {

    if(put_back) {
        resolve_hostnames_free(listnr);
        // each one goes in front
        for(int i = n - 1; v && (i >= 0); i--) {
            if(v[i]) {
                resolve_hostnames_str_add(listnr, v[i]);
            }
        }
    }
    for(int i = 0; v && (i < n); i++) {
        free(v[i]);
    }
    free(v);
}


static void json_list (struct strbuf **out, const char *name, const char *const *keys, int n) {

    sb_reprintf(out, "\"%s\":[", name);
    for(int i = 0; i < n; i++) {
        sb_reprintf(out, "%s\"%s\"", i ? "," : "", keys[i]);
    }
    sb_reprintf(out, "]");
}

static void log_list (const char *what, const char *const *keys, int n) {

    char buf[512];
    int at = 0;

    buf[0] = 0;
    for(int i = 0; (i < n) && (at < (int)sizeof(buf)); i++) {
        at += snprintf(buf + at, sizeof(buf) - at, "%s%s", i ? ", " : "", keys[i]);
    }
    traceEvent(TRACE_NORMAL, "reload: %s: %s", what, buf);
}


int n3n_reload (struct strbuf **out) {

    struct n3n_runtime_data *rt = reload_rt;
    n2n_edge_conf_t *conf;
    char **sn_saved, **peer_saved;
    int sn_count, peer_count, nold = 0, nnew = 0, i = 0, j = 0;
    struct setting *old = NULL, *new = NULL;
    const char **applied = NULL, **restart = NULL;
    int napplied = 0, nrestart = 0;
    char *old_dump = NULL, *new_dump;
    char *running = NULL;               // the next baseline
    size_t running_len = 0;
    const char *error = NULL;

    if(!rt || !reload_load || !baseline) {
        error = "not set up to reload";
        goto done;
    }
    traceEvent(TRACE_NORMAL, "reloading the configuration");
    {
        // systemd waits for READY=1 again; since 253 it wants the time too
        struct timespec ts;
        char msg[64];
        clock_gettime(CLOCK_MONOTONIC, &ts);
        snprintf(msg, sizeof(msg), "RELOADING=1\nMONOTONIC_USEC=%llu",
                 (unsigned long long)ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000);
        n3n_notify(msg);
    }

    // the lists of names are kept outside the configuration: emptied for
    // the new one, back as they were if it cannot be loaded
    sn_saved = list_save(RESOLVE_LIST_SUPERNODE, &sn_count);
    peer_saved = list_save(RESOLVE_LIST_PEER, &peer_count);
    resolve_hostnames_free(RESOLVE_LIST_SUPERNODE);
    resolve_hostnames_free(RESOLVE_LIST_PEER);

    conf = calloc(1, sizeof(*conf));
    if(!conf || (reload_load(conf) != 0) || !(new_dump = conf_dump(conf))) {
        list_restore(RESOLVE_LIST_SUPERNODE, sn_saved, sn_count, true);
        list_restore(RESOLVE_LIST_PEER, peer_saved, peer_count, true);
        free(conf);
        error = "the configuration could not be loaded, nothing changed";
        n3n_notify("READY=1");
        goto done;
    }
    // the new supernode list stays, the federation's peers do not change
    list_restore(RESOLVE_LIST_SUPERNODE, sn_saved, sn_count, false);
    list_restore(RESOLVE_LIST_PEER, peer_saved, peer_count, true);

    old_dump = strdup(baseline);
    old = old_dump ? settings_of(old_dump, &nold) : NULL;
    new = settings_of(new_dump, &nnew);
    applied = calloc(nold + nnew + 1, sizeof(*applied));
    restart = calloc(nold + nnew + 1, sizeof(*restart));

    while(applied && restart && ((i < nold) || (j < nnew))) {
        const char *key;
        int cmp = (i == nold) ? 1 : (j == nnew) ? -1 : strcmp(old[i].key, new[j].key);
        int i0 = i, j0 = j;

        key = (cmp <= 0) ? old[i].key : new[j].key;
        if(!key_differs(key, old, nold, &i, new, nnew, &j)) {
            add_lines(&running, &running_len, new, j0, j);
            continue;
        }
        if((is_live(key) || is_relay_community(rt, key)) && apply(rt, key, new, nnew, conf)) {
            applied[napplied++] = key;
            add_lines(&running, &running_len, new, j0, j);
        } else {
            // runs as it was until a restart
            restart[nrestart++] = key;
            add_lines(&running, &running_len, old, i0, i);
        }
    }
    if(running) {
        free(baseline);
        baseline = running;
    }

    // a supernode's communities are in a file of their own: read again
    if(rt->ops && rt->ops->reload_communities) {
        rt->ops->reload_communities(rt);
    }

    if(napplied) {
        log_list("applied", applied, napplied);
    }
    if(nrestart) {
        log_list("needs a restart", restart, nrestart);
    }
    if(!napplied && !nrestart) {
        traceEvent(TRACE_NORMAL, "reload: no change");
    }
    n3n_notify("READY=1");

    if(out) {
        sb_reprintf(out, "{\"loaded\":true,");
        json_list(out, "applied", applied, napplied);
        sb_reprintf(out, ",");
        json_list(out, "restart", restart, nrestart);
        sb_reprintf(out, "}");
    }
    // the strings of the new configuration stay with the running one
    free(applied);
    free(restart);
    free(old);
    free(new);
    free(old_dump);
    free(new_dump);
    free(conf);
    return 0;

done:
    traceEvent(TRACE_WARNING, "reload: %s", error);
    if(out) {
        sb_reprintf(out, "{\"loaded\":false,\"error\":\"%s\"}", error);
    }
    return -1;
}


void n3n_reload_setup (struct n3n_runtime_data *rt, const void *conf, n3n_reload_load_fn load) {

    reload_rt = rt;
    reload_load = load;
    free(baseline);
    baseline = conf_dump(conf);
}


void n3n_reload_request (void) {

    requested = 1;
}


void n3n_reload_pending (void) {

    if(requested) {
        requested = 0;
        n3n_reload(NULL);
    }
}
