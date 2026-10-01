/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The management page: one HTML page for whatever runs in this process - an
 * edge, a supernode, or a supernode with an edge of its own
 * (supernode.tap) - with a section for each.  It is complete as the
 * daemon sends it, so it reads in lynx or curl as well; a stylesheet and a
 * few lines of script that refresh it come along for browsers that take
 * them.  Everything from other peers (names, descriptions, versions) goes
 * through html_text().
 */

#include <connslot/strbuf.h>    // for strbuf_t, sb_reprintf
#include <n3n/ethernet.h>       // for macaddr_str, is_null_mac
#include <n3n/logging.h>        // for getTraceLevel
#include <n3n/strings.h>        // for sock_to_cstr, ip_subnet_to_str
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>              // for snprintf
#include <string.h>
#include <time.h>
#include "counter.h"            // for SHARED_LOAD
#include "management_page.h"
#include "n2n.h"
#include "n2n_typedefs.h"
#include "natclass.h"           // for nat_view_str, nat_hint_str
#include "peer_info.h"
#include "stats.h"              // for n3n_stats_sum
#include "uthash.h"

#ifdef _WIN32
#include "win32/defs.h"
#else
#include <arpa/inet.h>          // for inet_ntop
#endif

// Rows of a table at most; the JSON API has them all
#define PAGE_ROWS_MAX 250


static const char page_style[] =
    ":root{--bg:#f6f7f9;--fg:#1d2330;--card:#fff;--line:#dde1e7;--dim:#667085;"
    "--ok:#1a7f37;--warn:#9a6700;--info:#0969da;--bad:#cf222e}"
    "@media(prefers-color-scheme:dark){:root{--bg:#0f1218;--fg:#e6e9ef;"
    "--card:#181c24;--line:#2b313c;--dim:#9aa3b2;--ok:#3fb950;--warn:#d29922;"
    "--info:#58a6ff;--bad:#f85149}}"
    "body{margin:0;background:var(--bg);color:var(--fg);"
    "font:15px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}"
    "header,main{max-width:72rem;margin:auto;padding:0 1rem}"
    "header{display:flex;flex-wrap:wrap;gap:.5rem 1.5rem;align-items:center;"
    "padding-top:1rem}"
    "h1{font-size:1.4rem;margin:0}h1 small{color:var(--dim);font-weight:400}"
    "h2{font-size:1.15rem;margin:0 0 .6rem}h3{font-size:1rem;margin:1rem 0 .4rem}"
    "section,details{background:var(--card);border:1px solid var(--line);"
    "border-radius:.6rem;padding:1rem;margin:1rem 0}"
    "dl{display:grid;grid-template-columns:max-content 1fr;gap:.2rem 1rem;margin:0}"
    "dt{color:var(--dim)}dd{margin:0}"
    ".scroll{overflow-x:auto}"
    "table{border-collapse:collapse;width:100%;font-size:.9rem}"
    "th,td{text-align:left;padding:.3rem .6rem;border-bottom:1px solid var(--line);"
    "white-space:nowrap}th{color:var(--dim);font-weight:500}"
    "td.num,th.num{text-align:right}"
    "code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;"
    "font-size:.85rem}"
    ".b{display:inline-block;padding:0 .45rem;border-radius:1rem;font-size:.8rem;"
    "border:1px solid currentColor}"
    ".ok{color:var(--ok)}.warn{color:var(--warn)}.info{color:var(--info)}"
    ".bad{color:var(--bad)}.dim{color:var(--dim)}"
    "form{display:flex;gap:.4rem;flex-wrap:wrap;margin:0}"
    "button{font:inherit;padding:.25rem .7rem;border-radius:.4rem;cursor:pointer;"
    "border:1px solid var(--line);background:var(--card);color:var(--fg)}"
    "button.bad{border-color:var(--bad)}"
    "nav{margin-left:auto;color:var(--dim)}a{color:var(--info)}";

// Refresh the page in place every few seconds, keeping open what is open
static const char page_script[] =
    "setInterval(function(){"
    "if(document.hidden||!window.fetch||!window.DOMParser)return;"
    "fetch(location.pathname).then(function(r){return r.text()}).then(function(t){"
    "var n=new DOMParser().parseFromString(t,'text/html').querySelector('main'),"
    "o=document.querySelector('main');if(!n||!o)return;"
    "o.querySelectorAll('details[open]').forEach(function(d){"
    "var e=n.querySelector('#'+d.id);if(e)e.open=true});"
    "o.replaceWith(n)})},5000);";


// Text as HTML, up to its end or max bytes: markup characters escaped, bytes
// that are no UTF-8 replaced by U+FFFD
static void html_text (strbuf_t **b, const void *s, size_t max) {

    const uint8_t *p = s;
    size_t i = 0;

    while((i < max) && p[i]) {
        uint8_t c = p[i];
        int n = 0;

        switch(c) {
            case '&': sb_reprintf(b, "&amp;"); i++; continue;
            case '<': sb_reprintf(b, "&lt;"); i++; continue;
            case '>': sb_reprintf(b, "&gt;"); i++; continue;
            case '"': sb_reprintf(b, "&quot;"); i++; continue;
            case '\'': sb_reprintf(b, "&#39;"); i++; continue;
        }
        if(c < 0x80) {
            // control characters show as the replacement character too
            if((c < 0x20) || (c == 0x7f)) {
                sb_reprintf(b, "\xef\xbf\xbd");
            } else {
                sb_reprintf(b, "%c", c);
            }
            i++;
            continue;
        }
        if((c >= 0xc2) && (c <= 0xdf)) {
            n = 1;
        } else if((c & 0xf0) == 0xe0) {
            n = 2;
        } else if((c >= 0xf0) && (c <= 0xf4)) {
            n = 3;
        }
        bool ok = (n > 0) && (i + n < max);
        for(int k = 1; ok && (k <= n); k++) {
            ok = (p[i + k] & 0xc0) == 0x80;
        }
        if(!ok) {
            sb_reprintf(b, "\xef\xbf\xbd");
            i++;
            continue;
        }
        sb_reprintf(b, "%.*s", n + 1, (const char *)&p[i]);
        i += n + 1;
    }
}


// "12 s ago", "3 min ago" ... or "-" for never
static const char *ago (char *buf, size_t size, time_t now, time_t then) {

    time_t d = now - then;

    if(!then) {
        snprintf(buf, size, "-");
    } else if(d < 120) {
        snprintf(buf, size, "%d s ago", (int)((d < 0) ? 0 : d));
    } else if(d < 7200) {
        snprintf(buf, size, "%d min ago", (int)(d / 60));
    } else if(d < 172800) {
        snprintf(buf, size, "%d h ago", (int)(d / 3600));
    } else {
        snprintf(buf, size, "%d days ago", (int)(d / 86400));
    }
    return buf;
}


// How long ago a start time was, as "3 h 12 min"
static const char *uptime (char *buf, size_t size, time_t now, time_t start) {

    time_t d = start ? (now - start) : 0;

    if(d < 3600) {
        snprintf(buf, size, "%d min", (int)(d / 60));
    } else if(d < 86400) {
        snprintf(buf, size, "%d h %d min", (int)(d / 3600), (int)((d % 3600) / 60));
    } else {
        snprintf(buf, size, "%d days %d h", (int)(d / 86400), (int)((d % 86400) / 3600));
    }
    return buf;
}


static void row_more (strbuf_t **b, int cols, int left) {

    if(left > 0) {
        sb_reprintf(b, "<tr><td colspan=%d class=dim>%d more, see the JSON API</td></tr>\n", cols, left);
    }
}


// A peer of the edge, or an edge registered at the supernode
static void peer_row (strbuf_t **b, const struct peer_info *peer, const char *mode, const char *mode_class,
                      const char *community, struct nat_peer *nat_peers, time_t now) {

    macstr_t mac_buf;
    n3n_sock_str_t sockbuf;
    dec_ip_bit_str_t ip_bit_str = {'\0'};
    char nat[40];
    char when[24];
    const struct nat_peer *np = nat_peers ? nat_peer_find(nat_peers, peer->mac_addr, false) : NULL;

    sb_reprintf(b, "<tr><td><span class=\"b %s\">%s</span></td>", mode_class, mode);
    if(community) {
        sb_reprintf(b, "<td>");
        html_text(b, community, N2N_COMMUNITY_SIZE);
        sb_reprintf(b, "</td>");
    }
    sb_reprintf(b, "<td class=mono>%s</td><td class=mono>%s</td><td class=mono>%s</td>",
                (peer->dev_addr.net_addr == 0) ? "" : ip_subnet_to_str(ip_bit_str, &peer->dev_addr),
                is_null_mac(peer->mac_addr) ? "" : macaddr_str(mac_buf, peer->mac_addr),
                sock_to_cstr(sockbuf, &peer->sock));
    if(nat_peers) {
        sb_reprintf(b, "<td>%s</td>", nat_hint_str(nat, sizeof(nat), np ? np->hint : 0));
    }
    sb_reprintf(b, "<td>");
    html_text(b, peer->dev_desc, N2N_DESC_SIZE);
    sb_reprintf(b, "</td><td>%s</td></tr>\n", ago(when, sizeof(when), now, peer->last_seen));
}


static void counters (strbuf_t **b, const struct n3n_runtime_data *rt, bool relay) {

    struct n2n_edge_stats s;

    n3n_stats_sum(rt, &s);

    sb_reprintf(b, "<h3>Traffic</h3><div class=scroll><table>"
                "<tr><th>packets</th><th class=num>sent</th><th class=num>received</th></tr>\n");
    if(!relay) {
        sb_reprintf(b,
                    "<tr><td>encrypted / decrypted</td><td class=num>%u</td><td class=num>%u</td></tr>\n"
                    "<tr><td>peer to peer</td><td class=num>%u</td><td class=num>%u</td></tr>\n"
                    "<tr><td>through the supernode</td><td class=num>%u</td><td class=num>%u</td></tr>\n"
                    "<tr><td>broadcast through the supernode</td><td class=num>%u</td><td class=num>%u</td></tr>\n"
                    "<tr><td>multicast dropped</td><td class=num>%u</td><td class=num>%u</td></tr>\n"
                    "<tr><td>TAP device errors</td><td class=num>%u</td><td class=num></td></tr>\n",
                    s.transop_tx, s.transop_rx, s.tx_p2p, s.rx_p2p, s.tx_sup, s.rx_sup,
                    s.tx_sup_broadcast, s.rx_sup_broadcast, s.tx_multicast_drop, s.rx_multicast_drop,
                    s.tx_tuntap_error);
    } else {
        sb_reprintf(b,
                    "<tr><td>relayed between edges</td><td class=num>%u</td><td class=num></td></tr>\n"
                    "<tr><td>broadcast to edges</td><td class=num>%u</td><td class=num></td></tr>\n"
                    "<tr><td>registrations answered (refused)</td><td class=num>%u (%u)</td><td class=num></td></tr>\n"
                    "<tr><td>send errors</td><td class=num>%u</td><td class=num></td></tr>\n",
                    s.sn_fwd, s.sn_broadcast, s.sn_reg, s.sn_reg_nak, s.sn_errors);
    }
    sb_reprintf(b, "</table></div>\n");
}


static void section_edge (strbuf_t **b, struct n3n_runtime_data *eee, bool own_of_supernode, time_t now) {

    char ip[INET_ADDRSTRLEN] = "";
    char nat4[40];
    char nat6[40];
    char when[24];
    macstr_t mac_buf;
    n3n_sock_str_t sockbuf;
    struct peer_info *peer, *tmp;
    struct peer_info *sn = eee->client.curr_sn;
    bool registered = sn && !eee->client.sn_wait && SHARED_LOAD(eee->client.last_sup);
    int rows;

    inet_ntop(AF_INET, &eee->tap.device.ip_addr, ip, sizeof(ip));

    sb_reprintf(b, "<section id=edge><h2>Edge%s</h2><dl>\n",
                own_of_supernode ? " <small class=dim>(of this supernode, supernode.tap)</small>" : "");
    sb_reprintf(b, "<dt>Community</dt><dd>");
    html_text(b, eee->conf.community.community_name, N2N_COMMUNITY_SIZE);
    sb_reprintf(b, "</dd>\n<dt>Address</dt><dd class=mono>%s &nbsp; %s</dd>\n", ip,
                macaddr_str(mac_buf, eee->tap.device.mac_addr));
    if(own_of_supernode) {
        sb_reprintf(b, "<dt>Supernode</dt><dd>this one, inside the process</dd>\n");
    } else {
        sb_reprintf(b, "<dt>Supernode</dt><dd>%s <span class=mono>%s</span></dd>\n",
                    registered ? "<span class=\"b ok\">registered</span>" : "<span class=\"b bad\">not registered</span>",
                    sn ? sock_to_cstr(sockbuf, eee->client.tcp && sn->tcp_hostname ? &sn->tcp_sock : &sn->sock) : "-");
        sb_reprintf(b, "<dt>Transport</dt><dd>%s</dd>\n",
                    eee->client.tcp ? "<span class=\"b warn\">TCP</span> all traffic through the supernode"
                    : "<span class=\"b ok\">UDP</span>");
        sb_reprintf(b, "<dt>NAT</dt><dd>IPv4: %s &nbsp; IPv6: %s</dd>\n",
                    nat_view_str(nat4, sizeof(nat4), &eee->client.nat[0]),
                    nat_view_str(nat6, sizeof(nat6), &eee->client.nat[1]));
    }
    sb_reprintf(b, "</dl>\n");

    sb_reprintf(b, "<h3>Peers</h3><div class=scroll><table>"
                "<tr><th>path</th><th>address</th><th>MAC</th><th>socket</th><th>NAT</th>"
                "<th>description</th><th>last seen</th></tr>\n");
    rows = 0;
    HASH_ITER(hh, eee->client.known_peers, peer, tmp) {
        if(rows++ < PAGE_ROWS_MAX) {
            peer_row(b, peer, "direct", "ok", NULL, eee->client.nat_peers, now);
        }
    }
    HASH_ITER(hh, eee->client.pending_peers, peer, tmp) {
        if(rows++ < PAGE_ROWS_MAX) {
            peer_row(b, peer, "via supernode", "warn", NULL, eee->client.nat_peers, now);
        }
    }
    row_more(b, 7, rows - PAGE_ROWS_MAX);
    if(!rows) {
        sb_reprintf(b, "<tr><td colspan=7 class=dim>none yet</td></tr>\n");
    }
    sb_reprintf(b, "</table></div>\n");

    if(!own_of_supernode) {
        char version[N2N_VERSION_STRING_SIZE + 1];

        sb_reprintf(b, "<h3>Supernodes</h3><div class=scroll><table>"
                    "<tr><th></th><th>socket</th><th>TCP</th><th>over</th><th>version</th><th>last seen</th></tr>\n");
        rows = 0;
        HASH_ITER(hh, eee->client.supernodes, peer, tmp) {
            n3n_sock_str_t tcpbuf;
            if(rows++ >= PAGE_ROWS_MAX) {
                continue;
            }
            snprintf(version, sizeof(version), "%.*s", N2N_VERSION_STRING_SIZE, peer->version);
            sb_reprintf(b, "<tr><td>%s</td><td class=mono>%s</td><td class=mono>%s</td><td>%s</td><td>",
                        (peer == sn) ? "<span class=\"b info\">current</span>" : "",
                        sock_to_cstr(sockbuf, &peer->sock),
                        sock_to_cstr(tcpbuf, peer->tcp_hostname ? &peer->tcp_sock : &peer->sock),
                        (peer->transports == N3N_TRANSPORT_UDP) ? "UDP" :
                        (peer->transports == N3N_TRANSPORT_TCP) ? "TCP" : "UDP, TCP");
            html_text(b, version, sizeof(version));
            sb_reprintf(b, "</td><td>%s</td></tr>\n", ago(when, sizeof(when), now, peer->last_seen));
        }
        row_more(b, 6, rows - PAGE_ROWS_MAX);
        sb_reprintf(b, "</table></div>\n");
    }

    counters(b, eee, false);
    sb_reprintf(b, "</section>\n");
}


static void section_supernode (strbuf_t **b, struct n3n_runtime_data *sss, time_t now) {

    struct sn_community *comm, *tmp;
    struct peer_info *peer, *ptmp;
    macstr_t mac_buf;
    dec_ip_bit_str_t ip_bit_str = {'\0'};
    int communities = 0;
    int edges = 0;
    int rows;

    HASH_ITER(hh, sss->relay.communities, comm, tmp) {
        if(!comm->is_federation) {
            communities++;
            edges += HASH_COUNT(comm->edges);
        }
    }

    sb_reprintf(b, "<section id=supernode><h2>Supernode</h2><dl>\n"
                "<dt>MAC</dt><dd class=mono>%s</dd>\n"
                "<dt>Federation</dt><dd>",
                macaddr_str(mac_buf, sss->conf.relay.sn_mac_addr));
    html_text(b, sss->conf.relay.sn_federation, sizeof(sss->conf.relay.sn_federation));
    sb_reprintf(b, "</dd>\n<dt>Serving</dt><dd>%d edge%s in %d communit%s</dd>\n</dl>\n",
                edges, (edges == 1) ? "" : "s", communities, (communities == 1) ? "y" : "ies");

    sb_reprintf(b, "<h3>Communities</h3><div class=scroll><table>"
                "<tr><th>name</th><th>addresses</th><th class=num>edges</th><th>headers</th></tr>\n");
    rows = 0;
    HASH_ITER(hh, sss->relay.communities, comm, tmp) {
        if(comm->is_federation || (rows++ >= PAGE_ROWS_MAX)) {
            continue;
        }
        sb_reprintf(b, "<tr><td>");
        html_text(b, comm->community, N2N_COMMUNITY_SIZE);
        sb_reprintf(b, "</td><td class=mono>%s</td><td class=num>%u</td><td>%s</td></tr>\n",
                    comm->auto_ip_net.net_addr ? ip_subnet_to_str(ip_bit_str, &comm->auto_ip_net) : "",
                    HASH_COUNT(comm->edges),
                    (comm->header_encryption == HEADER_ENCRYPTION_ENABLED) ? "encrypted" : "plain");
    }
    row_more(b, 4, rows - PAGE_ROWS_MAX);
    if(!rows) {
        sb_reprintf(b, "<tr><td colspan=4 class=dim>none yet</td></tr>\n");
    }
    sb_reprintf(b, "</table></div>\n");

    sb_reprintf(b, "<h3>Edges</h3><div class=scroll><table>"
                "<tr><th>registered</th><th>community</th><th>address</th><th>MAC</th><th>socket</th>"
                "<th>description</th><th>last seen</th></tr>\n");
    rows = 0;
    HASH_ITER(hh, sss->relay.communities, comm, tmp) {
        if(comm->is_federation) {
            continue;
        }
        HASH_ITER(hh, comm->edges, peer, ptmp) {
            if(rows++ < PAGE_ROWS_MAX) {
                // its own edge is at 127.0.0.1:0, see local_link.h
                peer_row(b, peer, peer->sock.port ? "here" : "own", peer->sock.port ? "info" : "ok",
                         comm->community, NULL, now);
            }
        }
    }
    row_more(b, 7, rows - PAGE_ROWS_MAX);
    if(!rows) {
        sb_reprintf(b, "<tr><td colspan=7 class=dim>none yet</td></tr>\n");
    }
    sb_reprintf(b, "</table></div>\n");

    if(sss->relay.federation) {
        char when[24];
        n3n_sock_str_t sockbuf;
        char version[N2N_VERSION_STRING_SIZE + 1];

        sb_reprintf(b, "<h3>Federation</h3><div class=scroll><table>"
                    "<tr><th>supernode</th><th>MAC</th><th>version</th><th>last seen</th></tr>\n");
        rows = 0;
        HASH_ITER(hh, sss->relay.federation->edges, peer, ptmp) {
            if(rows++ >= PAGE_ROWS_MAX) {
                continue;
            }
            snprintf(version, sizeof(version), "%.*s", N2N_VERSION_STRING_SIZE, peer->version);
            sb_reprintf(b, "<tr><td class=mono>%s</td><td class=mono>%s</td><td>",
                        sock_to_cstr(sockbuf, &peer->sock),
                        is_null_mac(peer->mac_addr) ? "" : macaddr_str(mac_buf, peer->mac_addr));
            html_text(b, version, sizeof(version));
            sb_reprintf(b, "</td><td>%s</td></tr>\n", ago(when, sizeof(when), now, peer->last_seen));
        }
        row_more(b, 4, rows - PAGE_ROWS_MAX);
        if(!rows) {
            sb_reprintf(b, "<tr><td colspan=4 class=dim>no other supernodes</td></tr>\n");
        }
        sb_reprintf(b, "</table></div>\n");
    }

    counters(b, sss, true);
    sb_reprintf(b, "</section>\n");
}


void mgmt_page_render (strbuf_t **b, struct n3n_runtime_data *rt, struct n3n_runtime_data *edge,
                       struct n3n_runtime_data *relay) {

    time_t now = time(NULL);
    char up[32];
    char clock[16] = "";
    const char *roles = (edge && relay) ? "supernode and edge" : relay ? "supernode" : "edge";
    int level = getTraceLevel();
    struct tm *tm = localtime(&now);

    if(tm) {
        strftime(clock, sizeof(clock), "%H:%M:%S", tm);
    }

    sb_reprintf(b, "<!DOCTYPE html>\n<html lang=en><head><meta charset=utf-8>"
                "<meta name=viewport content=\"width=device-width,initial-scale=1\">"
                "<title>n3n ");
    html_text(b, rt->conf.sessionname ? rt->conf.sessionname : "", 64);
    sb_reprintf(b, "</title>\n<style>%s</style></head>\n<body>\n<header><h1>n3n <small>", page_style);
    html_text(b, rt->conf.sessionname ? rt->conf.sessionname : "", 64);
    sb_reprintf(b, "</small></h1>\n<span>%s | up %s | version %s</span>\n"
                "<nav><a href=\"/\">refresh</a> | <a href=\"/metrics\">metrics</a> | "
                "<a href=\"/help\">API</a></nav>\n</header>\n<main>\n",
                roles, uptime(up, sizeof(up), now, rt->start_time), VERSION);

    // what the whole process does: the log, stopping it
    sb_reprintf(b, "<section id=peer><h2>Peer</h2>\n"
                "<form method=post action=\"/page\">\n"
                "<span>log level <b>%d</b></span>\n"
                "<button name=do value=less%s>less</button>\n"
                "<button name=do value=more%s>more</button>\n"
                "<button name=do value=stop class=bad>stop n3n</button>\n"
                "</form>\n<p class=dim>Buttons ask for the management password (user name: anything). "
                "As of %s.</p></section>\n",
                level, (level <= 0) ? " disabled" : "", (level >= 4) ? " disabled" : "", clock);

    if(edge) {
        section_edge(b, edge, relay != NULL, now);
    }
    if(relay) {
        section_supernode(b, relay, now);
    }

    sb_reprintf(b, "</main>\n<script>%s</script>\n</body></html>\n", page_script);
}
