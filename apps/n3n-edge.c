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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */

#ifdef __LINUX__
#define _GNU_SOURCE                  // for enabling dladdr
#endif

#include <config.h>                  // for HAVE_LIBCRYPTO
#include <ctype.h>                   // for isspace
#include <errno.h>                   // for errno
#include <getopt.h>                  // for required_argument, no_argument
#include <inttypes.h>                // for PRIu64
#include <n3n/benchmark.h>           // for benchmark_run
#include <n3n/conffile.h>            // for n3n_config_set_option
#include <n3n/edge.h>                // for edge_init_conf_defaults
#include <n3n/ethernet.h>            // for macaddr_str, macstr_t
#include <n3n/hexdump.h>             // for fhexdump
#include <n3n/initfuncs.h>           // for n3n_initfuncs()
#include <n3n/logging.h>             // for traceEvent
#include <n3n/mainloop.h>            // for mainloop_register_fd
#include <n3n/tests.h>               // for test_hashing
#include <n3n/random.h>              // for n3n_rand_seeds, n3n_rand_seeds_s...
#include <n3n/transform.h>           // for n3n_transform_lookup_id
#include <signal.h>                  // for signal, SIG_IGN, SIGPIPE, SIGCHLD
#include <stdbool.h>
#include <stdint.h>                  // for uint8_t, uint16_t
#include <stdio.h>                   // for printf, NULL, fclose, snprintf
#include <stdlib.h>                  // for atoi, exit, calloc, free, malloc
#include <string.h>                  // for strncpy, memset, strlen, strcmp
#include <sys/param.h>               // for MIN
#include <sys/time.h>                // for timeval
#include <sys/types.h>               // for u_char
#include <time.h>                    // for time
#include <unistd.h>                  // for setuid, _exit, chdir, fork, getgid
#include "auth.h"                    // for generate_private_key, generate_p...
#include "n3n.h"                     // for n3n_edge_main
#include "n2n.h"                     // for n2n_edge_conf_t, n3n_runtime_data, fil...
#include "portable_endian.h"         // for htobe32
#include "sn_selection.h"            // for sn_selection_sort, sn_selection_...
#include "uthash.h"                  // for UT_hash_handle, HASH_ADD, HASH_C...

// FIXME, including private headers
#include "../src/crypto/speck.h"     // for speck_init, speck_context_t
#include "../src/edge_threads.h"     // for edge_threads_open_early
#include "../src/management.h"       // for mgmt_password_warn
#include "../src/notify.h"           // for n3n_notify_ready
#include "../src/peer_info.h"        // for peer_info, peer_info_t
#include "../src/resolve.h"          // for resolve_check, resolve_forked

#ifdef HAVE_LIBCRYPTO
#include <openssl/crypto.h>          // for OpenSSL_version
#endif

#ifdef _WIN32
#include "../src/win32/defs.h"  // FIXME: untangle the include path
#else
#include <netinet/in.h>              // for INADDR_ANY, INADDR_NONE, ntohl
#include <pwd.h>                     // for getpwnam, passwd
#include <sys/select.h>              // for select, FD_ISSET, FD_SET, FD_ZERO
#include <sys/socket.h>              // for AF_INET
#endif

#ifdef __LINUX__
#include <dlfcn.h>                   // for dladdr
#include <ucontext.h>                // for ucontext_t
#endif

/* *************************************************** */

/** maximum length of command line arguments */
#define MAX_CMDLINE_BUFFER_LENGTH        4096

/** maximum length of a line in the configuration file */
#define MAX_CONFFILE_LINE_LENGTH         1024

/* ***************************************************** */

#ifdef HAVE_LIBCAP

#include <sys/capability.h>
#include <sys/prctl.h>

static cap_value_t cap_values[] = {
    //CAP_NET_RAW,            /* Use RAW and PACKET sockets */
    CAP_NET_ADMIN         /* Needed to performs routes cleanup at exit */
};

int num_cap = sizeof(cap_values)/sizeof(cap_value_t);
#endif

/* *************************************************** */

#define GETOPTS "A:O:Va:c:fhk:l:rvz:"

static const struct option long_options[] = {
    { "community",           required_argument, NULL, 'c' },
    { "daemon",              no_argument,       NULL, 'd' },
    { "help",                no_argument,       NULL, 'h' },
    { "supernode-list",      required_argument, NULL, 'l' },
    { "verbose",             no_argument,       NULL, 'v' },
    { "version",             no_argument,       NULL, 'V' },
    { NULL,                  0,                 NULL,  0  }
};

static const struct n3n_config_getopt option_map[] = {
    { 'O', NULL, NULL, NULL, "<section>.<option>=<value>  Set any config" },
    { 'V', NULL, NULL, NULL, "       Show the version" },
    { 'a', NULL, NULL, NULL, "<arg>  Set tuntap.address and tuntap.address_mode" },
    { 'c',  "community",    "name",             NULL },
    { 'd',  "daemon",       "background",       "true" },
    { 'k',  "community",    "key",              NULL },
    { 'l',  "community",    "supernode",        NULL },
    { 'r',  "filter",       "allow_routing",    "true" },
    { 'v', NULL, NULL, NULL, "       Increase logging verbosity" },
    { .optkey = 0 }
};

/* *********************************************** */

// little wrapper to show errors if the conffile parser has a problem
static void set_option_wrap (n2n_edge_conf_t *conf, char *section, char *option, char *value) {
    int i = n3n_config_set_option(conf, section, option, value);
    if(i==0) {
        return;
    }

    traceEvent(TRACE_WARNING, "Error setting %s.%s=%s\n", section, option, value);
}

/* *************************************************** */

/* read command line options */
static void loadFromCLI (int argc, char *argv[], n2n_edge_conf_t *conf) {

    int c = 0;
    while(c != -1) {
        c = getopt_long(
            argc, argv,
            // The superset of all possible short options
            GETOPTS,
            long_options,
            NULL
        );

        /* traceEvent(TRACE_NORMAL, "Option %c = %s", optkey, optarg ? optarg : ""); */

        switch(c) {
            case 'O': { // Set any config option
                char *section = strtok(optarg, ".");
                char *option = strtok(NULL, "=");
                char *value = strtok(NULL, "");
                set_option_wrap(conf, section, option, value);
                break;
            }
            case 'a': /* IP address and mode of TUNTAP interface */ {
                /*
                 * of the form:
                 *
                 * ["static:"|"dhcp:","auto:"] <ip> [/<cidr subnet mask>]
                 *
                 * for example        static:192.168.8.5/24
                 *
                 */
                char *field2 = strchr(optarg, ':');
                if(field2) {
                    // We have a field #1, extract it
                    *field2++ = 0;
                    set_option_wrap(conf, "tuntap", "address_mode", optarg);
                } else {
                    set_option_wrap(conf, "tuntap", "address_mode", "static");
                    field2 = optarg;
                }

                set_option_wrap(conf, "tuntap", "address", field2);
                break;
            }

            case 'v': /* verbose */
                setTraceLevel(getTraceLevel() + 1);
                break;

            case -1: // dont try to set from option map the end sentinal
                break;

            default: {
                n3n_config_from_getopt(option_map, conf, c, optarg);
            }
        }
    }
}

/********************************************************************/

static struct n3n_subcmd_def cmd_top[]; // Forward define

static void cmd_help_about (int argc, char **argv, void *conf) {
    printf("n3n - a peer to peer VPN for when you have noLAN\n"
           "\n"
           " usage: edge [options...] [command] [command args]\n"
           "\n"
           " e.g: edge start [sessionname]\n"
           "\n"
           "  Loads the config based on the sessionname (default 'edge.conf')\n"
           "  Any commandline options override the config loaded\n"
           "\n"
           "Some commands for more help:\n"
           "\n"
           " edge help commands\n"
           " edge help options\n"
           " edge help\n"
           "\n"
    );
    exit(0);
}

#ifdef _WIN32
static void cmd_help_adaptors (int argc, char **argv, void *conf) {
    printf(" AVAILABLE TAP ADAPTERS\n");
    printf(" ----------------------\n\n");
    win_print_available_adapters();
    exit(0);
}
#endif

static void cmd_help_commands (int argc, char **argv, void *conf) {
    printf(
        "List of all possible sub commands\n"
        "A sub command requiring more words to complete is shown with '->'\n"
        "\n"
        "Eg:  edge help about\n"
        "\n"
    );
    n3n_subcmd_help(cmd_top, 1, true);
    exit(0);
}

static void cmd_help_config (int argc, char **argv, void *conf) {
    printf(
        "This shows a description of all the config settings.\n"
        "The values seen in each setting are just examples and may not be\n"
        "the compiled-in defaults.\n"
        "\n"
    );
    n3n_config_dump(conf, stdout, 4);
    exit(0);
}

static void cmd_help_options (int argc, char **argv, void *conf) {
    n3n_config_help_options(option_map, long_options);
    exit(0);
}

static void cmd_help_transform (int argc, char **argv, void *conf) {
    // TODO: add an interface to the registered transform lookups and print
    // out the list
    printf("Not implemented\n");
    exit(1);
}

static void cmd_help_version (int argc, char **argv, void *conf) {
    print_n3n_version();
    exit(0);
}

static void cmd_debug_config_addr (int argc, char **argv, void *conf) {
    n3n_config_debug_addr(conf, stdout);
    exit(0);
}

static void cmd_debug_config_dump (int argc, char **argv, void *conf) {
    int level=1;
    if(argv[1]) {
        level = atoi(argv[1]);
    }
    n3n_config_dump(conf, stdout, level);
    exit(0);
}

static void cmd_debug_config_load_dump (int argc, char **argv, void *conf) {
    n3n_config_dump(conf, stdout, 1);
    exit(0);
}

static void cmd_debug_random_seed (int argc, char **argv, void *conf) {
    int level=0;
    if(argv[1]) {
        level = atoi(argv[1]);
    }
    for(int i = 0; i < n3n_rand_seeds_size / sizeof(n3n_rand_seeds[0]); i++) {
        printf("%s", n3n_rand_seeds[i].name);
        if(level) {
            printf(" %" PRIu64, n3n_rand_seeds[i].seed());
        }
        printf("\n");
    }
    exit(0);
}

static void cmd_test_config_roundtrip (int argc, char **argv, void *_conf) {
    n2n_edge_conf_t *conf = (n2n_edge_conf_t *)_conf;
    if(!argv[1]) {
        fprintf(stderr,"Warning: No session name given\n");
    }

    // Because we want this test to be deterministic, we dont use the defaults
    // or load the normal way, we start with a zeroed out conf
    conf = malloc(sizeof(*conf));
    memset(conf, 0, sizeof(*conf));

    int r = n3n_config_load_file(conf, argv[1]);
    if(r == -2) {
        fprintf(stderr,"Warning: No config file found\n");
    } else if(r != 0) {
        printf("Error loading config file (%i)\n", r);
        exit(1);
    }

    fprintf(stderr, "Loaded config file for session name: '%s'\n", argv[1]);

    // Save the session name for later
    conf->sessionname = argv[1];

    // Then dump it out
    n3n_config_dump(conf, stdout, 1);
    exit(0);
}

static void cmd_test_benchmark (int argc, char **argv, void *_conf) {
    n2n_edge_conf_t *conf = (n2n_edge_conf_t *)_conf;

    // TODO:
    // - provide a way to run a partial set of benchmarks

    benchmark_run_bench(
        conf->test_output_format,
        conf->test_benchmark_seconds,
        conf->test_benchmark_threads,
        argc-1,
        ++argv
    );
    exit(0);
}

static void cmd_test_check (int argc, char **argv, void *_conf) {
    n2n_edge_conf_t *conf = (n2n_edge_conf_t *)_conf;
    int errors = benchmark_run_check(
        conf->test_output_format,
        argc-1,
        ++argv
    );
    if(errors) {
        printf("ERROR\n");
    } else {
        printf("OK\n");
    }
    exit(errors);
}

static void cmd_test_fakebench (int argc, char **argv, void *_conf) {
    n2n_edge_conf_t *conf = (n2n_edge_conf_t *)_conf;
    benchmark_run_ptrace(
        conf->test_benchmark_seconds,
        argc-1,
        ++argv
    );
    exit(0);
}

static void cmd_test_list (int argc, char **argv, void *_conf) {
    n2n_edge_conf_t *conf = (n2n_edge_conf_t *)_conf;
    benchmark_list(conf->test_output_format);
    exit(0);
}

static void cmd_test_hashing (int argc, char **argv, void *conf) {
    fprintf(stderr, "Deprecated: use `n3n-edge test check` instead\n");
    cmd_test_check(argc, argv, conf);
}

static void cmd_tools_keygen (int argc, char **argv, void *conf) {
    if(argc == 1) {
        printf(
            "n3n keygen tool\n"
            "\n"
            "  usage: edge tools keygen <username> <password>\n"
            "\n"
            "     or  edge tools keygen <federation name>\n"
            "\n"
            "   outputs a line to insert at supernode's community file for\n"
            "   user-and-password authentication or the config option\n"
            "   value with the public federation key for use in the edge's\n"
            "   config, please refer to the docs/configure/Authentication.md\n"
            "   document for more details\n"
            "\n"
        );
        exit(1);
    }

    char *private;
    n2n_private_public_key_t prv;  // 32 bytes private key
    n2n_private_public_key_t bin;  // 32 bytes public key binary output buffer
    char asc[44];   // 43 bytes + 0-terminator ascii string output
    bool fed;

    switch(argc) {
        case 3:
            private = argv[2];
            fed = false;
            break;
        case 2:
            private = argv[1];
            fed = true;
            break;
        default:
            printf("Unexpected number of args\n");
            exit(1);
    }

    // derive private key from username and password:
    // hash username once, hash password twice (so password is bound
    // to username but username and password are not interchangeable),
    // finally xor the result
    // in federation mode: only hash federation name, twice
    generate_private_key(prv, private);

    if(!fed) {
        // hash user name only if required
        bind_private_key_to_username(prv, argv[1]);
    }

    // calculate the public key into binary output buffer
    generate_public_key(bin, prv);

    // clear out the private key
    memset(prv, 0, sizeof(prv));

    // convert binary output to 6-bit-ascii string output
    bin_to_ascii(asc, bin, sizeof(bin));

    if(!fed) {
        printf("%c %s %s\n", N2N_USER_KEY_LINE_STARTER, argv[1], asc);
    } else {
        printf("auth.pubkey=%s\n", asc);
    }
    exit(0);
}

static void cmd_start (int argc, char **argv, void *conf) {
    // Simply avoid triggering the "Unknown sub com" message
    return;
}

static struct n3n_subcmd_def cmd_debug_config[] = {
    {
        .name = "addr",
        .help = "show internal config addresses and sizes",
        .type = n3n_subcmd_type_fn,
        .fn = &cmd_debug_config_addr,
    },
    {
        .name = "dump",
        .help = "[level] - just dump the default config",
        .type = n3n_subcmd_type_fn,
        .fn = &cmd_debug_config_dump,
    },
    {
        .name = "load_dump",
        .help = "[sessionname] - load from all normal sources, then dump",
        .type = n3n_subcmd_type_fn,
        .fn = &cmd_debug_config_load_dump,
        .session_arg = true,
    },
    { .name = NULL }
};

static struct n3n_subcmd_def cmd_debug_random[] = {
    {
        .name = "seed",
        .help = "show which random number seed generators are compiled",
        .type = n3n_subcmd_type_fn,
        .fn = &cmd_debug_random_seed,
    },
    { .name = NULL }
};

static struct n3n_subcmd_def cmd_debug[] = {
    {
        .name = "config",
        .type = n3n_subcmd_type_nest,
        .nest = cmd_debug_config,
    },
    {
        .name = "random",
        .type = n3n_subcmd_type_nest,
        .nest = cmd_debug_random,
    },
    { .name = NULL }
};

static struct n3n_subcmd_def cmd_help[] = {
    {
        .name = "about",
        .help = "Basic command help",
        .type = n3n_subcmd_type_fn,
        .fn = cmd_help_about,
    },
#ifdef _WIN32
    {
        .name = "adaptors",
        .help = "List windows TAP adaptors",
        .type = n3n_subcmd_type_fn,
        .fn = cmd_help_adaptors,
    },
#endif
    {
        .name = "commands",
        .help = "Show all possible commandline commands",
        .type = n3n_subcmd_type_fn,
        .fn = cmd_help_commands,
    },
    {
        .name = "config",
        .help = "Show all the config file help text",
        .type = n3n_subcmd_type_fn,
        .fn = cmd_help_config,
    },
    {
        .name = "options",
        .help = "Describe all commandline options ",
        .type = n3n_subcmd_type_fn,
        .fn = cmd_help_options,
    },
    {
        .name = "transform",
        .help = "Show compiled encryption and compression modules",
        .type = n3n_subcmd_type_fn,
        .fn = cmd_help_transform,
    },
    {
        .name = "version",
        .help = "Show the version",
        .type = n3n_subcmd_type_fn,
        .fn = cmd_help_version,
    },
    { .name = NULL }
};

static struct n3n_subcmd_def cmd_test_config[] = {
    {
        .name = "roundtrip",
        .help = "<sessionname> - load only the config file and then dump it",
        .type = n3n_subcmd_type_fn,
        .fn = &cmd_test_config_roundtrip,
    },
    { .name = NULL }
};

static struct n3n_subcmd_def cmd_tools[] = {
    {
        .name = "keygen",
        .help = "generate public keys",
        .type = n3n_subcmd_type_fn,
        .fn = &cmd_tools_keygen,
    },
    { .name = NULL }
};

static struct n3n_subcmd_def cmd_test[] = {
    {
        .name = "benchmark",
        .help = "[name..] - run built-in tests and benchmark results",
        .type = n3n_subcmd_type_fn,
        .fn = &cmd_test_benchmark,
        .session_arg = true,
    },
    {
        .name = "check",
        .help = "[name..] - run built-in tests and check results",
        .type = n3n_subcmd_type_fn,
        .fn = &cmd_test_check,
        .session_arg = true,
    },
    {
        .name = "config",
        .type = n3n_subcmd_type_nest,
        .nest = cmd_test_config,
    },
    {
        .name = "hashing",
        .help = "Deprecated",
        .type = n3n_subcmd_type_fn,
        .fn = &cmd_test_hashing,
    },
    {
        .name = "list",
        .help = "Show the built-in tests",
        .type = n3n_subcmd_type_fn,
        .fn = &cmd_test_list,
        .session_arg = true,
    },
    {
        .name = "fakebench",
        .help = "[name..] - run tests, counting instructions (when perf is unavailable)",
        .type = n3n_subcmd_type_fn,
        .fn = &cmd_test_fakebench,
        .session_arg = true,
    },
    { .name = NULL }
};

static struct n3n_subcmd_def cmd_top[] = {
    {
        .name = "debug",
        .help = "(Do not expect debug commands to be friendly)",
        .type = n3n_subcmd_type_nest,
        .nest = cmd_debug,
    },
    {
        .name = "help",
        .type = n3n_subcmd_type_nest,
        .nest = cmd_help,
    },
    {
        .name = "start",
        .help = "[sessionname] - starts the session",
        .type = n3n_subcmd_type_fn,
        .fn = &cmd_start,
        .session_arg = true,
    },
    {
        .name = "tools",
        .type = n3n_subcmd_type_nest,
        .nest = cmd_tools,
    },
    {
        .name = "test",
        .type = n3n_subcmd_type_nest,
        .nest = cmd_test,
    },
    { .name = NULL }
};

static void n3n_config (int argc, char **argv, char *defname, n2n_edge_conf_t *conf) {
    struct n3n_subcmd_result cmd = n3n_subcmd_parse(
        argc,
        argv,
        GETOPTS,
        long_options,
        cmd_top
    );

    switch(cmd.type) {
        case n3n_subcmd_result_unknown:
            // Shouldnt happen
            abort();
        case n3n_subcmd_result_version:
            cmd_help_version(0, NULL, NULL);
        case n3n_subcmd_result_about:
            cmd_help_about(0, NULL, NULL);
        case n3n_subcmd_result_ok:
            break;
    }

    // If no session name has been found, use the default
    if(!cmd.sessionname) {
        cmd.sessionname = defname;
    }

    // Now that we might need it, setup some default config
    edge_init_conf_defaults(conf, cmd.sessionname);

    if(cmd.subcmd->session_arg) {
        // the cmd structure can request the normal loading of config

        int r = n3n_config_load_file(conf, cmd.sessionname);
        if(r == -1) {
            printf("Error loading config file\n");
            exit(1);
        }
        if(r == -2) {
            traceEvent(
                TRACE_INFO,
                "Warning: no config file found for session '%s'\n",
                cmd.sessionname
            );
        }

        // Update the loaded conf with the current environment
        if(n3n_config_load_env(conf)!=0) {
            printf("Error loading environment variables\n");
            exit(1);
        }

        // Update the loaded conf with any option args
        optind = 1;
        loadFromCLI(argc, argv, conf);
    }

    // Do the selected subcmd
    cmd.subcmd->fn(cmd.argc, cmd.argv, conf);
}

/* ************************************** */

#ifdef __MUSL__
/*
 * Lookup what info we can about the address
 */
void print_addrinfo (void *addr) {

    printf(" %p\n", addr);
    fflush(stdout);

#if 0
    // This kind of dirty grubbing around is better suited for a debugger,
    // or turned on only in specific debug cases

    Dl_info info;
    if(dladdr(addr, &info) == 0) {
        printf(" %p in ??\n", addr);
        return;
    }

    if(!info.dli_sname) {
        info.dli_sname = "??";
    }

    printf(
        " %p in %s (%p) from %s (%p)\n",
        addr,
        info.dli_sname,
        info.dli_saddr,
        info.dli_fname,
        info.dli_fbase
    );
#endif
}

/*
 * Attempt to show some useful debugging information to the user.
 *
 * On a GNU libc system, using backtrace(3) would be better.
 *
 * Yes, I am calling lots of forbidden functions from a signal handler.  Since
 * we are a dieing process, I'm throwing caution to the wind.
 */
void handle_sigsegv (int sig, siginfo_t *info, void *unused)
{
    if(sig != SIGSEGV) {
        fprintf(stderr, "Unexpected signal %i\n", sig);
        return;
    }

    ucontext_t *u = (ucontext_t *)unused;

    // Just in case someone is redirecting their stdout, send a notice on the
    // stderr as well
    fprintf(stderr, "SIGSEGV handler start\n");
    printf("SIGSEGV: si_code=%i, si_addr=%p\n", info->si_code, info->si_addr);

    printf("ucontext:\n");
    fhexdump(0, u, sizeof(*u), stdout);

    printf("call_stack:\n");
    print_addrinfo(__builtin_return_address(0));
    print_addrinfo(__builtin_return_address(1));
    print_addrinfo(__builtin_return_address(2));
    print_addrinfo(__builtin_return_address(3));
    print_addrinfo(__builtin_return_address(4));

    printf("SIGSEGV handler finish\n\n");
    fflush(stdout);
    signal(SIGSEGV, SIG_DFL);
}
#endif

#ifndef _WIN32
static void daemonize () {
    int childpid;

    traceEvent(TRACE_NORMAL, "parent process is exiting (this is normal)");

    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP,  SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);

    if((childpid = fork()) < 0)
        traceEvent(TRACE_ERROR, "occurred while daemonizing (errno=%d)",
                   errno);
    else {
        if(!childpid) { /* child */
            int rc;

            //traceEvent(TRACE_NORMAL, "Bye bye: I'm becoming a daemon...");
            rc = chdir("/");
            if(rc != 0)
                traceEvent(TRACE_ERROR, "error while moving to / directory");

            setsid();    /* detach from the terminal */

            fclose(stdin);
            fclose(stdout);
            /* fclose(stderr); */

            /*
             * clear any inherited file mode creation mask
             */
            //umask(0);

            /*
             * Use line buffered stdout
             */
            /* setlinebuf (stdout); */
            setvbuf(stdout, (char *)NULL, _IOLBF, 0);
        } else /* father */
            exit(0);
    }
}
#endif

/* *************************************************** */

static bool keep_on_running = true;

#ifndef _WIN32
static void term_handler (int sig) {
    static int called = 0;

    if(called) {
        traceEvent(TRACE_NORMAL, "ok, I am leaving now");
        _exit(0);
    } else {
        traceEvent(TRACE_NORMAL, "shutting down...");
        called = 1;
    }

    keep_on_running = false;
}
#endif

#ifdef _WIN32
extern int windows_stop_fd;

// Note well, this gets called from a brand new thread, thus is completely
// different to how signals work in POSIX
static BOOL WINAPI ConsoleCtrlHandler (DWORD sig) {
    // Tell the mainloop to exit next time it wakes
    keep_on_running = false;

    traceEvent(TRACE_INFO, "starting stopping");
    // The windows environment claims to support signals, but they dont
    // interrupt a running select() statement.  Also, this console handler
    // is run in its own thread, so it is also not interrupting the select()
    // This is clearly contrary to how select was designed to be used and it
    // makes process termination annoying, so we need a workaround.
    //
    // Since windows usually has a managment TCP port listening in the
    // select fdset, we can close that - this immediately causes the select
    // to return with activity on that file descriptor and allows the
    // mainloop to notice that we are no longer wanting to run.
    //
    // something something, darkside
    closesocket(windows_stop_fd);

    switch(sig) {
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            // Will terminate us after we return, blocking it to cleanup
            Sleep(INFINITE);
    }
    return(TRUE);
}
#endif

/* *************************************************** */

/** Entry point of the edge, see n3n.c */
int n3n_edge_main (int argc, char* argv[]) {

    int rc;
    struct n3n_runtime_data *eee;              /* single instance for this program */
    n2n_edge_conf_t conf;         /* generic N2N edge config */
    uint8_t runlevel = 0;         /* bootstrap: runlevel */
    uint8_t seek_answer = 1;      /*            expecting answer from supernode */
    int ping_rounds = 0;          /*            PINGs without an answer */
    time_t now, last_action = 0;  /*            timeout */
    macstr_t mac_buf;             /*            output mac address */
    peer_info_t *scan, *scan_tmp; /*            supernode iteration */

#ifdef HAVE_LIBCAP
    cap_t caps;
#endif

#ifdef __MUSL__
    struct sigaction sa;

    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_sigaction = handle_sigsegv;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;

    sigaction(SIGSEGV, &sa, NULL);
#endif

    // Do this early to register all internals
    n3n_initfuncs();

    n3n_config(argc, argv, "edge", &conf);

    if(edge_conf_one_community(&conf) != 0) {
        exit(1);
    }

    edge_conf_prepare(&conf);

    if(edge_verify_conf(&conf) != 0) {
        printf("ERROR: missing or incomplete configuration provided\n");
        cmd_help_about(0, NULL, NULL);
    }

    traceEvent(TRACE_NORMAL, "starting n3n edge %s %s", VERSION, BUILDDATE);

#ifdef HAVE_LIBCRYPTO
    traceEvent(TRACE_NORMAL, "using %s", OpenSSL_version(0));
#endif

    traceEvent(TRACE_NORMAL, "using compression: %s.", n3n_compression_id2str(conf.community.compression));
    traceEvent(TRACE_NORMAL, "using %s cipher.", n3n_transform_id2str(conf.community.transop_id));

#ifndef _WIN32
    /* If running suid root then we need to setuid before using the force. */
    if(setuid(0) != 0)
        traceEvent(TRACE_ERROR, "unable to become root [%u/%s]", errno, strerror(errno));
    /* setgid(0); */
#endif

    if(conf.community.encrypt_key && !strcmp((char*)conf.community.community_name, conf.community.encrypt_key))
        traceEvent(TRACE_WARNING, "community and encryption key must differ, otherwise security will be compromised");

    if((eee = edge_init(&conf, &rc)) == NULL) {
        traceEvent(TRACE_ERROR, "failed in edge_init");
        exit(1);
    }
    eee->keep_running = &keep_on_running;

#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, term_handler);
    signal(SIGINT,  term_handler);
#endif
#ifdef _WIN32
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);
#endif

    switch(eee->conf.tap.tuntap_ip_mode) {
        case TUNTAP_IP_MODE_SN_ASSIGN:
            traceEvent(TRACE_NORMAL, "automatically assign IP address by supernode");
            break;
        case TUNTAP_IP_MODE_STATIC:
            traceEvent(TRACE_NORMAL, "use manually set IP address");
            break;
        case TUNTAP_IP_MODE_DHCP:
            traceEvent(TRACE_NORMAL, "obtain IP from other edge DHCP services");
            break;
        default:
            traceEvent(TRACE_ERROR, "unknown ip_mode");
            break;
    }

    // mini main loop for bootstrap, not using main loop code because some of its mechanisms do not fit in here
    // for the sake of quickly establishing connection. REVISIT when a more elegant way to re-use main loop code
    // is found

    // find at least one supernode alive to faster establish connection.
    // exceptions:
    if(eee->client.tcp) {
        traceEvent(TRACE_DEBUG, "skip PING to supernode: TCP mode");
        runlevel = 2;
    }
    if(eee->conf.shared_secret) {
        traceEvent(TRACE_DEBUG, "skip PING to supernode: shared secret");
        runlevel = 2;
    }
    if(HASH_COUNT(eee->client.supernodes) <= 1) {
        traceEvent(TRACE_DEBUG, "skip PING to supernode: only one supernode");
        runlevel = 2;
    }

    eee->client.last_sup = 0; /* if it wasn't zero yet */
    eee->client.curr_sn = supernode_first(eee); // Duplicates action taken by edge_init()
    supernode_connect(eee);
    while(runlevel < 5) {
        if(!keep_on_running) {
            edge_term(eee);
            return 1;
        }

        now = time(NULL);

        // we do not use switch-case because we also check for 'greater than'

        if(runlevel == 0) { /* PING to all known supernodes */
            last_action = now;
            eee->client.sn_pong = 0;
            // (re-)initialize the number of max concurrent pings (decreases by calling send_query_peer)
            eee->conf.client.number_max_sn_pings = NUMBER_SN_PINGS_INITIAL;
            send_query_peer(eee, null_mac);
            traceEvent(TRACE_INFO, "send PING to supernodes");
            runlevel++;
        }

        if(runlevel == 1) { /* PING has been sent to all known supernodes */
            if(eee->client.sn_pong) {
                // first answer
                eee->client.sn_pong = 0;
                sn_selection_sort(&(eee->client.supernodes), !eee->client.sn_other_family);
                eee->client.curr_sn = supernode_first(eee);
                supernode_connect(eee);
                traceEvent(
                    TRACE_NORMAL,
                    "received first PONG from supernode [%s]",
                    peer_info_get_hostname(eee->client.curr_sn)
                );
                runlevel++;
            } else if(last_action <= (now - BOOTSTRAP_TIMEOUT)) {
                // timeout
                if(++ping_rounds < BOOTSTRAP_PING_ROUNDS) {
                    runlevel--;
                } else {
                    // no answer: carry on with the first supernode, the
                    // main loop keeps trying them (and other transports)
                    traceEvent(TRACE_NORMAL, "no supernode answers PING, carrying on");
                    supernode_connect(eee);
                    runlevel++;
                }
                // skip waiting for answer to direcly go to send PING again
                seek_answer = 0;
                traceEvent(TRACE_DEBUG, "PONG timeout");
            }
        }

        // by the way, have every later PONG cause the remaining (!) list to be sorted because the entries
        // before have already been tried; as opposed to initial PONG, do not change curr_sn
        if(runlevel > 1) {
            if(eee->client.sn_pong) {
                eee->client.sn_pong = 0;
                if(eee->client.curr_sn->hh.next) {
                    sn_selection_sort((peer_info_t**)&(eee->client.curr_sn->hh.next), !eee->client.sn_other_family);
                    traceEvent(TRACE_DEBUG, "received additional PONG from supernode");
                    // here, it is hard to detemine from which one, so no details to output
                }
            }
        }

        if(runlevel == 2) { /* send REGISTER_SUPER to get auto ip address from a supernode */
            if(eee->conf.tap.tuntap_ip_mode == TUNTAP_IP_MODE_SN_ASSIGN) {
                last_action = now;
                eee->client.sn_wait = 1;
                send_register_super(eee);
                runlevel++;
                traceEvent(
                    TRACE_INFO,
                    "send REGISTER_SUPER to supernode [%s] asking for IP address",
                    peer_info_get_hostname(eee->client.curr_sn)
                );
            } else {
                runlevel += 2; /* skip waiting for TUNTAP IP address */
                traceEvent(TRACE_DEBUG, "skip auto IP address asignment");
            }
        }

        if(runlevel == 3) { /* REGISTER_SUPER to get auto ip address from a sn has been sent */
            if(!eee->client.sn_wait) { /* TUNTAP IP address received */
                runlevel++;
                traceEvent(TRACE_INFO, "received REGISTER_SUPER_ACK from supernode for IP address asignment");
                // it should be from curr_sn, but we can't determine definitely here, so no details to output
            } else if(last_action <= (now - BOOTSTRAP_TIMEOUT)) {
                // timeout, so try next supernode
                eee->client.curr_sn = supernode_next(eee, eee->client.curr_sn);
                supernode_connect(eee);
                transport_note_giveup(eee, now);
                runlevel--;
                // skip waiting for answer to direcly go to send REGISTER_SUPER again
                seek_answer = 0;
                traceEvent(TRACE_DEBUG, "REGISTER_SUPER_ACK timeout");
            }
        }

        if(runlevel == 4) { /* configure the TUNTAP device, including routes */
            if(edge_tap_open(eee) < 0)
                exit(1);
#ifndef _WIN32
            // TODO: this internal fn should not be called publicly
            mainloop_register_fd(eee->tap.device.fd, fd_info_proto_tuntap);
#endif
            in_addr_t addr = eee->conf.tap.tuntap_v4.net_addr;
            struct in_addr *tmp = (struct in_addr *)&addr;
            traceEvent(TRACE_NORMAL, "created local tap device IPv4: %s/%u, MAC: %s",
                       inet_ntoa(*tmp),
                       eee->conf.tap.tuntap_v4.net_bitlen,
                       macaddr_str(mac_buf, eee->tap.device.mac_addr));
            runlevel = 5;
            // no more answers required
            seek_answer = 0;
        }

        // we usually wait for some answer, there however are exceptions when going back to a previous runlevel
        if(seek_answer) {
            mainloop_runonce(eee);
            n3n_notify_tick(eee);

            // FIXME: the mainloop could wait for BOOTSTRAP_TIMEOUT, not its
            // usual timeout ?!?
        }
        seek_answer = 1;

        resolve_check(eee->resolve_parameter, false /* no intermediate resolution requirement at this point */, now);
    }

    // allow a higher number of pings for first regular round of ping
    // to quicker get an inital 'supernode selection criterion overview'
    eee->conf.client.number_max_sn_pings = NUMBER_SN_PINGS_INITIAL;
    // shape supernode list; make current one the first on the list
    HASH_ITER(hh, eee->client.supernodes, scan, scan_tmp) {
        if(scan == eee->client.curr_sn)
            scan->selection_criterion = sn_selection_criterion_good();
        else
            scan->selection_criterion = sn_selection_criterion_default();
    }
    sn_selection_sort(&(eee->client.supernodes), !eee->client.sn_other_family);
    // do not immediately ping again, allow some time
    eee->client.last_sweep = now - SWEEP_TIME + 2 * BOOTSTRAP_TIMEOUT;
    eee->client.sn_wait = 1;
    eee->client.last_register_req = 0;

#ifndef _WIN32
    if(conf.background) {
        setUseSyslog(1); /* traceEvent output now goes to syslog. */
        daemonize();
        // the resolver thread stayed with the parent
        resolve_forked(eee->resolve_parameter);
    }

#ifdef HAVE_LIBCAP
    /* Before dropping the privileges, retain capabilities to regain them in future. */
    caps = cap_get_proc();

    cap_set_flag(caps, CAP_PERMITTED, num_cap, cap_values, CAP_SET);
    cap_set_flag(caps, CAP_EFFECTIVE, num_cap, cap_values, CAP_SET);

    if((cap_set_proc(caps) != 0) || (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0))
        traceEvent(TRACE_WARNING, "unable to retain permitted capabilities [%s]\n", strerror(errno));
#else
#ifndef __APPLE__
    // TODO:
    // - refactor and the libcap usage and prove exactly where any issues may
    //   occur
    // - Output any informational warnings before taking those actions,
    //   instead of this nebulous warning at startup time
    // - Continue improving the ability to run with reduced runtime permissions
    //   and incorporate that in the standard examples
    traceEvent(
        TRACE_WARNING,
        "The build option to add libcap-dev was not used. "
        "Some actions may cause permissions messages."
    );
#endif
#endif /* HAVE_LIBCAP */

    // while this is still the user of the main socket
    edge_threads_open_early(eee);

    if((conf.userid != 0) || (conf.groupid != 0)) {
        traceEvent(TRACE_NORMAL, "dropping privileges to uid=%d, gid=%d",
                   (signed int)conf.userid, (signed int)conf.groupid);

        /* Finished with the need for root privileges. Drop to unprivileged user. */
        if((setgid(conf.groupid) != 0)
           || (setuid(conf.userid) != 0)) {
            traceEvent(TRACE_ERROR, "unable to drop privileges [%u/%s]", errno, strerror(errno));
            exit(1);
        }
    }

    if((getuid() == 0) || (getgid() == 0))
        traceEvent(
            TRACE_WARNING,
            "running as root is discouraged, check out the userid/groupid options"
        );
#endif /* _WIN32 */

    traceEvent(TRACE_NORMAL, "edge started");
    mgmt_password_warn(eee);
    n3n_notify_ready(eee);
    rc = run_edge_loop(eee);

#ifdef HAVE_LIBCAP
    /* Before completing the cleanup, regain the capabilities as some
     * cleanup tasks require them (e.g. routes cleanup). */
    cap_set_flag(caps, CAP_EFFECTIVE, num_cap, cap_values, CAP_SET);

    if(cap_set_proc(caps) != 0)
        traceEvent(TRACE_WARNING, "could not regain the capabilities [%s]\n", strerror(errno));

    cap_free(caps);
#endif

    /* Cleanup */
    tuntap_close(&eee->tap.device);
    edge_term(eee);

    // the addresses of connection.bind, which the config loading allocated
    // and edge_init() only took a copy of the pointer to
    free(conf.bind_address);

    return(rc);
}

/* ************************************** */
