/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * n3n-qr: an edge's configuration file as a QR code, for the Android app
 * to scan (see android/README.md).  The code holds the configuration as
 * text, without its comments and with at most one blank line in a row, so
 * that any QR reader shows it as it is.
 *
 *   n3n-qr home.conf             writes home.qr.png
 *   n3n-qr -t home.conf          shows it in the terminal
 *
 * Built when ./configure finds libqrencode and libpng.
 */


#include <ctype.h>             // for isspace, tolower
#include <errno.h>             // for errno, ERANGE
#include <getopt.h>            // for getopt_long
#include <png.h>               // for png_*
#include <qrencode.h>          // for QRcode_encodeData, QRcode_free
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>           // for strncasecmp

#define QUIET_ZONE    4        // modules of white around the code, as the standard asks
#define CONF_MAX      65536    // far more than a code can hold anyway


static void usage (void) {
    printf(
        "Usage: n3n-qr [options] FILE.conf\n"
        "\n"
        "Make a QR code of an edge's configuration, for the n3n Android app.\n"
        "Comments are left out, and blank lines in a row become one.  FILE.conf\n"
        "may be - for the standard input.\n"
        "\n"
        "  -o, --output NAME   write the PNG image to NAME (- for the standard\n"
        "                      output); by default FILE.qr.png in the current\n"
        "                      directory, or n3n.qr.png for the standard input\n"
        "  -s, --scale N       pixels per module of the code (default 8)\n"
        "  -t, --terminal      show the code in the terminal, no image\n"
        "  -p, --print         print the text that goes into the code, no image\n"
        "  -h, --help          this help\n"
        "\n"
        "The code holds the configuration as it is, community key included:\n"
        "share the image like the key itself.\n"
    );
}


// Read the whole configuration
static char *read_all (FILE *f) {
    char *buf = malloc(CONF_MAX + 1);
    if(!buf) {
        return NULL;
    }
    size_t len = fread(buf, 1, CONF_MAX, f);
    if(ferror(f) || !feof(f)) {
        free(buf);
        return NULL;
    }
    buf[len] = 0;
    return buf;
}


static char *trim (char *s) {
    while(isspace((unsigned char)*s)) {
        s++;
    }
    char *end = s + strlen(s);
    while(end > s && isspace((unsigned char)end[-1])) {
        end--;
    }
    *end = 0;
    return s;
}


// Is the option of this line (before the '=') named so?
static bool option_is (const char *line, const char *name) {
    size_t len = strlen(name);
    if(strncasecmp(line, name, len)) {
        return false;
    }
    return line[len] == '=';
}


/*
 * The configuration as the edge reads it (src/conffile.c): lines starting
 * with # or ; are comments, and so is anything after a #.  What is left
 * goes into the code, one line each, "option=value" without the spaces
 * around the '='.  Also tells what the app will care about.
 */
static char *compact (char *text, bool *has_secret, bool *has_address) {
    char *out = malloc(strlen(text) + 1);
    if(!out) {
        return NULL;
    }
    char *o = out;
    char section[64] = "";

    *has_secret = false;
    *has_address = false;

    // one blank line where the file has one or more, none at the ends
    bool blank = false;

    for(char *raw = text; raw; ) {
        char *nl = strchr(raw, '\n');
        if(nl) {
            *nl = 0;
        }
        char *line = trim(raw);
        raw = nl ? nl + 1 : NULL;

        if(!*line) {
            blank = (o > out);
            continue;
        }
        if(*line == '#' || *line == ';') {
            continue;
        }
        char *comment = strchr(line, '#');
        if(comment) {
            *comment = 0;
            line = trim(line);
            if(!*line) {
                continue;
            }
        }
        if(blank) {
            *o++ = '\n';
            blank = false;
        }

        if(*line == '[') {
            // "[community home]" is a community section too
            size_t i = 0;
            for(char *s = line + 1; *s && *s != ']' && !isspace((unsigned char)*s) && i < sizeof(section) - 1; s++) {
                section[i++] = tolower((unsigned char)*s);
            }
            section[i] = 0;
            o += sprintf(o, "%s\n", line);
            continue;
        }

        char *eq = strchr(line, '=');
        if(eq) {
            *eq = 0;
            char *name = trim(line);
            char *value = trim(eq + 1);
            o += sprintf(o, "%s=%s\n", name, value);
            // checked on what was just written, "name=value"
            char *written = o - strlen(name) - strlen(value) - 2;
            if(option_is(written, "key") || option_is(written, "password")) {
                *has_secret = true;
            }
            if(!strcmp(section, "tuntap") && option_is(written, "address")) {
                *has_address = true;
            }
        } else {
            o += sprintf(o, "%s\n", line);
        }
    }

    // no newline after the last line
    if(o > out) {
        o--;
    }
    *o = 0;
    return out;
}


// The code in the terminal: two rows of modules in one line of text, in
// black on white whatever the colours of the terminal are
static void show_terminal (const QRcode *qr) {
    int size = qr->width + 2 * QUIET_ZONE;

    for(int y = 0; y < size; y += 2) {
        fputs("\033[30;47m", stdout);
        for(int x = 0; x < size; x++) {
            bool top = false, bottom = false;
            int qx = x - QUIET_ZONE;
            int qy = y - QUIET_ZONE;
            if(qx >= 0 && qx < qr->width) {
                if(qy >= 0 && qy < qr->width) {
                    top = qr->data[qy * qr->width + qx] & 1;
                }
                if(qy + 1 >= 0 && qy + 1 < qr->width) {
                    bottom = qr->data[(qy + 1) * qr->width + qx] & 1;
                }
            }
            if(top && bottom) {
                fputs("█", stdout);
            } else if(top) {
                fputs("▀", stdout);
            } else if(bottom) {
                fputs("▄", stdout);
            } else {
                fputs(" ", stdout);
            }
        }
        fputs("\033[0m\n", stdout);
    }
}


// The code as a black and white PNG image, one bit per pixel
static int write_png (const QRcode *qr, int scale, FILE *f) {
    int size = (qr->width + 2 * QUIET_ZONE) * scale;
    png_structp png = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    png_infop info = png ? png_create_info_struct(png) : NULL;
    png_bytep row = calloc(1, (size + 7) / 8);

    if(!png || !info || !row) {
        png_destroy_write_struct(&png, &info);
        free(row);
        return -1;
    }
    if(setjmp(png_jmpbuf(png))) {
        png_destroy_write_struct(&png, &info);
        free(row);
        return -1;
    }

    png_init_io(png, f);
    png_set_IHDR(png, info, size, size, 1, PNG_COLOR_TYPE_GRAY,
                 PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);
    png_write_info(png, info);

    for(int y = 0; y < size; y++) {
        int qy = y / scale - QUIET_ZONE;
        for(int x = 0; x < size; x++) {
            int qx = x / scale - QUIET_ZONE;
            bool black = qx >= 0 && qx < qr->width && qy >= 0 && qy < qr->width
                         && (qr->data[qy * qr->width + qx] & 1);
            // a 1 bit is white
            if(black) {
                row[x / 8] &= ~(0x80 >> (x % 8));
            } else {
                row[x / 8] |= 0x80 >> (x % 8);
            }
        }
        png_write_row(png, row);
    }

    png_write_end(png, NULL);
    png_destroy_write_struct(&png, &info);
    free(row);
    return 0;
}


// FILE.conf, or a path to it, gives FILE.qr.png in the current directory
static char *default_output (const char *input) {
    if(!strcmp(input, "-")) {
        return strdup("n3n.qr.png");
    }
    const char *base = strrchr(input, '/');
    base = base ? base + 1 : input;
    size_t len = strlen(base);
    if(len > 5 && !strcmp(base + len - 5, ".conf")) {
        len -= 5;
    }
    char *out = malloc(len + sizeof(".qr.png"));
    if(out) {
        memcpy(out, base, len);
        strcpy(out + len, ".qr.png");
    }
    return out;
}


int main (int argc, char **argv) {
    static const struct option long_options[] = {
        {"output",   required_argument, NULL, 'o'},
        {"scale",    required_argument, NULL, 's'},
        {"terminal", no_argument,       NULL, 't'},
        {"print",    no_argument,       NULL, 'p'},
        {"help",     no_argument,       NULL, 'h'},
        {NULL,       0,                 NULL, 0}
    };
    const char *output = NULL;
    int scale = 8;
    bool terminal = false;
    bool print = false;
    int c;

    while((c = getopt_long(argc, argv, "o:s:tph", long_options, NULL)) != -1) {
        switch(c) {
            case 'o':
                output = optarg;
                break;
            case 's':
                scale = atoi(optarg);
                if(scale < 1 || scale > 64) {
                    fprintf(stderr, "n3n-qr: the scale goes from 1 to 64\n");
                    return 2;
                }
                break;
            case 't':
                terminal = true;
                break;
            case 'p':
                print = true;
                break;
            case 'h':
                usage();
                return 0;
            default:
                usage();
                return 2;
        }
    }
    if(optind != argc - 1) {
        usage();
        return 2;
    }
    const char *input = argv[optind];

    FILE *in = strcmp(input, "-") ? fopen(input, "r") : stdin;
    if(!in) {
        fprintf(stderr, "n3n-qr: %s: %s\n", input, strerror(errno));
        return 1;
    }
    char *text = read_all(in);
    if(in != stdin) {
        fclose(in);
    }
    if(!text) {
        fprintf(stderr, "n3n-qr: %s: could not read it, or it is too long\n", input);
        return 1;
    }

    bool has_secret, has_address;
    char *payload = compact(text, &has_secret, &has_address);
    free(text);
    if(!payload || !*payload) {
        fprintf(stderr, "n3n-qr: %s: nothing in it but comments\n", input);
        return 1;
    }

    if(print) {
        printf("%s\n", payload);
        free(payload);
        return 0;
    }

    if(!has_address) {
        fprintf(stderr, "n3n-qr: note: there is no address in [tuntap]; the app needs one\n");
    }

    // medium error correction, the usual; low if it does not fit else
    QRcode *qr = QRcode_encodeData(strlen(payload), (unsigned char *)payload, 0, QR_ECLEVEL_M);
    if(!qr && errno == ERANGE) {
        qr = QRcode_encodeData(strlen(payload), (unsigned char *)payload, 0, QR_ECLEVEL_L);
    }
    if(!qr) {
        fprintf(stderr, "n3n-qr: %s: %zu bytes do not fit into a QR code (about 2900 do)\n",
                input, strlen(payload));
        free(payload);
        return 1;
    }

    int rc = 0;
    if(terminal) {
        show_terminal(qr);
    } else {
        char *name = output ? strdup(output) : default_output(input);
        FILE *f = strcmp(name, "-") ? fopen(name, "wb") : stdout;
        if(!f) {
            fprintf(stderr, "n3n-qr: %s: %s\n", name, strerror(errno));
            rc = 1;
        } else {
            if(write_png(qr, scale, f) < 0) {
                fprintf(stderr, "n3n-qr: %s: could not write the image\n", name);
                rc = 1;
            }
            if(f != stdout) {
                if(fclose(f)) {
                    fprintf(stderr, "n3n-qr: %s: %s\n", name, strerror(errno));
                    rc = 1;
                } else if(!rc) {
                    fprintf(stderr, "n3n-qr: wrote %s (%zu bytes of configuration)\n", name, strlen(payload));
                }
            }
        }
        free(name);
    }

    if(has_secret && !rc) {
        fprintf(stderr, "n3n-qr: note: the code holds the community's key or a password: share it like the key itself\n");
    }

    QRcode_free(qr);
    free(payload);
    return rc;
}
