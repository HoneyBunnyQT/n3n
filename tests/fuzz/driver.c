/*
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * A fuzz target without libFuzzer: it gets each file named on the
 * command line, or each file in a directory named there - the regression
 * corpus and the seeds, with any compiler.  See README.md.
 */

#include <dirent.h>     // for opendir, readdir
#include <stdio.h>      // for fopen, fread, printf
#include <stdlib.h>     // for malloc, free
#include <string.h>     // for strcmp
#include <sys/stat.h>   // for stat, S_ISDIR
#include "fuzz.h"

static int count;

static int run_file (const char *path) {

    FILE *f = fopen(path, "rb");
    uint8_t *data;
    long size;

    if(!f) {
        perror(path);
        return 1;
    }
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);
    data = malloc(size ? size : 1);
    if(!data || (fread(data, 1, size, f) != (size_t)size)) {
        fprintf(stderr, "%s: cannot read\n", path);
        fclose(f);
        free(data);
        return 1;
    }
    fclose(f);
    // a copy of its own, so that a read past the end shows with ASan
    LLVMFuzzerTestOneInput(data, size);
    free(data);
    count++;
    return 0;
}

static int run_path (const char *path) {

    struct stat st;
    DIR *dir;
    struct dirent *e;
    int err = 0;

    if(stat(path, &st) != 0) {
        perror(path);
        return 1;
    }
    if(!S_ISDIR(st.st_mode)) {
        return run_file(path);
    }
    dir = opendir(path);
    if(!dir) {
        perror(path);
        return 1;
    }
    while((e = readdir(dir))) {
        char sub[4096];

        if(e->d_name[0] == '.') {
            continue;
        }
        snprintf(sub, sizeof(sub), "%s/%s", path, e->d_name);
        err |= run_path(sub);
    }
    closedir(dir);
    return err;
}

int main (int argc, char *argv[]) {

    int err = 0;
    int i;

    LLVMFuzzerInitialize(&argc, &argv);
    for(i = 1; i < argc; i++) {
        err |= run_path(argv[i]);
    }
    // a count only, so that the output does not depend on the files' order
    printf("%s: %s\n", argv[0], count ? "inputs run" : "no inputs");
    return err;
}
