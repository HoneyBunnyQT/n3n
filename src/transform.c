/*
 * Copyright (C) Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 *
 */

#include <n3n/transform.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

static struct n3n_transform *registered_transforms = NULL;

void n3n_transform_register (struct n3n_transform *transform) {
    if(!transform) {
        return;
    }

    // only once, so a second n3n_initfuncs() does not loop the list
    for(struct n3n_transform *p = registered_transforms; p; p = p->next) {
        if(p == transform) {
            return;
        }
    }

    transform->next = registered_transforms;
    registered_transforms = transform;
}

static struct n3n_transform *lookup_name (bool is_compress, char *name) {
    struct n3n_transform *p = registered_transforms;
    while(p) {
        if((is_compress == p->is_compress) && (0==strcmp(p->name, name))) {
            return p;
        }
        p = p->next;
    }
    return NULL;
}

static struct n3n_transform *lookup_id (bool is_compress, int id) {
    struct n3n_transform *p = registered_transforms;
    while(p) {
        if((is_compress == p->is_compress) && (p->id == id)) {
            return p;
        }
        p = p->next;
    }
    return NULL;
}

static const char *id2str (bool is_compress, int id) {
    struct n3n_transform *p = lookup_id(is_compress, id);
    if(!p) {
        return NULL;
    }
    return p->name;
}

struct n3n_transform *n3n_transform_lookup_name (char *name) {
    return lookup_name(false, name);
}

struct n3n_transform *n3n_transform_lookup_id (int id) {
    return lookup_id(false, id);
}

const char *n3n_transform_id2str (int id) {
    return id2str(false, id);
}

struct n3n_transform *n3n_compression_lookup_name (char *name) {
    return lookup_name(true, name);
}

struct n3n_transform *n3n_compression_lookup_id (int id) {
    return lookup_id(true, id);
}

const char *n3n_compression_id2str (int id) {
    return id2str(true, id);
}

// prototype any internal (non-public) initfuncs
void n3n_initfuncs_transform_aes ();
void n3n_initfuncs_transform_cc20 ();
void n3n_initfuncs_transform_lzo ();
void n3n_initfuncs_transform_none ();
void n3n_initfuncs_transform_null ();
void n3n_initfuncs_transform_speck ();
void n3n_initfuncs_transform_twofish ();
void n3n_initfuncs_transform_zstd ();

void n3n_initfuncs_transform () {
    n3n_initfuncs_transform_aes();
    n3n_initfuncs_transform_cc20();
    n3n_initfuncs_transform_lzo();
    n3n_initfuncs_transform_none();
    n3n_initfuncs_transform_null();
    n3n_initfuncs_transform_speck();
    n3n_initfuncs_transform_twofish();
    n3n_initfuncs_transform_zstd();
}
