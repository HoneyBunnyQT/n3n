/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The app's way into the core: N3nVpnService.nativeRun() runs the edge (see
 * n3n/embed.h) on the thread that calls it, until nativeStop().  Every socket
 * the edge opens goes to VpnService.protect(), every log line to logcat and
 * to the service's onLog(); the device comes from the service's onDevice(),
 * once the edge knows its address (static, or from the supernode).
 *
 * The callbacks do not only come from that thread: the edge's other threads
 * (the name resolver, packet threads) open sockets and log too.  A JNIEnv
 * belongs to one thread, and Android ends the app when another one uses it,
 * so each callback takes the one of the thread it runs on, attaching that
 * thread to the VM for the call if it is not yet.
 */

#include <jni.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <n3n/embed.h>
#include <n3n/qr_seal.h>
#include <arpa/inet.h>
#include "ipv6.h"

#ifdef __ANDROID__
#include <android/log.h>
#endif


// What the callbacks need, during nativeRun()
struct jni_ctx {
    JavaVM *vm;
    jobject service;        // a global reference: valid on every thread
    jmethodID protect;
    jmethodID on_log;
    jmethodID on_device;
};


// The JNIEnv of the calling thread; *attached says whether it had to be
// attached for this, and is to be detached again
static JNIEnv *thread_env (struct jni_ctx *c, bool *attached) {

    JNIEnv *env = NULL;

    *attached = false;
    switch((*c->vm)->GetEnv(c->vm, (void **)&env, JNI_VERSION_1_6)) {
        case JNI_OK:
            return env;
        case JNI_EDETACHED:
            if((*c->vm)->AttachCurrentThread(c->vm, (void *)&env, NULL) != JNI_OK) {
                return NULL;
            }
            *attached = true;
            return env;
        default:
            return NULL;
    }
}


static void thread_done (struct jni_ctx *c, JNIEnv *env, bool attached) {

    // an exception left pending would end the app at the next JNI call
    if((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
    }
    if(attached) {
        (*c->vm)->DetachCurrentThread(c->vm);
    }
}


static bool protect (void *ctx, int fd) {

    struct jni_ctx *c = ctx;
    bool attached;
    JNIEnv *env = thread_env(c, &attached);
    bool ok;

    if(!env) {
        return false;
    }
    ok = (*env)->CallBooleanMethod(env, c->service, c->protect, (jint)fd);
    thread_done(c, env, attached);
    return ok;
}


static void log_line (void *ctx, int level, const char *line) {

    struct jni_ctx *c = ctx;
    bool attached;
    JNIEnv *env;
    char *text;
    size_t len;

#ifdef __ANDROID__
    static const int prio[] = {ANDROID_LOG_ERROR, ANDROID_LOG_WARN, ANDROID_LOG_INFO, ANDROID_LOG_DEBUG, ANDROID_LOG_VERBOSE};
    __android_log_write(prio[(level >= 0 && level <= 4) ? level : 4], "n3n", line);
#endif

    // NewStringUTF() takes (modified) UTF-8 only, and ends the app on
    // anything else; log lines can carry what other peers sent, so they go
    // over as ASCII, the rest as '?'
    len = strlen(line);
    text = malloc(len + 1);
    if(!text) {
        return;
    }
    for(size_t i = 0; i < len; i++) {
        unsigned char ch = (unsigned char)line[i];
        text[i] = ((ch >= 0x20 && ch < 0x7f) || ch == '\t') ? (char)ch : '?';
    }
    text[len] = 0;

    env = thread_env(c, &attached);
    if(env) {
        jstring s = (*env)->NewStringUTF(env, text);
        if(s) {
            (*env)->CallVoidMethod(env, c->service, c->on_log, (jint)level, s);
            (*env)->DeleteLocalRef(env, s);
        }
        thread_done(c, env, attached);
    }
    free(text);
}


// The VPN device, from N3nVpnService.onDevice() once the edge knows its
// address: a file descriptor, or -1
static int device (void *ctx, const char *address, int bitlen) {

    struct jni_ctx *c = ctx;
    bool attached;
    JNIEnv *env = thread_env(c, &attached);
    int fd = -1;

    if(!env) {
        return -1;
    }
    // an address in dotted form: plain ASCII
    jstring s = (*env)->NewStringUTF(env, address);
    if(s) {
        fd = (*env)->CallIntMethod(env, c->service, c->on_device, s, (jint)bitlen);
        if((*env)->ExceptionCheck(env)) {
            fd = -1;
        }
        (*env)->DeleteLocalRef(env, s);
    }
    thread_done(c, env, attached);
    return fd;
}


JNIEXPORT jint JNICALL
Java_dev_n3n_android_N3nVpnService_nativeRun (JNIEnv *env, jobject service, jstring config, jint tun_fd, jstring rundir) {

    jclass cls = (*env)->GetObjectClass(env, service);
    struct jni_ctx c = {
        .service = (*env)->NewGlobalRef(env, service),
        .protect = (*env)->GetMethodID(env, cls, "protect", "(I)Z"),
        .on_log = (*env)->GetMethodID(env, cls, "onLog", "(ILjava/lang/String;)V"),
        .on_device = (*env)->GetMethodID(env, cls, "onDevice", "(Ljava/lang/String;I)I"),
    };

    if(((*env)->GetJavaVM(env, &c.vm) != JNI_OK) || !c.service || !c.protect || !c.on_log || !c.on_device) {
        if(c.service) {
            (*env)->DeleteGlobalRef(env, c.service);
        }
        return -1;
    }

    const char *conf = (*env)->GetStringUTFChars(env, config, NULL);
    const char *dir = (*env)->GetStringUTFChars(env, rundir, NULL);
    struct n3n_embed e = {
        .ctx = &c,
        .protect = protect,
        .log = log_line,
        .device = device,
        .rundir = dir,
        .session = "app",
    };

    // n3n_edge_run() ends all the edge's threads before it returns: no
    // callback comes after this
    jint rc = n3n_edge_run(conf, tun_fd, &e);

    (*env)->ReleaseStringUTFChars(env, config, conf);
    (*env)->ReleaseStringUTFChars(env, rundir, dir);
    (*env)->DeleteGlobalRef(env, c.service);
    return rc;
}


JNIEXPORT void JNICALL
Java_dev_n3n_android_N3nVpnService_nativeStop (JNIEnv *env, jobject service) {

    n3n_edge_stop();
}


JNIEXPORT void JNICALL
Java_dev_n3n_android_N3nVpnService_nativeNetworkChanged (JNIEnv *env, jobject service) {

    n3n_edge_network_changed();
}


// Seal: QR codes sealed with a PIN, see src/qr_seal.c

JNIEXPORT jstring JNICALL
Java_dev_n3n_android_Seal_seal (JNIEnv *env, jobject self, jstring text, jstring pin) {

    const char *t = (*env)->GetStringUTFChars(env, text, NULL);
    const char *p = (*env)->GetStringUTFChars(env, pin, NULL);
    char *code = NULL;
    jstring result = NULL;

    if(t && p && (qr_seal(t, p, &code) == 0)) {
        // base64url: plain ASCII
        result = (*env)->NewStringUTF(env, code);
        free(code);
    }
    if(t) {
        (*env)->ReleaseStringUTFChars(env, text, t);
    }
    if(p) {
        (*env)->ReleaseStringUTFChars(env, pin, p);
    }
    return result;
}


// The text as bytes: it can be anything the file held, and NewStringUTF()
// would end the app on what is no UTF-8
JNIEXPORT jbyteArray JNICALL
Java_dev_n3n_android_Seal_open (JNIEnv *env, jobject self, jstring code, jstring pin) {

    const char *c = (*env)->GetStringUTFChars(env, code, NULL);
    const char *p = (*env)->GetStringUTFChars(env, pin, NULL);
    char *text = NULL;
    jbyteArray result = NULL;

    if(c && p && (qr_open(c, p, &text) == 0)) {
        jsize len = (jsize)strlen(text);
        result = (*env)->NewByteArray(env, len);
        if(result) {
            (*env)->SetByteArrayRegion(env, result, 0, len, (const jbyte *)text);
        }
        free(text);
    }
    if(c) {
        (*env)->ReleaseStringUTFChars(env, code, c);
    }
    if(p) {
        (*env)->ReleaseStringUTFChars(env, pin, p);
    }
    return result;
}


JNIEXPORT jboolean JNICALL
Java_dev_n3n_android_Seal_looksSealed (JNIEnv *env, jobject self, jstring code) {

    const char *c = (*env)->GetStringUTFChars(env, code, NULL);
    jboolean result = JNI_FALSE;

    if(c) {
        result = qr_looks_sealed(c) ? JNI_TRUE : JNI_FALSE;
        (*env)->ReleaseStringUTFChars(env, code, c);
    }
    return result;
}


// Core.version(): what print_n3n_version() says of the core - git describe
// of the tree libn3n was built from, and the day it was built (ASCII)
JNIEXPORT jstring JNICALL
Java_dev_n3n_android_Core_version (JNIEnv *env, jobject self) {

    return (*env)->NewStringUTF(env, VERSION ", " BUILDDATE);
}


// Core.ipv6Address(): the edge's IPv6 address, as the edge itself works it
// out (src/ipv6.c), for the VpnService.Builder.  The MAC is no part of it:
// the device is set up once the edge has an IPv4 address (static or from the
// supernode), which gives the lower part of an "auto" address.
JNIEXPORT jstring JNICALL
Java_dev_n3n_android_Core_ipv6Address (JNIEnv *env, jobject self, jstring address6, jstring prefix6,
                                       jstring community, jstring ipv4) {

    const char *a6 = (*env)->GetStringUTFChars(env, address6, NULL);
    const char *p6 = (*env)->GetStringUTFChars(env, prefix6, NULL);
    const char *comm = (*env)->GetStringUTFChars(env, community, NULL);
    const char *v4s = (*env)->GetStringUTFChars(env, ipv4, NULL);
    static const uint8_t no_mac[6] = {0};
    jstring result = NULL;

    if(a6 && p6 && comm && v4s) {
        uint32_t v4 = 0;
        uint8_t addr[16];
        uint8_t len = 0;
        char buf[INET6_ADDRSTRLEN + 8];

        if(inet_pton(AF_INET, v4s, &v4) != 1) {
            v4 = 0;
        }
        int ret = n3n_ipv6_address(a6, p6, comm, v4, no_mac, addr, &len);
        if(ret == 0 && inet_ntop(AF_INET6, addr, buf, INET6_ADDRSTRLEN)) {
            size_t n = strlen(buf);
            snprintf(buf + n, sizeof(buf) - n, "/%u", len);
            result = (*env)->NewStringUTF(env, buf);
        } else if(ret < 0) {
            result = (*env)->NewStringUTF(env, "");
        }
    }
    if(a6) {
        (*env)->ReleaseStringUTFChars(env, address6, a6);
    }
    if(p6) {
        (*env)->ReleaseStringUTFChars(env, prefix6, p6);
    }
    if(comm) {
        (*env)->ReleaseStringUTFChars(env, community, comm);
    }
    if(v4s) {
        (*env)->ReleaseStringUTFChars(env, ipv4, v4s);
    }
    return result;
}
