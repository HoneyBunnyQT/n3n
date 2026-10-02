/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The app's way into the core: N3nVpnService.nativeRun() runs the edge (see
 * n3n/embed.h) on the thread that calls it, until nativeStop().  Every socket
 * the edge opens goes to VpnService.protect(), every log line to logcat and
 * to the service's onLog().
 */

#include <jni.h>
#include <stdbool.h>
#include <n3n/embed.h>

#ifdef __ANDROID__
#include <android/log.h>
#endif


// What the callbacks need, during nativeRun(): they run on its thread
struct jni_ctx {
    JNIEnv *env;
    jobject service;
    jmethodID protect;
    jmethodID on_log;
};


static bool protect (void *ctx, int fd) {

    struct jni_ctx *c = ctx;

    return (*c->env)->CallBooleanMethod(c->env, c->service, c->protect, (jint)fd);
}


static void log_line (void *ctx, int level, const char *line) {

    struct jni_ctx *c = ctx;

#ifdef __ANDROID__
    static const int prio[] = {ANDROID_LOG_ERROR, ANDROID_LOG_WARN, ANDROID_LOG_INFO, ANDROID_LOG_DEBUG, ANDROID_LOG_VERBOSE};
    __android_log_write(prio[(level >= 0 && level <= 4) ? level : 4], "n3n", line);
#endif

    jstring s = (*c->env)->NewStringUTF(c->env, line);
    if(s) {
        (*c->env)->CallVoidMethod(c->env, c->service, c->on_log, (jint)level, s);
        (*c->env)->DeleteLocalRef(c->env, s);
    }
}


JNIEXPORT jint JNICALL
Java_dev_n3n_android_N3nVpnService_nativeRun (JNIEnv *env, jobject service, jstring config, jint tun_fd, jstring rundir) {

    jclass cls = (*env)->GetObjectClass(env, service);
    struct jni_ctx c = {
        .env = env,
        .service = service,
        .protect = (*env)->GetMethodID(env, cls, "protect", "(I)Z"),
        .on_log = (*env)->GetMethodID(env, cls, "onLog", "(ILjava/lang/String;)V"),
    };
    const char *conf = (*env)->GetStringUTFChars(env, config, NULL);
    const char *dir = (*env)->GetStringUTFChars(env, rundir, NULL);
    struct n3n_embed e = {
        .ctx = &c,
        .protect = protect,
        .log = log_line,
        .rundir = dir,
        .session = "app",
    };

    jint rc = n3n_edge_run(conf, tun_fd, &e);

    (*env)->ReleaseStringUTFChars(env, config, conf);
    (*env)->ReleaseStringUTFChars(env, rundir, dir);
    return rc;
}


JNIEXPORT void JNICALL
Java_dev_n3n_android_N3nVpnService_nativeStop (JNIEnv *env, jobject service) {

    n3n_edge_stop();
}
