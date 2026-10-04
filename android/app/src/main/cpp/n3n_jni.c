/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The app's way into the core: N3nVpnService.nativeRun() runs the edge (see
 * n3n/embed.h) on the thread that calls it, until nativeStop().  Every socket
 * the edge opens goes to VpnService.protect(), every log line to logcat and
 * to the service's onLog().
 *
 * The callbacks do not only come from that thread: the edge's other threads
 * (the name resolver, packet threads) open sockets and log too.  A JNIEnv
 * belongs to one thread, and Android ends the app when another one uses it,
 * so each callback takes the one of the thread it runs on, attaching that
 * thread to the VM for the call if it is not yet.
 */

#include <jni.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <n3n/embed.h>
#include <n3n/qr_seal.h>

#ifdef __ANDROID__
#include <android/log.h>
#endif


// What the callbacks need, during nativeRun()
struct jni_ctx {
    JavaVM *vm;
    jobject service;        // a global reference: valid on every thread
    jmethodID protect;
    jmethodID on_log;
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


JNIEXPORT jint JNICALL
Java_dev_n3n_android_N3nVpnService_nativeRun (JNIEnv *env, jobject service, jstring config, jint tun_fd, jstring rundir) {

    jclass cls = (*env)->GetObjectClass(env, service);
    struct jni_ctx c = {
        .service = (*env)->NewGlobalRef(env, service),
        .protect = (*env)->GetMethodID(env, cls, "protect", "(I)Z"),
        .on_log = (*env)->GetMethodID(env, cls, "onLog", "(ILjava/lang/String;)V"),
    };

    if(((*env)->GetJavaVM(env, &c.vm) != JNI_OK) || !c.service || !c.protect || !c.on_log) {
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
