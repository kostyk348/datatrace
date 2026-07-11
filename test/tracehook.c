/* LD_PRELOAD hook: intercept malloc/free/memcpy/sendto/recvfrom
 * and emit JSON events to stderr (for DataTrace pipeline testing).
 *
 * Usage:
 *   gcc -shared -fPIC -o tracehook.so tracehook.c -ldl
 *   LD_PRELOAD=./tracehook.so ./game_server 2>events.json
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <time.h>
#include <sys/socket.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/syscall.h>

static FILE *log_fp = NULL;
static int initialized = 0;

static void init(void) {
    if (initialized) return;
    initialized = 1;
    /* Use stderr for event output */
    log_fp = stderr;
    fprintf(log_fp, "{\"event\":\"hook_ready\",\"pid\":%d}\n", getpid());
    fflush(log_fp);
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static const char b64t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void b64enc(const unsigned char *in, int inlen, char *out) {
    int i, j = 0;
    for (i = 0; i < inlen; i += 3) {
        int a = in[i];
        int b = i+1 < inlen ? in[i+1] : 0;
        int c = i+2 < inlen ? in[i+2] : 0;
        out[j++] = b64t[(a >> 2) & 0x3f];
        out[j++] = b64t[((a << 4) | (b >> 4)) & 0x3f];
        out[j++] = i+1 < inlen ? b64t[((b << 2) | (c >> 6)) & 0x3f] : '=';
        out[j++] = i+2 < inlen ? b64t[c & 0x3f] : '=';
    }
    out[j] = 0;
}

#define SAMPLE_SZ 32

/* avoid calling intercepted memcpy */
static void sample_copy(unsigned char *dst, const void *src, int n) {
    const unsigned char *sp = (const unsigned char *)src;
    for (int i = 0; i < n; i++) dst[i] = sp[i];
}

static void emit(int type, uint64_t addr, uint64_t addr2, uint64_t size, const void *ptr) {
    char b64[64] = "";
    int sample_type = (type == 2 || type == 6); /* free or sendto */
    if (sample_type && ptr) {
        unsigned char buf[SAMPLE_SZ];
        sample_copy(buf, ptr, SAMPLE_SZ);
        b64enc(buf, SAMPLE_SZ, b64);
    }
    if (sample_type && b64[0]) {
        fprintf(log_fp,
            "{\"ts\":%llu,\"pid\":%d,\"tid\":%d,\"type\":%d,"
            "\"addr\":%llu,\"addr2\":%llu,\"size\":%llu,"
            "\"sample_b64\":\"%s\"}\n",
            (unsigned long long)now_ns(),
            getpid(), (int)syscall(SYS_gettid),
            type, (unsigned long long)addr,
            (unsigned long long)addr2, (unsigned long long)size, b64);
    } else {
        fprintf(log_fp,
            "{\"ts\":%llu,\"pid\":%d,\"tid\":%d,\"type\":%d,"
            "\"addr\":%llu,\"addr2\":%llu,\"size\":%llu}\n",
            (unsigned long long)now_ns(),
            getpid(), (int)syscall(SYS_gettid),
            type, (unsigned long long)addr,
            (unsigned long long)addr2, (unsigned long long)size);
    }
    fflush(log_fp);
}

/* ---- Overridden functions ---- */

void *malloc(size_t size) {
    static void *(*real_malloc)(size_t) = NULL;
    if (!real_malloc) real_malloc = dlsym(RTLD_NEXT, "malloc");
    init();
    emit(1, 0, 0, size, NULL);
    void *p = real_malloc(size);
    emit(1 | 0x1000, (uint64_t)p, 0, 0, NULL);
    return p;
}

void free(void *ptr) {
    static void (*real_free)(void*) = NULL;
    if (!real_free) real_free = dlsym(RTLD_NEXT, "free");
    init();
    emit(2, (uint64_t)ptr, 0, 0, ptr);
    real_free(ptr);
}

void *calloc(size_t nmemb, size_t size) {
    static void *(*real_calloc)(size_t, size_t) = NULL;
    if (!real_calloc) real_calloc = dlsym(RTLD_NEXT, "calloc");
    init();
    emit(3, nmemb, size, 0, NULL);
    void *p = real_calloc(nmemb, size);
    emit(3 | 0x1000, (uint64_t)p, 0, 0, NULL);
    return p;
}

void *realloc(void *ptr, size_t size) {
    static void *(*real_realloc)(void*, size_t) = NULL;
    if (!real_realloc) real_realloc = dlsym(RTLD_NEXT, "realloc");
    init();
    void *p = real_realloc(ptr, size);
    return p;
}

void *memcpy(void *dst, const void *src, size_t size) {
    static void *(*real_memcpy)(void*, const void*, size_t) = NULL;
    if (!real_memcpy) real_memcpy = dlsym(RTLD_NEXT, "memcpy");
    init();
    emit(4, (uint64_t)dst, (uint64_t)src, size, NULL);
    return real_memcpy(dst, src, size);
}

void *memmove(void *dst, const void *src, size_t size) {
    static void *(*real_memmove)(void*, const void*, size_t) = NULL;
    if (!real_memmove) real_memmove = dlsym(RTLD_NEXT, "memmove");
    init();
    emit(5, (uint64_t)dst, (uint64_t)src, size, NULL);
    return real_memmove(dst, src, size);
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen) {
    static ssize_t (*real_sendto)(int, const void*, size_t, int,
                                   const struct sockaddr*, socklen_t) = NULL;
    if (!real_sendto) real_sendto = dlsym(RTLD_NEXT, "sendto");
    init();
    emit(6, (uint64_t)sockfd, (uint64_t)buf, len, buf);
    return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    return sendto(sockfd, buf, len, flags, NULL, 0);
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen) {
    static ssize_t (*real_recvfrom)(int, void*, size_t, int,
                                     struct sockaddr*, socklen_t*) = NULL;
    if (!real_recvfrom) real_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
    init();
    ssize_t r = real_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
    emit(7, (uint64_t)sockfd, (uint64_t)buf, r > 0 ? (size_t)r : 0, NULL);
    return r;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
    return recvfrom(sockfd, buf, len, flags, NULL, NULL);
}
