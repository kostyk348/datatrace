#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/syscall.h>  /* for SYS_gettid */

/* Event types matching events.py */
#define EV_MALLOC    1
#define EV_FREE      2
#define EV_CALLOC    3
#define EV_MEMCPY    4
#define EV_MEMMOVE   5
#define EV_SENDTO    6
#define EV_RECVFROM  7
#define EV_SEND      8
#define EV_RECV      9

#define EVENT_RET    0x1000

#define SAMPLE_SIZE  32
#define BUF_SIZE     2048

static int g_enabled = 0;
static __thread char g_buf[BUF_SIZE];
static __thread int g_depth = 0;

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void emit(const char *json) {
    size_t len = strlen(json);
    size_t n;
    do {
        n = write(STDERR_FILENO, json, len);
        if ((ssize_t)n < 0) return;
        json += n;
        len -= n;
    } while (len > 0);
}

static void emit_event(int type, uint64_t addr, uint64_t addr2, uint64_t size,
                        const void *sample, int sample_len)
{
    if (g_depth > 0) return;
    g_depth++;

    uint64_t ts = now_ns();
    pid_t pid = getpid();
    long tid = (long)syscall(SYS_gettid);

    int off = snprintf(g_buf, BUF_SIZE,
        "{\"ts\":%llu,\"pid\":%d,\"tid\":%ld,\"type\":%d,"
        "\"addr\":%llu,\"addr2\":%llu,\"size\":%llu",
        (unsigned long long)ts, (int)pid, tid, type,
        (unsigned long long)addr, (unsigned long long)addr2,
        (unsigned long long)size);

    if (sample && sample_len > 0 && off < BUF_SIZE - 80) {
        int slen = sample_len < SAMPLE_SIZE ? sample_len : SAMPLE_SIZE;
        off += snprintf(g_buf + off, BUF_SIZE - off, ",\"sample\":[");
        for (int i = 0; i < slen && off < BUF_SIZE - 10; i++) {
            off += snprintf(g_buf + off, BUF_SIZE - off, "%s%d",
                           i > 0 ? "," : "",
                           (unsigned char)((const char*)sample)[i]);
        }
        if (off < BUF_SIZE - 4) {
            off += snprintf(g_buf + off, BUF_SIZE - off, "]");
        }
    }

    if (off < BUF_SIZE - 3) {
        off += snprintf(g_buf + off, BUF_SIZE - off, "}\n");
    }
    emit(g_buf);
    g_depth--;
}

/* --- Real function pointers --- */
typedef void *(*real_malloc_t)(size_t);
typedef void (*real_free_t)(void *);
typedef void *(*real_calloc_t)(size_t, size_t);
typedef void *(*real_realloc_t)(void *, size_t);
typedef void *(*real_memcpy_t)(void *, const void *, size_t);
typedef void *(*real_memmove_t)(void *, const void *, size_t);
typedef char *(*real_strdup_t)(const char *);
typedef char *(*real_strndup_t)(const char *, size_t);
typedef ssize_t (*real_sendto_t)(int, const void *, size_t, int,
                                  const struct sockaddr *, socklen_t);
typedef ssize_t (*real_recvfrom_t)(int, void *, size_t, int,
                                    struct sockaddr *, socklen_t *);
typedef ssize_t (*real_send_t)(int, const void *, size_t, int);
typedef ssize_t (*real_recv_t)(int, void *, size_t, int);

static real_malloc_t  real_malloc  = NULL;
static real_free_t    real_free    = NULL;
static real_calloc_t  real_calloc  = NULL;
static real_realloc_t real_realloc = NULL;
static real_memcpy_t  real_memcpy  = NULL;
static real_memmove_t real_memmove = NULL;
static real_strdup_t  real_strdup  = NULL;
static real_strndup_t real_strndup = NULL;
static real_sendto_t  real_sendto  = NULL;
static real_recvfrom_t real_recvfrom = NULL;
static real_send_t    real_send    = NULL;
static real_recv_t    real_recv    = NULL;

static void resolve_symbols(void) {
    if (real_malloc) return;
    real_malloc   = (real_malloc_t)dlsym(RTLD_NEXT, "malloc");
    real_free     = (real_free_t)dlsym(RTLD_NEXT, "free");
    real_calloc   = (real_calloc_t)dlsym(RTLD_NEXT, "calloc");
    real_realloc  = (real_realloc_t)dlsym(RTLD_NEXT, "realloc");
    real_memcpy   = (real_memcpy_t)dlsym(RTLD_NEXT, "memcpy");
    real_memmove  = (real_memmove_t)dlsym(RTLD_NEXT, "memmove");
    real_strdup   = (real_strdup_t)dlsym(RTLD_NEXT, "strdup");
    real_strndup  = (real_strndup_t)dlsym(RTLD_NEXT, "strndup");
    real_sendto   = (real_sendto_t)dlsym(RTLD_NEXT, "sendto");
    real_recvfrom = (real_recvfrom_t)dlsym(RTLD_NEXT, "recvfrom");
    real_send     = (real_send_t)dlsym(RTLD_NEXT, "send");
    real_recv     = (real_recv_t)dlsym(RTLD_NEXT, "recv");
    g_enabled = 1;
}

/* --- Hook implementations --- */

void *malloc(size_t size) {
    resolve_symbols();
    void *ptr = real_malloc(size);
    if (g_enabled && size > 0) {
        emit_event(EV_MALLOC | EVENT_RET, (uint64_t)(unsigned long)ptr, 0, size, ptr, size);
    }
    return ptr;
}

void free(void *ptr) {
    resolve_symbols();
    if (ptr && g_enabled) {
        emit_event(EV_FREE, (uint64_t)(unsigned long)ptr, 0, 0, NULL, 0);
    }
    real_free(ptr);
}

void *calloc(size_t count, size_t size) {
    resolve_symbols();
    void *ptr = real_calloc(count, size);
    if (g_enabled && size > 0 && count > 0) {
        emit_event(EV_CALLOC | EVENT_RET, (uint64_t)(unsigned long)ptr, 0, count * size, ptr, count * size);
    }
    return ptr;
}

void *realloc(void *ptr, size_t size) {
    resolve_symbols();
    void *new_ptr = real_realloc(ptr, size);
    if (g_enabled) {
        if (ptr && g_enabled) {
            emit_event(EV_FREE, (uint64_t)(unsigned long)ptr, 0, 0, NULL, 0);
        }
        if (new_ptr && size > 0 && g_enabled) {
            emit_event(EV_MALLOC | EVENT_RET, (uint64_t)(unsigned long)new_ptr, 0, size, new_ptr, size);
        }
    }
    return new_ptr;
}

void *memcpy(void *dest, const void *src, size_t n) {
    resolve_symbols();
    if (n > 0 && g_enabled) {
        emit_event(EV_MEMCPY, (uint64_t)(unsigned long)dest,
                   (uint64_t)(unsigned long)src, n, src, n);
    }
    return real_memcpy(dest, src, n);
}

void *memmove(void *dest, const void *src, size_t n) {
    resolve_symbols();
    if (n > 0 && g_enabled) {
        emit_event(EV_MEMMOVE, (uint64_t)(unsigned long)dest,
                   (uint64_t)(unsigned long)src, n, src, n);
    }
    return real_memmove(dest, src, n);
}

char *strdup(const char *s) {
    resolve_symbols();
    char *ptr = real_strdup(s);
    if (ptr && g_enabled) {
        size_t len = strlen(ptr) + 1;
        emit_event(EV_MALLOC | EVENT_RET, (uint64_t)(unsigned long)ptr, 0, len, ptr, len);
    }
    return ptr;
}

char *strndup(const char *s, size_t n) {
    resolve_symbols();
    char *ptr = real_strndup(s, n);
    if (ptr && g_enabled) {
        size_t len = strlen(ptr) + 1;
        emit_event(EV_MALLOC | EVENT_RET, (uint64_t)(unsigned long)ptr, 0, len, ptr, len);
    }
    return ptr;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen)
{
    resolve_symbols();
    ssize_t ret = real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
    if (ret > 0 && g_enabled) {
        emit_event(EV_SENDTO, (uint64_t)(unsigned long)buf, (uint64_t)sockfd, ret, buf, ret);
    }
    return ret;
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen)
{
    resolve_symbols();
    ssize_t ret = real_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
    if (ret > 0 && g_enabled) {
        emit_event(EV_RECVFROM, (uint64_t)(unsigned long)buf, (uint64_t)sockfd, ret, buf, ret);
    }
    return ret;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
    resolve_symbols();
    ssize_t ret = real_send(sockfd, buf, len, flags);
    if (ret > 0 && g_enabled) {
        emit_event(EV_SEND, (uint64_t)(unsigned long)buf, (uint64_t)sockfd, ret, buf, ret);
    }
    return ret;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
    resolve_symbols();
    ssize_t ret = real_recv(sockfd, buf, len, flags);
    if (ret > 0 && g_enabled) {
        emit_event(EV_RECV, (uint64_t)(unsigned long)buf, (uint64_t)sockfd, ret, buf, ret);
    }
    return ret;
}
