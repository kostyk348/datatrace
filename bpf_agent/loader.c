/* DataTrace BPF Agent - user-space loader */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tracer.skel.h"

#define SAMPLE_SIZE 32

/* Must match struct event in tracer.bpf.c */
struct event {
    unsigned long long timestamp_ns;
    unsigned long long addr;
    unsigned long long addr2;
    unsigned long long size;
    unsigned int pid;
    unsigned int tid;
    unsigned int event_type;
    unsigned char sample[SAMPLE_SIZE];
} __attribute__((packed));

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

static volatile sig_atomic_t g_stop = 0;
static void handle_sig(int sig) { g_stop = 1; }

static int has_sample(unsigned int type) {
    int t = type & ~0x1000;
    return t == 2 || t == 6; /* free or sendto */
}

static void print_ev(const struct event *e) {
    char b64[64];
    if (has_sample(e->event_type)) {
        b64enc(e->sample, SAMPLE_SIZE, b64);
        printf("{\"ts\":%llu,\"pid\":%u,\"tid\":%u,\"type\":%u,"
               "\"addr\":%llu,\"addr2\":%llu,\"size\":%llu,"
               "\"sample_b64\":\"%s\"}\n",
               e->timestamp_ns, e->pid, e->tid, e->event_type,
               e->addr, e->addr2, e->size, b64);
    } else {
        printf("{\"ts\":%llu,\"pid\":%u,\"tid\":%u,\"type\":%u,"
               "\"addr\":%llu,\"addr2\":%llu,\"size\":%llu}\n",
               e->timestamp_ns, e->pid, e->tid, e->event_type,
               e->addr, e->addr2, e->size);
    }
    fflush(stdout);
}

static int handle_event(void *ctx, void *data, size_t sz) {
    print_ev((const struct event *)data);
    return 0;
}

int main(int argc, char **argv) {
    struct tracer_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int pid, err, map_fd;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        return 1;
    }
    pid = atoi(argv[1]);
    if (pid <= 0) {
        fprintf(stderr, "Invalid pid: %s\n", argv[1]);
        return 1;
    }

    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);

    /* Resolve libc path */
    char libc[256] = "/usr/lib/libc.so.6";
    {
        FILE *fp = popen("ldconfig -p | grep 'libc\\.so' | head -1 | awk '{print $NF}'", "r");
        if (fp) {
            if (fgets(libc, sizeof(libc), fp)) {
                char *nl = strchr(libc, '\n'); if (nl) *nl = '\0';
            }
            pclose(fp);
        }
    }

    fprintf(stderr, "[trace] using libc: %s\n", libc);
    fprintf(stderr, "[trace] targeting pid: %d\n", pid);

    skel = tracer_bpf__open();
    if (!skel) { fprintf(stderr, "Failed to open skeleton\n"); return 1; }

    err = tracer_bpf__load(skel);
    if (err) { fprintf(stderr, "Failed to load BPF: %s\n", strerror(-err)); goto out; }

    struct {
        const char *prog_name;
        const char *func;
        int retprobe;
    } tbl[] = {
        {"malloc_entry",  "malloc",   0},
        {"malloc_ret",    "malloc",   1},
        {"free_entry",    "free",     0},
        {"calloc_entry",  "calloc",   0},
        {"calloc_ret",    "calloc",   1},
        {"memcpy_entry",  "memcpy",   0},
        {"memmove_entry", "memmove",  0},
        {"sendto_entry",  "sendto",   0},
        {"recvfrom_entry","recvfrom", 0},
    };

    for (size_t i = 0; i < sizeof(tbl)/sizeof(tbl[0]); i++) {
        struct bpf_program *prog = bpf_object__find_program_by_name(skel->obj, tbl[i].prog_name);
        if (!prog) {
            fprintf(stderr, "[trace] program '%s' not found\n", tbl[i].prog_name);
            continue;
        }
        struct bpf_link *link = bpf_program__attach_uprobe(
            prog, tbl[i].retprobe, pid, libc, 0);
        if (!link) {
            fprintf(stderr, "[trace] attach %s(func=%s) FAILED\n",
                    tbl[i].prog_name, tbl[i].func);
        } else {
            printf("{\"event\":\"attached\",\"func\":\"%s\"}\n", tbl[i].func);
            fflush(stdout);
        }
    }

    map_fd = bpf_map__fd(skel->maps.events);
    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) { fprintf(stderr, "ring_buffer_new failed\n"); goto out; }

    printf("{\"event\":\"ready\",\"pid\":%d}\n", pid);
    fflush(stdout);

    while (!g_stop) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "poll error: %s\n", strerror(-err));
            break;
        }
    }

out:
    ring_buffer__free(rb);
    tracer_bpf__destroy(skel);
    printf("{\"event\":\"done\"}\n");
    return 0;
}
