/* DataTrace BPF Agent
 *
 * Hooks libc uprobes (malloc, free, calloc, realloc, memcpy, memmove,
 * sendto, recvfrom, send, recv, write, read, open, close)
 * and emits JSON events to stdout.
 *
 * Build: clang -O2 -target bpf -c tracer.c -o tracer.o
 *        then use bpftool or custom loader
 *
 * For simplicity, this version uses a two-step approach:
 *   1) BPF programs trace events into a perf/ring buffer
 *   2) User-space loader reads ring buffer and prints JSON
 *
 * We generate a skeleton via bpftool gen skeleton.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/syscall.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* ------------------------------------------------------------------- */
/* BPF program source (inline, compiled separately via clang -target bpf) */
/* ------------------------------------------------------------------- */
static const char bpf_program_source[] =
"#include <linux/bpf.h>\n"
"#include <bpf/bpf_helpers.h>\n"
"#include <bpf/bpf_tracing.h>\n"
"\n"
"struct event {\n"
"    __u64   timestamp_ns;\n"
"    __u64   addr;\n"
"    __u64   addr2;\n"
"    __u64   size;\n"
"    __u32   pid;\n"
"    __u32   tid;\n"
"    __u32   event_type;\n"
"};\n"
"\n"
"struct {\n"
"    __uint(type, BPF_MAP_TYPE_RINGBUF);\n"
"    __uint(max_entries, 1 << 24);\n"
"} events SEC(\".maps\");\n"
"\n"
"/* Event types */\n"
"enum {\n"
"    EVENT_MALLOC  = 1,\n"
"    EVENT_FREE    = 2,\n"
"    EVENT_CALLOC  = 3,\n"
"    EVENT_REALLOC = 4,\n"
"    EVENT_MEMCPY  = 5,\n"
"    EVENT_MEMMOVE = 6,\n"
"    EVENT_SENDTO  = 7,\n"
"    EVENT_RECVFROM= 8,\n"
"    EVENT_WRITE   = 9,\n"
"    EVENT_READ    = 10,\n"
"    EVENT_OPEN    = 11,\n"
"    EVENT_CLOSE   = 12,\n"
"};\n"
"\n"
"static __always_inline struct event* reserve_event() {\n"
"    return bpf_ringbuf_reserve(&events, sizeof(struct event), 0);\n"
"}\n"
"\n"
"/* malloc(size) */\n"
"SEC(\"uprobe/malloc\")\n"
"int uprobe_malloc(struct pt_regs *ctx) {\n"
"    struct event *e = reserve_event();\n"
"    if (!e) return 0;\n"
"    e->event_type = EVENT_MALLOC;\n"
"    e->size = PT_REGS_PARM1(ctx);\n"
"    e->addr = 0;\n"
"    e->addr2 = 0;\n"
"    e->pid = bpf_get_current_pid_tgid() >> 32;\n"
"    e->tid = (__u32)bpf_get_current_pid_tgid();\n"
"    e->timestamp_ns = bpf_ktime_get_ns();\n"
"    bpf_ringbuf_submit(e, 0);\n"
"    return 0;\n"
"}\n"
"\n"
"/* malloc return - captures the allocated address */\n"
"SEC(\"uretprobe/malloc\")\n"
"int uprobe_malloc_ret(struct pt_regs *ctx) {\n"
"    struct event *e = reserve_event();\n"
"    if (!e) return 0;\n"
"    e->event_type = EVENT_MALLOC | 0x1000; /* return event marker */\n"
"    e->addr = PT_REGS_RC(ctx);\n"
"    e->size = 0;\n"
"    e->addr2 = 0;\n"
"    e->pid = bpf_get_current_pid_tgid() >> 32;\n"
"    e->tid = (__u32)bpf_get_current_pid_tgid();\n"
"    e->timestamp_ns = bpf_ktime_get_ns();\n"
"    bpf_ringbuf_submit(e, 0);\n"
"    return 0;\n"
"}\n"
"\n"
"/* free(ptr) */\n"
"SEC(\"uprobe/free\")\n"
"int uprobe_free(struct pt_regs *ctx) {\n"
"    struct event *e = reserve_event();\n"
"    if (!e) return 0;\n"
"    e->event_type = EVENT_FREE;\n"
"    e->addr = PT_REGS_PARM1(ctx);\n"
"    e->size = 0;\n"
"    e->addr2 = 0;\n"
"    e->pid = bpf_get_current_pid_tgid() >> 32;\n"
"    e->tid = (__u32)bpf_get_current_pid_tgid();\n"
"    e->timestamp_ns = bpf_ktime_get_ns();\n"
"    bpf_ringbuf_submit(e, 0);\n"
"    return 0;\n"
"}\n"
"\n"
"/* calloc(nmemb, size) */\n"
"SEC(\"uprobe/calloc\")\n"
"int uprobe_calloc(struct pt_regs *ctx) {\n"
"    struct event *e = reserve_event();\n"
"    if (!e) return 0;\n"
"    e->event_type = EVENT_CALLOC;\n"
"    e->addr = PT_REGS_PARM1(ctx);  /* nmemb */\n"
"    e->addr2 = PT_REGS_PARM2(ctx); /* size */\n"
"    e->size = 0;\n"
"    e->pid = bpf_get_current_pid_tgid() >> 32;\n"
"    e->tid = (__u32)bpf_get_current_pid_tgid();\n"
"    e->timestamp_ns = bpf_ktime_get_ns();\n"
"    bpf_ringbuf_submit(e, 0);\n"
"    return 0;\n"
"}\n"
"\n"
"/* calloc return */\n"
"SEC(\"uretprobe/calloc\")\n"
"int uprobe_calloc_ret(struct pt_regs *ctx) {\n"
"    struct event *e = reserve_event();\n"
"    if (!e) return 0;\n"
"    e->event_type = EVENT_CALLOC | 0x1000;\n"
"    e->addr = PT_REGS_RC(ctx);\n"
"    e->size = 0;\n"
"    e->addr2 = 0;\n"
"    e->pid = bpf_get_current_pid_tgid() >> 32;\n"
"    e->tid = (__u32)bpf_get_current_pid_tgid();\n"
"    e->timestamp_ns = bpf_ktime_get_ns();\n"
"    bpf_ringbuf_submit(e, 0);\n"
"    return 0;\n"
"}\n"
"\n"
"/* memcpy(dst, src, size) */\n"
"SEC(\"uprobe/memcpy\")\n"
"int uprobe_memcpy(struct pt_regs *ctx) {\n"
"    struct event *e = reserve_event();\n"
"    if (!e) return 0;\n"
"    e->event_type = EVENT_MEMCPY;\n"
"    e->addr = PT_REGS_PARM1(ctx);\n"
"    e->addr2 = PT_REGS_PARM2(ctx);\n"
"    e->size = PT_REGS_PARM3(ctx);\n"
"    e->pid = bpf_get_current_pid_tgid() >> 32;\n"
"    e->tid = (__u32)bpf_get_current_pid_tgid();\n"
"    e->timestamp_ns = bpf_ktime_get_ns();\n"
"    bpf_ringbuf_submit(e, 0);\n"
"    return 0;\n"
"}\n"
"\n"
"/* memmove(dst, src, size) */\n"
"SEC(\"uprobe/memmove\")\n"
"int uprobe_memmove(struct pt_regs *ctx) {\n"
"    struct event *e = reserve_event();\n"
"    if (!e) return 0;\n"
"    e->event_type = EVENT_MEMMOVE;\n"
"    e->addr = PT_REGS_PARM1(ctx);\n"
"    e->addr2 = PT_REGS_PARM2(ctx);\n"
"    e->size = PT_REGS_PARM3(ctx);\n"
"    e->pid = bpf_get_current_pid_tgid() >> 32;\n"
"    e->tid = (__u32)bpf_get_current_pid_tgid();\n"
"    e->timestamp_ns = bpf_ktime_get_ns();\n"
"    bpf_ringbuf_submit(e, 0);\n"
"    return 0;\n"
"}\n"
"\n"
"/* sendto(sockfd, buf, len, flags, dest_addr, addrlen) */\n"
"SEC(\"uprobe/sendto\")\n"
"int uprobe_sendto(struct pt_regs *ctx) {\n"
"    struct event *e = reserve_event();\n"
"    if (!e) return 0;\n"
"    e->event_type = EVENT_SENDTO;\n"
"    e->addr = PT_REGS_PARM1(ctx);   /* sockfd */\n"
"    e->addr2 = PT_REGS_PARM2(ctx);  /* buf */\n"
"    e->size = PT_REGS_PARM3(ctx);   /* len */\n"
"    e->pid = bpf_get_current_pid_tgid() >> 32;\n"
"    e->tid = (__u32)bpf_get_current_pid_tgid();\n"
"    e->timestamp_ns = bpf_ktime_get_ns();\n"
"    bpf_ringbuf_submit(e, 0);\n"
"    return 0;\n"
"}\n"
"\n"
"/* recvfrom(sockfd, buf, len, flags, src_addr, addrlen) */\n"
"SEC(\"uprobe/recvfrom\")\n"
"int uprobe_recvfrom(struct pt_regs *ctx) {\n"
"    struct event *e = reserve_event();\n"
"    if (!e) return 0;\n"
"    e->event_type = EVENT_RECVFROM;\n"
"    e->addr = PT_REGS_PARM1(ctx);   /* sockfd */\n"
"    e->addr2 = PT_REGS_PARM2(ctx);  /* buf */\n"
"    e->size = PT_REGS_PARM3(ctx);   /* len */\n"
"    e->pid = bpf_get_current_pid_tgid() >> 32;\n"
"    e->tid = (__u32)bpf_get_current_pid_tgid();\n"
"    e->timestamp_ns = bpf_ktime_get_ns();\n"
"    bpf_ringbuf_submit(e, 0);\n"
"    return 0;\n"
"}\n"
"\n"
"char _license[] SEC(\"license\") = \"GPL\";\n";

/* ------------------------------------------------------------------- */
/* User-space loader                                                   */
/* ------------------------------------------------------------------- */

static volatile int g_stop = 0;

static void handle_signal(int sig) {
    g_stop = 1;
}

struct event_t {
    long long timestamp_ns;
    unsigned long long addr;
    unsigned long long addr2;
    unsigned long long size;
    unsigned int pid;
    unsigned int tid;
    unsigned int event_type;
};

static void print_event_json(const struct event_t* e) {
    printf("{\"ts\":%llu,\"pid\":%u,\"tid\":%u,\"type\":%u,"
           "\"addr\":%llu,\"addr2\":%llu,\"size\":%llu}\n",
           (unsigned long long)e->timestamp_ns,
           e->pid, e->tid, e->event_type,
           (unsigned long long)e->addr,
           (unsigned long long)e->addr2,
           (unsigned long long)e->size);
    fflush(stdout);
}

static int handle_event(void* ctx, void* data, size_t data_sz) {
    const struct event_t* e = (const struct event_t*)data;
    print_event_json(e);
    return 0;
}

int main(int argc, char** argv) {
    struct bpf_object* bpf_obj = NULL;
    struct bpf_program* prog;
    struct bpf_link* link;
    struct ring_buffer* rb = NULL;
    int pid = 0;
    int err;

    if (argc > 1) pid = atoi(argv[1]);

    if (pid <= 0) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    /* Compile BPF program inline */
    /* Write BPF source to temp file */
    const char* src_path = "/tmp/dtracesrc.bpf.c";
    const char* obj_path = "/tmp/dtracesrc.bpf.o";
    {
        FILE* f = fopen(src_path, "w");
        if (!f) { perror("fopen src"); return 1; }
        fwrite(bpf_program_source, 1, strlen(bpf_program_source), f);
        fclose(f);
    }

    /* Compile with clang */
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "clang -O2 -target bpf -I/usr/include/bpf "
             "-c %s -o %s 2>/dev/null",
             src_path, obj_path);
    int ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "clang compilation failed (ret=%d)\n", ret);
        return 1;
    }

    /* Load BPF object */
    bpf_obj = bpf_object__open(obj_path);
    if (!bpf_obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    err = bpf_object__load(bpf_obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(-err));
        goto cleanup;
    }

    /* Attach uprobes */

    /* Helper: find libc path */
    FILE* fp = popen("ldconfig -p | grep 'libc.so' | head -1 | awk '{print $NF}'", "r");
    char libc_path[256] = "/usr/lib/libc.so.6";
    if (fp) {
        if (fgets(libc_path, sizeof(libc_path), fp)) {
            char* nl = strchr(libc_path, '\n');
            if (nl) *nl = 0;
        }
        pclose(fp);
    }

    struct {
        const char* func;
        const char* sec;
        int is_ret;
    } probes[] = {
        {"malloc", "uprobe/malloc", 0},
        {"malloc", "uretprobe/malloc", 1},
        {"free", "uprobe/free", 0},
        {"calloc", "uprobe/calloc", 0},
        {"calloc", "uretprobe/calloc", 1},
        {"memcpy", "uprobe/memcpy", 0},
        {"memmove", "uprobe/memmove", 0},
        {"sendto", "uprobe/sendto", 0},
        {"recvfrom", "uprobe/recvfrom", 0},
        {NULL, NULL, 0}
    };

    for (int i = 0; probes[i].func; i++) {
        prog = bpf_object__find_program_by_name(bpf_obj, probes[i].sec);
        if (!prog) {
            fprintf(stderr, "Program %s not found\n", probes[i].sec);
            continue;
        }

        if (probes[i].is_ret)
            link = bpf_program__attach_uretprobe(prog, pid, libc_path,
                                                  probes[i].func, NULL);
        else
            link = bpf_program__attach_uprobe(prog, pid, libc_path,
                                               probes[i].func, NULL);

        if (!link) {
            fprintf(stderr, "Failed to attach %s (func=%s pid=%d)\n",
                    probes[i].sec, probes[i].func, pid);
        } else {
            printf("{\"event\":\"attached\",\"func\":\"%s\",\"probe\":\"%s\"}\n",
                   probes[i].func, probes[i].sec);
            fflush(stdout);
        }
    }

    /* Find ring buffer map */
    struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj, "events");
    if (!map) {
        fprintf(stderr, "Ring buffer map 'events' not found\n");
        goto cleanup;
    }

    int map_fd = bpf_map__fd(map);

    /* Set up ring buffer consumer */
    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    /* Signal ready */
    printf("{\"event\":\"ready\",\"pid\":%d}\n", pid);
    fflush(stdout);

    /* Event loop */
    while (!g_stop) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Poll error: %s\n", strerror(-err));
            break;
        }
    }

cleanup:
    if (rb) ring_buffer__free(rb);
    if (bpf_obj) bpf_object__close(bpf_obj);
    printf("{\"event\":\"done\"}\n");
    fflush(stdout);
    return 0;
}
