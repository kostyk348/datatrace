/* DataTrace BPF program - CO-RE uprobe tracing */
#include "vmlinux.h"

/* Suppress conflicting declaration from bpf_helpers.h */
#define bpf_stream_vprintk bpf_stream_vprintk_renamed

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* Restore in case something needs it */
#undef bpf_stream_vprintk

#define SAMPLE_SIZE 32

struct event {
    __u64   timestamp_ns;
    __u64   addr;
    __u64   addr2;
    __u64   size;
    __u32   pid;
    __u32   tid;
    __u32   event_type;
    __u8    sample[SAMPLE_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

enum {
    EVENT_MALLOC   = 1,
    EVENT_FREE     = 2,
    EVENT_CALLOC   = 3,
    EVENT_MEMCPY   = 4,
    EVENT_MEMMOVE  = 5,
    EVENT_SENDTO   = 6,
    EVENT_RECVFROM = 7,
    EVENT_RET_MASK = 0x1000,
};

static __always_inline struct event* reserve(void) {
    return bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
}

/* ---------- malloc ---------- */
SEC("uprobe")
int BPF_UPROBE(malloc_entry, size_t size) {
    struct event *e = reserve(); if (!e) return 0;
    e->event_type = EVENT_MALLOC;
    e->size = size;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = (__u32)bpf_get_current_pid_tgid();
    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uretprobe")
int BPF_URETPROBE(malloc_ret) {
    struct event *e = reserve(); if (!e) return 0;
    e->event_type = EVENT_MALLOC | EVENT_RET_MASK;
    e->addr = PT_REGS_RC(ctx);
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = (__u32)bpf_get_current_pid_tgid();
    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---------- free (content sample before free) ---------- */
SEC("uprobe")
int BPF_UPROBE(free_entry, void *ptr) {
    struct event *e = reserve(); if (!e) return 0;
    e->event_type = EVENT_FREE;
    e->addr = (__u64)ptr;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = (__u32)bpf_get_current_pid_tgid();
    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_probe_read_user(e->sample, SAMPLE_SIZE, ptr);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---------- calloc ---------- */
SEC("uprobe")
int BPF_UPROBE(calloc_entry, size_t nmemb, size_t size) {
    struct event *e = reserve(); if (!e) return 0;
    e->event_type = EVENT_CALLOC;
    e->addr = nmemb;
    e->addr2 = size;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = (__u32)bpf_get_current_pid_tgid();
    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uretprobe")
int BPF_URETPROBE(calloc_ret) {
    struct event *e = reserve(); if (!e) return 0;
    e->event_type = EVENT_CALLOC | EVENT_RET_MASK;
    e->addr = PT_REGS_RC(ctx);
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = (__u32)bpf_get_current_pid_tgid();
    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---------- memcpy ---------- */
SEC("uprobe")
int BPF_UPROBE(memcpy_entry, void *dst, void *src, size_t size) {
    struct event *e = reserve(); if (!e) return 0;
    e->event_type = EVENT_MEMCPY;
    e->addr = (__u64)dst;
    e->addr2 = (__u64)src;
    e->size = size;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = (__u32)bpf_get_current_pid_tgid();
    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---------- memmove ---------- */
SEC("uprobe")
int BPF_UPROBE(memmove_entry, void *dst, void *src, size_t size) {
    struct event *e = reserve(); if (!e) return 0;
    e->event_type = EVENT_MEMMOVE;
    e->addr = (__u64)dst;
    e->addr2 = (__u64)src;
    e->size = size;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = (__u32)bpf_get_current_pid_tgid();
    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---------- sendto (content sample of sent buffer) ---------- */
SEC("uprobe")
int BPF_UPROBE(sendto_entry, int fd, void *buf, size_t len, int flags,
               void *addr, unsigned int addrlen) {
    struct event *e = reserve(); if (!e) return 0;
    e->event_type = EVENT_SENDTO;
    e->addr = (__u64)fd;
    e->addr2 = (__u64)buf;
    e->size = len;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = (__u32)bpf_get_current_pid_tgid();
    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_probe_read_user(e->sample, SAMPLE_SIZE, buf);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---------- recvfrom ---------- */
SEC("uprobe")
int BPF_UPROBE(recvfrom_entry, int fd, void *buf, size_t len, int flags,
               void *src_addr, unsigned int *addrlen) {
    struct event *e = reserve(); if (!e) return 0;
    e->event_type = EVENT_RECVFROM;
    e->addr = (__u64)fd;
    e->addr2 = (__u64)buf;
    e->size = len;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = (__u32)bpf_get_current_pid_tgid();
    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
