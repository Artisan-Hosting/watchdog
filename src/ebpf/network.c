#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "macros.h" 

struct traffic_stats {
    __u64 rx_bytes;
    __u64 tx_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32); // PID
    __type(value, struct traffic_stats);
} pid_traffic_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64); // Cgroup ID
    __type(value, struct traffic_stats);
} cgroup_traffic_map SEC(".maps");

// Common function to update stats
static __always_inline void update_stats(__u32 pid, ssize_t bytes, bool is_tx) {
    if (bytes <= 0)
        return;

    struct traffic_stats zero = {};
    struct traffic_stats *stats = bpf_map_lookup_elem(&pid_traffic_map, &pid);
    if (!stats) {
        bpf_map_update_elem(&pid_traffic_map, &pid, &zero, BPF_ANY);
        stats = bpf_map_lookup_elem(&pid_traffic_map, &pid);
        if (!stats)
            return;
    }

    if (is_tx) {
        __sync_fetch_and_add(&stats->tx_bytes, bytes);
    } else {
        __sync_fetch_and_add(&stats->rx_bytes, bytes);
    }
}

// TCP send
SEC("kprobe/tcp_sendmsg")
int bpf_tcp_sendmsg(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    ssize_t size = PT_REGS_PARM3(ctx);
    bpf_printk("tcp_sendmsg: pid=%d, size=%d\n", pid, size);
    update_stats(pid, size, true);
    return 0;
}

// TCP receive
SEC("kprobe/tcp_cleanup_rbuf")
int bpf_tcp_recvmsg(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    int copied = PT_REGS_PARM2(ctx);
    // bpf_printk("tcp_recvmsg: pid=%d, size=%d\n", pid, size);
    update_stats(pid, copied, false);
    return 0;
}

// UDP send
SEC("kprobe/udp_sendmsg")
int bpf_udp_sendmsg(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    ssize_t size = PT_REGS_PARM3(ctx);
    bpf_printk("udp_sendmsg: pid=%d, size=%d\n", pid, size);
    update_stats(pid, size, true);
    return 0;
}

// UDP receive
SEC("kprobe/udp_recvmsg")
int bpf_udp_recvmsg(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    int copied = PT_REGS_PARM4(ctx);
    // bpf_printk("upp_recvmsg: pid=%d, size=%d\n", pid, size);
    update_stats(pid, copied, false);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
