#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

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

// Update traffic counters only for PIDs explicitly registered by user space.
static __always_inline void update_stats(__u32 pid, ssize_t bytes, bool is_tx) {
    if (bytes <= 0)
        return;

    struct traffic_stats *stats = bpf_map_lookup_elem(&pid_traffic_map, &pid);
    if (!stats)
        return;

    if (is_tx) {
        __sync_fetch_and_add(&stats->tx_bytes, bytes);
    } else {
        __sync_fetch_and_add(&stats->rx_bytes, bytes);
    }
}

// TCP send: count actual bytes sent via function return value.
SEC("kretprobe/tcp_sendmsg")
int bpf_tcp_sendmsg_ret(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    ssize_t written = PT_REGS_RC(ctx);
    update_stats(pid, written, true);
    return 0;
}

// TCP receive: count actual bytes copied to user space.
SEC("kretprobe/tcp_recvmsg")
int bpf_tcp_recvmsg_ret(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    ssize_t copied = PT_REGS_RC(ctx);
    update_stats(pid, copied, false);
    return 0;
}

// UDP send: count actual bytes sent via function return value.
SEC("kretprobe/udp_sendmsg")
int bpf_udp_sendmsg_ret(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    ssize_t written = PT_REGS_RC(ctx);
    update_stats(pid, written, true);
    return 0;
}

// UDP receive: count actual bytes copied to user space.
SEC("kretprobe/udp_recvmsg")
int bpf_udp_recvmsg_ret(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    ssize_t copied = PT_REGS_RC(ctx);
    update_stats(pid, copied, false);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
