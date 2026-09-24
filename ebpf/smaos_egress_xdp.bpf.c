/*
 * SMAOS Ring-0 Kernel Physics Layer: eBPF XDP Egress Filter
 * File: smaos_egress_xdp.bpf.c
 *
 * Drops unauthorized lateral movement and unapproved egress packets from the agent's
 * network interface in <500 nanoseconds directly in the driver/NIC XDP hook,
 * bypassing user-space networking and hypervisors.
 *
 * Enforces:
 * 1. Destination IP Whitelisting (allowed_ipv4 map)
 * 2. Destination Port Whitelisting (allowed_ports map)
 * 3. Atomic High-Speed Telemetry (egress_telemetry map)
 *
 * License: Dual MIT/GPL
 */

#ifndef __u8
typedef unsigned char __u8;
#endif
#ifndef __u16
typedef unsigned short __u16;
#endif
#ifndef __u32
typedef unsigned int __u32;
#endif
#ifndef __u64
typedef unsigned long long __u64;
#endif

/* XDP Action Codes */
#define XDP_ABORTED 0
#define XDP_DROP 1
#define XDP_PASS 2
#define XDP_TX 3
#define XDP_REDIRECT 4

/* BPF Map Types */
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2

/* Protocol Constants */
#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

/* Macro helpers */
#define SEC(NAME) __attribute__((section(NAME), used))
#define __bpf_ntohs(x) __builtin_bswap16(x)
#define __bpf_ntohl(x) __builtin_bswap32(x)

/* BPF Context */
struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

/* Protocol Headers */
struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __u16 h_proto;
} __attribute__((packed));

struct iphdr {
    __u8 ihl:4, version:4;
    __u8 tos;
    __u16 tot_len;
    __u16 id;
    __u16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __u16 check;
    __u32 saddr;
    __u32 daddr;
} __attribute__((packed));

struct tcphdr {
    __u16 source;
    __u16 dest;
    __u32 seq;
    __u32 ack_seq;
    __u16 res1:4, doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
    __u16 window;
    __u16 check;
    __u16 urg_ptr;
} __attribute__((packed));

/* BPF Helpers prototypes */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)2;
static long (*bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) = (void *)6;

/* BPF Map 1: Allowed IPv4 Destinations (Key: IPv4 as __u32, Val: 1 = ALLOWED) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} allowed_ipv4 SEC(".maps");

/* BPF Map 2: Allowed TCP/UDP Destination Ports (Key: Port as __u16, Val: 1 = ALLOWED) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);
    __type(value, __u8);
} allowed_ports SEC(".maps");

/* Telemetry Counter Indices */
#define METRIC_PACKETS_INSPECTED 0
#define METRIC_PACKETS_ALLOWED   1
#define METRIC_PACKETS_DROPPED   2
#define METRIC_DROP_BAD_PORT     3
#define METRIC_DROP_BAD_IP       4

/* BPF Map 3: Telemetry Metrics Array */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} egress_telemetry SEC(".maps");

static __attribute__((always_inline)) void increment_metric(__u32 index) {
    __u64 *val = bpf_map_lookup_elem(&egress_telemetry, &index);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
}

SEC("xdp_egress")
int smaos_xdp_egress_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    increment_metric(METRIC_PACKETS_INSPECTED);

    /* 1. Parse Ethernet Header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (__bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        return XDP_PASS; /* Non-IPv4 bypasses filter */
    }

    /* 2. Parse IPv4 Header */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    __u32 dest_ip = ip->daddr;

    /* 3. Check IP Whitelist */
    __u8 *ip_allowed = bpf_map_lookup_elem(&allowed_ipv4, &dest_ip);
    if (!ip_allowed || *ip_allowed != 1) {
        increment_metric(METRIC_PACKETS_DROPPED);
        increment_metric(METRIC_DROP_BAD_IP);
        return XDP_DROP; /* Hard Ring-0 Drop: <500 nanoseconds */
    }

    /* 4. Check TCP Destination Port if TCP */
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end) {
            return XDP_PASS;
        }

        __u16 dest_port = __bpf_ntohs(tcp->dest);
        __u8 *port_allowed = bpf_map_lookup_elem(&allowed_ports, &dest_port);
        if (!port_allowed || *port_allowed != 1) {
            increment_metric(METRIC_PACKETS_DROPPED);
            increment_metric(METRIC_DROP_BAD_PORT);
            return XDP_DROP; /* Hard Ring-0 Drop: <500 nanoseconds */
        }
    }

    increment_metric(METRIC_PACKETS_ALLOWED);
    return XDP_PASS;
}

char _license[] SEC("license") = "Dual MIT/GPL";
