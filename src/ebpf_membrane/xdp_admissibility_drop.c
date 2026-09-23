// SMAOS eBPF Kernel Membrane (Admissibility Drop)
// A tiny XDP (eXpress Data Path) program that drops packets targeting a specific port 
// when the admissibility flag (simulated via an eBPF map) is set to DENY.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

// BPF Map: Stores the admissibility state for target ports
// Key: Destination Port (u16)
// Value: Admissibility Status (0 = ALLOW, 1 = DENY)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);
    __type(value, __u32);
} admissibility_map SEC(".maps");

SEC("xdp")
int xdp_membrane_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    // Only inspect IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Only inspect TCP packets
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Parse TCP header
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u16 dest_port = bpf_ntohs(tcp->dest);

    // Check if the destination port is in our admissibility map
    __u32 *deny_flag = bpf_map_lookup_elem(&admissibility_map, &dest_port);
    
    if (deny_flag && *deny_flag == 1) {
        // Log the kernel-level drop for audit tracing
        bpf_printk("SMAOS eBPF: Admissibility DENIED. Dropping packet to port %d\\n", dest_port);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "Apache-2.0";
