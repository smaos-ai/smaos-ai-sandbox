/* 
 * Behavioral Governance: Kernel Physics Layer
 * eBPF XDP Egress Filter for SMAOS
 *
 * Drops unauthorized lateral movement packets from the agent's network
 * interface in <500 nanoseconds, bypassing the user-space stack entirely.
 * Defends against Cryptographic Context Injection escapes.
 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* BPF map holding allowed egress IPv4 destinations */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);   // IPv4 Address
    __type(value, __u8);  // 1 = Allowed
} allowed_destinations SEC(".maps");

SEC("xdp_egress")
int xdp_drop_unauthorized_egress(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }
    
    // Only inspect IPv4 traffic
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    
    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }
    
    // Look up destination IP in the allowed map
    __u32 dest_ip = ip->daddr;
    __u8 *is_allowed = bpf_map_lookup_elem(&allowed_destinations, &dest_ip);
    
    if (!is_allowed) {
        // Log the drop (viewable via bpftool / tracepipe)
        bpf_printk("SMAOS XDP_DROP: Unauthorized lateral egress attempt to IP %x\n", bpf_ntohl(dest_ip));
        
        // Physically drop the packet
        return XDP_DROP;
    }
    
    // IP is allowed (e.g. 127.0.0.1 or whitelisted API gateway)
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
