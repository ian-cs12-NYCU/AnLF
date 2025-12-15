//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "protocols/gtpu.h"
#include "include/maps.h"

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

char __license[] SEC("license") = "Dual MIT/GPL";

static __always_inline void update_ue_metrics(
    __u32 inner_src_ip,
    __u32 pkt_len,
    __u8 proto,
    __u8 tcp_flags,
    __u32 inner_dst_ip,
    int is_new_flow)
{
    struct ue_metrics_t *metrics;
    struct ue_metrics_t new_metrics = {};
    
    metrics = bpf_map_lookup_elem(&ue_metrics_map, &inner_src_ip);
    
    if (metrics) {
        __sync_fetch_and_add(&metrics->packet_count, 1);
        __sync_fetch_and_add(&metrics->byte_count, pkt_len);
        
        if (proto == IPPROTO_TCP) {
            __sync_fetch_and_add(&metrics->tcp_count, 1);
            if (tcp_flags & 0x02) {
                __sync_fetch_and_add(&metrics->syn_count, 1);
            }
            if (tcp_flags & 0x04) {
                __sync_fetch_and_add(&metrics->rst_count, 1);
            }
        } else if (proto == IPPROTO_UDP) {
            __sync_fetch_and_add(&metrics->udp_count, 1);
        } else if (proto == IPPROTO_ICMP) {
            __sync_fetch_and_add(&metrics->icmp_count, 1);
        }
        
        if (is_new_flow) {
            __sync_fetch_and_add(&metrics->new_flow_count, 1);
        }
        
        // Use hash of the full destination IP to distribute across 64 bits
        // This provides better distribution than just using last byte modulo
        __u32 hash = inner_dst_ip;
        hash = hash ^ (hash >> 16);
        hash = hash ^ (hash >> 8);
        __u64 bit_position = 1ULL << (hash & 0x3F);
        __sync_fetch_and_or(&metrics->dst_bitmap, bit_position);
        
    } else {
        new_metrics.packet_count = 1;
        new_metrics.byte_count = pkt_len;
        
        if (proto == IPPROTO_TCP) {
            new_metrics.tcp_count = 1;
            if (tcp_flags & 0x02) {
                new_metrics.syn_count = 1;
            }
            if (tcp_flags & 0x04) {
                new_metrics.rst_count = 1;
            }
        } else if (proto == IPPROTO_UDP) {
            new_metrics.udp_count = 1;
        } else if (proto == IPPROTO_ICMP) {
            new_metrics.icmp_count = 1;
        }
        
        if (is_new_flow) {
            new_metrics.new_flow_count = 1;
        }
        
        // Use hash of the full destination IP to distribute across 64 bits
        __u32 hash = inner_dst_ip;
        hash = hash ^ (hash >> 16);
        hash = hash ^ (hash >> 8);
        __u64 bit_position = 1ULL << (hash & 0x3F);
        new_metrics.dst_bitmap = bit_position;
        
        bpf_map_update_elem(&ue_metrics_map, &inner_src_ip, &new_metrics, BPF_ANY);
    }
}

static __always_inline int process_inner_ip(
    struct xdp_md *ctx,
    struct iphdr *iph,
    void *data_end)
{
    if ((void *)iph + sizeof(*iph) > data_end) {
        return XDP_PASS;
    }
    
    if (iph->version != 4) {
        return XDP_PASS;
    }
    
    __u32 inner_src_ip = iph->saddr;
    __u32 inner_dst_ip = iph->daddr;
    __u8 proto = iph->protocol;
    __u32 pkt_len = (__u32)(data_end - (void *)iph);
    
    __u8 tcp_flags = 0;
    int is_new_flow = 0;
    
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)((void *)iph + sizeof(*iph));
        if ((void *)tcph + sizeof(*tcph) <= data_end) {
            __u16 flags_word = *(__u16 *)((void *)tcph + 12);
            tcp_flags = (flags_word >> 8) & 0xFF;
            
            if (tcp_flags & 0x02) {
                is_new_flow = 1;
            }
        }
    } else if (proto == IPPROTO_UDP) {
        is_new_flow = 1;
    }
    
    update_ue_metrics(inner_src_ip, pkt_len, proto, tcp_flags, inner_dst_ip, is_new_flow);
    
    return XDP_PASS;
}

static __always_inline int handle_gtpu(
    struct xdp_md *ctx,
    const void *gtpuh,
    void *data_end)
{
    const void *inner = NULL;
    __u16 gtp_msg_len = 0;
    const struct gtpu_fixed *gtp_hdr = NULL;

    if (gtpu_locate_inner_l3(gtpuh, data_end, &inner, &gtp_msg_len, &gtp_hdr) < 0) {
        return XDP_PASS;
    }

    if (inner + sizeof(struct iphdr) > data_end) {
        return XDP_PASS;
    }

    return process_inner_ip(ctx, (struct iphdr *)inner, data_end);
}

static __always_inline int handle_udp(
    struct xdp_md *ctx,
    struct udphdr *udph,
    void *data_end)
{
    if ((void *)udph + sizeof(*udph) > data_end) {
        return XDP_PASS;
    }

    __u16 dest_port = bpf_ntohs(udph->dest);
    
    if (dest_port == GTP_UDP_PORT) {
        void *gtpuh = (void *)udph + sizeof(*udph);
        return handle_gtpu(ctx, gtpuh, data_end);
    }

    return XDP_PASS;
}

static __always_inline int handle_ipv4(
    struct xdp_md *ctx,
    struct iphdr *iph,
    void *data_end)
{
    if ((void *)iph + sizeof(*iph) > data_end) {
        return XDP_PASS;
    }

    if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)((void *)iph + sizeof(*iph));
        return handle_udp(ctx, udph, data_end);
    }

    return XDP_PASS;
}

SEC("xdp")
int anlf_xdp_main(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    struct ethhdr *eth = data;
    
    if ((void *)eth + sizeof(*eth) > data_end) {
        return XDP_PASS;
    }
    
    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    
    if (eth_proto != ETH_P_IP) {
        return XDP_PASS;
    }
    
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    
    return handle_ipv4(ctx, iph, data_end);
}
