//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "protocols/gtpu.h"
#include "include/maps.h"

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
#endif

char __license[] SEC("license") = "Dual MIT/GPL";

// Direction constants
#define DIRECTION_UNKNOWN 0
#define DIRECTION_UL 1
#define DIRECTION_DL 2

static __always_inline void update_ue_uplink_metrics(
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

// Update downlink metrics for a UE (identified by inner destination IP in GTP-U)
static __always_inline void update_ue_dl_metrics(
    __u32 inner_dst_ip,
    __u32 pkt_len,
    __u8 proto,
    __u8 tcp_flags)
{
    struct ue_metrics_t *metrics;
    struct ue_metrics_t new_metrics = {};
    
    metrics = bpf_map_lookup_elem(&ue_metrics_map, &inner_dst_ip);
    
    if (metrics) {
        __sync_fetch_and_add(&metrics->dl_packet_count, 1);
        __sync_fetch_and_add(&metrics->dl_byte_count, pkt_len);
        
        if (proto == IPPROTO_TCP) {
            __sync_fetch_and_add(&metrics->dl_tcp_count, 1);
            // Check if ACK flag is set (bit 4)
            if (tcp_flags & 0x10) {
                __sync_fetch_and_add(&metrics->dl_ack_count, 1);
            }
        }
    } else {
        // Create new entry with downlink metrics
        new_metrics.dl_packet_count = 1;
        new_metrics.dl_byte_count = pkt_len;
        
        if (proto == IPPROTO_TCP) {
            new_metrics.dl_tcp_count = 1;
            if (tcp_flags & 0x10) {
                new_metrics.dl_ack_count = 1;
            }
        }
        
        bpf_map_update_elem(&ue_metrics_map, &inner_dst_ip, &new_metrics, BPF_ANY);
    }
}

// ============================================================================
// TLS DPI Support Functions
// ============================================================================

// Safe payload copy with boundary checking
static __always_inline void copy_payload(__u8 *dst, __u8 *src, int len, void *data_end) {
    #pragma unroll
    for (int i = 0; i < 128; i++) {
        if (i >= len || (void *)(src + i + 1) > data_end) {
            dst[i] = 0;
            break;
        }
        dst[i] = src[i];
    }
}

// Check and capture TLS Client Hello packet
static __always_inline int check_and_capture_tls(
    struct xdp_md *ctx, 
    struct iphdr *iph, 
    struct tcphdr *tcph, 
    void *data_end) 
{
    // Calculate payload start position
    void *payload_start = (void *)tcph + (tcph->doff * 4);
    
    // 1. Basic filter: must have payload
    if (payload_start >= data_end) return 0;
    
    int payload_len = (int)(data_end - payload_start);
    if (payload_len <= 0) return 0;

    // 2. Feature filter: check TLS Handshake Header (0x16)
    if (payload_start + 1 > data_end) return 0;
    __u8 first_byte = *(__u8 *)payload_start;
    if (first_byte != 0x16) return 0;

    // 3. Prepare event
    struct tls_event_t event = {};
    event.src_ip = iph->saddr;
    event.dst_ip = iph->daddr;
    event.src_port = tcph->source;
    event.dst_port = tcph->dest;
    event.payload_len = payload_len > 128 ? 128 : payload_len;

    // 4. Copy payload (truncate to 128 bytes)
    copy_payload(event.payload, payload_start, payload_len, data_end);

    // 5. Send event to userspace (Fail-Open: ignore if buffer is full)
    if (bpf_perf_event_output(ctx, &tls_events, BPF_F_CURRENT_CPU, &event, sizeof(event)) != 0) {
        // Buffer full or other error, silently ignore
        // Original traffic statistics unaffected
    }

    return 1;  // Captured successfully
}

static __always_inline int process_inner_ip(
    struct xdp_md *ctx,
    struct iphdr *iph,
    void *data_end,
    __u8 direction)
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
    __u16 dst_port = 0;
    
    // Check if source is in UE subnet (10.60.0.0/16) for uplink
    __u32 src_ip_host = bpf_ntohl(inner_src_ip);
    __u32 ue_subnet_prefix = 0x0a3c0000;  // 10.60.0.0
    __u32 subnet_mask = 0xffff0000;       // /16 mask
    
    // Only process uplink traffic (source in UE subnet)
    // Downlink is handled by TC egress program
    if ((src_ip_host & subnet_mask) != ue_subnet_prefix) {
        // Not from UE subnet, skip
        return XDP_PASS;
    }
    
    direction = DIRECTION_UL;
    
    // Extract TCP flags and track new flows
    if (proto == IPPROTO_TCP) {
        // Use IHL (Internet Header Length) to skip IP header + options
        __u32 ip_hdr_len = iph->ihl * 4;
        struct tcphdr *tcph = (struct tcphdr *)((void *)iph + ip_hdr_len);
        if ((void *)tcph + sizeof(*tcph) <= data_end) {
            __u16 flags_word = *(__u16 *)((void *)tcph + 12);
            tcp_flags = (flags_word >> 8) & 0xFF;
            dst_port = bpf_ntohs(tcph->dest);
            
            // Check for HTTPS (Port 443) TLS capture
            if (dst_port == 443) {
                struct flow_key fkey = {};
                fkey.src_ip = inner_src_ip;
                fkey.dst_ip = inner_dst_ip;
                fkey.proto = proto;
                fkey.src_port = bpf_ntohs(tcph->source);
                fkey.dst_port = dst_port;

                __u8 *flow_state = bpf_map_lookup_elem(&tls_state_map, &fkey);
                
                // Capture TLS if not yet captured for this flow
                // Bitmask: 0x01=Seen, 0x02=TLS_Captured
                if (!flow_state || !(*flow_state & 0x02)) {
                    // Try to capture
                    if (check_and_capture_tls(ctx, iph, tcph, data_end)) {
                        // Capture succeeded, update state
                        __u8 new_state = (flow_state ? *flow_state : 0) | 0x02 | 0x01;
                        bpf_map_update_elem(&tls_state_map, &fkey, &new_state, BPF_ANY);
                    } else {
                        // Capture failed (not TLS), but mark as seen
                        if (!flow_state) {
                            __u8 init_state = 0x01;
                            bpf_map_update_elem(&tls_state_map, &fkey, &init_state, BPF_ANY);
                        }
                    }
                }
            }
            
            // Track new flows on SYN packets
            if (tcp_flags & 0x02) {
                struct flow_key fkey = {};
                fkey.src_ip = inner_src_ip;
                fkey.dst_ip = inner_dst_ip;
                fkey.proto = proto;
                fkey.src_port = bpf_ntohs(tcph->source);
                fkey.dst_port = dst_port;
                
                __u8 *existing = bpf_map_lookup_elem(&flow_tracking_map, &fkey);
                if (!existing) {
                    is_new_flow = 1;
                    __u8 marker = 1;
                    bpf_map_update_elem(&flow_tracking_map, &fkey, &marker, BPF_ANY);
                }
            }
        }
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)((void *)iph + sizeof(*iph));
        if ((void *)udph + sizeof(*udph) <= data_end) {
            dst_port = bpf_ntohs(udph->dest);
            
            struct flow_key fkey = {};
            fkey.src_ip = inner_src_ip;
            fkey.dst_ip = inner_dst_ip;
            fkey.proto = proto;
            fkey.src_port = bpf_ntohs(udph->source);
            fkey.dst_port = dst_port;
            
            __u8 *existing = bpf_map_lookup_elem(&flow_tracking_map, &fkey);
            if (!existing) {
                is_new_flow = 1;
                __u8 marker = 1;
                bpf_map_update_elem(&flow_tracking_map, &fkey, &marker, BPF_ANY);
            }
        }
    }
    
    // Update uplink metrics
    update_ue_uplink_metrics(inner_src_ip, pkt_len, proto, tcp_flags, inner_dst_ip, is_new_flow);
    
    // ============================================================================
    // Top-N Statistics for 10.201.0.0/16 subnet only
    // ============================================================================
    
    // Check if destination IP is in 10.201.0.0/16
    __u32 dst_ip_host = bpf_ntohl(inner_dst_ip);
    __u32 lab_subnet_prefix = 0x0ac90000;  // 10.201.0.0
    __u32 lab_subnet_mask = 0xffff0000;    // /16 mask
    
    if ((dst_ip_host & lab_subnet_mask) == lab_subnet_prefix) {
        // Update IP statistics
        __u64 *ip_bytes = bpf_map_lookup_elem(&ip_stats_map, &inner_dst_ip);
        if (ip_bytes) {
            __sync_fetch_and_add(ip_bytes, (__u64)pkt_len);
        } else {
            __u64 new_bytes = (__u64)pkt_len;
            bpf_map_update_elem(&ip_stats_map, &inner_dst_ip, &new_bytes, BPF_ANY);
        }
        
        // Update subnet statistics (/24)
        __u32 subnet_24 = inner_dst_ip & bpf_htonl(0xffffff00);  // Mask to /24
        __u64 *subnet_bytes = bpf_map_lookup_elem(&subnet_stats_map, &subnet_24);
        if (subnet_bytes) {
            __sync_fetch_and_add(subnet_bytes, (__u64)pkt_len);
        } else {
            __u64 new_bytes = (__u64)pkt_len;
            bpf_map_update_elem(&subnet_stats_map, &subnet_24, &new_bytes, BPF_ANY);
        }
        
        // Update port statistics (for TCP/UDP only)
        if ((proto == IPPROTO_TCP || proto == IPPROTO_UDP) && dst_port > 0) {
            __u64 *port_bytes = bpf_map_lookup_elem(&port_stats_map, &dst_port);
            if (port_bytes) {
                __sync_fetch_and_add(port_bytes, (__u64)pkt_len);
            } else {
                __u64 new_bytes = (__u64)pkt_len;
                bpf_map_update_elem(&port_stats_map, &dst_port, &new_bytes, BPF_ANY);
            }
        }
    }
    
    return XDP_PASS;
}

static __always_inline int handle_gtpu(
    struct xdp_md *ctx,
    const void *gtpuh,
    void *data_end,
    __u8 direction)
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

    return process_inner_ip(ctx, (struct iphdr *)inner, data_end, direction);
}

static __always_inline int handle_udp(
    struct xdp_md *ctx,
    struct udphdr *udph,
    void *data_end,
    __u8 direction)
{
    if ((void *)udph + sizeof(*udph) > data_end) {
        return XDP_PASS;
    }

    __u16 dest_port = bpf_ntohs(udph->dest);
    __u16 src_port = bpf_ntohs(udph->source);
    
    // GTP-U traffic on port 2152
    if (dest_port == GTP_UDP_PORT || src_port == GTP_UDP_PORT) {
        void *gtpuh = (void *)udph + sizeof(*udph);
        return handle_gtpu(ctx, gtpuh, data_end, direction);
    }

    return XDP_PASS;
}

static __always_inline int handle_ipv4(
    struct xdp_md *ctx,
    struct iphdr *iph,
    void *data_end,
    __u8 direction)
{
    if ((void *)iph + sizeof(*iph) > data_end) {
        return XDP_PASS;
    }

    if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)((void *)iph + sizeof(*iph));
        return handle_udp(ctx, udph, data_end, direction);
    }

    return XDP_PASS;
}

SEC("xdp")
int anlf_xdp_main(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    struct ethhdr *eth = data;
    
    // Try to parse as Ethernet first
    if ((void *)eth + sizeof(*eth) <= data_end) {
        __u16 eth_proto = bpf_ntohs(eth->h_proto);
        
        if (eth_proto == ETH_P_IP) {
            struct iphdr *iph = (struct iphdr *)(eth + 1);
            
            if ((void *)iph + sizeof(*iph) > data_end) {
                return XDP_PASS;
            }
            
            return handle_ipv4(ctx, iph, data_end, DIRECTION_UNKNOWN);
        }
    }
    
    // Fallback: Check if it's L3 (Raw IP) for interfaces like upfgtp
    // On upfgtp RX (ingress), we see decapsulated uplink traffic (Inner IP)
    struct iphdr *iph = data;
    if ((void *)iph + sizeof(*iph) <= data_end && iph->version == 4) {
        return process_inner_ip(ctx, iph, data_end, DIRECTION_UNKNOWN);
    }
    
    return XDP_PASS;
}

// ============================================================================
// TC Egress Program for Downlink Traffic
// ============================================================================

/**
 * @brief Process inner IP packet from GTP-U tunnel in TC context
 * 
 * @param skb Socket buffer
 * @param iph Inner IP header
 * @param data_end End of packet data
 * @return TC_ACT_OK on success
 */
static __always_inline int tc_process_inner_ip(
    struct __sk_buff *skb,
    struct iphdr *iph,
    void *data_end)
{
    if ((void *)iph + sizeof(*iph) > data_end) {
        return TC_ACT_OK;
    }
    
    if (iph->version != 4) {
        return TC_ACT_OK;
    }
    
    __u32 inner_dst_ip = iph->daddr;
    __u8 proto = iph->protocol;
    __u32 pkt_len = (__u32)(data_end - (void *)iph);
    
    // Check subnet 10.60.0.0/16 for downlink direction
    __u32 dst_ip_host = bpf_ntohl(inner_dst_ip);
    __u32 ue_subnet_prefix = 0x0a3c0000;  // 10.60.0.0
    __u32 subnet_mask = 0xffff0000;       // /16 mask
    
    // Only process if destination is in UE subnet (downlink traffic)
    if ((dst_ip_host & subnet_mask) != ue_subnet_prefix) {
        return TC_ACT_OK;
    }
    
    __u8 tcp_flags = 0;
    
    // Extract TCP flags if applicable
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)((void *)iph + sizeof(*iph));
        if ((void *)tcph + sizeof(*tcph) <= data_end) {
            __u16 flags_word = *(__u16 *)((void *)tcph + 12);
            tcp_flags = (flags_word >> 8) & 0xFF;
        }
    }
    
    // Update downlink metrics for the UE
    update_ue_dl_metrics(inner_dst_ip, pkt_len, proto, tcp_flags);
    
    return TC_ACT_OK;
}

/**
 * @brief Handle GTP-U packet in TC context
 * 
 * @param skb Socket buffer
 * @param gtpuh GTP-U header pointer
 * @param data_end End of packet data
 * @return TC_ACT_OK on success
 */
static __always_inline int tc_handle_gtpu(
    struct __sk_buff *skb,
    const void *gtpuh,
    void *data_end)
{
    const void *inner = NULL;
    __u16 gtp_msg_len = 0;
    const struct gtpu_fixed *gtp_hdr = NULL;

    if (gtpu_locate_inner_l3(gtpuh, data_end, &inner, &gtp_msg_len, &gtp_hdr) < 0) {
        return TC_ACT_OK;
    }

    if (inner + sizeof(struct iphdr) > data_end) {
        return TC_ACT_OK;
    }

    return tc_process_inner_ip(skb, (struct iphdr *)inner, data_end);
}

/**
 * @brief Handle UDP packet in TC context
 * 
 * @param skb Socket buffer
 * @param udph UDP header
 * @param data_end End of packet data
 * @return TC_ACT_OK on success
 */
static __always_inline int tc_handle_udp(
    struct __sk_buff *skb,
    struct udphdr *udph,
    void *data_end)
{
    if ((void *)udph + sizeof(*udph) > data_end) {
        return TC_ACT_OK;
    }

    __u16 dest_port = bpf_ntohs(udph->dest);
    __u16 src_port = bpf_ntohs(udph->source);
    
    // GTP-U traffic on port 2152
    if (dest_port == GTP_UDP_PORT || src_port == GTP_UDP_PORT) {
        void *gtpuh = (void *)udph + sizeof(*udph);
        return tc_handle_gtpu(skb, gtpuh, data_end);
    }

    return TC_ACT_OK;
}

/**
 * @brief TC egress program entry point for downlink traffic
 * Captures packets leaving upfgtp interface (egress path)
 * 
 * On upfgtp, egress traffic is decapsulated inner IP packets
 * going to UE devices (downlink direction).
 * 
 * @param skb Socket buffer
 * @return TC_ACT_OK to allow packet, TC_ACT_SHOT to drop
 */
SEC("tc")
int anlf_tc_egress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    // Check if packet starts with Ethernet header
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) <= data_end) {
        __u16 eth_proto = bpf_ntohs(eth->h_proto);
        
        if (eth_proto == ETH_P_IP) {
            struct iphdr *iph = (struct iphdr *)(eth + 1);
            
            if ((void *)iph + sizeof(*iph) > data_end) {
                return TC_ACT_OK;
            }
            
            if (iph->protocol == IPPROTO_UDP) {
                struct udphdr *udph = (struct udphdr *)((void *)iph + sizeof(*iph));
                return tc_handle_udp(skb, udph, data_end);
            }
        }
    }
    
    // Fallback: Check if it's raw IP (no Ethernet header)
    // This is the common case for upfgtp interface
    struct iphdr *iph = data;
    if ((void *)iph + sizeof(*iph) <= data_end && iph->version == 4) {
        if (iph->protocol == IPPROTO_UDP) {
            struct udphdr *udph = (struct udphdr *)((void *)iph + sizeof(*iph));
            return tc_handle_udp(skb, udph, data_end);
        }
        
        // For non-GTP-U traffic (direct IP to UE subnet), process as inner IP
        return tc_process_inner_ip(skb, iph, data_end);
    }
    
    return TC_ACT_OK;
}
