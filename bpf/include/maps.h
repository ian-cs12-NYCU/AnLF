#ifndef ANLF_MAPS_H
#define ANLF_MAPS_H

#include <bpf/bpf_helpers.h>

struct ue_metrics_t {
    // Uplink metrics
    __u64 packet_count;
    __u64 byte_count;
    
    __u64 tcp_count;
    __u64 udp_count;
    __u64 icmp_count;
    
    __u64 syn_count;
    __u64 rst_count;
    
    __u64 new_flow_count;
    
    __u64 dst_bitmap;
    
    // Downlink metrics
    __u64 dl_packet_count;
    __u64 dl_byte_count;
    
    __u64 dl_tcp_count;
    __u64 dl_ack_count;  // TCP ACK packets in downlink
};

// Flow tracking key (5-tuple for TCP/UDP flows)
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  pad[3];  // Padding for alignment
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct ue_metrics_t);
    __uint(max_entries, 10240);
} ue_metrics_map SEC(".maps");

// LRU hash map for flow tracking - automatically evicts old flows
// This tracks existing flows to identify new connections
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key);
    __type(value, __u8);  // Simple presence marker (value doesn't matter)
    __uint(max_entries, 65536);  // 64K flows
} flow_tracking_map SEC(".maps");

// Top-N statistics maps for 10.201.0.0/16 subnet only
// Subnet statistics (/24 subnet prefix)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);   // subnet prefix (e.g., 10.201.1.0 for /24)
    __type(value, __u64); // byte count
    __uint(max_entries, 256);  // 256 subnets max in /16
} subnet_stats_map SEC(".maps");

// Port statistics (destination port)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);   // destination port
    __type(value, __u64); // byte count
    __uint(max_entries, 65536);  // all possible ports
} port_stats_map SEC(".maps");

// IP statistics (single destination IP)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);   // destination IP
    __type(value, __u64); // byte count
    __uint(max_entries, 65536);  // 64K IPs
} ip_stats_map SEC(".maps");

// ============================================================================
// TLS DPI Support
// ============================================================================

// TLS event structure for transmitting to userspace
struct tls_event_t {
    __u32 src_ip;        // Network Byte Order
    __u32 dst_ip;        // Network Byte Order
    __u16 src_port;      // Network Byte Order
    __u16 dst_port;      // Network Byte Order
    __u32 payload_len;   // Actual payload length
    __u8  payload[10];   // Captured payload: min(payload_len, 10)
};

// Perf Buffer for streaming TLS events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} tls_events SEC(".maps");

// TLS capture state tracking (LRU map with automatic eviction)
// For each flow, track whether we've already captured the TLS hello
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key);
    __type(value, __u8);  // Bitmask: 0x01=Seen, 0x02=TLS_Captured
    __uint(max_entries, 65536);
} tls_state_map SEC(".maps");

#endif
