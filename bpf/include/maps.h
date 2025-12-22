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

#endif
