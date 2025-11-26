#ifndef ANLF_MAPS_H
#define ANLF_MAPS_H

#include <bpf/bpf_helpers.h>

struct ue_metrics_t {
    __u64 packet_count;
    __u64 byte_count;
    
    __u64 tcp_count;
    __u64 udp_count;
    __u64 icmp_count;
    
    __u64 syn_count;
    __u64 rst_count;
    
    __u64 new_flow_count;
    
    __u64 dst_bitmap;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct ue_metrics_t);
    __uint(max_entries, 10240);
} ue_metrics_map SEC(".maps");

#endif
