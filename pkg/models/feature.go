package models

// UeFeatureVector represents the per-UE feature vector for ML inference
// This is the core data structure shared across ebpf, monitor, analyzer, and exporter
type UeFeatureVector struct {
	LogPPS      float64 `json:"log_pps"`
	AvgLen      float64 `json:"avg_len_bytes"`
	IcmpRatio   float64 `json:"icmp_ratio"`
	TcpRatio    float64 `json:"tcp_ratio"`
	UdpRatio    float64 `json:"udp_ratio"`
	SynRatio    float64 `json:"syn_ratio"`
	RstRatio    float64 `json:"rst_ratio"`
	NewFlowRate float64 `json:"new_flow_rate"`
	FanOut      float64 `json:"fan_out"`
}

// UeTrafficRecord extends UeFeatureVector with metadata for data pipeline
// Used by TrafficMonitor -> FlowAnalyzer -> Exporter
type UeTrafficRecord struct {
	UeFeatureVector
	Timestamp int64  `json:"ts" csv:"timestamp"`
	Supi      string `json:"supi" csv:"supi"`
	UeIp      string `json:"ip" csv:"ue_ip"`
	PollID    uint64 `json:"-" csv:"-"` // Poll sequence number (for logging only, not exported)

	// Global network statistics for this batch window
	GlobalAvgPPS      float64 `json:"global_avg_pps" csv:"global_avg_pps"`
	GlobalAvgFlowRate float64 `json:"global_avg_flow_rate" csv:"global_avg_flow_rate"`
	GlobalAvgLen      float64 `json:"global_avg_len" csv:"global_avg_len"`
}

// GlobalNetworkStats represents aggregated statistics across all UEs in a batch
type GlobalNetworkStats struct {
	AvgLogPPS   float64 `json:"avg_log_pps"`
	AvgFlowRate float64 `json:"avg_flow_rate"`
	AvgLen      float64 `json:"avg_len"`
}

// BatchUeTrafficRecords represents a batch of UE traffic records collected in one monitoring cycle
type BatchUeTrafficRecords struct {
	Records     []*UeTrafficRecord  `json:"records"`
	Timestamp   int64               `json:"timestamp"`
	BatchSize   int                 `json:"batch_size"`
	PollID      uint64              `json:"poll_id"`      // Sequential poll number for tracking
	GlobalStats *GlobalNetworkStats `json:"global_stats"` // Global network statistics for this batch
}
