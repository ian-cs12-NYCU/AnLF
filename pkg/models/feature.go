package models

// UeFeatureVector represents the per-UE feature vector for ML inference
// This is the core data structure shared across ebpf, monitor, analyzer, and exporter
type UeFeatureVector struct {
	// Uplink features
	UlLogPPS    float64 `json:"ul_log_pps"`
	AvgLen      float64 `json:"ul_avg_len"`
	IcmpRatio   float64 `json:"icmp_ratio"`
	TcpRatio    float64 `json:"tcp_ratio"`
	UdpRatio    float64 `json:"udp_ratio"`
	SynRatio    float64 `json:"syn_ratio"`
	RstRatio    float64 `json:"rst_ratio"`
	NewFlowRate float64 `json:"new_flow_rate"`
	FanOut      float64 `json:"fan_out"`

	// Downlink features (Directional Symmetry & Protocol State)
	DlLogPPS  float64 `json:"dl_log_pps"` // Downlink log10(packets per second)
	DlAvgLen  float64 `json:"dl_avg_len"` // Downlink average packet length
	PPSRatio  float64 `json:"pps_ratio"`  // DL/UL PPS ratio
	ByteRatio float64 `json:"byte_ratio"` // DL/UL byte ratio
	AckRatio  float64 `json:"ack_ratio"`  // ACK packets ratio in DL TCP traffic
}

// UeTrafficRecord extends UeFeatureVector with metadata for data pipeline
// Used by TrafficMonitor -> FlowAnalyzer -> Exporter
type UeTrafficRecord struct {
	UeFeatureVector
	Timestamp int64  `json:"ts" csv:"timestamp"`
	Supi      string `json:"supi" csv:"supi"`
	UeIp      string `json:"ip" csv:"ue_ip"`
	PollID    uint64 `json:"-" csv:"-"` // Poll sequence number (for logging only, not exported)

	// Global network statistics for this batch window (uplink)
	GlobalUlLogPPS    float64 `json:"global_ul_log_pps" csv:"global_ul_log_pps"`       // Renamed from GlobalAvgPPS for clarity
	GlobalDlLogPPS    float64 `json:"global_dl_log_pps" csv:"global_dl_log_pps"`       // Downlink log PPS
	GlobalUlAvgLen    float64 `json:"global_ul_avg_len" csv:"global_ul_avg_len"`       // Renamed from GlobalAvgUlLen
	GlobalDlAvgLen    float64 `json:"global_dl_avg_len" csv:"global_dl_avg_len"`       // Downlink average length
	GlobalPPSRatio    float64 `json:"global_pps_ratio" csv:"global_pps_ratio"`         // Renamed from GlobalAvgPPSRatio
	GlobalByteRatio   float64 `json:"global_byte_ratio" csv:"global_byte_ratio"`       // Renamed from GlobalAvgByteRatio
	GlobalNewFlowRate float64 `json:"global_new_flow_rate" csv:"global_new_flow_rate"` // Renamed from GlobalAvgFlowRate
	GlobalFanOut      float64 `json:"global_fan_out" csv:"global_fan_out"`             // New: average fan out
}

// GlobalNetworkStats represents aggregated statistics across all UEs in a batch
type GlobalNetworkStats struct {
	// Uplink global statistics
	AvgUlLogPPS    float64 `json:"avg_ul_log_pps"`    // Average log10(PPS) across all UEs (uplink)
	AvgDlLogPPS    float64 `json:"avg_dl_log_pps"`    // Average log10(PPS) across all UEs (downlink)
	AvgUlLen       float64 `json:"avg_ul_len"`        // Average uplink packet length
	AvgDlLen       float64 `json:"avg_dl_len"`        // Average downlink packet length
	AvgPPSRatio    float64 `json:"avg_pps_ratio"`     // Average DL/UL PPS ratio
	AvgByteRatio   float64 `json:"avg_byte_ratio"`    // Average DL/UL byte ratio
	AvgNewFlowRate float64 `json:"avg_new_flow_rate"` // Average new flow rate
	AvgFanOut      float64 `json:"avg_fan_out"`       // Average fan out
}

// BatchUeTrafficRecords represents a batch of UE traffic records collected in one monitoring cycle
type BatchUeTrafficRecords struct {
	Records     []*UeTrafficRecord  `json:"records"`
	Timestamp   int64               `json:"timestamp"`
	BatchSize   int                 `json:"batch_size"`
	PollID      uint64              `json:"poll_id"`      // Sequential poll number for tracking
	GlobalStats *GlobalNetworkStats `json:"global_stats"` // Global network statistics for this batch
}
