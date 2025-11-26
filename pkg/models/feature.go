package models

// UeFeatureVector represents the per-UE feature vector for ML inference
// This is the core data structure shared across ebpf, monitor, analyzer, and exporter
type UeFeatureVector struct {
	LogPPS    float64 `json:"log_pps"`
	AvgLen    float64 `json:"avg_len"`
	IcmpRatio float64 `json:"icmp_ratio"`
	TcpRatio  float64 `json:"tcp_ratio"`
	UdpRatio  float64 `json:"udp_ratio"`
	SynRatio  float64 `json:"syn_ratio"`
	RstRatio  float64 `json:"rst_ratio"`
	FlowRate  float64 `json:"flow_rate"`
	FanOut    float64 `json:"fan_out"`
}

// UeTrafficRecord extends UeFeatureVector with metadata for data pipeline
// Used by TrafficMonitor -> FlowAnalyzer -> Exporter
type UeTrafficRecord struct {
	UeFeatureVector
	Timestamp int64  `json:"ts" csv:"timestamp"`
	Supi      string `json:"supi" csv:"supi"`
	UeIp      string `json:"ip" csv:"ue_ip"`
}
