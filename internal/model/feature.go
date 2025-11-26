package model

// UeFeatureVector is the common data structure for internal data flow
// Used to pass data between TrafficMonitor -> FlowAnalyzer -> Exporter
type UeFeatureVector struct {
	Timestamp int64  `json:"ts" csv:"timestamp"`
	Supi      string `json:"supi" csv:"supi"`
	UeIp      string `json:"ip" csv:"ue_ip"`

	// --- Feature values (10 features from eBPF.md) ---
	LogPPS    float64 `json:"log_pps" csv:"log_pps"`       // log10(packets_per_second)
	AvgLen    float64 `json:"avg_len" csv:"avg_len"`       // bytes / packets
	TcpRatio  float64 `json:"tcp_ratio" csv:"tcp_ratio"`   // tcp_packets / total_packets
	UdpRatio  float64 `json:"udp_ratio" csv:"udp_ratio"`   // udp_packets / total_packets
	IcmpRatio float64 `json:"icmp_ratio" csv:"icmp_ratio"` // icmp_packets / total_packets
	SynRatio  float64 `json:"syn_ratio" csv:"syn_ratio"`   // syn_count / tcp_packets
	RstRatio  float64 `json:"rst_ratio" csv:"rst_ratio"`   // rst_count / tcp_packets
	FlowRate  float64 `json:"flow_rate" csv:"flow_rate"`   // new_flows_per_second
	FanOut    float64 `json:"fan_out" csv:"fan_out"`       // dst_diversity (popcount/64)
	Entropy   float64 `json:"entropy" csv:"entropy"`       // Shannon entropy of dst bitmap
}
