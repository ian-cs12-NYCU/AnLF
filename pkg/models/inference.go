package models

// InferenceRequest represents data sent to LLM server for anomaly detection
type InferenceRequest struct {
	Record    *UeTrafficRecord `json:"record"`
	Timestamp int64            `json:"timestamp"`
}

// InferenceResult represents the result from LLM server
type InferenceResult struct {
	UeIp         string  `json:"ue_ip"`
	Supi         string  `json:"supi"`
	Timestamp    int64   `json:"timestamp"`
	IsAnomaly    bool    `json:"is_anomaly"`
	AnomalyScore float64 `json:"anomaly_score"` // 0.0 - 1.0
	Prediction   string  `json:"prediction"`    // "normal" or "attack"
	Confidence   float64 `json:"confidence"`    // 0.0 - 1.0
	ModelVersion string  `json:"model_version,omitempty"`
}
