package models

// InferenceRequest represents data sent to LLM server for anomaly detection (single UE)
type InferenceRequest struct {
	SystemPrompt string           `json:"system_prompt,omitempty"` // System prompt for LLM
	Record       *UeTrafficRecord `json:"record"`
	Timestamp    int64            `json:"timestamp"`
}

// BatchInferenceRequest represents batch data sent to LLM server for anomaly detection
type BatchInferenceRequest struct {
	SystemPrompt string             `json:"system_prompt,omitempty"` // System prompt for LLM
	Records      []*UeTrafficRecord `json:"records"`                 // Batch of UE traffic records
	Timestamp    int64              `json:"timestamp"`
	BatchSize    int                `json:"batch_size"`
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

// BatchInferenceResult represents batch results from LLM server
type BatchInferenceResult struct {
	Results      []*InferenceResult `json:"results"` // Individual UE results
	Timestamp    int64              `json:"timestamp"`
	BatchSize    int                `json:"batch_size"`
	ModelVersion string             `json:"model_version,omitempty"`
}
