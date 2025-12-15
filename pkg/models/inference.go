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

// InferenceResult represents the result from LLM server (simplified format)
type InferenceResult struct {
	Supi         string  `json:"supi"`
	AnomalyScore float64 `json:"anomaly_score"` // 0.0 - 1.0
}

// BatchInferenceResult represents batch results from LLM server (simplified format)
type BatchInferenceResult struct {
	Results []*InferenceResult `json:"results"` // Individual UE results
}
