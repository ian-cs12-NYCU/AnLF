package models

// InferenceResult represents the result from LLM server (single UE format)
type InferenceResult struct {
	Supi         string  `json:"supi"`
	AnomalyScore float64 `json:"anomaly_score"` // 0.0 - 1.0
}
