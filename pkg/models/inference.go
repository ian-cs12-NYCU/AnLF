package models

// InferenceResult represents the result from LLM server (single UE format)
type InferenceResult struct {
	Supi         string  `json:"supi"`
	AnomalyScore float64 `json:"anomaly_score"` // 0.0 - 1.0
	Timestamp    int64   `json:"timestamp"`     // Unix timestamp in seconds
}

// EnhancedInferenceResult extends InferenceResult with CUSUM-based risk scoring
// This is the output of the RiskScorer component
type EnhancedInferenceResult struct {
	InferenceResult         // Embed original LLM inference result
	RiskScore       float64 `json:"risk_score"`      // CUSUM risk score [0, 100]
	Status          string  `json:"status"`          // "NORMAL" or "BLOCKED"
	IsBlocked       bool    `json:"is_blocked"`      // True if UE is blocked
	AttackDetected  bool    `json:"attack_detected"` // True if LLM detected attack in this cycle
}
