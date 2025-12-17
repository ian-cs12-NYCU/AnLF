package scorer

import (
	"testing"
	"time"

	"github.com/free5gc/anlf/pkg/models"
)

func TestNewRiskScorer(t *testing.T) {
	config := &RiskScorerConfig{
		MaxScore:            100.0,
		BlockThreshold:      80.0,
		UnblockThreshold:    50.0,
		LLMConfidenceCutoff: 0.7,
		HitsToBan:           2,
		SecondsToForgive:    20,
		TimeWindowSec:       1,
	}

	scorer := NewRiskScorer(config)

	if scorer == nil {
		t.Fatal("NewRiskScorer returned nil")
	}

	if scorer.attackStep != 50.0 {
		t.Errorf("attackStep = %v, want 50.0", scorer.attackStep)
	}

	if scorer.decayStep != 5.0 {
		t.Errorf("decayStep = %v, want 5.0", scorer.decayStep)
	}
}

func TestProcessInferenceResults_SingleAttack(t *testing.T) {
	config := &RiskScorerConfig{
		MaxScore:            100.0,
		BlockThreshold:      80.0,
		UnblockThreshold:    50.0,
		LLMConfidenceCutoff: 0.7,
		HitsToBan:           2,
		SecondsToForgive:    20,
		TimeWindowSec:       1,
	}

	scorer := NewRiskScorer(config)

	results := []*models.InferenceResult{
		{
			Supi:         "imsi-001",
			AnomalyScore: 0.95,
		},
	}

	enhanced := scorer.ProcessInferenceResults(results, 1)

	if len(enhanced) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(enhanced))
	}

	result := enhanced[0]

	if result.RiskScore != 50.0 {
		t.Errorf("RiskScore = %v, want 50.0", result.RiskScore)
	}

	if result.Status != "NORMAL" {
		t.Errorf("Status = %v, want NORMAL", result.Status)
	}
}

func TestProcessInferenceResults_DoubleAttack(t *testing.T) {
	config := &RiskScorerConfig{
		MaxScore:            100.0,
		BlockThreshold:      80.0,
		UnblockThreshold:    50.0,
		LLMConfidenceCutoff: 0.7,
		HitsToBan:           2,
		SecondsToForgive:    20,
		TimeWindowSec:       1,
	}

	scorer := NewRiskScorer(config)
	supi := "imsi-001"

	// First attack
	results1 := []*models.InferenceResult{
		{Supi: supi, AnomalyScore: 0.95},
	}
	scorer.ProcessInferenceResults(results1, 1)

	// Second attack
	results2 := []*models.InferenceResult{
		{Supi: supi, AnomalyScore: 0.92},
	}
	enhanced2 := scorer.ProcessInferenceResults(results2, 2)

	if enhanced2[0].RiskScore != 100.0 {
		t.Errorf("After second attack: RiskScore = %v, want 100.0", enhanced2[0].RiskScore)
	}

	if enhanced2[0].Status != "BLOCKED" {
		t.Errorf("Status = %v, want BLOCKED", enhanced2[0].Status)
	}
}

func TestProcessInferenceResults_TimeDecay(t *testing.T) {
	config := &RiskScorerConfig{
		MaxScore:            100.0,
		BlockThreshold:      80.0,
		UnblockThreshold:    50.0,
		LLMConfidenceCutoff: 0.7,
		HitsToBan:           2,
		SecondsToForgive:    20,
		TimeWindowSec:       1,
	}

	scorer := NewRiskScorer(config)
	supi := "imsi-001"

	// First attack
	results1 := []*models.InferenceResult{
		{Supi: supi, AnomalyScore: 0.95},
	}
	scorer.ProcessInferenceResults(results1, 1)

	// Simulate time passing
	scorer.mu.Lock()
	ueState := scorer.ueStates[supi]
	ueState.LastUpdateTs = time.Now().Unix() - 5
	scorer.mu.Unlock()

	// Process again
	results2 := []*models.InferenceResult{
		{Supi: supi, AnomalyScore: 0.1},
	}
	enhanced2 := scorer.ProcessInferenceResults(results2, 2)

	// Should have decayed
	if enhanced2[0].RiskScore >= 50.0 {
		t.Errorf("After decay: RiskScore = %v, should be < 50.0", enhanced2[0].RiskScore)
	}
}

func TestProcessInferenceResults_MultipleUEs(t *testing.T) {
	config := &RiskScorerConfig{
		MaxScore:            100.0,
		BlockThreshold:      80.0,
		UnblockThreshold:    50.0,
		LLMConfidenceCutoff: 0.7,
		HitsToBan:           2,
		SecondsToForgive:    20,
		TimeWindowSec:       1,
	}

	scorer := NewRiskScorer(config)

	results := []*models.InferenceResult{
		{Supi: "imsi-001", AnomalyScore: 0.95},
		{Supi: "imsi-002", AnomalyScore: 0.1},
		{Supi: "imsi-003", AnomalyScore: 0.85},
	}

	enhanced := scorer.ProcessInferenceResults(results, 1)

	if len(enhanced) != 3 {
		t.Fatalf("Expected 3 results, got %d", len(enhanced))
	}

	// Check first UE (attack)
	if !enhanced[0].AttackDetected {
		t.Error("UE 001 should have attack detected")
	}

	// Check second UE (normal)
	if enhanced[1].AttackDetected {
		t.Error("UE 002 should not have attack detected")
	}
}
