package scorer

import (
	"fmt"
	"sync"
	"time"

	"github.com/free5gc/anlf/internal/logger"
	"github.com/free5gc/anlf/pkg/models"
)

// RiskScorer implements CUSUM-based risk scoring with asymmetric update and dual-threshold hysteresis
// Reference: Leaky Bucket Analogy for intuitive understanding
// - Attack: Fast charge (+attack_step when LLM confidence > threshold)
// - Decay: Slow leak (-decay_step per time window, regardless of state)
// - Block: Water overflow (score > BLOCK_THRESHOLD)
// - Unblock: Water drain (score < UNBLOCK_THRESHOLD)
type RiskScorer struct {
	config     *RiskScorerConfig
	ueStates   map[string]*UeRiskState // SUPI -> state
	mu         sync.RWMutex
	attackStep float64 // Calculated from HITS_TO_BAN
	decayStep  float64 // Calculated from SECONDS_TO_FORGIVE
}

// UeRiskState maintains per-UE risk score and status
type UeRiskState struct {
	SUPI         string
	Score        float64
	Status       UeStatus
	LastUpdateTs int64
	AttackCount  int
	BlockedSince int64
	mu           sync.RWMutex
}

// UeStatus represents the operational state of a UE
type UeStatus string

const (
	StatusNormal  UeStatus = "NORMAL"
	StatusBlocked UeStatus = "BLOCKED"
)

// RiskScorerConfig defines the configuration for risk scoring system
type RiskScorerConfig struct {
	// Fixed constants
	MaxScore         float64
	BlockThreshold   float64
	UnblockThreshold float64

	// Configurable parameters (from config file)
	LLMConfidenceCutoff float64
	HitsToBan           int
	SecondsToForgive    int
	TimeWindowSec       int
}

// NewRiskScorer creates a new risk scorer with auto-calculated parameters
func NewRiskScorer(config *RiskScorerConfig) *RiskScorer {
	// Validate config
	if config.MaxScore <= 0 {
		config.MaxScore = 100.0
	}
	if config.BlockThreshold <= 0 || config.BlockThreshold > config.MaxScore {
		config.BlockThreshold = 80.0
	}
	if config.UnblockThreshold <= 0 || config.UnblockThreshold >= config.BlockThreshold {
		config.UnblockThreshold = 50.0
	}
	if config.LLMConfidenceCutoff <= 0 || config.LLMConfidenceCutoff > 1.0 {
		config.LLMConfidenceCutoff = 0.7
	}
	if config.HitsToBan <= 0 {
		config.HitsToBan = 2
	}
	if config.SecondsToForgive <= 0 {
		config.SecondsToForgive = 20
	}
	if config.TimeWindowSec <= 0 {
		config.TimeWindowSec = 1
	}

	// Auto-calculate attack and decay steps
	attackStep := config.MaxScore / float64(config.HitsToBan)
	decayStep := config.MaxScore / float64(config.SecondsToForgive)

	logger.AnalyzerLog.Infof("[RiskScorer] Initialized with config: MaxScore=%.1f, Block=%.1f, Unblock=%.1f",
		config.MaxScore, config.BlockThreshold, config.UnblockThreshold)
	logger.AnalyzerLog.Infof("[RiskScorer] LLM Cutoff=%.2f, HitsToBan=%d, SecondsToForgive=%d",
		config.LLMConfidenceCutoff, config.HitsToBan, config.SecondsToForgive)
	logger.AnalyzerLog.Infof("[RiskScorer] Auto-calculated: AttackStep=%.2f, DecayStep=%.2f per second",
		attackStep, decayStep)

	return &RiskScorer{
		config:     config,
		ueStates:   make(map[string]*UeRiskState),
		attackStep: attackStep,
		decayStep:  decayStep,
	}
}

// ProcessInferenceResults processes a batch of LLM inference results and updates risk scores
// Returns enhanced results with risk score and block decision
func (rs *RiskScorer) ProcessInferenceResults(results []*models.InferenceResult, pollID uint64) []*models.EnhancedInferenceResult {
	if len(results) == 0 {
		return nil
	}

	currentTime := time.Now().Unix()
	enhancedResults := make([]*models.EnhancedInferenceResult, 0, len(results))

	logger.AnalyzerLog.Infof("[Poll #%d] [RiskScorer] Processing %d inference results", pollID, len(results))

	for _, result := range results {
		enhanced := rs.processOneUE(result, currentTime, pollID)
		enhancedResults = append(enhancedResults, enhanced)
	}

	return enhancedResults
}

// processOneUE processes a single UE's inference result and updates its risk state
func (rs *RiskScorer) processOneUE(result *models.InferenceResult, currentTime int64, pollID uint64) *models.EnhancedInferenceResult {
	rs.mu.Lock()
	state, exists := rs.ueStates[result.Supi]
	if !exists {
		// Create new UE state
		state = &UeRiskState{
			SUPI:         result.Supi,
			Score:        0.0,
			Status:       StatusNormal,
			LastUpdateTs: currentTime,
			AttackCount:  0,
			BlockedSince: 0,
		}
		rs.ueStates[result.Supi] = state
		logger.AnalyzerLog.Debugf("[Poll #%d] [RiskScorer] Created new state for UE %s", pollID, result.Supi)
	}
	rs.mu.Unlock()

	// Lock individual UE state for update
	state.mu.Lock()
	defer state.mu.Unlock()

	// Calculate time-based decay since last update
	timeDelta := currentTime - state.LastUpdateTs
	if timeDelta > 0 {
		decayAmount := rs.decayStep * float64(timeDelta)
		state.Score -= decayAmount
		if state.Score < 0 {
			state.Score = 0
		}
		logger.AnalyzerLog.Debugf("[Poll #%d] [RiskScorer] %s: Time decay %.2f (delta=%ds), score after decay: %.2f",
			pollID, result.Supi, decayAmount, timeDelta, state.Score)
	}

	// Check if LLM detected an attack
	isAttack := result.AnomalyScore >= rs.config.LLMConfidenceCutoff
	if isAttack {
		// Fast charge: Add attack step
		state.Score += rs.attackStep
		state.AttackCount++
		if state.Score > rs.config.MaxScore {
			state.Score = rs.config.MaxScore
		}
		logger.AnalyzerLog.Infof("[Poll #%d] [RiskScorer] %s: ATTACK detected (LLM=%.3f), score +%.2f -> %.2f (total attacks: %d)",
			pollID, result.Supi, result.AnomalyScore, rs.attackStep, state.Score, state.AttackCount)
	}

	// Apply dual-threshold hysteresis for status transition
	// Only change status if crossing thresholds, maintaining state within deadband
	if state.Status == StatusNormal && state.Score >= rs.config.BlockThreshold {
		state.Status = StatusBlocked
		state.BlockedSince = currentTime
		logger.AnalyzerLog.Infof("[Poll #%d] [RiskScorer] %s: BLOCKED (score %.2f >= %.2f)",
			pollID, result.Supi, state.Score, rs.config.BlockThreshold)
	} else if state.Status == StatusBlocked && state.Score < rs.config.UnblockThreshold {
		blockedDuration := currentTime - state.BlockedSince
		state.Status = StatusNormal
		state.BlockedSince = 0
		logger.AnalyzerLog.Infof("[Poll #%d] [RiskScorer] %s: UNBLOCKED (score %.2f < %.2f, was blocked for %ds)",
			pollID, result.Supi, state.Score, rs.config.UnblockThreshold, blockedDuration)
	}

	// Note: Status transitions are already logged above (BLOCKED/UNBLOCKED)

	// Update last update timestamp
	state.LastUpdateTs = currentTime

	// Create enhanced result
	enhanced := &models.EnhancedInferenceResult{
		InferenceResult: *result,
		RiskScore:       state.Score,
		Status:          string(state.Status),
		IsBlocked:       state.Status == StatusBlocked,
		AttackDetected:  isAttack,
	}

	logger.AnalyzerLog.Debugf("[Poll #%d] [RiskScorer] %s: Final state - Score=%.2f, Status=%s, LLM=%.3f",
		pollID, result.Supi, state.Score, state.Status, result.AnomalyScore)

	return enhanced
}

// GetUEState retrieves the current risk state for a specific UE (for diagnostics/testing)
func (rs *RiskScorer) GetUEState(supi string) (*UeRiskState, error) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	state, exists := rs.ueStates[supi]
	if !exists {
		return nil, fmt.Errorf("UE %s not found in risk scorer state", supi)
	}

	state.mu.RLock()
	defer state.mu.RUnlock()

	// Return a copy to avoid data races
	stateCopy := &UeRiskState{
		SUPI:         state.SUPI,
		Score:        state.Score,
		Status:       state.Status,
		LastUpdateTs: state.LastUpdateTs,
		AttackCount:  state.AttackCount,
		BlockedSince: state.BlockedSince,
	}

	return stateCopy, nil
}

// GetAllUEStates returns a snapshot of all UE states (for diagnostics/monitoring)
func (rs *RiskScorer) GetAllUEStates() map[string]*UeRiskState {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	snapshot := make(map[string]*UeRiskState, len(rs.ueStates))
	for supi, state := range rs.ueStates {
		state.mu.RLock()
		snapshot[supi] = &UeRiskState{
			SUPI:         state.SUPI,
			Score:        state.Score,
			Status:       state.Status,
			LastUpdateTs: state.LastUpdateTs,
			AttackCount:  state.AttackCount,
			BlockedSince: state.BlockedSince,
		}
		state.mu.RUnlock()
	}

	return snapshot
}

// ResetUE resets the risk state for a specific UE (for testing/admin purposes)
func (rs *RiskScorer) ResetUE(supi string) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	state, exists := rs.ueStates[supi]
	if !exists {
		return fmt.Errorf("UE %s not found in risk scorer state", supi)
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	state.Score = 0.0
	state.Status = StatusNormal
	state.AttackCount = 0
	state.BlockedSince = 0
	state.LastUpdateTs = time.Now().Unix()

	logger.AnalyzerLog.Infof("[RiskScorer] Reset state for UE %s", supi)
	return nil
}

// GetConfig returns the current configuration (for diagnostics)
func (rs *RiskScorer) GetConfig() RiskScorerConfig {
	return *rs.config
}
