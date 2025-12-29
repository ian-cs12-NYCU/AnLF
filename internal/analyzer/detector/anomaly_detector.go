package detector

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/free5gc/anlf/internal/analyzer/queue"
	"github.com/free5gc/anlf/internal/analyzer/scorer"
	"github.com/free5gc/anlf/internal/logger"
	"github.com/free5gc/anlf/pkg/models"
)

type AnomalyDetector struct {
	inferenceQueue       *queue.InferenceQueue
	exportQueue          *queue.ExportQueue
	llmClient            *LLMClient
	riskScorer           *scorer.RiskScorer // Risk scoring component
	llmTimeout           time.Duration      // Store timeout for diagnostics
	includeGlobalContext bool               // Whether to include global network stats in prompts
	stopChan             chan struct{}
	doneChan             chan struct{}
	enabled              bool
	riskScoringEnabled   bool // Whether risk scoring is enabled
}

// isEmptyRecord checks if a UE traffic record has all feature values set to zero
// Returns true if the record is empty (no traffic activity)
func isEmptyRecord(record *models.UeTrafficRecord) bool {
	return record.UeFeatureVector.UlLogPPS == 0.0 &&
		record.UeFeatureVector.AvgLen == 0.0 &&
		record.UeFeatureVector.IcmpRatio == 0.0 &&
		record.UeFeatureVector.TcpRatio == 0.0 &&
		record.UeFeatureVector.UdpRatio == 0.0 &&
		record.UeFeatureVector.SynRatio == 0.0 &&
		record.UeFeatureVector.RstRatio == 0.0 &&
		record.UeFeatureVector.NewFlowRate == 0.0 &&
		record.UeFeatureVector.FanOut == 0.0
}

type AnomalyDetectorConfig struct {
	LLMServerURL         string
	LLMTimeout           time.Duration
	SystemPromptPath     string                   // Path to system prompt file
	MaxConcurrent        int                      // Max concurrent HTTP requests to LLM server
	Temperature          float64                  // LLM temperature
	MaxTokens            int                      // Max response tokens
	IncludeGlobalContext bool                     // Include global network statistics in prompt
	RiskScorerConfig     *scorer.RiskScorerConfig // Risk scorer configuration (optional)
	QueueConfig          queue.QueueConfig
	Enabled              bool
}

func NewAnomalyDetector(cfg AnomalyDetectorConfig, exportQueue *queue.ExportQueue) (*AnomalyDetector, error) {
	if !cfg.Enabled {
		logger.AnalyzerLog.Info("AnomalyDetector is disabled")
		return &AnomalyDetector{
			enabled:  false,
			stopChan: make(chan struct{}),
			doneChan: make(chan struct{}),
		}, nil
	}

	llmClient := NewLLMClient(LLMClientConfig{
		ServerURL:        cfg.LLMServerURL,
		Timeout:          cfg.LLMTimeout,
		SystemPromptPath: cfg.SystemPromptPath,
		MaxConcurrent:    cfg.MaxConcurrent,
		Temperature:      cfg.Temperature,
		MaxTokens:        cfg.MaxTokens,
	})

	detector := &AnomalyDetector{
		llmClient:            llmClient,
		llmTimeout:           cfg.LLMTimeout,
		includeGlobalContext: cfg.IncludeGlobalContext,
		exportQueue:          exportQueue,
		riskScoringEnabled:   false,
		enabled:              true,
		stopChan:             make(chan struct{}),
		doneChan:             make(chan struct{}),
	}

	// Initialize risk scorer if configuration provided
	if cfg.RiskScorerConfig != nil {
		detector.riskScorer = scorer.NewRiskScorer(cfg.RiskScorerConfig)
		detector.riskScoringEnabled = true
		logger.AnalyzerLog.Info("AnomalyDetector: Risk scoring enabled")
	} else {
		logger.AnalyzerLog.Info("AnomalyDetector: Risk scoring disabled")
	}

	detector.inferenceQueue = queue.NewInferenceQueue(cfg.QueueConfig, detector)

	logger.AnalyzerLog.Infof("AnomalyDetector created with LLM server: %s", cfg.LLMServerURL)
	return detector, nil
}

// HandleBatch processes a batch of UE traffic records using single-UE concurrent requests
// Each UE sends one individual request to the LLM server with optimized connection pooling
// Reference: high_speed_HTTPclient.md for performance optimization
func (d *AnomalyDetector) HandleBatch(batch *models.BatchUeTrafficRecords) error {
	if !d.enabled {
		return nil
	}

	if batch == nil || len(batch.Records) == 0 {
		return nil
	}

	records := batch.Records
	pollID := batch.PollID

	startTime := time.Now()
	logPrefix := fmt.Sprintf("[Poll #%d]", pollID)
	logger.AnalyzerLog.Infof("%s [AnomalyDetector] Processing batch of %d UEs (single-UE concurrent mode)", logPrefix, len(records))

	// Semaphore for concurrency control (limit in-flight requests)
	// Reference: high_speed_HTTPclient.md - prevents server congestion
	maxConcurrent := d.llmClient.maxConcurrent
	sem := make(chan struct{}, maxConcurrent)

	var wg sync.WaitGroup
	var mu sync.Mutex
	allResults := make([]*models.InferenceResult, 0, len(records))
	errorCount := 0
	skippedEmptyCount := 0 // Count of UEs skipped due to empty records
	llmRequestCount := 0   // Count of actual LLM requests sent

	// Process each UE in parallel with concurrency control
	for _, record := range records {
		wg.Add(1)

		// Acquire semaphore slot (blocks if at capacity)
		sem <- struct{}{}

		go func(ue *models.UeTrafficRecord) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore slot

			// Check if UE record is empty (all feature values are zero)
			// If empty, skip LLM request and directly assign risk value = 0
			if isEmptyRecord(ue) {
				logger.AnalyzerLog.Debugf("%s [AnomalyDetector] %s: Empty record detected, skipping LLM request (risk=0.0)", logPrefix, ue.Supi)
				result := &models.InferenceResult{
					Supi:         ue.Supi,
					AnomalyScore: 0.0, // Empty records have zero risk
					Timestamp:    time.Now().Unix(),
				}
				mu.Lock()
				allResults = append(allResults, result)
				skippedEmptyCount++
				mu.Unlock()
				return
			}

			// Each goroutine gets its own context with timeout
			ctx, cancel := context.WithTimeout(context.Background(), d.llmTimeout)
			defer cancel()

			// Send single UE request with global network statistics (if enabled)
			var globalStats *models.GlobalNetworkStats
			if d.includeGlobalContext {
				globalStats = batch.GlobalStats
			}
			result, err := d.llmClient.PredictSingleUE(ctx, ue, globalStats)
			if err != nil {
				// Enhanced error logging with categorization
				if ctx.Err() == context.DeadlineExceeded {
					logger.AnalyzerLog.Warnf("%s [AnomalyDetector] ⏱️  %s: TIMEOUT - Request exceeded %.2fs (fail-open: Normal)",
						logPrefix, ue.Supi, d.llmTimeout.Seconds())
				} else if ctx.Err() == context.Canceled {
					logger.AnalyzerLog.Warnf("%s [AnomalyDetector] 🚫 %s: CANCELED - Request was cancelled (fail-open: Normal)", logPrefix, ue.Supi)
				} else {
					logger.AnalyzerLog.Warnf("%s [AnomalyDetector] ❌ %s: ERROR - %v (fail-open: Normal)", logPrefix, ue.Supi, err)
				}
				// Fail-Open: Create default "Normal" result
				result = &models.InferenceResult{
					Supi:         ue.Supi,
					AnomalyScore: 0.1,
				}
				mu.Lock()
				errorCount++
				mu.Unlock()
			}

			// Collect result thread-safely
			mu.Lock()
			allResults = append(allResults, result)
			llmRequestCount++ // Count actual LLM request sent
			mu.Unlock()
		}(record)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	// Log statistics about processing
	if skippedEmptyCount > 0 {
		logger.AnalyzerLog.Infof("%s [AnomalyDetector] Skipped %d empty records (no traffic, risk=0.0)", logPrefix, skippedEmptyCount)
	}

	if errorCount > 0 {
		errorRate := float64(errorCount) / float64(len(records)) * 100
		logger.AnalyzerLog.Warnf("%s ╔═══════════════════════════════════════════════════════════════════╗", logPrefix)
		logger.AnalyzerLog.Warnf("%s ║ ANOMALY DETECTOR: %d/%d UEs encountered errors (%.1f%%)           ", logPrefix, errorCount, len(records), errorRate)
		logger.AnalyzerLog.Warnf("%s ║ Fail-open applied: All errors treated as Normal (score=0.1)      ", logPrefix)
		logger.AnalyzerLog.Warnf("%s ║ Timeout setting: %.2fs                                            ", logPrefix, d.llmTimeout.Seconds())
		logger.AnalyzerLog.Warnf("%s ║ Possible causes:                                                  ", logPrefix)
		logger.AnalyzerLog.Warnf("%s ║   • LLM server overloaded (too many concurrent requests)          ", logPrefix)
		logger.AnalyzerLog.Warnf("%s ║   • Network latency or congestion                                 ", logPrefix)
		logger.AnalyzerLog.Warnf("%s ║   • Timeout too short for current load (consider increasing)      ", logPrefix)
		logger.AnalyzerLog.Warnf("%s ╚═══════════════════════════════════════════════════════════════════╝", logPrefix)
	} else {
		logger.AnalyzerLog.Infof("%s [AnomalyDetector] ✓ Successfully processed %d UEs (all parsed successfully)", logPrefix, len(records))
	}

	// Sort results by SUPI to maintain consistent order
	d.sortResultsBySUPI(allResults)

	// Process results through risk scorer if enabled
	if d.riskScoringEnabled && d.riskScorer != nil {
		enhancedResults := d.riskScorer.ProcessInferenceResults(allResults, pollID)

		// Collect blocked UEs for summary table
		var blockedUEs []*models.EnhancedInferenceResult
		for _, enhanced := range enhancedResults {
			if enhanced.IsBlocked {
				blockedUEs = append(blockedUEs, enhanced)
			}
		}

		// Enqueue enhanced results to ExportQueue
		for _, enhanced := range enhancedResults {
			msg := queue.NewEnhancedInferenceResultMessage(enhanced)
			if err := d.exportQueue.EnqueueExport(msg); err != nil {
				logger.AnalyzerLog.Errorf("%s [AnomalyDetector] Failed to enqueue enhanced result for %s: %v", logPrefix, enhanced.Supi, err)
			} else {
				logger.AnalyzerLog.Debugf("%s [AnomalyDetector] Enhanced analysis - SUPI: %s | LLM: %.3f | Risk: %.2f | Status: %s",
					logPrefix, enhanced.Supi, enhanced.AnomalyScore, enhanced.RiskScore, enhanced.Status)
			}
		}

		// Print summary table of blocked UEs if any
		if len(blockedUEs) > 0 {
			logger.AnalyzerLog.Infof("%s ╔═════════════════════════════════════════════════════════════════════════╗", logPrefix)
			logger.AnalyzerLog.Infof("%s ║ BLOCKED UEs SUMMARY (%d detected)                                           ", logPrefix, len(blockedUEs))
			logger.AnalyzerLog.Infof("%s ╠═════════════════════════════════════════════════════════════════════════╣", logPrefix)
			logger.AnalyzerLog.Infof("%s ║ SUPI                          | Anomaly Score | Risk Score | Attack Count  ║", logPrefix)
			logger.AnalyzerLog.Infof("%s ╟─────────────────────────────────────────────────────────────────────────╢", logPrefix)

			for _, ue := range blockedUEs {
				logger.AnalyzerLog.Infof("%s ║ %-29s │ %13.3f │ %10.2f │ %13s ║",
					logPrefix, ue.Supi, ue.AnomalyScore, ue.RiskScore,
					fmt.Sprintf("Yes" /* actual attack count would need to be tracked */))
			}

			logger.AnalyzerLog.Infof("%s ╚═════════════════════════════════════════════════════════════════════════╝", logPrefix)
		}
	} else {
		// Enqueue raw results without risk scoring (legacy mode)
		for _, result := range allResults {
			msg := queue.NewInferenceResultMessage(result)
			if err := d.exportQueue.EnqueueExport(msg); err != nil {
				logger.AnalyzerLog.Errorf("%s [AnomalyDetector] Failed to enqueue inference result for %s: %v", logPrefix, result.Supi, err)
			} else {
				logger.AnalyzerLog.Debugf("%s [AnomalyDetector] Analysis complete - SUPI: %s | Anomaly Score: %.3f",
					logPrefix, result.Supi, result.AnomalyScore)
			}
		}
	}

	duration := time.Since(startTime)

	// Calculate throughput metrics based on actual LLM requests and total UEs processed
	var llmThroughput float64
	var totalThroughput float64
	if duration > 0 {
		llmThroughput = float64(llmRequestCount) / duration.Seconds()
		totalThroughput = float64(len(allResults)) / duration.Seconds()
	}

	// Log detailed completion statistics
	logger.AnalyzerLog.Infof("%s [AnomalyDetector] Batch complete: %d total UEs, %d LLM requests, %d empty (skipped)",
		logPrefix, len(allResults), llmRequestCount, skippedEmptyCount)
	logger.AnalyzerLog.Infof("%s [AnomalyDetector] Throughput: %.2f LLM req/s | %.2f total UE/s | Duration: %v",
		logPrefix, llmThroughput, totalThroughput, duration)
	return nil
}

// createDefaultResults creates default "Normal" inference results for fail-open mechanism
func (d *AnomalyDetector) createDefaultResults(records []*models.UeTrafficRecord) []*models.InferenceResult {
	results := make([]*models.InferenceResult, len(records))
	now := time.Now().Unix()
	for i, record := range records {
		results[i] = &models.InferenceResult{
			Supi:         record.Supi,
			AnomalyScore: 0.1, // Default low risk score
			Timestamp:    now,
		}
	}
	return results
}

// sortResultsBySUPI sorts inference results by SUPI for consistent output ordering
func (d *AnomalyDetector) sortResultsBySUPI(results []*models.InferenceResult) {
	// Simple bubble sort by SUPI (sufficient for small batches)
	for i := 0; i < len(results)-1; i++ {
		for j := i + 1; j < len(results); j++ {
			if results[i].Supi > results[j].Supi {
				results[i], results[j] = results[j], results[i]
			}
		}
	}
}

func (d *AnomalyDetector) Start(ctx context.Context) error {
	if !d.enabled {
		logger.AnalyzerLog.Info("AnomalyDetector is disabled, skipping start")
		close(d.doneChan)
		return nil
	}

	logger.AnalyzerLog.Info("[AnomalyDetector] Starting AnomalyDetector...")

	healthCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := d.llmClient.HealthCheck(healthCtx); err != nil {
		logger.AnalyzerLog.Warnf("[AnomalyDetector] ⚠️  LLM server health check FAILED: %v", err)
		logger.AnalyzerLog.Warnf("[AnomalyDetector] ⚠️  Unable to connect to LLM server at: %s", d.llmClient.serverURL)
		logger.AnalyzerLog.Warn("[AnomalyDetector] ⚠️  Make sure the LLM server is running and accessible")
		logger.AnalyzerLog.Warn("[AnomalyDetector] ⚠️  AnomalyDetector will continue but will fail on predictions")
	} else {
		logger.AnalyzerLog.Info("[AnomalyDetector] ✓ LLM server health check PASSED")
	}

	if err := d.inferenceQueue.Start(ctx); err != nil {
		return fmt.Errorf("failed to start inference queue: %w", err)
	}

	logger.AnalyzerLog.Info("[AnomalyDetector] ✓ AnomalyDetector started successfully and ready to analyze traffic")
	return nil
}

func (d *AnomalyDetector) Stop(timeout time.Duration) error {
	if !d.enabled {
		logger.AnalyzerLog.Info("AnomalyDetector is disabled, skipping stop")
		return nil
	}

	logger.AnalyzerLog.Info("Stopping AnomalyDetector...")

	close(d.stopChan)

	if d.inferenceQueue != nil {
		if err := d.inferenceQueue.Stop(timeout); err != nil {
			logger.AnalyzerLog.Errorf("InferenceQueue stop error: %v", err)
		}
	}

	close(d.doneChan)
	logger.AnalyzerLog.Info("AnomalyDetector stopped successfully")
	return nil
}

func (d *AnomalyDetector) Name() string {
	return "AnomalyDetector"
}

// EnqueueBatch adds a batch of UE traffic records to the inference queue
func (d *AnomalyDetector) EnqueueBatch(batch *models.BatchUeTrafficRecords) error {
	if !d.enabled {
		return nil
	}
	return d.inferenceQueue.EnqueueBatch(batch)
}

func (d *AnomalyDetector) IsEnabled() bool {
	return d.enabled
}
