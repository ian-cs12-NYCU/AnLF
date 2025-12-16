package detector

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/free5gc/anlf/internal/analyzer/queue"
	"github.com/free5gc/anlf/internal/logger"
	"github.com/free5gc/anlf/pkg/models"
)

type AnomalyDetector struct {
	inferenceQueue *queue.InferenceQueue
	exportQueue    *queue.ExportQueue
	llmClient      *LLMClient
	llmTimeout     time.Duration // Store timeout for diagnostics
	stopChan       chan struct{}
	doneChan       chan struct{}
	enabled        bool
}

type AnomalyDetectorConfig struct {
	LLMServerURL     string
	LLMTimeout       time.Duration
	SystemPromptPath string  // Path to system prompt file
	Temperature      float64 // LLM temperature
	MaxTokens        int     // Max response tokens
	QueueConfig      queue.QueueConfig
	Enabled          bool
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
		Temperature:      cfg.Temperature,
		MaxTokens:        cfg.MaxTokens,
	})

	detector := &AnomalyDetector{
		llmClient:   llmClient,
		llmTimeout:  cfg.LLMTimeout,
		exportQueue: exportQueue,
		stopChan:    make(chan struct{}),
		doneChan:    make(chan struct{}),
		enabled:     true,
	}

	detector.inferenceQueue = queue.NewInferenceQueue(cfg.QueueConfig, detector)

	logger.AnalyzerLog.Infof("AnomalyDetector created with LLM server: %s", cfg.LLMServerURL)
	return detector, nil
}

// HandleBatch processes a batch of UE traffic records using single-UE concurrent requests
// Each UE sends one individual request to the LLM server with optimized connection pooling
// Reference: high_speed_HTTPclient.md for performance optimization
func (d *AnomalyDetector) HandleBatch(records []*models.UeTrafficRecord) error {
	if !d.enabled {
		return nil
	}

	if len(records) == 0 {
		return nil
	}

	// Get pollID from first record (all records in batch have same pollID)
	pollID := uint64(0)
	if len(records) > 0 && records[0] != nil {
		pollID = records[0].PollID
	}

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

	// Process each UE in parallel with concurrency control
	for _, record := range records {
		wg.Add(1)

		// Acquire semaphore slot (blocks if at capacity)
		sem <- struct{}{}

		go func(ue *models.UeTrafficRecord) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore slot

			// Each goroutine gets its own context with timeout
			ctx, cancel := context.WithTimeout(context.Background(), d.llmTimeout)
			defer cancel()

			// Send single UE request
			result, err := d.llmClient.PredictSingleUE(ctx, ue)
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
			mu.Unlock()
		}(record)
	}

	// Wait for all goroutines to complete
	wg.Wait()

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

	// Enqueue sorted results to ExportQueue
	for _, result := range allResults {
		msg := queue.NewInferenceResultMessage(result)
		if err := d.exportQueue.EnqueueExport(msg); err != nil {
			logger.AnalyzerLog.Errorf("%s [AnomalyDetector] Failed to enqueue inference result for %s: %v", logPrefix, result.Supi, err)
		} else {
			logger.AnalyzerLog.Debugf("%s [AnomalyDetector] Analysis complete - SUPI: %s | Anomaly Score: %.3f",
				logPrefix, result.Supi, result.AnomalyScore)
		}
	}

	duration := time.Since(startTime)
	throughput := float64(len(allResults)) / duration.Seconds()
	logger.AnalyzerLog.Infof("%s [AnomalyDetector] Batch complete: %d UEs analyzed in %v (%.2f req/s)",
		logPrefix, len(allResults), duration, throughput)
	return nil
}

// createDefaultResults creates default "Normal" inference results for fail-open mechanism
func (d *AnomalyDetector) createDefaultResults(records []*models.UeTrafficRecord) []*models.InferenceResult {
	results := make([]*models.InferenceResult, len(records))
	for i, record := range records {
		results[i] = &models.InferenceResult{
			Supi:         record.Supi,
			AnomalyScore: 0.1, // Default low risk score
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
func (d *AnomalyDetector) EnqueueBatch(records []*models.UeTrafficRecord) error {
	if !d.enabled {
		return nil
	}
	return d.inferenceQueue.EnqueueBatch(records)
}

func (d *AnomalyDetector) IsEnabled() bool {
	return d.enabled
}
