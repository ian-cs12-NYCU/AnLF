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
	stopChan       chan struct{}
	doneChan       chan struct{}
	enabled        bool
	batchSize      int // Optimal batch size for LLM server (5-10 UEs recommended)
}

type AnomalyDetectorConfig struct {
	LLMServerURL     string
	LLMTimeout       time.Duration
	SystemPromptPath string // Path to system prompt file
	QueueConfig      queue.QueueConfig
	Enabled          bool
	BatchSize        int // Optimal batch size for LLM server (default: 5)
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
	})

	// Set default batch size for optimal LLM performance (Qwen 2.5 1.5B recommendation: 5-10 UEs)
	batchSize := cfg.BatchSize
	if batchSize <= 0 {
		batchSize = 5 // Default to 5 UEs per batch for stability
	}

	detector := &AnomalyDetector{
		llmClient:   llmClient,
		exportQueue: exportQueue,
		stopChan:    make(chan struct{}),
		doneChan:    make(chan struct{}),
		enabled:     true,
		batchSize:   batchSize,
	}

	detector.inferenceQueue = queue.NewInferenceQueue(cfg.QueueConfig, detector)

	logger.AnalyzerLog.Infof("AnomalyDetector created with LLM server: %s", cfg.LLMServerURL)
	return detector, nil
}

// HandleBatch is called by InferenceQueue workers to process a batch of UE traffic records
// It splits large batches into smaller sub-batches and processes them in parallel using goroutines
func (d *AnomalyDetector) HandleBatch(records []*models.UeTrafficRecord) error {
	if !d.enabled {
		return nil
	}

	if len(records) == 0 {
		return nil
	}

	logger.AnalyzerLog.Infof("[AnomalyDetector] Processing batch of %d UE traffic records (batch_size=%d)", len(records), d.batchSize)

	// Split into optimal sub-batches for LLM processing (recommended: 5-10 UEs per batch)
	var subBatches [][]*models.UeTrafficRecord
	for i := 0; i < len(records); i += d.batchSize {
		end := i + d.batchSize
		if end > len(records) {
			end = len(records)
		}
		subBatches = append(subBatches, records[i:end])
	}

	logger.AnalyzerLog.Infof("[AnomalyDetector] Split into %d sub-batches for parallel processing", len(subBatches))

	// Process sub-batches in parallel using goroutines
	var wg sync.WaitGroup
	var mu sync.Mutex
	allResults := make([]*models.InferenceResult, 0, len(records))
	errChan := make(chan error, len(subBatches))

	for batchIdx, subBatch := range subBatches {
		wg.Add(1)
		go func(idx int, batch []*models.UeTrafficRecord) {
			defer wg.Done()

			// Each goroutine gets its own context with timeout
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			logger.AnalyzerLog.Debugf("[AnomalyDetector] Sub-batch %d: Processing %d UEs", idx+1, len(batch))

			// Call LLM server for this sub-batch
			batchResult, err := d.llmClient.PredictBatch(ctx, batch)
			if err != nil {
				logger.AnalyzerLog.Warnf("[AnomalyDetector] Sub-batch %d: LLM prediction failed: %v (fail-open: assuming Normal)", idx+1, err)
				// Fail-Open: Create default "Normal" results for this sub-batch
				defaultResults := d.createDefaultResults(batch)
				mu.Lock()
				allResults = append(allResults, defaultResults...)
				mu.Unlock()
				errChan <- fmt.Errorf("sub-batch %d failed: %w", idx+1, err)
				return
			}

			logger.AnalyzerLog.Debugf("[AnomalyDetector] Sub-batch %d: Received %d results from LLM", idx+1, len(batchResult.Results))

			// Collect results thread-safely
			mu.Lock()
			allResults = append(allResults, batchResult.Results...)
			mu.Unlock()
		}(batchIdx, subBatch)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(errChan)

	// Check for errors (non-fatal, already handled with fail-open)
	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		logger.AnalyzerLog.Warnf("[AnomalyDetector] %d/%d sub-batches encountered errors (fail-open applied)", len(errs), len(subBatches))
	}

	// Sort results by SUPI to maintain consistent order
	d.sortResultsBySUPI(allResults)

	// Enqueue sorted results to ExportQueue
	for _, result := range allResults {
		msg := queue.NewInferenceResultMessage(result)
		if err := d.exportQueue.EnqueueExport(msg); err != nil {
			logger.AnalyzerLog.Errorf("[AnomalyDetector] Failed to enqueue inference result for %s: %v", result.Supi, err)
		} else {
			logger.AnalyzerLog.Debugf("[AnomalyDetector] Analysis complete - SUPI: %s | Anomaly Score: %.3f",
				result.Supi, result.AnomalyScore)
		}
	}

	logger.AnalyzerLog.Debugf("[AnomalyDetector] Batch processing complete: %d UEs analyzed in %d parallel sub-batches (sorted by SUPI)", len(allResults), len(subBatches))
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
