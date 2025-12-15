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
	wg             sync.WaitGroup
	enabled        bool
}

type AnomalyDetectorConfig struct {
	LLMServerURL     string
	LLMTimeout       time.Duration
	SystemPromptPath string // Path to system prompt file
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
	})

	detector := &AnomalyDetector{
		llmClient:   llmClient,
		exportQueue: exportQueue,
		stopChan:    make(chan struct{}),
		doneChan:    make(chan struct{}),
		enabled:     true,
	}

	detector.inferenceQueue = queue.NewInferenceQueue(cfg.QueueConfig, detector)

	logger.AnalyzerLog.Infof("AnomalyDetector created with LLM server: %s", cfg.LLMServerURL)
	return detector, nil
}

func (d *AnomalyDetector) Handle(record *models.UeTrafficRecord) error {
	if !d.enabled {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	logger.AnalyzerLog.Debugf("[AnomalyDetector] Processing UE traffic: %s (SUPI: %s)", record.UeIp, record.Supi)

	result, err := d.llmClient.Predict(ctx, record)
	if err != nil {
		logger.AnalyzerLog.Warnf("[AnomalyDetector] LLM prediction failed for UE %s: %v", record.UeIp, err)
		return fmt.Errorf("LLM prediction failed: %w", err)
	}

	msg := queue.NewInferenceResultMessage(result)
	if err := d.exportQueue.EnqueueExport(msg); err != nil {
		logger.AnalyzerLog.Errorf("[AnomalyDetector] Failed to enqueue inference result for %s: %v", record.UeIp, err)
	} else {
		logger.AnalyzerLog.Infof("[AnomalyDetector] Analysis complete - UE: %s | Prediction: %s | Score: %.2f | Confidence: %.2f",
			record.UeIp, result.Prediction, result.AnomalyScore, result.Confidence)
	}

	return nil
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

func (d *AnomalyDetector) EnqueueRecord(record *models.UeTrafficRecord) error {
	if !d.enabled {
		return nil
	}
	return d.inferenceQueue.EnqueueInference(record)
}

func (d *AnomalyDetector) IsEnabled() bool {
	return d.enabled
}
