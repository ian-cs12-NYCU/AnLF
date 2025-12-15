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
LLMServerURL string
LLMTimeout   time.Duration
QueueConfig  queue.QueueConfig
Enabled      bool
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
ServerURL: cfg.LLMServerURL,
Timeout:   cfg.LLMTimeout,
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

result, err := d.llmClient.Predict(ctx, record)
if err != nil {
return fmt.Errorf("LLM prediction failed: %w", err)
}

msg := queue.NewInferenceResultMessage(result)
if err := d.exportQueue.EnqueueExport(msg); err != nil {
logger.AnalyzerLog.Errorf("Failed to enqueue inference result for %s: %v", record.UeIp, err)
} else {
logger.AnalyzerLog.Debugf("Enqueued inference result for UE %s: %s", record.UeIp, result.Prediction)
}

return nil
}

func (d *AnomalyDetector) Start(ctx context.Context) error {
if !d.enabled {
logger.AnalyzerLog.Info("AnomalyDetector is disabled, skipping start")
close(d.doneChan)
return nil
}

logger.AnalyzerLog.Info("Starting AnomalyDetector...")

healthCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
defer cancel()

if err := d.llmClient.HealthCheck(healthCtx); err != nil {
logger.AnalyzerLog.Errorf("LLM server health check failed: %v", err)
logger.AnalyzerLog.Warn("AnomalyDetector will continue but may experience errors")
} else {
logger.AnalyzerLog.Info("LLM server health check passed")
}

if err := d.inferenceQueue.Start(ctx); err != nil {
return fmt.Errorf("failed to start inference queue: %w", err)
}

logger.AnalyzerLog.Info("AnomalyDetector started successfully")
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
