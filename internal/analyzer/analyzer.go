package analyzer

import (
	"context"
	"fmt"
	"time"

	"github.com/free5gc/anlf/internal/analyzer/queue"
	"github.com/free5gc/anlf/internal/logger"
	"github.com/free5gc/anlf/pkg/models"
)

type FlowAnalyzer struct {
	featureChan     <-chan *models.BatchUeTrafficRecords
	exportQueue     *queue.ExportQueue
	anomalyDetector AnomalyDetector
	stopChan        chan struct{}
	doneChan        chan struct{}
}

type AnomalyDetector interface {
	EnqueueBatch(records []*models.UeTrafficRecord) error
	IsEnabled() bool
}

func NewFlowAnalyzer(
	featureChan <-chan *models.BatchUeTrafficRecords,
	exportQueue *queue.ExportQueue,
	anomalyDetector AnomalyDetector,
) *FlowAnalyzer {
	return &FlowAnalyzer{
		featureChan:     featureChan,
		exportQueue:     exportQueue,
		anomalyDetector: anomalyDetector,
		stopChan:        make(chan struct{}),
		doneChan:        make(chan struct{}),
	}
}

func (a *FlowAnalyzer) Start(ctx context.Context) error {
	logger.AnalyzerLog.Info("Starting FlowAnalyzer with message queue")

	go a.processLoop(ctx)

	logger.AnalyzerLog.Info("FlowAnalyzer started")
	return nil
}

func (a *FlowAnalyzer) Stop(timeout time.Duration) error {
	logger.AnalyzerLog.Info("Stopping FlowAnalyzer...")

	close(a.stopChan)

	select {
	case <-a.doneChan:
		logger.AnalyzerLog.Info("FlowAnalyzer stopped successfully")
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("FlowAnalyzer stop timeout")
	}
}

func (a *FlowAnalyzer) Name() string {
	return "FlowAnalyzer"
}

func (a *FlowAnalyzer) processLoop(ctx context.Context) {
	defer close(a.doneChan)

	for {
		select {
		case <-ctx.Done():
			logger.AnalyzerLog.Info("FlowAnalyzer context cancelled")
			return
		case <-a.stopChan:
			logger.AnalyzerLog.Info("FlowAnalyzer stop signal received")
			return
		case batch, ok := <-a.featureChan:
			if !ok {
				logger.AnalyzerLog.Info("Feature channel closed")
				return
			}
			a.processBatch(batch)
		}
	}
}

func (a *FlowAnalyzer) processBatch(batch *models.BatchUeTrafficRecords) {
	logger.AnalyzerLog.Infof("Received batch of %d traffic records", batch.BatchSize)

	// Log each UE
	for _, record := range batch.Records {
		logger.AnalyzerLog.Debugf("Received traffic record for UE %s (SUPI: %s)", record.UeIp, record.Supi)
	}

	// Send entire batch to ExportQueue (CSV exporter will handle sorting and writing)
	msg := queue.NewBatchTrafficRecordsMessage(batch)
	if err := a.exportQueue.EnqueueExport(msg); err != nil {
		logger.AnalyzerLog.Errorf("Failed to enqueue batch for export: %v", err)
	} else {
		logger.AnalyzerLog.Debugf("Enqueued batch of %d records for export", batch.BatchSize)
	}

	// Send entire batch to anomaly detector's inference queue for batch LLM inference
	if a.anomalyDetector != nil && a.anomalyDetector.IsEnabled() {
		if err := a.anomalyDetector.EnqueueBatch(batch.Records); err != nil {
			logger.AnalyzerLog.Errorf("Failed to enqueue batch for anomaly detection: %v", err)
		} else {
			logger.AnalyzerLog.Debugf("Enqueued batch of %d records for anomaly detection", batch.BatchSize)
		}
	}
}
