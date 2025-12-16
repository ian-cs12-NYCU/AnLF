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
	pollCounter     uint64 // Increment for each poll batch to track processing order
}

type AnomalyDetector interface {
	EnqueueBatch(batch *models.BatchUeTrafficRecords) error
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
	// Increment poll counter and assign to batch
	a.pollCounter++
	batch.PollID = a.pollCounter

	logger.AnalyzerLog.Infof("[Poll #%d] Received batch of %d traffic records", batch.PollID, batch.BatchSize)

	// Calculate global network statistics (avg across active UEs only)
	if batch.BatchSize > 0 {
		var sumLogPPS, sumFlowRate, sumAvgLen float64
		activeCount := 0
		for _, record := range batch.Records {
			// Skip empty records (inactive UEs)
			if record.UeFeatureVector.LogPPS == 0.0 &&
				record.UeFeatureVector.AvgLen == 0.0 &&
				record.UeFeatureVector.NewFlowRate == 0.0 {
				continue
			}
			sumLogPPS += record.UeFeatureVector.LogPPS
			sumFlowRate += record.UeFeatureVector.NewFlowRate
			sumAvgLen += record.UeFeatureVector.AvgLen
			activeCount++
		}
		if activeCount > 0 {
			batch.GlobalStats = &models.GlobalNetworkStats{
				AvgLogPPS:   sumLogPPS / float64(activeCount),
				AvgFlowRate: sumFlowRate / float64(activeCount),
				AvgLen:      sumAvgLen / float64(activeCount),
			}
			logger.AnalyzerLog.Debugf("[Poll #%d] Global Stats (from %d active UEs): Avg PPS=%.2f, Avg Flow=%.2f, Avg Len=%.0f",
				batch.PollID, activeCount, batch.GlobalStats.AvgLogPPS, batch.GlobalStats.AvgFlowRate, batch.GlobalStats.AvgLen)
		}
	}

	// Assign poll ID to each record (for logging in anomaly detector)
	for _, record := range batch.Records {
		record.PollID = batch.PollID
		logger.AnalyzerLog.Debugf("[Poll #%d] Received traffic record for UE %s (SUPI: %s)", batch.PollID, record.UeIp, record.Supi)
	}

	// Send entire batch to ExportQueue (CSV exporter will handle sorting and writing)
	msg := queue.NewBatchTrafficRecordsMessage(batch)
	if err := a.exportQueue.EnqueueExport(msg); err != nil {
		logger.AnalyzerLog.Errorf("[Poll #%d] Failed to enqueue batch for export: %v", batch.PollID, err)
	} else {
		logger.AnalyzerLog.Debugf("[Poll #%d] Enqueued batch of %d records for export", batch.PollID, batch.BatchSize)
	}

	// Send entire batch to anomaly detector's inference queue for batch LLM inference
	if a.anomalyDetector != nil && a.anomalyDetector.IsEnabled() {
		if err := a.anomalyDetector.EnqueueBatch(batch); err != nil {
			logger.AnalyzerLog.Errorf("[Poll #%d] Failed to enqueue batch for anomaly detection: %v", batch.PollID, err)
		} else {
			logger.AnalyzerLog.Debugf("[Poll #%d] Enqueued batch of %d records for anomaly detection", batch.PollID, batch.BatchSize)
		}
	}
}
