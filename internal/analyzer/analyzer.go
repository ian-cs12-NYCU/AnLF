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
	featureChan     <-chan *models.UeTrafficRecord
	exportQueue     *queue.ExportQueue
	anomalyDetector AnomalyDetector
	stopChan        chan struct{}
	doneChan        chan struct{}
}

type AnomalyDetector interface {
	EnqueueRecord(record *models.UeTrafficRecord) error
	IsEnabled() bool
}

func NewFlowAnalyzer(
	featureChan <-chan *models.UeTrafficRecord,
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
		case record, ok := <-a.featureChan:
			if !ok {
				logger.AnalyzerLog.Info("Feature channel closed")
				return
			}
			a.processRecord(record)
		}
	}
}

func (a *FlowAnalyzer) processRecord(record *models.UeTrafficRecord) {
	logger.AnalyzerLog.Infof("Received traffic record for UE %s (SUPI: %s)", record.UeIp, record.Supi)

	msg := queue.NewTrafficRecordMessage(record)
	if err := a.exportQueue.EnqueueExport(msg); err != nil {
		logger.AnalyzerLog.Errorf("Failed to enqueue record for %s: %v", record.UeIp, err)
	} else {
		logger.AnalyzerLog.Debugf("Enqueued traffic record for UE %s", record.UeIp)
	}

	if a.anomalyDetector != nil && a.anomalyDetector.IsEnabled() {
		if err := a.anomalyDetector.EnqueueRecord(record); err != nil {
			logger.AnalyzerLog.Errorf("Failed to enqueue for anomaly detection for %s: %v", record.UeIp, err)
		} else {
			logger.AnalyzerLog.Debugf("Enqueued for anomaly detection for UE %s", record.UeIp)
		}
	}
}
