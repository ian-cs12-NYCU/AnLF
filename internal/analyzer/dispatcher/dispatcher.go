package dispatcher

import (
	"fmt"
	"sync"

	"github.com/free5gc/anlf/internal/analyzer/exporter"
	"github.com/free5gc/anlf/internal/analyzer/queue"
	"github.com/free5gc/anlf/internal/logger"
)

type ExportDispatcher struct {
	trafficExporter   exporter.Exporter
	inferenceExporter exporter.Exporter
	mu                sync.RWMutex
}

func NewExportDispatcher(trafficExporter exporter.Exporter, inferenceExporter exporter.Exporter) *ExportDispatcher {
	return &ExportDispatcher{
		trafficExporter:   trafficExporter,
		inferenceExporter: inferenceExporter,
	}
}

func (d *ExportDispatcher) Handle(msg *queue.ExportMessage) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	switch msg.Type {
	case queue.MessageTypeTrafficRecord:
		return d.handleTrafficRecord(msg)
	case queue.MessageTypeBatchTrafficRecords:
		return d.handleBatchTrafficRecords(msg)
	case queue.MessageTypeInferenceResult:
		return d.handleInferenceResult(msg)
	default:
		return fmt.Errorf("unknown message type: %s", msg.Type)
	}
}

func (d *ExportDispatcher) handleTrafficRecord(msg *queue.ExportMessage) error {
	record, ok := msg.AsTrafficRecord()
	if !ok {
		return fmt.Errorf("failed to convert message to traffic record")
	}

	if err := d.trafficExporter.Export(record); err != nil {
		return fmt.Errorf("traffic exporter failed: %w", err)
	}

	logger.AnalyzerLog.Debugf("Exported traffic record for UE %s via %s",
		record.UeIp, d.trafficExporter.Name())
	return nil
}

func (d *ExportDispatcher) handleBatchTrafficRecords(msg *queue.ExportMessage) error {
	batch, ok := msg.AsBatchTrafficRecords()
	if !ok {
		return fmt.Errorf("failed to convert message to batch traffic records")
	}

	if err := d.trafficExporter.Export(batch); err != nil {
		return fmt.Errorf("traffic exporter failed: %w", err)
	}

	logger.AnalyzerLog.Debugf("Exported batch of %d traffic records via %s",
		batch.BatchSize, d.trafficExporter.Name())
	return nil
}

func (d *ExportDispatcher) handleInferenceResult(msg *queue.ExportMessage) error {
	result, ok := msg.AsInferenceResult()
	if !ok {
		return fmt.Errorf("failed to convert message to inference result")
	}

	if d.inferenceExporter == nil {
		return nil
	}

	if err := d.inferenceExporter.Export(result); err != nil {
		return fmt.Errorf("inference exporter failed: %w", err)
	}

	logger.AnalyzerLog.Debugf("Exported inference result for SUPI %s: score %.3f via %s",
		result.Supi, result.AnomalyScore, d.inferenceExporter.Name())
	return nil
}

func (d *ExportDispatcher) Shutdown() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	logger.AnalyzerLog.Info("Shutting down ExportDispatcher...")

	var errs []error

	if err := d.trafficExporter.Shutdown(); err != nil {
		logger.AnalyzerLog.Errorf("Traffic exporter shutdown error: %v", err)
		errs = append(errs, err)
	}

	if d.inferenceExporter != nil {
		if err := d.inferenceExporter.Shutdown(); err != nil {
			logger.AnalyzerLog.Errorf("Inference exporter shutdown error: %v", err)
			errs = append(errs, err)
		}
	}

	logger.AnalyzerLog.Info("ExportDispatcher shutdown complete")

	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %v", errs)
	}
	return nil
}

func (d *ExportDispatcher) SetTrafficExporter(exp exporter.Exporter) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.trafficExporter = exp
}
