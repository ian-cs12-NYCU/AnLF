package dispatcher

import (
	"fmt"
	"sync"

	"github.com/free5gc/anlf/internal/analyzer/exporter"
	"github.com/free5gc/anlf/internal/analyzer/queue"
	"github.com/free5gc/anlf/internal/logger"
)

// ExportDispatcher routes messages to appropriate exporters based on message type
type ExportDispatcher struct {
	trafficExporter exporter.Exporter
	// Future: llmExporter exporter.Exporter
	mu sync.RWMutex
}

// NewExportDispatcher creates a new dispatcher with configured exporters
func NewExportDispatcher(trafficExporter exporter.Exporter) *ExportDispatcher {
	return &ExportDispatcher{
		trafficExporter: trafficExporter,
	}
}

// Handle implements queue.MessageHandler interface
func (d *ExportDispatcher) Handle(msg *queue.ExportMessage) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	switch msg.Type {
	case queue.MessageTypeTrafficRecord:
		return d.handleTrafficRecord(msg)
	case queue.MessageTypeLLMInference:
		// Future: implement LLM inference result export
		logger.AnalyzerLog.Warnf("LLM inference export not yet implemented")
		return nil
	default:
		return fmt.Errorf("unknown message type: %s", msg.Type)
	}
}

// handleTrafficRecord processes traffic record messages
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

// Shutdown closes all exporters
func (d *ExportDispatcher) Shutdown() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	logger.AnalyzerLog.Info("Shutting down ExportDispatcher...")

	if err := d.trafficExporter.Shutdown(); err != nil {
		logger.AnalyzerLog.Errorf("Traffic exporter shutdown error: %v", err)
		return err
	}

	logger.AnalyzerLog.Info("ExportDispatcher shutdown complete")
	return nil
}

// SetTrafficExporter updates the traffic exporter (for future hot-reload)
func (d *ExportDispatcher) SetTrafficExporter(exp exporter.Exporter) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.trafficExporter = exp
}
