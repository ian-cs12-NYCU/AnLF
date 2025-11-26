package analyzer

import (
	"context"
	"fmt"
	"time"

	"github.com/free5gc/anlf/internal/analyzer/exporter"
	"github.com/free5gc/anlf/internal/logger"
	"github.com/free5gc/anlf/pkg/models"
)

// FlowAnalyzer receives traffic records and exports them
type FlowAnalyzer struct {
	featureChan <-chan *models.UeTrafficRecord
	exporter    exporter.Exporter
	stopChan    chan struct{}
	doneChan    chan struct{}
}

// NewFlowAnalyzer creates a new flow analyzer
func NewFlowAnalyzer(
	featureChan <-chan *models.UeTrafficRecord,
	exp exporter.Exporter,
) *FlowAnalyzer {
	return &FlowAnalyzer{
		featureChan: featureChan,
		exporter:    exp,
		stopChan:    make(chan struct{}),
		doneChan:    make(chan struct{}),
	}
}

// Start implements Lifecycle.Start
func (a *FlowAnalyzer) Start(ctx context.Context) error {
	logger.AnalyzerLog.Infof("Starting FlowAnalyzer with exporter: %s", a.exporter.Name())

	go a.processLoop(ctx)

	logger.AnalyzerLog.Info("FlowAnalyzer started")
	return nil
}

// Stop implements Lifecycle.Stop
func (a *FlowAnalyzer) Stop(timeout time.Duration) error {
	logger.AnalyzerLog.Info("Stopping FlowAnalyzer...")

	close(a.stopChan)

	select {
	case <-a.doneChan:
		// Shutdown exporter
		if err := a.exporter.Shutdown(); err != nil {
			logger.AnalyzerLog.Errorf("Exporter shutdown error: %v", err)
		}
		logger.AnalyzerLog.Info("FlowAnalyzer stopped successfully")
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("FlowAnalyzer stop timeout")
	}
}

// Name implements Lifecycle.Name
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
	if err := a.exporter.Export(record); err != nil {
		logger.AnalyzerLog.Errorf("Failed to export record for %s: %v", record.UeIp, err)
	} else {
		logger.AnalyzerLog.Infof("Exported record for UE %s via %s", record.UeIp, a.exporter.Name())
	}
}
