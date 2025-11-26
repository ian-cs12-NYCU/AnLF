package monitor

import (
	"context"
	"fmt"
	"time"

	"github.com/free5gc/anlf/internal/logger"
	"github.com/free5gc/anlf/internal/sbi/consumer"
	"github.com/free5gc/anlf/pkg/ebpf"
	"github.com/free5gc/anlf/pkg/models"
)

// TrafficMonitor polls eBPF maps and sends records to analyzer
type TrafficMonitor struct {
	ebpfMgr       *ebpf.Manager
	smfClient     *consumer.MockSMF
	featureChan   chan<- *models.UeTrafficRecord
	pollInterval  time.Duration
	windowSeconds float64
	stopChan      chan struct{}
	doneChan      chan struct{}
}

// NewTrafficMonitor creates a new traffic monitor
func NewTrafficMonitor(
	ebpfMgr *ebpf.Manager,
	smfClient *consumer.MockSMF,
	featureChan chan<- *models.UeTrafficRecord,
	pollInterval time.Duration,
) *TrafficMonitor {
	return &TrafficMonitor{
		ebpfMgr:       ebpfMgr,
		smfClient:     smfClient,
		featureChan:   featureChan,
		pollInterval:  pollInterval,
		windowSeconds: pollInterval.Seconds(),
		stopChan:      make(chan struct{}),
		doneChan:      make(chan struct{}),
	}
}

// Start implements Lifecycle.Start
func (m *TrafficMonitor) Start(ctx context.Context) error {
	logger.MonitorLog.Infof("Starting TrafficMonitor (poll interval: %v)...", m.pollInterval)

	go m.pollLoop(ctx)

	logger.MonitorLog.Info("TrafficMonitor started")
	return nil
}

// Stop implements Lifecycle.Stop
func (m *TrafficMonitor) Stop(timeout time.Duration) error {
	logger.MonitorLog.Info("Stopping TrafficMonitor...")

	close(m.stopChan)

	select {
	case <-m.doneChan:
		logger.MonitorLog.Info("TrafficMonitor stopped successfully")
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("TrafficMonitor stop timeout")
	}
}

// Name implements Lifecycle.Name
func (m *TrafficMonitor) Name() string {
	return "TrafficMonitor"
}

func (m *TrafficMonitor) pollLoop(ctx context.Context) {
	defer close(m.doneChan)

	ticker := time.NewTicker(m.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.MonitorLog.Info("TrafficMonitor context cancelled")
			return
		case <-m.stopChan:
			logger.MonitorLog.Info("TrafficMonitor stop signal received")
			return
		case <-ticker.C:
			m.pollAndSend()
		}
	}
}

func (m *TrafficMonitor) pollAndSend() {
	// Read and reset metrics atomically
	metrics, err := m.ebpfMgr.ReadAndReset()
	if err != nil {
		logger.MonitorLog.Errorf("Failed to read eBPF metrics: %v", err)
		return
	}

	if len(metrics) == 0 {
		logger.MonitorLog.Infof("No traffic detected in this window (upfgtp interface)")
		return
	}

	logger.MonitorLog.Infof("Collected %d UE metrics", len(metrics))

	// Convert and send each UE's metrics
	for ueIpNet, rawMetrics := range metrics {
		ueIp := ebpf.IPFromNetByteOrder(ueIpNet).String()
		supi := m.smfClient.GetSupi(ueIp)

		record := ConvertToTrafficRecord(ueIp, supi, &rawMetrics, m.windowSeconds)

		// Non-blocking send
		select {
		case m.featureChan <- record:
			logger.MonitorLog.Infof("Sent traffic record for UE %s (SUPI: %s)", ueIp, supi)
		default:
			logger.MonitorLog.Warnf("Feature channel full, dropping record for %s", ueIp)
		}
	}
}
