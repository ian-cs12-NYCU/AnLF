package monitor

import (
	"context"
	"fmt"
	"net"
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
	featureChan   chan<- *models.BatchUeTrafficRecords
	pollInterval  time.Duration
	windowSeconds float64
	stopChan      chan struct{}
	doneChan      chan struct{}
}

// NewTrafficMonitor creates a new traffic monitor
func NewTrafficMonitor(
	ebpfMgr *ebpf.Manager,
	smfClient *consumer.MockSMF,
	featureChan chan<- *models.BatchUeTrafficRecords,
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

	// Get all known UEs from SMF
	allUeIps := m.smfClient.GetAllUeIps()

	if len(allUeIps) == 0 {
		logger.MonitorLog.Warnf("No UEs configured in SMF")
		return
	}

	logger.MonitorLog.Infof("Processing %d known UEs (eBPF metrics for %d UEs)", len(allUeIps), len(metrics))

	// Collect all UE records in a batch
	records := make([]*models.UeTrafficRecord, 0, len(allUeIps))
	timestamp := time.Now().Unix()

	for _, ueIp := range allUeIps {
		supi := m.smfClient.GetSupi(ueIp)

		var record *models.UeTrafficRecord

		// Try to find metrics for this UE
		rawMetrics, hasMetrics := metrics[ipToUint32(ueIp)]

		if hasMetrics {
			// UE has traffic in this window
			record = ConvertToTrafficRecord(ueIp, supi, &rawMetrics, m.windowSeconds)
		} else {
			// UE has no traffic in this window - create zero-filled record
			record = &models.UeTrafficRecord{
				UeFeatureVector: models.UeFeatureVector{}, // All fields default to 0
				Timestamp:       timestamp,
				Supi:            supi,
				UeIp:            ueIp,
			}
		}

		records = append(records, record)
	}

	// Send batch of all UE records
	batch := &models.BatchUeTrafficRecords{
		Records:   records,
		Timestamp: timestamp,
		BatchSize: len(records),
	}

	// Non-blocking send
	select {
	case m.featureChan <- batch:
		logger.MonitorLog.Infof("Sent batch of %d UE traffic records", len(records))
	default:
		logger.MonitorLog.Warnf("Feature channel full, dropping batch of %d records", len(records))
	}
}

// ipToUint32 converts an IP string to uint32 in network byte order format
func ipToUint32(ipStr string) uint32 {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0
	}
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0]) | uint32(ip[1])<<8 | uint32(ip[2])<<16 | uint32(ip[3])<<24
}
