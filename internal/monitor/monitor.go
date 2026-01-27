package monitor

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/free5gc/anlf/internal/analyzer/exporter"
	"github.com/free5gc/anlf/internal/logger"
	"github.com/free5gc/anlf/internal/sbi/consumer"
	"github.com/free5gc/anlf/pkg/ebpf"
	"github.com/free5gc/anlf/pkg/models"
)

// TrafficMonitor polls eBPF maps and sends records to analyzer
type TrafficMonitor struct {
	ebpfMgr        *ebpf.Manager
	ueDataProvider consumer.UeDataProvider
	featureChan    chan<- *models.BatchUeTrafficRecords
	pollInterval   time.Duration
	windowSeconds  float64
	topNExporter   exporter.Exporter
	tlsCache       *TlsEventCache
	tlsReader      *TlsEventReader
	stopChan       chan struct{}
	doneChan       chan struct{}
}

// NewTrafficMonitor creates a new traffic monitor
func NewTrafficMonitor(
	ebpfMgr *ebpf.Manager,
	ueDataProvider consumer.UeDataProvider,
	featureChan chan<- *models.BatchUeTrafficRecords,
	pollInterval time.Duration,
) *TrafficMonitor {
	// Create Top-N statistics exporter
	topNExp, err := exporter.NewTopNExporter("./output")
	if err != nil {
		logger.MonitorLog.Errorf("Failed to create Top-N exporter: %v", err)
		topNExp = nil
	}

	// Create TLS event cache and reader
	tlsCache := NewTlsEventCache()
	tlsReader := NewTlsEventReader(tlsCache)

	return &TrafficMonitor{
		ebpfMgr:        ebpfMgr,
		ueDataProvider: ueDataProvider,
		featureChan:    featureChan,
		pollInterval:   pollInterval,
		windowSeconds:  pollInterval.Seconds(),
		topNExporter:   topNExp,
		tlsCache:       tlsCache,
		tlsReader:      tlsReader,
		stopChan:       make(chan struct{}),
		doneChan:       make(chan struct{}),
	}
}

// Start implements Lifecycle.Start
func (m *TrafficMonitor) Start(ctx context.Context) error {
	logger.MonitorLog.Infof("Starting TrafficMonitor (poll interval: %v)...", m.pollInterval)

	// Start TLS event reader
	tlsEventsMap, err := m.ebpfMgr.GetTlsEventsMap()
	if err != nil {
		logger.MonitorLog.Warnf("Failed to get TLS events map: %v", err)
	} else if tlsEventsMap != nil {
		if err := m.tlsReader.Start(tlsEventsMap); err != nil {
			logger.MonitorLog.Warnf("Failed to start TLS event reader: %v", err)
		}
	}

	go m.pollLoop(ctx)

	logger.MonitorLog.Info("TrafficMonitor started")
	return nil
}

// Stop implements Lifecycle.Stop
func (m *TrafficMonitor) Stop(timeout time.Duration) error {
	logger.MonitorLog.Info("Stopping TrafficMonitor...")

	// Stop TLS reader
	m.tlsReader.Stop()

	close(m.stopChan)

	select {
	case <-m.doneChan:
		// Shutdown Top-N exporter
		if m.topNExporter != nil {
			if err := m.topNExporter.Shutdown(); err != nil {
				logger.MonitorLog.Errorf("Failed to shutdown Top-N exporter: %v", err)
			}
		}
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

	// Read and reset top-N statistics
	topStats, err := m.ebpfMgr.ReadAndResetTopStats()
	if err != nil {
		logger.MonitorLog.Errorf("Failed to read top stats: %v", err)
	} else {
		// Log Top 3 statistics
		m.logTopStats(topStats)

		// Export to CSV file
		if m.topNExporter != nil {
			if err := m.topNExporter.Export(topStats); err != nil {
				logger.MonitorLog.Errorf("Failed to export Top-N stats: %v", err)
			}
		}
	}

	// Get all known UEs from UE data provider (already sorted by SUPI)
	allUeIps := m.ueDataProvider.GetAllUeIps()

	if len(allUeIps) == 0 {
		logger.MonitorLog.Warnf("No UEs configured in UE data provider")
		return
	}

	logger.MonitorLog.Infof("Processing %d known UEs (eBPF metrics for %d UEs), sorted by SUPI", len(allUeIps), len(metrics))

	// Collect all UE records in a batch
	records := make([]*models.UeTrafficRecord, 0, len(allUeIps))
	timestamp := time.Now().Unix()

	for _, ueIp := range allUeIps {
		supi := m.ueDataProvider.GetSupi(ueIp)

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

		// Check for TLS sample in cache (Sticky State: data persists across windows)
		// If UE reconnects and sends new Hello, eBPF will update the cache automatically
		if tlsHex, ok := m.tlsCache.Get(ueIp); ok {
			record.HasTlsSample = true
			record.TlsHelloHex = tlsHex
			logger.MonitorLog.Debugf("Added TLS sample for UE %s: %d bytes", ueIp, len(tlsHex)/2)
		} else {
			record.HasTlsSample = false
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

func (m *TrafficMonitor) logTopStats(stats *ebpf.TopStats) {
	if stats == nil {
		return
	}

	// Log Top 3 Subnets
	logger.MonitorLog.Infof("=== Top 3 Subnets (/24) ===")
	for i, s := range stats.TopSubnets {
		subnetIP := ebpf.IPFromNetByteOrder(s.Key)
		logger.MonitorLog.Infof("  #%d: %s/24 - %d bytes", i+1, subnetIP.String(), s.Bytes)
	}

	// Log Top 3 Ports
	logger.MonitorLog.Infof("=== Top 3 Destination Ports ===")
	for i, s := range stats.TopPorts {
		logger.MonitorLog.Infof("  #%d: Port %d - %d bytes", i+1, s.Key, s.Bytes)
	}

	// Log Top 3 IPs
	logger.MonitorLog.Infof("=== Top 3 Destination IPs ===")
	for i, s := range stats.TopIPs {
		destIP := ebpf.IPFromNetByteOrder(s.Key)
		logger.MonitorLog.Infof("  #%d: %s - %d bytes", i+1, destIP.String(), s.Bytes)
	}
}

// ipToUint32 converts an IP string to uint32 in network byte order (big-endian)
// This matches the format used by iph->saddr in eBPF (network byte order)
func ipToUint32(ipStr string) uint32 {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0
	}
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	// Convert IP to uint32 (Little Endian for x86)
	return uint32(ip[0]) | uint32(ip[1])<<8 | uint32(ip[2])<<16 | uint32(ip[3])<<24
}
