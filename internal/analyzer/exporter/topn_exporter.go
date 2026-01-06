package exporter

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/free5gc/anlf/internal/logger"
	"github.com/free5gc/anlf/pkg/ebpf"
)

// TopNExporter implements Exporter interface for Top-N statistics CSV output
type TopNExporter struct {
	file   *os.File
	writer *csv.Writer
	mu     sync.Mutex
}

// NewTopNExporter creates a new Top-N statistics CSV exporter
func NewTopNExporter(baseDir string) (*TopNExporter, error) {
	// Generate timestamp-based path: baseDir/YYYYMMDD_HHMMSS/topn_stats_YYYYMMDD_HHMMSS.csv
	timestamp := time.Now().Format("20060102_150405")
	sessionDir := filepath.Join(baseDir, timestamp)

	// Create session directory
	if err := os.MkdirAll(sessionDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create session directory: %w", err)
	}

	filePath := filepath.Join(sessionDir, fmt.Sprintf("topn_stats_%s.csv", timestamp))
	file, err := os.Create(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create Top-N stats CSV file: %w", err)
	}

	writer := csv.NewWriter(file)
	exporter := &TopNExporter{
		file:   file,
		writer: writer,
	}

	// Write header
	header := []string{
		"timestamp",
		"top1_subnet", "top1_subnet_bytes",
		"top2_subnet", "top2_subnet_bytes",
		"top3_subnet", "top3_subnet_bytes",
		"top1_port", "top1_port_bytes",
		"top2_port", "top2_port_bytes",
		"top3_port", "top3_port_bytes",
		"top1_ip", "top1_ip_bytes",
		"top2_ip", "top2_ip_bytes",
		"top3_ip", "top3_ip_bytes",
	}
	if err := writer.Write(header); err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to write Top-N stats CSV header: %w", err)
	}
	writer.Flush()

	logger.InitLog.Infof("Top-N stats CSV exporter initialized: %s", filePath)
	return exporter, nil
}

// Export writes Top-N statistics to CSV file
func (e *TopNExporter) Export(data interface{}) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	stats, ok := data.(*ebpf.TopStats)
	if !ok {
		return fmt.Errorf("invalid data type, expected *ebpf.TopStats")
	}

	timestamp := time.Now().Unix()
	row := make([]string, 19) // 1 timestamp + 18 data fields
	row[0] = strconv.FormatInt(timestamp, 10)

	// Top 3 Subnets
	for i := 0; i < 3; i++ {
		if i < len(stats.TopSubnets) {
			subnet := ebpf.IPFromNetByteOrder(stats.TopSubnets[i].Key)
			row[1+i*2] = fmt.Sprintf("%s/24", subnet.String())
			row[2+i*2] = strconv.FormatUint(stats.TopSubnets[i].Bytes, 10)
		} else {
			row[1+i*2] = ""
			row[2+i*2] = "0"
		}
	}

	// Top 3 Ports
	for i := 0; i < 3; i++ {
		if i < len(stats.TopPorts) {
			row[7+i*2] = strconv.FormatUint(uint64(stats.TopPorts[i].Key), 10)
			row[8+i*2] = strconv.FormatUint(stats.TopPorts[i].Bytes, 10)
		} else {
			row[7+i*2] = ""
			row[8+i*2] = "0"
		}
	}

	// Top 3 IPs
	for i := 0; i < 3; i++ {
		if i < len(stats.TopIPs) {
			ip := ebpf.IPFromNetByteOrder(stats.TopIPs[i].Key)
			row[13+i*2] = ip.String()
			row[14+i*2] = strconv.FormatUint(stats.TopIPs[i].Bytes, 10)
		} else {
			row[13+i*2] = ""
			row[14+i*2] = "0"
		}
	}

	if err := e.writer.Write(row); err != nil {
		return fmt.Errorf("failed to write Top-N stats row: %w", err)
	}

	e.writer.Flush()
	return e.writer.Error()
}

// Shutdown flushes buffer and closes file
func (e *TopNExporter) Shutdown() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.writer.Flush()
	if err := e.file.Close(); err != nil {
		return fmt.Errorf("failed to close Top-N stats CSV file: %w", err)
	}

	logger.InitLog.Info("Top-N stats CSV exporter shut down")
	return nil
}

// Name returns the exporter name
func (e *TopNExporter) Name() string {
	return "TopNExporter"
}
