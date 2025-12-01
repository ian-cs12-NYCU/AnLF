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
	"github.com/free5gc/anlf/pkg/models"
)

// CsvExporter implements Exporter interface for CSV file output
type CsvExporter struct {
	file   *os.File
	writer *csv.Writer
	mu     sync.Mutex
}

// NewCsvExporter creates a new CSV exporter with timestamped directory/file
func NewCsvExporter(baseDir string) (*CsvExporter, error) {
	// Generate timestamp-based path: baseDir/YYYYMMDD_HHMMSS/traffic_YYYYMMDD_HHMMSS.csv
	timestamp := time.Now().Format("20060102_150405")
	sessionDir := filepath.Join(baseDir, timestamp)

	// Create session directory
	if err := os.MkdirAll(sessionDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create session directory: %w", err)
	}

	filePath := filepath.Join(sessionDir, fmt.Sprintf("traffic_%s.csv", timestamp))
	file, err := os.Create(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSV file: %w", err)
	}

	writer := csv.NewWriter(file)
	exporter := &CsvExporter{
		file:   file,
		writer: writer,
	}

	// Write header
	header := []string{
		"timestamp", "supi", "ue_ip",
		"log_pps", "avg_len", "tcp_ratio", "udp_ratio", "icmp_ratio",
		"syn_ratio", "rst_ratio", "flow_rate", "fan_out",
	}
	if err := writer.Write(header); err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to write CSV header: %w", err)
	}
	writer.Flush()

	logger.InitLog.Infof("CSV exporter initialized: %s", filePath)
	return exporter, nil
}

// Export writes a UeTrafficRecord to CSV file
func (e *CsvExporter) Export(rec *models.UeTrafficRecord) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	row := []string{
		strconv.FormatInt(rec.Timestamp, 10),
		rec.Supi,
		rec.UeIp,
		fmt.Sprintf("%.4f", rec.LogPPS),
		fmt.Sprintf("%.4f", rec.AvgLen),
		fmt.Sprintf("%.4f", rec.TcpRatio),
		fmt.Sprintf("%.4f", rec.UdpRatio),
		fmt.Sprintf("%.4f", rec.IcmpRatio),
		fmt.Sprintf("%.4f", rec.SynRatio),
		fmt.Sprintf("%.4f", rec.RstRatio),
		fmt.Sprintf("%.4f", rec.FlowRate),
		fmt.Sprintf("%.4f", rec.FanOut),
	}

	if err := e.writer.Write(row); err != nil {
		return fmt.Errorf("failed to write CSV row: %w", err)
	}

	// Flush periodically (every write for safety, can be optimized later)
	e.writer.Flush()
	return e.writer.Error()
}

// Shutdown closes the CSV file and flushes remaining data
func (e *CsvExporter) Shutdown() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	logger.InitLog.Info("Shutting down CSV exporter...")

	e.writer.Flush()
	if err := e.writer.Error(); err != nil {
		logger.InitLog.Errorf("CSV writer flush error: %v", err)
	}

	if err := e.file.Close(); err != nil {
		return fmt.Errorf("failed to close CSV file: %w", err)
	}

	logger.InitLog.Info("CSV exporter shutdown complete")
	return nil
}

// Name returns the exporter identifier
func (e *CsvExporter) Name() string {
	return "CsvExporter"
}
