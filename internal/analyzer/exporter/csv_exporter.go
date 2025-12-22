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
		// PPS (uplink and downlink paired)
		"ul_log_pps", "dl_log_pps",
		// Packet length (uplink and downlink paired)
		"ul_avg_len", "dl_avg_len",
		// Traffic ratios
		"pps_ratio", "byte_ratio",
		// Protocol ratios
		"tcp_ratio", "udp_ratio", "icmp_ratio",
		// TCP flags
		"syn_ratio", "rst_ratio",
		// Flow characteristics
		"new_flow_rate", "fan_out",
		// Downlink-specific
		"ack_ratio",
		// Global context (uplink)
		"global_avg_pps", "global_avg_flow_rate", "global_avg_ul_len",
		// Global context (downlink)
		"global_avg_dl_pps", "global_avg_dl_len", "global_avg_pps_ratio", "global_avg_byte_ratio",
	}
	if err := writer.Write(header); err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to write CSV header: %w", err)
	}
	writer.Flush()

	logger.InitLog.Infof("CSV exporter initialized: %s", filePath)
	return exporter, nil
}

// Export writes UeTrafficRecord(s) to CSV file
// Supports both single record and BatchUeTrafficRecords
func (e *CsvExporter) Export(data interface{}) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Handle batch traffic records
	if batch, ok := data.(*models.BatchUeTrafficRecords); ok {
		return e.exportBatch(batch)
	}

	// Handle single traffic record (legacy)
	if rec, ok := data.(*models.UeTrafficRecord); ok {
		return e.exportRecord(rec)
	}

	return fmt.Errorf("invalid data type, expected *models.UeTrafficRecord or *models.BatchUeTrafficRecords")
}

// exportBatch writes a batch of UE traffic records, sorted by SUPI
func (e *CsvExporter) exportBatch(batch *models.BatchUeTrafficRecords) error {
	// Sort records by SUPI
	sortedRecords := make([]*models.UeTrafficRecord, len(batch.Records))
	copy(sortedRecords, batch.Records)

	// Simple bubble sort by SUPI (sufficient for small batches like 20 UEs)
	for i := 0; i < len(sortedRecords)-1; i++ {
		for j := i + 1; j < len(sortedRecords); j++ {
			if sortedRecords[i].Supi > sortedRecords[j].Supi {
				sortedRecords[i], sortedRecords[j] = sortedRecords[j], sortedRecords[i]
			}
		}
	}

	// Write all sorted records
	for _, rec := range sortedRecords {
		if err := e.exportRecord(rec); err != nil {
			return err
		}
	}

	return nil
}

// exportRecord writes a single UE traffic record
func (e *CsvExporter) exportRecord(rec *models.UeTrafficRecord) error {
	row := []string{
		strconv.FormatInt(rec.Timestamp, 10),
		rec.Supi,
		rec.UeIp,
		// PPS (uplink and downlink paired)
		fmt.Sprintf("%.4f", rec.UlLogPPS),
		fmt.Sprintf("%.4f", rec.DlLogPPS),
		// Packet length (uplink and downlink paired)
		fmt.Sprintf("%.4f", rec.AvgLen),
		fmt.Sprintf("%.4f", rec.DlAvgLen),
		// Traffic ratios
		fmt.Sprintf("%.4f", rec.PPSRatio),
		fmt.Sprintf("%.4f", rec.ByteRatio),
		// Protocol ratios
		fmt.Sprintf("%.4f", rec.TcpRatio),
		fmt.Sprintf("%.4f", rec.UdpRatio),
		fmt.Sprintf("%.4f", rec.IcmpRatio),
		// TCP flags
		fmt.Sprintf("%.4f", rec.SynRatio),
		fmt.Sprintf("%.4f", rec.RstRatio),
		// Flow characteristics
		fmt.Sprintf("%.4f", rec.NewFlowRate),
		fmt.Sprintf("%.4f", rec.FanOut),
		// Downlink-specific
		fmt.Sprintf("%.4f", rec.AckRatio),
		// Global context (uplink)
		fmt.Sprintf("%.4f", rec.GlobalAvgPPS),
		fmt.Sprintf("%.4f", rec.GlobalAvgFlowRate),
		fmt.Sprintf("%.4f", rec.GlobalAvgUlLen),
		// Global context (downlink)
		fmt.Sprintf("%.4f", rec.GlobalAvgDlPPS),
		fmt.Sprintf("%.4f", rec.GlobalAvgDlLen),
		fmt.Sprintf("%.4f", rec.GlobalAvgPPSRatio),
		fmt.Sprintf("%.4f", rec.GlobalAvgByteRatio),
	}

	if err := e.writer.Write(row); err != nil {
		return fmt.Errorf("failed to write CSV row: %w", err)
	}

	// Flush after each record/batch
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
