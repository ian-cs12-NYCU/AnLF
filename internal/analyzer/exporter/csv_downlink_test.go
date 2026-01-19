package exporter

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/free5gc/anlf/pkg/models"
)

// TestCsvExporter_DownlinkFeatures specifically tests downlink feature export
func TestCsvExporter_DownlinkFeatures(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "test_csv_downlink_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create exporter
	exp, err := NewCsvExporter(tmpDir)
	if err != nil {
		t.Fatalf("NewCsvExporter failed: %v", err)
	}

	// Create test records with various traffic patterns
	records := []*models.UeTrafficRecord{
		// Normal download traffic (high byte ratio)
		{
			UeFeatureVector: models.UeFeatureVector{
				UlLogPPS:  3.0,
				AvgLen:    512.0,
				TcpRatio:  0.9,
				SynRatio:  0.05,
				DlLogPPS:  5000.0,
				DlAvgLen:  1450.0, // Near MTU
				PPSRatio:  1.2,
				ByteRatio: 15.5, // High ratio = download
				AckRatio:  0.85, // Normal ACK ratio
			},
			Timestamp: time.Now().Unix(),
			Supi:      "imsi-001",
			UeIp:      "10.60.0.1",
		},
		// Attack traffic (asymmetric)
		{
			UeFeatureVector: models.UeFeatureVector{
				UlLogPPS:  5.0,
				AvgLen:    64.0,
				TcpRatio:  0.8,
				SynRatio:  0.7,
				DlLogPPS:  100.0, // Very low
				DlAvgLen:  80.0,  // Small packets
				PPSRatio:  0.01,  // Asymmetric
				ByteRatio: 0.005, // Very low
				AckRatio:  0.1,   // Few ACKs
			},
			Timestamp: time.Now().Unix(),
			Supi:      "imsi-002",
			UeIp:      "10.60.0.2",
		},
	}

	// Export batch
	batch := &models.BatchUeTrafficRecords{
		Records: records,
	}
	if err := exp.Export(batch); err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	// Shutdown
	if err := exp.Shutdown(); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}

	// Find and read CSV file
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("Failed to read temp dir: %v", err)
	}
	sessionDir := filepath.Join(tmpDir, entries[0].Name())
	csvFiles, err := filepath.Glob(filepath.Join(sessionDir, "traffic_*.csv"))
	if err != nil || len(csvFiles) == 0 {
		t.Fatalf("Failed to find CSV file")
	}

	// Read and verify CSV structure
	file, err := os.Open(csvFiles[0])
	if err != nil {
		t.Fatalf("Failed to open CSV file: %v", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	rows, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("Failed to read CSV: %v", err)
	}

	// Verify header count
	// 3 metadata (timestamp, supi, ue_ip) +
	// 2 pairs uplink PPS (ul_log_pps, global_ul_log_pps) +
	// 2 pairs downlink PPS (dl_log_pps, global_dl_log_pps) +
	// 2 pairs uplink length (ul_avg_len, global_ul_avg_len) +
	// 2 pairs downlink length (dl_avg_len, global_dl_avg_len) +
	// 2 pairs PPS ratio (pps_ratio, global_pps_ratio) +
	// 2 pairs byte ratio (byte_ratio, global_byte_ratio) +
	// 3 protocol (tcp_ratio, udp_ratio, icmp_ratio) +
	// 2 TCP flags (syn_ratio, rst_ratio) +
	// 2 pairs flow rate (new_flow_rate, global_new_flow_rate) +
	// 2 pairs fan out (fan_out, global_fan_out) +
	// 1 downlink ACK (ack_ratio) +
	// 2 TLS DPI (has_tls_sample, tls_hello_hex)
	// = 27 columns total
	expectedColumns := 27
	if len(rows[0]) != expectedColumns {
		t.Errorf("Expected %d columns, got %d. Header: %v", expectedColumns, len(rows[0]), rows[0])
	}

	// Verify downlink columns exist
	header := rows[0]
	dlColumns := []string{"dl_log_pps", "dl_avg_len", "pps_ratio", "byte_ratio", "ack_ratio"}
	for _, col := range dlColumns {
		found := false
		for _, h := range header {
			if h == col {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Missing downlink column: %s", col)
		}
	}

	// Verify data rows (should be 2 records + 1 header)
	if len(rows) != 3 {
		t.Errorf("Expected 3 rows (header + 2 data), got %d", len(rows))
	}

	t.Logf("CSV Export Test Passed!")
	t.Logf("Header: %v", rows[0])
	t.Logf("Normal Download Record: %v", rows[1])
	t.Logf("Attack Record: %v", rows[2])
}
