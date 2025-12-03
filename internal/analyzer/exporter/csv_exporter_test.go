package exporter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/free5gc/anlf/pkg/models"
)

func TestCsvExporter_ExportAndShutdown(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "test_csv_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create exporter (will create timestamped subdirectory)
	exp, err := NewCsvExporter(tmpDir)
	if err != nil {
		t.Fatalf("NewCsvExporter failed: %v", err)
	}

	// Export test record
	rec := &models.UeTrafficRecord{
		UeFeatureVector: models.UeFeatureVector{
			LogPPS:      2.0,
			AvgLen:      500.0,
			TcpRatio:    0.8,
			UdpRatio:    0.15,
			IcmpRatio:   0.05,
			SynRatio:    0.1,
			RstRatio:    0.01,
			NewFlowRate: 0.5,
			FanOut:      0.3,
		},
		Timestamp: time.Now().Unix(),
		Supi:      "imsi-208930000000001",
		UeIp:      "10.60.100.1",
	}

	if err := exp.Export(rec); err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	// Shutdown
	if err := exp.Shutdown(); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}

	// Find the generated CSV file in timestamped subdirectory
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("Failed to read temp dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("Expected 1 subdirectory, got %d", len(entries))
	}

	sessionDir := filepath.Join(tmpDir, entries[0].Name())
	csvFiles, err := filepath.Glob(filepath.Join(sessionDir, "traffic_*.csv"))
	if err != nil || len(csvFiles) == 0 {
		t.Fatalf("Failed to find CSV file in %s", sessionDir)
	}

	// Verify file content
	content, err := os.ReadFile(csvFiles[0])
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	lines := strings.Split(string(content), "\n")
	if len(lines) < 2 {
		t.Fatalf("Expected at least 2 lines (header + data), got %d", len(lines))
	}

	// Check header
	if !strings.Contains(lines[0], "timestamp") || !strings.Contains(lines[0], "supi") {
		t.Errorf("Header missing expected columns: %s", lines[0])
	}

	// Check data row contains expected values
	if !strings.Contains(lines[1], "imsi-208930000000001") {
		t.Errorf("Data row missing SUPI: %s", lines[1])
	}
	if !strings.Contains(lines[1], "10.60.100.1") {
		t.Errorf("Data row missing UE IP: %s", lines[1])
	}
}
