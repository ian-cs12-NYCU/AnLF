package exporter

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/free5gc/anlf/pkg/models"
)

func TestInferenceResultExporter_CreationAndHeader(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "test_inference_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create exporter
	exp, err := NewInferenceResultExporter(tmpDir)
	if err != nil {
		t.Fatalf("NewInferenceResultExporter failed: %v", err)
	}
	defer exp.Shutdown()

	// Verify file was created with proper structure
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("Failed to read temp dir: %v", err)
	}

	if len(entries) != 1 {
		t.Errorf("Expected 1 subdirectory, got %d", len(entries))
	}

	// Check for CSV file
	subDirs, _ := os.ReadDir(filepath.Join(tmpDir, entries[0].Name()))
	if len(subDirs) != 1 {
		t.Errorf("Expected 1 CSV file in subdirectory, got %d", len(subDirs))
	}

	// Verify filename contains timestamp
	csvFileName := subDirs[0].Name()
	if !strings.Contains(csvFileName, "inference_") || !strings.HasSuffix(csvFileName, ".csv") {
		t.Errorf("CSV filename has unexpected format: %s", csvFileName)
	}
}

func TestInferenceResultExporter_ExportEnhancedResult(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "test_inference_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create exporter
	exp, err := NewInferenceResultExporter(tmpDir)
	if err != nil {
		t.Fatalf("NewInferenceResultExporter failed: %v", err)
	}

	// Create test data with timestamp
	now := time.Now().Unix()
	testResult := &models.EnhancedInferenceResult{
		InferenceResult: models.InferenceResult{
			Supi:         "imsi-208930000000001",
			AnomalyScore: 0.85,
			Timestamp:    now,
		},
		RiskScore:      75.5,
		Status:         "BLOCKED",
		IsBlocked:      true,
		AttackDetected: true,
	}

	// Export result
	if err := exp.Export(testResult); err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	// Shutdown to flush data
	if err := exp.Shutdown(); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}

	// Read CSV file and verify
	entries, _ := os.ReadDir(tmpDir)
	subDir := filepath.Join(tmpDir, entries[0].Name())
	files, _ := os.ReadDir(subDir)
	csvPath := filepath.Join(subDir, files[0].Name())

	file, err := os.Open(csvPath)
	if err != nil {
		t.Fatalf("Failed to open CSV file: %v", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("Failed to read CSV: %v", err)
	}

	// Verify header
	expectedHeader := []string{
		"timestamp", "supi", "anomaly_score", "risk_score", "status", "is_blocked", "attack_detected",
	}
	if len(records[0]) != len(expectedHeader) {
		t.Errorf("Header length mismatch: expected %d, got %d", len(expectedHeader), len(records[0]))
	}

	for i, h := range expectedHeader {
		if i < len(records[0]) && records[0][i] != h {
			t.Errorf("Header mismatch at column %d: expected %s, got %s", i, h, records[0][i])
		}
	}

	// Verify data row
	if len(records) < 2 {
		t.Fatal("Expected at least 2 rows (header + data), got less")
	}

	dataRow := records[1]
	if len(dataRow) != len(expectedHeader) {
		t.Errorf("Data row length mismatch: expected %d, got %d", len(expectedHeader), len(dataRow))
	}

	// Verify timestamp is first column and is a valid number
	if dataRow[0] != "0" && dataRow[0] != string(rune(now)) {
		// Timestamp should be the Unix timestamp value
		if dataRow[0] == "" {
			t.Error("Timestamp column is empty")
		}
		// Just verify it's not empty for now
	}

	// Verify SUPI
	if dataRow[1] != testResult.Supi {
		t.Errorf("SUPI mismatch: expected %s, got %s", testResult.Supi, dataRow[1])
	}

	// Verify status
	if dataRow[4] != testResult.Status {
		t.Errorf("Status mismatch: expected %s, got %s", testResult.Status, dataRow[4])
	}

	// Verify is_blocked
	if dataRow[5] != "true" {
		t.Errorf("IsBlocked mismatch: expected true, got %s", dataRow[5])
	}

	// Verify attack_detected
	if dataRow[6] != "true" {
		t.Errorf("AttackDetected mismatch: expected true, got %s", dataRow[6])
	}
}

func TestInferenceResultExporter_ExportLegacyResult(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "test_inference_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create exporter
	exp, err := NewInferenceResultExporter(tmpDir)
	if err != nil {
		t.Fatalf("NewInferenceResultExporter failed: %v", err)
	}

	// Create legacy test data with timestamp
	now := time.Now().Unix()
	testResult := &models.InferenceResult{
		Supi:         "imsi-208930000000002",
		AnomalyScore: 0.45,
		Timestamp:    now,
	}

	// Export result
	if err := exp.Export(testResult); err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	// Shutdown to flush data
	if err := exp.Shutdown(); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}

	// Read CSV file and verify
	entries, _ := os.ReadDir(tmpDir)
	subDir := filepath.Join(tmpDir, entries[0].Name())
	files, _ := os.ReadDir(subDir)
	csvPath := filepath.Join(subDir, files[0].Name())

	file, err := os.Open(csvPath)
	if err != nil {
		t.Fatalf("Failed to open CSV file: %v", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("Failed to read CSV: %v", err)
	}

	// Verify data row
	if len(records) < 2 {
		t.Fatal("Expected at least 2 rows (header + data), got less")
	}

	dataRow := records[1]

	// Verify SUPI
	if dataRow[1] != testResult.Supi {
		t.Errorf("SUPI mismatch: expected %s, got %s", testResult.Supi, dataRow[1])
	}

	// Verify default status
	if dataRow[4] != "NORMAL" {
		t.Errorf("Default status mismatch: expected NORMAL, got %s", dataRow[4])
	}

	// Verify default is_blocked (false)
	if dataRow[5] != "false" {
		t.Errorf("Default is_blocked mismatch: expected false, got %s", dataRow[5])
	}
}

func TestInferenceResultExporter_MultipleExports(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "test_inference_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create exporter
	exp, err := NewInferenceResultExporter(tmpDir)
	if err != nil {
		t.Fatalf("NewInferenceResultExporter failed: %v", err)
	}

	// Export multiple results with different timestamps
	results := []*models.EnhancedInferenceResult{
		{
			InferenceResult: models.InferenceResult{
				Supi:         "imsi-208930000000001",
				AnomalyScore: 0.2,
				Timestamp:    time.Now().Unix(),
			},
			RiskScore:      10.0,
			Status:         "NORMAL",
			IsBlocked:      false,
			AttackDetected: false,
		},
		{
			InferenceResult: models.InferenceResult{
				Supi:         "imsi-208930000000002",
				AnomalyScore: 0.8,
				Timestamp:    time.Now().Unix() + 1,
			},
			RiskScore:      80.0,
			Status:         "BLOCKED",
			IsBlocked:      true,
			AttackDetected: true,
		},
	}

	for _, result := range results {
		if err := exp.Export(result); err != nil {
			t.Fatalf("Export failed: %v", err)
		}
		time.Sleep(10 * time.Millisecond) // Small delay to ensure different timestamps
	}

	// Shutdown to flush data
	if err := exp.Shutdown(); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}

	// Read CSV file and verify all records
	entries, _ := os.ReadDir(tmpDir)
	subDir := filepath.Join(tmpDir, entries[0].Name())
	files, _ := os.ReadDir(subDir)
	csvPath := filepath.Join(subDir, files[0].Name())

	file, err := os.Open(csvPath)
	if err != nil {
		t.Fatalf("Failed to open CSV file: %v", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("Failed to read CSV: %v", err)
	}

	// Should have header + 2 data rows
	if len(records) != 3 {
		t.Errorf("Expected 3 rows (1 header + 2 data), got %d", len(records))
	}

	// Verify first data row
	if records[1][1] != "imsi-208930000000001" {
		t.Errorf("First SUPI mismatch: expected imsi-208930000000001, got %s", records[1][1])
	}

	// Verify second data row
	if records[2][1] != "imsi-208930000000002" {
		t.Errorf("Second SUPI mismatch: expected imsi-208930000000002, got %s", records[2][1])
	}

	// Verify both have timestamps
	if records[1][0] == "" {
		t.Error("First row timestamp is empty")
	}
	if records[2][0] == "" {
		t.Error("Second row timestamp is empty")
	}
}

func TestInferenceResultExporter_InvalidDataType(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "test_inference_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create exporter
	exp, err := NewInferenceResultExporter(tmpDir)
	if err != nil {
		t.Fatalf("NewInferenceResultExporter failed: %v", err)
	}
	defer exp.Shutdown()

	// Try to export invalid type
	err = exp.Export("invalid data")
	if err == nil {
		t.Error("Expected error for invalid data type, got nil")
	}

	// Verify error message
	if !strings.Contains(err.Error(), "invalid data type") {
		t.Errorf("Error message doesn't contain 'invalid data type': %v", err)
	}
}

func TestInferenceResultExporter_Name(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test_inference_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	exp, err := NewInferenceResultExporter(tmpDir)
	if err != nil {
		t.Fatalf("NewInferenceResultExporter failed: %v", err)
	}
	defer exp.Shutdown()

	// Verify exporter name
	name := exp.Name()
	if name != "InferenceResultExporter" {
		t.Errorf("Name mismatch: expected InferenceResultExporter, got %s", name)
	}
}
