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

// InferenceResultExporter implements Exporter interface for inference result CSV output
type InferenceResultExporter struct {
	file   *os.File
	writer *csv.Writer
	mu     sync.Mutex
}

// NewInferenceResultExporter creates a new inference result exporter with timestamped directory/file
func NewInferenceResultExporter(baseDir string) (*InferenceResultExporter, error) {
	// Generate timestamp-based path: baseDir/YYYYMMDD_HHMMSS/inference_YYYYMMDD_HHMMSS.csv
	timestamp := time.Now().Format("20060102_150405")
	sessionDir := filepath.Join(baseDir, timestamp)

	// Create session directory
	if err := os.MkdirAll(sessionDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create session directory: %w", err)
	}

	filePath := filepath.Join(sessionDir, fmt.Sprintf("inference_%s.csv", timestamp))
	file, err := os.Create(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSV file: %w", err)
	}

	writer := csv.NewWriter(file)
	exporter := &InferenceResultExporter{
		file:   file,
		writer: writer,
	}

	// Write header
	header := []string{
		"timestamp", "supi", "ue_ip",
		"is_anomaly", "anomaly_score", "prediction", "confidence", "model_version",
	}
	if err := writer.Write(header); err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to write CSV header: %w", err)
	}
	writer.Flush()

	logger.InitLog.Infof("Inference result exporter initialized: %s", filePath)
	return exporter, nil
}

// Export writes an InferenceResult to CSV file
func (e *InferenceResultExporter) Export(data interface{}) error {
	result, ok := data.(*models.InferenceResult)
	if !ok {
		return fmt.Errorf("invalid data type, expected *models.InferenceResult")
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	row := []string{
		strconv.FormatInt(result.Timestamp, 10),
		result.Supi,
		result.UeIp,
		strconv.FormatBool(result.IsAnomaly),
		fmt.Sprintf("%.4f", result.AnomalyScore),
		result.Prediction,
		fmt.Sprintf("%.4f", result.Confidence),
		result.ModelVersion,
	}

	if err := e.writer.Write(row); err != nil {
		return fmt.Errorf("failed to write CSV row: %w", err)
	}

	// Flush periodically
	e.writer.Flush()
	return e.writer.Error()
}

// Shutdown closes the CSV file and flushes remaining data
func (e *InferenceResultExporter) Shutdown() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	logger.InitLog.Info("Shutting down inference result exporter...")

	e.writer.Flush()
	if err := e.writer.Error(); err != nil {
		logger.InitLog.Errorf("CSV writer flush error: %v", err)
	}

	if err := e.file.Close(); err != nil {
		return fmt.Errorf("failed to close file: %w", err)
	}

	logger.InitLog.Info("Inference result exporter closed successfully")
	return nil
}

// Name returns the exporter identifier
func (e *InferenceResultExporter) Name() string {
	return "InferenceResultExporter"
}
