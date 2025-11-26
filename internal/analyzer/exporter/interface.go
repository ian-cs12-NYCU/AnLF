package exporter

import "github.com/free5gc/anlf/pkg/models"

// Exporter defines the output strategy for analysis results
type Exporter interface {
	// Export receives traffic record and executes output (write to file or inference)
	Export(rec *models.UeTrafficRecord) error

	// Shutdown handles resource cleanup (flush buffer, close connection)
	Shutdown() error

	// Name returns identifier for logging (e.g., "CsvExporter", "LlmExporter")
	Name() string
}
