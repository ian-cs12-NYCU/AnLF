package exporter

// Exporter defines the output strategy for analysis results
type Exporter interface {
	// Export receives data and executes output (write to file or inference)
	// Accepts interface{} to support different data types (UeTrafficRecord, InferenceResult, etc.)
	Export(data interface{}) error

	// Shutdown handles resource cleanup (flush buffer, close connection)
	Shutdown() error

	// Name returns identifier for logging (e.g., "CsvExporter", "InferenceResultExporter")
	Name() string
}
