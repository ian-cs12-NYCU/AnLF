package exporter

// StubExporter is a no-op exporter for when recording is disabled
type StubExporter struct{}

// NewStubExporter creates a new stub exporter
func NewStubExporter() *StubExporter {
	return &StubExporter{}
}

// Export does nothing
func (e *StubExporter) Export(data interface{}) error {
	return nil
}

// Shutdown does nothing
func (e *StubExporter) Shutdown() error {
	return nil
}

// Name returns the exporter identifier
func (e *StubExporter) Name() string {
	return "StubExporter"
}
