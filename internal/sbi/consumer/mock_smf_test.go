package consumer

import (
"os"
"testing"
)

func TestMockSMF_LoadAndGet(t *testing.T) {
// Create temp JSON file
tmpFile, err := os.CreateTemp("", "ue_table_*.json")
if err != nil {
t.Fatalf("Failed to create temp file: %v", err)
}
defer os.Remove(tmpFile.Name())

// Write test data
testData := `{
"10.60.100.1": "imsi-208930000000001",
"10.60.100.2": "imsi-208930000000002"
}`
if _, err := tmpFile.WriteString(testData); err != nil {
t.Fatalf("Failed to write test data: %v", err)
}
tmpFile.Close()

// Test MockSMF
smf := NewMockSMF()
if err := smf.LoadUeTable(tmpFile.Name()); err != nil {
t.Fatalf("LoadUeTable failed: %v", err)
}

if count := smf.GetUeCount(); count != 2 {
t.Errorf("Expected 2 UEs, got %d", count)
}

// Test lookups
if supi := smf.GetSupi("10.60.100.1"); supi != "imsi-208930000000001" {
t.Errorf("Expected imsi-208930000000001, got %s", supi)
}

if supi := smf.GetSupi("10.60.100.2"); supi != "imsi-208930000000002" {
t.Errorf("Expected imsi-208930000000002, got %s", supi)
}

// Test unknown IP
if supi := smf.GetSupi("10.60.100.999"); supi != "unknown" {
t.Errorf("Expected 'unknown', got %s", supi)
}
}
