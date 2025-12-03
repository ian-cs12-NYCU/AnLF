package consumer

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/free5gc/anlf/internal/logger"
)

// MockSMF provides UE IP to SUPI mapping
type MockSMF struct {
	ueTable map[string]string // key: UE IP, value: SUPI
	mu      sync.RWMutex
}

// NewMockSMF creates a new MockSMF instance
func NewMockSMF() *MockSMF {
	return &MockSMF{
		ueTable: make(map[string]string),
	}
}

// LoadUeTable reads static UE list from JSON file
func (m *MockSMF) LoadUeTable(filePath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read UE table: %w", err)
	}

	// Expected format: {"ue_ip": "supi", ...}
	var table map[string]string
	if err := json.Unmarshal(data, &table); err != nil {
		return fmt.Errorf("failed to parse UE table: %w", err)
	}

	m.ueTable = table
	logger.ConsumerLog.Infof("Loaded %d UE entries from %s", len(table), filePath)
	return nil
}

// GetSupi returns SUPI for given UE IP, returns "unknown" if not found
func (m *MockSMF) GetSupi(ueIp string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if supi, ok := m.ueTable[ueIp]; ok {
		return supi
	}
	return "unknown"
}

// GetUeCount returns the number of UEs in the table
func (m *MockSMF) GetUeCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.ueTable)
}

// GetAllUeIps returns a slice of all known UE IPs
func (m *MockSMF) GetAllUeIps() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ips := make([]string, 0, len(m.ueTable))
	for ip := range m.ueTable {
		ips = append(ips, ip)
	}
	return ips
}
