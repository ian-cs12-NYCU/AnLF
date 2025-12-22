package ebpf

import (
	"testing"
)

func TestLoadAnlfObjects(t *testing.T) {
	var objs anlfObjects

	err := loadAnlfObjects(&objs, nil)
	if err != nil {
		// eBPF loading requires CAP_BPF or root privileges
		// Skip test if permission denied
		if contains(err.Error(), "operation not permitted") || contains(err.Error(), "permission denied") {
			t.Skipf("Skipping eBPF load test: insufficient permissions (requires CAP_BPF or root). Error: %v", err)
		}
		t.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	if objs.UeMetricsMap == nil {
		t.Fatal("UeMetricsMap is nil")
	}

	if objs.AnlfXdpMain == nil {
		t.Fatal("AnlfXdpMain program is nil")
	}

	if objs.AnlfTcEgress == nil {
		t.Fatal("AnlfTcEgress program is nil")
	}

	t.Logf("Successfully loaded eBPF programs (XDP and TC) and maps")
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && containsHelper(s, substr)))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if s[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
