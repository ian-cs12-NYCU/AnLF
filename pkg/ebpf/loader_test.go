package ebpf

import (
	"testing"
)

func TestLoadAnlfObjects(t *testing.T) {
	var objs anlfObjects

	err := loadAnlfObjects(&objs, nil)
	if err != nil {
		t.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	if objs.UeMetricsMap == nil {
		t.Fatal("UeMetricsMap is nil")
	}

	if objs.AnlfXdpMain == nil {
		t.Fatal("AnlfXdpMain program is nil")
	}

	t.Logf("Successfully loaded eBPF program and maps")
}
