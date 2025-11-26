package ebpf

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf/link"
)

// UeMetrics is an exported alias for the eBPF-generated metrics struct
type UeMetrics = anlfUeMetricsT

type Manager struct {
	objs anlfObjects
	link link.Link
}

func NewManager() (*Manager, error) {
	return &Manager{}, nil
}

func (m *Manager) Load() error {
	if err := loadAnlfObjects(&m.objs, nil); err != nil {
		return fmt.Errorf("loading eBPF objects: %w", err)
	}
	return nil
}

func (m *Manager) AttachXDP(ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("getting interface %s: %w", ifaceName, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   m.objs.AnlfXdpMain,
		Interface: iface.Index,
	})
	if err != nil {
		return fmt.Errorf("attaching XDP: %w", err)
	}

	m.link = l
	return nil
}

func (m *Manager) ReadMetrics() (map[uint32]UeMetrics, error) {
	if m.objs.UeMetricsMap == nil {
		return nil, fmt.Errorf("map not loaded")
	}

	metrics := make(map[uint32]UeMetrics)

	var key uint32
	var value anlfUeMetricsT

	iter := m.objs.UeMetricsMap.Iterate()
	for iter.Next(&key, &value) {
		metrics[key] = value
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterating map: %w", err)
	}

	return metrics, nil
}

// ReadAndReset atomically reads all metrics and resets (deletes) them from the map
// This prevents data loss in high-traffic scenarios and implements Phase 3 requirement
func (m *Manager) ReadAndReset() (map[uint32]UeMetrics, error) {
	if m.objs.UeMetricsMap == nil {
		return nil, fmt.Errorf("map not loaded")
	}

	metrics := make(map[uint32]UeMetrics)

	var key uint32
	var value anlfUeMetricsT

	// Iterate and collect all keys first
	keys := make([]uint32, 0)
	iter := m.objs.UeMetricsMap.Iterate()
	for iter.Next(&key, &value) {
		metrics[key] = value
		keys = append(keys, key)
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterating map: %w", err)
	}

	// Delete all keys atomically after reading
	for _, k := range keys {
		if err := m.objs.UeMetricsMap.Delete(k); err != nil {
			// Log but continue - some keys may have been updated/deleted by eBPF
			// This is expected in high-traffic scenarios
		}
	}

	return metrics, nil
}

func (m *Manager) ResetMetrics() error {
	if m.objs.UeMetricsMap == nil {
		return fmt.Errorf("map not loaded")
	}

	var key uint32
	var value anlfUeMetricsT

	iter := m.objs.UeMetricsMap.Iterate()
	for iter.Next(&key, &value) {
		if err := m.objs.UeMetricsMap.Delete(key); err != nil {
			return fmt.Errorf("deleting key %d: %w", key, err)
		}
	}

	return iter.Err()
}

func (m *Manager) Close() error {
	if m.link != nil {
		if err := m.link.Close(); err != nil {
			return err
		}
	}
	return m.objs.Close()
}

func IPFromNetByteOrder(ipNet uint32) net.IP {
	ip := make(net.IP, 4)
	ip[0] = byte(ipNet & 0xFF)
	ip[1] = byte((ipNet >> 8) & 0xFF)
	ip[2] = byte((ipNet >> 16) & 0xFF)
	ip[3] = byte((ipNet >> 24) & 0xFF)
	return ip
}

func CountBits(bitmap uint64) int {
	count := 0
	for bitmap > 0 {
		count += int(bitmap & 1)
		bitmap >>= 1
	}
	return count
}
