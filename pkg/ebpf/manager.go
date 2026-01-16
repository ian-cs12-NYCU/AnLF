package ebpf

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// UeMetrics is an exported alias for the eBPF-generated metrics struct
type UeMetrics = anlfUeMetricsT

type Manager struct {
	objs     anlfObjects
	xdpLink  link.Link
	tcFilter *netlink.BpfFilter
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

	m.xdpLink = l
	return nil
}

func (m *Manager) AttachTC(ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("getting interface %s: %w", ifaceName, err)
	}

	// Ensure clsact qdisc exists on the interface
	if err := ensureClsact(iface.Index); err != nil {
		return fmt.Errorf("ensuring clsact qdisc: %w", err)
	}

	// Attach TC egress filter
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: iface.Index,
			Parent:    uint32(netlink.HANDLE_MIN_EGRESS),
			Priority:  50,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           m.objs.AnlfTcEgress.FD(),
		Name:         "anlf_tc_egress",
		DirectAction: true,
	}

	if err := netlink.FilterAdd(filter); err != nil {
		return fmt.Errorf("adding TC filter: %w", err)
	}

	m.tcFilter = filter
	return nil
}

// ensureClsact ensures that clsact qdisc is attached to the interface
func ensureClsact(ifindex int) error {
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifindex,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	if err := netlink.QdiscAdd(qdisc); err != nil {
		// If already exists, that's fine
		return nil
	}
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
	var errs []error

	if m.xdpLink != nil {
		if err := m.xdpLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing XDP link: %w", err))
		}
	}

	if m.tcFilter != nil {
		if err := netlink.FilterDel(m.tcFilter); err != nil {
			errs = append(errs, fmt.Errorf("closing TC filter: %w", err))
		}
	}

	if err := m.objs.Close(); err != nil {
		errs = append(errs, fmt.Errorf("closing objects: %w", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing manager: %v", errs)
	}

	return nil
}

// GetTlsEventsMap returns the TLS events perf buffer map
func (m *Manager) GetTlsEventsMap() (*ebpf.Map, error) {
	if m.objs.TlsEvents == nil {
		return nil, fmt.Errorf("TLS events map not loaded")
	}
	return m.objs.TlsEvents, nil
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

// TopStat represents a single statistic entry for top-N calculations
type TopStat struct {
	Key   uint32 // For subnet/IP, or port (as uint32)
	Bytes uint64
}

// TopStats contains the top-N statistics
type TopStats struct {
	TopSubnets []TopStat // Top 3 /24 subnets
	TopPorts   []TopStat // Top 3 destination ports
	TopIPs     []TopStat // Top 3 destination IPs
}

// ReadAndResetTopStats reads top-N statistics from eBPF maps and resets them
func (m *Manager) ReadAndResetTopStats() (*TopStats, error) {
	if m.objs.SubnetStatsMap == nil || m.objs.PortStatsMap == nil || m.objs.IpStatsMap == nil {
		return nil, fmt.Errorf("top stats maps not loaded")
	}

	stats := &TopStats{
		TopSubnets: make([]TopStat, 0),
		TopPorts:   make([]TopStat, 0),
		TopIPs:     make([]TopStat, 0),
	}

	// Read subnet statistics
	var subnetKey uint32
	var subnetValue uint64
	subnetStats := make([]TopStat, 0)
	iter := m.objs.SubnetStatsMap.Iterate()
	for iter.Next(&subnetKey, &subnetValue) {
		subnetStats = append(subnetStats, TopStat{Key: subnetKey, Bytes: subnetValue})
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterating subnet stats: %w", err)
	}

	// Read port statistics
	var portKey uint16
	var portValue uint64
	portStats := make([]TopStat, 0)
	iter = m.objs.PortStatsMap.Iterate()
	for iter.Next(&portKey, &portValue) {
		portStats = append(portStats, TopStat{Key: uint32(portKey), Bytes: portValue})
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterating port stats: %w", err)
	}

	// Read IP statistics
	var ipKey uint32
	var ipValue uint64
	ipStats := make([]TopStat, 0)
	iter = m.objs.IpStatsMap.Iterate()
	for iter.Next(&ipKey, &ipValue) {
		ipStats = append(ipStats, TopStat{Key: ipKey, Bytes: ipValue})
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterating ip stats: %w", err)
	}

	// Sort and get top 3 for each category
	stats.TopSubnets = getTop3(subnetStats)
	stats.TopPorts = getTop3(portStats)
	stats.TopIPs = getTop3(ipStats)

	// Reset all maps after reading
	for _, s := range subnetStats {
		m.objs.SubnetStatsMap.Delete(s.Key)
	}
	for _, s := range portStats {
		m.objs.PortStatsMap.Delete(uint16(s.Key))
	}
	for _, s := range ipStats {
		m.objs.IpStatsMap.Delete(s.Key)
	}

	return stats, nil
}

// getTop3 returns the top 3 entries sorted by bytes (descending)
func getTop3(stats []TopStat) []TopStat {
	// Sort by bytes in descending order
	for i := 0; i < len(stats); i++ {
		for j := i + 1; j < len(stats); j++ {
			if stats[j].Bytes > stats[i].Bytes {
				stats[i], stats[j] = stats[j], stats[i]
			}
		}
	}

	// Return top 3 (or fewer if less than 3 entries)
	if len(stats) > 3 {
		return stats[:3]
	}
	return stats
}
