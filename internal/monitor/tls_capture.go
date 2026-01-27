package monitor

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/free5gc/anlf/internal/logger"
)

// TlsEventC mirrors the C struct from eBPF code
type TlsEventC struct {
	SrcIP      uint32
	DstIP      uint32
	SrcPort    uint16
	DstPort    uint16
	PayloadLen uint32
	Payload    [10]byte
}

// TlsEventCache provides thread-safe caching of TLS events
// Key: UE IP address string
// Value: Hex-encoded TLS payload
type TlsEventCache struct {
	sync.RWMutex
	data map[string]string
}

// NewTlsEventCache creates a new thread-safe TLS event cache
func NewTlsEventCache() *TlsEventCache {
	return &TlsEventCache{
		data: make(map[string]string),
	}
}

// Add stores a TLS event in the cache (overwrites if exists)
func (c *TlsEventCache) Add(ip string, hexPayload string) {
	c.Lock()
	defer c.Unlock()
	c.data[ip] = hexPayload
}

// Get retrieves a TLS event from the cache without removing it (Sticky State)
// This allows TLS hex data to persist across multiple collection windows
func (c *TlsEventCache) Get(ip string) (string, bool) {
	c.RLock()
	defer c.RUnlock()
	val, ok := c.data[ip]
	return val, ok
}

// Len returns the number of cached events
func (c *TlsEventCache) Len() int {
	c.RLock()
	defer c.RUnlock()
	return len(c.data)
}

// TlsEventReader reads TLS events from the eBPF Perf Buffer
type TlsEventReader struct {
	cache    *TlsEventCache
	stopChan chan struct{}
	doneChan chan struct{}
}

// NewTlsEventReader creates a new TLS event reader
func NewTlsEventReader(cache *TlsEventCache) *TlsEventReader {
	return &TlsEventReader{
		cache:    cache,
		stopChan: make(chan struct{}),
		doneChan: make(chan struct{}),
	}
}

// Start begins reading TLS events from the Perf Buffer
func (r *TlsEventReader) Start(eventsMap *ebpf.Map) error {
	if eventsMap == nil {
		return errors.New("events map is nil")
	}

	go r.readLoop(eventsMap)
	return nil
}

// Stop halts the TLS event reader
func (r *TlsEventReader) Stop() {
	close(r.stopChan)
	<-r.doneChan
}

// readLoop continuously reads from the Perf Buffer
func (r *TlsEventReader) readLoop(eventsMap *ebpf.Map) {
	defer close(r.doneChan)

	// Create perf event reader
	rd, err := perf.NewReader(eventsMap, 4096)
	if err != nil {
		logger.MonitorLog.Errorf("Failed to create perf reader for TLS events: %v", err)
		return
	}
	defer rd.Close()

	logger.MonitorLog.Info("TLS event reader started")

	for {
		select {
		case <-r.stopChan:
			logger.MonitorLog.Info("TLS event reader stopped")
			return
		default:
		}

		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			logger.MonitorLog.Debugf("Error reading perf record: %v", err)
			continue
		}

		// Parse the TLS event
		if err := r.parseAndCache(record.RawSample); err != nil {
			logger.MonitorLog.Debugf("Error parsing TLS event: %v", err)
		}
	}
}

// parseAndCache extracts TLS event from raw sample and caches it
func (r *TlsEventReader) parseAndCache(rawSample []byte) error {
	var event TlsEventC
	if err := binary.Read(bytes.NewReader(rawSample), binary.LittleEndian, &event); err != nil {
		return err
	}

	// Convert source IP from network byte order to string
	// eBPF sends iph->saddr in network byte order (big-endian)
	// When read with LittleEndian, the uint32 is byte-swapped
	// So we need to use LittleEndian.PutUint32 to get correct byte order
	ipBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ipBytes, event.SrcIP)
	ueIP := net.IP(ipBytes).String()

	// Validate payload length
	validLen := int(event.PayloadLen)
	if validLen > 10 {
		validLen = 10
	}
	if validLen < 0 {
		validLen = 0
	}

	// Convert to hex string
	hexPayload := hex.EncodeToString(event.Payload[:validLen])

	// Cache the event
	r.cache.Add(ueIP, hexPayload)

	logger.MonitorLog.Debugf("Cached TLS event from %s: %d bytes", ueIP, validLen)

	return nil
}
