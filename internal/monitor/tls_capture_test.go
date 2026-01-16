package monitor

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"testing"
)

func TestTlsEventCache(t *testing.T) {
	cache := NewTlsEventCache()

	// Test basic add and pop
	cache.Add("10.60.0.1", "160301")
	val, ok := cache.Pop("10.60.0.1")
	if !ok {
		t.Fatal("Failed to pop cache value")
	}
	if val != "160301" {
		t.Fatalf("Expected '160301', got %s", val)
	}

	// Test pop on empty cache
	val, ok = cache.Pop("10.60.0.1")
	if ok {
		t.Fatal("Should return ok=false for non-existent key")
	}

	// Test multiple entries
	cache.Add("10.60.0.2", "aabbcc")
	cache.Add("10.60.0.3", "ddeeff")
	if cache.Len() != 2 {
		t.Fatalf("Expected 2 entries, got %d", cache.Len())
	}
}

func TestTlsEventCacheConcurrency(t *testing.T) {
	cache := NewTlsEventCache()

	// Simple concurrent test
	done := make(chan bool)

	go func() {
		for i := 0; i < 100; i++ {
			cache.Add("10.60.0.1", "160301")
			cache.Pop("10.60.0.1")
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			cache.Add("10.60.0.2", "aabbcc")
			cache.Pop("10.60.0.2")
		}
		done <- true
	}()

	<-done
	<-done
}

func TestTlsEventCStructLayout(t *testing.T) {
	// Verify that TlsEventC has the expected binary layout
	event := TlsEventC{
		SrcIP:      0x0a3c0001,
		DstIP:      0x0a3c0002,
		SrcPort:    0x1234,
		DstPort:    0x01bb, // 443 in big-endian
		PayloadLen: 100,
	}

	// Copy some test data
	copy(event.Payload[:], []byte("160301"))

	// Serialize to bytes
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, event)
	if err != nil {
		t.Fatalf("Failed to serialize: %v", err)
	}

	// Deserialize back
	var decoded TlsEventC
	err = binary.Read(bytes.NewReader(buf.Bytes()), binary.LittleEndian, &decoded)
	if err != nil {
		t.Fatalf("Failed to deserialize: %v", err)
	}

	if decoded.SrcIP != event.SrcIP {
		t.Fatalf("SrcIP mismatch: %x vs %x", decoded.SrcIP, event.SrcIP)
	}
	if decoded.PayloadLen != event.PayloadLen {
		t.Fatalf("PayloadLen mismatch: %d vs %d", decoded.PayloadLen, event.PayloadLen)
	}
}

func TestIPConversion(t *testing.T) {
	// Test network byte order to IP string conversion
	// Network byte order is big-endian for IPv4
	// So 0x0a3c0001 represents 10.60.0.1 in big-endian
	tests := []struct {
		netByteOrder uint32
		expected     string
	}{
		{0x0a3c0001, "10.60.0.1"},   // 10.60.0.1 in network byte order (big-endian)
		{0x0a3c0002, "10.60.0.2"},   // 10.60.0.2
		{0x7f000001, "127.0.0.1"},   // loopback
		{0xffffffff, "255.255.255.255"}, // broadcast
	}

	for _, tt := range tests {
		ipBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(ipBytes, tt.netByteOrder)
		result := net.IP(ipBytes).String()
		if result != tt.expected {
			t.Fatalf("IP conversion failed: got %s, expected %s (input: 0x%08x)", result, tt.expected, tt.netByteOrder)
		}
	}
}

func TestHexEncoding(t *testing.T) {
	// Test that payloads are correctly hex-encoded
	payload := []byte{0x16, 0x03, 0x01, 0x00, 0x50}
	hexStr := hex.EncodeToString(payload)
	expected := "1603010050"
	if hexStr != expected {
		t.Fatalf("Hex encoding failed: got %s, expected %s", hexStr, expected)
	}

	// Test decoding
	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("Hex decoding failed: %v", err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("Decoded payload doesn't match original")
	}
}

func TestTlsEventParsePayload(t *testing.T) {
	// Simulate parsing a TLS event
	event := TlsEventC{
		SrcIP:      0x0a3c0001,
		DstIP:      0x0a3c0002,
		SrcPort:    0x1234,
		DstPort:    0x01bb,
		PayloadLen: 5,
	}

	// Set payload to TLS handshake
	tlsData := []byte{0x16, 0x03, 0x01, 0x00, 0x50}
	copy(event.Payload[:], tlsData)

	// Convert IP
	ipBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(ipBytes, event.SrcIP)
	ueIP := net.IP(ipBytes).String()

	// Convert payload to hex
	validLen := int(event.PayloadLen)
	if validLen > 128 {
		validLen = 128
	}
	hexPayload := hex.EncodeToString(event.Payload[:validLen])

	// Verify
	if ueIP != "10.60.0.1" {
		t.Fatalf("IP conversion failed: got %s", ueIP)
	}
	if hexPayload != "1603010050" {
		t.Fatalf("Hex encoding failed: got %s", hexPayload)
	}
}
