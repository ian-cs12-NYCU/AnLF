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

	// Test basic add and get (Sticky State)
	cache.Add("10.60.0.1", "160301")
	val, ok := cache.Get("10.60.0.1")
	if !ok {
		t.Fatal("Failed to get cache value")
	}
	if val != "160301" {
		t.Fatalf("Expected '160301', got %s", val)
	}

	// Test get again - data should still be there (not deleted)
	val, ok = cache.Get("10.60.0.1")
	if !ok {
		t.Fatal("Data should persist after Get")
	}
	if val != "160301" {
		t.Fatalf("Expected '160301', got %s", val)
	}

	// Test get on non-existent key
	val, ok = cache.Get("10.60.0.99")
	if ok {
		t.Fatal("Should return ok=false for non-existent key")
	}

	// Test multiple entries and update
	cache.Add("10.60.0.2", "aabbcc")
	cache.Add("10.60.0.3", "ddeeff")
	cache.Add("10.60.0.1", "new_hex") // Update existing entry
	if cache.Len() != 3 {
		t.Fatalf("Expected 3 entries, got %d", cache.Len())
	}

	// Verify update worked
	val, _ = cache.Get("10.60.0.1")
	if val != "new_hex" {
		t.Fatalf("Expected 'new_hex' after update, got %s", val)
	}
}

func TestTlsEventCacheConcurrency(t *testing.T) {
	cache := NewTlsEventCache()

	// Simple concurrent test
	done := make(chan bool)

	go func() {
		for i := 0; i < 100; i++ {
			cache.Add("10.60.0.1", "160301")
			cache.Get("10.60.0.1")
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			cache.Add("10.60.0.2", "aabbcc")
			cache.Get("10.60.0.2")
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
	// Test IP conversion after binary.Read with LittleEndian
	// When eBPF sends iph->saddr (0x0a3c0001 for 10.60.0.1 in network/big-endian),
	// binary.Read(..., LittleEndian) will read it as uint32 with byte order reversed
	// So we need LittleEndian.PutUint32 to restore the original byte order
	tests := []struct {
		ebpfValue uint32 // Value as received by binary.Read with LittleEndian
		expected  string
	}{
		{0x01643c0a, "10.60.100.1"},     // eBPF sends 0x0a3c6401, read as little-endian
		{0x02003c0a, "10.60.0.2"},       // eBPF sends 0x0a3c0002
		{0x0100007f, "127.0.0.1"},       // loopback
		{0xffffffff, "255.255.255.255"}, // broadcast (same in both endians)
	}

	for _, tt := range tests {
		ipBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(ipBytes, tt.ebpfValue)
		result := net.IP(ipBytes).String()
		if result != tt.expected {
			t.Fatalf("IP conversion failed: got %s, expected %s (input: 0x%08x)", result, tt.expected, tt.ebpfValue)
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
	// Simulate parsing a TLS event after binary.Read with LittleEndian
	// If eBPF sends 0x0a3c6401, binary.Read will interpret as 0x01643c0a
	event := TlsEventC{
		SrcIP:      0x01643c0a, // 10.60.100.1 after LittleEndian read
		DstIP:      0x02003c0a, // 10.60.0.2 after LittleEndian read
		SrcPort:    0x1234,
		DstPort:    0x01bb,
		PayloadLen: 5,
	}

	// Set payload to TLS handshake
	tlsData := []byte{0x16, 0x03, 0x01, 0x00, 0x50}
	copy(event.Payload[:], tlsData)

	// Convert IP (same as parseAndCache function)
	ipBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ipBytes, event.SrcIP)
	ueIP := net.IP(ipBytes).String()

	// Convert payload to hex
	validLen := int(event.PayloadLen)
	if validLen > 128 {
		validLen = 128
	}
	hexPayload := hex.EncodeToString(event.Payload[:validLen])

	// Verify
	if ueIP != "10.60.100.1" {
		t.Fatalf("IP conversion failed: got %s", ueIP)
	}
	if hexPayload != "1603010050" {
		t.Fatalf("Hex encoding failed: got %s", hexPayload)
	}
}
