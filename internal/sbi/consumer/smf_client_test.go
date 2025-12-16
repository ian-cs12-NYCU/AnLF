package consumer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSMFClient_FetchUeData(t *testing.T) {
	// Create mock SMF server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request path
		expectedPath := "/nsmf-oam/v1/ue-pdu-session-info/"
		if r.URL.Path != expectedPath {
			t.Errorf("Expected path %s, got %s", expectedPath, r.URL.Path)
		}

		// Return mock response
		response := SmfOamResponse{
			PoolSize: 2,
			SmContexts: map[string]PduSessionInfo{
				"urn:uuid:test-1": {
					Supi:         "imsi-208930000000001",
					PduSessionId: "1",
					PduAddress:   "10.60.0.1",
				},
				"urn:uuid:test-2": {
					Supi:         "imsi-208930000000002",
					PduSessionId: "1",
					PduAddress:   "10.60.0.2",
				},
			},
			TotalContexts: 2,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer mockServer.Close()

	// Create SMF client
	client := NewSMFClient(mockServer.URL, 10*time.Second)

	// Fetch data
	err := client.fetchUeData()
	if err != nil {
		t.Fatalf("fetchUeData failed: %v", err)
	}

	// Verify UE count
	if count := client.GetUeCount(); count != 2 {
		t.Errorf("Expected 2 UEs, got %d", count)
	}

	// Verify SUPI lookups
	testCases := []struct {
		ip           string
		expectedSupi string
	}{
		{"10.60.0.1", "imsi-208930000000001"},
		{"10.60.0.2", "imsi-208930000000002"},
		{"10.60.0.999", "unknown"},
	}

	for _, tc := range testCases {
		supi := client.GetSupi(tc.ip)
		if supi != tc.expectedSupi {
			t.Errorf("GetSupi(%s): expected %s, got %s", tc.ip, tc.expectedSupi, supi)
		}
	}

	// Verify sorted UE IPs
	ueIps := client.GetAllUeIps()
	if len(ueIps) != 2 {
		t.Errorf("Expected 2 IPs, got %d", len(ueIps))
	}

	// Verify sorting by SUPI (imsi-208930000000001 should come first)
	if len(ueIps) >= 2 {
		if ueIps[0] != "10.60.0.1" {
			t.Errorf("Expected first IP to be 10.60.0.1, got %s", ueIps[0])
		}
		if ueIps[1] != "10.60.0.2" {
			t.Errorf("Expected second IP to be 10.60.0.2, got %s", ueIps[1])
		}
	}
}

func TestSMFClient_NoContexts(t *testing.T) {
	// Create mock SMF server that returns 404
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		response := map[string]string{
			"message": "No SM contexts found",
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer mockServer.Close()

	// Create SMF client
	client := NewSMFClient(mockServer.URL, 10*time.Second)

	// Fetch data
	err := client.fetchUeData()
	if err != nil {
		t.Fatalf("fetchUeData should not fail on 404: %v", err)
	}

	// Verify UE table is empty
	if count := client.GetUeCount(); count != 0 {
		t.Errorf("Expected 0 UEs on 404, got %d", count)
	}
}

func TestSMFClient_EmptyResponse(t *testing.T) {
	// Create mock SMF server with empty contexts
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := SmfOamResponse{
			PoolSize:      0,
			SmContexts:    map[string]PduSessionInfo{},
			TotalContexts: 0,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer mockServer.Close()

	// Create SMF client
	client := NewSMFClient(mockServer.URL, 10*time.Second)

	// Fetch data
	err := client.fetchUeData()
	if err != nil {
		t.Fatalf("fetchUeData failed: %v", err)
	}

	// Verify UE table is empty
	if count := client.GetUeCount(); count != 0 {
		t.Errorf("Expected 0 UEs, got %d", count)
	}
}

func TestSMFClient_PartialData(t *testing.T) {
	// Create mock SMF server with partial data (missing pduAddress)
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := SmfOamResponse{
			PoolSize: 2,
			SmContexts: map[string]PduSessionInfo{
				"urn:uuid:test-1": {
					Supi:         "imsi-208930000000001",
					PduSessionId: "1",
					PduAddress:   "10.60.0.1",
				},
				"urn:uuid:test-2": {
					Supi:         "imsi-208930000000002",
					PduSessionId: "1",
					PduAddress:   "", // Empty address - should be skipped
				},
			},
			TotalContexts: 2,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer mockServer.Close()

	// Create SMF client
	client := NewSMFClient(mockServer.URL, 10*time.Second)

	// Fetch data
	err := client.fetchUeData()
	if err != nil {
		t.Fatalf("fetchUeData failed: %v", err)
	}

	// Verify only valid UE is added
	if count := client.GetUeCount(); count != 1 {
		t.Errorf("Expected 1 UE (other has empty address), got %d", count)
	}

	// Verify the valid UE is accessible
	supi := client.GetSupi("10.60.0.1")
	if supi != "imsi-208930000000001" {
		t.Errorf("Expected imsi-208930000000001, got %s", supi)
	}
}

func TestSMFClient_StartStop(t *testing.T) {
	// Create mock SMF server
	requestCount := 0
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		response := SmfOamResponse{
			PoolSize:      0,
			SmContexts:    map[string]PduSessionInfo{},
			TotalContexts: 0,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer mockServer.Close()

	// Create SMF client with short poll interval
	client := NewSMFClient(mockServer.URL, 100*time.Millisecond)

	// Start client
	ctx := context.Background()
	if err := client.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Wait for a few polls
	time.Sleep(350 * time.Millisecond)

	// Stop client
	if err := client.Stop(5 * time.Second); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	// Record request count after stop
	countAfterStop := requestCount

	// Wait a bit more to ensure no more requests
	time.Sleep(200 * time.Millisecond)

	// Verify requests stopped
	if requestCount != countAfterStop {
		t.Errorf("Client did not stop properly, requests continued after Stop()")
	}

	// Verify at least some requests were made (at least initial + 2-3 polls)
	if requestCount < 3 {
		t.Errorf("Expected at least 3 requests (initial + polls), got %d", requestCount)
	}
}
