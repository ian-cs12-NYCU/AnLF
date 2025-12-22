package detector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/free5gc/anlf/internal/analyzer/queue"
	"github.com/free5gc/anlf/pkg/models"
)

type MockExportHandler struct {
	enqueueCount atomic.Int32
}

func (m *MockExportHandler) Handle(msg *queue.ExportMessage) error {
	m.enqueueCount.Add(1)
	return nil
}

func TestAnomalyDetector_Disabled(t *testing.T) {
	mockHandler := &MockExportHandler{}
	exportQueue := queue.NewExportQueue(queue.QueueConfig{
		BufferSize:  100,
		WorkerCount: 2,
	}, mockHandler)

	detector, err := NewAnomalyDetector(AnomalyDetectorConfig{
		Enabled: false,
	}, exportQueue)

	if err != nil {
		t.Fatalf("Failed to create detector: %v", err)
	}

	batch := &models.BatchUeTrafficRecords{
		Records: []*models.UeTrafficRecord{
			{
				UeIp: "60.60.0.1",
				Supi: "imsi-208930000000001",
			},
			{
				UeIp: "60.60.0.2",
				Supi: "imsi-208930000000002",
			},
		},
		BatchSize: 2,
	}

	err = detector.EnqueueBatch(batch)
	if err != nil {
		t.Fatalf("Expected no error when disabled, got: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	if mockHandler.enqueueCount.Load() != 0 {
		t.Errorf("Expected no export when disabled, got %d", mockHandler.enqueueCount.Load())
	}
}

func TestAnomalyDetector_Success(t *testing.T) {
	server := newMockLLMServer(false, 0)
	defer server.Close()

	mockHandler := &MockExportHandler{}
	exportQueue := queue.NewExportQueue(queue.QueueConfig{
		BufferSize:  100,
		WorkerCount: 2,
	}, mockHandler)

	detector, err := NewAnomalyDetector(AnomalyDetectorConfig{
		Enabled:      true,
		LLMServerURL: server.URL,
		LLMTimeout:   5 * time.Second,
		QueueConfig: queue.QueueConfig{
			BufferSize:  100,
			WorkerCount: 2,
		},
	}, exportQueue)

	if err != nil {
		t.Fatalf("Failed to create detector: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := exportQueue.Start(ctx); err != nil {
		t.Fatalf("Failed to start export queue: %v", err)
	}
	defer exportQueue.Stop(2 * time.Second)

	if err := detector.Start(ctx); err != nil {
		t.Fatalf("Failed to start detector: %v", err)
	}
	defer detector.Stop(2 * time.Second)

	batch := &models.BatchUeTrafficRecords{
		Records: []*models.UeTrafficRecord{
			{
				UeIp:      "60.60.0.1",
				Supi:      "imsi-208930000000001",
				Timestamp: 1234567890,
			},
			{
				UeIp:      "60.60.0.2",
				Supi:      "imsi-208930000000002",
				Timestamp: 1234567890,
			},
		},
		BatchSize: 2,
	}

	err = detector.EnqueueBatch(batch)
	if err != nil {
		t.Fatalf("EnqueueBatch failed: %v", err)
	}

	time.Sleep(300 * time.Millisecond)

	// Expect 2 exports (one per UE in the batch)
	expectedExports := int32(2)
	if mockHandler.enqueueCount.Load() != expectedExports {
		t.Errorf("Expected %d exports, got %d", expectedExports, mockHandler.enqueueCount.Load())
	}
}

func TestAnomalyDetector_MultipleRecords(t *testing.T) {
	server := newMockLLMServer(false, 0)
	defer server.Close()

	mockHandler := &MockExportHandler{}
	exportQueue := queue.NewExportQueue(queue.QueueConfig{
		BufferSize:  1000,
		WorkerCount: 4,
	}, mockHandler)

	detector, err := NewAnomalyDetector(AnomalyDetectorConfig{
		Enabled:      true,
		LLMServerURL: server.URL,
		LLMTimeout:   5 * time.Second,
		QueueConfig: queue.QueueConfig{
			BufferSize:  1000,
			WorkerCount: 4,
		},
	}, exportQueue)

	if err != nil {
		t.Fatalf("Failed to create detector: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := exportQueue.Start(ctx); err != nil {
		t.Fatalf("Failed to start export queue: %v", err)
	}
	defer exportQueue.Stop(2 * time.Second)

	if err := detector.Start(ctx); err != nil {
		t.Fatalf("Failed to start detector: %v", err)
	}
	defer detector.Stop(2 * time.Second)

	batchCount := 5
	for i := 0; i < batchCount; i++ {
		batch := &models.BatchUeTrafficRecords{
			Records: []*models.UeTrafficRecord{
				{
					UeIp:      "60.60.0.1",
					Supi:      "imsi-208930000000001",
					Timestamp: int64(1234567890 + i),
				},
				{
					UeIp:      "60.60.0.2",
					Supi:      "imsi-208930000000002",
					Timestamp: int64(1234567890 + i),
				},
			},
			BatchSize: 2,
		}
		if err := detector.EnqueueBatch(batch); err != nil {
			t.Fatalf("EnqueueBatch failed for batch %d: %v", i, err)
		}
	}

	time.Sleep(500 * time.Millisecond)

	exports := mockHandler.enqueueCount.Load()
	expectedExports := int32(batchCount * 2) // 2 UEs per batch
	if exports != expectedExports {
		t.Errorf("Expected %d exports, got %d", expectedExports, exports)
	}
}

// Helper function to create a mock LLM server
func newMockLLMServer(shouldFail bool, delay time.Duration) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if delay > 0 {
			time.Sleep(delay)
		}

		if shouldFail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Handle OpenAI Chat Completions API
		if r.URL.Path == "/v1/chat/completions" {
			var req map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			// Extract messages from request
			messages, ok := req["messages"].([]interface{})
			if !ok || len(messages) == 0 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			// Get user message (should contain UE traffic data)
			userMsg, ok := messages[len(messages)-1].(map[string]interface{})
			if !ok {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			content, ok := userMsg["content"].(string)
			if !ok {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			// Parse UE records from content (it's a formatted prompt, so extract JSON part)
			// The content format is: "Analyze... Return...\n\n[JSON array]"
			jsonStart := strings.Index(content, "[")
			jsonEnd := strings.LastIndex(content, "]")
			if jsonStart < 0 || jsonEnd < 0 || jsonStart >= jsonEnd {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			jsonStr := content[jsonStart : jsonEnd+1]
			var records []*models.UeTrafficRecord
			if err := json.Unmarshal([]byte(jsonStr), &records); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			if len(records) == 0 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			// Generate results
			results := make([]*models.InferenceResult, len(records))
			for i, record := range records {
				results[i] = &models.InferenceResult{
					Supi:         record.Supi,
					AnomalyScore: 0.85,
				}
			}

			// Build OpenAI response format
			responseContent := map[string]interface{}{
				"results": results,
			}
			contentBytes, _ := json.Marshal(responseContent)

			openAIResp := map[string]interface{}{
				"choices": []map[string]interface{}{
					{
						"message": map[string]interface{}{
							"content": string(contentBytes),
						},
					},
				},
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(openAIResp)
			return
		}

		// Handle health check
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
}

// TestAnomalyDetector_EmptyRecords verifies that empty UE records (all zeros) are skipped
// and directly assigned risk value = 0 without sending LLM request
func TestAnomalyDetector_EmptyRecords(t *testing.T) {
	// Track number of LLM prediction requests (not health checks)
	var llmRequestCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only count actual prediction requests, not health checks
		if r.URL.Path == "/v1/chat/completions" {
			llmRequestCount.Add(1)

			// Return mock response (simulating single-UE format)
			openAIResp := map[string]interface{}{
				"choices": []map[string]interface{}{
					{
						"message": map[string]interface{}{
							"content": "Risk Score: 0.75",
						},
					},
				},
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(openAIResp)
			return
		}

		// Handle health check
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	mockHandler := &MockExportHandler{}
	exportQueue := queue.NewExportQueue(queue.QueueConfig{
		BufferSize:  100,
		WorkerCount: 2,
	}, mockHandler)

	detector, err := NewAnomalyDetector(AnomalyDetectorConfig{
		Enabled:      true,
		LLMServerURL: server.URL,
		LLMTimeout:   5 * time.Second,
		QueueConfig: queue.QueueConfig{
			BufferSize:  100,
			WorkerCount: 2,
		},
	}, exportQueue)

	if err != nil {
		t.Fatalf("Failed to create detector: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := exportQueue.Start(ctx); err != nil {
		t.Fatalf("Failed to start export queue: %v", err)
	}
	defer exportQueue.Stop(2 * time.Second)

	if err := detector.Start(ctx); err != nil {
		t.Fatalf("Failed to start detector: %v", err)
	}
	defer detector.Stop(2 * time.Second)

	// Create batch with mixed records: some empty, some with traffic
	batch := &models.BatchUeTrafficRecords{
		Records: []*models.UeTrafficRecord{
			// Empty record (all zeros) - should skip LLM request
			{
				Supi:      "imsi-208930000000001",
				Timestamp: time.Now().Unix(),
				UeIp:      "60.60.0.1",
				UeFeatureVector: models.UeFeatureVector{
					LogPPS:      0.0,
					AvgLen:      0.0,
					TcpRatio:    0.0,
					UdpRatio:    0.0,
					IcmpRatio:   0.0,
					SynRatio:    0.0,
					RstRatio:    0.0,
					NewFlowRate: 0.0,
					FanOut:      0.0,
				},
			},
			// Non-empty record - should send LLM request
			{
				Supi:      "imsi-208930000000002",
				Timestamp: time.Now().Unix(),
				UeIp:      "60.60.0.2",
				UeFeatureVector: models.UeFeatureVector{
					LogPPS:      3.5,
					AvgLen:      600.0,
					TcpRatio:    0.8,
					UdpRatio:    0.15,
					IcmpRatio:   0.05,
					SynRatio:    0.1,
					RstRatio:    0.01,
					NewFlowRate: 0.5,
					FanOut:      0.3,
				},
			},
			// Another empty record - should skip LLM request
			{
				Supi:      "imsi-208930000000003",
				Timestamp: time.Now().Unix(),
				UeIp:      "60.60.0.3",
				UeFeatureVector: models.UeFeatureVector{
					LogPPS:      0.0,
					AvgLen:      0.0,
					TcpRatio:    0.0,
					UdpRatio:    0.0,
					IcmpRatio:   0.0,
					SynRatio:    0.0,
					RstRatio:    0.0,
					NewFlowRate: 0.0,
					FanOut:      0.0,
				},
			},
		},
		BatchSize: 3,
		PollID:    1,
	}

	if err := detector.EnqueueBatch(batch); err != nil {
		t.Fatalf("Failed to enqueue batch: %v", err)
	}

	// Wait for processing
	time.Sleep(2 * time.Second)

	// Verify: Only 1 LLM request should be sent (for the non-empty record)
	requestCount := llmRequestCount.Load()
	if requestCount != 1 {
		t.Errorf("Expected 1 LLM request (only for non-empty record), got %d", requestCount)
	}

	// Verify: All 3 UEs should be exported (empty ones should still be in output)
	exportCount := mockHandler.enqueueCount.Load()
	if exportCount != 3 {
		t.Errorf("Expected 3 export messages (all UEs), got %d", exportCount)
	}

	t.Logf("✓ Empty records test passed: %d LLM requests, %d exports", requestCount, exportCount)
}

// TestIsEmptyRecord tests the isEmptyRecord helper function
func TestIsEmptyRecord(t *testing.T) {
	tests := []struct {
		name     string
		record   *models.UeTrafficRecord
		expected bool
	}{
		{
			name: "all zeros",
			record: &models.UeTrafficRecord{
				UeFeatureVector: models.UeFeatureVector{
					LogPPS:      0.0,
					AvgLen:      0.0,
					IcmpRatio:   0.0,
					TcpRatio:    0.0,
					UdpRatio:    0.0,
					SynRatio:    0.0,
					RstRatio:    0.0,
					NewFlowRate: 0.0,
					FanOut:      0.0,
				},
			},
			expected: true,
		},
		{
			name: "has LogPPS",
			record: &models.UeTrafficRecord{
				UeFeatureVector: models.UeFeatureVector{
					LogPPS:      3.5,
					AvgLen:      0.0,
					IcmpRatio:   0.0,
					TcpRatio:    0.0,
					UdpRatio:    0.0,
					SynRatio:    0.0,
					RstRatio:    0.0,
					NewFlowRate: 0.0,
					FanOut:      0.0,
				},
			},
			expected: false,
		},
		{
			name: "has AvgLen",
			record: &models.UeTrafficRecord{
				UeFeatureVector: models.UeFeatureVector{
					LogPPS:      0.0,
					AvgLen:      500.0,
					IcmpRatio:   0.0,
					TcpRatio:    0.0,
					UdpRatio:    0.0,
					SynRatio:    0.0,
					RstRatio:    0.0,
					NewFlowRate: 0.0,
					FanOut:      0.0,
				},
			},
			expected: false,
		},
		{
			name: "all fields populated",
			record: &models.UeTrafficRecord{
				UeFeatureVector: models.UeFeatureVector{
					LogPPS:      3.5,
					AvgLen:      600.0,
					IcmpRatio:   0.05,
					TcpRatio:    0.8,
					UdpRatio:    0.15,
					SynRatio:    0.1,
					RstRatio:    0.01,
					NewFlowRate: 0.5,
					FanOut:      0.3,
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isEmptyRecord(tt.record)
			if result != tt.expected {
				t.Errorf("isEmptyRecord() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestAnomalyDetector_EnabledFieldInitialization(t *testing.T) {
	mockHandler := &MockExportHandler{}
	exportQueue := queue.NewExportQueue(queue.QueueConfig{
		BufferSize:  100,
		WorkerCount: 2,
	}, mockHandler)

	// Test disabled detector
	disabledDetector, err := NewAnomalyDetector(AnomalyDetectorConfig{
		Enabled: false,
	}, exportQueue)
	if err != nil {
		t.Fatalf("Failed to create disabled detector: %v", err)
	}
	if disabledDetector.IsEnabled() {
		t.Error("Expected detector to be disabled, but IsEnabled() returned true")
	}
	if disabledDetector.enabled {
		t.Error("Expected detector.enabled to be false, but got true")
	}

	// Test enabled detector
	server := newMockLLMServer(false, 0)
	defer server.Close()

	enabledDetector, err := NewAnomalyDetector(AnomalyDetectorConfig{
		Enabled:      true,
		LLMServerURL: server.URL,
		LLMTimeout:   5 * time.Second,
		QueueConfig: queue.QueueConfig{
			BufferSize:  100,
			WorkerCount: 2,
		},
	}, exportQueue)
	if err != nil {
		t.Fatalf("Failed to create enabled detector: %v", err)
	}
	if !enabledDetector.IsEnabled() {
		t.Error("Expected detector to be enabled, but IsEnabled() returned false")
	}
	if !enabledDetector.enabled {
		t.Error("Expected detector.enabled to be true, but got false")
	}

	// Verify that enabled detector can actually enqueue batches
	batch := &models.BatchUeTrafficRecords{
		Records: []*models.UeTrafficRecord{
			{
				UeIp: "60.60.0.1",
				Supi: "imsi-208930000000001",
				UeFeatureVector: models.UeFeatureVector{
					LogPPS:   5.0,
					AvgLen:   500.0,
					TcpRatio: 0.8,
				},
			},
		},
		BatchSize: 1,
	}

	// Start the detector to enable queueing
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := exportQueue.Start(ctx); err != nil {
		t.Fatalf("Failed to start export queue: %v", err)
	}
	defer exportQueue.Stop(2 * time.Second)

	if err := enabledDetector.Start(ctx); err != nil {
		t.Fatalf("Failed to start enabled detector: %v", err)
	}
	defer enabledDetector.Stop(2 * time.Second)

	// This should succeed because detector is enabled
	err = enabledDetector.EnqueueBatch(batch)
	if err != nil {
		t.Errorf("Expected enabled detector to enqueue batch successfully, got error: %v", err)
	}
}
