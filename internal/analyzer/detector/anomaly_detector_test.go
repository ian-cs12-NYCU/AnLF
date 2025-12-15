package detector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

	record := &models.UeTrafficRecord{
		UeIp: "60.60.0.1",
		Supi: "imsi-001010000000001",
	}

	err = detector.EnqueueRecord(record)
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

	record := &models.UeTrafficRecord{
		UeIp:      "60.60.0.1",
		Supi:      "imsi-001010000000001",
		Timestamp: 1234567890,
	}

	err = detector.EnqueueRecord(record)
	if err != nil {
		t.Fatalf("EnqueueRecord failed: %v", err)
	}

	time.Sleep(300 * time.Millisecond)

	if mockHandler.enqueueCount.Load() != 1 {
		t.Errorf("Expected 1 export, got %d", mockHandler.enqueueCount.Load())
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

	recordCount := 10
	for i := 0; i < recordCount; i++ {
		record := &models.UeTrafficRecord{
			UeIp:      "60.60.0.1",
			Supi:      "imsi-001010000000001",
			Timestamp: int64(1234567890 + i),
		}
		if err := detector.EnqueueRecord(record); err != nil {
			t.Fatalf("EnqueueRecord failed for record %d: %v", i, err)
		}
	}

	time.Sleep(500 * time.Millisecond)

	exports := mockHandler.enqueueCount.Load()
	if exports != int32(recordCount) {
		t.Errorf("Expected %d exports, got %d", recordCount, exports)
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

		var req models.InferenceRequest
		json.NewDecoder(r.Body).Decode(&req)

		resp := models.InferenceResult{
			UeIp:         req.Record.UeIp,
			Supi:         req.Record.Supi,
			Timestamp:    req.Record.Timestamp,
			IsAnomaly:    true,
			AnomalyScore: 0.75,
			Prediction:   "attack",
			Confidence:   0.85,
			ModelVersion: "test-v1.0",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
}
