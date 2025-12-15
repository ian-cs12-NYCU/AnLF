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

	batch := []*models.UeTrafficRecord{
		{
			UeIp: "60.60.0.1",
			Supi: "imsi-208930000000001",
		},
		{
			UeIp: "60.60.0.2",
			Supi: "imsi-208930000000002",
		},
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

	batch := []*models.UeTrafficRecord{
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
		batch := []*models.UeTrafficRecord{
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

		// Handle batch predictions
		if r.URL.Path == "/predict_batch" {
			var req models.BatchInferenceRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			results := make([]*models.InferenceResult, len(req.Records))
			for i, record := range req.Records {
				results[i] = &models.InferenceResult{
					UeIp:         record.UeIp,
					Supi:         record.Supi,
					Timestamp:    record.Timestamp,
					IsAnomaly:    true,
					AnomalyScore: 0.75,
					Prediction:   "attack",
					Confidence:   0.85,
					ModelVersion: "test-v1.0",
				}
			}

			resp := models.BatchInferenceResult{
				Results:      results,
				Timestamp:    req.Timestamp,
				BatchSize:    len(results),
				ModelVersion: "test-v1.0",
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}

		// Handle single prediction (legacy)
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
