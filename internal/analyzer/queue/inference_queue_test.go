package queue

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/free5gc/anlf/pkg/models"
)

type MockInferenceHandler struct {
	handleCount  atomic.Int32
	lastBatch    *models.BatchUeTrafficRecords
	totalRecords atomic.Int32
}

func (m *MockInferenceHandler) HandleBatch(batch *models.BatchUeTrafficRecords) error {
	m.handleCount.Add(1)
	m.lastBatch = batch
	if batch != nil {
		m.totalRecords.Add(int32(len(batch.Records)))
	}
	return nil
}

func TestInferenceQueue_Basic(t *testing.T) {
	handler := &MockInferenceHandler{}
	cfg := QueueConfig{
		BufferSize:  100,
		WorkerCount: 2,
	}

	queue := NewInferenceQueue(cfg, handler)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := queue.Start(ctx); err != nil {
		t.Fatalf("Failed to start queue: %v", err)
	}

	batch := &models.BatchUeTrafficRecords{
		Records: []*models.UeTrafficRecord{
			{
				UeFeatureVector: models.UeFeatureVector{
					UlLogPPS: 3.5,
				},
				UeIp: "60.60.0.1",
				Supi: "imsi-001010000000001",
			},
			{
				UeFeatureVector: models.UeFeatureVector{
					UlLogPPS: 4.2,
				},
				UeIp: "60.60.0.2",
				Supi: "imsi-001010000000002",
			},
		},
		BatchSize: 2,
	}

	if err := queue.EnqueueBatch(batch); err != nil {
		t.Fatalf("Failed to enqueue batch: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	if handler.handleCount.Load() != 1 {
		t.Errorf("Expected handler called once, got %d", handler.handleCount.Load())
	}

	if handler.lastBatch == nil {
		t.Fatal("Expected lastBatch to be set")
	}

	if handler.lastBatch.BatchSize != 2 {
		t.Errorf("Expected batch size 2, got %d", handler.lastBatch.BatchSize)
	}

	if len(handler.lastBatch.Records) != 2 {
		t.Errorf("Expected 2 records, got %d", len(handler.lastBatch.Records))
	}

	if handler.lastBatch.Records[0].UeIp != batch.Records[0].UeIp {
		t.Errorf("Expected UE IP %s, got %s", batch.Records[0].UeIp, handler.lastBatch.Records[0].UeIp)
	}

	if err := queue.Stop(2 * time.Second); err != nil {
		t.Fatalf("Failed to stop queue: %v", err)
	}
}

func TestInferenceQueue_MultipleRecords(t *testing.T) {
	handler := &MockInferenceHandler{}
	cfg := QueueConfig{
		BufferSize:  1000,
		WorkerCount: 4,
	}

	queue := NewInferenceQueue(cfg, handler)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := queue.Start(ctx); err != nil {
		t.Fatalf("Failed to start queue: %v", err)
	}

	batchCount := 10
	for i := 0; i < batchCount; i++ {
		batch := &models.BatchUeTrafficRecords{
			Records: []*models.UeTrafficRecord{
				{
					UeFeatureVector: models.UeFeatureVector{
						UlLogPPS: float64(i * 5),
					},
					UeIp: "60.60.0.1",
					Supi: "imsi-001010000000001",
				},
				{
					UeFeatureVector: models.UeFeatureVector{
						UlLogPPS: float64(i*5 + 1),
					},
					UeIp: "60.60.0.2",
					Supi: "imsi-001010000000002",
				},
				{
					UeFeatureVector: models.UeFeatureVector{
						UlLogPPS: float64(i*5 + 2),
					},
					UeIp: "60.60.0.3",
					Supi: "imsi-001010000000003",
				},
			},
			BatchSize: 3,
		}
		if err := queue.EnqueueBatch(batch); err != nil {
			t.Fatalf("Failed to enqueue batch %d: %v", i, err)
		}
	}

	time.Sleep(500 * time.Millisecond)

	handled := handler.handleCount.Load()
	if handled != int32(batchCount) {
		t.Errorf("Expected %d batches handled, got %d", batchCount, handled)
	}

	totalRecords := handler.totalRecords.Load()
	if totalRecords != int32(batchCount*3) {
		t.Errorf("Expected %d total records, got %d", batchCount*3, totalRecords)
	}

	if err := queue.Stop(2 * time.Second); err != nil {
		t.Fatalf("Failed to stop queue: %v", err)
	}
}
