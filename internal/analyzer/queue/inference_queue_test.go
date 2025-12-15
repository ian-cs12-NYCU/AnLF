package queue

import (
"context"
"sync/atomic"
"testing"
"time"

"github.com/free5gc/anlf/pkg/models"
)

type MockInferenceHandler struct {
handleCount atomic.Int32
lastRecord  *models.UeTrafficRecord
}

func (m *MockInferenceHandler) Handle(record *models.UeTrafficRecord) error {
m.handleCount.Add(1)
m.lastRecord = record
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

record := &models.UeTrafficRecord{
UeFeatureVector: models.UeFeatureVector{
LogPPS: 3.5,
},
UeIp: "60.60.0.1",
Supi: "imsi-001010000000001",
}

if err := queue.EnqueueInference(record); err != nil {
t.Fatalf("Failed to enqueue record: %v", err)
}

time.Sleep(100 * time.Millisecond)

if handler.handleCount.Load() != 1 {
t.Errorf("Expected handler called once, got %d", handler.handleCount.Load())
}

if handler.lastRecord == nil {
t.Fatal("Expected lastRecord to be set")
}

if handler.lastRecord.UeIp != record.UeIp {
t.Errorf("Expected UE IP %s, got %s", record.UeIp, handler.lastRecord.UeIp)
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

recordCount := 50
for i := 0; i < recordCount; i++ {
record := &models.UeTrafficRecord{
UeFeatureVector: models.UeFeatureVector{
LogPPS: float64(i),
},
UeIp: "60.60.0.1",
Supi: "imsi-001010000000001",
}
if err := queue.EnqueueInference(record); err != nil {
t.Fatalf("Failed to enqueue record %d: %v", i, err)
}
}

time.Sleep(500 * time.Millisecond)

handled := handler.handleCount.Load()
if handled != int32(recordCount) {
t.Errorf("Expected %d records handled, got %d", recordCount, handled)
}

if err := queue.Stop(2 * time.Second); err != nil {
t.Fatalf("Failed to stop queue: %v", err)
}
}
