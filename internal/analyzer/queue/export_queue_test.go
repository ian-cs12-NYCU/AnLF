package queue

import (
"context"
"sync/atomic"
"testing"
"time"

"github.com/free5gc/anlf/pkg/models"
)

type MockExportHandler struct {
handleCount atomic.Int32
lastMessage *ExportMessage
}

func (m *MockExportHandler) Handle(msg *ExportMessage) error {
m.handleCount.Add(1)
m.lastMessage = msg
return nil
}

func TestExportQueue_Basic(t *testing.T) {
handler := &MockExportHandler{}
cfg := QueueConfig{
BufferSize:  100,
WorkerCount: 2,
}

queue := NewExportQueue(cfg, handler)
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
msg := NewTrafficRecordMessage(record)

if err := queue.EnqueueExport(msg); err != nil {
t.Fatalf("Failed to enqueue message: %v", err)
}

time.Sleep(100 * time.Millisecond)

if handler.handleCount.Load() != 1 {
t.Errorf("Expected handler called once, got %d", handler.handleCount.Load())
}

if err := queue.Stop(2 * time.Second); err != nil {
t.Fatalf("Failed to stop queue: %v", err)
}
}

func TestExportQueue_MultipleMessages(t *testing.T) {
handler := &MockExportHandler{}
cfg := QueueConfig{
BufferSize:  1000,
WorkerCount: 4,
}

queue := NewExportQueue(cfg, handler)
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

if err := queue.Start(ctx); err != nil {
t.Fatalf("Failed to start queue: %v", err)
}

messageCount := 100
for i := 0; i < messageCount; i++ {
record := &models.UeTrafficRecord{
UeFeatureVector: models.UeFeatureVector{
LogPPS: float64(i),
},
UeIp: "60.60.0.1",
Supi: "imsi-001010000000001",
}
msg := NewTrafficRecordMessage(record)
if err := queue.EnqueueExport(msg); err != nil {
t.Fatalf("Failed to enqueue message %d: %v", i, err)
}
}

time.Sleep(500 * time.Millisecond)

handled := handler.handleCount.Load()
if handled != int32(messageCount) {
t.Errorf("Expected %d messages handled, got %d", messageCount, handled)
}

if err := queue.Stop(2 * time.Second); err != nil {
t.Fatalf("Failed to stop queue: %v", err)
}
}

func TestExportMessage_TrafficRecord(t *testing.T) {
record := &models.UeTrafficRecord{
UeFeatureVector: models.UeFeatureVector{
LogPPS: 4.2,
},
UeIp:      "60.60.0.1",
Supi:      "imsi-001010000000001",
Timestamp: 1234567890,
}

msg := NewTrafficRecordMessage(record)

if msg.Type != MessageTypeTrafficRecord {
t.Errorf("Expected message type %s, got %s", MessageTypeTrafficRecord, msg.Type)
}

converted, ok := msg.AsTrafficRecord()
if !ok {
t.Fatal("Failed to convert message to traffic record")
}

if converted.UeIp != record.UeIp {
t.Errorf("Expected UE IP %s, got %s", record.UeIp, converted.UeIp)
}

if converted.LogPPS != record.LogPPS {
t.Errorf("Expected LogPPS %.2f, got %.2f", record.LogPPS, converted.LogPPS)
}
}

func TestExportMessage_InferenceResult(t *testing.T) {
result := &models.InferenceResult{
UeIp:         "60.60.0.1",
Supi:         "imsi-001010000000001",
Timestamp:    1234567890,
IsAnomaly:    true,
AnomalyScore: 0.85,
Prediction:   "attack",
Confidence:   0.92,
ModelVersion: "v1.0",
}

msg := NewInferenceResultMessage(result)

if msg.Type != MessageTypeInferenceResult {
t.Errorf("Expected message type %s, got %s", MessageTypeInferenceResult, msg.Type)
}

converted, ok := msg.AsInferenceResult()
if !ok {
t.Fatal("Failed to convert message to inference result")
}

if converted.UeIp != result.UeIp {
t.Errorf("Expected UE IP %s, got %s", result.UeIp, converted.UeIp)
}

if converted.Prediction != result.Prediction {
t.Errorf("Expected prediction %s, got %s", result.Prediction, converted.Prediction)
}

if converted.AnomalyScore != result.AnomalyScore {
t.Errorf("Expected anomaly score %.2f, got %.2f", result.AnomalyScore, converted.AnomalyScore)
}
}
