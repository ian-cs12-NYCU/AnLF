package queue

import (
"context"
"sync/atomic"
"testing"
"time"

"github.com/free5gc/anlf/pkg/models"
)

type MockHandler struct {
handleCount atomic.Int32
lastMessage *ExportMessage
}

func (m *MockHandler) Handle(msg *ExportMessage) error {
m.handleCount.Add(1)
m.lastMessage = msg
return nil
}

func TestExportQueue_Basic(t *testing.T) {
handler := &MockHandler{}
cfg := Config{
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

if err := queue.Enqueue(msg); err != nil {
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

func TestExportMessage_TypeConversion(t *testing.T) {
record := &models.UeTrafficRecord{
UeFeatureVector: models.UeFeatureVector{
LogPPS: 4.2,
},
UeIp: "60.60.0.1",
Supi: "imsi-001010000000001",
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
