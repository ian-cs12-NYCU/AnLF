package queue

import (
"context"
"sync/atomic"
"testing"
"time"
)

type MockGenericHandler struct {
handleCount atomic.Int32
lastMessage interface{}
}

func (m *MockGenericHandler) Handle(msg interface{}) error {
m.handleCount.Add(1)
m.lastMessage = msg
return nil
}

func TestBaseQueue_Basic(t *testing.T) {
handler := &MockGenericHandler{}
cfg := QueueConfig{
BufferSize:  100,
WorkerCount: 2,
}

queue := NewBaseQueue("TestQueue", cfg, handler)
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

if err := queue.Start(ctx); err != nil {
t.Fatalf("Failed to start queue: %v", err)
}

testMsg := "test message"
if err := queue.Enqueue(testMsg); err != nil {
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

func TestBaseQueue_MultipleMessages(t *testing.T) {
handler := &MockGenericHandler{}
cfg := QueueConfig{
BufferSize:  1000,
WorkerCount: 4,
}

queue := NewBaseQueue("TestQueue", cfg, handler)
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

if err := queue.Start(ctx); err != nil {
t.Fatalf("Failed to start queue: %v", err)
}

messageCount := 100
for i := 0; i < messageCount; i++ {
if err := queue.Enqueue(i); err != nil {
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

func TestBaseQueue_FullQueue(t *testing.T) {
handler := &MockGenericHandler{}
cfg := QueueConfig{
BufferSize:  10,
WorkerCount: 0,
}

queue := NewBaseQueue("TestQueue", cfg, handler)

for i := 0; i < 10; i++ {
if err := queue.Enqueue(i); err != nil {
t.Fatalf("Failed to enqueue message %d: %v", i, err)
}
}

err := queue.Enqueue("overflow")
if err == nil {
t.Error("Expected error when queue is full, got nil")
}
}

func TestBaseQueue_GracefulShutdown(t *testing.T) {
handler := &MockGenericHandler{}
cfg := QueueConfig{
BufferSize:  100,
WorkerCount: 2,
}

queue := NewBaseQueue("TestQueue", cfg, handler)
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

if err := queue.Start(ctx); err != nil {
t.Fatalf("Failed to start queue: %v", err)
}

messageCount := 50
for i := 0; i < messageCount; i++ {
queue.Enqueue(i)
}

if err := queue.Stop(5 * time.Second); err != nil {
t.Fatalf("Failed to stop queue: %v", err)
}

handled := handler.handleCount.Load()
if handled != int32(messageCount) {
t.Errorf("Expected %d messages handled during shutdown, got %d", messageCount, handled)
}
}
