package queue

import (
	"context"
	"time"

	"github.com/free5gc/anlf/pkg/models"
)

// InferenceQueue manages a queue for LLM inference requests
type InferenceQueue struct {
	*BaseQueue
	handler InferenceHandler
}

// InferenceHandler processes inference requests from the queue
type InferenceHandler interface {
	Handle(record *models.UeTrafficRecord) error
}

// inferenceHandlerAdapter adapts InferenceHandler to generic MessageHandler
type inferenceHandlerAdapter struct {
	handler InferenceHandler
}

func (a *inferenceHandlerAdapter) Handle(msg interface{}) error {
	record, ok := msg.(*models.UeTrafficRecord)
	if !ok {
		return nil // Skip non-traffic-record messages
	}
	return a.handler.Handle(record)
}

// NewInferenceQueue creates a new inference queue with the given configuration
func NewInferenceQueue(cfg QueueConfig, handler InferenceHandler) *InferenceQueue {
	adapter := &inferenceHandlerAdapter{handler: handler}
	baseQueue := NewBaseQueue("InferenceQueue", cfg, adapter)

	return &InferenceQueue{
		BaseQueue: baseQueue,
		handler:   handler,
	}
}

// EnqueueInference adds a traffic record to the inference queue
func (q *InferenceQueue) EnqueueInference(record *models.UeTrafficRecord) error {
	return q.BaseQueue.Enqueue(record)
}

// Start overrides BaseQueue.Start for inference-specific initialization
func (q *InferenceQueue) Start(ctx context.Context) error {
	return q.BaseQueue.Start(ctx)
}

// Stop overrides BaseQueue.Stop for inference-specific cleanup
func (q *InferenceQueue) Stop(timeout time.Duration) error {
	return q.BaseQueue.Stop(timeout)
}
