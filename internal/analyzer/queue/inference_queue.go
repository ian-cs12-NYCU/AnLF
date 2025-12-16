package queue

import (
	"context"
	"time"

	"github.com/free5gc/anlf/pkg/models"
)

// InferenceQueue manages a queue for LLM batch inference requests
type InferenceQueue struct {
	*BaseQueue
	handler BatchInferenceHandler
}

// BatchInferenceHandler processes batch inference requests from the queue
type BatchInferenceHandler interface {
	HandleBatch(batch *models.BatchUeTrafficRecords) error
}

// batchInferenceHandlerAdapter adapts BatchInferenceHandler to generic MessageHandler
type batchInferenceHandlerAdapter struct {
	handler BatchInferenceHandler
}

func (a *batchInferenceHandlerAdapter) Handle(msg interface{}) error {
	batch, ok := msg.(*models.BatchUeTrafficRecords)
	if !ok {
		return nil // Skip non-batch messages
	}
	return a.handler.HandleBatch(batch)
}

// NewInferenceQueue creates a new inference queue with the given configuration
func NewInferenceQueue(cfg QueueConfig, handler BatchInferenceHandler) *InferenceQueue {
	adapter := &batchInferenceHandlerAdapter{handler: handler}
	baseQueue := NewBaseQueue("InferenceQueue", cfg, adapter)

	return &InferenceQueue{
		BaseQueue: baseQueue,
		handler:   handler,
	}
}

// EnqueueBatch adds a batch of traffic records to the inference queue
func (q *InferenceQueue) EnqueueBatch(batch *models.BatchUeTrafficRecords) error {
	return q.BaseQueue.Enqueue(batch)
}

// Start overrides BaseQueue.Start for inference-specific initialization
func (q *InferenceQueue) Start(ctx context.Context) error {
	return q.BaseQueue.Start(ctx)
}

// Stop overrides BaseQueue.Stop for inference-specific cleanup
func (q *InferenceQueue) Stop(timeout time.Duration) error {
	return q.BaseQueue.Stop(timeout)
}
