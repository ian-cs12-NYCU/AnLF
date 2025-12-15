package queue

import (
	"context"
	"time"
)

// ExportQueue manages a high-performance message queue for export operations
type ExportQueue struct {
	*BaseQueue
	handler ExportMessageHandler
}

// ExportMessageHandler processes export messages from the queue
type ExportMessageHandler interface {
	Handle(msg *ExportMessage) error
}

// exportHandlerAdapter adapts ExportMessageHandler to generic MessageHandler
type exportHandlerAdapter struct {
	handler ExportMessageHandler
}

func (a *exportHandlerAdapter) Handle(msg interface{}) error {
	exportMsg, ok := msg.(*ExportMessage)
	if !ok {
		return nil // Skip non-export messages
	}
	return a.handler.Handle(exportMsg)
}

// NewExportQueue creates a new export queue with the given configuration
func NewExportQueue(cfg QueueConfig, handler ExportMessageHandler) *ExportQueue {
	adapter := &exportHandlerAdapter{handler: handler}
	baseQueue := NewBaseQueue("ExportQueue", cfg, adapter)

	return &ExportQueue{
		BaseQueue: baseQueue,
		handler:   handler,
	}
}

// EnqueueExport adds an export message to the queue
func (q *ExportQueue) EnqueueExport(msg *ExportMessage) error {
	return q.BaseQueue.Enqueue(msg)
}

// Start overrides BaseQueue.Start for export-specific initialization
func (q *ExportQueue) Start(ctx context.Context) error {
	return q.BaseQueue.Start(ctx)
}

// Stop overrides BaseQueue.Stop for export-specific cleanup
func (q *ExportQueue) Stop(timeout time.Duration) error {
	return q.BaseQueue.Stop(timeout)
}
