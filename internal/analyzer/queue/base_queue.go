package queue

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/free5gc/anlf/internal/logger"
)

// MessageHandler processes messages from the queue
type MessageHandler interface {
	Handle(msg interface{}) error
}

// QueueConfig for queue configuration
type QueueConfig struct {
	BufferSize  int // Size of the buffered channel
	WorkerCount int // Number of concurrent workers
}

// DefaultQueueConfig returns default queue configuration
func DefaultQueueConfig() QueueConfig {
	return QueueConfig{
		BufferSize:  10000, // Large buffer for high throughput
		WorkerCount: 4,     // Multiple workers for parallel processing
	}
}

// BaseQueue provides common queue functionality with generic message handling
type BaseQueue struct {
	name        string
	queue       chan interface{}
	stopChan    chan struct{}
	doneChan    chan struct{}
	wg          sync.WaitGroup
	workerCount int
	handler     MessageHandler
	mu          sync.RWMutex
}

// NewBaseQueue creates a new base queue
func NewBaseQueue(name string, cfg QueueConfig, handler MessageHandler) *BaseQueue {
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = DefaultQueueConfig().BufferSize
	}
	if cfg.WorkerCount <= 0 {
		cfg.WorkerCount = DefaultQueueConfig().WorkerCount
	}

	return &BaseQueue{
		name:        name,
		queue:       make(chan interface{}, cfg.BufferSize),
		stopChan:    make(chan struct{}),
		doneChan:    make(chan struct{}),
		workerCount: cfg.WorkerCount,
		handler:     handler,
	}
}

// Start begins processing messages from the queue
func (q *BaseQueue) Start(ctx context.Context) error {
	logger.AnalyzerLog.Infof("Starting %s with %d workers and buffer size %d",
		q.name, q.workerCount, cap(q.queue))

	// Launch worker goroutines
	for i := 0; i < q.workerCount; i++ {
		q.wg.Add(1)
		go q.worker(ctx, i)
	}

	go q.monitor()

	logger.AnalyzerLog.Infof("%s started successfully", q.name)
	return nil
}

// Stop gracefully shuts down the queue
func (q *BaseQueue) Stop(timeout time.Duration) error {
	logger.AnalyzerLog.Infof("Stopping %s...", q.name)

	close(q.stopChan)

	// Wait for all messages to be processed
	done := make(chan struct{})
	go func() {
		q.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		close(q.doneChan)
		logger.AnalyzerLog.Infof("%s stopped successfully", q.name)
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("%s stop timeout after %v", q.name, timeout)
	}
}

// Name returns the component name
func (q *BaseQueue) Name() string {
	return q.name
}

// Enqueue adds a message to the queue (non-blocking)
func (q *BaseQueue) Enqueue(msg interface{}) error {
	select {
	case q.queue <- msg:
		return nil
	case <-q.stopChan:
		return fmt.Errorf("queue is shutting down")
	default:
		// Queue is full, drop the message and log warning
		logger.AnalyzerLog.Warnf("%s is full (size: %d), dropping message",
			q.name, cap(q.queue))
		return fmt.Errorf("queue full")
	}
}

// worker processes messages from the queue
func (q *BaseQueue) worker(ctx context.Context, id int) {
	defer q.wg.Done()

	logger.AnalyzerLog.Debugf("%s worker %d started", q.name, id)

	for {
		select {
		case <-ctx.Done():
			logger.AnalyzerLog.Debugf("%s worker %d: context cancelled", q.name, id)
			return
		case <-q.stopChan:
			// Process remaining messages in queue
			q.drainQueue(id)
			logger.AnalyzerLog.Debugf("%s worker %d stopped", q.name, id)
			return
		case msg, ok := <-q.queue:
			if !ok {
				logger.AnalyzerLog.Debugf("%s worker %d: channel closed", q.name, id)
				return
			}
			q.processMessage(msg, id)
		}
	}
}

// processMessage handles a single message
func (q *BaseQueue) processMessage(msg interface{}, workerID int) {
	if err := q.handler.Handle(msg); err != nil {
		logger.AnalyzerLog.Errorf("%s worker %d failed to handle message: %v",
			q.name, workerID, err)
	}
}

// drainQueue processes remaining messages during shutdown
func (q *BaseQueue) drainQueue(workerID int) {
	logger.AnalyzerLog.Infof("%s worker %d draining remaining messages...", q.name, workerID)
	count := 0
	for {
		select {
		case msg, ok := <-q.queue:
			if !ok {
				return
			}
			q.processMessage(msg, workerID)
			count++
		default:
			if count > 0 {
				logger.AnalyzerLog.Infof("%s worker %d drained %d messages", q.name, workerID, count)
			}
			return
		}
	}
}

// monitor periodically reports queue status
func (q *BaseQueue) monitor() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-q.stopChan:
			return
		case <-ticker.C:
			queueSize := len(q.queue)
			queueCap := cap(q.queue)
			utilization := float64(queueSize) / float64(queueCap) * 100

			if utilization > 80 {
				logger.AnalyzerLog.Warnf("%s high utilization: %d/%d (%.1f%%)",
					q.name, queueSize, queueCap, utilization)
			} else if utilization > 50 {
				logger.AnalyzerLog.Infof("%s utilization: %d/%d (%.1f%%)",
					q.name, queueSize, queueCap, utilization)
			}
		}
	}
}

// Len returns the current number of messages in queue
func (q *BaseQueue) Len() int {
	return len(q.queue)
}

// Cap returns the capacity of the queue
func (q *BaseQueue) Cap() int {
	return cap(q.queue)
}
