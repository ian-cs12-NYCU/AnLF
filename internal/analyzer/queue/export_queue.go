package queue

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/free5gc/anlf/internal/logger"
)

// ExportQueue manages a high-performance message queue for export operations
type ExportQueue struct {
	queue       chan *ExportMessage
	stopChan    chan struct{}
	doneChan    chan struct{}
	wg          sync.WaitGroup
	workerCount int
	handler     MessageHandler
}

// MessageHandler processes messages from the queue
type MessageHandler interface {
	Handle(msg *ExportMessage) error
}

// Config for ExportQueue configuration
type Config struct {
	BufferSize  int // Size of the buffered channel
	WorkerCount int // Number of concurrent workers
}

// DefaultConfig returns default queue configuration
func DefaultConfig() Config {
	return Config{
		BufferSize:  10000, // Large buffer for high throughput
		WorkerCount: 4,     // Multiple workers for parallel processing
	}
}

// NewExportQueue creates a new export queue with the given configuration
func NewExportQueue(cfg Config, handler MessageHandler) *ExportQueue {
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = DefaultConfig().BufferSize
	}
	if cfg.WorkerCount <= 0 {
		cfg.WorkerCount = DefaultConfig().WorkerCount
	}

	return &ExportQueue{
		queue:       make(chan *ExportMessage, cfg.BufferSize),
		stopChan:    make(chan struct{}),
		doneChan:    make(chan struct{}),
		workerCount: cfg.WorkerCount,
		handler:     handler,
	}
}

// Start begins processing messages from the queue
func (q *ExportQueue) Start(ctx context.Context) error {
	logger.AnalyzerLog.Infof("Starting ExportQueue with %d workers and buffer size %d",
		q.workerCount, cap(q.queue))

	// Launch worker goroutines
	for i := 0; i < q.workerCount; i++ {
		q.wg.Add(1)
		go q.worker(ctx, i)
	}

	go q.monitor()

	logger.AnalyzerLog.Info("ExportQueue started successfully")
	return nil
}

// Stop gracefully shuts down the queue
func (q *ExportQueue) Stop(timeout time.Duration) error {
	logger.AnalyzerLog.Info("Stopping ExportQueue...")

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
		logger.AnalyzerLog.Info("ExportQueue stopped successfully")
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("ExportQueue stop timeout after %v", timeout)
	}
}

// Name returns the component name
func (q *ExportQueue) Name() string {
	return "ExportQueue"
}

// Enqueue adds a message to the queue (non-blocking)
func (q *ExportQueue) Enqueue(msg *ExportMessage) error {
	select {
	case q.queue <- msg:
		return nil
	case <-q.stopChan:
		return fmt.Errorf("queue is shutting down")
	default:
		// Queue is full, drop the message and log warning
		logger.AnalyzerLog.Warnf("ExportQueue is full (size: %d), dropping message of type %s",
			cap(q.queue), msg.Type)
		return fmt.Errorf("queue full")
	}
}

// worker processes messages from the queue
func (q *ExportQueue) worker(ctx context.Context, id int) {
	defer q.wg.Done()

	logger.AnalyzerLog.Debugf("ExportQueue worker %d started", id)

	for {
		select {
		case <-ctx.Done():
			logger.AnalyzerLog.Debugf("ExportQueue worker %d: context cancelled", id)
			return
		case <-q.stopChan:
			// Process remaining messages in queue
			q.drainQueue(id)
			logger.AnalyzerLog.Debugf("ExportQueue worker %d stopped", id)
			return
		case msg, ok := <-q.queue:
			if !ok {
				logger.AnalyzerLog.Debugf("ExportQueue worker %d: channel closed", id)
				return
			}
			q.processMessage(msg, id)
		}
	}
}

// processMessage handles a single message
func (q *ExportQueue) processMessage(msg *ExportMessage, workerID int) {
	if err := q.handler.Handle(msg); err != nil {
		logger.AnalyzerLog.Errorf("Worker %d failed to handle message type %s: %v",
			workerID, msg.Type, err)
	}
}

// drainQueue processes remaining messages during shutdown
func (q *ExportQueue) drainQueue(workerID int) {
	logger.AnalyzerLog.Infof("Worker %d draining remaining messages...", workerID)
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
				logger.AnalyzerLog.Infof("Worker %d drained %d messages", workerID, count)
			}
			return
		}
	}
}

// monitor periodically reports queue status
func (q *ExportQueue) monitor() {
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
				logger.AnalyzerLog.Warnf("ExportQueue high utilization: %d/%d (%.1f%%)",
					queueSize, queueCap, utilization)
			} else if utilization > 50 {
				logger.AnalyzerLog.Infof("ExportQueue utilization: %d/%d (%.1f%%)",
					queueSize, queueCap, utilization)
			}
		}
	}
}

// Len returns the current number of messages in queue
func (q *ExportQueue) Len() int {
	return len(q.queue)
}

// Cap returns the capacity of the queue
func (q *ExportQueue) Cap() int {
	return cap(q.queue)
}
