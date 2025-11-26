package app

import (
	"context"
	"sync"
	"time"

	"github.com/free5gc/anlf/internal/logger"
)

// Lifecycle defines the interface for components that need graceful shutdown
type Lifecycle interface {
	// Start initializes and starts the component
	Start(ctx context.Context) error
	// Stop gracefully stops the component with timeout
	Stop(timeout time.Duration) error
	// Name returns the component name for logging
	Name() string
}

// LifecycleManager manages multiple components with graceful shutdown
type LifecycleManager struct {
	components []Lifecycle
	mu         sync.RWMutex
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewLifecycleManager creates a new lifecycle manager
func NewLifecycleManager(ctx context.Context) *LifecycleManager {
	childCtx, cancel := context.WithCancel(ctx)
	return &LifecycleManager{
		components: make([]Lifecycle, 0),
		ctx:        childCtx,
		cancel:     cancel,
	}
}

// Register adds a component to the lifecycle manager
func (lm *LifecycleManager) Register(component Lifecycle) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	lm.components = append(lm.components, component)
	logger.MainLog.Debugf("Registered component: %s", component.Name())
}

// StartAll starts all registered components
func (lm *LifecycleManager) StartAll() error {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	for _, component := range lm.components {
		logger.MainLog.Infof("Starting component: %s", component.Name())
		if err := component.Start(lm.ctx); err != nil {
			logger.MainLog.Errorf("Failed to start component %s: %v", component.Name(), err)
			// Try to stop already started components
			lm.StopAll(5 * time.Second)
			return err
		}
	}
	return nil
}

// StopAll gracefully stops all components in reverse order
func (lm *LifecycleManager) StopAll(timeout time.Duration) {
	lm.mu.RLock()
	components := make([]Lifecycle, len(lm.components))
	copy(components, lm.components)
	lm.mu.RUnlock()

	logger.MainLog.Infof("Stopping all components (timeout: %v)...", timeout)

	// Stop in reverse order
	for i := len(components) - 1; i >= 0; i-- {
		component := components[i]
		logger.MainLog.Infof("Stopping component: %s", component.Name())

		// Create timeout context for this component
		stopCtx, cancel := context.WithTimeout(context.Background(), timeout)

		done := make(chan error, 1)
		go func() {
			done <- component.Stop(timeout)
		}()

		select {
		case err := <-done:
			if err != nil {
				logger.MainLog.Errorf("Error stopping component %s: %v", component.Name(), err)
			} else {
				logger.MainLog.Infof("Component %s stopped successfully", component.Name())
			}
		case <-stopCtx.Done():
			logger.MainLog.Warnf("Component %s stop timeout after %v", component.Name(), timeout)
		}
		cancel()
	}

	logger.MainLog.Infof("All components stopped")
}

// Shutdown triggers graceful shutdown
func (lm *LifecycleManager) Shutdown(timeout time.Duration) {
	logger.MainLog.Infof("Initiating graceful shutdown...")
	lm.cancel()
	lm.StopAll(timeout)
}

// Wait waits for all goroutines to finish
func (lm *LifecycleManager) Wait() {
	lm.wg.Wait()
}

// AddTask adds a goroutine task to track
func (lm *LifecycleManager) AddTask() {
	lm.wg.Add(1)
}

// TaskDone marks a task as complete
func (lm *LifecycleManager) TaskDone() {
	lm.wg.Done()
}

// Context returns the lifecycle context
func (lm *LifecycleManager) Context() context.Context {
	return lm.ctx
}
