package ebpf

import (
	"context"
	"fmt"
	"time"

	"github.com/free5gc/anlf/internal/logger"
)

// Component implements the Lifecycle interface for eBPF manager
type Component struct {
	manager   *Manager
	iface     string
	isStarted bool
}

// NewComponent creates a new eBPF lifecycle component
func NewComponent(iface string) (*Component, error) {
	if iface == "" {
		return nil, fmt.Errorf("interface name cannot be empty")
	}

	manager, err := NewManager()
	if err != nil {
		return nil, fmt.Errorf("failed to create eBPF manager: %w", err)
	}

	return &Component{
		manager:   manager,
		iface:     iface,
		isStarted: false,
	}, nil
}

// Start implements Lifecycle.Start
func (c *Component) Start(ctx context.Context) error {
	if c.isStarted {
		return fmt.Errorf("eBPF component already started")
	}

	logger.MainLog.Infof("Loading eBPF programs...")
	if err := c.manager.Load(); err != nil {
		return fmt.Errorf("failed to load eBPF programs: %w", err)
	}

	logger.MainLog.Infof("Attaching XDP to interface %s...", c.iface)
	if err := c.manager.AttachXDP(c.iface); err != nil {
		// Try to close manager if attach fails
		_ = c.manager.Close()
		return fmt.Errorf("failed to attach XDP to interface %s: %w", c.iface, err)
	}
	logger.MainLog.Infof("✓ eBPF XDP attached successfully to %s", c.iface)

	logger.MainLog.Infof("Attaching TC egress to interface %s...", c.iface)
	if err := c.manager.AttachTC(c.iface); err != nil {
		// Try to close manager if attach fails
		_ = c.manager.Close()
		return fmt.Errorf("failed to attach TC to interface %s: %w", c.iface, err)
	}
	logger.MainLog.Infof("✓ eBPF TC egress attached successfully to %s", c.iface)

	c.isStarted = true
	return nil
}

// Stop implements Lifecycle.Stop
func (c *Component) Stop(timeout time.Duration) error {
	if !c.isStarted {
		logger.MainLog.Warnf("eBPF component not started, skipping stop")
		return nil
	}

	logger.MainLog.Infof("Detaching XDP from interface %s...", c.iface)

	done := make(chan error, 1)
	go func() {
		done <- c.manager.Close()
	}()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("failed to close eBPF manager: %w", err)
		}
		c.isStarted = false
		logger.MainLog.Infof("✓ eBPF component stopped successfully")
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("eBPF stop timeout after %v", timeout)
	}
}

// Name implements Lifecycle.Name
func (c *Component) Name() string {
	return "eBPF Manager"
}

// GetManager returns the underlying eBPF manager for metric access
func (c *Component) GetManager() *Manager {
	return c.manager
}

// IsStarted returns whether the component is running
func (c *Component) IsStarted() bool {
	return c.isStarted
}
