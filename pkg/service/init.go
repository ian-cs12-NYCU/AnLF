package service

import (
	"context"
	"io"
	"os"
	"runtime/debug"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	nf_context "github.com/free5gc/anlf/internal/context"
	"github.com/free5gc/anlf/internal/logger"
	"github.com/free5gc/anlf/internal/sbi"
	"github.com/free5gc/anlf/internal/sbi/consumer"
	"github.com/free5gc/anlf/internal/sbi/processor"
	"github.com/free5gc/anlf/pkg/app"
	"github.com/free5gc/anlf/pkg/factory"
)

type ANLF interface {
	app.App
	CancelContext() context.Context
	Consumer() *consumer.Consumer
	Processor() *processor.Processor
}

type AnlfApp struct {
	ANLF
	cfg              *factory.Config
	nfCtx            *nf_context.ANLFContext
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
	sbiServer        *sbi.Server
	consumer         *consumer.Consumer
	processor        *processor.Processor
	lifecycleManager *app.LifecycleManager
	shutdownTimeout  time.Duration
}

var _ app.App = &AnlfApp{}

func NewApp(ctx context.Context, cfg *factory.Config, tlsKeyLogPath string) (*AnlfApp, error) {
	nf_context.InitNfContext()

	nf := &AnlfApp{
		cfg:             cfg,
		wg:              sync.WaitGroup{},
		nfCtx:           nf_context.GetSelf(),
		shutdownTimeout: 10 * time.Second,
	}

	nf.SetLogEnable(cfg.GetLogEnable())
	nf.SetLogLevel(cfg.GetLogLevel())
	nf.SetReportCaller(cfg.GetLogReportCaller())

	nf.ctx, nf.cancel = context.WithCancel(ctx)
	nf.lifecycleManager = app.NewLifecycleManager(nf.ctx)

	sbiServer, errServer := sbi.NewServer(nf, tlsKeyLogPath)
	if errServer != nil {
		return nf, errServer
	}
	nf.sbiServer = sbiServer

	consumer, errConsumer := consumer.NewConsumer(nf)
	if errConsumer != nil {
		return nf, errConsumer
	}
	nf.consumer = consumer

	processor, err := processor.NewProcessor(nf)
	if err != nil {
		return nf, err
	}
	nf.processor = processor

	return nf, nil
}

func (a *AnlfApp) Config() *factory.Config {
	return a.cfg
}

func (a *AnlfApp) Context() *nf_context.ANLFContext {
	return a.nfCtx
}

func (a *AnlfApp) Consumer() *consumer.Consumer {
	return a.consumer
}

func (a *AnlfApp) Processor() *processor.Processor {
	return a.processor
}

func (a *AnlfApp) CancelContext() context.Context {
	return a.ctx
}

func (a *AnlfApp) SetLogEnable(enable bool) {
	logger.MainLog.Infof("Log enable is set to [%v]", enable)
	if enable && logger.Log.Out == os.Stderr {
		return
	} else if !enable && logger.Log.Out == io.Discard {
		return
	}
	a.cfg.SetLogEnable(enable)
	if enable {
		logger.Log.SetOutput(os.Stderr)
	} else {
		logger.Log.SetOutput(io.Discard)
	}
}

func (a *AnlfApp) SetLogLevel(level string) {
	lvl, err := logrus.ParseLevel(level)
	if err != nil {
		logger.MainLog.Warnf("Log level [%s] is invalid", level)
		return
	}
	logger.MainLog.Infof("Log level is set to [%s]", level)
	if lvl == logger.Log.GetLevel() {
		return
	}
	a.cfg.SetLogLevel(level)
	logger.Log.SetLevel(lvl)
}

func (a *AnlfApp) SetReportCaller(reportCaller bool) {
	logger.MainLog.Infof("Report Caller is set to [%v]", reportCaller)
	if reportCaller == logger.Log.ReportCaller {
		return
	}
	a.cfg.SetLogReportCaller(reportCaller)
	logger.Log.SetReportCaller(reportCaller)
}

func (a *AnlfApp) Start() {
	defer func() {
		if p := recover(); p != nil {
			logger.InitLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
	}()

	// Start SBI server
	if err := a.sbiServer.Run(context.Background(), &a.wg); err != nil {
		logger.MainLog.Fatalf("Run SBI server failed: %+v", err)
	}

	// Listen for shutdown signals
	a.wg.Add(1)
	go a.listenShutdown()

	// Wait for all goroutines
	a.WaitRoutineStopped()
}

func (a *AnlfApp) listenShutdown() {
	defer a.wg.Done()

	select {
	case <-a.ctx.Done():
		logger.MainLog.Infof("Shutdown signal received, reason: %v", a.ctx.Err())
	}

	a.terminateProcedure()
}

func (a *AnlfApp) Terminate() {
	logger.MainLog.Infof("Terminate called, initiating shutdown...")
	a.cancel()
}

func (a *AnlfApp) terminateProcedure() {
	logger.MainLog.Infof("Terminating ANLF...")

	// Create shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), a.shutdownTimeout)
	defer cancel()

	// Use channel to track shutdown completion
	shutdownComplete := make(chan struct{})

	go func() {
		defer close(shutdownComplete)

		// Stop SBI server (includes NRF deregistration)
		a.sbiServer.Stop()

		// Stop lifecycle managed components
		if a.lifecycleManager != nil {
			a.lifecycleManager.StopAll(5 * time.Second)
		}
	}()

	// Wait for shutdown or timeout
	select {
	case <-shutdownComplete:
		logger.MainLog.Infof("Graceful shutdown completed successfully")
	case <-shutdownCtx.Done():
		logger.MainLog.Warnf("Shutdown timeout after %v, forcing termination", a.shutdownTimeout)
	}
}

func (a *AnlfApp) WaitRoutineStopped() {
	// Wait for all goroutines with timeout detection
	done := make(chan struct{})
	go func() {
		a.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.MainLog.Infof("ANLF terminated successfully")
	case <-time.After(15 * time.Second):
		logger.MainLog.Warnf("WaitGroup timeout - some goroutines may still be running")
	}
}

// GetLifecycleManager returns the lifecycle manager for component registration
func (a *AnlfApp) GetLifecycleManager() *app.LifecycleManager {
	return a.lifecycleManager
}

// SetShutdownTimeout sets custom shutdown timeout
func (a *AnlfApp) SetShutdownTimeout(timeout time.Duration) {
	logger.MainLog.Infof("Shutdown timeout set to %v", timeout)
	a.shutdownTimeout = timeout
}
