package sbi

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"runtime/debug"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"github.com/free5gc/anlf/internal/logger"
	"github.com/free5gc/anlf/internal/sbi/consumer"
	"github.com/free5gc/anlf/internal/sbi/processor"
	"github.com/free5gc/anlf/pkg/app"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/httpwrapper"
	logger_util "github.com/free5gc/util/logger"
)

type ANLF interface {
	app.App
	Processor() *processor.Processor
	Consumer() *consumer.Consumer
	CancelContext() context.Context
}

type Server struct {
	ANLF
	httpServer *http.Server
	router     *gin.Engine
}

func NewServer(anlf ANLF, tlsKeyLogPath string) (*Server, error) {
	s := &Server{
		ANLF:   anlf,
		router: logger_util.NewGinWithLogrus(logger.GinLog),
	}
	s.ApplyServices()

	cfg := s.Config()
	bindAddr := cfg.GetSbiBindingAddr()
	logger.SBILog.Infof("Binding addr: [%s]", bindAddr)
	var err error
	if s.httpServer, err = httpwrapper.NewHttp2Server(bindAddr, tlsKeyLogPath, s.router); err != nil {
		logger.InitLog.Errorf("Initialize HTTP server failed: %v", err)
		return nil, err
	}
	s.httpServer.ErrorLog = log.New(logger.SBILog.WriterLevel(logrus.ErrorLevel), "HTTP2: ", 0)
	s.httpServer.ReadHeaderTimeout = 3 * time.Second
	return s, nil
}

func (s *Server) newGroup(apiPrefix string) *gin.RouterGroup {
	return s.router.Group(apiPrefix)
}

func (s *Server) ApplyServices() {
	for serviceName := range s.Context().NfService {
		var group *gin.RouterGroup
		var route []Route
		switch serviceName {
		case models.ServiceName_NNWDAF_ANALYTICSINFO:
			group = s.newGroup("/nnwdaf-analyticsinfo/v1")
			route = s.getAnalyticsInfoRoutes()
		case models.ServiceName_NNWDAF_EVENTSSUBSCRIPTION:
			group = s.newGroup("/nnwdaf-eventssubscription/v1")
			route = s.getEventSubscriptionRoutes()
		default:
			logger.SBILog.Warnf("ServiceName:[%v] not provided by this ANLF", serviceName)
			continue
		}
		applyRoutes(group, route)
	}
}

func (s *Server) Run(traceCtx context.Context, wg *sync.WaitGroup) error {
	// Register with NRF
	_, s.Context().NfId, _ = s.Consumer().RegisterNFInstance(s.CancelContext())

	// Start HTTP server in background
	wg.Add(1)
	go s.startServer(wg)

	return nil
}

func (s *Server) Stop() {
	// Deregister from NRF first
	if err := s.Consumer().SendDeregisterNFInstance(); err != nil {
		logger.SBILog.Errorf("Deregister NF instance Error[%+v]", err)
	} else {
		logger.SBILog.Infof("Deregister from NRF successfully")
	}

	// Shutdown HTTP server with timeout
	const defaultShutdownTimeout time.Duration = 5 * time.Second
	if s.httpServer != nil {
		logger.SBILog.Infof("Stopping SBI server (listen on %s)", s.httpServer.Addr)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), defaultShutdownTimeout)
		defer cancel()

		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			logger.SBILog.Errorf("Error during server shutdown: %v", err)
			// Force close if graceful shutdown fails
			if err := s.httpServer.Close(); err != nil {
				logger.SBILog.Errorf("Error forcing server close: %v", err)
			}
		} else {
			logger.SBILog.Infof("SBI server stopped gracefully")
		}
	}
	logger.MainLog.Infof("ANLF SBI Server terminated")
}

func (s *Server) startServer(wg *sync.WaitGroup) {
	defer func() {
		if p := recover(); p != nil {
			logger.SBILog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
		wg.Done()
		s.Terminate()
	}()

	logger.SBILog.Infof("Start SBI server (listen on %s)", s.httpServer.Addr)

	var err error
	cfg := s.Config()
	scheme := cfg.GetSbiScheme()
	switch scheme {
	case "http":
		err = s.httpServer.ListenAndServe()
	case "https":
		err = s.httpServer.ListenAndServeTLS(
			cfg.GetCertPemPath(),
			cfg.GetCertKeyPath())
	default:
		err = fmt.Errorf("No support this scheme[%s]", scheme)
	}
	if err != nil && err != http.ErrServerClosed {
		logger.SBILog.Errorf("SBI server error: %v", err)
		return
	}
	logger.SBILog.Infof("SBI server (listen on %s) stopped", s.httpServer.Addr)
}
