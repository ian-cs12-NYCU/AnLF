package app

import (
nf_context "github.com/free5gc/anlf/internal/context"
"github.com/free5gc/anlf/pkg/factory"
)

type App interface {
SetLogEnable(enable bool)
SetLogLevel(level string)
SetReportCaller(reportCaller bool)

Start()
Terminate()

Context() *nf_context.ANLFContext
Config() *factory.Config
}
