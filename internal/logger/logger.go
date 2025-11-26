package logger

import (
	"github.com/sirupsen/logrus"

	logger_util "github.com/free5gc/util/logger"
)

var (
	Log     *logrus.Logger
	NfLog   *logrus.Entry
	MainLog *logrus.Entry
	InitLog *logrus.Entry
	CfgLog  *logrus.Entry
	CtxLog  *logrus.Entry

	GinLog *logrus.Entry
	SBILog *logrus.Entry

	ConsumerLog  *logrus.Entry
	ProcessorLog *logrus.Entry
	RecorderLog  *logrus.Entry

	EbpfLog *logrus.Entry
)

func init() {
	fieldsOrder := []string{
		logger_util.FieldNF,
		logger_util.FieldCategory,
	}
	Log = logger_util.New(fieldsOrder)
	NfLog = Log.WithField(logger_util.FieldNF, "ANLF")

	MainLog = NfLog.WithField(logger_util.FieldCategory, "Main")
	InitLog = NfLog.WithField(logger_util.FieldCategory, "Init")
	CfgLog = NfLog.WithField(logger_util.FieldCategory, "CFG")
	CtxLog = NfLog.WithField(logger_util.FieldCategory, "CTX")

	GinLog = NfLog.WithField(logger_util.FieldCategory, "GIN")
	SBILog = NfLog.WithField(logger_util.FieldCategory, "SBI")
	ConsumerLog = NfLog.WithField(logger_util.FieldCategory, "Consumer")
	ProcessorLog = NfLog.WithField(logger_util.FieldCategory, "Processor")
	RecorderLog = NfLog.WithField(logger_util.FieldCategory, "Recorder")
	EbpfLog = NfLog.WithField(logger_util.FieldCategory, "eBPF")
}
