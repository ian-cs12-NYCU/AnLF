package factory

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"

	"github.com/asaskevich/govalidator"
	"github.com/free5gc/anlf/internal/logger"
	"github.com/free5gc/openapi/models"
)

const (
	NfDefaultConfigPath     = "./config/anlfcfg.yaml"
	NfDefaultTLSKeyLogPath  = "./log/nfsslkey.log"
	NfDefaultCertPemPath    = "./cert/anlf.pem"
	NfDefaultPrivateKeyPath = "./cert/anlf.key"
	AnlfSbiDefaultPort      = 8000
	AnlfSbiDefaultScheme    = "http"
)

type Config struct {
	Info          *Info          `yaml:"info" valid:"required"`
	Configuration *Configuration `yaml:"configuration" valid:"required"`
	Logger        *Logger        `yaml:"logger" valid:"required"`
	sync.RWMutex
}

type Info struct {
	Version     string `yaml:"version" valid:"required,in(1.0.0)"`
	Description string `yaml:"description,omitempty" valid:"type(string)"`
}

type Configuration struct {
	NfName           string               `yaml:"nfName,omitempty"`
	Sbi              *Sbi                 `yaml:"sbi"`
	ServiceNameList  []models.ServiceName `yaml:"serviceNameList"`
	NrfUri           string               `yaml:"nrfUri" valid:"url,required"`
	NrfCertPem       string               `yaml:"nrfCertPem,omitempty" valid:"optional"`
	Recording        *Recording           `yaml:"recording,omitempty" valid:"optional"`
	Ebpf             *Ebpf                `yaml:"ebpf,omitempty" valid:"optional"`
	Monitoring       *Monitoring          `yaml:"monitoring,omitempty" valid:"optional"`
	AnomalyDetection *AnomalyDetection    `yaml:"anomalyDetection,omitempty" valid:"optional"`
}

type Recording struct {
	Enable    bool   `yaml:"enable" valid:"type(bool)"`
	OutputDir string `yaml:"outputDir" valid:"type(string)"`
}

type Ebpf struct {
	Enable    bool   `yaml:"enable" valid:"type(bool)"`
	Interface string `yaml:"interface" valid:"type(string)"`
}

type Monitoring struct {
	Enable       bool   `yaml:"enable" valid:"type(bool)"`
	PollInterval int    `yaml:"pollInterval" valid:"type(int)"` // in seconds
	UeTablePath  string `yaml:"ueTablePath" valid:"type(string)"`
}

type AnomalyDetection struct {
	Enable           bool    `yaml:"enable" valid:"type(bool)"`
	ServerURL        string  `yaml:"serverUrl" valid:"url,optional"`
	Timeout          int     `yaml:"timeout" valid:"type(int),optional"`             // in seconds
	SystemPromptPath string  `yaml:"systemPromptPath" valid:"type(string),optional"` // path to system prompt file
	BatchSize        int     `yaml:"batchSize" valid:"type(int),optional"`           // optimal batch size for LLM (5-10 UEs recommended)
	Temperature      float64 `yaml:"temperature" valid:"type(float64),optional"`     // LLM temperature (0.0-2.0, default: 0.1)
	MaxTokens        int     `yaml:"maxTokens" valid:"type(int),optional"`           // Max response tokens (default: 50)
}

type Logger struct {
	Enable       bool   `yaml:"enable" valid:"type(bool)"`
	Level        string `yaml:"level" valid:"required,in(trace|debug|info|warn|error|fatal|panic)"`
	ReportCaller bool   `yaml:"reportCaller" valid:"type(bool)"`
}

type Sbi struct {
	Scheme       models.UriScheme `yaml:"scheme"`
	BindingIPv4  string           `yaml:"bindingIPv4,omitempty" valid:"host,required"`
	RegisterIPv4 string           `yaml:"registerIPv4,omitempty" valid:"host,optional"`
	Port         int              `yaml:"port"`
	Cert         *Cert            `yaml:"cert,omitempty" valid:"optional"`
}

type Cert struct {
	Pem string `yaml:"pem,omitempty" valid:"type(string),minstringlength(1),required"`
	Key string `yaml:"key,omitempty" valid:"type(string),minstringlength(1),required"`
}

func (c *Config) Validate() (bool, error) {
	if configuration := c.Configuration; configuration != nil {
		if result, err := configuration.validate(); err != nil {
			return result, err
		}
	}

	result, err := govalidator.ValidateStruct(c)
	return result, appendInvalid(err)
}

func (c *Configuration) validate() (bool, error) {
	if sbi := c.Sbi; sbi != nil {
		if result, err := sbi.validate(); err != nil {
			return result, err
		}
	}

	for index, serviceName := range c.ServiceNameList {
		switch {
		case serviceName == models.ServiceName_NNWDAF_ANALYTICSINFO:
		case serviceName == models.ServiceName_NNWDAF_EVENTSSUBSCRIPTION:
		default:
			err := errors.New("Invalid serviceNameList[" + strconv.Itoa(index) + "]: " +
				string(serviceName) + ".")
			return false, err
		}
	}

	result, err := govalidator.ValidateStruct(c)
	return result, appendInvalid(err)
}

func (s *Sbi) validate() (bool, error) {
	govalidator.TagMap["scheme"] = govalidator.Validator(func(str string) bool {
		return str == "https" || str == "http"
	})

	if cert := s.Cert; cert != nil {
		if result, err := cert.validate(); err != nil {
			return result, err
		}
	}

	result, err := govalidator.ValidateStruct(s)
	return result, appendInvalid(err)
}

func (t *Cert) validate() (bool, error) {
	result, err := govalidator.ValidateStruct(t)
	return result, err
}

func appendInvalid(err error) error {
	var errs govalidator.Errors
	if err == nil {
		return nil
	}
	es := err.(govalidator.Errors).Errors()
	for _, e := range es {
		errs = append(errs, fmt.Errorf("Invalid %w", e))
	}
	return error(errs)
}

func (c *Config) GetVersion() string {
	c.RLock()
	defer c.RUnlock()
	if c.Info.Version != "" {
		return c.Info.Version
	}
	return ""
}

func (c *Config) SetLogEnable(enable bool) {
	c.Lock()
	defer c.Unlock()
	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		c.Logger = &Logger{Enable: enable, Level: "info"}
	} else {
		c.Logger.Enable = enable
	}
}

func (c *Config) SetLogLevel(level string) {
	c.Lock()
	defer c.Unlock()
	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		c.Logger = &Logger{Level: level}
	} else {
		c.Logger.Level = level
	}
}

func (c *Config) SetLogReportCaller(reportCaller bool) {
	c.Lock()
	defer c.Unlock()
	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		c.Logger = &Logger{Level: "info", ReportCaller: reportCaller}
	} else {
		c.Logger.ReportCaller = reportCaller
	}
}

func (c *Config) GetLogEnable() bool {
	c.RLock()
	defer c.RUnlock()
	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		return false
	}
	return c.Logger.Enable
}

func (c *Config) GetLogLevel() string {
	c.RLock()
	defer c.RUnlock()
	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		return "info"
	}
	return c.Logger.Level
}

func (c *Config) GetLogReportCaller() bool {
	c.RLock()
	defer c.RUnlock()
	if c.Logger == nil {
		logger.CfgLog.Warnf("Logger should not be nil")
		return false
	}
	return c.Logger.ReportCaller
}

func (c *Config) GetSbiBindingAddr() string {
	c.RLock()
	defer c.RUnlock()
	return c.GetSbiBindingIP() + ":" + strconv.Itoa(c.GetSbiPort())
}

func (c *Config) GetSbiBindingIP() string {
	c.RLock()
	defer c.RUnlock()
	bindIP := "0.0.0.0"
	if c.Configuration == nil || c.Configuration.Sbi == nil {
		return bindIP
	}
	if c.Configuration.Sbi.BindingIPv4 != "" {
		if bindIP = os.Getenv(c.Configuration.Sbi.BindingIPv4); bindIP != "" {
			logger.CfgLog.Infof("Parsing ServerIPv4 [%s] from ENV Variable", bindIP)
		} else {
			bindIP = c.Configuration.Sbi.BindingIPv4
		}
	}
	return bindIP
}

func (c *Config) GetSbiPort() int {
	c.RLock()
	defer c.RUnlock()
	if c.Configuration != nil && c.Configuration.Sbi != nil && c.Configuration.Sbi.Port != 0 {
		return c.Configuration.Sbi.Port
	}
	return AnlfSbiDefaultPort
}

func (c *Config) GetSbiScheme() models.UriScheme {
	c.RLock()
	defer c.RUnlock()
	if c.Configuration != nil && c.Configuration.Sbi != nil && c.Configuration.Sbi.Scheme != "" {
		return c.Configuration.Sbi.Scheme
	}
	return AnlfSbiDefaultScheme
}

func (c *Config) GetCertPemPath() string {
	c.RLock()
	defer c.RUnlock()
	return c.Configuration.Sbi.Cert.Pem
}

func (c *Config) GetCertKeyPath() string {
	c.RLock()
	defer c.RUnlock()
	return c.Configuration.Sbi.Cert.Key
}

func (c *Config) GetRecordingStatus() bool {
	c.RLock()
	defer c.RUnlock()
	return c.Configuration != nil && c.Configuration.Recording != nil && c.Configuration.Recording.Enable
}

func (c *Config) GetRecordingOutputDir() string {
	c.RLock()
	defer c.RUnlock()
	if c.Configuration != nil && c.Configuration.Recording != nil && c.Configuration.Recording.OutputDir != "" {
		return c.Configuration.Recording.OutputDir
	}
	return "./output"
}

func (c *Config) GetEbpfEnabled() bool {
	c.RLock()
	defer c.RUnlock()
	return c.Configuration != nil && c.Configuration.Ebpf != nil && c.Configuration.Ebpf.Enable
}

func (c *Config) GetEbpfInterface() string {
	c.RLock()
	defer c.RUnlock()
	if c.Configuration != nil && c.Configuration.Ebpf != nil && c.Configuration.Ebpf.Interface != "" {
		return c.Configuration.Ebpf.Interface
	}
	return "upfgtp"
}

func (c *Config) GetMonitoringEnabled() bool {
	c.RLock()
	defer c.RUnlock()
	return c.Configuration != nil && c.Configuration.Monitoring != nil && c.Configuration.Monitoring.Enable
}

func (c *Config) GetMonitoringPollInterval() int {
	c.RLock()
	defer c.RUnlock()
	if c.Configuration != nil && c.Configuration.Monitoring != nil && c.Configuration.Monitoring.PollInterval > 0 {
		return c.Configuration.Monitoring.PollInterval
	}
	return 1 // default 1 second
}

func (c *Config) GetAnomalyDetectionEnabled() bool {
	c.RLock()
	defer c.RUnlock()
	return c.Configuration != nil && c.Configuration.AnomalyDetection != nil && c.Configuration.AnomalyDetection.Enable
}

func (c *Config) GetAnomalyDetectionServerURL() string {
	c.RLock()
	defer c.RUnlock()
	if c.Configuration != nil && c.Configuration.AnomalyDetection != nil && c.Configuration.AnomalyDetection.ServerURL != "" {
		return c.Configuration.AnomalyDetection.ServerURL
	}
	return "http://127.0.0.1:5000" // default LLM server URL
}

func (c *Config) GetAnomalyDetectionTimeout() int {
	c.RLock()
	defer c.RUnlock()
	if c.Configuration != nil && c.Configuration.AnomalyDetection != nil && c.Configuration.AnomalyDetection.Timeout > 0 {
		return c.Configuration.AnomalyDetection.Timeout
	}
	return 5 // default 5 seconds
}

func (c *Config) GetMonitoringUeTablePath() string {
	c.RLock()
	defer c.RUnlock()
	if c.Configuration != nil && c.Configuration.Monitoring != nil && c.Configuration.Monitoring.UeTablePath != "" {
		return c.Configuration.Monitoring.UeTablePath
	}
	return "./config/static_ue_list.json"
}

func (c *Config) GetAnomalyDetectionSystemPromptPath() string {
	c.RLock()
	defer c.RUnlock()
	if c.Configuration != nil && c.Configuration.AnomalyDetection != nil && c.Configuration.AnomalyDetection.SystemPromptPath != "" {
		return c.Configuration.AnomalyDetection.SystemPromptPath
	}
	return "./prompts/anomaly_detection_basic.txt" // default system prompt path
}

func (c *Config) GetAnomalyDetectionBatchSize() int {
	c.RLock()
	defer c.RUnlock()
	if c.Configuration != nil && c.Configuration.AnomalyDetection != nil && c.Configuration.AnomalyDetection.BatchSize > 0 {
		return c.Configuration.AnomalyDetection.BatchSize
	}
	return 5 // default batch size (optimal for Qwen 2.5 1.5B)
}

func (c *Config) GetAnomalyDetectionTemperature() float64 {
	c.RLock()
	defer c.RUnlock()
	if c.Configuration != nil && c.Configuration.AnomalyDetection != nil && c.Configuration.AnomalyDetection.Temperature > 0 {
		return c.Configuration.AnomalyDetection.Temperature
	}
	return 0.1 // default temperature (low randomness for consistent detection)
}

func (c *Config) GetAnomalyDetectionMaxTokens() int {
	c.RLock()
	defer c.RUnlock()
	if c.Configuration != nil && c.Configuration.AnomalyDetection != nil && c.Configuration.AnomalyDetection.MaxTokens > 0 {
		return c.Configuration.AnomalyDetection.MaxTokens
	}
	return 50 // default max tokens (sufficient for "Risk Score: X.X")
}
