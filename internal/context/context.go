package context

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/free5gc/anlf/internal/logger"
	"github.com/free5gc/anlf/pkg/factory"
	"github.com/free5gc/openapi/models"
	"github.com/google/uuid"
)

type ANLFContext struct {
	NfId            string
	NfProfile       *models.NrfNfManagementNfProfile
	Name            string
	UriScheme       models.UriScheme
	BindingIPv4     string
	RegisterIPv4    string
	SBIPort         int
	NfService       map[models.ServiceName]models.NrfNfManagementNfService
	NrfUri          string
	NrfCertPem      string
	IsRegistered    bool
	OAuth2Required  bool
	EnableRecording bool
	RecordingOutput string
}

var anlfContext = ANLFContext{}

func InitNfContext() {
	cfg := factory.NfConfig
	configuration := cfg.Configuration

	anlfContext.NfId = uuid.New().String()
	anlfContext.Name = "ANLF"
	anlfContext.UriScheme = configuration.Sbi.Scheme
	anlfContext.SBIPort = configuration.Sbi.Port
	anlfContext.BindingIPv4 = os.Getenv(configuration.Sbi.BindingIPv4)
	anlfContext.RegisterIPv4 = configuration.Sbi.RegisterIPv4
	anlfContext.IsRegistered = false

	if anlfContext.BindingIPv4 != "" {
		logger.CtxLog.Info("Parsing ServerIPv4 address from ENV Variable.")
	} else {
		anlfContext.BindingIPv4 = configuration.Sbi.BindingIPv4
		if anlfContext.BindingIPv4 == "" {
			logger.CtxLog.Warn("Error parsing ServerIPv4 address. Using 0.0.0.0 as default.")
			anlfContext.BindingIPv4 = "0.0.0.0"
		}
	}
	anlfContext.NfService = initNfService(configuration.ServiceNameList, "1.0.0")

	if configuration.NrfUri != "" {
		anlfContext.NrfUri = configuration.NrfUri
	} else {
		logger.CfgLog.Warn("NRF Uri is empty! Using localhost as NRF IPv4 address.")
		anlfContext.NrfUri = fmt.Sprintf("%s://%s:%d", anlfContext.UriScheme, "127.0.0.1", 29510)
	}
	anlfContext.NrfCertPem = configuration.NrfCertPem

	if configuration.Recording != nil {
		anlfContext.EnableRecording = configuration.Recording.Enable
		anlfContext.RecordingOutput = configuration.Recording.OutputDir
	}
}

func GetSelf() *ANLFContext {
	return &anlfContext
}

func initNfService(serviceName []models.ServiceName, version string) map[models.ServiceName]models.NrfNfManagementNfService {
	versionUri := "v" + strings.Split(version, ".")[0]
	nfService := make(map[models.ServiceName]models.NrfNfManagementNfService)
	for idx, name := range serviceName {
		nfService[name] = models.NrfNfManagementNfService{
			ServiceInstanceId: strconv.Itoa(idx),
			ServiceName:       name,
			Versions: []models.NfServiceVersion{
				{
					ApiFullVersion:  version,
					ApiVersionInUri: versionUri,
				},
			},
			Scheme:          anlfContext.UriScheme,
			NfServiceStatus: models.NfServiceStatus_REGISTERED,
			ApiPrefix:       GetIPv4Uri(),
			IpEndPoints: []models.IpEndPoint{
				{
					Ipv4Address: anlfContext.RegisterIPv4,
					Transport:   models.NrfNfManagementTransportProtocol_TCP,
					Port:        int32(anlfContext.SBIPort),
				},
			},
		}
	}
	logger.MainLog.Infof("Service: %v", serviceName)
	return nfService
}

func GetIPv4Uri() string {
	return fmt.Sprintf("%s://%s:%d", anlfContext.UriScheme, anlfContext.RegisterIPv4, anlfContext.SBIPort)
}

func (c *ANLFContext) BuildNfProfile() {
	c.NfProfile = &models.NrfNfManagementNfProfile{
		NfInstanceId:  c.NfId,
		NfType:        models.NrfNfManagementNfType_NWDAF,
		NfStatus:      models.NrfNfManagementNfStatus_REGISTERED,
		Ipv4Addresses: []string{c.RegisterIPv4},
		NfServices:    []models.NrfNfManagementNfService{},
		NwdafInfo: &models.NwdafInfo{
			NwdafEvents: []models.NwdafEvent{models.NwdafEvent_NF_LOAD},
		},
	}
	for _, nfService := range c.NfService {
		c.NfProfile.NfServices = append(c.NfProfile.NfServices, nfService)
	}
}
