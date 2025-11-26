package consumer

import (
"context"
"fmt"
"strings"
"sync"
"time"

"github.com/free5gc/anlf/internal/logger"
"github.com/free5gc/openapi/models"
Nnrf_NFManagement "github.com/free5gc/openapi/nrf/NFManagement"
"github.com/free5gc/openapi/oauth"
)

type nnrfService struct {
consumer       *Consumer
nfMngmntMu     sync.RWMutex
nfMngmntClients map[string]*Nnrf_NFManagement.APIClient
}

func (s *nnrfService) getNFManagementClient(uri string) *Nnrf_NFManagement.APIClient {
if uri == "" {
return nil
}
s.nfMngmntMu.RLock()
client, ok := s.nfMngmntClients[uri]
if ok {
s.nfMngmntMu.RUnlock()
return client
}

configuration := Nnrf_NFManagement.NewConfiguration()
configuration.SetBasePath(uri)
client = Nnrf_NFManagement.NewAPIClient(configuration)

s.nfMngmntMu.RUnlock()
s.nfMngmntMu.Lock()
defer s.nfMngmntMu.Unlock()
s.nfMngmntClients[uri] = client
return client
}

func (s *nnrfService) RegisterNFInstance(ctx context.Context) (string, string, error) {
logger.ConsumerLog.Debugf("In RegisterNFInstance")

nfContext := s.consumer.Context()
nfContext.BuildNfProfile()

client := s.getNFManagementClient(nfContext.NrfUri)
if client == nil {
err := fmt.Errorf("getNFManagementClient error on uri[%s]", nfContext.NrfUri)
return "", "", err
}

registerNFInstanceRequest := &Nnrf_NFManagement.RegisterNFInstanceRequest{
NfInstanceID:             &nfContext.NfId,
NrfNfManagementNfProfile: nfContext.NfProfile,
}

tryMaxtime := 3
for i := 0; i < tryMaxtime; i++ {
select {
case <-ctx.Done():
return "", "", fmt.Errorf("NfRegister Stopped due to context cancel, retry time: %d", i)
default:
res, errDo := client.NFInstanceIDDocumentApi.RegisterNFInstance(context.Background(), registerNFInstanceRequest)
if errDo != nil || res == nil {
logger.ConsumerLog.Errorf("%s register to NRF Error[%v]", nfContext.Name, errDo)
time.Sleep(2 * time.Second)
continue
}
nf := res.NrfNfManagementNfProfile

if res.Location == "" {
return "", "", nil
} else {
resourceUri := res.Location
resouceNrfUri := ""
if idx := strings.Index(resourceUri, "/nnrf-nfm/"); idx >= 0 {
resouceNrfUri = resourceUri[:idx]
}
retrieveNfInstanceID := resourceUri[strings.LastIndex(resourceUri, "/")+1:]

oauth2 := false
if nf.CustomInfo != nil {
v, ok := nf.CustomInfo["oauth2"].(bool)
if ok {
oauth2 = v
logger.MainLog.Infoln("OAuth2 setting receive from NRF:", oauth2)
}
}
nfContext.OAuth2Required = oauth2
if oauth2 && nfContext.NrfCertPem == "" {
logger.CfgLog.Warn("OAuth2 enabled but no nrfCertPem provided in config.")
}
nfContext.IsRegistered = true
return resouceNrfUri, retrieveNfInstanceID, nil
}
}
}
return "", "", fmt.Errorf("Register Failed, maximum retry time reached[%d]", tryMaxtime)
}

func (s *nnrfService) SendDeregisterNFInstance() error {
if !s.consumer.Context().IsRegistered {
return fmt.Errorf("ANLF is not register to NRF yet!")
}
logger.ConsumerLog.Infof("Send Deregister NFInstance")

nfContext := s.consumer.Context()
ctx, _, err := s.GetTokenCtx(models.ServiceName_NNRF_NFM, models.NrfNfManagementNfType_NRF)
if err != nil {
return err
}

client := s.getNFManagementClient(nfContext.NrfUri)
request := &Nnrf_NFManagement.DeregisterNFInstanceRequest{
NfInstanceID: &nfContext.NfId,
}
_, err = client.NFInstanceIDDocumentApi.DeregisterNFInstance(ctx, request)
return err
}

func (s *nnrfService) GetTokenCtx(serviceName models.ServiceName, targetNF models.NrfNfManagementNfType) (context.Context, *models.ProblemDetails, error) {
c := s.consumer.Context()
if !c.OAuth2Required {
return context.Background(), nil, nil
}
return oauth.GetTokenCtx(models.NrfNfManagementNfType_NWDAF, targetNF, c.NfId, c.NrfUri, string(serviceName))
}
