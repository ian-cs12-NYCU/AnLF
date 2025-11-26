package consumer

import (
"github.com/free5gc/anlf/pkg/app"
Nnrf_NFManagement "github.com/free5gc/openapi/nrf/NFManagement"
)

type ConsumerAnlf interface {
app.App
}

type Consumer struct {
ConsumerAnlf
*nnrfService
}

func NewConsumer(anlf ConsumerAnlf) (*Consumer, error) {
c := &Consumer{
ConsumerAnlf: anlf,
}

c.nnrfService = &nnrfService{
consumer:        c,
nfMngmntClients: make(map[string]*Nnrf_NFManagement.APIClient),
}

return c, nil
}
