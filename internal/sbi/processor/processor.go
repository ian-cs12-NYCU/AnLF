package processor

import (
"github.com/free5gc/anlf/pkg/app"
)

type ProcessorAnlf interface {
app.App
}

type Processor struct {
ProcessorAnlf
}

func NewProcessor(anlf ProcessorAnlf) (*Processor, error) {
p := &Processor{
ProcessorAnlf: anlf,
}
return p, nil
}
