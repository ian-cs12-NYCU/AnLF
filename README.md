# ANLF - Anomaly Load Function

ANLF (Anomaly Load Function) is a 5G Core Network Function designed for detecting anomalous behavior using eBPF-based traffic analysis.

## Phase 1: NRF Registration ✅

The ANLF service can now:
- Initialize as a 5G NF with proper context
- Register with NRF (Network Repository Function)
- Start HTTP Server on SBI (Service Based Interface)
- Handle basic analytics and subscription endpoints

## Project Structure

```
anlf/
├── cmd/
│   └── main.go              # Entry point
├── config/
│   └── anlfcfg.yaml         # Configuration file
├── internal/
│   ├── context/
│   │   └── context.go       # ANLF context and NF profile
│   ├── logger/
│   │   └── logger.go        # Logging utilities
│   ├── sbi/
│   │   ├── consumer/        # NRF client for registration
│   │   ├── processor/       # Request processors
│   │   ├── routes.go        # API routes
│   │   └── server.go        # HTTP server
│   └── recorder/            # Data recording (Phase 4)
├── pkg/
│   ├── app/
│   │   └── app.go           # App interface
│   ├── factory/
│   │   ├── config.go        # Configuration structures
│   │   └── factory.go       # Config loading
│   └── service/
│       └── init.go          # Service initialization
└── Makefile

```

## Build

```bash
make build
# or
go build -o bin/anlf ./cmd/main.go
```

## Configuration

Edit `config/anlfcfg.yaml`:

```yaml
configuration:
  nfName: ANLF
  sbi:
    scheme: http
    bindingIPv4: 127.0.0.165  # Change to your IP
    registerIPv4: 127.0.0.165
    port: 8000
  nrfUri: http://127.0.0.10:8000  # Your NRF address
  
  recording:
    enable: false
    output: ./output/data.csv
```

## Run

```bash
# Basic run
sudo ./bin/anlf -c config/anlfcfg.yaml

# With logging
sudo ./bin/anlf -c config/anlfcfg.yaml -l log/anlf.log

# Or use make
make run
```

## Verify Registration

After starting ANLF, check NRF for registration:
```bash
curl http://127.0.0.10:8000/nnrf-nfm/v1/nf-instances
```

## Next Steps (TODO.md)

- Phase 2: eBPF kernel-side implementation
- Phase 3: eBPF management in Go
- Phase 4: Mock SMF and data recording
- Phase 5: Attack validation and thesis data

## Dependencies

- Go 1.21+
- free5gc/openapi
- free5gc/util
- gin-gonic/gin

## Documentation

Detailed documentation is available in the `docs/` directory:

- [Architecture](docs/architecture.md) - System architecture, data flow, and global metrics
- [eBPF Implementation](docs/eBPF.md) - eBPF kernel-side implementation details
- [Export Queue](docs/EXPORT_QUEUE.md) - Message queue architecture for data export
- [LLM Integration](docs/LLM.md) - LLM-based anomaly detection
- [LLM Server](docs/LLM_server.md) - LLM server setup and configuration
- [Risk Scoring](docs/RISK_SCORING.md) - CUSUM-based risk scoring mechanism
- [Graceful Shutdown](docs/GRACEFUL_SHUTDOWN.md) - Component lifecycle management
- [Testing eBPF](docs/TESTING_EBPF.md) - eBPF testing procedures
