.PHONY: all build clean test run ebpf-generate ebpf-test

all: build

# Generate vmlinux.h from kernel BTF
bpf/vmlinux.h:
	@echo "Generating vmlinux.h from kernel BTF..."
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
	@echo "✓ vmlinux.h generated ($(shell ls -lh bpf/vmlinux.h | awk '{print $$5}'))"

# Generate eBPF Go bindings
ebpf-generate: bpf/vmlinux.h
	@echo "Generating eBPF Go bindings..."
	@cd pkg/ebpf && go generate
	@echo "✓ eBPF bindings generated"

build: ebpf-generate
	@echo "Building ANLF..."
	@go build -o bin/anlf ./cmd/main.go
	@echo "✓ Build complete: bin/anlf"

# Build eBPF test tool
ebpf-test: ebpf-generate
	@echo "Building eBPF test tool..."
	@go build -o bin/ebpf-test ./cmd/ebpf-test
	@echo "✓ eBPF test tool built: bin/ebpf-test"
	@echo ""
	@echo "Run test with: sudo ./bin/ebpf-test -iface <interface_name>"

clean:
	@echo "Cleaning..."
	@rm -rf bin/
	@rm -f bpf/vmlinux.h
	@rm -f pkg/ebpf/anlf_bpf.go pkg/ebpf/anlf_bpf.o
	@echo "✓ Clean complete"

test:
	@go test -v ./...

run:
	@./bin/anlf -c config/anlfcfg.yaml

run-log:
	@./bin/anlf -c config/anlfcfg.yaml -l log/anlf.log
