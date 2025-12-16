.PHONY: all build clean test run ebpf-generate ebpf-test

all: build tools-prompt-preview

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

# Build tools: prompt preview
.PHONY: tools-prompt-preview
tools-prompt-preview:
	@echo "Building tools/prompt_preview..."
	@mkdir -p bin
	@go build -o bin/prompt_preview ./tools/prompt_preview.go
	@echo "✓ Tool built: bin/prompt_preview"

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
	@rm -f bin/prompt_preview
	@echo "✓ Clean complete"

test:
	@go test -v ./...

run:
	@sudo ./bin/anlf -c config/anlfcfg.yaml

run-log:
	@sudo ./bin/anlf -c config/anlfcfg.yaml -l log/anlf.log