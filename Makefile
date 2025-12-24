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
	@mkdir -p output
	@echo "Running ANLF (as root)..."
	@sudo ./bin/anlf -c config/anlfcfg.yaml
	@if [ -d output ]; then echo "Fixing output directory permissions..."; sudo chown -R $$(id -u):$$(id -g) output 2>/dev/null; echo "✓ Output directory now owned by $(shell whoami)"; fi

# Alternative: Run with Linux capabilities instead of sudo (requires one-time setup)
run-cap: build
	@mkdir -p output
	@echo "Setting up capabilities for eBPF and TC operations..."
	@sudo setcap cap_bpf,cap_perfmon,cap_sys_resource,cap_sys_admin,cap_net_admin=ep ./bin/anlf
	@echo "Running ANLF without sudo (using capabilities)..."
	@./bin/anlf -c config/anlfcfg.yaml

.PHONY: cap-setup
cap-setup:
	@echo "Setting up capabilities for eBPF and TC operations..."
	@sudo setcap cap_bpf,cap_perfmon,cap_sys_resource,cap_sys_admin,cap_net_admin=ep ./bin/anlf
	@echo "✓ Capabilities set successfully"
	@echo "   Capabilities: cap_bpf, cap_perfmon, cap_sys_resource, cap_sys_admin, cap_net_admin"
	@echo "   You can now run 'make run-cap' without sudo"
	@echo "   To verify: getcap ./bin/anlf"

.PHONY: cap-revoke
cap-revoke:
	@echo "Revoking capabilities from binary..."
	@sudo setcap -r ./bin/anlf
	@echo "✓ Capabilities revoked"

.PHONY: fix-perms
fix-perms:
	@echo "Fixing output directory permissions..."
	@sudo chown -R $$(id -u):$$(id -g) output 2>/dev/null
	@echo "✓ Output directory now owned by $(shell whoami)"

run-log:
	@sudo ./bin/anlf -c config/anlfcfg.yaml -l log/anlf.log