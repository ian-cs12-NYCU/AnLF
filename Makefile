.PHONY: all build clean test run

all: build

build:
@echo "Building ANLF..."
@go build -o bin/anlf ./cmd/main.go
@echo "✓ Build complete: bin/anlf"

clean:
@echo "Cleaning..."
@rm -rf bin/
@echo "✓ Clean complete"

test:
@go test -v ./...

run:
@./bin/anlf -c config/anlfcfg.yaml

run-log:
@./bin/anlf -c config/anlfcfg.yaml -l log/anlf.log
