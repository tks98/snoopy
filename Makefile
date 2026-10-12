VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build generate test integration lint run clean help

all: build

build: ## Build ./snoopy (a static binary)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o snoopy .

generate: ## Recompile bpf/snoopy.c; needs clang and llvm-strip (CI uses clang 18)
	go generate ./...

test: ## Run unit tests
	go test ./...

integration: ## Run the eBPF integration tests (uses sudo)
	go test -c -tags integration -o internal/tracer/tracer.test ./internal/tracer
	cd internal/tracer && sudo ./tracer.test -test.v

lint: ## Run golangci-lint
	golangci-lint run ./...
	golangci-lint run --build-tags integration ./...

run: build ## Build and run with sudo; pass flags with ARGS="--json --pid 123"
	sudo ./snoopy $(ARGS)

clean:
	rm -rf snoopy dist internal/tracer/tracer.test

help:
	@grep -E '^[a-z]+:.*## ' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'
