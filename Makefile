.PHONY: build clean test install lint

# Build variables
BINARY_NAME=snyk-ignore
GO=go
GOFLAGS=-v
VERSION=0.1.0
LDFLAGS=-ldflags "-X main.Version=$(VERSION)"

# Build targets
build:
	$(GO) build $(LDFLAGS) -o bin/$(BINARY_NAME) .

build-all: build-darwin build-linux build-windows

build-darwin:
	GOOS=darwin GOARCH=arm64 $(GO) build $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-arm64 .
	GOOS=darwin GOARCH=amd64 $(GO) build $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-amd64 .

build-linux:
	GOOS=linux GOARCH=amd64 $(GO) build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-amd64 .
	GOOS=linux GOARCH=arm64 $(GO) build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-arm64 .

build-windows:
	GOOS=windows GOARCH=amd64 $(GO) build $(LDFLAGS) -o bin/$(BINARY_NAME)-windows-amd64.exe .

install: build
	cp bin/$(BINARY_NAME) $(shell go env GOPATH)/bin/

test:
	$(GO) test ./... -v -race -coverprofile=coverage.out

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/
	$(GO) clean

deps:
	$(GO) mod download
	$(GO) mod tidy

help:
	@echo "Available targets:"
	@echo "  make build          - Build binary for current platform"
	@echo "  make build-all      - Build for all platforms (Darwin, Linux, Windows)"
	@echo "  make install        - Build and install to \$$GOPATH/bin"
	@echo "  make test           - Run tests"
	@echo "  make lint           - Run linter"
	@echo "  make clean          - Remove build artifacts"
	@echo "  make deps           - Download and tidy dependencies"
