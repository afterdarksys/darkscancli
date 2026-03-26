.PHONY: all build clean test install uninstall run help deps

BINARY_NAME=darkscan
BUILD_DIR=build
INSTALL_PATH=/usr/local/bin

all: build

help:
	@echo "DarkScan - Makefile targets:"
	@echo "  make build       - Build the darkscan binary"
	@echo "  make install     - Install darkscan to $(INSTALL_PATH)"
	@echo "  make uninstall   - Remove darkscan from $(INSTALL_PATH)"
	@echo "  make clean       - Remove build artifacts"
	@echo "  make test        - Run tests"
	@echo "  make deps        - Download dependencies"
	@echo "  make run         - Build and run darkscan"

deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

build: deps
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/darkscan
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

build-noclamav: deps
	@echo "Building $(BINARY_NAME) without ClamAV..."
	@mkdir -p $(BUILD_DIR)
	go build -tags noclamav -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/darkscan
	@echo "Build complete (no ClamAV): $(BUILD_DIR)/$(BINARY_NAME)"

build-windows: deps
	@echo "Building $(BINARY_NAME) for Windows..."
	@mkdir -p $(BUILD_DIR)
	GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME).exe ./cmd/darkscan
	@echo "Windows build complete: $(BUILD_DIR)/$(BINARY_NAME).exe"

build-static: deps
	@echo "Building static binary..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 go build -ldflags="-s -w -extldflags=-static" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/darkscan
	@echo "Static build complete: $(BUILD_DIR)/$(BINARY_NAME)"

install: build
	@echo "Installing $(BINARY_NAME) to $(INSTALL_PATH)..."
	@install -m 755 $(BUILD_DIR)/$(BINARY_NAME) $(INSTALL_PATH)/$(BINARY_NAME)
	@echo "Installation complete"

uninstall:
	@echo "Removing $(BINARY_NAME) from $(INSTALL_PATH)..."
	@rm -f $(INSTALL_PATH)/$(BINARY_NAME)
	@echo "Uninstallation complete"

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@go clean
	@echo "Clean complete"

test:
	@echo "Running tests..."
	go test -v ./...

test-coverage:
	@echo "Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

run: build
	@$(BUILD_DIR)/$(BINARY_NAME)

run-scan: build
	@$(BUILD_DIR)/$(BINARY_NAME) scan $(ARGS)

cross-compile: deps
	@echo "Cross-compiling for multiple platforms..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/darkscan
	GOOS=linux GOARCH=arm64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/darkscan
	GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/darkscan
	GOOS=darwin GOARCH=arm64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/darkscan
	GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/darkscan
	@echo "Cross-compilation complete"

fmt:
	@echo "Formatting code..."
	go fmt ./...

lint:
	@echo "Running linter..."
	golangci-lint run

vet:
	@echo "Running go vet..."
	go vet ./...
