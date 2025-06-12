# GitHub Findings Manager Makefile

.PHONY: build clean test install deps help lint run-example

# Variables
BINARY_NAME=github-findings-manager
VERSION?=1.0.0
BUILD_DIR=./bin
GO_FILES=$(shell find . -name "*.go" -type f)

# Default target
help: ## Show this help message
	@echo "GitHub Findings Manager"
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Build targets
build: ## Build the binary
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build -ldflags "-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME) .

build-all: ## Build for all platforms
	@echo "Building for all platforms..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build -ldflags "-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 .
	GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build -ldflags "-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 .
	GOOS=windows GOARCH=amd64 go build -ldflags "-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe .

# Dependencies
deps: ## Download dependencies
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

# Development
test: ## Run tests
	@echo "Running tests..."
	go test -v ./...

test-coverage: ## Run tests with coverage
	@echo "Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

lint: ## Run linter
	@echo "Running linter..."
	golangci-lint run

format: ## Format code
	@echo "Formatting code..."
	go fmt ./...

# Installation
install: build ## Install binary to GOPATH/bin
	@echo "Installing $(BINARY_NAME)..."
	cp $(BUILD_DIR)/$(BINARY_NAME) $(GOPATH)/bin/

# Cleanup
clean: ## Clean build artifacts
	@echo "Cleaning up..."
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html
	rm -rf cache/
	rm -rf reports/

# Example runs
run-example: build ## Run example with sample organization
	@echo "Running example (requires GITHUB_TOKEN environment variable)..."
	@if [ -z "$(GITHUB_TOKEN)" ]; then \
		echo "Error: GITHUB_TOKEN environment variable is required"; \
		exit 1; \
	fi
	$(BUILD_DIR)/$(BINARY_NAME) --org $(ORG) --verbose

run-help: build ## Show help for the built binary
	$(BUILD_DIR)/$(BINARY_NAME) --help

# Development helpers
dev-setup: ## Set up development environment
	@echo "Setting up development environment..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go mod download

# Docker (optional)
docker-build: ## Build Docker image
	docker build -t github-findings-manager:$(VERSION) .

# Release preparation
release-prep: clean deps test lint build-all ## Prepare for release
	@echo "Release preparation complete"
	@echo "Artifacts in $(BUILD_DIR):"
	@ls -la $(BUILD_DIR)/

# Benchmarks
benchmark: ## Run benchmarks
	@echo "Running benchmarks..."
	go test -bench=. -benchmem ./...

# Security check
security-check: ## Run security checks
	@echo "Running security checks..."
	go list -json -deps ./... | nancy sleuth

# Generate documentation
docs: ## Generate documentation
	@echo "Generating documentation..."
	godoc -http=:6060 &
	@echo "Documentation server started at http://localhost:6060"

# Quick development cycle
dev: format lint test build ## Quick development cycle: format, lint, test, build

# Usage examples
examples: ## Show usage examples
	@echo "Usage examples:"
	@echo ""
	@echo "1. Basic usage:"
	@echo "   ./$(BUILD_DIR)/$(BINARY_NAME) --org myorg"
	@echo ""
	@echo "2. Specific repositories:"
	@echo "   ./$(BUILD_DIR)/$(BINARY_NAME) --org myorg --repos 'repo1,repo2'"
	@echo ""
	@echo "3. Filter by pod:"
	@echo "   ./$(BUILD_DIR)/$(BINARY_NAME) --org myorg --pod 'platform,security'"
	@echo ""
	@echo "4. Generate CSV output:"
	@echo "   ./$(BUILD_DIR)/$(BINARY_NAME) --org myorg --csv"
	@echo ""
	@echo "5. Custom output directory:"
	@echo "   ./$(BUILD_DIR)/$(BINARY_NAME) --org myorg --output /path/to/reports" 