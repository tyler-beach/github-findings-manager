# GitHub Findings Manager Makefile

.PHONY: build test lint clean install

# Variables
APP_NAME := github-findings-manager
VERSION := $(shell git describe --tags --abbrev=0 2>/dev/null || echo "v0.1.0")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)

# Go variables
GOCMD := go
GOBUILD := $(GOCMD) build
GOTEST := $(GOCMD) test
GOGET := $(GOCMD) get
GOMOD := $(GOCMD) mod
GOFMT := gofmt
GOLINT := golangci-lint

# Build targets
build:
	@echo "Building $(APP_NAME) $(VERSION)..."
	$(GOBUILD) -ldflags="$(LDFLAGS)" -o bin/$(APP_NAME) ./cmd/github-findings-manager

build-all: clean
	@echo "Building for all platforms..."
	GOOS=darwin GOARCH=amd64 $(GOBUILD) -ldflags="$(LDFLAGS)" -o bin/$(APP_NAME)-darwin-amd64 ./cmd/github-findings-manager
	GOOS=darwin GOARCH=arm64 $(GOBUILD) -ldflags="$(LDFLAGS)" -o bin/$(APP_NAME)-darwin-arm64 ./cmd/github-findings-manager
	GOOS=linux GOARCH=amd64 $(GOBUILD) -ldflags="$(LDFLAGS)" -o bin/$(APP_NAME)-linux-amd64 ./cmd/github-findings-manager
	GOOS=windows GOARCH=amd64 $(GOBUILD) -ldflags="$(LDFLAGS)" -o bin/$(APP_NAME)-windows-amd64.exe ./cmd/github-findings-manager

# Development targets
test:
	@echo "Running tests..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...

test-coverage: test ## Run tests with coverage report
	@echo "Generating coverage report..."
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

benchmark: ## Run benchmarks
	@echo "Running benchmarks..."
	$(GOTEST) -bench=. -benchmem ./...

lint:
	@echo "Running linter..."
	$(GOLINT) run

fmt: ## Format code
	@echo "Formatting code..."
	$(GOFMT) -s -w .
	$(GOCMD) mod tidy

deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) verify
	$(GOMOD) tidy
	$(GOGET) github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Installation targets
install: build
	@echo "Installing $(APP_NAME)..."
	mv bin/$(APP_NAME) /usr/local/bin/$(APP_NAME)

# Utility targets
clean:
	@echo "Cleaning..."
	rm -rf bin/
	rm -f coverage.out coverage.html
	rm -f *.db *.xlsx *.csv

run: build ## Build and run the application
	@echo "Running $(APP_NAME)..."
	./bin/$(APP_NAME) --help

run-example: build ## Run with example parameters
	@echo "Running example..."
	./bin/$(APP_NAME) --org example-org --env-type Production --verbose

# Release targets
release-prep: clean fmt lint test build-all ## Prepare for release
	@echo "Release preparation complete"

# Database targets
db-clean: ## Clean database files
	rm -f *.db

db-reset: db-clean ## Reset database
	@echo "Database reset complete"

# Performance targets
profile-cpu: build ## Run CPU profiling
	@echo "Running CPU profiling..."
	./bin/$(APP_NAME) --org $(ORG) --profile-cpu cpu.prof

profile-mem: build ## Run memory profiling
	@echo "Running memory profiling..."
	./bin/$(APP_NAME) --org $(ORG) --profile-mem mem.prof

# Security targets
security-scan: ## Run security scan
	@echo "Running security scan..."
	$(GOCMD) list -json -m all | nancy sleuth

vuln-check: ## Check for vulnerabilities
	@echo "Checking for vulnerabilities..."
	$(GOCMD) list -json -m all | nancy sleuth

# Documentation targets
docs: ## Generate documentation
	@echo "Generating documentation..."
	$(GOCMD) doc -all > docs/api.md

# CI/CD targets
ci-test: lint test ## Run CI tests
	@echo "CI tests complete"

ci-build: build test ## CI build pipeline
	@echo "CI build complete"

ci-deploy: release-prep ## CI deployment pipeline
	@echo "CI deployment complete"

# Help target
help: ## Show this help message
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Default target
.DEFAULT_GOAL := help

# Version information
version: ## Show version information
	@echo "$(APP_NAME) $(VERSION)"
	@echo "Commit: $(COMMIT)"
	@echo "Build Time: $(BUILD_TIME)" 