.PHONY: build test lint cover vet tidy vuln hooks

# Point git at the tracked hooks directory so the pre-commit gates run.
# Run once per clone.
hooks:
	git config core.hooksPath .githooks
	@echo "git hooks enabled (core.hooksPath=.githooks)"

# Build all packages.
build:
	go build ./...

# Run the full test suite with the race detector and coverage profiling.
test:
	go test ./... -race -coverprofile=coverage.out

# Run the linter aggregator.
lint:
	golangci-lint run

# Show a per-function coverage report from the last test run.
cover:
	go tool cover -func=coverage.out

# Run go vet across all packages.
vet:
	go vet ./...

# Tidy the module dependency graph.
tidy:
	go mod tidy

# Scan for known vulnerabilities in dependencies and the toolchain.
vuln:
	govulncheck ./...
