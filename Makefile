.PHONY: build test lint cover vet tidy vuln hooks dist repro sbom clean

# Supply-chain tool versions are pinned here and mirrored in the workflows, so
# a local run and a CI run scan with exactly the same tool. An unpinned scanner
# is an unpinned dependency.
GOVULNCHECK_VERSION ?= v1.6.0
CYCLONEDX_GOMOD_VERSION ?= v1.10.0

# Output directory for release artifacts (binary, SBOM, checksums).
DIST_DIR ?= dist

# Point git at the tracked hooks directory so the pre-commit gates run.
# Run once per clone.
hooks:
	git config core.hooksPath .githooks
	@echo "git hooks enabled (core.hooksPath=.githooks)"

# Build all packages.
build:
	go build -ldflags "-s -w" ./...

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
# The pinned version is installed on demand so this target behaves identically
# whether or not the developer already has govulncheck on PATH.
vuln:
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

# Produce the reproducible release binary. Delegates to scripts/build.sh, which
# is the single source of truth for the release build flags -- CI calls this
# same target, so a local build and a release build cannot diverge.
dist:
	OUT_DIR=$(DIST_DIR) ./scripts/build.sh

# Verify the release build is reproducible by building twice and comparing
# bytes. This is the test that certifies the `dist` target's central claim.
repro:
	go test ./internal/build/ -run TestBuildIsReproducible -count=1 -v

# Generate a CycloneDX SBOM for the module.
#
# CycloneDX is chosen over SPDX because cyclonedx-gomod is Go-module-native: it
# records the exact module versions and their go.sum hashes, which is precisely
# the evidence needed to answer "what went into this binary".
#
# -notimestamp and -noserial keep the SBOM itself reproducible: a generation
# timestamp and a random serial number would make two SBOMs of identical source
# differ, which defeats the point of publishing one alongside a reproducible
# binary. Release provenance comes from the cosign signature, not from a
# self-asserted clock reading.
sbom:
	mkdir -p $(DIST_DIR)
	go run github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@$(CYCLONEDX_GOMOD_VERSION) \
		mod -licenses -json -notimestamp -noserial -output $(DIST_DIR)/sbom.cdx.json

# Remove build outputs.
clean:
	rm -rf $(DIST_DIR) coverage.out coverage.html
