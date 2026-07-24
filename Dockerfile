# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# valletd — production container image
#
# Multi-stage:
#   1. builder  — pinned Go toolchain, produces a static, CGO-free binary.
#   2. final    — distroless static (non-root), ships only the binary + CA roots.
#
# Design constraints honoured (see CLAUDE.md / docs/architecture/adr/):
#   * HTTPS-only, fail-closed server — there is deliberately NO plaintext port.
#   * Pure-Go SQLite (modernc.org/sqlite) — CGO_ENABLED=0, so the binary is
#     fully static and runs on a scratch/distroless base with no libc.
#   * Reproducibility-friendly flags mirror scripts/build.sh (the repo's single
#     source of truth for release flags): -trimpath, -buildvcs=false, -ldflags
#     "-s -w". No build timestamp is baked in.
# ---------------------------------------------------------------------------

# Pin the exact toolchain from go.mod (`toolchain go1.26.5`). Pinning the tag
# plus GOTOOLCHAIN=local means a mismatch fails loudly instead of silently
# auto-downloading a different compiler mid-build (which would break byte-for-
# byte reproducibility).
FROM golang:1.26.5-bookworm AS builder

ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local \
    GOFLAGS=-mod=readonly

WORKDIR /src

# Warm the module cache in its own layer so dependency downloads are cached
# across source-only changes.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

COPY . .

# VERSION is injected the same way scripts/build.sh does it. `.git` is excluded
# from the build context (see .dockerignore), so pass it explicitly for a real
# version string; it defaults to a dev marker otherwise.
ARG VERSION=0.0.0-dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build \
        -trimpath \
        -buildvcs=false \
        -ldflags "-s -w -X 'github.com/sadeq-n-yazdi/sshpilot-vallete/internal/version.Version=${VERSION}'" \
        -o /out/valletd \
        ./cmd/valletd

# A tiny, static, dependency-free healthcheck. distroless has no shell/curl/wget,
# and the server is HTTPS-only (often with a self-signed dev cert), so a naive
# probe has nothing to run and would fail the TLS handshake. This ~2 MB helper
# does an HTTPS GET of /healthz with certificate verification skipped (it only
# proves the process is alive and serving TLS locally — it is NOT a security
# boundary) and exits 0 on HTTP 200. It works against both the self-signed dev
# cert and a real production cert. /healthz is unauthenticated and reports pure
# process liveness, so it is safe to poll and unaffected by the fail-closed auth
# wiring. Generated inline so no extra command is added to the repo tree.
RUN mkdir -p /hc && cat > /hc/healthcheck.go <<'GO'
package main

import (
	"crypto/tls"
	"net/http"
	"os"
	"time"
)

// A liveness probe, not a trust check: InsecureSkipVerify is intentional so the
// same probe works against the self-signed dev certificate and a real one. It
// only asks "is valletd answering TLS on the health port with 200?".
func main() {
	addr := os.Getenv("VALLET_HEALTHCHECK_URL")
	if addr == "" {
		addr = "https://127.0.0.1:8443/healthz"
	}
	c := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // liveness probe only
		},
	}
	resp, err := c.Get(addr)
	if err != nil {
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		os.Exit(1)
	}
}
GO
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    cd /hc && go mod init healthcheck >/dev/null 2>&1 && \
    go build -trimpath -ldflags "-s -w" -o /out/healthcheck ./healthcheck.go

# Create the data directory here (the distroless final stage has no shell to
# `mkdir`), owned by the non-root UID the final stage runs as. When a named
# volume is first mounted over this path, Docker seeds it from the image and
# preserves this ownership, so SQLite can write without a root chown step.
# NB: sqlite.Open does NOT create the parent directory — it must exist.
RUN mkdir -p /data && chown 65532:65532 /data

# ---------------------------------------------------------------------------
# Final stage: distroless static, non-root.
#   * static-debian12 carries the CA root bundle (needed for outbound HTTPS to
#     ACME/DNS providers) and /etc/passwd for the nonroot user — nothing else.
#   * :nonroot runs as UID/GID 65532; no shell, no package manager, minimal
#     attack surface. Pin by tag; digest-pinning is recommended for releases.
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS final

# The default SQLite path is ./data/vallet.db, resolved relative to the working
# directory, so WORKDIR + the /data volume line up with the built-in default.
WORKDIR /

COPY --from=builder /out/valletd /usr/local/bin/valletd
COPY --from=builder /out/healthcheck /usr/local/bin/healthcheck
COPY --from=builder --chown=65532:65532 /data /data

# Persist the SQLite database and any on-disk cert/cache material (e.g. ACME or
# cloudflare_origin cache_dir) across container recreation.
VOLUME ["/data"]

# HTTPS API listener (server.listen_addr default :8443). There is no plaintext
# port to expose by design.
EXPOSE 8443

USER 65532:65532

# Sensible container defaults; override per environment via env / a mounted
# config file. The database path is pinned to the volume mount point.
ENV VALLET_DATABASE_SQLITE_PATH=/data/vallet.db

# HTTPS-only + distroless-aware healthcheck (see the builder note above).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/healthcheck"]

ENTRYPOINT ["/usr/local/bin/valletd"]
