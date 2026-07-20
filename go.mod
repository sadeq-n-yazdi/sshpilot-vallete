module github.com/sadeq-n-yazdi/sshpilot-vallete

go 1.26

// The toolchain is pinned because it is the dominant input to build
// reproducibility: the same source built with two different Go patch releases
// produces different bytes. Pinning it here means a contributor's local build,
// CI, and the release pipeline all use one compiler.
//
// go1.26.5 specifically: go1.26.4 carries GO-2026-5856, a reachable
// crypto/tls Encrypted Client Hello privacy leak, which this server's TLS
// listener calls into. The govulncheck gate keeps this honest -- a new
// standard-library vulnerability turns CI red until the pin is raised.
toolchain go1.26.5

require (
	github.com/jackc/pgx/v5 v5.10.0
	golang.org/x/crypto v0.54.0
	gopkg.in/yaml.v3 v3.0.1
	modernc.org/sqlite v1.54.0
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rogpeppe/go-internal v1.15.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	modernc.org/libc v1.74.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)
