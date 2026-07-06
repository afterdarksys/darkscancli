# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

DarkScan is a multi-engine malware scanner written in Go. It orchestrates several detection
engines (ClamAV, YARA, CAPA, Viper) behind one interface and enriches results with threat
intelligence from DarkAPI.io and filehashes.io. It ships as a CLI (`darkscan`), a daemon
(`darkscand`), and a C-shared library (`libdarkscan`), and can also be imported as a Go
library. Module path: `github.com/afterdarksys/darkscan`. Licensed MIT.

## Common commands

Requires Go 1.21+. ClamAV support uses CGO and libclamav; builds can opt out of it.

```bash
make build              # go build -o build/darkscan ./cmd/darkscan (with ClamAV, needs CGO + libclamav)
make build-noclamav     # go build -tags noclamav (no C compiler needed)
make build-windows      # GOOS=windows build (ClamAV auto-disabled)
make build-static       # static CGO binary
make build-lib          # buildmode=c-shared -> build/libdarkscan.so (build-lib-windows for .dll)
make cross-compile      # linux/darwin/windows amd64+arm64
make install            # install build/darkscan to /usr/local/bin
make test               # go test -v ./...
make test-coverage      # go test with coverage -> coverage.html
make lint               # golangci-lint run
make vet                # go vet ./...
make fmt                # go fmt ./...
make run / run-scan ARGS=...   # build then run
```

Run a single test with Go directly: `go test -v ./pkg/scanner -run TestName`.
See `BUILD.md` for platform/CGO build-tag details (`noclamav`, Windows).

Basic usage: `darkscan scan <path>` (`-r` recursive), `darkscan init` (writes
`$HOME/.darkscan/config.json`), `darkscan update`, `darkscan version`. Engines are toggled
with `--clamav --yara --capa --viper` (see README / `EXAMPLES.md`).

## Architecture

Engine-registry design. `pkg/scanner` defines the core `Scanner` and a common engine
interface; each detection backend is its own package under `pkg/` (`clamav`, `yara`, `capa`,
`viper`) and is registered on the scanner via `RegisterEngine`. `ScanFile` / directory scans
fan out across the registered engines concurrently (thread count and file-size limits from
config) and aggregate per-engine results (`Infected`, `Threats`, `ScanEngine`). Because the
scanner is engine-agnostic, adding an engine means implementing the interface and registering
it — the CLI and library both drive the same core.

- `cmd/darkscan/` — Cobra CLI application (`scan`, `init`, `update`, `version`; global
  `--config/--output/--verbose`).
- `cmd/` also contains the daemon entry point; `darkscand` is the built daemon binary.
- `pkg/config/` — JSON config management (`$HOME/.darkscan/config.json`), auto-created on
  first run; controls which engines are enabled and threat-intel integrations.
- `darkscanlib/` — C-shared library wrapper (built with `buildmode=c-shared`).
- `internal/utils/` — internal helpers.

Threat-intelligence integrations (DarkAPI.io for malicious domain/IP feeds and lookups;
filehashes.io for hash reputation/submission) are configured in `config.json` and layer on
top of local engine results.

ClamAV integration wraps `libclamav` via CGO, so the standard build needs a C compiler and
`libclamav-dev`; use the `noclamav` build tag (or `make build-noclamav`) to build without it.

## Docs in repo

`README.md` (full feature/config reference), `BUILD.md` (build matrix), `EXAMPLES.md`,
`INSTALL.md`, `PROJECT_SUMMARY.md`, and `config.example.json`.
