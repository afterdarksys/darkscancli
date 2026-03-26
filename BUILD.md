# Build Instructions

## Platform-Specific Builds

### macOS / Linux (with ClamAV)

Standard build with full ClamAV support:

```bash
make build
```

Or manually:

```bash
CGO_ENABLED=1 go build -o darkscan ./cmd/darkscan
```

### macOS / Linux (without ClamAV)

Build without ClamAV if you don't have libclamav installed:

```bash
make build-noclamav
```

Or manually:

```bash
go build -tags noclamav -o darkscan ./cmd/darkscan
```

### Windows

Windows build automatically disables ClamAV:

```bash
make build-windows
```

Or manually:

```bash
GOOS=windows GOARCH=amd64 go build -o darkscan.exe ./cmd/darkscan
```

## Build Tags

- `noclamav` - Disable ClamAV support
- `windows` - Automatically disables ClamAV on Windows

## Cross-Platform Compilation

Build for all platforms:

```bash
make cross-compile
```

Outputs:
- `build/darkscan-linux-amd64`
- `build/darkscan-linux-arm64`
- `build/darkscan-darwin-amd64`
- `build/darkscan-darwin-arm64`
- `build/darkscan-windows-amd64.exe`

## Engine Availability by Platform

| Engine | Linux | macOS | Windows |
|--------|-------|-------|---------|
| ClamAV | ✅ (CGO) | ✅ (CGO) | ⚠️ (disabled by default) |
| YARA   | ✅ | ✅ | ✅ |
| CAPA   | ✅ | ✅ | ✅ |
| Viper  | ✅ | ✅ | ⚠️ (if installed) |

## Requirements by Build Type

### Full Build (with ClamAV)
- Go 1.21+
- C compiler (gcc/clang)
- libclamav-dev
- CGO_ENABLED=1

### No ClamAV Build
- Go 1.21+
- No C compiler needed
- CGO_ENABLED=0 works

### Windows Build
- Go 1.21+
- ClamAV automatically disabled
- YARA, CAPA, Viper still available
