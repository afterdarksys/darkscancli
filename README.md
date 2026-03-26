# DarkScan

DarkScan is an open-source, multi-engine malware scanner written in Go. It integrates multiple detection engines to provide comprehensive malware analysis capabilities.

## Features

- **Multiple Detection Engines**
  - **ClamAV**: Industry-standard antivirus engine with extensive virus definitions
  - **YARA**: Pattern matching for malware research and detection
  - **CAPA**: Detect capabilities in executable files (FLARE team)
  - **Viper**: Malware analysis and management framework integration

- **Threat Intelligence Integrations**
  - **DarkAPI.io**: Access to threat intelligence feeds for malicious domains and IPs
    - Retrieve curated lists of malicious domains and IPs
    - Individual and bulk threat indicator lookups
    - Incremental updates for efficient threat feed synchronization
  - **filehashes.io**: File hash reputation and tracking
    - Submit and lookup file hashes (SHA256, SHA1, MD5)
    - Track hash sightings and reputation across the community

- **Flexible Scanning**
  - File and directory scanning
  - Recursive directory traversal
  - Context-aware scanning with cancellation support
  - Multiple concurrent engine execution

- **Library and CLI**
  - Use as a standalone CLI tool
  - Import as a Go library in your own projects
  - Clean, well-documented API

- **Configuration Management**
  - JSON-based configuration
  - Auto-creation of config on first run
  - Stored in `$HOME/.darkscan/config.json`

## Installation

### Prerequisites

1. **Go 1.21 or later**
   ```bash
   go version
   ```

2. **ClamAV** (optional but recommended)
   ```bash
   # macOS
   brew install clamav

   # Ubuntu/Debian
   sudo apt-get install clamav libclamav-dev

   # Fedora/RHEL
   sudo dnf install clamav clamav-devel
   ```

3. **YARA** (optional)
   ```bash
   # macOS
   brew install yara

   # Ubuntu/Debian
   sudo apt-get install libyara-dev

   # Fedora/RHEL
   sudo dnf install yara-devel
   ```

4. **CAPA** (optional)
   ```bash
   # Download from https://github.com/mandiant/capa/releases
   # Place in PATH or specify path in config
   ```

5. **Viper** (optional)
   ```bash
   # Install from https://github.com/viper-framework/viper
   pip install viper-framework
   ```

### Build from Source

```bash
git clone https://github.com/afterdarktech/darkscan.git
cd darkscan
go mod download
go build -o darkscan ./cmd/darkscan
```

### Install

```bash
go install github.com/afterdarktech/darkscan/cmd/darkscan@latest
```

## Quick Start

### Initialize Configuration

On first run, DarkScan will automatically create a configuration file at `$HOME/.darkscan/config.json`:

```bash
darkscan scan /path/to/file
```

Or explicitly initialize:

```bash
darkscan init
```

### Scan a File

```bash
darkscan scan /path/to/suspicious/file
```

### Scan a Directory

```bash
darkscan scan -r /path/to/directory
```

### Enable Specific Engines

```bash
# Scan with ClamAV and YARA
darkscan scan --clamav --yara --yara-rules=/path/to/rules /path/to/file

# Scan with all engines
darkscan scan --clamav --yara --capa --viper /path/to/file
```

## Configuration

The configuration file is located at `$HOME/.darkscan/config.json`:

```json
{
  "clamav": {
    "enabled": true,
    "database_path": "/var/lib/clamav",
    "auto_update": false
  },
  "yara": {
    "enabled": false,
    "rules_path": ""
  },
  "capa": {
    "enabled": false,
    "exe_path": "capa",
    "rules_path": ""
  },
  "viper": {
    "enabled": false,
    "exe_path": "viper-cli",
    "project_name": "default"
  },
  "darkapi": {
    "enabled": false,
    "api_key": "",
    "base_url": "https://api.darkapi.io",
    "features": {
      "bad_domains": true,
      "bad_ips": true,
      "domain_lookup": true,
      "ip_lookup": true,
      "bulk_lookup": true
    }
  },
  "filehashes": {
    "enabled": false,
    "api_key": "",
    "base_url": "https://api.filehashes.io",
    "submit_hash": true,
    "lookup_hash": true
  },
  "scan": {
    "recursive": true,
    "max_file_size": 104857600,
    "exclude_extensions": [],
    "include_extensions": [],
    "threads": 4
  }
}
```

### Configuration Options

#### ClamAV
- `enabled`: Enable/disable ClamAV engine
- `database_path`: Path to ClamAV virus definition database
- `auto_update`: Automatically update definitions (not yet implemented)

#### YARA
- `enabled`: Enable/disable YARA engine
- `rules_path`: Path to YARA rules file or directory

#### CAPA
- `enabled`: Enable/disable CAPA engine
- `exe_path`: Path to CAPA executable
- `rules_path`: Path to CAPA rules (optional)

#### Viper
- `enabled`: Enable/disable Viper engine
- `exe_path`: Path to viper-cli executable
- `project_name`: Viper project name to use

#### DarkAPI
- `enabled`: Enable/disable DarkAPI.io integration
- `api_key`: Your DarkAPI.io API key
- `base_url`: DarkAPI.io base URL (default: https://api.darkapi.io)
- `features`: Configure which DarkAPI features to use
  - `bad_domains`: Retrieve and check against malicious domain lists
  - `bad_ips`: Retrieve and check against malicious IP lists
  - `domain_lookup`: Enable individual domain threat lookups
  - `ip_lookup`: Enable individual IP threat lookups
  - `bulk_lookup`: Enable bulk threat lookups for multiple indicators

#### FileHashes
- `enabled`: Enable/disable filehashes.io integration
- `api_key`: Your filehashes.io API key
- `base_url`: filehashes.io base URL (default: https://api.filehashes.io)
- `submit_hash`: Submit file hashes to the filehashes.io database
- `lookup_hash`: Query filehashes.io for hash reputation and statistics

#### Scan
- `recursive`: Scan directories recursively
- `max_file_size`: Maximum file size to scan (bytes)
- `exclude_extensions`: File extensions to exclude
- `include_extensions`: File extensions to include (empty = all)
- `threads`: Number of concurrent scanning threads

## Using as a Library

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/afterdarktech/darkscan/pkg/scanner"
    "github.com/afterdarktech/darkscan/pkg/clamav"
    "github.com/afterdarktech/darkscan/pkg/yara"
)

func main() {
    // Create scanner
    s := scanner.New()

    // Register ClamAV engine
    clamavEngine, err := clamav.New("/var/lib/clamav")
    if err != nil {
        log.Fatal(err)
    }
    defer clamavEngine.Close()
    s.RegisterEngine(clamavEngine)

    // Register YARA engine
    yaraEngine, err := yara.New("/path/to/rules")
    if err != nil {
        log.Fatal(err)
    }
    defer yaraEngine.Close()
    s.RegisterEngine(yaraEngine)

    // Scan a file
    ctx := context.Background()
    results, err := s.ScanFile(ctx, "/path/to/file")
    if err != nil {
        log.Fatal(err)
    }

    // Process results
    for _, result := range results {
        if result.Infected {
            fmt.Printf("Threat detected by %s:\n", result.ScanEngine)
            for _, threat := range result.Threats {
                fmt.Printf("  - %s: %s\n", threat.Name, threat.Description)
            }
        }
    }
}
```

## CLI Usage

### Commands

#### `scan`
Scan a file or directory for malware.

```bash
darkscan scan [flags] <path>
```

**Flags:**
- `-r, --recursive`: Scan directories recursively (default: true)
- `--clamav`: Enable ClamAV engine (default: true)
- `--yara`: Enable YARA engine
- `--capa`: Enable CAPA engine
- `--viper`: Enable Viper engine
- `--yara-rules <path>`: Path to YARA rules
- `--capa-rules <path>`: Path to CAPA rules

#### `init`
Initialize configuration file.

```bash
darkscan init
```

#### `update`
Update scan engine definitions.

```bash
darkscan update
```

#### `version`
Show version information.

```bash
darkscan version
```

### Global Flags

- `-c, --config <path>`: Config file path (default: `$HOME/.darkscan/config.json`)
- `-o, --output <format>`: Output format (text, json)
- `-v, --verbose`: Verbose output

## Directory Structure

```
$HOME/.darkscan/
├── config.json          # Configuration file
├── yara-rules/          # YARA rules directory
├── capa-rules/          # CAPA rules directory
└── logs/                # Scan logs
```

## Engine Details

### ClamAV
ClamAV integration uses CGO to wrap `libclamav`. It provides:
- Signature-based malware detection
- Real-time database updates via `freshclam`
- Extensive virus definition database

**Database Location:**
- Linux: `/var/lib/clamav`
- macOS (Homebrew): `/usr/local/share/clamav`

**Update Definitions:**
```bash
sudo freshclam
```

### YARA
YARA integration uses `go-yara` for pattern matching:
- Custom rule support
- File and directory rule loading
- Detailed match information

**Example YARA Rule:**
```yara
rule SuspiciousPE {
    meta:
        description = "Detects suspicious PE files"
    strings:
        $mz = "MZ"
        $suspicious = "malicious_function"
    condition:
        $mz at 0 and $suspicious
}
```

### CAPA
CAPA detects capabilities in executable files:
- ATT&CK technique mapping
- Malware Behavior Catalog (MBC) mapping
- Detailed capability reports

**Download Rules:**
```bash
git clone https://github.com/mandiant/capa-rules.git ~/.darkscan/capa-rules
```

### Viper
Viper framework integration for malware management:
- Hash-based sample identification
- Project-based organization
- Tag and note support

## Development

### Project Structure

```
.
├── cmd/
│   └── darkscan/        # CLI application
│       └── main.go
├── pkg/
│   ├── scanner/         # Core scanner logic
│   ├── clamav/          # ClamAV engine
│   ├── yara/            # YARA engine
│   ├── capa/            # CAPA engine
│   ├── viper/           # Viper engine
│   └── config/          # Configuration management
├── internal/
│   └── utils/           # Internal utilities
├── go.mod
├── go.sum
└── README.md
```

### Running Tests

```bash
go test ./...
```

### Building

```bash
# Build for current platform
go build -o darkscan ./cmd/darkscan

# Cross-compile
GOOS=linux GOARCH=amd64 go build -o darkscan-linux ./cmd/darkscan
GOOS=windows GOARCH=amd64 go build -o darkscan.exe ./cmd/darkscan
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License. See LICENSE file for details.

## Acknowledgments

- **ClamAV**: Cisco Talos
- **YARA**: Victor M. Alvarez
- **CAPA**: Mandiant FLARE team
- **Viper**: Viper Framework developers

## Security Notice

This tool is designed for legitimate security research, malware analysis, and system protection. Users are responsible for ensuring they have appropriate authorization before scanning files and systems.

## Support

- Issues: https://github.com/afterdarktech/darkscan/issues
- Documentation: https://github.com/afterdarktech/darkscan/wiki

## Roadmap

- [ ] Automated ClamAV definition updates
- [ ] JSON output format
- [ ] Scan result logging
- [ ] Quarantine functionality
- [ ] REST API server mode
- [ ] Docker container support
- [ ] Additional engine integrations
- [ ] Performance optimizations
- [ ] Enhanced reporting
