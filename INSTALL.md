# Installation Guide

This guide covers the installation of DarkScan and its dependencies.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installing Dependencies](#installing-dependencies)
- [Building DarkScan](#building-darkscan)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)

## Prerequisites

- Go 1.21 or later
- C compiler (gcc or clang) for CGO support
- Make (optional, for using Makefile)

## Installing Dependencies

### macOS

#### Using Homebrew

```bash
# Install Go
brew install go

# Install ClamAV
brew install clamav

# Install YARA
brew install yara

# Install CAPA (download binary)
curl -L https://github.com/mandiant/capa/releases/latest/download/capa-macos -o /usr/local/bin/capa
chmod +x /usr/local/bin/capa

# Download ClamAV virus definitions
sudo freshclam
```

### Linux (Ubuntu/Debian)

```bash
# Install Go
sudo apt update
sudo apt install golang-go

# Install ClamAV
sudo apt install clamav libclamav-dev clamav-daemon

# Install YARA
sudo apt install libyara-dev yara

# Install build essentials
sudo apt install build-essential pkg-config

# Install CAPA
curl -L https://github.com/mandiant/capa/releases/latest/download/capa-linux -o /tmp/capa
sudo install -m 755 /tmp/capa /usr/local/bin/capa

# Update ClamAV definitions
sudo systemctl stop clamav-freshclam
sudo freshclam
sudo systemctl start clamav-freshclam
```

### Linux (Fedora/RHEL/CentOS)

```bash
# Install Go
sudo dnf install golang

# Install ClamAV
sudo dnf install clamav clamav-devel clamav-update

# Install YARA
sudo dnf install yara yara-devel

# Install development tools
sudo dnf groupinstall "Development Tools"

# Install CAPA
curl -L https://github.com/mandiant/capa/releases/latest/download/capa-linux -o /tmp/capa
sudo install -m 755 /tmp/capa /usr/local/bin/capa

# Update ClamAV definitions
sudo freshclam
```

## Building DarkScan

### Quick Build

```bash
# Clone the repository
git clone https://github.com/afterdarksys/darkscan.git
cd darkscan

# Download Go dependencies
go mod download

# Build the binary
go build -o darkscan ./cmd/darkscan

# Run darkscan
./darkscan --help
```

### Using Makefile

```bash
# Clone the repository
git clone https://github.com/afterdarksys/darkscan.git
cd darkscan

# Build
make build

# Install to /usr/local/bin
sudo make install

# Run darkscan
darkscan --help
```

### Build with CGO (ClamAV support)

ClamAV integration requires CGO to be enabled:

```bash
# Ensure CGO is enabled (default)
export CGO_ENABLED=1

# Build
go build -o darkscan ./cmd/darkscan
```

If you encounter CGO errors:

```bash
# macOS: Install Xcode Command Line Tools
xcode-select --install

# Linux: Install build essentials
sudo apt install build-essential  # Ubuntu/Debian
sudo dnf groupinstall "Development Tools"  # Fedora/RHEL
```

### Static Binary (Linux)

To build a static binary:

```bash
make build-static
```

Or manually:

```bash
CGO_ENABLED=1 go build -ldflags="-s -w -extldflags=-static" -o darkscan ./cmd/darkscan
```

## Configuration

### First Run

On first run, DarkScan creates a default configuration at `$HOME/.darkscan/config.json`:

```bash
darkscan scan /bin/ls
```

### Manual Configuration

Create the configuration directory:

```bash
mkdir -p ~/.darkscan
```

Create `~/.darkscan/config.json`:

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
  "scan": {
    "recursive": true,
    "max_file_size": 104857600,
    "exclude_extensions": [],
    "include_extensions": [],
    "threads": 4
  }
}
```

### ClamAV Database Paths

DarkScan looks for ClamAV databases in these locations:

- **macOS (Homebrew)**: `/usr/local/share/clamav`
- **Linux**: `/var/lib/clamav`
- **Custom**: Specify in config.json

Verify your database path:

```bash
# macOS
ls -la /usr/local/share/clamav

# Linux
ls -la /var/lib/clamav
```

### YARA Rules

Download YARA rules:

```bash
# Create rules directory
mkdir -p ~/.darkscan/yara-rules

# Clone popular rule sets
git clone https://github.com/Yara-Rules/rules.git ~/.darkscan/yara-rules/yara-rules
```

Update config to use YARA:

```json
{
  "yara": {
    "enabled": true,
    "rules_path": "/home/user/.darkscan/yara-rules"
  }
}
```

### CAPA Rules

Download CAPA rules:

```bash
# Create rules directory
mkdir -p ~/.darkscan/capa-rules

# Clone CAPA rules
git clone https://github.com/mandiant/capa-rules.git ~/.darkscan/capa-rules
```

Update config to use CAPA:

```json
{
  "capa": {
    "enabled": true,
    "exe_path": "capa",
    "rules_path": "/home/user/.darkscan/capa-rules"
  }
}
```

## Verification

Verify all components are working:

```bash
# Check DarkScan version
darkscan version

# Test scan with ClamAV only
darkscan scan --clamav /bin/ls

# Test with all engines (if configured)
darkscan scan --clamav --yara --capa /bin/ls
```

## Troubleshooting

### ClamAV: "failed to load database"

**Problem**: ClamAV database not found

**Solution**:
```bash
# Update virus definitions
sudo freshclam

# Or specify custom database path
darkscan scan --config=/path/to/config.json /file
```

### YARA: "failed to compile rules"

**Problem**: Invalid YARA rules or syntax errors

**Solution**:
```bash
# Test YARA rules manually
yara /path/to/rules.yar /path/to/file

# Check for syntax errors in rules
```

### CAPA: "executable not found"

**Problem**: CAPA not in PATH

**Solution**:
```bash
# Add to PATH
export PATH=$PATH:/path/to/capa

# Or specify full path in config
{
  "capa": {
    "exe_path": "/usr/local/bin/capa"
  }
}
```

### CGO: "C compiler not found"

**Problem**: Missing C compiler

**Solution**:
```bash
# macOS
xcode-select --install

# Ubuntu/Debian
sudo apt install build-essential

# Fedora/RHEL
sudo dnf groupinstall "Development Tools"
```

### Permission Denied

**Problem**: Cannot access files or write to directories

**Solution**:
```bash
# Run with sudo for system files
sudo darkscan scan /system/path

# Or change file permissions
chmod +r /path/to/file
```

## Updating

### Update DarkScan

```bash
cd darkscan
git pull
make clean
make build
sudo make install
```

### Update Virus Definitions

```bash
# ClamAV
sudo freshclam

# YARA rules
cd ~/.darkscan/yara-rules
git pull

# CAPA rules
cd ~/.darkscan/capa-rules
git pull
```

## Uninstallation

```bash
# Remove binary
sudo make uninstall

# Or manually
sudo rm /usr/local/bin/darkscan

# Remove configuration (optional)
rm -rf ~/.darkscan
```

## Next Steps

- Read the [README.md](README.md) for usage examples
- Configure your scan engines in `~/.darkscan/config.json`
- Download YARA and CAPA rules for enhanced detection
- Run your first scan!
