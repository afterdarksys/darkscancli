# DarkScan Usage Examples

This document provides practical examples of using DarkScan for various malware scanning scenarios.

## Table of Contents

- [Basic Scanning](#basic-scanning)
- [Advanced Scanning](#advanced-scanning)
- [Library Usage](#library-usage)
- [Real-World Scenarios](#real-world-scenarios)

## Basic Scanning

### Scan a Single File

```bash
darkscan scan /path/to/suspicious.exe
```

### Scan a Directory

```bash
# Recursive scan (default)
darkscan scan /path/to/directory

# Non-recursive scan
darkscan scan --recursive=false /path/to/directory
```

### Scan with Specific Engines

```bash
# ClamAV only
darkscan scan --clamav /path/to/file

# ClamAV + YARA
darkscan scan --clamav --yara --yara-rules=/path/to/rules /path/to/file

# All engines
darkscan scan --clamav --yara --capa --viper /path/to/file
```

## Advanced Scanning

### Using Custom YARA Rules

```bash
# Single rule file
darkscan scan --yara --yara-rules=/path/to/malware.yar /suspicious/file

# Directory of rules
darkscan scan --yara --yara-rules=/path/to/rules/ /suspicious/directory
```

Example YARA rule (`~/.darkscan/yara-rules/custom.yar`):

```yara
rule SuspiciousPacker {
    meta:
        description = "Detects common packer signatures"
        author = "Security Team"

    strings:
        $upx = "UPX!"
        $mz = "MZ"

    condition:
        $mz at 0 and $upx
}
```

### CAPA Analysis

```bash
# Basic CAPA scan
darkscan scan --capa /path/to/malware.exe

# With custom rules
darkscan scan --capa --capa-rules=/path/to/capa-rules /path/to/malware.exe
```

### Verbose Output

```bash
darkscan scan -v --clamav --yara /path/to/file
```

Output:
```
Initializing ClamAV engine...
Initializing YARA engine...
Scanning file: /path/to/file
======================================================================
SCAN RESULTS
======================================================================

THREATS DETECTED:

[!] /path/to/file
    ├─ Engine: ClamAV
    ├─ Threat: Win.Trojan.Generic
    ├─ Severity: HIGH
    └─ Description: Detected by ClamAV: Win.Trojan.Generic

----------------------------------------------------------------------
SUMMARY
----------------------------------------------------------------------
Files scanned:   1
Threats found:   1
Clean:           0
Errors:          0
Scan duration:   234ms
======================================================================
```

## Library Usage

### Basic Scanner

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/afterdarktech/darkscan/pkg/scanner"
    "github.com/afterdarktech/darkscan/pkg/clamav"
)

func main() {
    // Create scanner
    s := scanner.New()

    // Initialize ClamAV
    clamavEngine, err := clamav.New("/var/lib/clamav")
    if err != nil {
        log.Fatal(err)
    }
    defer clamavEngine.Close()

    // Register engine
    s.RegisterEngine(clamavEngine)

    // Scan file
    ctx := context.Background()
    results, err := s.ScanFile(ctx, "/path/to/file")
    if err != nil {
        log.Fatal(err)
    }

    // Check results
    for _, result := range results {
        if result.Infected {
            fmt.Printf("INFECTED: %s\n", result.FilePath)
            for _, threat := range result.Threats {
                fmt.Printf("  %s: %s\n", threat.Name, threat.Description)
            }
        } else {
            fmt.Printf("CLEAN: %s\n", result.FilePath)
        }
    }
}
```

### Multi-Engine Scanner

```go
package main

import (
    "context"
    "log"

    "github.com/afterdarktech/darkscan/pkg/scanner"
    "github.com/afterdarktech/darkscan/pkg/clamav"
    "github.com/afterdarktech/darkscan/pkg/yara"
    "github.com/afterdarktech/darkscan/pkg/capa"
)

func main() {
    s := scanner.New()

    // Register ClamAV
    clamavEngine, err := clamav.New("/var/lib/clamav")
    if err != nil {
        log.Printf("ClamAV init failed: %v", err)
    } else {
        defer clamavEngine.Close()
        s.RegisterEngine(clamavEngine)
    }

    // Register YARA
    yaraEngine, err := yara.New("/path/to/rules")
    if err != nil {
        log.Printf("YARA init failed: %v", err)
    } else {
        defer yaraEngine.Close()
        s.RegisterEngine(yaraEngine)
    }

    // Register CAPA
    capaEngine, err := capa.New("capa", "/path/to/capa-rules")
    if err != nil {
        log.Printf("CAPA init failed: %v", err)
    } else {
        defer capaEngine.Close()
        s.RegisterEngine(capaEngine)
    }

    // Scan directory
    ctx := context.Background()
    results, err := s.ScanDirectory(ctx, "/path/to/scan", true)
    if err != nil {
        log.Fatal(err)
    }

    // Process results
    processResults(results)
}

func processResults(results []*scanner.ScanResult) {
    infected := 0
    for _, result := range results {
        if result.Infected {
            infected++
        }
    }
    log.Printf("Scanned %d files, found %d threats", len(results), infected)
}
```

### Scan with Context Cancellation

```go
package main

import (
    "context"
    "log"
    "time"

    "github.com/afterdarktech/darkscan/pkg/scanner"
    "github.com/afterdarktech/darkscan/pkg/clamav"
)

func main() {
    s := scanner.New()

    clamavEngine, _ := clamav.New("/var/lib/clamav")
    defer clamavEngine.Close()
    s.RegisterEngine(clamavEngine)

    // Create context with timeout
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    results, err := s.ScanDirectory(ctx, "/large/directory", true)
    if err != nil {
        if err == context.DeadlineExceeded {
            log.Println("Scan timed out after 30 seconds")
        } else {
            log.Fatal(err)
        }
    }

    log.Printf("Scanned %d files", len(results))
}
```

## Real-World Scenarios

### Scan Downloads Directory

```bash
# Scan user downloads with all engines
darkscan scan -v --clamav --yara \
    --yara-rules=~/.darkscan/yara-rules \
    ~/Downloads/
```

### Automated Malware Analysis Pipeline

```go
package main

import (
    "context"
    "encoding/json"
    "log"
    "os"

    "github.com/afterdarktech/darkscan/pkg/scanner"
    "github.com/afterdarktech/darkscan/pkg/clamav"
    "github.com/afterdarktech/darkscan/pkg/yara"
    "github.com/afterdarktech/darkscan/pkg/capa"
)

type Report struct {
    FilePath string                  `json:"file_path"`
    Results  []*scanner.ScanResult   `json:"results"`
}

func analyzeFile(filePath string) error {
    s := scanner.New()

    // Initialize engines
    clamavEngine, _ := clamav.New("/var/lib/clamav")
    defer clamavEngine.Close()
    s.RegisterEngine(clamavEngine)

    yaraEngine, _ := yara.New("/etc/yara/rules")
    defer yaraEngine.Close()
    s.RegisterEngine(yaraEngine)

    capaEngine, _ := capa.New("capa", "")
    defer capaEngine.Close()
    s.RegisterEngine(capaEngine)

    // Scan
    ctx := context.Background()
    results, err := s.ScanFile(ctx, filePath)
    if err != nil {
        return err
    }

    // Generate report
    report := Report{
        FilePath: filePath,
        Results:  results,
    }

    // Output JSON
    encoder := json.NewEncoder(os.Stdout)
    encoder.SetIndent("", "  ")
    return encoder.Encode(report)
}

func main() {
    if len(os.Args) < 2 {
        log.Fatal("Usage: analyze <file>")
    }

    if err := analyzeFile(os.Args[1]); err != nil {
        log.Fatal(err)
    }
}
```

### Email Attachment Scanner

```go
package main

import (
    "context"
    "io"
    "log"
    "os"

    "github.com/afterdarktech/darkscan/pkg/scanner"
    "github.com/afterdarktech/darkscan/pkg/clamav"
)

func scanAttachment(reader io.Reader, name string) (bool, error) {
    s := scanner.New()

    clamavEngine, err := clamav.New("/var/lib/clamav")
    if err != nil {
        return false, err
    }
    defer clamavEngine.Close()
    s.RegisterEngine(clamavEngine)

    ctx := context.Background()
    results, err := s.ScanReader(ctx, reader, name)
    if err != nil {
        return false, err
    }

    // Check if infected
    for _, result := range results {
        if result.Infected {
            return true, nil
        }
    }

    return false, nil
}

func main() {
    file, err := os.Open("attachment.pdf")
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close()

    infected, err := scanAttachment(file, "attachment.pdf")
    if err != nil {
        log.Fatal(err)
    }

    if infected {
        log.Println("WARNING: Attachment contains malware!")
    } else {
        log.Println("Attachment is clean")
    }
}
```

### Batch Processing

```bash
#!/bin/bash
# scan-batch.sh - Scan multiple files and generate report

OUTPUT_DIR="scan-results"
mkdir -p "$OUTPUT_DIR"

for file in /path/to/samples/*; do
    filename=$(basename "$file")
    darkscan scan --clamav --yara --capa "$file" > "$OUTPUT_DIR/$filename.txt" 2>&1
    echo "Scanned: $filename"
done

echo "Batch scan complete. Results in $OUTPUT_DIR/"
```

### Integration with Quarantine

```go
package main

import (
    "context"
    "fmt"
    "io"
    "log"
    "os"
    "path/filepath"

    "github.com/afterdarktech/darkscan/pkg/scanner"
    "github.com/afterdarktech/darkscan/pkg/clamav"
)

func scanAndQuarantine(filePath, quarantineDir string) error {
    s := scanner.New()

    clamavEngine, _ := clamav.New("/var/lib/clamav")
    defer clamavEngine.Close()
    s.RegisterEngine(clamavEngine)

    ctx := context.Background()
    results, err := s.ScanFile(ctx, filePath)
    if err != nil {
        return err
    }

    // Check for threats
    for _, result := range results {
        if result.Infected {
            // Move to quarantine
            quarantinePath := filepath.Join(quarantineDir, filepath.Base(filePath))
            return moveToQuarantine(filePath, quarantinePath)
        }
    }

    return nil
}

func moveToQuarantine(src, dst string) error {
    srcFile, err := os.Open(src)
    if err != nil {
        return err
    }
    defer srcFile.Close()

    dstFile, err := os.Create(dst)
    if err != nil {
        return err
    }
    defer dstFile.Close()

    if _, err := io.Copy(dstFile, srcFile); err != nil {
        return err
    }

    return os.Remove(src)
}

func main() {
    if err := scanAndQuarantine("/path/to/file", "/quarantine"); err != nil {
        log.Fatal(err)
    }
    fmt.Println("File processed successfully")
}
```

## Tips and Best Practices

1. **Keep Definitions Updated**
   ```bash
   sudo freshclam  # Update ClamAV
   cd ~/.darkscan/yara-rules && git pull  # Update YARA
   ```

2. **Use Appropriate Engines**
   - **ClamAV**: General malware, known threats
   - **YARA**: Custom patterns, specific malware families
   - **CAPA**: Executable analysis, capability detection
   - **Viper**: Known samples, hash matching

3. **Performance Optimization**
   - Adjust `threads` in config for parallel scanning
   - Set `max_file_size` to skip large files
   - Use `exclude_extensions` for known-clean types

4. **Error Handling**
   - Always check error returns
   - Handle context cancellation gracefully
   - Close engines with defer

5. **Security**
   - Run with least privilege necessary
   - Quarantine infected files immediately
   - Log all detections for audit trail
