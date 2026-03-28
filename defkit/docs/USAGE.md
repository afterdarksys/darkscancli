# defkit Usage Guide

## Quick Start

### 1. Analyze a Sample

```bash
# Basic analysis
defkit analyze malware.exe

# Save analysis to file
defkit analyze malware.exe -o analysis/

# Custom options
defkit analyze --min-string 8 --format text malware.exe
```

### 2. Generate Signatures

```bash
# Generate all signature types
defkit generate --name Trojan.Generic malware.exe

# Generate specific format
defkit generate --format yara --name MyRule malware.exe

# From existing analysis
defkit generate analysis/malware.json --name Backdoor.Win32.Agent
```

## Detailed Usage

### Analysis Options

```bash
defkit analyze [options] <file>

Options:
  -o, --output <dir>      Save analysis to directory
  -f, --format <format>   Output format: json, text (default: json)
  --no-strings            Skip string extraction
  --no-patterns           Skip pattern extraction
  --min-string <n>        Minimum string length (default: 4)
```

**Analysis Output:**
- File type and architecture
- Hash values (MD5, SHA1, SHA256, SSDEEP)
- Extracted strings (ASCII, Unicode, URLs, IPs, domains)
- Binary patterns with entropy
- PE/ELF/Mach-O structural information
- Auto-classification and tagging

### Signature Generation

```bash
defkit generate [options] <file-or-analysis>

Options:
  -o, --output <dir>      Output directory (default: ./signatures)
  -n, --name <name>       Threat name (REQUIRED)
  -f, --format <fmt>      Format: all, clamav, yara, capa (default: all)
  --clamav-type <type>    ClamAV type: all, hdb, ndb, ldb (default: all)
  --author <name>         Author name (default: defkit)
  -d, --description <txt> Threat description
  --family <name>         Malware family
  --severity <level>      Severity: low, medium, high
```

**Signature Formats:**

#### ClamAV Signatures

- **HDB**: MD5 hash signatures
  ```
  44d88612fea8a8f36de82e1278abb02f:68:EICAR-AV-Test
  ```

- **HSB**: SHA256 hash signatures
  ```
  275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:68:EICAR-AV-Test
  ```

- **NDB**: Extended hex pattern signatures
  ```
  Trojan.Generic:1:0:4d5a90000300000004000000ffff0000
  ```

- **LDB**: Logical signatures with multiple patterns
  ```
  Trojan.Generic;1:*:*;0&1;hexpattern1;hexpattern2
  ```

#### YARA Rules

Complete YARA rules with metadata, strings, and conditions:

```yara
rule Trojan_Generic : trojan pe {
    meta:
        author = "defkit"
        date = "2024-01-15"
        md5 = "44d88612fea8a8f36de82e1278abb02f"
        severity = "high"

    strings:
        $str1 = "http://malicious.com" ascii wide
        $hex1 = { 4D 5A 90 00 03 00 00 00 }
        $api1 = "VirtualAlloc" ascii

    condition:
        2 of ($str*) and 1 of ($hex*) and filesize < 10MB
}
```

#### CAPA Rules

Behavioral capability rules with ATT&CK mapping:

```yaml
rule:
  meta:
    name: Trojan_Generic
    namespace: malware/trojan
    authors:
      - defkit
    scope: file
    att&ck:
      - Defense Evasion::Process Injection [T1055]
    mbc:
      - Defense Evasion::Process Injection [E1055]
  features:
    - api: VirtualAllocEx
    - api: WriteProcessMemory
    - api: CreateRemoteThread
```

## Workflow Examples

### Example 1: Analyze and Generate from Sample

```bash
# Analyze the sample
defkit analyze trojan.exe -o analysis/

# Review the analysis
cat analysis/trojan.exe.json

# Generate all signature types
defkit generate analysis/trojan.exe.json \
  --name Trojan.Win32.Generic \
  --family trojan \
  --severity high \
  --description "Generic trojan detection"

# Result:
# signatures/
# ├── clamav/
# │   ├── custom.hdb
# │   ├── custom.ndb
# │   └── custom.ldb
# ├── yara/
# │   └── Trojan.Win32.Generic.yar
# └── capa/
#     ├── Trojan.Win32.Generic.json
#     └── Trojan.Win32.Generic.yml
```

### Example 2: Quick YARA Rule Generation

```bash
# Generate only YARA rule
defkit generate malware.exe \
  --format yara \
  --name Backdoor_Custom \
  --author "Security Team" \
  -o rules/

# Test the rule
yara rules/Backdoor_Custom.yar samples/
```

### Example 3: ClamAV Hash Signature

```bash
# Generate only MD5 hash signature
defkit generate malware.exe \
  --format clamav \
  --clamav-type hdb \
  --name Malware.Generic

# Add to ClamAV database
cat signatures/clamav/custom.hdb >> /var/lib/clamav/custom.hdb
```

### Example 4: Batch Processing

```bash
#!/bin/bash
# Process multiple samples

for sample in samples/*.exe; do
    basename=$(basename "$sample" .exe)
    echo "Processing $basename..."

    # Analyze
    defkit analyze "$sample" -o "analysis/"

    # Generate signatures
    defkit generate "analysis/${basename}.exe.json" \
        --name "Detected_${basename}" \
        --family "unknown" \
        -o "signatures/${basename}/"
done
```

## Integration with darkscand

### Deploy to darkscand Mirror

```bash
# Generate signatures
defkit generate malware.exe --name CustomThreat -o /tmp/sigs

# Copy to darkscand database
cp /tmp/sigs/clamav/*.hdb /var/lib/clamav/
cp /tmp/sigs/yara/*.yar /etc/darkscand/yara-rules/

# Reload darkscand engines
curl -X POST http://localhost:8080/api/v1/reload
```

### Custom Mirror Deployment

```bash
# Generate bundled signatures
defkit generate batch_samples/ --name CustomDB -o custom_db/

# Package for mirror
tar czf custom-definitions.tar.gz -C custom_db .

# Upload to mirror
scp custom-definitions.tar.gz mirror:/var/www/clamav/custom.tar.gz
```

## Best Practices

### 1. Naming Conventions

Use consistent naming patterns:
- `Malware.Platform.Family.Variant`
- Examples:
  - `Trojan.Win32.Emotet.A`
  - `Backdoor.Linux.Mirai.B`
  - `Ransomware.Win32.WannaCry`

### 2. Analysis Workflow

1. Always save analysis to file for review
2. Verify auto-classification is accurate
3. Adjust metadata before generating signatures
4. Test signatures against clean files

### 3. Signature Quality

- Use multiple signature types for defense-in-depth
- Prefer behavioral YARA rules over static hashes
- Include ATT&CK mappings for context
- Document signature purpose and references

### 4. Testing

```bash
# Test ClamAV signatures
clamscan -d signatures/clamav/ testdata/samples/

# Test YARA rules
yara signatures/yara/*.yar testdata/samples/

# Check false positives
yara signatures/yara/*.yar testdata/clean/
```

## Troubleshooting

### No Patterns Found

If pattern extraction fails:
- Sample may be heavily packed/encrypted
- Try analyzing unpacked version
- Use hash-based signatures (HDB/HSB)

### YARA Syntax Errors

Common issues:
- Special characters in strings need escaping
- Rule names must be alphanumeric + underscore
- Use `--author` flag to set proper metadata

### Low Quality Signatures

Improve signature quality:
- Increase `--min-string` length
- Analyze multiple samples from same family
- Manually review and refine generated rules
- Combine multiple pattern types

## Advanced Usage

### Custom String Extraction

```bash
# Focus on longer, more unique strings
defkit analyze malware.exe --min-string 12 -o analysis/

# Skip patterns to reduce processing time
defkit analyze large_file.bin --no-patterns -o analysis/
```

### Targeted Signature Generation

```bash
# Generate only NDB patterns (hex signatures)
defkit generate malware.exe \
  --format clamav \
  --clamav-type ndb \
  --name Targeted.Detection

# Generate PE-specific YARA rule
# (automatically done for PE files)
defkit generate pe_file.exe --format yara --name PE_Specific
```

## Reference

### File Type Support

- **PE**: Windows executables (EXE, DLL, SYS)
- **ELF**: Linux executables
- **Mach-O**: macOS executables
- **Scripts**: Shell scripts, Python, etc.
- **Documents**: Limited support (use darkscand document scanner)

### Output Directory Structure

```
signatures/
├── clamav/
│   ├── custom.hdb      # MD5 hashes
│   ├── custom.hsb      # SHA256 hashes
│   ├── custom.ndb      # Hex patterns
│   ├── custom.ldb      # Logical signatures
│   └── database.info   # Metadata
├── yara/
│   └── ThreatName.yar  # YARA rule
└── capa/
    ├── ThreatName.json # JSON format
    └── ThreatName.yml  # YAML format
```

## See Also

- [darkscand Documentation](../../README.md)
- [ClamAV Signature Format](https://docs.clamav.net/manual/Signatures.html)
- [YARA Documentation](https://yara.readthedocs.io/)
- [CAPA Rules](https://github.com/mandiant/capa-rules)
- [MITRE ATT&CK](https://attack.mitre.org/)
