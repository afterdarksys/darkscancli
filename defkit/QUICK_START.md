# defkit Quick Start Guide

## Installation

```bash
cd defkit
go build -o bin/defkit ./cmd/defkit
```

## Basic Usage

### 1. Analyze a Sample

```bash
# Analyze EICAR test file
./bin/defkit analyze testdata/samples/EICAR.txt

# Save analysis to file
./bin/defkit analyze malware.exe -o analysis/
```

### 2. Generate Signatures

```bash
# Generate all signature types
./bin/defkit generate --name Trojan.Generic malware.exe

# Generate only YARA rules
./bin/defkit generate --format yara --name MyRule malware.exe

# Generate with metadata
./bin/defkit generate \
  --name Ransomware.WannaCry \
  --family ransomware \
  --severity high \
  --description "WannaCry ransomware detection" \
  malware.exe
```

### 3. EICAR Test Example

```bash
# Analyze EICAR
./bin/defkit analyze testdata/samples/EICAR.txt

# Generate signatures
./bin/defkit generate --name EICAR-AV-Test testdata/samples/EICAR.txt

# View generated ClamAV signature
cat signatures/clamav/custom.hdb
# Output: 44d88612fea8a8f36de82e1278abb02f:68:EICAR-AV-Test

# View generated YARA rule
cat signatures/yara/EICAR-AV-Test.yar
```

## Output Formats

### ClamAV Signatures

Generated files in `signatures/clamav/`:
- `custom.hdb` - MD5 hash signatures
- `custom.hsb` - SHA256 hash signatures
- `custom.ndb` - Extended hex pattern signatures
- `custom.ldb` - Logical signatures (when applicable)

### YARA Rules

Generated in `signatures/yara/`:
- Complete YARA rules with metadata, strings, and conditions
- Includes hash values, author, date, severity
- Auto-generated string and hex patterns

### CAPA Rules

Generated in `signatures/capa/`:
- JSON format for programmatic use
- YAML format for human editing
- ATT&CK technique mapping
- Behavioral capability features

## Integration with darkscand

### Add Custom Signatures

```bash
# Generate signatures
./bin/defkit generate --name CustomThreat malware.exe

# Copy to darkscand database
sudo cp signatures/clamav/*.hdb /var/lib/clamav/
sudo cp signatures/yara/*.yar /etc/darkscand/yara-rules/

# Reload darkscand (if running as daemon)
curl -X POST http://localhost:8080/api/v1/reload
```

### Batch Processing

```bash
# Analyze multiple samples
for file in samples/*.exe; do
    ./bin/defkit analyze "$file" -o analysis/
done

# Generate signatures for all
for analysis in analysis/*.json; do
    name=$(basename "$analysis" .json)
    ./bin/defkit generate "$analysis" --name "Detected_${name}"
done
```

## Common Options

### Analysis Options

```
-o, --output <dir>     Output directory for analysis
--min-string <n>       Minimum string length (default: 4)
--no-strings           Skip string extraction
--no-patterns          Skip pattern extraction
```

### Generation Options

```
-n, --name <name>      Threat name (REQUIRED)
-o, --output <dir>     Output directory
-f, --format <type>    all, clamav, yara, capa (default: all)
--clamav-type <type>   all, hdb, ndb, ldb (default: all)
--author <name>        Author name
--family <name>        Malware family
--severity <level>     low, medium, high
-d, --description      Threat description
```

## Next Steps

- Read [USAGE.md](docs/USAGE.md) for detailed documentation
- Add your own samples to `testdata/samples/`
- Customize signature generation logic
- Integrate with your scanning infrastructure
- Deploy to darkscand custom mirror

## Troubleshooting

**No patterns found:**
- Sample may be packed/encrypted
- Try hash-based signatures: `--clamav-type hdb`

**YARA syntax errors:**
- Check special characters in strings
- Rule names must be alphanumeric + underscore

**Low quality signatures:**
- Increase `--min-string` length
- Analyze multiple samples from same family
- Manually refine generated rules

## Example Workflow

```bash
# 1. Analyze a malware sample
./bin/defkit analyze trojan.exe -o analysis/

# 2. Review the analysis
cat analysis/trojan.exe.json | jq

# 3. Generate signatures with metadata
./bin/defkit generate analysis/trojan.exe.json \
  --name Trojan.Win32.Agent \
  --family trojan \
  --severity high \
  --description "Generic trojan agent"

# 4. Test ClamAV signature
clamscan -d signatures/clamav/ testdata/samples/

# 5. Test YARA rule
yara signatures/yara/*.yar testdata/samples/

# 6. Deploy to darkscand
sudo cp signatures/clamav/*.hdb /var/lib/clamav/
sudo systemctl reload darkscand
```

## Resources

- Main README: [README.md](README.md)
- Detailed usage: [docs/USAGE.md](docs/USAGE.md)
- ClamAV signatures: https://docs.clamav.net/manual/Signatures.html
- YARA documentation: https://yara.readthedocs.io/
- CAPA rules: https://github.com/mandiant/capa-rules
