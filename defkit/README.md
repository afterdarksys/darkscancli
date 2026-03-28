# Definition Kit (defkit)

A comprehensive toolkit for creating, testing, and distributing virus definitions for ClamAV, darkscand, and aftersec-server.

## Architecture

```
defkit/
├── cmd/defkit/              # CLI tool
├── pkg/
│   ├── analyzer/            # Sample analysis and feature extraction
│   ├── generator/           # Signature generators
│   │   ├── clamav/         # ClamAV (HDB, NDB, LDB, CVD)
│   │   ├── yara/           # YARA rule generation
│   │   └── capa/           # CAPA capability definitions
│   ├── validator/           # Signature testing and validation
│   └── packager/            # Bundle creation and distribution
├── internal/
│   ├── sample/              # Sample file handling
│   ├── pattern/             # Pattern extraction utilities
│   └── hash/                # Hash computation utilities
├── testdata/
│   ├── samples/             # Malware samples (EICAR, test files)
│   └── clean/               # Clean files for FP testing
└── docs/                    # Documentation
```

## Features

### 1. Sample Analysis
- Hash extraction (MD5, SHA1, SHA256, SSDEEP)
- String extraction (ASCII, Unicode, URLs, IPs, domains)
- Binary pattern extraction with wildcards
- PE/ELF/Mach-O structure analysis
- Entropy calculation
- Import/Export table analysis
- Section characteristics

### 2. Signature Generation

#### ClamAV Formats
- **HDB**: MD5 hash signatures
- **HSB**: SHA1/SHA256 hash signatures
- **NDB**: Extended signatures with hex patterns
- **LDB**: Logical signatures with targeting
- **PDB**: PE section-based signatures
- **CVD**: Packaged database files

#### YARA Rules
- Auto-generated from binary patterns
- String-based rules with conditions
- PE header/section rules
- Import table rules
- Behavioral pattern rules

#### CAPA Definitions
- ATT&CK technique mapping
- MBC (Malware Behavior Catalog) mapping
- Capability-based behavioral rules

### 3. Validation & Testing
- Test signatures against sample corpus
- False positive detection
- Coverage analysis
- Performance benchmarking
- Signature quality scoring

### 4. Packaging & Distribution
- Version-controlled signature bundles
- Metadata generation (threat names, severity, references)
- darkscand custom mirror compatible packages
- Incremental update support

## Usage

### Analyze a Sample
```bash
defkit analyze malware.exe
defkit analyze --extract-all malware.exe -o analysis/
```

### Generate Signatures
```bash
# Generate all formats
defkit generate malware.exe

# Generate specific format
defkit generate --format clamav malware.exe
defkit generate --format yara malware.exe
defkit generate --format capa malware.exe

# Batch generation
defkit generate --batch samples/ -o signatures/
```

### Test Signatures
```bash
# Test against samples
defkit test signatures/ --samples testdata/samples/

# Check false positives
defkit test signatures/ --clean testdata/clean/

# Full validation
defkit validate signatures/
```

### Package for Distribution
```bash
# Create CVD bundle for ClamAV/darkscand
defkit package --format cvd signatures/ -o darkscand.cvd

# Create YARA bundle
defkit package --format yara signatures/ -o rules.yar

# Create full bundle
defkit package --all signatures/ -o bundle.tar.gz
```

## Integration with darkscand

The definition kit generates signatures compatible with darkscand's custom mirror infrastructure:

```bash
# Generate and deploy to mirror
defkit package --format cvd signatures/ -o /var/www/clamav/daily.cvd
defkit package --format yara signatures/ -o /var/www/yara/custom-rules.yar
```

## Development Status

- [x] Architecture design
- [ ] Sample analyzer implementation
- [ ] ClamAV signature generator
- [ ] YARA rule generator
- [ ] CAPA definition generator
- [ ] Validation framework
- [ ] Packaging system
- [ ] darkscand integration
- [ ] Documentation and examples

## License

Same license as darkscand parent project.
