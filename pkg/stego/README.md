# Steganography Detection Engine

Advanced steganography detection for images using multiple analysis techniques.

## Features

### 1. **LSB (Least Significant Bit) Analysis**
- Analyzes LSB planes of RGB/RGBA channels
- Calculates entropy for each color channel's LSB
- Detects suspicious patterns indicating embedded data
- Natural images typically have LSB entropy < 0.7
- Embedded data typically shows LSB entropy > 0.95

### 2. **Statistical Analysis**
- **Chi-Square Test**: Detects non-random data distribution
- **Histogram Analysis**: Identifies unnaturally flat histograms (indicates embedding)
- **Entropy Scoring**: Measures overall randomness of pixel values
- Provides p-values for statistical significance

### 3. **Tool Signature Detection**
Detects known steganography tools:
- **Steghide**: JPEG/BMP embedding with password protection
- **OutGuess**: DCT coefficient modification in JPEG
- **F5**: Matrix encoding in JPEG
- **OpenStego**: PNG tEXt chunk embedding
- **JSteg**: JPEG DCT LSB embedding
- **Generic LSB**: Detects generic LSB-based tools

### 4. **Visual Attack Analysis**
- Amplifies LSB plane to make hidden data visible
- Creates enhanced image where embedded data appears
- Useful for manual verification

### 5. **Data Extraction**
- Extracts LSB data from images
- Auto-detects text content
- Saves binary data for analysis

## Usage

### Command Line Tool

```bash
# Scan single image
darkscan-stego scan image.jpg

# Scan directory
darkscan-stego scan ./images/ -r --verbose

# Extract LSB data
darkscan-stego extract hidden.png -o ./output/

# Generate visual attack image
darkscan-stego visual suspect.jpg enhanced.png
```

### Programmatic Usage

```go
import "github.com/afterdarksys/darkscan/pkg/stego"

// Create analyzer
analyzer := stego.NewAnalyzer()

// Analyze image
analysis, err := analyzer.AnalyzeFile("image.jpg")
if err != nil {
    log.Fatal(err)
}

// Check results
if analysis.Suspicious {
    fmt.Printf("Steganography detected! Confidence: %d%%\n", analysis.Confidence)

    for _, indicator := range analysis.Indicators {
        fmt.Printf("  - %s: %s\n", indicator.Type, indicator.Description)
    }

    // Check detected tools
    for _, sig := range analysis.Signatures {
        fmt.Printf("  Tool: %s (confidence: %d%%)\n", sig.Tool, sig.Confidence)
    }
}

// Extract LSB data
img, _ := loadImage("image.jpg")
data := stego.ExtractLSB(img)
os.WriteFile("extracted.bin", data, 0644)

// Visual attack
enhanced := stego.VisualAttack(img)
saveImage("visual.png", enhanced)
```

## Detection Techniques

### LSB Detection
Analyzes the least significant bit plane of each color channel. Natural images show low entropy in LSB plane (~0.5-0.7) due to correlation between adjacent pixels. Steganography using LSB replacement increases entropy to near-maximum (~0.95-1.0).

**Indicators:**
- Average LSB entropy > 0.9 (suspicious)
- Average LSB entropy > 0.95 (highly suspicious)
- LSB change ratio > 0.48 (random LSB changes)

### Chi-Square Test
Tests the hypothesis that pixel values follow a uniform distribution. Steganography often creates non-random patterns detectable via chi-square test.

**Indicators:**
- p-value < 0.05 (statistically significant non-random distribution)
- Lower p-values indicate higher confidence

### Histogram Flatness
Natural images have varied histograms with peaks and valleys. Embedded data tends to flatten the histogram as it increases randomness.

**Indicators:**
- Coefficient of variation < 0.3 (suspiciously flat)
- Very low standard deviation relative to mean

### Tool Signatures

#### Steghide
- Checks JPEG comment markers
- Looks for high-entropy regions
- Detects password-protected embedding patterns

#### OutGuess
- Analyzes JPEG DCT coefficient distribution
- Checks for Start of Scan markers
- Detects unusual coefficient patterns

#### F5
- Examines JPEG quantization tables
- Checks for matrix encoding patterns
- Analyzes DQT (Define Quantization Table) markers

#### OpenStego
- Looks for PNG tEXt chunks
- Checks for "OpenStego" markers
- Counts tEXt chunk frequency

#### JSteg
- Analyzes JPEG structure
- Checks for sequential LSB modifications
- Detects unusual byte distributions

#### Generic LSB
- Checks for ~50% LSB alternation pattern
- Analyzes bit patterns in file header
- Detects LSB modification signatures

## Confidence Scoring

The engine calculates confidence scores (0-100) based on:

1. **LSB Entropy**: Higher entropy = higher confidence
2. **Statistical Tests**: Lower p-values = higher confidence
3. **Multiple Indicators**: Multiple indicators boost confidence
4. **Tool Signatures**: Detected signatures = high confidence

**Scoring Formula:**
- Base: Average of all indicator confidences
- Multiplier: 1 + (num_indicators - 1) * 0.1
- Cap at 100

**Thresholds:**
- 0-40: Likely clean
- 40-60: Low suspicion
- 60-80: Medium suspicion
- 80-100: High suspicion

## Output Analysis

### Analysis Structure
```go
type Analysis struct {
    FilePath         string        // Path to analyzed file
    Format           string        // Image format (jpeg, png, etc.)
    Dimensions       image.Point   // Width x Height
    Suspicious       bool          // True if confidence >= threshold
    Confidence       int           // 0-100 confidence score
    Indicators       []Indicator   // List of suspicious indicators
    LSBAnalysis      *LSBAnalysis  // Detailed LSB analysis
    StatisticalTests *StatisticalTests // Statistical test results
    Signatures       []Signature   // Detected tool signatures
}
```

### Indicators
Each indicator includes:
- **Type**: lsb, entropy, chi-square, signature
- **Description**: Human-readable explanation
- **Severity**: low, medium, high
- **Confidence**: 0-100 for this specific indicator
- **Details**: Additional technical information

## Examples

### Example 1: Clean Image
```
✓ Clean (Confidence: 15%)
Format: jpeg, Size: 1920x1080

LSB Analysis:
  Red entropy:   0.6234
  Green entropy: 0.5891
  Blue entropy:  0.6102
  LSB ratio:     0.4123
  Status: ✓ Normal
```

### Example 2: Suspicious Image (LSB Embedding)
```
🚨 SUSPICIOUS (Confidence: 87%)
Format: png, Size: 800x600

Indicators:
  🔴 [LSB] Suspicious LSB pattern detected (Confidence: 92%)
    - red_entropy: 0.9823
    - green_entropy: 0.9891
    - blue_entropy: 0.9856
    - lsb_ratio: 0.4921

  🟡 [CHI-SQUARE] Chi-square test indicates non-random data (Confidence: 75%)
    - chi_square: 245.32
    - p_value: 0.0234

LSB Analysis:
  Red entropy:   0.9823
  Green entropy: 0.9891
  Blue entropy:  0.9856
  LSB ratio:     0.4921
  Status: ⚠️  SUSPICIOUS
```

### Example 3: Detected Tool (Steghide)
```
🚨 SUSPICIOUS (Confidence: 95%)
Format: jpeg, Size: 2048x1536

Indicators:
  🔴 [SIGNATURE] Detected Steghide signature (Confidence: 75%)
    - tool: Steghide
    - version: unknown

  🔴 [LSB] Suspicious LSB pattern detected (Confidence: 88%)

Detected Tools:
  🔍 Steghide (Confidence: 75%)
     Possible Steghide embedded data in JPEG
```

## Integration with darkscand

The steganography detection can be integrated into darkscand:

```go
import "github.com/afterdarksys/darkscan/pkg/stego"

// In scanner
func scanFile(path string) {
    // ... existing malware scanning ...

    // Add stego detection for images
    if isImage(path) {
        analyzer := stego.NewAnalyzer()
        analysis, err := analyzer.AnalyzeFile(path)

        if err == nil && analysis.Suspicious {
            reportSteganography(path, analysis)
        }
    }
}
```

## Performance

- **LSB Analysis**: O(width × height × channels) - Fast
- **Statistical Tests**: O(width × height) - Fast
- **Signature Detection**: O(file_size) - Fast
- **Visual Attack**: O(width × height) - Moderate

Typical performance:
- 1920x1080 JPEG: ~50-100ms
- 4K image: ~200-400ms
- Directory of 100 images: ~5-10 seconds

## Limitations

1. **False Positives**: High-quality compressed images may trigger LSB alerts
2. **Encrypted Payloads**: Cannot detect content of encrypted embedded data
3. **Advanced Techniques**: Some sophisticated methods may evade detection
4. **File Formats**: Currently supports JPEG, PNG, GIF, BMP (no TIFF/WebP yet)

## Future Enhancements

- [ ] Support for TIFF, WebP, HEIC formats
- [ ] Machine learning-based detection
- [ ] Audio steganography detection (WAV, MP3)
- [ ] Video steganography detection
- [ ] Automated payload decryption (with passwords)
- [ ] Integration with VirusTotal/YARA for payload analysis
- [ ] Real-time monitoring mode
- [ ] Batch processing with parallel scanning

## References

- **Digital Steganography** by Gary C. Kessler
- **Information Hiding Techniques for Steganography** - Fabien A.P. Petitcolas
- **Detecting LSB Steganography** - Andreas Westfeld & Andreas Pfitzmann
- **F5 Algorithm** - Andreas Westfeld
- **OutGuess** - Niels Provos
- **Chi-Square Attack** - Andreas Westfeld & Andreas Pfitzmann
