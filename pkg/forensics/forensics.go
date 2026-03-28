package forensics

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"

	"github.com/afterdarksys/darkscan/pkg/filetype"
)

type FileFeatures struct {
	MD5     string
	SHA1    string
	SHA256  string
	Size    int64
	Type    string
	Entropy float64

	// File Type Identification
	DetectedType   string // Detected file type from magic bytes
	MIMEType       string // MIME type
	FileCategory   string // Category: executable, document, image, etc.
	IsSpoofed      bool   // True if extension doesn't match content
	ActualType     string // Actual type if spoofed
	DeclaredExt    string // Extension from filename
	TypeConfidence int    // Confidence in type detection (0-100)

	// Structure
	NumSections int
	NumImports  int
	NumExports  int
	ImpHash     string

	// Behaviors
	StringsCount        int
	HasNetworkCalls     bool
	HasInjection        bool
	HasEvasion          bool
	HasPersistence      bool
	HasCrypto           bool
	HasExecutableStack  bool
}

type Analyzer struct {
	LargeFileThreshold int64
}

func NewAnalyzer(largeFileThresholdMB int64) *Analyzer {
	return &Analyzer{
		LargeFileThreshold: largeFileThresholdMB * 1024 * 1024,
	}
}

func (a *Analyzer) Analyze(path string) (*FileFeatures, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	feats := &FileFeatures{
		Size: info.Size(),
	}

	// Perform file type identification
	detector := filetype.NewDetector()
	fileType, err := detector.IdentifyFile(path)
	if err == nil {
		feats.DetectedType = fileType.Extension
		feats.MIMEType = fileType.MIMEType
		feats.FileCategory = fileType.Category
		feats.IsSpoofed = fileType.IsSpoofed
		feats.ActualType = fileType.ActualType
		feats.DeclaredExt = fileType.DeclaredExt
		feats.TypeConfidence = fileType.Confidence
	}

	// Calculate Hashes
	hMd5 := md5.New()
	hSha1 := sha1.New()
	hSha256 := sha256.New()
	mw := io.MultiWriter(hMd5, hSha1, hSha256)

	// Stream max LargeFileThreshold to prevent out of memory
	limit := a.LargeFileThreshold
	if limit == 0 {
		limit = 100 * 1024 * 1024 // 100MB default
	}

	lr := io.LimitReader(f, limit)
	buf, err := io.ReadAll(lr)
	if err != nil && err != io.EOF {
		return nil, err
	}

	mw.Write(buf)
	feats.MD5 = hex.EncodeToString(hMd5.Sum(nil))
	feats.SHA1 = hex.EncodeToString(hSha1.Sum(nil))
	feats.SHA256 = hex.EncodeToString(hSha256.Sum(nil))

	// Get Entropy
	feats.Entropy = CalculateEntropy(buf)

	// Get Strings
	ExtractStrings(buf, feats)

	// Attempt Binary Parses
	_ = AnalyzePE(path, feats)
	_ = AnalyzeELF(path, feats)
	_ = AnalyzeMachO(path, feats)

	return feats, nil
}
