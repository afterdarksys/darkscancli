package carving

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"io"
	"math"
	"sync"
)

// CarvedFile represents a file carved from disk
type CarvedFile struct {
	Offset      int64         // Offset where file was found
	Size        int64         // Size of carved file
	Type        string        // File type name
	Extension   string        // File extension
	MIMEType    string        // MIME type
	Category    string        // File category
	Signature   FileSignature // Matched signature
	Data        []byte        // File data
	IsComplete  bool          // Whether file has valid footer
	IsFragmented bool         // Whether file appears fragmented
	Confidence  int           // Confidence score (0-100)
	ValidationErrors []string  // Validation issues found
	MD5    string
	SHA256 string
}

// ProgressFunc is called periodically during carving with current progress.
type ProgressFunc func(offset, total int64, filesFound int)

// Carver performs file carving operations
type Carver struct {
	signatures    []FileSignature
	blockSize     int64
	maxFileSize   int64
	minConfidence int
	validateFiles bool
	mu            sync.RWMutex
	Progress      ProgressFunc
}

// Options for carver configuration
type Options struct {
	BlockSize     int64 // Block size for reading (default: 4096)
	MaxFileSize   int64 // Maximum file size to carve (default: 100MB)
	MinConfidence int   // Minimum confidence to report (default: 50)
	ValidateFiles bool  // Whether to validate carved files (default: true)
	Signatures    []FileSignature // Custom signatures (default: all)
	Progress      ProgressFunc
}

// NewCarver creates a new file carver
func NewCarver(opts Options) *Carver {
	if opts.BlockSize == 0 {
		opts.BlockSize = 4096
	}
	if opts.MaxFileSize == 0 {
		opts.MaxFileSize = 100 * 1024 * 1024 // 100MB
	}
	if opts.MinConfidence == 0 {
		opts.MinConfidence = 50
	}

	sigs := opts.Signatures
	if sigs == nil {
		sigs = Signatures
	}

	return &Carver{
		signatures:    sigs,
		blockSize:     opts.BlockSize,
		maxFileSize:   opts.MaxFileSize,
		minConfidence: opts.MinConfidence,
		validateFiles: opts.ValidateFiles,
		Progress:      opts.Progress,
	}
}

// CarveReader carves files from a reader starting at a given offset
func (c *Carver) CarveReader(ctx context.Context, r io.ReaderAt, startOffset, length int64) ([]*CarvedFile, error) {
	var carved []*CarvedFile
	var mu sync.Mutex

	// Read in blocks
	buffer := make([]byte, c.blockSize*2) // Double buffer for overlapping reads
	offset := startOffset
	endOffset := startOffset + length

	for offset < endOffset {
		select {
		case <-ctx.Done():
			return carved, ctx.Err()
		default:
		}

		// Read block
		n, err := r.ReadAt(buffer, offset)
		if err != nil && err != io.EOF {
			return carved, fmt.Errorf("read error at offset %d: %w", offset, err)
		}
		if n == 0 {
			break
		}

		// Search for signatures in this block
		for _, sig := range c.signatures {
			matches := c.findSignatureMatches(buffer[:n], sig, offset)

			for _, matchOffset := range matches {
				// Try to carve file starting at this offset
				file, err := c.carveFile(ctx, r, matchOffset, sig, endOffset)
				if err != nil {
					continue // Skip if carving failed
				}

				if file != nil && file.Confidence >= c.minConfidence {
					mu.Lock()
					carved = append(carved, file)
					mu.Unlock()
				}
			}
		}

		// Move to next block with overlap to catch signatures spanning blocks
		offset += c.blockSize

		if c.Progress != nil {
			mu.Lock()
			filesFound := len(carved)
			mu.Unlock()
			c.Progress(offset-startOffset, length, filesFound)
		}
	}

	return carved, nil
}

// findSignatureMatches finds all occurrences of a signature in buffer
func (c *Carver) findSignatureMatches(buffer []byte, sig FileSignature, baseOffset int64) []int64 {
	var matches []int64

	headerLen := len(sig.Header)
	if headerLen == 0 {
		return matches
	}

	for i := 0; i <= len(buffer)-headerLen; i++ {
		if c.matchesSignature(buffer[i:i+headerLen], sig.Header, sig.HeaderMask) {
			matches = append(matches, baseOffset+int64(i))
		}
	}

	return matches
}

// matchesSignature checks if data matches signature with optional mask
func (c *Carver) matchesSignature(data, signature, mask []byte) bool {
	if len(data) < len(signature) {
		return false
	}

	if mask != nil && len(mask) == len(signature) {
		// Apply mask
		for i := 0; i < len(signature); i++ {
			if (data[i] & mask[i]) != signature[i] {
				return false
			}
		}
		return true
	}

	return bytes.Equal(data[:len(signature)], signature)
}

// carveFile attempts to carve a complete file starting at offset
func (c *Carver) carveFile(ctx context.Context, r io.ReaderAt, offset int64, sig FileSignature, maxOffset int64) (*CarvedFile, error) {
	file := &CarvedFile{
		Offset:     offset,
		Type:       sig.Name,
		Extension:  sig.Extension,
		MIMEType:   sig.MIMEType,
		Category:   sig.Category,
		Signature:  sig,
		Confidence: 50, // Base confidence
	}

	// Determine maximum size to read
	maxSize := sig.MaxSize
	if maxSize == 0 || maxSize > c.maxFileSize {
		maxSize = c.maxFileSize
	}

	// Don't read past end of available data
	if offset+maxSize > maxOffset {
		maxSize = maxOffset - offset
	}

	// Allocate buffer
	buffer := make([]byte, maxSize)

	// Read data
	n, err := r.ReadAt(buffer, offset)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("read error: %w", err)
	}

	buffer = buffer[:n]

	// If signature has footer, find it
	if sig.HasFooter && len(sig.Footer) > 0 {
		footerIdx := c.findFooter(buffer, sig.Footer, sig.FooterMask)
		if footerIdx > 0 {
			// Found footer - carve complete file
			file.Size = int64(footerIdx + len(sig.Footer))
			file.Data = buffer[:file.Size]
			file.IsComplete = true
			file.Confidence += 30 // Bonus for complete file
		} else {
			// No footer found - carve up to max size
			file.Size = int64(len(buffer))
			file.Data = buffer
			file.IsComplete = false
			file.Confidence -= 20 // Penalty for incomplete
		}
	} else {
		// No footer defined - use heuristics or max size
		estimatedSize := c.estimateFileSize(buffer, sig)
		if estimatedSize > 0 && estimatedSize < int64(len(buffer)) {
			file.Size = estimatedSize
			file.Data = buffer[:estimatedSize]
		} else {
			file.Size = int64(len(buffer))
			file.Data = buffer
		}
	}

	// Check minimum size
	if file.Size < sig.MinSize {
		return nil, fmt.Errorf("file too small: %d < %d", file.Size, sig.MinSize)
	}

	// Compute hashes
	md5sum := md5.Sum(file.Data)
	sha256sum := sha256.Sum256(file.Data)
	file.MD5 = fmt.Sprintf("%x", md5sum)
	file.SHA256 = fmt.Sprintf("%x", sha256sum)

	// Validate if enabled
	if c.validateFiles {
		c.validateFile(file)
	}

	// Check for fragmentation indicators
	file.IsFragmented = c.detectFragmentation(file.Data)
	if file.IsFragmented {
		file.Confidence -= 10
	}

	return file, nil
}

// findFooter searches for footer signature in buffer
func (c *Carver) findFooter(buffer, footer, mask []byte) int {
	footerLen := len(footer)
	if footerLen == 0 {
		return -1
	}

	// Search from end backwards for efficiency
	for i := len(buffer) - footerLen; i >= 0; i-- {
		if c.matchesSignature(buffer[i:], footer, mask) {
			return i
		}
	}

	return -1
}

// estimateFileSize attempts to estimate file size using heuristics
func (c *Carver) estimateFileSize(data []byte, sig FileSignature) int64 {
	// Different strategies based on file type
	switch sig.Category {
	case "executable":
		return c.estimateExecutableSize(data, sig)
	case "image":
		return c.estimateImageSize(data, sig)
	case "archive":
		return c.estimateArchiveSize(data, sig)
	case "document":
		return c.estimateDocumentSize(data, sig)
	default:
		// For unknown types, look for long runs of zeros (likely unallocated space)
		return c.findZeroRun(data, 1024) // Stop at 1KB of zeros
	}
}

// estimateExecutableSize estimates size of executable files
func (c *Carver) estimateExecutableSize(data []byte, sig FileSignature) int64 {
	if sig.Extension == "exe" || sig.Extension == "dll" {
		if len(data) < 0x40 {
			return 0
		}
		peOffset := int64(data[0x3C]) | int64(data[0x3D])<<8 | int64(data[0x3E])<<16 | int64(data[0x3F])<<24
		if peOffset+4 > int64(len(data)) {
			return 0
		}
		if data[peOffset] != 'P' || data[peOffset+1] != 'E' {
			return 0
		}
		sizeOffset := peOffset + 0x50
		if sizeOffset+4 > int64(len(data)) {
			return 0
		}
		size := int64(data[sizeOffset]) | int64(data[sizeOffset+1])<<8 | int64(data[sizeOffset+2])<<16 | int64(data[sizeOffset+3])<<24
		if size > 0 {
			return size
		}
	}

	if sig.Extension == "elf" {
		if len(data) < 52 {
			return 0
		}
		elfClass := data[4]
		var shoff, shentsize, shnum int64
		if elfClass == 1 {
			shoff = int64(data[0x20]) | int64(data[0x21])<<8 | int64(data[0x22])<<16 | int64(data[0x23])<<24
			shentsize = int64(data[0x2E]) | int64(data[0x2F])<<8
			shnum = int64(data[0x30]) | int64(data[0x31])<<8
		} else if elfClass == 2 {
			if len(data) < 64 {
				return 0
			}
			shoff = int64(data[0x28]) | int64(data[0x29])<<8 | int64(data[0x2A])<<16 | int64(data[0x2B])<<24
			shentsize = int64(data[0x3A]) | int64(data[0x3B])<<8
			shnum = int64(data[0x3C]) | int64(data[0x3D])<<8
		}
		if shoff > 0 && shentsize > 0 && shnum > 0 {
			return shoff + shentsize*shnum
		}
	}

	return 0
}

// estimateImageSize estimates size of image files
func (c *Carver) estimateImageSize(data []byte, sig FileSignature) int64 {
	// For BMP, size is in header
	if sig.Extension == "bmp" && len(data) >= 18 {
		// BMP file size is at offset 2 (4 bytes, little endian)
		size := int64(data[2]) | int64(data[3])<<8 | int64(data[4])<<16 | int64(data[5])<<24
		return size
	}

	return 0
}

// estimateArchiveSize estimates size of archive files
func (c *Carver) estimateArchiveSize(data []byte, sig FileSignature) int64 {
	// ZIP files have central directory that contains size info
	// This is complex and would require full ZIP parsing
	return 0
}

// estimateDocumentSize estimates size of document files
func (c *Carver) estimateDocumentSize(data []byte, sig FileSignature) int64 {
	// Some documents have size in header
	return 0
}

// findZeroRun finds a run of consecutive zeros
func (c *Carver) findZeroRun(data []byte, minRun int) int64 {
	zeroCount := 0
	for i := 0; i < len(data); i++ {
		if data[i] == 0 {
			zeroCount++
			if zeroCount >= minRun {
				return int64(i - minRun + 1)
			}
		} else {
			zeroCount = 0
		}
	}
	return 0
}

// validateFile performs validation checks on carved file
func (c *Carver) validateFile(file *CarvedFile) {
	if file.Signature.Validator != nil {
		if !file.Signature.Validator(file.Data) {
			file.ValidationErrors = append(file.ValidationErrors, "custom validation failed")
			file.Confidence -= 20
		}
	}

	// Check for header corruption
	if !c.matchesSignature(file.Data, file.Signature.Header, file.Signature.HeaderMask) {
		file.ValidationErrors = append(file.ValidationErrors, "header mismatch")
		file.Confidence -= 30
	}

	// Check entropy (very low or very high entropy may indicate corruption)
	entropy := calculateEntropy(file.Data)
	if entropy < 1.0 {
		file.ValidationErrors = append(file.ValidationErrors, "suspiciously low entropy")
		file.Confidence -= 10
	} else if entropy > 7.9 {
		file.ValidationErrors = append(file.ValidationErrors, "suspiciously high entropy (encrypted/compressed)")
		file.Confidence -= 5
	}

	// Check for excessive null bytes
	nullRatio := float64(countNullBytes(file.Data)) / float64(len(file.Data))
	if nullRatio > 0.5 {
		file.ValidationErrors = append(file.ValidationErrors, "excessive null bytes")
		file.Confidence -= 15
	}
}

// detectFragmentation detects signs of file fragmentation
func (c *Carver) detectFragmentation(data []byte) bool {
	// Look for sudden jumps in content that might indicate fragmentation
	// This is a heuristic - real fragmentation is hard to detect without FS metadata

	// Check for large blocks of zeros in the middle
	blockSize := 512
	for i := blockSize; i < len(data)-blockSize; i += blockSize {
		block := data[i : i+blockSize]
		if isAllZeros(block) {
			return true // Might be fragmented
		}
	}

	return false
}

// calculateEntropy calculates Shannon entropy
func calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	var entropy float64
	length := float64(len(data))

	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

func countNullBytes(data []byte) int {
	count := 0
	for _, b := range data {
		if b == 0 {
			count++
		}
	}
	return count
}

func isAllZeros(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}
