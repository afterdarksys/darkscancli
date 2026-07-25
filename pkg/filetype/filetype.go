package filetype

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// FileType represents an identified file type
type FileType struct {
	Extension   string // Primary extension (e.g., "exe", "pdf")
	MIMEType    string // MIME type (e.g., "application/pdf")
	Description string // Human-readable description
	Category    string // Category: executable, document, image, archive, etc.
	Confidence  int    // Confidence level (0-100)
	IsSpoofed   bool   // True if extension doesn't match actual type
	ActualType  string // Actual detected type if spoofed
	DeclaredExt string // File extension from filename
}

// MagicSignature represents a file type signature
type MagicSignature struct {
	Magic       []byte
	Offset      int64
	Extension   string
	MIMEType    string
	Description string
	Category    string
	Mask        []byte // Optional mask for flexible matching
}

// Common file type signatures organized by category
var signatures = []MagicSignature{
	// Executables
	{[]byte{0x4D, 0x5A}, 0, "exe", "application/x-msdownload", "Windows PE Executable", "executable", nil},
	{[]byte{0x7F, 0x45, 0x4C, 0x46}, 0, "elf", "application/x-elf", "Linux ELF Executable", "executable", nil},
	{[]byte{0xCF, 0xFA, 0xED, 0xFE}, 0, "macho", "application/x-mach-binary", "Mach-O Executable (32-bit)", "executable", nil},
	{[]byte{0xFE, 0xED, 0xFA, 0xCE}, 0, "macho", "application/x-mach-binary", "Mach-O Executable (32-bit reverse)", "executable", nil},
	{[]byte{0xCF, 0xFA, 0xED, 0xFE}, 0, "macho", "application/x-mach-binary", "Mach-O Executable (64-bit)", "executable", nil},
	{[]byte{0xCA, 0xFE, 0xBA, 0xBE}, 0, "macho", "application/x-mach-binary", "Mach-O Universal Binary", "executable", nil},

	// Archives
	{[]byte{0x50, 0x4B, 0x03, 0x04}, 0, "zip", "application/zip", "ZIP Archive", "archive", nil},
	{[]byte{0x50, 0x4B, 0x05, 0x06}, 0, "zip", "application/zip", "ZIP Archive (empty)", "archive", nil},
	{[]byte{0x50, 0x4B, 0x07, 0x08}, 0, "zip", "application/zip", "ZIP Archive (spanned)", "archive", nil},
	{[]byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07}, 0, "rar", "application/x-rar-compressed", "RAR Archive", "archive", nil},
	{[]byte{0x1F, 0x8B, 0x08}, 0, "gz", "application/gzip", "GZIP Compressed", "archive", nil},
	{[]byte{0x42, 0x5A, 0x68}, 0, "bz2", "application/x-bzip2", "BZIP2 Compressed", "archive", nil},
	{[]byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, 0, "7z", "application/x-7z-compressed", "7-Zip Archive", "archive", nil},
	{[]byte("ustar"), 257, "tar", "application/x-tar", "TAR Archive", "archive", nil},

	// Documents
	{[]byte{0x25, 0x50, 0x44, 0x46}, 0, "pdf", "application/pdf", "PDF Document", "document", nil},
	{[]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, 0, "doc", "application/msword", "Microsoft Office Document (Legacy)", "document", nil},
	{[]byte{0x50, 0x4B, 0x03, 0x04}, 0, "docx", "application/vnd.openxmlformats-officedocument", "Office Open XML Document", "document", nil},
	{[]byte{0x7B, 0x5C, 0x72, 0x74, 0x66}, 0, "rtf", "application/rtf", "Rich Text Format", "document", nil},

	// Images
	{[]byte{0xFF, 0xD8, 0xFF}, 0, "jpg", "image/jpeg", "JPEG Image", "image", nil},
	{[]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, 0, "png", "image/png", "PNG Image", "image", nil},
	{[]byte("GIF87a"), 0, "gif", "image/gif", "GIF Image (87a)", "image", nil},
	{[]byte("GIF89a"), 0, "gif", "image/gif", "GIF Image (89a)", "image", nil},
	{[]byte("BM"), 0, "bmp", "image/bmp", "Bitmap Image", "image", nil},
	{[]byte{0x49, 0x49, 0x2A, 0x00}, 0, "tiff", "image/tiff", "TIFF Image (Little Endian)", "image", nil},
	{[]byte{0x4D, 0x4D, 0x00, 0x2A}, 0, "tiff", "image/tiff", "TIFF Image (Big Endian)", "image", nil},
	{[]byte("WEBP"), 8, "webp", "image/webp", "WebP Image", "image", nil},
	{[]byte{0x00, 0x00, 0x01, 0x00}, 0, "ico", "image/x-icon", "Windows Icon", "image", nil},

	// Video/Audio
	{[]byte("ftyp"), 4, "mp4", "video/mp4", "MP4 Video", "video", nil},
	{[]byte("RIFF"), 0, "avi", "video/x-msvideo", "AVI Video", "video", nil},
	{[]byte{0x1A, 0x45, 0xDF, 0xA3}, 0, "mkv", "video/x-matroska", "Matroska Video", "video", nil},
	{[]byte("ID3"), 0, "mp3", "audio/mpeg", "MP3 Audio", "audio", nil},
	{[]byte{0xFF, 0xFB}, 0, "mp3", "audio/mpeg", "MP3 Audio (no ID3)", "audio", nil},
	{[]byte("OggS"), 0, "ogg", "audio/ogg", "OGG Audio", "audio", nil},
	{[]byte("fLaC"), 0, "flac", "audio/flac", "FLAC Audio", "audio", nil},
	{[]byte("RIFF"), 0, "wav", "audio/wav", "WAV Audio", "audio", nil},

	// Scripts
	{[]byte("#!/bin/bash"), 0, "sh", "application/x-sh", "Bash Script", "script", nil},
	{[]byte("#!/bin/sh"), 0, "sh", "application/x-sh", "Shell Script", "script", nil},
	{[]byte("#!/usr/bin/python"), 0, "py", "text/x-python", "Python Script", "script", nil},
	{[]byte("#!/usr/bin/env python"), 0, "py", "text/x-python", "Python Script", "script", nil},
	{[]byte("#!/usr/bin/perl"), 0, "pl", "text/x-perl", "Perl Script", "script", nil},
	{[]byte("#!/usr/bin/ruby"), 0, "rb", "text/x-ruby", "Ruby Script", "script", nil},

	// Java
	{[]byte{0xCA, 0xFE, 0xBA, 0xBE}, 0, "class", "application/java-vm", "Java Class File", "executable", nil},
	{[]byte{0x50, 0x4B, 0x03, 0x04}, 0, "jar", "application/java-archive", "Java Archive", "archive", nil},

	// Android
	{[]byte{0x50, 0x4B, 0x03, 0x04}, 0, "apk", "application/vnd.android.package-archive", "Android Package", "executable", nil},
	{[]byte("dex\n"), 0, "dex", "application/octet-stream", "Dalvik Executable", "executable", nil},

	// Web
	{[]byte("<!DOCTYPE html"), 0, "html", "text/html", "HTML Document", "web", nil},
	{[]byte("<html"), 0, "html", "text/html", "HTML Document", "web", nil},
	{[]byte("<?xml"), 0, "xml", "application/xml", "XML Document", "web", nil},

	// Databases
	{[]byte("SQLite format 3"), 0, "sqlite", "application/x-sqlite3", "SQLite Database", "database", nil},

	// Other
	{[]byte{0x1F, 0x9D}, 0, "z", "application/x-compress", "Compressed (compress)", "archive", nil},
	{[]byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, 0, "xz", "application/x-xz", "XZ Compressed", "archive", nil},
}

// Detector performs file type identification
type Detector struct {
	buffer []byte
}

// NewDetector creates a new file type detector
func NewDetector() *Detector {
	return &Detector{}
}

// IdentifyFile identifies a file's type from its path
func (d *Detector) IdentifyFile(path string) (*FileType, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Read first 8KB for magic byte detection
	d.buffer = make([]byte, 8192)
	n, err := f.Read(d.buffer)
	if err != nil && err != io.EOF {
		return nil, err
	}
	d.buffer = d.buffer[:n]

	// Get declared extension from filename
	declaredExt := strings.ToLower(strings.TrimPrefix(filepath.Ext(path), "."))

	// Detect actual file type
	result := d.detectType()
	result.DeclaredExt = declaredExt

	// Check for extension spoofing
	if declaredExt != "" && result.Extension != "" {
		if !d.isCompatibleExtension(declaredExt, result.Extension, result.Category) {
			result.IsSpoofed = true
			result.ActualType = result.Extension
			result.Confidence = 95 // High confidence in spoofing detection
		}
	}

	return result, nil
}

// detectType analyzes the buffer to determine file type
func (d *Detector) detectType() *FileType {
	// Try each signature
	for _, sig := range signatures {
		if d.matchesSignature(sig) {
			return &FileType{
				Extension:   sig.Extension,
				MIMEType:    sig.MIMEType,
				Description: sig.Description,
				Category:    sig.Category,
				Confidence:  90,
			}
		}
	}

	// Try text detection as fallback
	if d.isLikelyText() {
		return &FileType{
			Extension:   "txt",
			MIMEType:    "text/plain",
			Description: "Text File",
			Category:    "text",
			Confidence:  60,
		}
	}

	// Unknown type
	return &FileType{
		Extension:   "unknown",
		MIMEType:    "application/octet-stream",
		Description: "Unknown Binary",
		Category:    "unknown",
		Confidence:  30,
	}
}

// matchesSignature checks if buffer matches a signature
func (d *Detector) matchesSignature(sig MagicSignature) bool {
	if int64(len(d.buffer)) < sig.Offset+int64(len(sig.Magic)) {
		return false
	}

	start := sig.Offset
	end := start + int64(len(sig.Magic))

	if sig.Mask != nil {
		// Apply mask if present
		for i := 0; i < len(sig.Magic); i++ {
			if (d.buffer[start+int64(i)] & sig.Mask[i]) != sig.Magic[i] {
				return false
			}
		}
		return true
	}

	return bytes.Equal(d.buffer[start:end], sig.Magic)
}

// isLikelyText checks if content is likely text
func (d *Detector) isLikelyText() bool {
	if len(d.buffer) == 0 {
		return false
	}

	// Count printable characters
	printable := 0
	for _, b := range d.buffer {
		if (b >= 0x20 && b <= 0x7E) || b == 0x09 || b == 0x0A || b == 0x0D {
			printable++
		}
	}

	// If > 95% printable, likely text
	return float64(printable)/float64(len(d.buffer)) > 0.95
}

// isCompatibleExtension checks if declared extension is compatible with detected type
func (d *Detector) isCompatibleExtension(declared, actual, category string) bool {
	// Exact match
	if declared == actual {
		return true
	}

	// Known compatible extensions
	compatible := map[string][]string{
		"zip":  {"zip", "jar", "apk", "docx", "xlsx", "pptx", "odt", "ods"},
		"jpg":  {"jpg", "jpeg", "jpe", "jfif"},
		"tiff": {"tiff", "tif"},
		"mpeg": {"mpeg", "mpg", "mp3"},
		"html": {"html", "htm"},
		"sh":   {"sh", "bash"},
	}

	// Check if they're in the same compatible group
	for _, group := range compatible {
		foundDeclared := false
		foundActual := false
		for _, ext := range group {
			if ext == declared {
				foundDeclared = true
			}
			if ext == actual {
				foundActual = true
			}
		}
		if foundDeclared && foundActual {
			return true
		}
	}

	// If categories match and both are generic, allow it
	if category == "text" || category == "unknown" {
		return true
	}

	return false
}

// IdentifyBuffer identifies a file type from a byte buffer
func (d *Detector) IdentifyBuffer(data []byte) *FileType {
	d.buffer = data
	if len(d.buffer) > 8192 {
		d.buffer = d.buffer[:8192]
	}
	return d.detectType()
}

// IsDangerous returns true if the file type is potentially dangerous
func (ft *FileType) IsDangerous() bool {
	dangerous := []string{"executable", "script"}
	for _, cat := range dangerous {
		if ft.Category == cat {
			return true
		}
	}
	return false
}

// GetRiskLevel returns a risk assessment
func (ft *FileType) GetRiskLevel() string {
	if ft.IsSpoofed && ft.IsDangerous() {
		return "CRITICAL" // Executable disguised as something else
	}
	if ft.IsSpoofed {
		return "HIGH" // File type mismatch
	}
	if ft.IsDangerous() {
		return "MEDIUM" // Executable or script
	}
	return "LOW"
}

// Helper function to read specific bytes for complex detection
func readBytesAt(f *os.File, offset int64, length int) ([]byte, error) {
	buf := make([]byte, length)
	_, err := f.ReadAt(buf, offset)
	return buf, err
}

// DetectOfficeDocument tries to identify specific Office document types
func DetectOfficeDocument(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "unknown"
	}
	defer f.Close()

	// Check if it's a ZIP (Office 2007+)
	header := make([]byte, 4)
	f.Read(header)
	if bytes.Equal(header, []byte{0x50, 0x4B, 0x03, 0x04}) {
		// It's a ZIP-based Office file, could be docx, xlsx, pptx
		// Would need to read internal structure to determine exactly
		return "office-xml"
	}

	// Check if it's OLE (Office 97-2003)
	f.Seek(0, 0)
	header = make([]byte, 8)
	f.Read(header)
	if bytes.Equal(header, []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}) {
		return "office-ole"
	}

	return "unknown"
}
