package carving

// FileSignature defines a file type signature for carving
type FileSignature struct {
	Name        string   // File type name (e.g., "JPEG", "PDF")
	Extension   string   // File extension
	MIMEType    string   // MIME type
	Header      []byte   // File header signature
	Footer      []byte   // File footer signature (optional)
	HeaderMask  []byte   // Mask for flexible header matching
	FooterMask  []byte   // Mask for flexible footer matching
	MinSize     int64    // Minimum valid file size
	MaxSize     int64    // Maximum file size to extract
	Category    string   // Category: image, document, video, etc.
	HasFooter   bool     // Whether file has a defined footer
	Validator   func([]byte) bool // Optional validation function
}

// Common file signatures for carving
var Signatures = []FileSignature{
	// Images
	{
		Name:      "JPEG",
		Extension: "jpg",
		MIMEType:  "image/jpeg",
		Header:    []byte{0xFF, 0xD8, 0xFF},
		Footer:    []byte{0xFF, 0xD9},
		MinSize:   100,
		MaxSize:   50 * 1024 * 1024, // 50MB
		Category:  "image",
		HasFooter: true,
	},
	{
		Name:      "PNG",
		Extension: "png",
		MIMEType:  "image/png",
		Header:    []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
		Footer:    []byte{0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82},
		MinSize:   100,
		MaxSize:   50 * 1024 * 1024,
		Category:  "image",
		HasFooter: true,
	},
	{
		Name:      "GIF",
		Extension: "gif",
		MIMEType:  "image/gif",
		Header:    []byte("GIF89a"),
		Footer:    []byte{0x00, 0x3B}, // GIF terminator
		MinSize:   100,
		MaxSize:   50 * 1024 * 1024,
		Category:  "image",
		HasFooter: true,
	},
	{
		Name:      "BMP",
		Extension: "bmp",
		MIMEType:  "image/bmp",
		Header:    []byte("BM"),
		MinSize:   54, // BMP header size
		MaxSize:   100 * 1024 * 1024,
		Category:  "image",
		HasFooter: false,
	},

	// Documents
	{
		Name:      "PDF",
		Extension: "pdf",
		MIMEType:  "application/pdf",
		Header:    []byte("%PDF-"),
		Footer:    []byte("%%EOF"),
		MinSize:   100,
		MaxSize:   100 * 1024 * 1024,
		Category:  "document",
		HasFooter: true,
	},
	{
		Name:      "MS Office (OLE)",
		Extension: "doc",
		MIMEType:  "application/msword",
		Header:    []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1},
		MinSize:   512,
		MaxSize:   100 * 1024 * 1024,
		Category:  "document",
		HasFooter: false,
	},
	{
		Name:      "RTF",
		Extension: "rtf",
		MIMEType:  "application/rtf",
		Header:    []byte("{\\rtf1"),
		Footer:    []byte("}"),
		MinSize:   100,
		MaxSize:   50 * 1024 * 1024,
		Category:  "document",
		HasFooter: true,
	},

	// Archives
	{
		Name:      "ZIP",
		Extension: "zip",
		MIMEType:  "application/zip",
		Header:    []byte{0x50, 0x4B, 0x03, 0x04},
		Footer:    []byte{0x50, 0x4B, 0x05, 0x06}, // End of central directory
		MinSize:   22,
		MaxSize:   1024 * 1024 * 1024, // 1GB
		Category:  "archive",
		HasFooter: true,
	},
	{
		Name:      "RAR",
		Extension: "rar",
		MIMEType:  "application/x-rar-compressed",
		Header:    []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00},
		MinSize:   20,
		MaxSize:   1024 * 1024 * 1024,
		Category:  "archive",
		HasFooter: false,
	},
	{
		Name:      "GZIP",
		Extension: "gz",
		MIMEType:  "application/gzip",
		Header:    []byte{0x1F, 0x8B, 0x08},
		MinSize:   18,
		MaxSize:   1024 * 1024 * 1024,
		Category:  "archive",
		HasFooter: false,
	},
	{
		Name:      "7-Zip",
		Extension: "7z",
		MIMEType:  "application/x-7z-compressed",
		Header:    []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C},
		MinSize:   32,
		MaxSize:   1024 * 1024 * 1024,
		Category:  "archive",
		HasFooter: false,
	},

	// Executables
	{
		Name:      "Windows PE",
		Extension: "exe",
		MIMEType:  "application/x-msdownload",
		Header:    []byte{0x4D, 0x5A}, // MZ header
		MinSize:   512,
		MaxSize:   500 * 1024 * 1024,
		Category:  "executable",
		HasFooter: false,
	},
	{
		Name:      "Linux ELF",
		Extension: "elf",
		MIMEType:  "application/x-elf",
		Header:    []byte{0x7F, 0x45, 0x4C, 0x46},
		MinSize:   52, // ELF header size
		MaxSize:   500 * 1024 * 1024,
		Category:  "executable",
		HasFooter: false,
	},
	{
		Name:      "Mach-O",
		Extension: "macho",
		MIMEType:  "application/x-mach-binary",
		Header:    []byte{0xCF, 0xFA, 0xED, 0xFE},
		MinSize:   4096,
		MaxSize:   500 * 1024 * 1024,
		Category:  "executable",
		HasFooter: false,
	},

	// Video/Audio
	{
		Name:      "MP4",
		Extension: "mp4",
		MIMEType:  "video/mp4",
		Header:    []byte{0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70}, // ftyp box
		MinSize:   1024,
		MaxSize:   10 * 1024 * 1024 * 1024, // 10GB
		Category:  "video",
		HasFooter: false,
	},
	{
		Name:      "AVI",
		Extension: "avi",
		MIMEType:  "video/x-msvideo",
		Header:    []byte("RIFF"),
		MinSize:   1024,
		MaxSize:   10 * 1024 * 1024 * 1024,
		Category:  "video",
		HasFooter: false,
	},
	{
		Name:      "MP3",
		Extension: "mp3",
		MIMEType:  "audio/mpeg",
		Header:    []byte{0xFF, 0xFB}, // MPEG-1 Layer 3
		MinSize:   128,
		MaxSize:   100 * 1024 * 1024,
		Category:  "audio",
		HasFooter: false,
	},
	{
		Name:      "WAV",
		Extension: "wav",
		MIMEType:  "audio/wav",
		Header:    []byte("RIFF"),
		MinSize:   44, // WAV header size
		MaxSize:   1024 * 1024 * 1024,
		Category:  "audio",
		HasFooter: false,
	},
	{
		Name:      "FLAC",
		Extension: "flac",
		MIMEType:  "audio/flac",
		Header:    []byte("fLaC"),
		MinSize:   42,
		MaxSize:   1024 * 1024 * 1024,
		Category:  "audio",
		HasFooter: false,
	},

	// Databases
	{
		Name:      "SQLite",
		Extension: "sqlite",
		MIMEType:  "application/x-sqlite3",
		Header:    []byte("SQLite format 3\x00"),
		MinSize:   100,
		MaxSize:   10 * 1024 * 1024 * 1024,
		Category:  "database",
		HasFooter: false,
	},

	// Email
	{
		Name:      "PST (Outlook)",
		Extension: "pst",
		MIMEType:  "application/vnd.ms-outlook",
		Header:    []byte{0x21, 0x42, 0x44, 0x4E},
		MinSize:   512,
		MaxSize:   10 * 1024 * 1024 * 1024,
		Category:  "email",
		HasFooter: false,
	},
	{
		Name:      "EML",
		Extension: "eml",
		MIMEType:  "message/rfc822",
		Header:    []byte("From: "),
		MinSize:   100,
		MaxSize:   100 * 1024 * 1024,
		Category:  "email",
		HasFooter: false,
	},

	// Disk Images
	{
		Name:      "VMDK",
		Extension: "vmdk",
		MIMEType:  "application/x-vmdk",
		Header:    []byte("KDMV"),
		MinSize:   512,
		MaxSize:   100 * 1024 * 1024 * 1024,
		Category:  "disk-image",
		HasFooter: false,
	},
	{
		Name:      "VHD",
		Extension: "vhd",
		MIMEType:  "application/x-vhd",
		Header:    []byte("conectix"),
		MinSize:   512,
		MaxSize:   100 * 1024 * 1024 * 1024,
		Category:  "disk-image",
		HasFooter: false,
	},
}

// GetSignatureByExtension returns a signature by extension
func GetSignatureByExtension(ext string) *FileSignature {
	for i := range Signatures {
		if Signatures[i].Extension == ext {
			return &Signatures[i]
		}
	}
	return nil
}

// GetSignaturesByCategory returns all signatures in a category
func GetSignaturesByCategory(category string) []FileSignature {
	var sigs []FileSignature
	for _, sig := range Signatures {
		if sig.Category == category {
			sigs = append(sigs, sig)
		}
	}
	return sigs
}
