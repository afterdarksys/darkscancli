package sample

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"os"

	"github.com/h2non/filetype"
)

// Type represents the type of executable file
type Type string

const (
	TypePE      Type = "pe"
	TypeELF     Type = "elf"
	TypeMachO   Type = "macho"
	TypeScript  Type = "script"
	TypeArchive Type = "archive"
	TypeDocument Type = "document"
	TypeUnknown Type = "unknown"
)

// Sample represents a malware sample or file
type Sample struct {
	Path     string            `json:"path"`
	Type     Type              `json:"type"`
	FileType string            `json:"file_type"`
	Arch     string            `json:"arch,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// PEInfo contains PE-specific information
type PEInfo struct {
	Machine          string            `json:"machine"`
	Characteristics  uint16            `json:"characteristics"`
	Subsystem        string            `json:"subsystem"`
	Sections         []PESection       `json:"sections"`
	Imports          []string          `json:"imports"`
	Exports          []string          `json:"exports"`
	Resources        int               `json:"resources"`
	CompilationTime  uint32            `json:"compilation_time"`
	ImageBase        uint64            `json:"image_base"`
}

// PESection represents a PE section
type PESection struct {
	Name             string  `json:"name"`
	VirtualSize      uint32  `json:"virtual_size"`
	VirtualAddress   uint32  `json:"virtual_address"`
	RawSize          uint32  `json:"raw_size"`
	RawAddress       uint32  `json:"raw_address"`
	Characteristics  uint32  `json:"characteristics"`
	Entropy          float64 `json:"entropy"`
}

// ELFInfo contains ELF-specific information
type ELFInfo struct {
	Class    string   `json:"class"` // 32 or 64
	Machine  string   `json:"machine"`
	Sections []string `json:"sections"`
	Symbols  []string `json:"symbols"`
}

// MachOInfo contains Mach-O specific information
type MachOInfo struct {
	Type     string   `json:"type"`
	CPU      string   `json:"cpu"`
	Segments []string `json:"segments"`
}

// Identify identifies the file type and architecture
func Identify(path string) (*Sample, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	sample := &Sample{
		Path:     path,
		Metadata: make(map[string]string),
	}

	// Detect file type using magic bytes
	head := make([]byte, 512)
	if n, _ := f.Read(head); n > 0 {
		kind, _ := filetype.Match(head[:n])
		sample.FileType = kind.MIME.Value
	}

	// Reset for format-specific detection
	f.Seek(0, 0)

	// Try PE
	if peFile, err := pe.NewFile(f); err == nil {
		sample.Type = TypePE
		sample.Arch = fmt.Sprintf("0x%x", peFile.Machine)
		peFile.Close()
		return sample, nil
	}

	// Reset and try ELF
	f.Seek(0, 0)
	if elfFile, err := elf.NewFile(f); err == nil {
		sample.Type = TypeELF
		sample.Arch = elfFile.Machine.String()
		elfFile.Close()
		return sample, nil
	}

	// Reset and try Mach-O
	f.Seek(0, 0)
	if machoFile, err := macho.NewFile(f); err == nil {
		sample.Type = TypeMachO
		sample.Arch = machoFile.Cpu.String()
		machoFile.Close()
		return sample, nil
	}

	// Check for scripts
	f.Seek(0, 0)
	head = make([]byte, 16)
	f.Read(head)

	if len(head) >= 2 && head[0] == '#' && head[1] == '!' {
		sample.Type = TypeScript
		return sample, nil
	}

	// Default to unknown
	sample.Type = TypeUnknown
	return sample, nil
}

// AnalyzePE performs detailed PE analysis
func AnalyzePE(path string) (*PEInfo, error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open PE: %w", err)
	}
	defer f.Close()

	info := &PEInfo{
		Machine:         fmt.Sprintf("0x%x", f.Machine),
		Characteristics: f.FileHeader.Characteristics,
	}

	// Optional header info
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		info.Subsystem = subsystemString(oh.Subsystem)
		info.ImageBase = uint64(oh.ImageBase)
	case *pe.OptionalHeader64:
		info.Subsystem = subsystemString(oh.Subsystem)
		info.ImageBase = oh.ImageBase
	}

	// Sections
	for _, section := range f.Sections {
		s := PESection{
			Name:            section.Name,
			VirtualSize:     section.VirtualSize,
			VirtualAddress:  section.VirtualAddress,
			RawSize:         section.Size,
			RawAddress:      section.Offset,
			Characteristics: section.Characteristics,
		}

		// Read section data for entropy calculation
		if data, err := section.Data(); err == nil && len(data) > 0 {
			s.Entropy = calculateEntropy(data)
		}

		info.Sections = append(info.Sections, s)
	}

	// Imports
	imports, err := f.ImportedSymbols()
	if err == nil {
		info.Imports = imports
	}

	// Note: Export parsing would require manual parsing of PE export directory
	// Left as future enhancement

	return info, nil
}

// AnalyzeELF performs detailed ELF analysis
func AnalyzeELF(path string) (*ELFInfo, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open ELF: %w", err)
	}
	defer f.Close()

	info := &ELFInfo{
		Machine: f.Machine.String(),
	}

	if f.Class == elf.ELFCLASS32 {
		info.Class = "32"
	} else {
		info.Class = "64"
	}

	// Sections
	for _, section := range f.Sections {
		info.Sections = append(info.Sections, section.Name)
	}

	// Symbols
	symbols, err := f.Symbols()
	if err == nil {
		for _, sym := range symbols {
			if sym.Name != "" {
				info.Symbols = append(info.Symbols, sym.Name)
			}
		}
	}

	return info, nil
}

// AnalyzeMachO performs detailed Mach-O analysis
func AnalyzeMachO(path string) (*MachOInfo, error) {
	f, err := macho.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open Mach-O: %w", err)
	}
	defer f.Close()

	info := &MachOInfo{
		Type: f.Type.String(),
		CPU:  f.Cpu.String(),
	}

	// Segments
	for _, seg := range f.Loads {
		if segment, ok := seg.(*macho.Segment); ok {
			info.Segments = append(info.Segments, segment.Name)
		}
	}

	return info, nil
}

func subsystemString(subsystem uint16) string {
	switch subsystem {
	case 1:
		return "NATIVE"
	case 2:
		return "WINDOWS_GUI"
	case 3:
		return "WINDOWS_CUI"
	case 7:
		return "POSIX_CUI"
	case 9:
		return "WINDOWS_CE_GUI"
	case 10:
		return "EFI_APPLICATION"
	case 11:
		return "EFI_BOOT_SERVICE_DRIVER"
	case 12:
		return "EFI_RUNTIME_DRIVER"
	case 13:
		return "EFI_ROM"
	case 14:
		return "XBOX"
	case 16:
		return "WINDOWS_BOOT_APPLICATION"
	default:
		return "UNKNOWN"
	}
}

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
			entropy -= p * logBase2(p)
		}
	}

	return entropy
}

func logBase2(x float64) float64 {
	if x == 0 {
		return 0
	}
	// Natural log approximation
	const ln2 = 0.693147180559945309417
	return naturalLog(x) / ln2
}

func naturalLog(x float64) float64 {
	if x <= 0 {
		return 0
	}
	// Simple approximation
	y := (x - 1) / (x + 1)
	y2 := y * y
	sum := y
	term := y

	for i := 1; i < 100; i++ {
		term *= y2
		sum += term / float64(2*i+1)
	}

	return 2 * sum
}
