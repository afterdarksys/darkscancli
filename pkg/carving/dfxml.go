package carving

import (
	"encoding/xml"
	"fmt"
	"os"
	"time"
)

// DFXML (Digital Forensics XML) support for forensic reporting
// Based on http://www.forensicswiki.org/wiki/DFXML

// DFXMLReport represents a Digital Forensics XML report
type DFXMLReport struct {
	XMLName xml.Name `xml:"dfxml"`
	Version string   `xml:"version,attr"`
	Creator *Creator `xml:"creator"`
	Source  *Source  `xml:"source"`
	RunInfo *RunInfo `xml:"runinfo"`
	Files   []FileObject `xml:"fileobject"`
}

// Creator identifies the tool that created the report
type Creator struct {
	Program string `xml:"program"`
	Version string `xml:"version"`
}

// Source describes the source being analyzed
type Source struct {
	ImageFilename string `xml:"image_filename,omitempty"`
	DeviceName    string `xml:"device_name,omitempty"`
	PartitionOffset int64 `xml:"partition_offset,omitempty"`
	VolumeSize    int64  `xml:"volume_size,omitempty"`
}

// RunInfo contains information about the scan run
type RunInfo struct {
	StartTime time.Time `xml:"start_time"`
	EndTime   time.Time `xml:"end_time,omitempty"`
	Hostname  string    `xml:"hostname,omitempty"`
	Username  string    `xml:"username,omitempty"`
	ScanType  string    `xml:"scan_type"` // full, unallocated, targeted
}

// FileObject represents a carved file in DFXML format
type FileObject struct {
	Filename      string       `xml:"filename"`
	FileSize      int64        `xml:"filesize"`
	AllocatedSize int64        `xml:"alloc_size,omitempty"`
	ByteRuns      []ByteRun    `xml:"byte_runs>byte_run"`
	HashDigest    *HashDigest  `xml:"hashdigest,omitempty"`
	CarvingInfo   *CarvingInfo `xml:"carving_info,omitempty"`
	FileType      string       `xml:"file_type,omitempty"`
	MIMEType      string       `xml:"mime_type,omitempty"`
}

// ByteRun describes where file data is located on disk
type ByteRun struct {
	FileOffset  int64 `xml:"file_offset,attr,omitempty"`
	ImageOffset int64 `xml:"img_offset,attr"`
	Length      int64 `xml:"len,attr"`
}

// HashDigest contains file hashes
type HashDigest struct {
	MD5    string `xml:"md5,omitempty"`
	SHA1   string `xml:"sha1,omitempty"`
	SHA256 string `xml:"sha256,omitempty"`
}

// CarvingInfo contains carving-specific metadata
type CarvingInfo struct {
	Confidence     int      `xml:"confidence"`
	IsComplete     bool     `xml:"is_complete"`
	IsFragmented   bool     `xml:"is_fragmented"`
	HeaderOffset   int64    `xml:"header_offset"`
	FooterOffset   int64    `xml:"footer_offset,omitempty"`
	ValidationErrors []string `xml:"validation_errors>error,omitempty"`
}

// NewDFXMLReport creates a new DFXML report
func NewDFXMLReport() *DFXMLReport {
	return &DFXMLReport{
		Version: "1.2.0",
		Creator: &Creator{
			Program: "darkscand-carver",
			Version: "1.0.0",
		},
		Source: &Source{},
		RunInfo: &RunInfo{
			StartTime: time.Now(),
			ScanType:  "full",
		},
		Files: []FileObject{},
	}
}

// AddCarvedFile adds a carved file to the report
func (r *DFXMLReport) AddCarvedFile(file *CarvedFile, outputFilename string) {
	fileObj := FileObject{
		Filename:  outputFilename,
		FileSize:  file.Size,
		FileType:  file.Type,
		MIMEType:  file.MIMEType,
		ByteRuns: []ByteRun{
			{
				ImageOffset: file.Offset,
				Length:      file.Size,
			},
		},
		CarvingInfo: &CarvingInfo{
			Confidence:       file.Confidence,
			IsComplete:       file.IsComplete,
			IsFragmented:     file.IsFragmented,
			HeaderOffset:     file.Offset,
			ValidationErrors: file.ValidationErrors,
		},
	}

	r.Files = append(r.Files, fileObj)
}

// AddFragmentedFile adds a fragmented file to the report
func (r *DFXMLReport) AddFragmentedFile(file *FragmentedFile, outputFilename string) {
	fileObj := FileObject{
		Filename: outputFilename,
		FileSize: file.TotalSize,
		FileType: file.Type,
		CarvingInfo: &CarvingInfo{
			Confidence:   file.Confidence,
			IsComplete:   file.IsComplete,
			IsFragmented: true,
		},
	}

	// Add byte runs for each fragment
	for _, frag := range file.Fragments {
		fileObj.ByteRuns = append(fileObj.ByteRuns, ByteRun{
			ImageOffset: frag.Offset,
			Length:      frag.Size,
		})
	}

	r.Files = append(r.Files, fileObj)
}

// Finalize completes the report
func (r *DFXMLReport) Finalize() {
	r.RunInfo.EndTime = time.Now()
}

// WriteToFile writes the report to an XML file
func (r *DFXMLReport) WriteToFile(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer f.Close()

	// Write XML header
	f.WriteString(xml.Header)

	// Marshal and write XML
	encoder := xml.NewEncoder(f)
	encoder.Indent("", "  ")

	if err := encoder.Encode(r); err != nil {
		return fmt.Errorf("encode XML: %w", err)
	}

	return nil
}

// String returns the report as an XML string
func (r *DFXMLReport) String() (string, error) {
	data, err := xml.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}

	return xml.Header + string(data), nil
}

// Statistics generates statistics from the report
type Statistics struct {
	TotalFiles       int
	TotalBytes       int64
	FilesByType      map[string]int
	FilesByCategory  map[string]int
	AverageConfidence float64
	CompleteFiles    int
	FragmentedFiles  int
}

// GetStatistics calculates statistics from the report
func (r *DFXMLReport) GetStatistics() *Statistics {
	stats := &Statistics{
		FilesByType:     make(map[string]int),
		FilesByCategory: make(map[string]int),
	}

	totalConfidence := 0

	for _, file := range r.Files {
		stats.TotalFiles++
		stats.TotalBytes += file.FileSize

		if file.FileType != "" {
			stats.FilesByType[file.FileType]++
		}

		if file.CarvingInfo != nil {
			totalConfidence += file.CarvingInfo.Confidence

			if file.CarvingInfo.IsComplete {
				stats.CompleteFiles++
			}
			if file.CarvingInfo.IsFragmented {
				stats.FragmentedFiles++
			}
		}
	}

	if stats.TotalFiles > 0 {
		stats.AverageConfidence = float64(totalConfidence) / float64(stats.TotalFiles)
	}

	return stats
}

// FilterByConfidence returns files above a confidence threshold
func (r *DFXMLReport) FilterByConfidence(minConfidence int) []FileObject {
	var filtered []FileObject

	for _, file := range r.Files {
		if file.CarvingInfo != nil && file.CarvingInfo.Confidence >= minConfidence {
			filtered = append(filtered, file)
		}
	}

	return filtered
}

// FilterByType returns files of a specific type
func (r *DFXMLReport) FilterByType(fileType string) []FileObject {
	var filtered []FileObject

	for _, file := range r.Files {
		if file.FileType == fileType {
			filtered = append(filtered, file)
		}
	}

	return filtered
}
