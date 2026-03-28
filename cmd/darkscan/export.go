package main

import (
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"time"

	"github.com/afterdarksys/darkscan/pkg/scanner"
)

// ExportFormat defines the supported export formats
type ExportFormat string

const (
	FormatJSON ExportFormat = "json"
	FormatCSV  ExportFormat = "csv"
	FormatXML  ExportFormat = "xml"
	FormatText ExportFormat = "text"
)

// ScanReport wraps scan results with summary information
type ScanReport struct {
	XMLName      xml.Name `xml:"ScanReport" json:"-"`
	Summary      ScanSummary
	Results      []ExportScanResult
	GeneratedAt  time.Time
	ScanDuration string
}

// ScanSummary provides aggregate statistics
type ScanSummary struct {
	TotalFiles    int     `xml:"TotalFiles" json:"total_files"`
	InfectedFiles int     `xml:"InfectedFiles" json:"infected_files"`
	CleanFiles    int     `xml:"CleanFiles" json:"clean_files"`
	Errors        int     `xml:"Errors" json:"errors"`
	ScanDuration  string  `xml:"ScanDuration" json:"scan_duration"`
}

// ExportScanResult is a serialization-friendly version of ScanResult
type ExportScanResult struct {
	FilePath   string        `xml:"FilePath" json:"file_path" csv:"FilePath"`
	Infected   bool          `xml:"Infected" json:"infected" csv:"Infected"`
	Threats    []ExportThreat `xml:"Threats>Threat" json:"threats"`
	ScanEngine string        `xml:"ScanEngine" json:"scan_engine" csv:"ScanEngine"`
	Error      string        `xml:"Error,omitempty" json:"error,omitempty" csv:"Error"`
}

// ExportThreat is a serialization-friendly version of Threat
type ExportThreat struct {
	Name        string `xml:"Name" json:"name"`
	Severity    string `xml:"Severity" json:"severity"`
	Description string `xml:"Description,omitempty" json:"description,omitempty"`
	Engine      string `xml:"Engine" json:"engine"`
}

// ExportResults exports scan results to the specified format
func ExportResults(results []*scanner.ScanResult, format ExportFormat, outputFile string, duration time.Duration) error {
	report := buildReport(results, duration)

	var output *os.File
	var err error
	if outputFile != "" && format != FormatText {
		output, err = os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer output.Close()
	} else {
		output = os.Stdout
	}

	switch format {
	case FormatJSON:
		return exportJSON(output, report)
	case FormatCSV:
		return exportCSV(output, report)
	case FormatXML:
		return exportXML(output, report)
	case FormatText:
		// Text format is handled by printResults, nothing to export
		return nil
	default:
		return fmt.Errorf("unsupported export format: %s", format)
	}
}

func buildReport(results []*scanner.ScanResult, duration time.Duration) ScanReport {
	report := ScanReport{
		GeneratedAt:  time.Now(),
		ScanDuration: duration.String(),
		Results:      make([]ExportScanResult, 0, len(results)),
	}

	for _, r := range results {
		exportResult := ExportScanResult{
			FilePath:   r.FilePath,
			Infected:   r.Infected,
			ScanEngine: r.ScanEngine,
			Threats:    make([]ExportThreat, 0, len(r.Threats)),
		}

		if r.Error != nil {
			exportResult.Error = r.Error.Error()
			report.Summary.Errors++
		}

		for _, t := range r.Threats {
			exportResult.Threats = append(exportResult.Threats, ExportThreat{
				Name:        t.Name,
				Severity:    t.Severity,
				Description: t.Description,
				Engine:      t.Engine,
			})
		}

		report.Results = append(report.Results, exportResult)

		if r.Infected {
			report.Summary.InfectedFiles++
		} else if r.Error == nil {
			report.Summary.CleanFiles++
		}
	}

	report.Summary.TotalFiles = len(results)
	report.Summary.ScanDuration = duration.String()

	return report
}

func exportJSON(output *os.File, report ScanReport) error {
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func exportCSV(output *os.File, report ScanReport) error {
	writer := csv.NewWriter(output)
	defer writer.Flush()

	// Write header
	header := []string{"FilePath", "Infected", "ScanEngine", "Threats", "Error"}
	if err := writer.Write(header); err != nil {
		return err
	}

	// Write data
	for _, result := range report.Results {
		infected := "false"
		if result.Infected {
			infected = "true"
		}

		// Concatenate threat names
		threatNames := ""
		for i, threat := range result.Threats {
			if i > 0 {
				threatNames += "; "
			}
			threatNames += fmt.Sprintf("%s (%s)", threat.Name, threat.Severity)
		}

		record := []string{
			result.FilePath,
			infected,
			result.ScanEngine,
			threatNames,
			result.Error,
		}

		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}

func exportXML(output *os.File, report ScanReport) error {
	encoder := xml.NewEncoder(output)
	encoder.Indent("", "  ")

	// Write XML header
	if _, err := output.WriteString(xml.Header); err != nil {
		return err
	}

	return encoder.Encode(report)
}
