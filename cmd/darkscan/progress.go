package main

import (
	"encoding/json"
	"os"
	"time"

	"github.com/afterdarksys/darkscan/pkg/scanner"
)

// ProgressEvent represents a progress update event
type ProgressEvent struct {
	Type      string                 `json:"type"` // scan_start, file_scanning, file_scanned, threat_detected, scan_complete
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

// ProgressReporter handles progress reporting for GUI integration
type ProgressReporter struct {
	enabled      bool
	startTime    time.Time
	totalFiles   int
	scannedFiles int
	threatsFound int
}

// NewProgressReporter creates a new progress reporter
func NewProgressReporter(enabled bool) *ProgressReporter {
	return &ProgressReporter{
		enabled:   enabled,
		startTime: time.Now(),
	}
}

// emit outputs a progress event as JSON to stderr
func (pr *ProgressReporter) emit(eventType string, data map[string]interface{}) {
	if !pr.enabled {
		return
	}

	event := ProgressEvent{
		Type:      eventType,
		Timestamp: time.Now(),
		Data:      data,
	}

	jsonBytes, err := json.Marshal(event)
	if err != nil {
		return // Silently fail on progress reporting errors
	}

	// Output to stderr (so stdout can be used for normal output)
	os.Stderr.Write(jsonBytes)
	os.Stderr.Write([]byte("\n"))
}

// ScanStart reports the start of a scan
func (pr *ProgressReporter) ScanStart(path string, totalFiles int) {
	pr.totalFiles = totalFiles
	pr.scannedFiles = 0
	pr.threatsFound = 0
	pr.startTime = time.Now()

	pr.emit("scan_start", map[string]interface{}{
		"path":        path,
		"total_files": totalFiles,
	})
}

// FileScanning reports that a file is being scanned
func (pr *ProgressReporter) FileScanning(path string) {
	pr.emit("file_scanning", map[string]interface{}{
		"file":     path,
		"progress": pr.getProgress(),
	})
}

// FileScanned reports that a file has been scanned
func (pr *ProgressReporter) FileScanned(result *scanner.ScanResult) {
	pr.scannedFiles++

	if result.Infected {
		pr.threatsFound++
	}

	data := map[string]interface{}{
		"file":     result.FilePath,
		"infected": result.Infected,
		"progress": pr.getProgress(),
	}

	if result.Infected {
		threats := make([]map[string]interface{}, len(result.Threats))
		for i, threat := range result.Threats {
			threats[i] = map[string]interface{}{
				"name":        threat.Name,
				"severity":    threat.Severity,
				"description": threat.Description,
				"engine":      threat.Engine,
			}
		}
		data["threats"] = threats
	}

	pr.emit("file_scanned", data)
}

// ThreatDetected reports that a threat was detected (for real-time alerts)
func (pr *ProgressReporter) ThreatDetected(result *scanner.ScanResult) {
	if !result.Infected {
		return
	}

	threats := make([]map[string]interface{}, len(result.Threats))
	for i, threat := range result.Threats {
		threats[i] = map[string]interface{}{
			"name":        threat.Name,
			"severity":    threat.Severity,
			"description": threat.Description,
			"engine":      threat.Engine,
		}
	}

	pr.emit("threat_detected", map[string]interface{}{
		"file":    result.FilePath,
		"threats": threats,
	})
}

// ScanComplete reports the completion of a scan
func (pr *ProgressReporter) ScanComplete(totalScanned, threatsFound int, duration time.Duration) {
	pr.emit("scan_complete", map[string]interface{}{
		"total_scanned": totalScanned,
		"threats_found": threatsFound,
		"duration":      duration.Seconds(),
		"clean_files":   totalScanned - threatsFound,
	})
}

// Error reports an error during scanning
func (pr *ProgressReporter) Error(path string, err error) {
	pr.emit("scan_error", map[string]interface{}{
		"file":  path,
		"error": err.Error(),
	})
}

// getProgress calculates current progress percentage
func (pr *ProgressReporter) getProgress() map[string]interface{} {
	var percentage float64
	if pr.totalFiles > 0 {
		percentage = float64(pr.scannedFiles) / float64(pr.totalFiles) * 100
	}

	elapsed := time.Since(pr.startTime).Seconds()
	var eta float64
	if pr.scannedFiles > 0 {
		rate := float64(pr.scannedFiles) / elapsed
		remaining := pr.totalFiles - pr.scannedFiles
		if rate > 0 {
			eta = float64(remaining) / rate
		}
	}

	return map[string]interface{}{
		"scanned":    pr.scannedFiles,
		"total":      pr.totalFiles,
		"percentage": percentage,
		"threats":    pr.threatsFound,
		"elapsed":    elapsed,
		"eta":        eta,
	}
}
