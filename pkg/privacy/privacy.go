package privacy

import (
	"fmt"
	"time"
)

// Scanner performs privacy and tracking detection
type Scanner struct {
	browsers []Browser
}

// Finding represents a privacy/tracking issue found
type Finding struct {
	Type        FindingType
	Severity    Severity
	Category    string
	Name        string
	Description string
	Location    string
	Browser     string
	Value       string
	Removable   bool
	AutoRemove  bool // Safe to auto-remove without user confirmation
}

// FindingType categorizes the type of privacy issue
type FindingType string

const (
	FindingTypeCookie         FindingType = "tracking_cookie"
	FindingTypeExtension      FindingType = "suspicious_extension"
	FindingTypeHijack         FindingType = "browser_hijack"
	FindingTypeTelemetry      FindingType = "windows_telemetry"
	FindingTypeDNSTracker     FindingType = "dns_tracker"
	FindingTypeRegistry       FindingType = "registry_tracker"
	FindingTypeStorageTracker FindingType = "storage_tracker"
	FindingTypeHistoryTracker FindingType = "history_tracker"
)

// Severity levels
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Browser represents a detected browser installation
type Browser struct {
	Name         string
	ProfilePath  string
	CookiePath   string
	ExtensionDir string
	PrefsFile    string
	HistoryDB    string
	Detected     bool
}

// ScanResult contains all privacy scan findings
type ScanResult struct {
	Findings        []Finding
	TotalFindings   int
	CriticalCount   int
	HighCount       int
	MediumCount     int
	LowCount        int
	InfoCount       int
	BrowsersScanned int
	ScanDuration    time.Duration
}

// NewScanner creates a new privacy scanner
func NewScanner() *Scanner {
	return &Scanner{
		browsers: DetectBrowsers(),
	}
}

// Scan performs a comprehensive privacy scan
func (s *Scanner) Scan() (*ScanResult, error) {
	startTime := time.Now()
	result := &ScanResult{
		Findings: make([]Finding, 0),
	}

	// Scan for tracking cookies
	cookieFindings, err := s.ScanCookies()
	if err == nil {
		result.Findings = append(result.Findings, cookieFindings...)
	}

	// Scan browser extensions
	extensionFindings, err := s.ScanExtensions()
	if err == nil {
		result.Findings = append(result.Findings, extensionFindings...)
	}

	// Scan for browser hijacks
	hijackFindings, err := s.ScanHijacks()
	if err == nil {
		result.Findings = append(result.Findings, hijackFindings...)
	}

	// Scan Windows telemetry (Windows only)
	telemetryFindings, err := s.ScanTelemetry()
	if err == nil {
		result.Findings = append(result.Findings, telemetryFindings...)
	}

	// Calculate statistics
	result.TotalFindings = len(result.Findings)
	result.BrowsersScanned = s.CountDetectedBrowsers()

	for _, finding := range result.Findings {
		switch finding.Severity {
		case SeverityCritical:
			result.CriticalCount++
		case SeverityHigh:
			result.HighCount++
		case SeverityMedium:
			result.MediumCount++
		case SeverityLow:
			result.LowCount++
		case SeverityInfo:
			result.InfoCount++
		}
	}

	result.ScanDuration = time.Since(startTime)
	return result, nil
}

// CountDetectedBrowsers returns the number of detected browsers
func (s *Scanner) CountDetectedBrowsers() int {
	count := 0
	for _, browser := range s.browsers {
		if browser.Detected {
			count++
		}
	}
	return count
}

// GetBrowsers returns detected browsers
func (s *Scanner) GetBrowsers() []Browser {
	detected := make([]Browser, 0)
	for _, browser := range s.browsers {
		if browser.Detected {
			detected = append(detected, browser)
		}
	}
	return detected
}

// RemoveFinding attempts to remove/clean a finding
func (s *Scanner) RemoveFinding(finding Finding) error {
	if !finding.Removable {
		return fmt.Errorf("finding is not removable")
	}

	switch finding.Type {
	case FindingTypeCookie:
		return RemoveCookie(finding.Location, finding.Name)
	case FindingTypeExtension:
		return RemoveExtension(finding.Location)
	case FindingTypeHijack:
		return FixHijack(finding)
	case FindingTypeTelemetry:
		return DisableTelemetry(finding)
	default:
		return fmt.Errorf("removal not implemented for type: %s", finding.Type)
	}
}

// RemoveFindings removes multiple findings
func (s *Scanner) RemoveFindings(findings []Finding) (int, error) {
	removed := 0
	var lastErr error

	for _, finding := range findings {
		if err := s.RemoveFinding(finding); err != nil {
			lastErr = err
		} else {
			removed++
		}
	}

	return removed, lastErr
}
