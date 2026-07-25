package privacy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SuspiciousPermissions that extensions shouldn't normally need
var suspiciousPermissions = map[string]string{
	"<all_urls>":         "Access to all websites",
	"webRequest":         "Monitor all web requests",
	"webRequestBlocking": "Block/modify web requests",
	"proxy":              "Control network proxy",
	"cookies":            "Access cookies on all sites",
	"history":            "Access browsing history",
	"tabs":               "Access tab information",
	"management":         "Manage other extensions",
	"debugger":           "Attach debugger to pages",
	"desktopCapture":     "Capture desktop",
	"nativeMessaging":    "Communicate with native apps",
	"privacy":            "Modify privacy settings",
	"system.storage":     "Access system storage info",
	"topSites":           "Access most visited sites",
	"webNavigation":      "Track navigation events",
}

// ExtensionManifest represents a simplified Chrome extension manifest
type ExtensionManifest struct {
	Name            string   `json:"name"`
	Version         string   `json:"version"`
	Description     string   `json:"description"`
	Permissions     []string `json:"permissions"`
	HostPermissions []string `json:"host_permissions"` // Manifest V3
	UpdateURL       string   `json:"update_url"`
}

// ScanExtensions scans browser extensions for suspicious permissions
func (s *Scanner) ScanExtensions() ([]Finding, error) {
	findings := make([]Finding, 0)

	for _, browser := range s.browsers {
		if !browser.Detected || browser.ExtensionDir == "" {
			continue
		}

		browserFindings, err := scanBrowserExtensions(browser)
		if err != nil {
			continue
		}

		findings = append(findings, browserFindings...)
	}

	return findings, nil
}

// scanBrowserExtensions scans a specific browser's extensions
func scanBrowserExtensions(browser Browser) ([]Finding, error) {
	findings := make([]Finding, 0)

	// Check if extension directory exists
	if _, err := os.Stat(browser.ExtensionDir); os.IsNotExist(err) {
		return findings, nil
	}

	// Read extension directories
	extensions, err := os.ReadDir(browser.ExtensionDir)
	if err != nil {
		return findings, err
	}

	for _, ext := range extensions {
		if !ext.IsDir() {
			continue
		}

		extPath := filepath.Join(browser.ExtensionDir, ext.Name())

		// Find the version directory (extensions usually have version subdirs)
		versions, err := os.ReadDir(extPath)
		if err != nil {
			continue
		}

		for _, version := range versions {
			if !version.IsDir() {
				continue
			}

			manifestPath := filepath.Join(extPath, version.Name(), "manifest.json")
			if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
				continue
			}

			// Analyze the manifest
			extFindings := analyzeExtensionManifest(manifestPath, browser, ext.Name())
			findings = append(findings, extFindings...)
		}
	}

	return findings, nil
}

// analyzeExtensionManifest analyzes an extension manifest for suspicious permissions
func analyzeExtensionManifest(manifestPath string, browser Browser, extID string) []Finding {
	findings := make([]Finding, 0)

	// Read manifest
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return findings
	}

	var manifest ExtensionManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return findings
	}

	// Collect all permissions
	allPermissions := make([]string, 0)
	allPermissions = append(allPermissions, manifest.Permissions...)
	allPermissions = append(allPermissions, manifest.HostPermissions...)

	// Check for suspicious permissions
	suspiciousPerms := make([]string, 0)
	for _, perm := range allPermissions {
		if desc, isSuspicious := suspiciousPermissions[perm]; isSuspicious {
			suspiciousPerms = append(suspiciousPerms, fmt.Sprintf("%s (%s)", perm, desc))
		}

		// Check for broad host permissions
		if strings.Contains(perm, "*") && (strings.Contains(perm, "http") || strings.Contains(perm, "https")) {
			suspiciousPerms = append(suspiciousPerms, fmt.Sprintf("%s (broad access)", perm))
		}
	}

	// Create finding if suspicious permissions found
	if len(suspiciousPerms) > 0 {
		severity := calculateExtensionSeverity(suspiciousPerms, allPermissions)

		description := fmt.Sprintf("Extension '%s' has %d suspicious permissions", manifest.Name, len(suspiciousPerms))
		if len(suspiciousPerms) <= 3 {
			description = fmt.Sprintf("Extension '%s' requests: %s", manifest.Name, strings.Join(suspiciousPerms, ", "))
		}

		finding := Finding{
			Type:        FindingTypeExtension,
			Severity:    severity,
			Category:    "Suspicious Extension",
			Name:        manifest.Name,
			Description: description,
			Location:    filepath.Dir(manifestPath),
			Browser:     browser.Name,
			Value:       fmt.Sprintf("ID: %s, Version: %s, Permissions: %d", extID, manifest.Version, len(allPermissions)),
			Removable:   true,
			AutoRemove:  false, // Never auto-remove extensions
		}

		findings = append(findings, finding)
	}

	// Check for tracking in update URL
	if manifest.UpdateURL != "" {
		for _, tracker := range trackingDomains {
			if strings.Contains(strings.ToLower(manifest.UpdateURL), tracker) {
				finding := Finding{
					Type:        FindingTypeExtension,
					Severity:    SeverityHigh,
					Category:    "Extension with Tracking",
					Name:        manifest.Name,
					Description: fmt.Sprintf("Extension updates from known tracking domain: %s", manifest.UpdateURL),
					Location:    filepath.Dir(manifestPath),
					Browser:     browser.Name,
					Value:       fmt.Sprintf("Update URL: %s", manifest.UpdateURL),
					Removable:   true,
					AutoRemove:  false,
				}

				findings = append(findings, finding)
				break
			}
		}
	}

	return findings
}

// calculateExtensionSeverity determines severity based on permission combination
func calculateExtensionSeverity(suspiciousPerms, allPermissions []string) Severity {
	// Critical: Access to all URLs + webRequest + cookies/history
	hasAllURLs := false
	hasWebRequest := false
	hasSensitiveData := false

	for _, perm := range allPermissions {
		if perm == "<all_urls>" {
			hasAllURLs = true
		}
		if perm == "webRequest" || perm == "webRequestBlocking" {
			hasWebRequest = true
		}
		if perm == "cookies" || perm == "history" || perm == "topSites" {
			hasSensitiveData = true
		}
	}

	if hasAllURLs && hasWebRequest && hasSensitiveData {
		return SeverityCritical
	}

	if hasAllURLs && (hasWebRequest || hasSensitiveData) {
		return SeverityHigh
	}

	if len(suspiciousPerms) >= 3 {
		return SeverityMedium
	}

	return SeverityLow
}

// RemoveExtension removes an extension directory
func RemoveExtension(extensionPath string) error {
	// Safety check: ensure path contains "Extension" to avoid accidents
	if !strings.Contains(extensionPath, "Extension") {
		return fmt.Errorf("invalid extension path")
	}

	return os.RemoveAll(extensionPath)
}
