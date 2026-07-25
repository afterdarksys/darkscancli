package privacy

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Known safe/default values
var safeHomepages = []string{
	"chrome://newtab/",
	"about:newtab",
	"about:blank",
	"edge://newtab/",
	"chrome://new-tab-page",
}

var safeSearchEngines = []string{
	"google.com",
	"bing.com",
	"duckduckgo.com",
	"yahoo.com",
	"ecosia.org",
	"startpage.com",
}

// ChromiumPreferences represents simplified Chrome/Edge preferences
type ChromiumPreferences struct {
	Session struct {
		RestoreOnStartup int      `json:"restore_on_startup"`
		StartupURLs      []string `json:"startup_urls"`
	} `json:"session"`
	Homepage              string `json:"homepage"`
	HomepageIsNTP         bool   `json:"homepage_is_newtabpage"`
	DefaultSearchProvider struct {
		SearchURL string `json:"search_url"`
		Name      string `json:"name"`
		Keyword   string `json:"keyword"`
	} `json:"default_search_provider_data"`
}

// ScanHijacks scans for browser hijacking
func (s *Scanner) ScanHijacks() ([]Finding, error) {
	findings := make([]Finding, 0)

	for _, browser := range s.browsers {
		if !browser.Detected || browser.PrefsFile == "" {
			continue
		}

		browserFindings, err := scanBrowserHijacks(browser)
		if err != nil {
			continue
		}

		findings = append(findings, browserFindings...)
	}

	return findings, nil
}

// scanBrowserHijacks scans a specific browser for hijacks
func scanBrowserHijacks(browser Browser) ([]Finding, error) {
	findings := make([]Finding, 0)

	// Check if preferences file exists
	if _, err := os.Stat(browser.PrefsFile); os.IsNotExist(err) {
		return findings, nil
	}

	// Chromium-based browsers use JSON preferences
	if strings.Contains(browser.Name, "Chrome") ||
		strings.Contains(browser.Name, "Edge") ||
		strings.Contains(browser.Name, "Brave") ||
		strings.Contains(browser.Name, "Chromium") {
		return scanChromiumHijacks(browser)
	}

	return findings, nil
}

// scanChromiumHijacks scans Chromium-based browser for hijacks
func scanChromiumHijacks(browser Browser) ([]Finding, error) {
	findings := make([]Finding, 0)

	// Read preferences file
	data, err := os.ReadFile(browser.PrefsFile)
	if err != nil {
		return findings, err
	}

	var prefs ChromiumPreferences
	if err := json.Unmarshal(data, &prefs); err != nil {
		return findings, err
	}

	// Check homepage hijack
	if prefs.Homepage != "" && !prefs.HomepageIsNTP {
		if !isSafeHomepage(prefs.Homepage) {
			finding := Finding{
				Type:        FindingTypeHijack,
				Severity:    SeverityHigh,
				Category:    "Homepage Hijack",
				Name:        "Modified Homepage",
				Description: fmt.Sprintf("Homepage changed to: %s", prefs.Homepage),
				Location:    browser.PrefsFile,
				Browser:     browser.Name,
				Value:       prefs.Homepage,
				Removable:   true,
				AutoRemove:  false,
			}

			findings = append(findings, finding)
		}
	}

	// Check startup URLs hijack
	if len(prefs.Session.StartupURLs) > 0 && prefs.Session.RestoreOnStartup == 4 {
		for _, url := range prefs.Session.StartupURLs {
			if !isSafeStartupURL(url) {
				finding := Finding{
					Type:        FindingTypeHijack,
					Severity:    SeverityHigh,
					Category:    "Startup URL Hijack",
					Name:        "Modified Startup URL",
					Description: fmt.Sprintf("Browser opens: %s", url),
					Location:    browser.PrefsFile,
					Browser:     browser.Name,
					Value:       url,
					Removable:   true,
					AutoRemove:  false,
				}

				findings = append(findings, finding)
			}
		}
	}

	// Check search engine hijack
	if prefs.DefaultSearchProvider.SearchURL != "" {
		if !isSafeSearchEngine(prefs.DefaultSearchProvider.SearchURL) {
			finding := Finding{
				Type:        FindingTypeHijack,
				Severity:    SeverityHigh,
				Category:    "Search Engine Hijack",
				Name:        "Modified Search Engine",
				Description: fmt.Sprintf("Search engine changed to: %s", prefs.DefaultSearchProvider.Name),
				Location:    browser.PrefsFile,
				Browser:     browser.Name,
				Value:       prefs.DefaultSearchProvider.SearchURL,
				Removable:   true,
				AutoRemove:  false,
			}

			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// isSafeHomepage checks if homepage is a known safe default
func isSafeHomepage(homepage string) bool {
	homepageLower := strings.ToLower(homepage)

	for _, safe := range safeHomepages {
		if strings.Contains(homepageLower, safe) {
			return true
		}
	}

	// Allow empty or common sites
	if homepage == "" || strings.Contains(homepageLower, "google.com") {
		return true
	}

	return false
}

// isSafeStartupURL checks if startup URL is safe
func isSafeStartupURL(url string) bool {
	urlLower := strings.ToLower(url)

	// Allow safe defaults
	for _, safe := range safeHomepages {
		if strings.Contains(urlLower, safe) {
			return true
		}
	}

	// Allow user's own sites (this is a heuristic)
	// Suspicious: URLs with "toolbar", "search", "extension" etc
	suspiciousPatterns := []string{
		"toolbar", "search-", "mysearch", "searchassist",
		"browser-assistant", "homepage-web",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(urlLower, pattern) {
			return false
		}
	}

	return true
}

// isSafeSearchEngine checks if search engine is a known safe provider
func isSafeSearchEngine(searchURL string) bool {
	searchLower := strings.ToLower(searchURL)

	for _, safe := range safeSearchEngines {
		if strings.Contains(searchLower, safe) {
			return true
		}
	}

	return false
}

// FixHijack attempts to fix a browser hijack
func FixHijack(finding Finding) error {
	// Read current preferences
	data, err := os.ReadFile(finding.Location)
	if err != nil {
		return err
	}

	var prefs ChromiumPreferences
	if err := json.Unmarshal(data, &prefs); err != nil {
		return err
	}

	// Fix based on hijack type
	switch finding.Category {
	case "Homepage Hijack":
		prefs.Homepage = ""
		prefs.HomepageIsNTP = true

	case "Startup URL Hijack":
		// Clear suspicious startup URLs
		prefs.Session.StartupURLs = []string{}
		prefs.Session.RestoreOnStartup = 5 // Open New Tab Page

	case "Search Engine Hijack":
		// Reset to default (empty will make browser use built-in default)
		prefs.DefaultSearchProvider.SearchURL = ""
		prefs.DefaultSearchProvider.Name = ""
		prefs.DefaultSearchProvider.Keyword = ""
	}

	// Write back preferences
	updatedData, err := json.MarshalIndent(prefs, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(finding.Location, updatedData, 0644)
}
