package privacy

import (
	"database/sql"
	"fmt"
	"os"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

// Known tracking domains and cookie patterns
var trackingDomains = []string{
	// Advertising Networks
	"doubleclick.net", "googlesyndication.com", "googleadservices.com",
	"adnxs.com", "adsrvr.org", "advertising.com", "criteo.com",
	"pubmatic.com", "rubiconproject.com", "openx.net", "adform.net",
	"turn.com", "serving-sys.com", "2mdn.net", "amazon-adsystem.com",

	// Analytics & Tracking
	"google-analytics.com", "googletagmanager.com", "scorecardresearch.com",
	"quantserve.com", "hotjar.com", "mixpanel.com", "segment.com",
	"newrelic.com", "nr-data.net", "fullstory.com", "heap.io",
	"amplitude.com", "mxpnl.com",

	// Social Media Trackers
	"facebook.com", "facebook.net", "connect.facebook.net",
	"twitter.com", "platform.twitter.com", "linkedin.com",
	"pinterest.com", "instagram.com", "snapchat.com",

	// Third-Party Widgets
	"addthis.com", "sharethis.com", "disqus.com",

	// Fingerprinting
	"maxmind.com", "iovation.com", "threatmetrix.com",

	// Data Brokers
	"acxiom.com", "experian.com", "datalogix.com", "bluekai.com",
	"tapad.com", "exelate.com", "liveramp.com",

	// Ad Exchanges
	"appnexus.com", "pubmatic.com", "indexexchange.com",
}

var trackingCookieNames = []string{
	"_ga", "_gid", "_gat", "__utma", "__utmb", "__utmc", "__utmz", "__utmt",
	"_fbp", "_fbc", "fr", "datr", "c_user",
	"_hjid", "_hjIncludedInSample",
	"__qca", "_mkto_trk", "_uetsid",
	"IDE", "DSID", "FLC", "NID", "ANID",
	"uuid2", "anj", "sess", "usersync",
}

// ScanCookies scans browsers for tracking cookies
func (s *Scanner) ScanCookies() ([]Finding, error) {
	findings := make([]Finding, 0)

	for _, browser := range s.browsers {
		if !browser.Detected || browser.CookiePath == "" {
			continue
		}

		browserFindings, err := scanBrowserCookies(browser)
		if err != nil {
			continue // Skip browser if we can't read cookies
		}

		findings = append(findings, browserFindings...)
	}

	return findings, nil
}

// scanBrowserCookies scans a specific browser's cookie database
func scanBrowserCookies(browser Browser) ([]Finding, error) {
	findings := make([]Finding, 0)

	// Check if cookie file exists
	if _, err := os.Stat(browser.CookiePath); os.IsNotExist(err) {
		return findings, nil
	}

	// Chrome/Edge/Brave use SQLite for cookies
	if strings.Contains(browser.Name, "Chrome") ||
		strings.Contains(browser.Name, "Edge") ||
		strings.Contains(browser.Name, "Brave") ||
		strings.Contains(browser.Name, "Chromium") {
		return scanChromiumCookies(browser)
	}

	// Firefox uses SQLite too but different schema
	if strings.Contains(browser.Name, "Firefox") {
		return scanFirefoxCookies(browser)
	}

	// Safari uses binary cookie format (skip for now)
	return findings, nil
}

// scanChromiumCookies scans Chromium-based browser cookies
func scanChromiumCookies(browser Browser) ([]Finding, error) {
	findings := make([]Finding, 0)

	// Open cookie database (read-only)
	db, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?mode=ro", browser.CookiePath))
	if err != nil {
		return findings, err
	}
	defer db.Close()

	// Query cookies
	query := `SELECT host_key, name, path, creation_utc, expires_utc, is_persistent
	          FROM cookies
	          ORDER BY creation_utc DESC`

	rows, err := db.Query(query)
	if err != nil {
		return findings, err
	}
	defer rows.Close()

	for rows.Next() {
		var hostKey, name, path string
		var creationUTC, expiresUTC int64
		var isPersistent int

		if err := rows.Scan(&hostKey, &name, &path, &creationUTC, &expiresUTC, &isPersistent); err != nil {
			continue
		}

		// Check if it's a tracking cookie
		if isTrackingCookie(hostKey, name) {
			severity := getSeverityForTracker(hostKey, name)

			finding := Finding{
				Type:        FindingTypeCookie,
				Severity:    severity,
				Category:    "Tracking Cookie",
				Name:        fmt.Sprintf("%s (%s)", name, hostKey),
				Description: fmt.Sprintf("Tracking cookie from %s", hostKey),
				Location:    browser.CookiePath,
				Browser:     browser.Name,
				Value:       fmt.Sprintf("name=%s, domain=%s, path=%s", name, hostKey, path),
				Removable:   true,
				AutoRemove:  severity == SeverityLow, // Only auto-remove low severity
			}

			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// scanFirefoxCookies scans Firefox cookies
func scanFirefoxCookies(browser Browser) ([]Finding, error) {
	findings := make([]Finding, 0)

	// Firefox uses profiles, need to find them
	profiles, err := os.ReadDir(browser.ProfilePath)
	if err != nil {
		return findings, err
	}

	for _, profile := range profiles {
		if !profile.IsDir() {
			continue
		}

		cookiePath := fmt.Sprintf("%s/%s/cookies.sqlite", browser.ProfilePath, profile.Name())
		if _, err := os.Stat(cookiePath); os.IsNotExist(err) {
			continue
		}

		db, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?mode=ro", cookiePath))
		if err != nil {
			continue
		}

		query := `SELECT host, name, path, creationTime, expiry FROM moz_cookies ORDER BY creationTime DESC`
		rows, err := db.Query(query)
		if err != nil {
			db.Close()
			continue
		}

		for rows.Next() {
			var host, name, path string
			var creationTime, expiry int64

			if err := rows.Scan(&host, &name, &path, &creationTime, &expiry); err != nil {
				continue
			}

			if isTrackingCookie(host, name) {
				severity := getSeverityForTracker(host, name)

				finding := Finding{
					Type:        FindingTypeCookie,
					Severity:    severity,
					Category:    "Tracking Cookie",
					Name:        fmt.Sprintf("%s (%s)", name, host),
					Description: fmt.Sprintf("Tracking cookie from %s", host),
					Location:    cookiePath,
					Browser:     browser.Name,
					Value:       fmt.Sprintf("name=%s, domain=%s, path=%s", name, host, path),
					Removable:   true,
					AutoRemove:  severity == SeverityLow,
				}

				findings = append(findings, finding)
			}
		}

		rows.Close()
		db.Close()
	}

	return findings, nil
}

// isTrackingCookie determines if a cookie is likely a tracking cookie
func isTrackingCookie(domain, name string) bool {
	domainLower := strings.ToLower(domain)
	nameLower := strings.ToLower(name)

	// Check against known tracking domains
	for _, tracker := range trackingDomains {
		if strings.Contains(domainLower, tracker) {
			return true
		}
	}

	// Check against known tracking cookie names
	for _, cookieName := range trackingCookieNames {
		if strings.HasPrefix(nameLower, strings.ToLower(cookieName)) {
			return true
		}
	}

	// Check for common tracking patterns
	trackingPatterns := []string{
		"_utm", "ga_", "_gac_", "_gid", "_hjid",
		"__qca", "_fbp", "_fbc", "uuid", "sess",
		"visitor", "tracking", "analytics",
	}

	for _, pattern := range trackingPatterns {
		if strings.Contains(nameLower, pattern) {
			return true
		}
	}

	return false
}

// getSeverityForTracker determines severity based on tracker type
func getSeverityForTracker(domain, name string) Severity {
	domainLower := strings.ToLower(domain)

	// High severity: Known aggressive trackers and fingerprinting
	highSeverityTrackers := []string{
		"facebook.com", "facebook.net", "doubleclick.net",
		"iovation.com", "threatmetrix.com", "maxmind.com",
		"acxiom.com", "datalogix.com", "bluekai.com",
	}

	for _, tracker := range highSeverityTrackers {
		if strings.Contains(domainLower, tracker) {
			return SeverityHigh
		}
	}

	// Medium severity: Ad networks and data brokers
	mediumSeverityTrackers := []string{
		"adnxs.com", "criteo.com", "pubmatic.com",
		"tapad.com", "liveramp.com",
	}

	for _, tracker := range mediumSeverityTrackers {
		if strings.Contains(domainLower, tracker) {
			return SeverityMedium
		}
	}

	// Low severity: General analytics
	return SeverityLow
}

// RemoveCookie removes a specific cookie from the database
func RemoveCookie(cookiePath, cookieName string) error {
	// Open database in read-write mode
	db, err := sql.Open("sqlite3", cookiePath)
	if err != nil {
		return fmt.Errorf("failed to open cookie database: %w", err)
	}
	defer db.Close()

	// Delete the cookie
	_, err = db.Exec("DELETE FROM cookies WHERE name = ?", cookieName)
	if err != nil {
		// Try Firefox schema
		_, err = db.Exec("DELETE FROM moz_cookies WHERE name = ?", cookieName)
	}

	return err
}
