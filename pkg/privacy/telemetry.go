package privacy

import (
	"fmt"
	"runtime"
)

// ScanTelemetry scans for Windows telemetry and tracking
func (s *Scanner) ScanTelemetry() ([]Finding, error) {
	findings := make([]Finding, 0)

	// Only scan on Windows
	if runtime.GOOS != "windows" {
		return findings, nil
	}

	// Check Windows telemetry services
	findings = append(findings, scanWindowsTelemetryServices()...)

	// Check scheduled tasks
	findings = append(findings, scanTelemetryTasks()...)

	// Check registry tracking entries
	findings = append(findings, scanRegistryTracking()...)

	return findings, nil
}

// scanWindowsTelemetryServices checks Windows telemetry services
func scanWindowsTelemetryServices() []Finding {
	findings := make([]Finding, 0)

	// Known Windows telemetry services
	telemetryServices := map[string]string{
		"DiagTrack":        "Connected User Experiences and Telemetry",
		"dmwappushservice": "Device Management Wireless Application Protocol",
		"RetailDemo":       "Retail Demo Service",
		"Fax":              "Fax Service (rarely used, potential tracking)",
		"WerSvc":           "Windows Error Reporting Service",
		"WSearch":          "Windows Search (can track searches)",
	}

	for service, desc := range telemetryServices {
		// Note: Actual service checking would require Windows API calls
		// This is a placeholder - full implementation would check service status
		finding := Finding{
			Type:        FindingTypeTelemetry,
			Severity:    SeverityMedium,
			Category:    "Windows Telemetry Service",
			Name:        service,
			Description: fmt.Sprintf("%s - May collect usage data", desc),
			Location:    "Services",
			Browser:     "Windows",
			Value:       service,
			Removable:   true,
			AutoRemove:  false,
		}

		findings = append(findings, finding)
	}

	return findings
}

// scanTelemetryTasks checks scheduled tasks that may track
func scanTelemetryTasks() []Finding {
	findings := make([]Finding, 0)

	// Known telemetry tasks
	telemetryTasks := []string{
		"Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser",
		"Microsoft\\Windows\\Application Experience\\ProgramDataUpdater",
		"Microsoft\\Windows\\Autochk\\Proxy",
		"Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator",
		"Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip",
		"Microsoft\\Windows\\DiskDiagnostic\\Microsoft-Windows-DiskDiagnosticDataCollector",
	}

	for _, task := range telemetryTasks {
		finding := Finding{
			Type:        FindingTypeTelemetry,
			Severity:    SeverityLow,
			Category:    "Telemetry Scheduled Task",
			Name:        task,
			Description: "Scheduled task for data collection",
			Location:    "Task Scheduler",
			Browser:     "Windows",
			Value:       task,
			Removable:   true,
			AutoRemove:  false,
		}

		findings = append(findings, finding)
	}

	return findings
}

// scanRegistryTracking checks registry for tracking entries
func scanRegistryTracking() []Finding {
	findings := make([]Finding, 0)

	// Known registry tracking locations
	trackingKeys := map[string]string{
		"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection": "Telemetry Settings",
		"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection":                 "Data Collection Policy",
		"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo":          "Advertising ID",
	}

	for key, desc := range trackingKeys {
		finding := Finding{
			Type:        FindingTypeRegistry,
			Severity:    SeverityInfo,
			Category:    "Registry Tracking Entry",
			Name:        desc,
			Description: "Registry key used for tracking configuration",
			Location:    key,
			Browser:     "Windows",
			Value:       key,
			Removable:   false, // Registry edits are risky
			AutoRemove:  false,
		}

		findings = append(findings, finding)
	}

	return findings
}

// DisableTelemetry attempts to disable a telemetry service/task
func DisableTelemetry(finding Finding) error {
	// Note: This would require Windows-specific implementation
	// using syscall or external commands like:
	// - sc.exe for services
	// - schtasks.exe for scheduled tasks
	// - reg.exe for registry

	return fmt.Errorf("telemetry disabling not yet implemented for this platform")
}
