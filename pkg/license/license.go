package license

import (
	"encoding/json"
	"fmt"
	"os"
)

const (
	FeatureAll             = "ALL"
	FeatureVSSRecovery     = "VSS_RECOVERY"
	FeatureADSStripping    = "ADS_STRIPPING"
	FeatureMFTRestoration  = "MFT_RESTORATION"
	FeatureJournalRollback = "JOURNAL_ROLLBACK"
	FeatureBootRepair      = "BOOT_REPAIR"
)

type License struct {
	ID       string   `json:"id"`
	Customer string   `json:"customer"`
	Features []string `json:"features"`
}

var activeLicense *License

// Load parses the license.json file and sets the active license globally.
func Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		activeLicense = nil
		return fmt.Errorf("failed to read license: %w", err)
	}

	var lic License
	if err := json.Unmarshal(data, &lic); err != nil {
		activeLicense = nil
		return fmt.Errorf("invalid license format: %w", err)
	}

	activeLicense = &lic
	return nil
}

// HasFeature returns true if the active license has the "ALL" feature or the specific feature requested.
func HasFeature(feature string) bool {
	if activeLicense == nil {
		return false
	}
	for _, f := range activeLicense.Features {
		if f == FeatureAll || f == feature {
			return true
		}
	}
	return false
}

// GetActive returns the currently loaded license or nil if none is loaded.
func GetActive() *License {
	return activeLicense
}
