package license

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLicenseEnforcement(t *testing.T) {
	tmpDir := t.TempDir()
	
	validPath := filepath.Join(tmpDir, "valid_license.json")
	os.WriteFile(validPath, []byte(`{
		"id": "LIC-12345",
		"customer": "TestCorp",
		"features": ["VSS_RECOVERY", "ADS_STRIPPING"]
	}`), 0644)

	err := Load(validPath)
	if err != nil {
		t.Fatalf("Failed to load valid license: %v", err)
	}

	if GetActive() == nil || GetActive().Customer != "TestCorp" {
		t.Fatalf("Loaded license data is incorrect")
	}

	// Should have VSS
	if !HasFeature(FeatureVSSRecovery) {
		t.Errorf("Expected VSS_RECOVERY to be enabled")
	}

	// Should NOT have Boot Repair
	if HasFeature(FeatureBootRepair) {
		t.Errorf("Expected BOOT_REPAIR to be disabled")
	}

	allAccessPath := filepath.Join(tmpDir, "all_access_license.json")
	os.WriteFile(allAccessPath, []byte(`{
		"id": "LIC-MASTER",
		"customer": "Admin",
		"features": ["ALL"]
	}`), 0644)

	Load(allAccessPath)
	if !HasFeature(FeatureBootRepair) {
		t.Errorf("Expected ALL feature to unlock BOOT_REPAIR")
	}
}
