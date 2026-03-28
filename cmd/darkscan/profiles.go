package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/afterdarksys/darkscan/pkg/config"
	"github.com/afterdarksys/darkscan/pkg/profiles"
	"github.com/spf13/cobra"
)

var profilesCmd = &cobra.Command{
	Use:   "profiles",
	Short: "Manage scan profiles/presets",
	Long:  `Commands for managing scan configuration profiles and presets.`,
}

var profilesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available scan profiles",
	RunE:  runProfilesList,
}

var profilesShowCmd = &cobra.Command{
	Use:   "show [profile]",
	Short: "Show details of a scan profile",
	Args:  cobra.ExactArgs(1),
	RunE:  runProfilesShow,
}

var profilesDeleteCmd = &cobra.Command{
	Use:   "delete [profile]",
	Short: "Delete a custom scan profile",
	Args:  cobra.ExactArgs(1),
	RunE:  runProfilesDelete,
}

func init() {
	profilesCmd.AddCommand(profilesListCmd)
	profilesCmd.AddCommand(profilesShowCmd)
	profilesCmd.AddCommand(profilesDeleteCmd)
}

func getProfilesManager() (*profiles.Manager, error) {
	darkscanDir, err := config.GetDarkscanDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get darkscan dir: %w", err)
	}

	profilesDir := filepath.Join(darkscanDir, "profiles")
	return profiles.NewManager(profilesDir)
}

func runProfilesList(cmd *cobra.Command, args []string) error {
	pm, err := getProfilesManager()
	if err != nil {
		return err
	}

	profileList, err := pm.List()
	if err != nil {
		return fmt.Errorf("failed to list profiles: %w", err)
	}

	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("AVAILABLE SCAN PROFILES")
	fmt.Println(strings.Repeat("=", 80))

	// Group profiles
	builtIn := make([]profiles.ScanProfile, 0)
	custom := make([]profiles.ScanProfile, 0)

	for _, profile := range profileList {
		if _, ok := profiles.BuiltInProfiles[profile.Name]; ok {
			builtIn = append(builtIn, profile)
		} else {
			custom = append(custom, profile)
		}
	}

	if len(builtIn) > 0 {
		fmt.Println("\nBUILT-IN PROFILES:")
		for _, profile := range builtIn {
			fmt.Printf("  %-15s - %s\n", profile.Name, profile.Description)
		}
	}

	if len(custom) > 0 {
		fmt.Println("\nCUSTOM PROFILES:")
		for _, profile := range custom {
			fmt.Printf("  %-15s - %s\n", profile.Name, profile.Description)
		}
	}

	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("\nUsage: darkscan scan --profile <name> <path>")
	return nil
}

func runProfilesShow(cmd *cobra.Command, args []string) error {
	pm, err := getProfilesManager()
	if err != nil {
		return err
	}

	profileName := args[0]
	profile, err := pm.Load(profileName)
	if err != nil {
		return fmt.Errorf("failed to load profile: %w", err)
	}

	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("SCAN PROFILE: %s\n", profile.Name)
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("Description:      %s\n", profile.Description)
	fmt.Println(strings.Repeat("-", 70))
	fmt.Printf("Recursive:        %v\n", profile.Recursive)
	fmt.Printf("ClamAV:           %v\n", profile.EnableClamAV)
	fmt.Printf("YARA:             %v\n", profile.EnableYARA)
	fmt.Printf("CAPA:             %v\n", profile.EnableCAPA)
	fmt.Printf("Viper:            %v\n", profile.EnableViper)
	fmt.Printf("Document:         %v\n", profile.EnableDocument)
	fmt.Printf("Heuristics:       %v\n", profile.EnableHeuristics)
	fmt.Printf("Auto-Quarantine:  %v\n", profile.AutoQuarantine)
	if profile.YARARulesPath != "" {
		fmt.Printf("YARA Rules:       %s\n", profile.YARARulesPath)
	}
	if profile.CAPARulesPath != "" {
		fmt.Printf("CAPA Rules:       %s\n", profile.CAPARulesPath)
	}
	fmt.Println(strings.Repeat("=", 70))

	return nil
}

func runProfilesDelete(cmd *cobra.Command, args []string) error {
	pm, err := getProfilesManager()
	if err != nil {
		return err
	}

	profileName := args[0]

	fmt.Printf("Delete profile '%s'? (yes/no): ", profileName)
	var response string
	fmt.Scanln(&response)

	if strings.ToLower(response) != "yes" {
		fmt.Println("Deletion cancelled.")
		return nil
	}

	if err := pm.Delete(profileName); err != nil {
		return fmt.Errorf("failed to delete profile: %w", err)
	}

	fmt.Printf("Profile '%s' deleted successfully\n", profileName)
	return nil
}
