package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/afterdarksys/darkscan/pkg/config"
	"github.com/afterdarksys/darkscan/pkg/quarantine"
	"github.com/spf13/cobra"
)

var (
	quarantineRestorePath string
)

var quarantineCmd = &cobra.Command{
	Use:   "quarantine",
	Short: "Manage quarantined files",
	Long:  `Commands for managing the file quarantine system.`,
}

var quarantineListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all quarantined files",
	RunE:  runQuarantineList,
}

var quarantineRestoreCmd = &cobra.Command{
	Use:   "restore [id]",
	Short: "Restore a quarantined file",
	Args:  cobra.ExactArgs(1),
	RunE:  runQuarantineRestore,
}

var quarantineDeleteCmd = &cobra.Command{
	Use:   "delete [id]",
	Short: "Permanently delete a quarantined file",
	Args:  cobra.ExactArgs(1),
	RunE:  runQuarantineDelete,
}

var quarantineInfoCmd = &cobra.Command{
	Use:   "info [id]",
	Short: "Show detailed information about a quarantined file",
	Args:  cobra.ExactArgs(1),
	RunE:  runQuarantineInfo,
}

func init() {
	quarantineRestoreCmd.Flags().StringVarP(&quarantineRestorePath, "path", "p", "", "Restore to specific path (default: original location)")

	quarantineCmd.AddCommand(quarantineListCmd)
	quarantineCmd.AddCommand(quarantineRestoreCmd)
	quarantineCmd.AddCommand(quarantineDeleteCmd)
	quarantineCmd.AddCommand(quarantineInfoCmd)
}

func getQuarantineManager() (*quarantine.Manager, error) {
	darkscanDir, err := config.GetDarkscanDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get darkscan dir: %w", err)
	}

	quarantineDir := filepath.Join(darkscanDir, "quarantine")
	return quarantine.New(quarantineDir)
}

func runQuarantineList(cmd *cobra.Command, args []string) error {
	qm, err := getQuarantineManager()
	if err != nil {
		return err
	}

	entries, err := qm.List()
	if err != nil {
		return fmt.Errorf("failed to list quarantine: %w", err)
	}

	if len(entries) == 0 {
		fmt.Println("No files in quarantine.")
		return nil
	}

	fmt.Printf("%-25s %-50s %-15s %s\n", "ID", "ORIGINAL PATH", "SIZE", "THREATS")
	fmt.Println(strings.Repeat("-", 120))

	for _, entry := range entries {
		path := entry.OriginalPath
		if len(path) > 48 {
			path = "..." + path[len(path)-45:]
		}

		threats := strings.Join(entry.Threats, ", ")
		if len(threats) > 30 {
			threats = threats[:27] + "..."
		}

		fmt.Printf("%-25s %-50s %-15s %s\n",
			entry.ID,
			path,
			formatBytes(entry.FileSize),
			threats,
		)
	}

	fmt.Printf("\nTotal: %d files in quarantine\n", len(entries))
	return nil
}

func runQuarantineRestore(cmd *cobra.Command, args []string) error {
	qm, err := getQuarantineManager()
	if err != nil {
		return err
	}

	id := args[0]

	// Get entry info for confirmation
	entry, err := qm.GetEntry(id)
	if err != nil {
		return fmt.Errorf("failed to get entry: %w", err)
	}

	restorePath := quarantineRestorePath
	if restorePath == "" {
		restorePath = entry.OriginalPath
	}

	fmt.Printf("Restoring quarantined file:\n")
	fmt.Printf("  ID:       %s\n", entry.ID)
	fmt.Printf("  Original: %s\n", entry.OriginalPath)
	fmt.Printf("  Restore:  %s\n", restorePath)
	fmt.Printf("  Threats:  %s\n", strings.Join(entry.Threats, ", "))
	fmt.Printf("\nWARNING: This file was quarantined due to detected threats.\n")
	fmt.Printf("Are you sure you want to restore it? (yes/no): ")

	var response string
	fmt.Scanln(&response)

	if strings.ToLower(response) != "yes" {
		fmt.Println("Restore cancelled.")
		return nil
	}

	if err := qm.Restore(id, restorePath); err != nil {
		return fmt.Errorf("failed to restore file: %w", err)
	}

	fmt.Printf("File restored to: %s\n", restorePath)
	return nil
}

func runQuarantineDelete(cmd *cobra.Command, args []string) error {
	qm, err := getQuarantineManager()
	if err != nil {
		return err
	}

	id := args[0]

	// Get entry info for confirmation
	entry, err := qm.GetEntry(id)
	if err != nil {
		return fmt.Errorf("failed to get entry: %w", err)
	}

	fmt.Printf("Permanently delete quarantined file:\n")
	fmt.Printf("  ID:       %s\n", entry.ID)
	fmt.Printf("  Original: %s\n", entry.OriginalPath)
	fmt.Printf("  Threats:  %s\n", strings.Join(entry.Threats, ", "))
	fmt.Printf("\nWARNING: This action cannot be undone.\n")
	fmt.Printf("Are you sure? (yes/no): ")

	var response string
	fmt.Scanln(&response)

	if strings.ToLower(response) != "yes" {
		fmt.Println("Delete cancelled.")
		return nil
	}

	if err := qm.Delete(id); err != nil {
		return fmt.Errorf("failed to delete file: %w", err)
	}

	fmt.Println("Quarantined file permanently deleted.")
	return nil
}

func runQuarantineInfo(cmd *cobra.Command, args []string) error {
	qm, err := getQuarantineManager()
	if err != nil {
		return err
	}

	id := args[0]

	entry, err := qm.GetEntry(id)
	if err != nil {
		return fmt.Errorf("failed to get entry: %w", err)
	}

	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("QUARANTINE ENTRY DETAILS")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("ID:               %s\n", entry.ID)
	fmt.Printf("Original Path:    %s\n", entry.OriginalPath)
	fmt.Printf("Quarantined At:   %s\n", entry.QuarantinedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("File Hash:        %s\n", entry.FileHash)
	fmt.Printf("File Size:        %s\n", formatBytes(entry.FileSize))
	fmt.Printf("Threats:          %s\n", strings.Join(entry.Threats, ", "))
	if entry.DetectionInfo != "" {
		fmt.Printf("Detection Info:   %s\n", entry.DetectionInfo)
	}
	fmt.Println(strings.Repeat("=", 70))

	return nil
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
