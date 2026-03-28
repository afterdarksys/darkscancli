package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/afterdarksys/darkscan/pkg/config"
	"github.com/afterdarksys/darkscan/pkg/rules"
	"github.com/spf13/cobra"
)

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Manage YARA rule repositories",
	Long:  `Commands for managing YARA rule repositories and downloads.`,
}

var rulesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available YARA rule repositories",
	RunE:  runRulesList,
}

var rulesUpdateCmd = &cobra.Command{
	Use:   "update [repository]",
	Short: "Download/update YARA rules",
	Long:  `Download or update YARA rules from repositories. If no repository is specified, updates all enabled repositories.`,
	RunE:  runRulesUpdate,
}

var rulesInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show information about installed YARA rules",
	RunE:  runRulesInfo,
}

var rulesRemoveCmd = &cobra.Command{
	Use:   "remove [repository]",
	Short: "Remove downloaded YARA rules",
	Args:  cobra.ExactArgs(1),
	RunE:  runRulesRemove,
}

func init() {
	rulesCmd.AddCommand(rulesListCmd)
	rulesCmd.AddCommand(rulesUpdateCmd)
	rulesCmd.AddCommand(rulesInfoCmd)
	rulesCmd.AddCommand(rulesRemoveCmd)
}

func getRulesManager() (*rules.YARAManager, error) {
	darkscanDir, err := config.GetDarkscanDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get darkscan dir: %w", err)
	}

	rulesDir := filepath.Join(darkscanDir, "yara-rules")
	return rules.NewYARAManager(rulesDir)
}

func runRulesList(cmd *cobra.Command, args []string) error {
	rm, err := getRulesManager()
	if err != nil {
		return err
	}

	repos := rm.ListRepositories()

	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("AVAILABLE YARA RULE REPOSITORIES")
	fmt.Println(strings.Repeat("=", 80))

	for _, repo := range repos {
		status := "[ ]"
		if repo.Enabled {
			status = "[X]"
		}

		fmt.Printf("\n%s %s\n", status, repo.Name)
		fmt.Printf("    Description: %s\n", repo.Description)
		fmt.Printf("    URL: %s\n", repo.URL)
	}

	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("\nNote: Use 'darkscan rules update' to download enabled repositories")
	return nil
}

func runRulesUpdate(cmd *cobra.Command, args []string) error {
	rm, err := getRulesManager()
	if err != nil {
		return err
	}

	if len(args) == 0 {
		// Update all enabled repositories
		fmt.Println("Updating all enabled YARA rule repositories...")
		if err := rm.UpdateAll(); err != nil {
			return fmt.Errorf("update failed: %w", err)
		}
		fmt.Println("All repositories updated successfully")
	} else {
		// Update specific repository
		repoName := args[0]
		repos := rm.ListRepositories()

		var targetRepo *rules.YARARepository
		for _, repo := range repos {
			if repo.Name == repoName {
				targetRepo = &repo
				break
			}
		}

		if targetRepo == nil {
			return fmt.Errorf("repository not found: %s", repoName)
		}

		if err := rm.DownloadRepository(*targetRepo); err != nil {
			return fmt.Errorf("failed to download repository: %w", err)
		}
	}

	return nil
}

func runRulesInfo(cmd *cobra.Command, args []string) error {
	rm, err := getRulesManager()
	if err != nil {
		return err
	}

	count, err := rm.GetRuleCount()
	if err != nil {
		return fmt.Errorf("failed to count rules: %w", err)
	}

	rules, err := rm.GetInstalledRules()
	if err != nil {
		return fmt.Errorf("failed to get rules: %w", err)
	}

	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("YARA RULES INFORMATION")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("Total rule files: %d\n", count)

	if count > 0 && count <= 20 {
		fmt.Println("\nInstalled rules:")
		for _, rule := range rules {
			fmt.Printf("  - %s\n", rule)
		}
	} else if count > 20 {
		fmt.Println("\nSample installed rules (first 20):")
		for i, rule := range rules {
			if i >= 20 {
				break
			}
			fmt.Printf("  - %s\n", rule)
		}
		fmt.Printf("\n... and %d more\n", count-20)
	} else {
		fmt.Println("\nNo rules installed. Use 'darkscan rules update' to download rules.")
	}

	fmt.Println(strings.Repeat("=", 70))
	return nil
}

func runRulesRemove(cmd *cobra.Command, args []string) error {
	rm, err := getRulesManager()
	if err != nil {
		return err
	}

	repoName := args[0]

	fmt.Printf("Removing repository: %s\n", repoName)
	fmt.Print("Are you sure? (yes/no): ")

	var response string
	fmt.Scanln(&response)

	if strings.ToLower(response) != "yes" {
		fmt.Println("Removal cancelled.")
		return nil
	}

	if err := rm.RemoveRepository(repoName); err != nil {
		return fmt.Errorf("failed to remove repository: %w", err)
	}

	fmt.Printf("Repository '%s' removed successfully\n", repoName)
	return nil
}
