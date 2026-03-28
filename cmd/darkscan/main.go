package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/afterdarktech/darkscan/pkg/api/client"
	"golang.org/x/term"

	"github.com/afterdarktech/darkscan/pkg/capa"
	"github.com/afterdarktech/darkscan/pkg/clamav"
	"github.com/afterdarktech/darkscan/pkg/config"
	"github.com/afterdarktech/darkscan/pkg/document"
	"github.com/afterdarktech/darkscan/pkg/forensics"
	"github.com/afterdarktech/darkscan/pkg/heuristics"
	"github.com/afterdarktech/darkscan/pkg/license"
	"github.com/afterdarktech/darkscan/pkg/quarantine"
	"github.com/afterdarktech/darkscan/pkg/scanner"
	"github.com/afterdarktech/darkscan/pkg/store"
	"github.com/afterdarktech/darkscan/pkg/vfs/local"
	"github.com/afterdarktech/darkscan/pkg/vfs/nfs"
	"github.com/afterdarktech/darkscan/pkg/vfs/ntfs"
	"github.com/afterdarktech/darkscan/pkg/vfs/s3"
	"github.com/afterdarktech/darkscan/pkg/viper"
	"github.com/afterdarktech/darkscan/pkg/yara"
	"github.com/spf13/cobra"
)

var (
	configPath        string
	licensePath       string
	outputFormat      string
	outputFile        string
	scanProfile       string
	verbose           bool
	recursive         bool
	enableClamAV      bool
	enableYARA        bool
	enableCAPA        bool
	enableViper       bool
	enableDocument    bool
	enableHeuristics  bool
	autoQuarantine    bool
	yaraRulesPath     string
	capaRulesPath     string
)

var rootCmd = &cobra.Command{
	Use:   "darkscan",
	Short: "DarkScan - Multi-engine malware scanner",
	Long: `DarkScan is an open-source CLI malware scanner that integrates multiple
detection engines including ClamAV, YARA, CAPA, and Viper framework.`,
	Version: "1.0.0",
}

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan a file or directory",
	Args:  cobra.ExactArgs(1),
	RunE:  runScan,
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize configuration file",
	RunE:  runInit,
}

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update scan engine definitions",
	RunE:  runUpdate,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Run:   runVersion,
}

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Manage DarkScan daemon",
	Long:  "Commands for managing the DarkScan daemon service",
}

var daemonStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Get daemon status",
	Long:  "Retrieve status information from the running DarkScan daemon",
	RunE:  runDaemonStatus,
}

var daemonUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update daemon engines",
	Long:  "Trigger manual update of scanning engines in the DarkScan daemon",
	RunE:  runDaemonUpdate,
}

func init() {
	defaultConfigPath, _ := config.GetDefaultConfigPath()

	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", defaultConfigPath, "Config file path")
	rootCmd.PersistentFlags().StringVarP(&licensePath, "license", "l", "license.json", "Commercial license file path")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "text", "Output format (text, json, csv, xml)")
	rootCmd.PersistentFlags().StringVar(&outputFile, "output-file", "", "Output file for export formats (default: stdout)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	scanCmd.Flags().StringVarP(&scanProfile, "profile", "p", "", "Use a scan profile (quick, thorough, forensic, safe, or custom)")
	scanCmd.Flags().BoolVarP(&recursive, "recursive", "r", true, "Scan directories recursively")
	scanCmd.Flags().BoolVar(&enableClamAV, "clamav", true, "Enable ClamAV engine")
	scanCmd.Flags().BoolVar(&enableYARA, "yara", false, "Enable YARA engine")
	scanCmd.Flags().BoolVar(&enableCAPA, "capa", false, "Enable CAPA engine")
	scanCmd.Flags().BoolVar(&enableViper, "viper", false, "Enable Viper engine")
	scanCmd.Flags().BoolVar(&enableDocument, "document", true, "Enable Document parsing engine")
	scanCmd.Flags().BoolVar(&enableHeuristics, "heuristics", true, "Enable Heuristics engine")
	scanCmd.Flags().BoolVarP(&autoQuarantine, "quarantine", "q", false, "Automatically quarantine infected files")
	scanCmd.Flags().StringVar(&yaraRulesPath, "yara-rules", "", "Path to YARA rules")
	scanCmd.Flags().StringVar(&capaRulesPath, "capa-rules", "", "Path to CAPA rules")

	daemonCmd.AddCommand(daemonStatusCmd)
	daemonCmd.AddCommand(daemonUpdateCmd)

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(updateCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(historyCmd)
	rootCmd.AddCommand(searchCmd)
	rootCmd.AddCommand(hashCmd)
	rootCmd.AddCommand(quarantineCmd)
	rootCmd.AddCommand(rulesCmd)
	rootCmd.AddCommand(forensicsCmd)
	rootCmd.AddCommand(profilesCmd)
	rootCmd.AddCommand(identifyCmd)
	rootCmd.AddCommand(privacyCmd)
	rootCmd.AddCommand(daemonCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	path := args[0]

	// Load potential license file
	if err := license.Load(licensePath); err != nil {
		if verbose {
			fmt.Printf("Warning: Could not load license (%v). Advanced capabilities will be restricted.\n", err)
		}
	} else if verbose {
		fmt.Printf("Commercial license loaded (Customer: %s)\n", license.GetActive().Customer)
	}

	// Load profile if specified
	if scanProfile != "" {
		pm, err := getProfilesManager()
		if err != nil {
			return fmt.Errorf("failed to get profiles manager: %w", err)
		}

		profile, err := pm.Load(scanProfile)
		if err != nil {
			return fmt.Errorf("failed to load profile: %w", err)
		}

		// Apply profile settings (only if flags weren't explicitly set)
		if !cmd.Flags().Changed("recursive") {
			recursive = profile.Recursive
		}
		if !cmd.Flags().Changed("clamav") {
			enableClamAV = profile.EnableClamAV
		}
		if !cmd.Flags().Changed("yara") {
			enableYARA = profile.EnableYARA
		}
		if !cmd.Flags().Changed("capa") {
			enableCAPA = profile.EnableCAPA
		}
		if !cmd.Flags().Changed("viper") {
			enableViper = profile.EnableViper
		}
		if !cmd.Flags().Changed("document") {
			enableDocument = profile.EnableDocument
		}
		if !cmd.Flags().Changed("heuristics") {
			enableHeuristics = profile.EnableHeuristics
		}
		if !cmd.Flags().Changed("quarantine") {
			autoQuarantine = profile.AutoQuarantine
		}
		if !cmd.Flags().Changed("yara-rules") && profile.YARARulesPath != "" {
			yaraRulesPath = profile.YARARulesPath
		}
		if !cmd.Flags().Changed("capa-rules") && profile.CAPARulesPath != "" {
			capaRulesPath = profile.CAPARulesPath
		}

		if verbose {
			fmt.Printf("Using profile: %s\n", profile.Name)
		}
	}

	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Try Daemon Connection
	daemonURL := ""
	if cfg.Daemon.DaemonEndpoint != "" {
		daemonURL = cfg.Daemon.DaemonEndpoint
	}

	// Parse timeouts from config
	requestTimeout, err := time.ParseDuration(cfg.Daemon.RequestTimeout)
	if err != nil {
		requestTimeout = 1 * time.Hour
	}
	connectTimeout, err := time.ParseDuration(cfg.Daemon.ConnectTimeout)
	if err != nil {
		connectTimeout = 3 * time.Second
	}

	dsClient, daemonErr := client.NewClient(daemonURL, "", requestTimeout, connectTimeout)
	if daemonErr == nil && dsClient != nil {
		if verbose {
			fmt.Println("Connected to DarkScan daemon, routing scan request...")
		}
		
		scanStart := time.Now()
		
		// If it's a remote URL like S3, might want to stream it, but for MVP we send Path
		// A fully robust implementation would parse s3:// and stream the bytes, or rely on daemon to mount it
		results, err := dsClient.ScanLocal(path, recursive)
		if err != nil {
			return fmt.Errorf("scan failed via daemon: %w", err)
		}
		
		printResults(results, time.Since(scanStart))
		return nil
	} else if !cfg.Daemon.AutoFallback {
		return fmt.Errorf("daemon not found and auto_fallback is disabled: %v", daemonErr)
	}

	if verbose {
		fmt.Printf("Daemon connect failed (%v), falling back to standalone engine initialization...\n", daemonErr)
	}

	s := scanner.New()

	// VFS Storage Provider Route Setup
	if strings.HasPrefix(path, "s3://") {
		parts := strings.SplitN(strings.TrimPrefix(path, "s3://"), "/", 2)
		bucket := parts[0]
		key := ""
		if len(parts) > 1 {
			key = parts[1]
		}
		fs, err := s3.New(context.Background(), bucket)
		if err != nil {
			return fmt.Errorf("failed to setup s3 vfs: %w", err)
		}
		s.SetVFS(fs)
		path = key // Update path correctly
		fmt.Printf("Connected to AWS S3 bucket: %s\n", bucket)
	} else if strings.HasPrefix(path, "nfs://") {
		parts := strings.SplitN(strings.TrimPrefix(path, "nfs://"), "/", 2)
		host := parts[0]
		mount := "/"
		if len(parts) > 1 {
			mount = "/" + parts[1]
		}
		fs, err := nfs.New(host, mount)
		if err != nil {
			return fmt.Errorf("failed to setup nfs vfs: %w", err)
		}
		s.SetVFS(fs)
		path = "/" // Root of the mount
		fmt.Printf("Connected to NFS Target: %s@%s\n", mount, host)
	} else if strings.HasPrefix(path, "ntfs://") {
		imgPath := strings.TrimPrefix(path, "ntfs://")
		part, err := local.NewPartition(imgPath)
		if err != nil {
			return fmt.Errorf("failed to open ntfs source: %w", err)
		}
		fs, err := ntfs.New(part)
		if err != nil {
			return fmt.Errorf("failed to setup ntfs vfs: %w", err)
		}
		s.SetVFS(fs)
		path = "/"
		fmt.Printf("Connected to NTFS Raw Partition: %s\n", imgPath)
	} else {
		s.SetVFS(local.New())
	}

	s.SetPasswordCallback(func(p string) (string, error) {
		fmt.Printf("\n[SECURE PROMPT] Encrypted volume/archive detected (%s)\n", path)
		fmt.Print("Enter decryption password: ")
		bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return "", err
		}
		return string(bytePassword), nil
	})

	if enableDocument {
		if verbose {
			fmt.Println("Initializing Document engine...")
		}
		docEngine := document.New()
		s.RegisterEngine(docEngine)
		defer docEngine.Close()
	}

	if enableClamAV && cfg.ClamAV.Enabled {
		if verbose {
			fmt.Println("Initializing ClamAV engine...")
		}
		clamavEngine, err := clamav.New(cfg.ClamAV.DatabasePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to initialize ClamAV: %v\n", err)
		} else {
			s.RegisterEngine(clamavEngine)
			defer clamavEngine.Close()
		}
	}

	if enableYARA && cfg.YARA.Enabled {
		rulesPath := yaraRulesPath
		if rulesPath == "" {
			rulesPath = cfg.YARA.RulesPath
		}
		if rulesPath != "" {
			if verbose {
				fmt.Println("Initializing YARA engine...")
			}
			yaraEngine, err := yara.New(rulesPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Failed to initialize YARA: %v\n", err)
			} else {
				s.RegisterEngine(yaraEngine)
				defer yaraEngine.Close()
			}
		}
	}

	if enableCAPA && cfg.CAPA.Enabled {
		if verbose {
			fmt.Println("Initializing CAPA engine...")
		}
		capaRules := capaRulesPath
		if capaRules == "" {
			capaRules = cfg.CAPA.RulesPath
		}
		capaEngine, err := capa.New(cfg.CAPA.ExePath, capaRules)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to initialize CAPA: %v\n", err)
		} else {
			s.RegisterEngine(capaEngine)
			defer capaEngine.Close()
		}
	}

	if enableViper && cfg.Viper.Enabled {
		if verbose {
			fmt.Println("Initializing Viper engine...")
		}
		viperEngine, err := viper.New(cfg.Viper.ExePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to initialize Viper: %v\n", err)
		} else {
			viperEngine.SetProject(cfg.Viper.ProjectName)
			s.RegisterEngine(viperEngine)
			defer viperEngine.Close()
		}
	}

	if enableHeuristics {
		if verbose {
			fmt.Println("Initializing Heuristics engine...")
		}
		heuristicsEngine := heuristics.New()
		s.RegisterEngine(heuristicsEngine)
		defer heuristicsEngine.Close()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nReceived interrupt signal, stopping scan...")
		cancel()
	}()

	db, dbErr := store.New(getStorePath())
	if dbErr == nil {
		db.Cleanup(6)
		defer db.Close()
	}

	startTime := time.Now()
	var results []*scanner.ScanResult

	var info os.FileInfo
	var statErr error
	if s.FS != nil {
		info, statErr = s.FS.Stat(path)
	} else {
		info, statErr = os.Stat(path)
	}

	if statErr != nil {
		return fmt.Errorf("failed to access path: %w", statErr)
	}

	if info.IsDir() {
		if verbose {
			fmt.Printf("Scanning directory: %s (recursive: %v)\n", path, recursive)
		}
		results, err = s.ScanDirectory(ctx, path, recursive)
	} else {
		if verbose {
			fmt.Printf("Scanning file: %s\n", path)
		}
		results, err = s.ScanFile(ctx, path)
	}

	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	duration := time.Since(startTime)

	// Initialize quarantine manager if auto-quarantine is enabled
	var qm *quarantine.Manager
	if autoQuarantine {
		darkscanDir, err := config.GetDarkscanDir()
		if err == nil {
			quarantineDir := filepath.Join(darkscanDir, "quarantine")
			qm, _ = quarantine.New(quarantineDir)
		}
	}

	if db != nil && len(results) > 0 {
		analyzer := forensics.NewAnalyzer(100) // 100MB threshold

		for _, r := range results {
			threats := ""
			threatList := make([]string, 0)
			for i, t := range r.Threats {
				if i > 0 {
					threats += ","
				}
				threats += t.Name
				threatList = append(threatList, t.Name)
			}

			// Calculate file hashes for hash cache
			var fileHash string
			features, err := analyzer.Analyze(r.FilePath)
			if err == nil && features != nil {
				fileHash = features.SHA256

				// Update hash cache
				db.UpdateHashCache(store.HashCacheEntry{
					Hash:     fileHash,
					MD5:      features.MD5,
					SHA1:     features.SHA1,
					SHA256:   features.SHA256,
					FileSize: features.Size,
					Infected: r.Infected,
					Threats:  threats,
				})
			}

			// Quarantine infected files if auto-quarantine is enabled
			if autoQuarantine && r.Infected && qm != nil {
				detectionInfo := fmt.Sprintf("Detected by %s", r.ScanEngine)
				_, qErr := qm.Quarantine(r.FilePath, threatList, detectionInfo)
				if qErr != nil {
					fmt.Fprintf(os.Stderr, "Warning: Failed to quarantine %s: %v\n", r.FilePath, qErr)
				} else if verbose {
					fmt.Printf("Quarantined: %s\n", r.FilePath)
				}
			}

			// Record in scan history
			db.RecordScan(store.ScanRecord{
				FilePath: r.FilePath,
				Infected: r.Infected,
				Threats:  threats,
				ScanTime: time.Now(),
				FileHash: fileHash,
			})
		}
	}

	printResults(results, duration)

	return nil
}

func runInit(cmd *cobra.Command, args []string) error {
	if configPath == "" {
		var err error
		configPath, err = config.GetDefaultConfigPath()
		if err != nil {
			return fmt.Errorf("failed to determine config path: %w", err)
		}
	}

	if _, err := os.Stat(configPath); err == nil {
		return fmt.Errorf("config file already exists at %s", configPath)
	}

	if err := config.InitConfig(configPath); err != nil {
		return fmt.Errorf("failed to initialize config: %w", err)
	}

	fmt.Printf("Configuration file created at: %s\n", configPath)
	fmt.Println("\nEdit this file to customize your scan settings.")

	return nil
}

func runUpdate(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	s := scanner.New()

	if cfg.ClamAV.Enabled {
		clamavEngine, err := clamav.New(cfg.ClamAV.DatabasePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to initialize ClamAV: %v\n", err)
		} else {
			s.RegisterEngine(clamavEngine)
			defer clamavEngine.Close()
		}
	}

	fmt.Println("Updating scan engine definitions...")

	ctx := context.Background()
	if err := s.UpdateEngines(ctx); err != nil {
		return fmt.Errorf("update failed: %w", err)
	}

	fmt.Println("Update completed successfully")

	return nil
}

func runVersion(cmd *cobra.Command, args []string) {
	fmt.Printf("DarkScan v%s\n", rootCmd.Version)
	fmt.Println("\nIntegrated Engines:")

	clamavVersion := clamav.GetVersion()
	fmt.Printf("  ClamAV: %s\n", clamavVersion)

	if capaVersion, err := capa.GetVersion(); err == nil {
		fmt.Printf("  CAPA: %s\n", capaVersion)
	} else {
		fmt.Printf("  CAPA: not installed\n")
	}

	fmt.Printf("  YARA: go-yara/v4\n")
	fmt.Printf("  Viper: Framework integration\n")
}

func loadConfig() (*config.Config, error) {
	if configPath == "" {
		var err error
		configPath, err = config.GetDefaultConfigPath()
		if err != nil {
			return nil, err
		}
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

type JSONThreat struct {
	Engine      string `json:"engine"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

type JSONFileResult struct {
	FilePath string       `json:"file_path"`
	Infected bool         `json:"infected"`
	Threats  []JSONThreat `json:"threats,omitempty"`
	Error    string       `json:"error,omitempty"`
}

type JSONScanOutput struct {
	Summary struct {
		TotalFiles    int    `json:"total_files"`
		InfectedFiles int    `json:"infected_files"`
		CleanFiles    int    `json:"clean_files"`
		Errors        int    `json:"errors"`
		ScanDuration  string `json:"scan_duration"`
	} `json:"summary"`
	Results []JSONFileResult `json:"results"`
}

func printResults(results []*scanner.ScanResult, duration time.Duration) {
	// Handle export formats
	format := ExportFormat(outputFormat)
	if format == FormatJSON || format == FormatCSV || format == FormatXML {
		if err := ExportResults(results, format, outputFile, duration); err != nil {
			fmt.Fprintf(os.Stderr, "Export error: %v\n", err)
		}
		return
	}

	infected := 0
	clean := 0
	errors := 0

	threatsByFile := make(map[string][]scanner.Threat)

	for _, result := range results {
		if result.Error != nil {
			errors++
			continue
		}

		if result.Infected {
			infected++
			threatsByFile[result.FilePath] = append(threatsByFile[result.FilePath], result.Threats...)
		} else {
			clean++
		}
	}

	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("SCAN RESULTS")
	fmt.Println(strings.Repeat("=", 70))

	if len(threatsByFile) > 0 {
		fmt.Println("\nTHREATS DETECTED:")
		for filePath, threats := range threatsByFile {
			fmt.Printf("\n[!] %s\n", filePath)
			for _, threat := range threats {
				fmt.Printf("    ├─ Engine: %s\n", threat.Engine)
				fmt.Printf("    ├─ Threat: %s\n", threat.Name)
				fmt.Printf("    ├─ Severity: %s\n", strings.ToUpper(threat.Severity))
				fmt.Printf("    └─ Description: %s\n", threat.Description)
			}
		}
	}

	fmt.Println("\n" + strings.Repeat("-", 70))
	fmt.Println("SUMMARY")
	fmt.Println(strings.Repeat("-", 70))
	fmt.Printf("Files scanned:   %d\n", len(results))
	fmt.Printf("Threats found:   %d\n", infected)
	fmt.Printf("Clean:           %d\n", clean)
	fmt.Printf("Errors:          %d\n", errors)
	fmt.Printf("Scan duration:   %s\n", duration.Round(time.Millisecond))
	fmt.Println(strings.Repeat("=", 70))
}

func printJSONResults(results []*scanner.ScanResult, duration time.Duration) {
	output := JSONScanOutput{}
	output.Results = make([]JSONFileResult, 0)

	infected := 0
	clean := 0
	errors := 0

	for _, result := range results {
		fileResult := JSONFileResult{
			FilePath: result.FilePath,
			Infected: result.Infected,
		}

		if result.Error != nil {
			errors++
			fileResult.Error = result.Error.Error()
		} else if result.Infected {
			infected++
			fileResult.Threats = make([]JSONThreat, 0, len(result.Threats))
			for _, threat := range result.Threats {
				fileResult.Threats = append(fileResult.Threats, JSONThreat{
					Engine:      threat.Engine,
					Name:        threat.Name,
					Severity:    threat.Severity,
					Description: threat.Description,
				})
			}
		} else {
			clean++
		}

		output.Results = append(output.Results, fileResult)
	}

	output.Summary.TotalFiles = len(results)
	output.Summary.InfectedFiles = infected
	output.Summary.CleanFiles = clean
	output.Summary.Errors = errors
	output.Summary.ScanDuration = duration.Round(time.Millisecond).String()

	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(jsonData))
}

func runDaemonStatus(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Parse timeouts from config
	requestTimeout, err := time.ParseDuration(cfg.Daemon.RequestTimeout)
	if err != nil {
		requestTimeout = 1 * time.Hour
	}
	connectTimeout, err := time.ParseDuration(cfg.Daemon.ConnectTimeout)
	if err != nil {
		connectTimeout = 3 * time.Second
	}

	dsClient, err := client.NewClient(cfg.Daemon.DaemonEndpoint, "", requestTimeout, connectTimeout)
	if err != nil {
		return fmt.Errorf("failed to connect to daemon: %w", err)
	}

	status, err := dsClient.GetStatus()
	if err != nil {
		return fmt.Errorf("failed to get status: %w", err)
	}

	// Pretty print the status
	fmt.Printf("Daemon Status: %s\n", status.Status)
	fmt.Printf("Version: %s\n", status.Version)
	fmt.Printf("Uptime: %s\n", status.Uptime)
	fmt.Printf("\nEngines:\n")
	for _, engine := range status.Engines {
		fmt.Printf("  - %s: ", engine.Name)
		if engine.Enabled {
			fmt.Printf("enabled")
			if engine.Version != "" {
				fmt.Printf(" (version: %s)", engine.Version)
			}
			if engine.LastUpdate != "" {
				fmt.Printf(" [last update: %s]", engine.LastUpdate)
			}
			fmt.Println()
		} else {
			fmt.Println("disabled")
		}
	}

	return nil
}

func runDaemonUpdate(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Parse timeouts from config
	requestTimeout, err := time.ParseDuration(cfg.Daemon.RequestTimeout)
	if err != nil {
		requestTimeout = 1 * time.Hour
	}
	connectTimeout, err := time.ParseDuration(cfg.Daemon.ConnectTimeout)
	if err != nil {
		connectTimeout = 3 * time.Second
	}

	dsClient, err := client.NewClient(cfg.Daemon.DaemonEndpoint, "", requestTimeout, connectTimeout)
	if err != nil {
		return fmt.Errorf("failed to connect to daemon: %w", err)
	}

	fmt.Println("Triggering daemon engine update...")
	if err := dsClient.TriggerUpdate(); err != nil {
		return fmt.Errorf("update failed: %w", err)
	}

	fmt.Println("Engines updated successfully")
	return nil
}
