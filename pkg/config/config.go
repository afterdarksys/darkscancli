package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Config struct {
	ClamAV     ClamAVConfig     `json:"clamav"`
	YARA       YARAConfig       `json:"yara"`
	CAPA       CAPAConfig       `json:"capa"`
	Viper      ViperConfig      `json:"viper"`
	DarkAPI    DarkAPIConfig    `json:"darkapi"`
	FileHashes FileHashesConfig `json:"filehashes"`
	Scan       ScanConfig       `json:"scan"`
}

type ClamAVConfig struct {
	Enabled      bool   `json:"enabled"`
	DatabasePath string `json:"database_path"`
	AutoUpdate   bool   `json:"auto_update"`
}

type YARAConfig struct {
	Enabled   bool   `json:"enabled"`
	RulesPath string `json:"rules_path"`
}

type CAPAConfig struct {
	Enabled   bool   `json:"enabled"`
	ExePath   string `json:"exe_path"`
	RulesPath string `json:"rules_path"`
}

type ViperConfig struct {
	Enabled     bool   `json:"enabled"`
	ExePath     string `json:"exe_path"`
	ProjectName string `json:"project_name"`
}

type DarkAPIConfig struct {
	Enabled            bool                     `json:"enabled"`
	APIKey             string                   `json:"api_key"`
	BaseURL            string                   `json:"base_url"`
	Features           DarkAPIFeaturesConfig    `json:"features"`
}

type DarkAPIFeaturesConfig struct {
	BadDomains    bool `json:"bad_domains"`
	BadIPs        bool `json:"bad_ips"`
	DomainLookup  bool `json:"domain_lookup"`
	IPLookup      bool `json:"ip_lookup"`
	BulkLookup    bool `json:"bulk_lookup"`
}

type FileHashesConfig struct {
	Enabled    bool   `json:"enabled"`
	APIKey     string `json:"api_key"`
	BaseURL    string `json:"base_url"`
	SubmitHash bool   `json:"submit_hash"`
	LookupHash bool   `json:"lookup_hash"`
}

type ScanConfig struct {
	Recursive         bool     `json:"recursive"`
	MaxFileSize       int64    `json:"max_file_size"`
	ExcludeExtensions []string `json:"exclude_extensions"`
	IncludeExtensions []string `json:"include_extensions"`
	Threads           int      `json:"threads"`
}

func DefaultConfig() *Config {
	return &Config{
		ClamAV: ClamAVConfig{
			Enabled:      true,
			DatabasePath: "/var/lib/clamav",
			AutoUpdate:   false,
		},
		YARA: YARAConfig{
			Enabled:   false,
			RulesPath: "",
		},
		CAPA: CAPAConfig{
			Enabled:   false,
			ExePath:   "capa",
			RulesPath: "",
		},
		Viper: ViperConfig{
			Enabled:     false,
			ExePath:     "viper-cli",
			ProjectName: "default",
		},
		DarkAPI: DarkAPIConfig{
			Enabled: false,
			APIKey:  "",
			BaseURL: "https://api.darkapi.io",
			Features: DarkAPIFeaturesConfig{
				BadDomains:   true,
				BadIPs:       true,
				DomainLookup: true,
				IPLookup:     true,
				BulkLookup:   true,
			},
		},
		FileHashes: FileHashesConfig{
			Enabled:    false,
			APIKey:     "",
			BaseURL:    "https://api.filehashes.io",
			SubmitHash: true,
			LookupHash: true,
		},
		Scan: ScanConfig{
			Recursive:         true,
			MaxFileSize:       100 * 1024 * 1024,
			ExcludeExtensions: []string{},
			IncludeExtensions: []string{},
			Threads:           4,
		},
	}
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			cfg := DefaultConfig()
			if err := cfg.Save(path); err != nil {
				return nil, fmt.Errorf("failed to create default config: %w", err)
			}
			return cfg, nil
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

func (c *Config) Save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

func GetDefaultConfigPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %w", err)
	}

	return filepath.Join(homeDir, ".darkscan", "config.json"), nil
}

func GetDarkscanDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %w", err)
	}

	darkscanDir := filepath.Join(homeDir, ".darkscan")

	if err := os.MkdirAll(darkscanDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create .darkscan directory: %w", err)
	}

	return darkscanDir, nil
}

func GetYaraRulesDir() (string, error) {
	darkscanDir, err := GetDarkscanDir()
	if err != nil {
		return "", err
	}

	yaraDir := filepath.Join(darkscanDir, "yara-rules")
	if err := os.MkdirAll(yaraDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create yara-rules directory: %w", err)
	}

	return yaraDir, nil
}

func GetCapaRulesDir() (string, error) {
	darkscanDir, err := GetDarkscanDir()
	if err != nil {
		return "", err
	}

	capaDir := filepath.Join(darkscanDir, "capa-rules")
	if err := os.MkdirAll(capaDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create capa-rules directory: %w", err)
	}

	return capaDir, nil
}

func GetLogsDir() (string, error) {
	darkscanDir, err := GetDarkscanDir()
	if err != nil {
		return "", err
	}

	logsDir := filepath.Join(darkscanDir, "logs")
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create logs directory: %w", err)
	}

	return logsDir, nil
}

func (c *Config) Validate() error {
	if c.ClamAV.Enabled && c.ClamAV.DatabasePath == "" {
		return fmt.Errorf("ClamAV database path is required when ClamAV is enabled")
	}

	if c.YARA.Enabled && c.YARA.RulesPath == "" {
		return fmt.Errorf("YARA rules path is required when YARA is enabled")
	}

	if c.CAPA.Enabled && c.CAPA.ExePath == "" {
		return fmt.Errorf("CAPA executable path is required when CAPA is enabled")
	}

	if c.Viper.Enabled && c.Viper.ExePath == "" {
		return fmt.Errorf("Viper executable path is required when Viper is enabled")
	}

	if c.DarkAPI.Enabled && c.DarkAPI.APIKey == "" {
		return fmt.Errorf("DarkAPI API key is required when DarkAPI is enabled")
	}

	if c.DarkAPI.Enabled && c.DarkAPI.BaseURL == "" {
		return fmt.Errorf("DarkAPI base URL is required when DarkAPI is enabled")
	}

	if c.FileHashes.Enabled && c.FileHashes.APIKey == "" {
		return fmt.Errorf("FileHashes API key is required when FileHashes is enabled")
	}

	if c.FileHashes.Enabled && c.FileHashes.BaseURL == "" {
		return fmt.Errorf("FileHashes base URL is required when FileHashes is enabled")
	}

	if c.Scan.Threads < 1 {
		return fmt.Errorf("scan threads must be at least 1")
	}

	if c.Scan.MaxFileSize < 0 {
		return fmt.Errorf("max file size cannot be negative")
	}

	return nil
}

func InitConfig(path string) error {
	config := DefaultConfig()
	return config.Save(path)
}
