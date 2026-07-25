package clamav

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// MirrorClient handles downloading ClamAV definitions from a custom mirror server
type MirrorClient struct {
	mirrorURL string
	client    *http.Client
	targetDir string
}

// MirrorMetadata represents definition metadata from the mirror server
type MirrorMetadata struct {
	Version         string    `json:"version"`
	MainVersion     string    `json:"main_version"`
	DailyVersion    string    `json:"daily_version"`
	BytecodeVersion string    `json:"bytecode_version"`
	UpdatedAt       time.Time `json:"updated_at"`
	TotalSizeBytes  int64     `json:"total_size_bytes"`
	TotalSizeMB     float64   `json:"total_size_mb"`
}

// NewMirrorClient creates a new mirror client
func NewMirrorClient(mirrorURL, targetDir string) *MirrorClient {
	if targetDir == "" {
		targetDir = "/usr/local/share/clamav"
	}

	return &MirrorClient{
		mirrorURL: mirrorURL,
		client:    &http.Client{Timeout: 10 * time.Minute},
		targetDir: targetDir,
	}
}

// GetVersion fetches the current definition version from the mirror
func (m *MirrorClient) GetVersion() (*MirrorMetadata, error) {
	url := fmt.Sprintf("%s/api/v1/clamav/definitions/version", m.mirrorURL)
	resp, err := m.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch version: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mirror returned status %d", resp.StatusCode)
	}

	var metadata MirrorMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to decode metadata: %w", err)
	}

	return &metadata, nil
}

// DownloadDefinitions downloads the latest definition bundle from the mirror
func (m *MirrorClient) DownloadDefinitions() error {
	url := fmt.Sprintf("%s/api/v1/clamav/definitions/latest", m.mirrorURL)

	// Download bundle
	resp, err := m.client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download bundle: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("mirror returned status %d", resp.StatusCode)
	}

	// Create target directory if it doesn't exist
	if err := os.MkdirAll(m.targetDir, 0755); err != nil {
		return fmt.Errorf("failed to create target directory: %w", err)
	}

	// Extract tarball
	gzipReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar: %w", err)
		}

		// Skip directories
		if header.Typeflag == tar.TypeDir {
			continue
		}

		// Validate filename to prevent directory traversal
		cleanName := filepath.Clean(header.Name)
		if strings.Contains(cleanName, "..") || filepath.IsAbs(cleanName) {
			return fmt.Errorf("invalid file path in archive: %s", header.Name)
		}

		// Create target file
		targetPath := filepath.Join(m.targetDir, cleanName)

		// Double-check the target path is within targetDir
		if !strings.HasPrefix(filepath.Clean(targetPath), filepath.Clean(m.targetDir)) {
			return fmt.Errorf("path traversal attempt detected: %s", header.Name)
		}

		targetFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
		if err != nil {
			return fmt.Errorf("failed to create file %s: %w", targetPath, err)
		}

		// Copy content
		if _, err := io.Copy(targetFile, tarReader); err != nil {
			targetFile.Close()
			return fmt.Errorf("failed to write file %s: %w", targetPath, err)
		}

		targetFile.Close()
	}

	return nil
}

// DownloadFile downloads a specific definition file
func (m *MirrorClient) DownloadFile(filename string) error {
	url := fmt.Sprintf("%s/api/v1/clamav/definitions/%s", m.mirrorURL, filename)

	resp, err := m.client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("mirror returned status %d", resp.StatusCode)
	}

	targetPath := filepath.Join(m.targetDir, filename)
	targetFile, err := os.Create(targetPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer targetFile.Close()

	if _, err := io.Copy(targetFile, resp.Body); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// GetLocalVersion reads the current version of local ClamAV definitions
func GetLocalVersion(targetDir string) (string, error) {
	dailyPath := filepath.Join(targetDir, "daily.cvd")
	if _, err := os.Stat(dailyPath); err == nil {
		// CVD file exists, read its version (simplified - just check file mod time)
		info, err := os.Stat(dailyPath)
		if err != nil {
			return "", err
		}
		return info.ModTime().Format("2006-01-02"), nil
	}

	// Alternative: check daily.cld
	dailyCldPath := filepath.Join(targetDir, "daily.cld")
	if _, err := os.Stat(dailyCldPath); err == nil {
		info, err := os.Stat(dailyCldPath)
		if err != nil {
			return "", err
		}
		return info.ModTime().Format("2006-01-02"), nil
	}

	return "", fmt.Errorf("no local definitions found")
}

// UpdateFromMirror downloads definitions from the mirror if they're newer
func UpdateFromMirror(mirrorURL, targetDir string) error {
	if mirrorURL == "" {
		return fmt.Errorf("mirror URL not configured")
	}

	client := NewMirrorClient(mirrorURL, targetDir)

	// Get remote version
	metadata, err := client.GetVersion()
	if err != nil {
		return fmt.Errorf("failed to get mirror version: %w", err)
	}

	// Check local version
	localVersion, err := GetLocalVersion(targetDir)
	if err == nil {
		// Compare versions (simplified comparison by date)
		if localVersion >= metadata.UpdatedAt.Format("2006-01-02") {
			fmt.Printf("Local definitions are up to date (version: %s)\n", localVersion)
			return nil
		}
		fmt.Printf("Updating from version %s to %s\n", localVersion, metadata.Version)
	} else {
		fmt.Printf("No local definitions found, downloading initial set\n")
	}

	// Download latest definitions
	if err := client.DownloadDefinitions(); err != nil {
		return fmt.Errorf("failed to download definitions: %w", err)
	}

	fmt.Printf("Successfully updated ClamAV definitions from mirror (version: %s, size: %.1f MB)\n",
		metadata.Version, metadata.TotalSizeMB)

	return nil
}
