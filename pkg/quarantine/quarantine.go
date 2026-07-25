package quarantine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// Manager handles quarantine operations
type Manager struct {
	quarantineDir string
}

var validID = regexp.MustCompile(`^[0-9]{8}_[0-9]{6}_[a-f0-9]{8}$`)

func (m *Manager) entryDir(id string) (string, error) {
	if !validID.MatchString(id) {
		return "", fmt.Errorf("invalid quarantine entry ID")
	}
	return filepath.Join(m.quarantineDir, id), nil
}

// QuarantineEntry represents metadata for a quarantined file
type QuarantineEntry struct {
	ID            string    `json:"id"`
	OriginalPath  string    `json:"original_path"`
	QuarantinedAt time.Time `json:"quarantined_at"`
	FileHash      string    `json:"file_hash"`
	FileSize      int64     `json:"file_size"`
	Threats       []string  `json:"threats"`
	DetectionInfo string    `json:"detection_info"`
}

// New creates a new quarantine manager
func New(quarantineDir string) (*Manager, error) {
	if err := os.MkdirAll(quarantineDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create quarantine directory: %w", err)
	}

	return &Manager{
		quarantineDir: quarantineDir,
	}, nil
}

// Quarantine moves a file to quarantine
func (m *Manager) Quarantine(filePath string, threats []string, detectionInfo string) (*QuarantineEntry, error) {
	// Check if file exists
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	// Calculate file hash
	hash, err := calculateFileHash(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate hash: %w", err)
	}

	// Generate quarantine ID (timestamp + hash prefix)
	id := fmt.Sprintf("%s_%s", time.Now().Format("20060102_150405"), hash[:8])

	entry := &QuarantineEntry{
		ID:            id,
		OriginalPath:  filePath,
		QuarantinedAt: time.Now(),
		FileHash:      hash,
		FileSize:      info.Size(),
		Threats:       threats,
		DetectionInfo: detectionInfo,
	}

	// Create quarantine subdirectory for this entry
	entryDir := filepath.Join(m.quarantineDir, id)
	if err := os.MkdirAll(entryDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create entry directory: %w", err)
	}

	// Copy file to quarantine (safer than move)
	quarantinedPath := filepath.Join(entryDir, "file.quarantined")
	if err := copyFile(filePath, quarantinedPath); err != nil {
		return nil, fmt.Errorf("failed to copy file to quarantine: %w", err)
	}

	// Make quarantined file read-only
	if err := os.Chmod(quarantinedPath, 0400); err != nil {
		return nil, fmt.Errorf("failed to set quarantine file permissions: %w", err)
	}

	// Save metadata
	metadataPath := filepath.Join(entryDir, "metadata.json")
	if err := m.saveMetadata(entry, metadataPath); err != nil {
		return nil, fmt.Errorf("failed to save metadata: %w", err)
	}

	// Delete original file
	if err := os.Remove(filePath); err != nil {
		return nil, fmt.Errorf("failed to remove original file: %w", err)
	}

	return entry, nil
}

// List returns all quarantined files
func (m *Manager) List() ([]*QuarantineEntry, error) {
	entries := make([]*QuarantineEntry, 0)

	files, err := os.ReadDir(m.quarantineDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read quarantine directory: %w", err)
	}

	for _, file := range files {
		if !file.IsDir() {
			continue
		}

		metadataPath := filepath.Join(m.quarantineDir, file.Name(), "metadata.json")
		entry, err := m.loadMetadata(metadataPath)
		if err != nil {
			// Skip entries with corrupted metadata
			continue
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// Restore restores a quarantined file to its original location or a specified path
func (m *Manager) Restore(id string, targetPath string) error {
	entryDir, err := m.entryDir(id)
	if err != nil {
		return err
	}
	metadataPath := filepath.Join(entryDir, "metadata.json")

	entry, err := m.loadMetadata(metadataPath)
	if err != nil {
		return fmt.Errorf("failed to load metadata: %w", err)
	}

	// Determine restore path
	restorePath := targetPath
	if restorePath == "" {
		restorePath = entry.OriginalPath
	}

	// Check if target already exists
	if _, err := os.Stat(restorePath); err == nil {
		return fmt.Errorf("target file already exists: %s", restorePath)
	}

	// Create target directory if needed
	targetDir := filepath.Dir(restorePath)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("failed to create target directory: %w", err)
	}

	// Copy file from quarantine
	quarantinedPath := filepath.Join(entryDir, "file.quarantined")
	if err := copyFile(quarantinedPath, restorePath); err != nil {
		return fmt.Errorf("failed to restore file: %w", err)
	}

	// Remove from quarantine
	if err := os.RemoveAll(entryDir); err != nil {
		return fmt.Errorf("failed to remove quarantine entry: %w", err)
	}

	return nil
}

// Delete permanently deletes a quarantined file
func (m *Manager) Delete(id string) error {
	entryDir, err := m.entryDir(id)
	if err != nil {
		return err
	}

	// Verify entry exists
	if _, err := os.Stat(entryDir); err != nil {
		return fmt.Errorf("quarantine entry not found: %s", id)
	}

	// Remove the entire entry directory
	if err := os.RemoveAll(entryDir); err != nil {
		return fmt.Errorf("failed to delete quarantine entry: %w", err)
	}

	return nil
}

// GetEntry retrieves a specific quarantine entry by ID
func (m *Manager) GetEntry(id string) (*QuarantineEntry, error) {
	entryDir, err := m.entryDir(id)
	if err != nil {
		return nil, err
	}
	metadataPath := filepath.Join(entryDir, "metadata.json")
	return m.loadMetadata(metadataPath)
}

// Helper functions

func calculateFileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return err
	}

	return destFile.Sync()
}

func (m *Manager) saveMetadata(entry *QuarantineEntry, path string) error {
	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

func (m *Manager) loadMetadata(path string) (*QuarantineEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var entry QuarantineEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}

	return &entry, nil
}
