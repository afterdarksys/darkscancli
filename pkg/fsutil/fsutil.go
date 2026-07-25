package fsutil

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// IsSystemDirectory checks if the path points to a critical OS directory we shouldn't scan
func IsSystemDirectory(path string) bool {
	path = filepath.Clean(path)
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		systemPaths := []string{"/proc", "/sys", "/dev", "/run"}
		for _, sp := range systemPaths {
			if strings.HasPrefix(path, sp) {
				return true
			}
		}
	} else if runtime.GOOS == "windows" {
		lowerPath := strings.ToLower(path)
		if strings.Contains(lowerPath, "windows\\system32") {
			// Often locked / too critical
			return true
		}
	}
	return false
}

// Walk safely traverses a directory excluding system directories and parsing Alternate Data Streams on Windows.
func Walk(root string, fn func(path string, info os.FileInfo, err error) error) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fn(path, info, err)
		}
		if info.IsDir() && IsSystemDirectory(path) {
			return filepath.SkipDir
		}

		// Dispatch to standard handler
		if err := fn(path, info, nil); err != nil {
			return err
		}

		// Check for Alternate Data Streams
		if !info.IsDir() {
			streams, streamErr := GetAlternateDataStreams(path)
			if streamErr == nil {
				for _, stream := range streams {
					// stream is typically ":StreamName:$DATA"
					streamPath := path + stream
					if err := fn(streamPath, info, nil); err != nil {
						// Don't kill entire walk if one stream callback fails unless specifically requested
						if err == filepath.SkipDir {
							continue
						}
						return err
					}
				}
			}
		}

		return nil
	})
}
