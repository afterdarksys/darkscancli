package hash

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/glaslos/ssdeep"
)

// Hashes contains all computed hashes for a file
type Hashes struct {
	MD5     string `json:"md5"`
	SHA1    string `json:"sha1"`
	SHA256  string `json:"sha256"`
	SSDEEP  string `json:"ssdeep,omitempty"`
	Size    int64  `json:"size"`
}

// ComputeAll computes all hashes for a file
func ComputeAll(path string) (*Hashes, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat file: %w", err)
	}

	hashes := &Hashes{
		Size: stat.Size(),
	}

	// Create hash writers
	md5Hash := md5.New()
	sha1Hash := sha1.New()
	sha256Hash := sha256.New()

	// Multi-writer for efficiency
	mw := io.MultiWriter(md5Hash, sha1Hash, sha256Hash)

	// Read file once, compute all hashes
	if _, err := io.Copy(mw, f); err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	hashes.MD5 = hex.EncodeToString(md5Hash.Sum(nil))
	hashes.SHA1 = hex.EncodeToString(sha1Hash.Sum(nil))
	hashes.SHA256 = hex.EncodeToString(sha256Hash.Sum(nil))

	// Compute SSDEEP (fuzzy hash)
	if fuzzy, err := ssdeep.FuzzyFilename(path); err == nil {
		hashes.SSDEEP = fuzzy
	}

	return hashes, nil
}

// ComputeMD5 computes MD5 hash of a file
func ComputeMD5(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// ComputeSHA256 computes SHA256 hash of a file
func ComputeSHA256(path string) (string, error) {
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

// ComputeBytes computes all hashes for byte data
func ComputeBytes(data []byte) *Hashes {
	md5Hash := md5.Sum(data)
	sha1Hash := sha1.Sum(data)
	sha256Hash := sha256.Sum256(data)

	hashes := &Hashes{
		MD5:    hex.EncodeToString(md5Hash[:]),
		SHA1:   hex.EncodeToString(sha1Hash[:]),
		SHA256: hex.EncodeToString(sha256Hash[:]),
		Size:   int64(len(data)),
	}

	// SSDEEP for byte data
	if fuzzy, err := ssdeep.FuzzyBytes(data); err == nil {
		hashes.SSDEEP = fuzzy
	}

	return hashes
}
