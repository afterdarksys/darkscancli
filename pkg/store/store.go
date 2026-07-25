package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Store provides sqlite persistence for darkscan
type Store struct {
	db *sql.DB
}

// ScanRecord represents a past scan log entry
type ScanRecord struct {
	ID       int
	FilePath string
	Infected bool
	Threats  string
	ScanTime time.Time
	FileHash string
}

// HashCacheEntry represents a cached file hash with scan results
type HashCacheEntry struct {
	Hash      string
	MD5       string
	SHA1      string
	SHA256    string
	FileSize  int64
	Infected  bool
	Threats   string
	FirstSeen time.Time
	LastSeen  time.Time
	ScanCount int
}

// New initializes a new sqlite database at the given path
func New(dbPath string) (*Store, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create db directory: %w", err)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	s := &Store{db: db}
	if err := s.Init(); err != nil {
		db.Close()
		return nil, err
	}

	return s, nil
}

// Init creates necessary tables if they don't exist
func (s *Store) Init() error {
	query := `
	CREATE TABLE IF NOT EXISTS scans (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		file_path TEXT NOT NULL,
		infected BOOLEAN NOT NULL,
		threats TEXT,
		scan_time DATETIME DEFAULT CURRENT_TIMESTAMP,
		file_hash TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_file_path ON scans(file_path);
	CREATE INDEX IF NOT EXISTS idx_file_hash ON scans(file_hash);

	CREATE TABLE IF NOT EXISTS hash_cache (
		hash TEXT PRIMARY KEY,
		md5 TEXT NOT NULL,
		sha1 TEXT NOT NULL,
		sha256 TEXT NOT NULL,
		file_size INTEGER NOT NULL,
		infected BOOLEAN NOT NULL,
		threats TEXT,
		first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		scan_count INTEGER DEFAULT 1
	);
	CREATE INDEX IF NOT EXISTS idx_md5 ON hash_cache(md5);
	CREATE INDEX IF NOT EXISTS idx_sha1 ON hash_cache(sha1);
	CREATE INDEX IF NOT EXISTS idx_sha256 ON hash_cache(sha256);
	`
	_, err := s.db.Exec(query)
	return err
}

// RecordScan writes a scan record to the database
func (s *Store) RecordScan(record ScanRecord) error {
	query := `INSERT INTO scans (file_path, infected, threats, file_hash, scan_time) VALUES (?, ?, ?, ?, ?)`
	_, err := s.db.Exec(query, record.FilePath, record.Infected, record.Threats, record.FileHash, record.ScanTime)
	return err
}

// Cleanup removes records older than retentionMonths
func (s *Store) Cleanup(retentionMonths int) error {
	query := `DELETE FROM scans WHERE scan_time < datetime('now', '-' || ? || ' months')`
	_, err := s.db.Exec(query, retentionMonths)
	return err
}

// SearchScans queries the history for matching file paths, hashes, or threat heuristics
func (s *Store) SearchScans(searchQuery string, limit int) ([]ScanRecord, error) {
	query := `
	SELECT id, file_path, infected, threats, scan_time, file_hash 
	FROM scans 
	WHERE file_path LIKE ? OR threats LIKE ? OR file_hash = ?
	ORDER BY scan_time DESC LIMIT ?`

	likeMatch := "%" + searchQuery + "%"
	rows, err := s.db.Query(query, likeMatch, likeMatch, searchQuery, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []ScanRecord
	for rows.Next() {
		var r ScanRecord
		if err := rows.Scan(&r.ID, &r.FilePath, &r.Infected, &r.Threats, &r.ScanTime, &r.FileHash); err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, nil
}

// GetRecentScans fetches the most recent scan logs
func (s *Store) GetRecentScans(limit int) ([]ScanRecord, error) {
	query := `SELECT id, file_path, infected, threats, scan_time, file_hash FROM scans ORDER BY scan_time DESC LIMIT ?`
	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []ScanRecord
	for rows.Next() {
		var r ScanRecord
		if err := rows.Scan(&r.ID, &r.FilePath, &r.Infected, &r.Threats, &r.ScanTime, &r.FileHash); err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, nil
}

// Close closes the database connection
func (s *Store) Close() error {
	return s.db.Close()
}

// CheckHashCache checks if a hash exists in the cache and returns its status
func (s *Store) CheckHashCache(sha256 string) (*HashCacheEntry, bool) {
	query := `SELECT hash, md5, sha1, sha256, file_size, infected, threats, first_seen, last_seen, scan_count
	          FROM hash_cache WHERE sha256 = ?`

	var entry HashCacheEntry
	err := s.db.QueryRow(query, sha256).Scan(
		&entry.Hash, &entry.MD5, &entry.SHA1, &entry.SHA256,
		&entry.FileSize, &entry.Infected, &entry.Threats,
		&entry.FirstSeen, &entry.LastSeen, &entry.ScanCount,
	)

	if err == sql.ErrNoRows {
		return nil, false
	}
	if err != nil {
		return nil, false
	}

	return &entry, true
}

// UpdateHashCache adds or updates a hash in the cache
func (s *Store) UpdateHashCache(entry HashCacheEntry) error {
	// Use SHA256 as primary hash
	if entry.Hash == "" {
		entry.Hash = entry.SHA256
	}

	query := `INSERT INTO hash_cache (hash, md5, sha1, sha256, file_size, infected, threats, first_seen, last_seen, scan_count)
	          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	          ON CONFLICT(hash) DO UPDATE SET
	          last_seen = ?,
	          scan_count = scan_count + 1,
	          infected = ?,
	          threats = ?`

	now := time.Now()
	_, err := s.db.Exec(query,
		entry.Hash, entry.MD5, entry.SHA1, entry.SHA256,
		entry.FileSize, entry.Infected, entry.Threats,
		now, now, 1,
		now, entry.Infected, entry.Threats,
	)

	return err
}

// GetHashStats returns statistics about the hash cache
func (s *Store) GetHashStats() (total, infected, clean int, err error) {
	query := `SELECT
	            COUNT(*) as total,
	            SUM(CASE WHEN infected = 1 THEN 1 ELSE 0 END) as infected,
	            SUM(CASE WHEN infected = 0 THEN 1 ELSE 0 END) as clean
	          FROM hash_cache`

	err = s.db.QueryRow(query).Scan(&total, &infected, &clean)
	return
}

// ExportHashes exports all hashes to the specified format
func (s *Store) ExportHashes(format string, infected bool) ([]HashCacheEntry, error) {
	query := `SELECT hash, md5, sha1, sha256, file_size, infected, threats, first_seen, last_seen, scan_count
	          FROM hash_cache WHERE infected = ? ORDER BY last_seen DESC`

	rows, err := s.db.Query(query, infected)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []HashCacheEntry
	for rows.Next() {
		var entry HashCacheEntry
		if err := rows.Scan(&entry.Hash, &entry.MD5, &entry.SHA1, &entry.SHA256,
			&entry.FileSize, &entry.Infected, &entry.Threats,
			&entry.FirstSeen, &entry.LastSeen, &entry.ScanCount); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

// CleanHashCache removes hash entries older than the specified days
func (s *Store) CleanHashCache(retentionDays int) (int64, error) {
	query := `DELETE FROM hash_cache WHERE last_seen < datetime('now', '-' || ? || ' days')`
	result, err := s.db.Exec(query, retentionDays)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
