package vfs

import (
	"io"
	"os"
	"path/filepath"
)

// File represents a generic file object read from any VFS backend.
type File interface {
	io.Reader
	io.ReaderAt
	io.Seeker
	io.Closer
	Stat() (os.FileInfo, error)
}

// FileSystem represents the interface all VFS backends must implement.
type FileSystem interface {
	// Open opens a file for reading.
	Open(name string) (File, error)

	// Stat returns a FileInfo describing the named file.
	Stat(name string) (os.FileInfo, error)

	// Walk walks the file tree rooted at root, calling fn for each file or directory.
	Walk(root string, fn filepath.WalkFunc) error

	// Extended Attributes / Metadata
	// ListXattrs returns a list of extended attribute names for a generic path
	ListXattrs(path string) ([]string, error)

	// GetXattr returns the value of an extended attribute
	GetXattr(path string, attr string) ([]byte, error)
}

// ForensicNode represents basic forensic information extracted from raw MFT/Inode structures.
type ForensicNode struct {
	Name         string
	Path         string
	Size         int64
	IsDeleted    bool
	ReferenceID  uint64           // NTFS MFT Reference or Unix Inode
	Timestamps   map[string]int64 // Creation, modification, access times (Unix epoch)
	RawStruct    []byte           // The raw bytes of the MFT record or Inode
}

// ForensicFileSystem extends FileSystem with deep block-level recovery capabilities.
// This is typically implemented by native parsers like NTFS, Ext4, and APFS.
type ForensicFileSystem interface {
	FileSystem

	// WalkDeleted enumerates recovered or marked-as-deleted files in the specified path.
	WalkDeleted(root string, fn func(node ForensicNode) error) error

	// GetForensicNode returns forensic metadata for a specific MFT ref or Inode.
	GetForensicNode(referenceID uint64) (ForensicNode, error)

	// ReadDeleted opens a deleted file by its inode or reference ID for reading (if content is recoverable).
	ReadDeleted(referenceID uint64) (File, error)

	// ParseJournal processes the OS filesystem journal (e.g., USN on Windows, ext4 journal) 
	// for historical actions that happened after the specified `since` timestamp.
	ParseJournal(sinceEpoch int64, fn func(entry string) error) error
}

// Partition represents a physical disk partition or raw loopback image.
type Partition interface {
	io.ReaderAt
	io.WriterAt
	io.Closer
	Size() int64
}

// ForensicRepair extends ForensicFileSystem with active threat reversal and repair capabilities.
type ForensicRepair interface {
	ForensicFileSystem

	// RestoreFromVSS attempts to extract the clean $DATA stream from a shadow copy.
	// Requires License Feature: VSS_RECOVERY
	RestoreFromVSS(referenceID uint64, snapshotID string) error

	// StripMaliciousADS zeroes and unlinks a malicious Alternate Data Stream.
	// Requires License Feature: ADS_STRIPPING
	StripMaliciousADS(referenceID uint64, streamName string) error

	// Undelete attempts to restore an MFT record and re-link it to its parent index.
	// Requires License Feature: MFT_RESTORATION
	Undelete(referenceID uint64) error

	// RollbackJournal traverses the $UsnJrnl backwards to revert file modifications.
	// Requires License Feature: JOURNAL_ROLLBACK
	RollbackJournal(sinceEpoch int64) error

	// RepairBootSector restores standard OEM VBR code or writes from a known baseline hash.
	// Requires License Feature: BOOT_REPAIR
	RepairBootSector(knownGoodHash string) error
}

