package hfsplus

import (
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"time"

	"github.com/afterdarksys/darkscan/pkg/vfs"
)

// VFS implements the VFS interface for HFS+
type VFS struct {
	hfs   *HFSPlus
	cache map[string]*CatalogFile
}

// NewVFS creates a new HFS+ VFS
func NewVFS(source vfs.Partition) (*VFS, error) {
	hfs, err := New(source)
	if err != nil {
		return nil, err
	}

	return &VFS{
		hfs:   hfs,
		cache: make(map[string]*CatalogFile),
	}, nil
}

// Open opens a file for reading
func (v *VFS) Open(path string) (vfs.File, error) {
	// Normalize path
	path = filepath.Clean(path)

	// Check cache
	if file, ok := v.cache[path]; ok {
		return &File{
			vfs:  v,
			file: file,
			path: path,
			pos:  0,
		}, nil
	}

	// Get file from catalog
	file, err := v.hfs.GetFileByPath(path)
	if err != nil {
		return nil, &fs.PathError{
			Op:   "open",
			Path: path,
			Err:  err,
		}
	}

	// Cache file
	v.cache[path] = file

	return &File{
		vfs:  v,
		file: file,
		path: path,
		pos:  0,
	}, nil
}

// Stat returns file information
func (v *VFS) Stat(path string) (fs.FileInfo, error) {
	path = filepath.Clean(path)

	file, err := v.hfs.GetFileByPath(path)
	if err != nil {
		return nil, &fs.PathError{
			Op:   "stat",
			Path: path,
			Err:  err,
		}
	}

	return &HFSFileInfo{
		name:    filepath.Base(path),
		size:    int64(file.DataFork.LogicalSize),
		mode:    0444, // Read-only
		modTime: ParseHFSTime(file.ContentModDate),
		isDir:   false,
	}, nil
}

// ReadDir reads a directory
func (v *VFS) ReadDir(path string) ([]fs.DirEntry, error) {
	// Get all files and filter by parent path
	entries, err := v.hfs.ListFiles()
	if err != nil {
		return nil, err
	}

	// Build path to folder ID map
	// This is simplified - in production would traverse catalog properly
	var dirEntries []fs.DirEntry

	for _, entry := range entries {
		// For now, just return all files
		// TODO: Implement proper directory traversal
		dirEntries = append(dirEntries, &DirEntry{
			name:  entry.Name,
			isDir: false,
			info: &HFSFileInfo{
				name:    entry.Name,
				size:    int64(entry.Size),
				mode:    0444,
				modTime: entry.ModifyDate,
				isDir:   false,
			},
		})
	}

	return dirEntries, nil
}

// Walk walks the filesystem
func (v *VFS) Walk(root string, fn fs.WalkDirFunc) error {
	entries, err := v.hfs.ListFiles()
	if err != nil {
		return err
	}

	for _, entry := range entries {
		info := &HFSFileInfo{
			name:    entry.Name,
			size:    int64(entry.Size),
			mode:    0444,
			modTime: entry.ModifyDate,
			isDir:   false,
		}

		dirEntry := &DirEntry{
			name:  entry.Name,
			isDir: false,
			info:  info,
		}

		// Construct full path (simplified)
		fullPath := entry.Name

		if err := fn(fullPath, dirEntry, nil); err != nil {
			if err == filepath.SkipDir {
				continue
			}
			return err
		}
	}

	return nil
}

// Type returns the filesystem type
func (v *VFS) Type() string {
	if v.hfs.header.Signature == 0x4858 {
		return "HFSX"
	}
	return "HFS+"
}

// File implements vfs.File for HFS+ files
type File struct {
	vfs  *VFS
	file *CatalogFile
	path string
	pos  int64
}

// Read reads from the file
func (f *File) Read(p []byte) (int, error) {
	if f.pos >= int64(f.file.DataFork.LogicalSize) {
		return 0, io.EOF
	}

	n, err := f.vfs.hfs.ReadFileAt(f.file, f.pos, p, false)
	f.pos += int64(n)

	return n, err
}

// ReadAt reads from the file at offset
func (f *File) ReadAt(p []byte, off int64) (int, error) {
	return f.vfs.hfs.ReadFileAt(f.file, off, p, false)
}

// Seek seeks to a position in the file
func (f *File) Seek(offset int64, whence int) (int64, error) {
	var newPos int64

	switch whence {
	case io.SeekStart:
		newPos = offset
	case io.SeekCurrent:
		newPos = f.pos + offset
	case io.SeekEnd:
		newPos = int64(f.file.DataFork.LogicalSize) + offset
	default:
		return 0, fmt.Errorf("invalid whence")
	}

	if newPos < 0 {
		return 0, fmt.Errorf("negative position")
	}

	f.pos = newPos
	return newPos, nil
}

// Close closes the file
func (f *File) Close() error {
	return nil
}

// Stat returns file info
func (f *File) Stat() (fs.FileInfo, error) {
	return &HFSFileInfo{
		name:    filepath.Base(f.path),
		size:    int64(f.file.DataFork.LogicalSize),
		mode:    0444,
		modTime: ParseHFSTime(f.file.ContentModDate),
		isDir:   false,
	}, nil
}

// ReadResourceFork reads the resource fork of the file
func (f *File) ReadResourceFork() ([]byte, error) {
	return f.vfs.hfs.ReadFile(f.file, true)
}

// HFSFileInfo implements fs.FileInfo
type HFSFileInfo struct {
	name    string
	size    int64
	mode    fs.FileMode
	modTime time.Time
	isDir   bool
}

func (fi *HFSFileInfo) Name() string       { return fi.name }
func (fi *HFSFileInfo) Size() int64        { return fi.size }
func (fi *HFSFileInfo) Mode() fs.FileMode  { return fi.mode }
func (fi *HFSFileInfo) ModTime() time.Time { return fi.modTime }
func (fi *HFSFileInfo) IsDir() bool        { return fi.isDir }
func (fi *HFSFileInfo) Sys() interface{}   { return nil }

// DirEntry implements fs.DirEntry
type DirEntry struct {
	name  string
	isDir bool
	info  *HFSFileInfo
}

func (de *DirEntry) Name() string               { return de.name }
func (de *DirEntry) IsDir() bool                { return de.isDir }
func (de *DirEntry) Type() fs.FileMode          { return de.info.Mode() }
func (de *DirEntry) Info() (fs.FileInfo, error) { return de.info, nil }

// GetVolumeInfo returns HFS+ volume information
func (v *VFS) GetVolumeInfo() VolumeInfo {
	return v.hfs.GetVolumeInfo()
}

// RecoverDeletedFiles attempts to recover deleted files
func (v *VFS) RecoverDeletedFiles() ([]FileEntry, error) {
	// This would require:
	// 1. Scanning catalog B-tree for deleted entries
	// 2. Checking journal for recent deletions
	// 3. Scanning unallocated blocks for file signatures

	// For now, return empty list
	// Full implementation would be a significant undertaking
	return []FileEntry{}, nil
}

// SearchFilesByName searches for files by name pattern
func (v *VFS) SearchFilesByName(pattern string) ([]string, error) {
	entries, err := v.hfs.ListFiles()
	if err != nil {
		return nil, err
	}

	var matches []string
	for _, entry := range entries {
		matched, err := filepath.Match(pattern, entry.Name)
		if err != nil {
			return nil, err
		}
		if matched {
			matches = append(matches, entry.Name)
		}
	}

	return matches, nil
}

// GetFileExtendedAttributes returns extended attributes for a file
func (v *VFS) GetFileExtendedAttributes(path string) (map[string][]byte, error) {
	file, err := v.hfs.GetFileByPath(path)
	if err != nil {
		return nil, err
	}

	return v.hfs.GetExtendedAttributes(file.FileID)
}

// IsJournaled returns whether the volume is journaled
func (v *VFS) IsJournaled() bool {
	return v.hfs.header.Attributes&AttrVolumeJournaled != 0
}

// IsCaseSensitive returns whether the volume is case-sensitive (HFSX)
func (v *VFS) IsCaseSensitive() bool {
	return v.hfs.header.Signature == 0x4858
}

// GetJournalInfo returns journal information if available
func (v *VFS) GetJournalInfo() *JournalInfoBlock {
	return v.hfs.journal
}
