package hfsplus

import (
	"encoding/binary"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/afterdarksys/darkscan/pkg/vfs"
)

// HFSPlus represents an HFS+ filesystem
type HFSPlus struct {
	source        vfs.Partition
	header        VolumeHeader
	catalogTree   *BTree
	extentsTree   *BTree
	attributesTree *BTree
	journal       *JournalInfoBlock
}

// New creates a new HFS+ filesystem parser
func New(source vfs.Partition) (*HFSPlus, error) {
	hfs := &HFSPlus{
		source: source,
	}

	// Parse volume header
	if err := hfs.parseVolumeHeader(); err != nil {
		return nil, fmt.Errorf("failed to parse volume header: %w", err)
	}

	// Verify signature
	if hfs.header.Signature != 0x482B && hfs.header.Signature != 0x4858 {
		return nil, fmt.Errorf("invalid HFS+ signature: 0x%04X", hfs.header.Signature)
	}

	// Initialize catalog B-tree
	catalogTree, err := NewBTree(hfs, &hfs.header.CatalogFile)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize catalog tree: %w", err)
	}
	hfs.catalogTree = catalogTree

	// Initialize extents overflow B-tree
	extentsTree, err := NewBTree(hfs, &hfs.header.ExtentsFile)
	if err != nil {
		// Non-fatal, extents overflow may not be needed
		extentsTree = nil
	}
	hfs.extentsTree = extentsTree

	// Initialize attributes B-tree (if present)
	if hfs.header.AttributesFile.LogicalSize > 0 {
		attributesTree, err := NewBTree(hfs, &hfs.header.AttributesFile)
		if err == nil {
			hfs.attributesTree = attributesTree
		}
	}

	// Parse journal if present
	if hfs.header.Attributes&AttrVolumeJournaled != 0 && hfs.header.JournalInfoBlock != 0 {
		if err := hfs.parseJournal(); err != nil {
			// Non-fatal
		}
	}

	return hfs, nil
}

// parseVolumeHeader parses the HFS+ volume header
func (hfs *HFSPlus) parseVolumeHeader() error {
	// Volume header is at offset 1024 bytes
	buf := make([]byte, 512)
	if _, err := hfs.source.ReadAt(buf, 1024); err != nil {
		return fmt.Errorf("failed to read volume header: %w", err)
	}

	hfs.header.Signature = binary.BigEndian.Uint16(buf[0:2])
	hfs.header.Version = binary.BigEndian.Uint16(buf[2:4])
	hfs.header.Attributes = binary.BigEndian.Uint32(buf[4:8])
	hfs.header.LastMountedVersion = binary.BigEndian.Uint32(buf[8:12])
	hfs.header.JournalInfoBlock = binary.BigEndian.Uint32(buf[12:16])

	hfs.header.CreateDate = binary.BigEndian.Uint32(buf[16:20])
	hfs.header.ModifyDate = binary.BigEndian.Uint32(buf[20:24])
	hfs.header.BackupDate = binary.BigEndian.Uint32(buf[24:28])
	hfs.header.CheckedDate = binary.BigEndian.Uint32(buf[28:32])

	hfs.header.FileCount = binary.BigEndian.Uint32(buf[32:36])
	hfs.header.FolderCount = binary.BigEndian.Uint32(buf[36:40])

	hfs.header.BlockSize = binary.BigEndian.Uint32(buf[40:44])
	hfs.header.TotalBlocks = binary.BigEndian.Uint32(buf[44:48])
	hfs.header.FreeBlocks = binary.BigEndian.Uint32(buf[48:52])

	// Parse fork data for special files
	offset := 112
	offset = hfs.parseForkData(buf[offset:], &hfs.header.AllocationFile)
	offset = hfs.parseForkData(buf[offset:], &hfs.header.ExtentsFile)
	offset = hfs.parseForkData(buf[offset:], &hfs.header.CatalogFile)
	offset = hfs.parseForkData(buf[offset:], &hfs.header.AttributesFile)
	hfs.parseForkData(buf[offset:], &hfs.header.StartupFile)

	return nil
}

// parseForkData parses a ForkData structure
func (hfs *HFSPlus) parseForkData(buf []byte, fork *ForkData) int {
	if len(buf) < 80 {
		return 0
	}

	fork.LogicalSize = binary.BigEndian.Uint64(buf[0:8])
	fork.ClumpSize = binary.BigEndian.Uint32(buf[8:12])
	fork.TotalBlocks = binary.BigEndian.Uint32(buf[12:16])

	// Parse extent descriptors
	offset := 16
	for i := 0; i < 8; i++ {
		fork.Extents[i].StartBlock = binary.BigEndian.Uint32(buf[offset : offset+4])
		fork.Extents[i].BlockCount = binary.BigEndian.Uint32(buf[offset+4 : offset+8])
		offset += 8
	}

	return 80
}

// parseJournal parses the journal info block
func (hfs *HFSPlus) parseJournal() error {
	blockNum := hfs.header.JournalInfoBlock
	blockOffset := int64(blockNum) * int64(hfs.header.BlockSize)

	buf := make([]byte, 512)
	if _, err := hfs.source.ReadAt(buf, blockOffset); err != nil {
		return fmt.Errorf("failed to read journal info block: %w", err)
	}

	hfs.journal = &JournalInfoBlock{}
	hfs.journal.Flags = binary.BigEndian.Uint32(buf[0:4])
	hfs.journal.Offset = binary.BigEndian.Uint64(buf[40:48])
	hfs.journal.Size = binary.BigEndian.Uint64(buf[48:56])

	return nil
}

// GetFileByPath retrieves a file by path
func (hfs *HFSPlus) GetFileByPath(path string) (*CatalogFile, error) {
	path = filepath.Clean(path)
	parts := strings.Split(path, "/")

	// Start from root (CNID 2)
	parentID := uint32(2)

	for i, part := range parts {
		if part == "" {
			continue
		}

		record, err := hfs.catalogTree.SearchCatalog(parentID, part)
		if err != nil {
			return nil, fmt.Errorf("path component '%s' not found: %w", part, err)
		}

		// Parse record type
		if len(record.Data) < 2 {
			return nil, fmt.Errorf("invalid catalog record")
		}

		recordType := int16(binary.BigEndian.Uint16(record.Data[0:2]))

		if i == len(parts)-1 {
			// Last component - should be a file
			if recordType != RecordTypeFile {
				return nil, fmt.Errorf("not a file")
			}

			file := &CatalogFile{}
			if err := hfs.parseCatalogFile(record.Data, file); err != nil {
				return nil, err
			}

			return file, nil
		} else {
			// Intermediate component - should be a folder
			if recordType != RecordTypeFolder {
				return nil, fmt.Errorf("not a folder")
			}

			folder := &CatalogFolder{}
			if err := hfs.parseCatalogFolder(record.Data, folder); err != nil {
				return nil, err
			}

			parentID = folder.FolderID
		}
	}

	return nil, fmt.Errorf("file not found")
}

// parseCatalogFile parses a catalog file record
func (hfs *HFSPlus) parseCatalogFile(data []byte, file *CatalogFile) error {
	if len(data) < 248 {
		return fmt.Errorf("data too short for catalog file")
	}

	file.RecordType = int16(binary.BigEndian.Uint16(data[0:2]))
	file.Flags = binary.BigEndian.Uint16(data[2:4])
	file.FileID = binary.BigEndian.Uint32(data[8:12])

	file.CreateDate = binary.BigEndian.Uint32(data[12:16])
	file.ContentModDate = binary.BigEndian.Uint32(data[16:20])
	file.AttributeModDate = binary.BigEndian.Uint32(data[20:24])
	file.AccessDate = binary.BigEndian.Uint32(data[24:28])
	file.BackupDate = binary.BigEndian.Uint32(data[28:32])

	// Parse forks
	offset := 88
	hfs.parseForkData(data[offset:], &file.DataFork)
	offset += 80
	hfs.parseForkData(data[offset:], &file.ResourceFork)

	return nil
}

// parseCatalogFolder parses a catalog folder record
func (hfs *HFSPlus) parseCatalogFolder(data []byte, folder *CatalogFolder) error {
	if len(data) < 88 {
		return fmt.Errorf("data too short for catalog folder")
	}

	folder.RecordType = int16(binary.BigEndian.Uint16(data[0:2]))
	folder.Flags = binary.BigEndian.Uint16(data[2:4])
	folder.Valence = binary.BigEndian.Uint32(data[4:8])
	folder.FolderID = binary.BigEndian.Uint32(data[8:12])

	folder.CreateDate = binary.BigEndian.Uint32(data[12:16])
	folder.ContentModDate = binary.BigEndian.Uint32(data[16:20])
	folder.AttributeModDate = binary.BigEndian.Uint32(data[20:24])
	folder.AccessDate = binary.BigEndian.Uint32(data[24:28])
	folder.BackupDate = binary.BigEndian.Uint32(data[28:32])

	return nil
}

// ReadFile reads the entire contents of a file
func (hfs *HFSPlus) ReadFile(file *CatalogFile, useResourceFork bool) ([]byte, error) {
	fork := &file.DataFork
	if useResourceFork {
		fork = &file.ResourceFork
	}

	if fork.LogicalSize == 0 {
		return []byte{}, nil
	}

	data := make([]byte, fork.LogicalSize)
	if err := hfs.readForkData(fork, 0, data); err != nil {
		return nil, err
	}

	return data, nil
}

// ReadFileAt reads from a file at a specific offset
func (hfs *HFSPlus) ReadFileAt(file *CatalogFile, offset int64, data []byte, useResourceFork bool) (int, error) {
	fork := &file.DataFork
	if useResourceFork {
		fork = &file.ResourceFork
	}

	if offset < 0 || uint64(offset) >= fork.LogicalSize {
		return 0, io.EOF
	}

	readSize := len(data)
	if uint64(offset)+uint64(readSize) > fork.LogicalSize {
		readSize = int(fork.LogicalSize - uint64(offset))
	}

	if err := hfs.readForkData(fork, uint64(offset), data[:readSize]); err != nil {
		return 0, err
	}

	return readSize, nil
}

// readForkData reads data from a fork
func (hfs *HFSPlus) readForkData(fork *ForkData, offset uint64, data []byte) error {
	remaining := uint64(len(data))
	position := offset
	dataOffset := 0

	// Read from extents
	for _, extent := range fork.Extents {
		if extent.BlockCount == 0 {
			break
		}

		extentStart := uint64(extent.StartBlock) * uint64(hfs.header.BlockSize)
		extentSize := uint64(extent.BlockCount) * uint64(hfs.header.BlockSize)

		if position < extentSize {
			// This extent contains data we need
			readOffset := extentStart + position
			readSize := extentSize - position

			if readSize > remaining {
				readSize = remaining
			}

			if _, err := hfs.source.ReadAt(data[dataOffset:dataOffset+int(readSize)], int64(readOffset)); err != nil {
				return fmt.Errorf("failed to read extent data: %w", err)
			}

			dataOffset += int(readSize)
			remaining -= readSize
			position = 0

			if remaining == 0 {
				return nil
			}
		} else {
			position -= extentSize
		}
	}

	if remaining > 0 {
		// Need extents overflow file
		if hfs.extentsTree != nil {
			return fmt.Errorf("extents overflow file needed (not yet implemented)")
		}
		return fmt.Errorf("data extends beyond extents")
	}

	return nil
}

// ListFiles lists all files in the volume
func (hfs *HFSPlus) ListFiles() ([]FileEntry, error) {
	var files []FileEntry

	err := hfs.catalogTree.WalkCatalog(func(key *CatalogKey, data []byte) error {
		if len(data) < 2 {
			return nil
		}

		recordType := int16(binary.BigEndian.Uint16(data[0:2]))

		if recordType == RecordTypeFile {
			file := &CatalogFile{}
			if err := hfs.parseCatalogFile(data, file); err != nil {
				return nil // Skip invalid records
			}

			entry := FileEntry{
				Name:         key.NodeName.ToGoString(),
				ParentID:     key.ParentID,
				FileID:       file.FileID,
				Size:         file.DataFork.LogicalSize,
				ResourceSize: file.ResourceFork.LogicalSize,
				CreateDate:   ParseHFSTime(file.CreateDate),
				ModifyDate:   ParseHFSTime(file.ContentModDate),
				IsDeleted:    false,
			}

			files = append(files, entry)
		}

		return nil
	})

	return files, err
}

// FileEntry represents a file entry
type FileEntry struct {
	Name         string
	ParentID     uint32
	FileID       uint32
	Size         uint64
	ResourceSize uint64
	CreateDate   time.Time
	ModifyDate   time.Time
	IsDeleted    bool
}

// GetVolumeInfo returns volume information
func (hfs *HFSPlus) GetVolumeInfo() VolumeInfo {
	return VolumeInfo{
		Signature:    hfs.header.Signature,
		Version:      hfs.header.Version,
		BlockSize:    hfs.header.BlockSize,
		TotalBlocks:  hfs.header.TotalBlocks,
		FreeBlocks:   hfs.header.FreeBlocks,
		FileCount:    hfs.header.FileCount,
		FolderCount:  hfs.header.FolderCount,
		CreateDate:   ParseHFSTime(hfs.header.CreateDate),
		ModifyDate:   ParseHFSTime(hfs.header.ModifyDate),
		IsJournaled:  hfs.header.Attributes&AttrVolumeJournaled != 0,
		IsEncrypted:  false, // Would need additional detection
	}
}

// VolumeInfo contains volume information
type VolumeInfo struct {
	Signature    uint16
	Version      uint16
	BlockSize    uint32
	TotalBlocks  uint32
	FreeBlocks   uint32
	FileCount    uint32
	FolderCount  uint32
	CreateDate   time.Time
	ModifyDate   time.Time
	IsJournaled  bool
	IsEncrypted  bool
}

// GetExtendedAttributes retrieves extended attributes for a file
func (hfs *HFSPlus) GetExtendedAttributes(fileID uint32) (map[string][]byte, error) {
	if hfs.attributesTree == nil {
		return nil, fmt.Errorf("no attributes file")
	}

	// This would require searching the attributes B-tree
	// Implementation left for future enhancement
	return make(map[string][]byte), nil
}
