package hfsplus

import (
	"encoding/binary"
	"fmt"
	"time"
)

// HFS+ uses a different epoch: January 1, 1904
var hfsPlusEpoch = time.Date(1904, 1, 1, 0, 0, 0, 0, time.UTC)

// VolumeHeader represents the HFS+ Volume Header
// Located at offset 1024 bytes from the start of the volume
type VolumeHeader struct {
	Signature          uint16 // 'H+' (0x482B) for HFS+, 'HX' (0x4858) for HFSX
	Version            uint16 // Volume version (4 for HFS+, 5 for HFSX)
	Attributes         uint32 // Volume attributes
	LastMountedVersion uint32
	JournalInfoBlock   uint32 // Journal info block number

	CreateDate  uint32 // Volume creation date (seconds since HFS+ epoch)
	ModifyDate  uint32 // Volume last modification date
	BackupDate  uint32 // Volume last backup date
	CheckedDate uint32 // Volume last checked date

	FileCount   uint32 // Number of files on volume
	FolderCount uint32 // Number of folders on volume

	BlockSize   uint32 // Allocation block size in bytes
	TotalBlocks uint32 // Total number of allocation blocks
	FreeBlocks  uint32 // Number of free allocation blocks

	NextAllocation uint32 // Hint for next allocation block
	RsrcClumpSize  uint32 // Default resource fork clump size
	DataClumpSize  uint32 // Default data fork clump size
	NextCatalogID  uint32 // Next unused catalog node ID

	WriteCount      uint32 // Volume write count
	EncodingsBitmap uint64 // Encodings used on this volume

	FinderInfo [32]byte // Information used by Finder

	AllocationFile ForkData // Allocation bitmap file
	ExtentsFile    ForkData // Extents overflow file
	CatalogFile    ForkData // Catalog file
	AttributesFile ForkData // Attributes file
	StartupFile    ForkData // Startup file (bootloader)
}

// ForkData describes a file's fork (data or resource)
type ForkData struct {
	LogicalSize uint64              // Logical size of fork in bytes
	ClumpSize   uint32              // Fork clump size
	TotalBlocks uint32              // Total blocks used by fork
	Extents     [8]ExtentDescriptor // Initial extent records
}

// ExtentDescriptor describes a contiguous range of blocks
type ExtentDescriptor struct {
	StartBlock uint32 // First allocation block
	BlockCount uint32 // Number of allocation blocks
}

// Volume attributes flags
const (
	AttrVolumeHardwareLock     = 1 << 7  // Volume is hardware locked
	AttrVolumeUnmounted        = 1 << 8  // Volume was unmounted cleanly
	AttrVolumeSparedBad        = 1 << 9  // Volume has bad blocks spared
	AttrVolumeNoCacheRequired  = 1 << 10 // No cache required for this volume
	AttrBootVolumeInconsistent = 1 << 11 // Boot volume is inconsistent
	AttrCatalogNodeIDsReused   = 1 << 12 // Catalog node IDs have been reused
	AttrVolumeJournaled        = 1 << 13 // Volume is journaled
	AttrVolumeSoftwareLock     = 1 << 15 // Volume is software locked
)

// BTNodeDescriptor describes a B-tree node
type BTNodeDescriptor struct {
	FLink      uint32 // Forward link (next node at this level)
	BLink      uint32 // Backward link (previous node at this level)
	Kind       int8   // Node type (leaf, index, header, map)
	Height     uint8  // Node level (0 = leaf)
	NumRecords uint16 // Number of records in node
	Reserved   uint16
}

// Node types
const (
	NodeTypeLeaf   = -1
	NodeTypeIndex  = 0
	NodeTypeHeader = 1
	NodeTypeMap    = 2
)

// BTHeaderRecord is the B-tree header record
type BTHeaderRecord struct {
	TreeDepth      uint16 // Maximum height of tree
	RootNode       uint32 // Node number of root
	LeafRecords    uint32 // Number of leaf records
	FirstLeafNode  uint32 // Node number of first leaf
	LastLeafNode   uint32 // Node number of last leaf
	NodeSize       uint16 // Size of a node in bytes
	MaxKeyLength   uint16 // Maximum key length
	TotalNodes     uint32 // Total number of nodes
	FreeNodes      uint32 // Number of free nodes
	Reserved1      uint16
	ClumpSize      uint32 // Clump size
	BTType         uint8  // B-tree type
	KeyCompareType uint8  // Key comparison type
	Attributes     uint32 // B-tree attributes
	Reserved3      [16]uint32
}

// CatalogKey is the key for catalog B-tree records
type CatalogKey struct {
	KeyLength uint16       // Length of key in bytes
	ParentID  uint32       // Parent catalog node ID (CNID)
	NodeName  HFSUniStr255 // Name of the node
}

// HFSUniStr255 is a Unicode string (up to 255 characters)
type HFSUniStr255 struct {
	Length  uint16      // Number of Unicode characters
	Unicode [255]uint16 // Unicode characters (UTF-16BE)
}

// CatalogFolder represents a folder in the catalog
type CatalogFolder struct {
	RecordType       int16              // Record type (folder = 1)
	Flags            uint16             // Folder flags
	Valence          uint32             // Number of items in folder
	FolderID         uint32             // Folder catalog node ID
	CreateDate       uint32             // Date folder was created
	ContentModDate   uint32             // Date folder contents were modified
	AttributeModDate uint32             // Date folder attributes were modified
	AccessDate       uint32             // Date folder was last accessed
	BackupDate       uint32             // Date folder was last backed up
	Permissions      Permissions        // BSD permissions
	UserInfo         FolderInfo         // Finder user info
	FinderInfo       ExtendedFolderInfo // Finder extended info
	TextEncoding     uint32             // Text encoding hint
	Reserved         uint32
}

// CatalogFile represents a file in the catalog
type CatalogFile struct {
	RecordType       int16  // Record type (file = 2)
	Flags            uint16 // File flags
	Reserved1        uint32
	FileID           uint32           // File catalog node ID
	CreateDate       uint32           // Date file was created
	ContentModDate   uint32           // Date file contents were modified
	AttributeModDate uint32           // Date file attributes were modified
	AccessDate       uint32           // Date file was last accessed
	BackupDate       uint32           // Date file was last backed up
	Permissions      Permissions      // BSD permissions
	UserInfo         FileInfo         // Finder user info
	FinderInfo       ExtendedFileInfo // Finder extended info
	TextEncoding     uint32           // Text encoding hint
	Reserved2        uint32
	DataFork         ForkData // Data fork
	ResourceFork     ForkData // Resource fork
}

// Permissions represents BSD-style permissions
type Permissions struct {
	OwnerID    uint32 // Owner user ID
	GroupID    uint32 // Group ID
	AdminFlags uint8  // Admin flags
	OwnerFlags uint8  // Owner flags
	FileMode   uint16 // File mode (permissions)
	Special    uint32 // Special device info
}

// FileInfo is Finder user info for files
type FileInfo struct {
	FileType    uint32 // File type (4-char code)
	FileCreator uint32 // File creator (4-char code)
	FinderFlags uint16 // Finder flags
	Location    Point  // File location in window
	Reserved    uint16
}

// FolderInfo is Finder user info for folders
type FolderInfo struct {
	WindowBounds Rect   // Window bounds
	FinderFlags  uint16 // Finder flags
	Location     Point  // Folder location
	Reserved     uint16
}

// ExtendedFileInfo is extended Finder info for files
type ExtendedFileInfo struct {
	Reserved1           [4]uint16
	ExtendedFinderFlags uint16
	Reserved2           uint16
	PutAwayFolderID     uint32
}

// ExtendedFolderInfo is extended Finder info for folders
type ExtendedFolderInfo struct {
	ScrollPosition      Point
	Reserved1           uint32
	ExtendedFinderFlags uint16
	Reserved2           uint16
	PutAwayFolderID     uint32
}

// Point represents a 2D point
type Point struct {
	V int16 // Vertical coordinate
	H int16 // Horizontal coordinate
}

// Rect represents a rectangle
type Rect struct {
	Top    int16
	Left   int16
	Bottom int16
	Right  int16
}

// Record types
const (
	RecordTypeFolder       = 0x0001
	RecordTypeFile         = 0x0002
	RecordTypeFolderThread = 0x0003
	RecordTypeFileThread   = 0x0004
)

// File flags
const (
	FileFlagLocked             = 0x0001 // File is locked
	FileFlagThreadExists       = 0x0002 // Thread record exists
	FileFlagHasAttributeRecord = 0x0004 // File has attributes
	FileFlagHasSecurityData    = 0x0008 // File has security data
	FileFlagHasResourceFork    = 0x0010 // File has resource fork
	FileFlagHasDataFork        = 0x0020 // File has data fork
	FileFlagHasCompression     = 0x0080 // File is compressed
)

// JournalInfoBlock contains information about the journal
type JournalInfoBlock struct {
	Flags           uint32    // Journal flags
	DeviceSignature [8]uint32 // Device signature
	Offset          uint64    // Offset to journal from volume start
	Size            uint64    // Size of journal in bytes
	Reserved        [32]uint32
}

// AttributeKey is the key for attributes B-tree
type AttributeKey struct {
	KeyLength  uint16 // Length of key
	Pad        uint16
	FileID     uint32      // File catalog node ID
	StartBlock uint32      // Starting block number
	NameLength uint16      // Attribute name length
	Name       [127]uint16 // Attribute name (UTF-16BE)
}

// AttributeRecord represents an extended attribute
type AttributeRecord struct {
	RecordType uint32 // Record type
	Reserved   uint32
	Size       uint32 // Size of attribute data
	Data       []byte // Attribute data
}

// Helper functions

// ParseHFSTime converts HFS+ time (seconds since 1904) to Go time
func ParseHFSTime(hfsTime uint32) time.Time {
	if hfsTime == 0 {
		return time.Time{}
	}
	return hfsPlusEpoch.Add(time.Duration(hfsTime) * time.Second)
}

// ToGoString converts HFSUniStr255 to Go string
func (s *HFSUniStr255) ToGoString() string {
	runes := make([]rune, s.Length)
	for i := uint16(0); i < s.Length; i++ {
		runes[i] = rune(s.Unicode[i])
	}
	return string(runes)
}

// ParseCatalogKey parses a catalog key from bytes
func ParseCatalogKey(data []byte) (*CatalogKey, int, error) {
	if len(data) < 6 {
		return nil, 0, fmt.Errorf("data too short for catalog key")
	}

	key := &CatalogKey{}
	key.KeyLength = binary.BigEndian.Uint16(data[0:2])
	key.ParentID = binary.BigEndian.Uint32(data[2:6])

	if len(data) < 6+2 {
		return nil, 0, fmt.Errorf("data too short for node name length")
	}

	key.NodeName.Length = binary.BigEndian.Uint16(data[6:8])

	if int(key.NodeName.Length) > 255 {
		return nil, 0, fmt.Errorf("invalid node name length: %d", key.NodeName.Length)
	}

	expectedSize := 8 + int(key.NodeName.Length)*2
	if len(data) < expectedSize {
		return nil, 0, fmt.Errorf("data too short for node name")
	}

	for i := uint16(0); i < key.NodeName.Length; i++ {
		offset := 8 + int(i)*2
		key.NodeName.Unicode[i] = binary.BigEndian.Uint16(data[offset : offset+2])
	}

	totalSize := int(key.KeyLength) + 2 // KeyLength field + actual key data
	return key, totalSize, nil
}

// FileTypeString converts a file type code to string
func FileTypeString(code uint32) string {
	return string([]byte{
		byte(code >> 24),
		byte(code >> 16),
		byte(code >> 8),
		byte(code),
	})
}
