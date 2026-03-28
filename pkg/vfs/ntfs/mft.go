package ntfs

import (
	"time"
)

// BootSector represents the BIOS Parameter Block (BPB) and Extended BPB of an NTFS volume.
type BootSector struct {
	JmpInstruction        [3]byte
	OEMID                 [8]byte
	BytesPerSector        uint16
	SectorsPerCluster     uint8
	ReservedSectors       uint16
	MediaDescriptor       uint8
	SectorsPerTrack       uint16
	NumberOfHeads         uint16
	HiddenSectors         uint32
	TotalSectors32        uint32
	TotalSectors64        uint64
	MFTCluster            uint64
	MFTMirrCluster        uint64
	ClustersPerMFTRec     int8
	Reserved0             [3]byte
	ClustersPerIndexBlock int8
	Reserved1             [3]byte
	VolumeSerialNumber    uint64
	Checksum              uint32
}

// MFTRecordHeader is the standard header for an MFT record.
type MFTRecordHeader struct {
	Magic                [4]byte // "FILE" or "BAAD"
	UpdateSequenceOffset uint16
	UpdateSequenceSize   uint16
	LogFileSeqNum        uint64
	SequenceNumber       uint16
	HardLinkCount        uint16
	AttributeOffset      uint16
	Flags                uint16 // 0x01 = InUse/Allocated, 0x02 = Directory
	UsedSize             uint32 // Real size of the MFT record
	AllocatedSize        uint32 // Allocated size of the MFT record
	BaseRecordRef        uint64 // Reference to base record if this is an extension
	NextAttrID           uint16
	RecordNumber         uint32 // XP and later
}

// AttributeType defines NTFS attributes.
type AttributeType uint32

const (
	AttrStandardInformation AttributeType = 0x10
	AttrAttributeList       AttributeType = 0x20
	AttrFileName            AttributeType = 0x30
	AttrVolumeVersion       AttributeType = 0x40
	AttrSecurityDescriptor  AttributeType = 0x50
	AttrVolumeName          AttributeType = 0x60
	AttrVolumeInformation   AttributeType = 0x70
	AttrData                AttributeType = 0x80
	AttrIndexRoot           AttributeType = 0x90
	AttrIndexAllocation     AttributeType = 0xA0
	AttrBitmap              AttributeType = 0xB0
	AttrReparsePoint        AttributeType = 0xC0
	AttrEAInformation       AttributeType = 0xD0
	AttrEA                  AttributeType = 0xE0
	AttrPropertySet         AttributeType = 0xF0
	AttrLoggedUtilityStream AttributeType = 0x100
)

const (
	FlagInUse     uint16 = 0x01
	FlagDirectory uint16 = 0x02
)

// FiletimeToTime converts Windows FILETIME (100-nanosecond intervals since January 1, 1601) to Unix time
func FiletimeToTime(ft uint64) time.Time {
	// 116444736000000000 is the difference between 1601 and 1970 in 100-ns intervals
	epoch := int64(ft) - 116444736000000000
	if epoch < 0 {
		return time.Unix(0, 0)
	}
	return time.Unix(0, epoch*100)
}
