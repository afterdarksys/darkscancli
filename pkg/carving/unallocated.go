package carving

import (
	"context"
	"fmt"
	"io"
)

// UnallocatedRegion represents a region of unallocated space on disk
type UnallocatedRegion struct {
	Offset int64 // Starting offset
	Length int64 // Length in bytes
}

// AllocationMap tracks allocated and unallocated regions
type AllocationMap struct {
	regions []UnallocatedRegion
	total   int64
}

// NewAllocationMap creates a new allocation map
func NewAllocationMap(totalSize int64) *AllocationMap {
	return &AllocationMap{
		total: totalSize,
		regions: []UnallocatedRegion{
			{Offset: 0, Length: totalSize}, // Initially all unallocated
		},
	}
}

// MarkAllocated marks a region as allocated
func (am *AllocationMap) MarkAllocated(offset, length int64) {
	var newRegions []UnallocatedRegion

	for _, region := range am.regions {
		// Check if this allocated region overlaps with unallocated region
		if offset >= region.Offset+region.Length || offset+length <= region.Offset {
			// No overlap, keep region as-is
			newRegions = append(newRegions, region)
			continue
		}

		// There's overlap - split the unallocated region
		if offset > region.Offset {
			// Add region before allocation
			newRegions = append(newRegions, UnallocatedRegion{
				Offset: region.Offset,
				Length: offset - region.Offset,
			})
		}

		if offset+length < region.Offset+region.Length {
			// Add region after allocation
			newRegions = append(newRegions, UnallocatedRegion{
				Offset: offset + length,
				Length: (region.Offset + region.Length) - (offset + length),
			})
		}
	}

	am.regions = newRegions
}

// GetUnallocatedRegions returns all unallocated regions
func (am *AllocationMap) GetUnallocatedRegions() []UnallocatedRegion {
	return am.regions
}

// GetTotalUnallocated returns total unallocated space
func (am *AllocationMap) GetTotalUnallocated() int64 {
	var total int64
	for _, region := range am.regions {
		total += region.Length
	}
	return total
}

// UnallocatedScanner scans only unallocated regions of a filesystem
type UnallocatedScanner struct {
	carver *Carver
	allocMap *AllocationMap
}

// NewUnallocatedScanner creates a scanner for unallocated space
func NewUnallocatedScanner(carver *Carver, totalSize int64) *UnallocatedScanner {
	return &UnallocatedScanner{
		carver:   carver,
		allocMap: NewAllocationMap(totalSize),
	}
}

// MarkAllocated marks a region as allocated (won't be scanned)
func (us *UnallocatedScanner) MarkAllocated(offset, length int64) {
	us.allocMap.MarkAllocated(offset, length)
}

// ScanUnallocated scans only unallocated regions
func (us *UnallocatedScanner) ScanUnallocated(ctx context.Context, r io.ReaderAt) ([]*CarvedFile, error) {
	var allCarved []*CarvedFile

	regions := us.allocMap.GetUnallocatedRegions()

	for i, region := range regions {
		select {
		case <-ctx.Done():
			return allCarved, ctx.Err()
		default:
		}

		// Skip very small regions
		if region.Length < 512 {
			continue
		}

		// Carve this unallocated region
		carved, err := us.carver.CarveReader(ctx, r, region.Offset, region.Length)
		if err != nil {
			// Log error but continue with other regions
			continue
		}

		allCarved = append(allCarved, carved...)

		// Progress reporting could be added here
		_ = i // region index for progress
	}

	return allCarved, nil
}

// BuildAllocationMapFromNTFS builds allocation map from NTFS filesystem
func BuildAllocationMapFromNTFS(r io.ReaderAt, volumeSize int64) (*AllocationMap, error) {
	allocMap := NewAllocationMap(volumeSize)

	// Parse NTFS $Bitmap file to determine allocated clusters
	// This is a simplified version - real implementation would:
	// 1. Parse NTFS boot sector to get cluster size
	// 2. Parse MFT to find $Bitmap file
	// 3. Read $Bitmap and mark allocated clusters

	// For now, return basic map
	// TODO: Implement full NTFS bitmap parsing
	return allocMap, nil
}

// BuildAllocationMapFromHFSPlus builds allocation map from HFS+ filesystem
func BuildAllocationMapFromHFSPlus(r io.ReaderAt, volumeSize int64) (*AllocationMap, error) {
	allocMap := NewAllocationMap(volumeSize)

	// Parse HFS+ allocation file to determine allocated blocks
	// This is a simplified version - real implementation would:
	// 1. Parse HFS+ volume header
	// 2. Read allocation file (special file at catalog ID 6)
	// 3. Parse bitmap to mark allocated blocks

	// For now, return basic map
	// TODO: Implement full HFS+ allocation parsing
	return allocMap, nil
}

// BuildAllocationMapFromExt4 builds allocation map from ext4 filesystem
func BuildAllocationMapFromExt4(r io.ReaderAt, volumeSize int64) (*AllocationMap, error) {
	allocMap := NewAllocationMap(volumeSize)

	// Parse ext4 block bitmap to determine allocated blocks
	// This is a simplified version - real implementation would:
	// 1. Parse ext4 superblock
	// 2. Read block group descriptors
	// 3. Parse block bitmaps for each group

	// For now, return basic map
	// TODO: Implement full ext4 bitmap parsing
	return allocMap, nil
}

// ScanResult contains carving results with statistics
type ScanResult struct {
	Files            []*CarvedFile
	TotalScanned     int64
	UnallocatedSpace int64
	FilesRecovered   int
	BytesRecovered   int64
	ScanDuration     int64 // milliseconds
}

// SmartCarver performs intelligent carving with filesystem awareness
type SmartCarver struct {
	carver           *Carver
	filesystemType   string
	useUnallocated   bool
	parallelScan     bool
	workers          int
}

// NewSmartCarver creates an intelligent carver
func NewSmartCarver(carver *Carver, fsType string) *SmartCarver {
	return &SmartCarver{
		carver:         carver,
		filesystemType: fsType,
		useUnallocated: true,
		parallelScan:   true,
		workers:        4,
	}
}

// CarveWithFilesystemAwareness carves files using filesystem metadata
func (sc *SmartCarver) CarveWithFilesystemAwareness(ctx context.Context, r io.ReaderAt, volumeSize int64) (*ScanResult, error) {
	result := &ScanResult{}

	var allocMap *AllocationMap
	var err error

	// Build allocation map based on filesystem type
	if sc.useUnallocated {
		switch sc.filesystemType {
		case "ntfs":
			allocMap, err = BuildAllocationMapFromNTFS(r, volumeSize)
		case "hfsplus":
			allocMap, err = BuildAllocationMapFromHFSPlus(r, volumeSize)
		case "ext4":
			allocMap, err = BuildAllocationMapFromExt4(r, volumeSize)
		default:
			// Unknown filesystem - scan entire volume
			allocMap = NewAllocationMap(volumeSize)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to build allocation map: %w", err)
		}
	} else {
		// Scan entire volume
		allocMap = NewAllocationMap(volumeSize)
	}

	// Create unallocated scanner
	scanner := &UnallocatedScanner{
		carver:   sc.carver,
		allocMap: allocMap,
	}

	// Scan unallocated regions
	files, err := scanner.ScanUnallocated(ctx, r)
	if err != nil {
		return nil, err
	}

	// Populate result
	result.Files = files
	result.FilesRecovered = len(files)
	result.UnallocatedSpace = allocMap.GetTotalUnallocated()
	result.TotalScanned = result.UnallocatedSpace

	for _, file := range files {
		result.BytesRecovered += file.Size
	}

	return result, nil
}

// FilterRegionsByPattern filters regions based on search pattern
func FilterRegionsByPattern(regions []UnallocatedRegion, pattern []byte, r io.ReaderAt) []UnallocatedRegion {
	var filtered []UnallocatedRegion

	for _, region := range regions {
		// Quick check: read first block and see if pattern exists
		buffer := make([]byte, 4096)
		n, err := r.ReadAt(buffer, region.Offset)
		if err != nil && err != io.EOF {
			continue
		}

		// Search for pattern
		if containsPattern(buffer[:n], pattern) {
			filtered = append(filtered, region)
		}
	}

	return filtered
}

func containsPattern(data, pattern []byte) bool {
	if len(pattern) == 0 {
		return false
	}

	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j := 0; j < len(pattern); j++ {
			if data[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}

	return false
}
