package carving

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sort"
)

// Fragment represents a piece of a fragmented file
type Fragment struct {
	Offset    int64  // Offset where fragment was found
	Size      int64  // Size of fragment
	Data      []byte // Fragment data
	Sequence  int    // Estimated sequence number
	Signature FileSignature
}

// FragmentedFile represents a file reconstructed from fragments
type FragmentedFile struct {
	Fragments    []*Fragment
	TotalSize    int64
	Type         string
	Extension    string
	IsComplete   bool
	Confidence   int
	MissingRanges []Range // Byte ranges that are missing
}

// Range represents a byte range
type Range struct {
	Start int64
	End   int64
}

// FragmentAssembler assembles fragmented files
type FragmentAssembler struct {
	maxGap       int64 // Maximum gap between fragments to consider
	minFragments int   // Minimum fragments needed
}

// NewFragmentAssembler creates a new fragment assembler
func NewFragmentAssembler() *FragmentAssembler {
	return &FragmentAssembler{
		maxGap:       1024 * 1024, // 1MB max gap
		minFragments: 2,
	}
}

// AssembleFragments attempts to assemble fragments into complete files
func (fa *FragmentAssembler) AssembleFragments(fragments []*Fragment) ([]*FragmentedFile, error) {
	if len(fragments) < fa.minFragments {
		return nil, fmt.Errorf("insufficient fragments: %d < %d", len(fragments), fa.minFragments)
	}

	// Group fragments by file type
	grouped := fa.groupFragmentsByType(fragments)

	var assembled []*FragmentedFile

	for fileType, frags := range grouped {
		// Try to assemble fragments of this type
		file := fa.assembleFileType(fileType, frags)
		if file != nil {
			assembled = append(assembled, file)
		}
	}

	return assembled, nil
}

// groupFragmentsByType groups fragments by detected file type
func (fa *FragmentAssembler) groupFragmentsByType(fragments []*Fragment) map[string][]*Fragment {
	grouped := make(map[string][]*Fragment)

	for _, frag := range fragments {
		key := frag.Signature.Extension
		grouped[key] = append(grouped[key], frag)
	}

	return grouped
}

// assembleFileType attempts to assemble fragments of a specific type
func (fa *FragmentAssembler) assembleFileType(fileType string, fragments []*Fragment) *FragmentedFile {
	if len(fragments) < fa.minFragments {
		return nil
	}

	// Sort fragments by offset
	sort.Slice(fragments, func(i, j int) bool {
		return fragments[i].Offset < fragments[j].Offset
	})

	// Try to determine fragment sequence
	fa.orderFragments(fragments)

	// Check if fragments are contiguous or have acceptable gaps
	if !fa.validateFragmentSequence(fragments) {
		return nil
	}

	// Assemble fragments
	file := &FragmentedFile{
		Fragments:  fragments,
		Type:       fileType,
		Extension:  fragments[0].Signature.Extension,
		Confidence: 70, // Base confidence
	}

	// Calculate total size and detect gaps
	file.TotalSize = fa.calculateTotalSize(fragments)
	file.MissingRanges = fa.detectMissingRanges(fragments)

	// Check if file appears complete
	file.IsComplete = len(file.MissingRanges) == 0

	if !file.IsComplete {
		file.Confidence -= 20
	}

	return file
}

// orderFragments attempts to determine the correct sequence of fragments
func (fa *FragmentAssembler) orderFragments(fragments []*Fragment) {
	// For now, use offset-based ordering
	// More sophisticated ordering could use:
	// - Content analysis
	// - Sequence numbers (if file format supports)
	// - Structural markers

	for i := range fragments {
		fragments[i].Sequence = i
	}
}

// validateFragmentSequence checks if fragment sequence is valid
func (fa *FragmentAssembler) validateFragmentSequence(fragments []*Fragment) bool {
	if len(fragments) == 0 {
		return false
	}

	// Check gaps between fragments
	for i := 0; i < len(fragments)-1; i++ {
		gap := fragments[i+1].Offset - (fragments[i].Offset + fragments[i].Size)

		// Gap too large
		if gap > fa.maxGap {
			return false
		}

		// Overlapping fragments (suspicious)
		if gap < 0 {
			return false
		}
	}

	return true
}

// calculateTotalSize calculates total size of assembled file
func (fa *FragmentAssembler) calculateTotalSize(fragments []*Fragment) int64 {
	if len(fragments) == 0 {
		return 0
	}

	// Total from first fragment start to last fragment end
	first := fragments[0]
	last := fragments[len(fragments)-1]

	return (last.Offset + last.Size) - first.Offset
}

// detectMissingRanges finds gaps in fragment coverage
func (fa *FragmentAssembler) detectMissingRanges(fragments []*Fragment) []Range {
	var missing []Range

	for i := 0; i < len(fragments)-1; i++ {
		currentEnd := fragments[i].Offset + fragments[i].Size
		nextStart := fragments[i+1].Offset

		if nextStart > currentEnd {
			// There's a gap
			missing = append(missing, Range{
				Start: currentEnd,
				End:   nextStart,
			})
		}
	}

	return missing
}

// ReconstructFile reconstructs a file from fragments
func (fa *FragmentAssembler) ReconstructFile(file *FragmentedFile) ([]byte, error) {
	if len(file.Fragments) == 0 {
		return nil, fmt.Errorf("no fragments to reconstruct")
	}

	// Allocate buffer for complete file
	buffer := make([]byte, file.TotalSize)

	// Copy each fragment into appropriate position
	baseOffset := file.Fragments[0].Offset

	for _, frag := range file.Fragments {
		relativeOffset := frag.Offset - baseOffset
		if relativeOffset < 0 || relativeOffset+frag.Size > file.TotalSize {
			return nil, fmt.Errorf("fragment out of bounds")
		}

		copy(buffer[relativeOffset:], frag.Data)
	}

	// Fill missing ranges with zeros or attempt recovery
	for _, missing := range file.MissingRanges {
		// Could attempt to fill gaps using context or leave as zeros
		// For now, gaps are left as zeros
		_ = missing
	}

	return buffer, nil
}

// SmartFragmentCarver performs intelligent fragment detection and assembly
type SmartFragmentCarver struct {
	carver    *Carver
	assembler *FragmentAssembler
}

// NewSmartFragmentCarver creates a smart fragment carver
func NewSmartFragmentCarver(carver *Carver) *SmartFragmentCarver {
	return &SmartFragmentCarver{
		carver:    carver,
		assembler: NewFragmentAssembler(),
	}
}

// CarveAndAssemble carves and attempts to assemble fragmented files
func (sfc *SmartFragmentCarver) CarveAndAssemble(ctx context.Context, r io.ReaderAt, offset, length int64) ([]*FragmentedFile, error) {
	// First, carve all fragments
	carved, err := sfc.carver.CarveReader(ctx, r, offset, length)
	if err != nil {
		return nil, err
	}

	// Convert carved files to fragments
	var fragments []*Fragment
	for _, file := range carved {
		frag := &Fragment{
			Offset:    file.Offset,
			Size:      file.Size,
			Data:      file.Data,
			Signature: file.Signature,
		}
		fragments = append(fragments, frag)
	}

	// Attempt assembly
	assembled, err := sfc.assembler.AssembleFragments(fragments)
	if err != nil {
		return nil, err
	}

	return assembled, nil
}

// AdvancedFragmentMatcher uses content analysis to match fragments
type AdvancedFragmentMatcher struct {
	blockSize int64
}

// NewAdvancedFragmentMatcher creates an advanced fragment matcher
func NewAdvancedFragmentMatcher() *AdvancedFragmentMatcher {
	return &AdvancedFragmentMatcher{
		blockSize: 4096,
	}
}

// MatchFragments attempts to match fragments using content similarity
func (afm *AdvancedFragmentMatcher) MatchFragments(fragments []*Fragment) [][]int {
	// Group fragments that likely belong together
	var groups [][]int

	// Use entropy, byte patterns, and structure to match
	for i := 0; i < len(fragments); i++ {
		group := []int{i}

		for j := i + 1; j < len(fragments); j++ {
			if afm.areRelated(fragments[i], fragments[j]) {
				group = append(group, j)
			}
		}

		if len(group) > 1 {
			groups = append(groups, group)
		}
	}

	return groups
}

// areRelated checks if two fragments are likely from the same file
func (afm *AdvancedFragmentMatcher) areRelated(frag1, frag2 *Fragment) bool {
	// Must be same file type
	if frag1.Signature.Extension != frag2.Signature.Extension {
		return false
	}

	// Check entropy similarity
	entropy1 := calculateEntropy(frag1.Data)
	entropy2 := calculateEntropy(frag2.Data)

	if abs(entropy1-entropy2) > 1.0 {
		return false
	}

	// Check for pattern continuity
	if afm.hasContinuity(frag1.Data, frag2.Data) {
		return true
	}

	return false
}

// hasContinuity checks if fragments have content continuity
func (afm *AdvancedFragmentMatcher) hasContinuity(data1, data2 []byte) bool {
	// Check if end of data1 matches beginning of data2
	overlapSize := min(len(data1), len(data2), 256)

	if overlapSize < 16 {
		return false
	}

	// Try different overlap sizes
	for size := 16; size <= overlapSize; size *= 2 {
		tail := data1[len(data1)-size:]
		head := data2[:size]

		// Check for exact match
		if bytes.Equal(tail, head) {
			return true
		}

		// Check for partial match (allowing for some corruption)
		matches := 0
		for i := 0; i < size; i++ {
			if tail[i] == head[i] {
				matches++
			}
		}

		if float64(matches)/float64(size) > 0.9 { // 90% match
			return true
		}
	}

	return false
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

func min(values ...int) int {
	if len(values) == 0 {
		return 0
	}
	m := values[0]
	for _, v := range values[1:] {
		if v < m {
			m = v
		}
	}
	return m
}

// BifragmentGapFiller attempts to fill gaps between fragments
type BifragmentGapFiller struct {
	maxGapSize int64
}

// NewBifragmentGapFiller creates a gap filler
func NewBifragmentGapFiller() *BifragmentGapFiller {
	return &BifragmentGapFiller{
		maxGapSize: 64 * 1024, // 64KB
	}
}

// FillGap attempts to fill a gap between fragments using context
func (bgf *BifragmentGapFiller) FillGap(frag1, frag2 *Fragment, r io.ReaderAt) ([]byte, error) {
	gapStart := frag1.Offset + frag1.Size
	gapEnd := frag2.Offset
	gapSize := gapEnd - gapStart

	if gapSize <= 0 || gapSize > bgf.maxGapSize {
		return nil, fmt.Errorf("gap too large or invalid: %d", gapSize)
	}

	// Read the gap region
	gapData := make([]byte, gapSize)
	_, err := r.ReadAt(gapData, gapStart)
	if err != nil && err != io.EOF {
		return nil, err
	}

	// Validate that gap data is reasonable
	// (not all zeros, has reasonable entropy, etc.)
	if isAllZeros(gapData) {
		return nil, fmt.Errorf("gap is all zeros (likely unallocated)")
	}

	entropy := calculateEntropy(gapData)
	if entropy < 1.0 || entropy > 7.9 {
		return nil, fmt.Errorf("gap has suspicious entropy: %f", entropy)
	}

	return gapData, nil
}
