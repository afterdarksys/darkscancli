package hfsplus

import (
	"encoding/binary"
	"fmt"
)

// BTree represents an HFS+ B-tree
type BTree struct {
	hfs       *HFSPlus
	fork      *ForkData
	header    *BTHeaderRecord
	nodeSize  uint32
	nodeCache map[uint32]*BTNode
}

// BTNode represents a node in the B-tree
type BTNode struct {
	Descriptor BTNodeDescriptor
	Records    []BTRecord
}

// BTRecord represents a record in a B-tree node
type BTRecord struct {
	Key  []byte
	Data []byte
}

// NewBTree creates a new B-tree parser
func NewBTree(hfs *HFSPlus, fork *ForkData) (*BTree, error) {
	bt := &BTree{
		hfs:       hfs,
		fork:      fork,
		nodeCache: make(map[uint32]*BTNode),
	}

	// Read header node (node 0)
	headerNode, err := bt.readNode(0)
	if err != nil {
		return nil, fmt.Errorf("failed to read header node: %w", err)
	}

	if headerNode.Descriptor.Kind != NodeTypeHeader {
		return nil, fmt.Errorf("node 0 is not a header node")
	}

	// Parse header record
	if len(headerNode.Records) < 1 {
		return nil, fmt.Errorf("header node has no records")
	}

	bt.header = &BTHeaderRecord{}
	if err := bt.parseHeaderRecord(headerNode.Records[0].Data); err != nil {
		return nil, fmt.Errorf("failed to parse header record: %w", err)
	}

	bt.nodeSize = uint32(bt.header.NodeSize)

	return bt, nil
}

// parseHeaderRecord parses the B-tree header record
func (bt *BTree) parseHeaderRecord(data []byte) error {
	if len(data) < 106 {
		return fmt.Errorf("header record too short")
	}

	bt.header.TreeDepth = binary.BigEndian.Uint16(data[0:2])
	bt.header.RootNode = binary.BigEndian.Uint32(data[2:6])
	bt.header.LeafRecords = binary.BigEndian.Uint32(data[6:10])
	bt.header.FirstLeafNode = binary.BigEndian.Uint32(data[10:14])
	bt.header.LastLeafNode = binary.BigEndian.Uint32(data[14:18])
	bt.header.NodeSize = binary.BigEndian.Uint16(data[18:20])
	bt.header.MaxKeyLength = binary.BigEndian.Uint16(data[20:22])
	bt.header.TotalNodes = binary.BigEndian.Uint32(data[22:26])
	bt.header.FreeNodes = binary.BigEndian.Uint32(data[26:30])
	bt.header.ClumpSize = binary.BigEndian.Uint32(data[32:36])
	bt.header.BTType = data[36]
	bt.header.KeyCompareType = data[37]
	bt.header.Attributes = binary.BigEndian.Uint32(data[38:42])

	return nil
}

// readNode reads a B-tree node
func (bt *BTree) readNode(nodeNumber uint32) (*BTNode, error) {
	// Check cache
	if node, ok := bt.nodeCache[nodeNumber]; ok {
		return node, nil
	}

	// Calculate node offset within the fork
	nodeOffset := uint64(nodeNumber) * uint64(bt.nodeSize)

	// Read node data
	nodeData := make([]byte, bt.nodeSize)
	if err := bt.readForkData(bt.fork, nodeOffset, nodeData); err != nil {
		return nil, fmt.Errorf("failed to read node data: %w", err)
	}

	// Parse node descriptor
	node := &BTNode{}
	if err := bt.parseNodeDescriptor(nodeData, &node.Descriptor); err != nil {
		return nil, fmt.Errorf("failed to parse node descriptor: %w", err)
	}

	// Parse records
	if err := bt.parseNodeRecords(nodeData, node); err != nil {
		return nil, fmt.Errorf("failed to parse node records: %w", err)
	}

	// Cache node
	bt.nodeCache[nodeNumber] = node

	return node, nil
}

// parseNodeDescriptor parses a node descriptor
func (bt *BTree) parseNodeDescriptor(data []byte, desc *BTNodeDescriptor) error {
	if len(data) < 14 {
		return fmt.Errorf("data too short for node descriptor")
	}

	desc.FLink = binary.BigEndian.Uint32(data[0:4])
	desc.BLink = binary.BigEndian.Uint32(data[4:8])
	desc.Kind = int8(data[8])
	desc.Height = data[9]
	desc.NumRecords = binary.BigEndian.Uint16(data[10:12])

	return nil
}

// parseNodeRecords parses records from a node
func (bt *BTree) parseNodeRecords(data []byte, node *BTNode) error {
	numRecords := int(node.Descriptor.NumRecords)
	if numRecords == 0 {
		return nil
	}

	// Record offsets are at the end of the node
	offsetsStart := int(bt.nodeSize) - (numRecords+1)*2

	if offsetsStart < 14 {
		return fmt.Errorf("invalid node structure")
	}

	offsets := make([]uint16, numRecords+1)
	for i := 0; i <= numRecords; i++ {
		offset := offsetsStart + i*2
		if offset+2 > len(data) {
			return fmt.Errorf("offset out of bounds")
		}
		offsets[i] = binary.BigEndian.Uint16(data[offset : offset+2])
	}

	// Parse each record
	node.Records = make([]BTRecord, numRecords)
	for i := 0; i < numRecords; i++ {
		start := int(offsets[i])
		end := int(offsets[i+1])

		if start < 14 || end > int(bt.nodeSize) || start >= end {
			return fmt.Errorf("invalid record bounds")
		}

		recordData := data[start:end]
		node.Records[i] = BTRecord{
			Key:  recordData,
			Data: recordData,
		}
	}

	return nil
}

// readForkData reads data from a fork
func (bt *BTree) readForkData(fork *ForkData, offset uint64, data []byte) error {
	remaining := uint64(len(data))
	position := offset
	dataOffset := 0

	// Read from extents
	for _, extent := range fork.Extents {
		if extent.BlockCount == 0 {
			break
		}

		extentStart := uint64(extent.StartBlock) * uint64(bt.hfs.header.BlockSize)
		extentSize := uint64(extent.BlockCount) * uint64(bt.hfs.header.BlockSize)

		if position < extentSize {
			// This extent contains data we need
			readOffset := extentStart + position
			readSize := extentSize - position

			if readSize > remaining {
				readSize = remaining
			}

			if _, err := bt.hfs.source.ReadAt(data[dataOffset:dataOffset+int(readSize)], int64(readOffset)); err != nil {
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
		return fmt.Errorf("data extends beyond extents (need extents overflow file)")
	}

	return nil
}

// SearchCatalog searches the catalog B-tree for a file/folder
func (bt *BTree) SearchCatalog(parentID uint32, name string) (*BTRecord, error) {
	// Start from root
	return bt.searchNode(bt.header.RootNode, parentID, name)
}

// searchNode searches a specific node
func (bt *BTree) searchNode(nodeNumber uint32, parentID uint32, name string) (*BTRecord, error) {
	node, err := bt.readNode(nodeNumber)
	if err != nil {
		return nil, err
	}

	if node.Descriptor.Kind == NodeTypeLeaf {
		// Search leaf records
		for i := range node.Records {
			key, _, err := ParseCatalogKey(node.Records[i].Key)
			if err != nil {
				continue
			}

			if key.ParentID == parentID && key.NodeName.ToGoString() == name {
				return &node.Records[i], nil
			}
		}
		return nil, fmt.Errorf("not found")
	}

	// Index node - find appropriate child
	// For simplicity, do linear search (in production, use binary search)
	for i := range node.Records {
		key, keySize, err := ParseCatalogKey(node.Records[i].Key)
		if err != nil {
			continue
		}

		// Check if this is the right subtree
		if key.ParentID >= parentID {
			// Get child node pointer (after key)
			if keySize+4 > len(node.Records[i].Data) {
				continue
			}

			childNode := binary.BigEndian.Uint32(node.Records[i].Data[keySize : keySize+4])
			return bt.searchNode(childNode, parentID, name)
		}
	}

	return nil, fmt.Errorf("not found in index")
}

// WalkCatalog walks the entire catalog B-tree
func (bt *BTree) WalkCatalog(visitor func(*CatalogKey, []byte) error) error {
	return bt.walkLeafNodes(bt.header.FirstLeafNode, visitor)
}

// walkLeafNodes walks through all leaf nodes
func (bt *BTree) walkLeafNodes(nodeNumber uint32, visitor func(*CatalogKey, []byte) error) error {
	for nodeNumber != 0 {
		node, err := bt.readNode(nodeNumber)
		if err != nil {
			return err
		}

		if node.Descriptor.Kind != NodeTypeLeaf {
			return fmt.Errorf("expected leaf node, got %d", node.Descriptor.Kind)
		}

		// Visit each record
		for i := range node.Records {
			key, keySize, err := ParseCatalogKey(node.Records[i].Data)
			if err != nil {
				continue
			}

			recordData := node.Records[i].Data[keySize:]
			if err := visitor(key, recordData); err != nil {
				return err
			}
		}

		// Move to next leaf node
		nodeNumber = node.Descriptor.FLink
	}

	return nil
}
