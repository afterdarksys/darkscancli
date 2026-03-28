# HFS+ Filesystem Support

Advanced HFS+ (Hierarchical File System Plus) forensic parser and VFS implementation for macOS filesystem analysis.

## Features

### Core Capabilities

- **Volume Header Parsing**: Complete HFS+ and HFSX volume header support
- **B-Tree Catalog**: Full catalog B-tree traversal and search
- **File Extraction**: Read data and resource forks from any file
- **Extended Attributes**: Support for extended attributes (xattrs)
- **Journal Support**: Parse journal info for forensic analysis
- **Resource Forks**: Native support for HFS+ resource forks
- **Unicode Names**: Full Unicode filename support (UTF-16BE)
- **Extent Management**: Handle fragmented files via extent descriptors

### Forensic Features

- File metadata extraction (dates, permissions, Finder info)
- Volume information and statistics
- Journal information for recovery
- Support for both case-sensitive (HFSX) and case-insensitive (HFS+) volumes
- Direct disk/partition access without mounting
- Future: Deleted file recovery via catalog scanning

## Architecture

### File Structure

```
hfsplus/
├── structures.go    # HFS+ data structures
├── btree.go        # B-tree parser implementation
├── hfsplus.go      # Main HFS+ filesystem parser
├── vfs.go          # VFS interface implementation
└── README.md       # This file
```

### Key Components

**1. Volume Header** (`VolumeHeader`)
- Located at offset 1024 bytes
- Contains volume metadata and special file locations
- Signature: 'H+' (0x482B) for HFS+, 'HX' (0x4858) for HFSX

**2. B-Tree Catalog** (`BTree`)
- Stores file and folder metadata
- Node-based structure with efficient searching
- Supports index nodes, leaf nodes, header nodes

**3. Fork Data** (`ForkData`)
- Describes file data (data fork) and resources (resource fork)
- Contains extent descriptors for file allocation
- Supports up to 8 inline extents (more via extents overflow file)

**4. Catalog Records**
- `CatalogFile`: File metadata with both forks
- `CatalogFolder`: Folder metadata with item count
- `CatalogKey`: Search key (parent ID + Unicode name)

## Usage

### Basic File Access

```go
import "github.com/afterdarksys/darkscan/pkg/vfs/hfsplus"

// Open HFS+ volume
partition := ... // Your partition/disk source
vfs, err := hfsplus.NewVFS(partition)
if err != nil {
    log.Fatal(err)
}

// Open a file
file, err := vfs.Open("/Users/alice/Documents/report.pdf")
if err != nil {
    log.Fatal(err)
}
defer file.Close()

// Read file contents
data := make([]byte, 4096)
n, err := file.Read(data)
```

### Resource Fork Access

```go
// Open file
file, err := vfs.Open("/Applications/MyApp.app/Contents/Resources/icon.icns")
if err != nil {
    log.Fatal(err)
}

// Read resource fork (HFS+ specific)
hfsFile := file.(*hfsplus.File)
resourceData, err := hfsFile.ReadResourceFork()
if err != nil {
    log.Fatal(err)
}
```

### List All Files

```go
vfs, _ := hfsplus.NewVFS(partition)

entries, err := vfs.hfs.ListFiles()
if err != nil {
    log.Fatal(err)
}

for _, entry := range entries {
    fmt.Printf("%s - %d bytes - %s\n",
        entry.Name,
        entry.Size,
        entry.ModifyDate)
}
```

### Volume Information

```go
vfs, _ := hfsplus.NewVFS(partition)

info := vfs.GetVolumeInfo()
fmt.Printf("HFS+ Volume:\n")
fmt.Printf("  Block Size: %d bytes\n", info.BlockSize)
fmt.Printf("  Total Blocks: %d\n", info.TotalBlocks)
fmt.Printf("  Free Blocks: %d\n", info.FreeBlocks)
fmt.Printf("  Files: %d\n", info.FileCount)
fmt.Printf("  Folders: %d\n", info.FolderCount)
fmt.Printf("  Journaled: %v\n", info.IsJournaled)
fmt.Printf("  Created: %s\n", info.CreateDate)
fmt.Printf("  Modified: %s\n", info.ModifyDate)
```

### Search Files

```go
// Search by pattern
matches, err := vfs.SearchFilesByName("*.dmg")
if err != nil {
    log.Fatal(err)
}

for _, path := range matches {
    fmt.Println(path)
}
```

### Extended Attributes

```go
// Get extended attributes
xattrs, err := vfs.GetFileExtendedAttributes("/path/to/file")
if err != nil {
    log.Fatal(err)
}

for name, data := range xattrs {
    fmt.Printf("Attribute: %s (%d bytes)\n", name, len(data))
}
```

### Walk Filesystem

```go
err := vfs.Walk("/", func(path string, d fs.DirEntry, err error) error {
    if err != nil {
        return err
    }

    info, _ := d.Info()
    fmt.Printf("%s - %d bytes\n", path, info.Size())

    return nil
})
```

## HFS+ Specific Features

### Catalog Node IDs (CNIDs)

Special CNIDs:
- **1**: Parent of root (not used)
- **2**: Root folder
- **3**: Extents overflow file
- **4**: Catalog file
- **5**: Bad blocks file
- **6**: Allocation bitmap file
- **7**: Startup file
- **8**: Attributes file
- **16+**: User files and folders

### Finder Information

HFS+ stores macOS Finder metadata:
- File type and creator codes (4-character codes)
- Custom icon locations
- Window positions
- Color labels
- Locked status

### Resource Forks

Resource forks are a unique HFS+ feature:
- Store structured data (icons, menus, dialogs)
- Common in older macOS applications
- Still present in some modern files (`.icns`, `.rsrc`)
- Access via `ReadResourceFork()` method

### Time Format

HFS+ uses seconds since January 1, 1904 (HFS+ epoch):
- Different from Unix epoch (1970)
- Automatically converted to Go `time.Time`
- Available fields: create, modify, access, backup, attribute mod

## Forensic Analysis

### Journal Information

```go
if vfs.IsJournaled() {
    journal := vfs.GetJournalInfo()
    if journal != nil {
        fmt.Printf("Journal Offset: 0x%X\n", journal.Offset)
        fmt.Printf("Journal Size: %d bytes\n", journal.Size)
        // Analyze journal for recent changes
    }
}
```

### Deleted File Recovery

```go
// Future implementation
deletedFiles, err := vfs.RecoverDeletedFiles()
for _, file := range deletedFiles {
    fmt.Printf("Deleted: %s (%d bytes)\n", file.Name, file.Size)
}
```

### Case Sensitivity

```go
if vfs.IsCaseSensitive() {
    fmt.Println("This is an HFSX (case-sensitive) volume")
} else {
    fmt.Println("This is an HFS+ (case-insensitive) volume")
}
```

## Technical Details

### Volume Header Structure

Located at offset 1024:
- Signature (2 bytes): 'H+' or 'HX'
- Version (2 bytes): 4 for HFS+, 5 for HFSX
- Attributes (4 bytes): Volume flags
- Block size (4 bytes): Allocation block size
- Total/free blocks (8 bytes): Space information
- Special file fork data (5 × 80 bytes)

### B-Tree Node Structure

Each node contains:
- **Node Descriptor** (14 bytes): Links, type, height, record count
- **Records**: Variable-size key/data pairs
- **Free Space**: Unused space
- **Offsets**: Record offset table (at end of node)

### Catalog Key Format

Keys are compared by:
1. Parent CNID (ascending)
2. Node name (Unicode, case-insensitive or case-sensitive)

### Extent Descriptors

Each extent describes a contiguous allocation:
- Start block (4 bytes): First allocation block
- Block count (4 bytes): Number of blocks

Files can have up to 8 inline extents. More require extents overflow file.

## Performance Considerations

### Caching

- File metadata cached in memory
- B-tree nodes cached during traversal
- Consider memory usage for large volumes

### Optimization

- Use `ReadFileAt()` for partial reads
- Batch file operations when possible
- Minimize catalog searches (cache paths)

## Limitations

### Current Implementation

1. **Extents Overflow**: Not fully implemented for highly fragmented files
2. **Deleted File Recovery**: Stub implementation (future feature)
3. **Journal Replay**: Journal parsing only, not replay
4. **Compression**: HFS+ compression not supported
5. **Encryption**: FileVault detection only, not decryption

### Compatibility

- Read-only access (no write operations)
- Requires raw partition/disk access
- No support for corrupted/damaged volumes (yet)
- Unicode normalization not implemented

## Integration with darkscand

### Usage in Scanner

```go
// Register HFS+ VFS
vfs.RegisterFilesystem("hfsplus", func(p vfs.Partition) (vfs.VFS, error) {
    return hfsplus.NewVFS(p)
})

// Scan HFS+ volume
scanner := darkscan.NewScanner()
results := scanner.ScanPartition("/dev/disk0s2", "hfsplus")
```

### Forensic Workflow

1. Identify HFS+ partition via signature
2. Parse volume header
3. Extract file list from catalog
4. Scan each file for malware
5. Check extended attributes for suspicious data
6. Analyze journal for recent activity
7. Generate forensic report

## Examples

### Complete File Extraction

```go
package main

import (
    "fmt"
    "log"
    "os"

    "github.com/afterdarksys/darkscan/pkg/vfs/hfsplus"
    "github.com/afterdarksys/darkscan/pkg/vfs/local"
)

func main() {
    // Open disk image
    disk, err := local.NewLocalPartition("/path/to/disk.dmg")
    if err != nil {
        log.Fatal(err)
    }
    defer disk.Close()

    // Create HFS+ VFS
    vfs, err := hfsplus.NewVFS(disk)
    if err != nil {
        log.Fatal(err)
    }

    // Extract all files
    entries, err := vfs.hfs.ListFiles()
    if err != nil {
        log.Fatal(err)
    }

    for _, entry := range entries {
        fmt.Printf("Extracting: %s\n", entry.Name)

        // Get file
        file, err := vfs.hfs.GetFileByPath(entry.Name)
        if err != nil {
            continue
        }

        // Read data
        data, err := vfs.hfs.ReadFile(file, false)
        if err != nil {
            continue
        }

        // Save to disk
        os.WriteFile("extracted/"+entry.Name, data, 0644)
    }
}
```

## References

- [Apple TN1150: HFS Plus Volume Format](https://developer.apple.com/library/archive/technotes/tn/tn1150.html)
- [HFS+ Specification](https://developer.apple.com/documentation/coreservices/file_system_management)
- [The Sleuth Kit: HFS+ Implementation](https://github.com/sleuthkit/sleuthkit)
- [libhfs: HFS Filesystem Library](https://www.mars.org/home/rob/proj/hfs/)

## Future Enhancements

- [ ] Extents overflow file support
- [ ] Deleted file recovery via catalog scanning
- [ ] Journal transaction replay
- [ ] HFS+ compression support
- [ ] Hard link detection and handling
- [ ] Symbolic link support
- [ ] File cloning (APFS-style) detection
- [ ] Snapshot support (for APFS migration)
- [ ] Unicode normalization (NFD ↔ NFC)
- [ ] Performance optimization for large volumes

## License

Same license as darkscand parent project.
