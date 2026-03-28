package hfsplus_test

import (
	"fmt"
	"log"

	"github.com/afterdarksys/darkscan/pkg/vfs/hfsplus"
)

// ExampleVFS demonstrates basic HFS+ VFS usage
func ExampleVFS() {
	// This example assumes you have an HFS+ disk image or partition
	// partition := local.NewLocalPartition("/dev/disk2s2")

	// vfs, err := hfsplus.NewVFS(partition)
	// if err != nil {
	//     log.Fatal(err)
	// }

	// // Get volume information
	// info := vfs.GetVolumeInfo()
	// fmt.Printf("Volume Type: %s\n", vfs.Type())
	// fmt.Printf("Block Size: %d\n", info.BlockSize)
	// fmt.Printf("Total Files: %d\n", info.FileCount)
	// fmt.Printf("Total Folders: %d\n", info.FolderCount)
	// fmt.Printf("Journaled: %v\n", info.IsJournaled)

	// Output:
	// Volume Type: HFS+
	// Block Size: 4096
	// Total Files: 12345
	// Total Folders: 678
	// Journaled: true
}

// ExampleVFS_Open demonstrates opening and reading a file
func ExampleVFS_Open() {
	// partition := local.NewLocalPartition("/path/to/disk.dmg")
	// vfs, _ := hfsplus.NewVFS(partition)

	// // Open a file
	// file, err := vfs.Open("/Users/alice/Documents/report.pdf")
	// if err != nil {
	//     log.Fatal(err)
	// }
	// defer file.Close()

	// // Read file contents
	// data := make([]byte, 4096)
	// n, err := file.Read(data)
	// fmt.Printf("Read %d bytes\n", n)

	// Output:
	// Read 4096 bytes
}

// ExampleFile_ReadResourceFork demonstrates reading a resource fork
func ExampleFile_ReadResourceFork() {
	// partition := local.NewLocalPartition("/path/to/disk.dmg")
	// vfs, _ := hfsplus.NewVFS(partition)

	// file, _ := vfs.Open("/Applications/MyApp.app/Contents/Resources/icon.icns")
	// hfsFile := file.(*hfsplus.File)

	// // Read resource fork
	// resourceData, err := hfsFile.ReadResourceFork()
	// if err != nil {
	//     log.Fatal(err)
	// }

	// fmt.Printf("Resource fork size: %d bytes\n", len(resourceData))

	// Output:
	// Resource fork size: 12345 bytes
}

// ExampleVFS_SearchFilesByName demonstrates file searching
func ExampleVFS_SearchFilesByName() {
	// partition := local.NewLocalPartition("/path/to/disk.dmg")
	// vfs, _ := hfsplus.NewVFS(partition)

	// // Search for all .dmg files
	// matches, err := vfs.SearchFilesByName("*.dmg")
	// if err != nil {
	//     log.Fatal(err)
	// }

	// for _, path := range matches {
	//     fmt.Println(path)
	// }

	// Output:
	// installer.dmg
	// backup.dmg
}

// ExampleVFS_GetVolumeInfo demonstrates getting volume information
func ExampleVFS_GetVolumeInfo() {
	// partition := local.NewLocalPartition("/dev/disk2s2")
	// vfs, _ := hfsplus.NewVFS(partition)

	// info := vfs.GetVolumeInfo()
	// fmt.Printf("Volume Information:\n")
	// fmt.Printf("  Signature: 0x%04X\n", info.Signature)
	// fmt.Printf("  Version: %d\n", info.Version)
	// fmt.Printf("  Block Size: %d bytes\n", info.BlockSize)
	// fmt.Printf("  Total Space: %d MB\n",
	//     uint64(info.TotalBlocks)*uint64(info.BlockSize)/1024/1024)
	// fmt.Printf("  Free Space: %d MB\n",
	//     uint64(info.FreeBlocks)*uint64(info.BlockSize)/1024/1024)
	// fmt.Printf("  Files: %d\n", info.FileCount)
	// fmt.Printf("  Folders: %d\n", info.FolderCount)
	// fmt.Printf("  Created: %s\n", info.CreateDate)
	// fmt.Printf("  Modified: %s\n", info.ModifyDate)
	// fmt.Printf("  Journaled: %v\n", info.IsJournaled)

	// Output:
	// Volume Information:
	//   Signature: 0x482B
	//   Version: 4
	//   Block Size: 4096 bytes
	//   Total Space: 500000 MB
	//   Free Space: 250000 MB
	//   Files: 50000
	//   Folders: 5000
	//   Created: 2020-01-15 10:30:00
	//   Modified: 2024-03-28 15:45:00
	//   Journaled: true
}

// ExampleParseHFSTime demonstrates HFS+ time parsing
func ExampleParseHFSTime() {
	// HFS+ time: seconds since Jan 1, 1904
	hfsTime := uint32(3786825600) // Approx Jan 1, 2024

	goTime := hfsplus.ParseHFSTime(hfsTime)
	fmt.Println(goTime.Year())

	// Output:
	// 2024
}

// Example_forensicAnalysis demonstrates forensic capabilities
func Example_forensicAnalysis() {
	// partition := local.NewLocalPartition("/dev/disk2s2")
	// vfs, _ := hfsplus.NewVFS(partition)

	// // Check if journaled
	// if vfs.IsJournaled() {
	//     journal := vfs.GetJournalInfo()
	//     if journal != nil {
	//         fmt.Printf("Journal at offset: 0x%X\n", journal.Offset)
	//         fmt.Printf("Journal size: %d MB\n", journal.Size/1024/1024)
	//     }
	// }

	// // Check case sensitivity
	// if vfs.IsCaseSensitive() {
	//     fmt.Println("Volume is case-sensitive (HFSX)")
	// } else {
	//     fmt.Println("Volume is case-insensitive (HFS+)")
	// }

	// // List all files
	// entries, _ := vfs.hfs.ListFiles()
	// fmt.Printf("Total files found: %d\n", len(entries))

	// for _, entry := range entries {
	//     if entry.ResourceSize > 0 {
	//         fmt.Printf("File with resource fork: %s (%d bytes)\n",
	//             entry.Name, entry.ResourceSize)
	//     }
	// }

	// Output:
	// Journal at offset: 0x1000000
	// Journal size: 8 MB
	// Volume is case-insensitive (HFS+)
	// Total files found: 1234
	// File with resource fork: icon.icns (45678 bytes)
}

// Example_walkFilesystem demonstrates walking the entire filesystem
func Example_walkFilesystem() {
	// partition := local.NewLocalPartition("/path/to/disk.dmg")
	// vfs, _ := hfsplus.NewVFS(partition)

	// var totalSize int64
	// var fileCount int

	// err := vfs.Walk("/", func(path string, d fs.DirEntry, err error) error {
	//     if err != nil {
	//         return err
	//     }

	//     if !d.IsDir() {
	//         info, _ := d.Info()
	//         totalSize += info.Size()
	//         fileCount++
	//     }

	//     return nil
	// })

	// if err != nil {
	//     log.Fatal(err)
	// }

	// fmt.Printf("Total files: %d\n", fileCount)
	// fmt.Printf("Total size: %d MB\n", totalSize/1024/1024)

	// Output:
	// Total files: 5000
	// Total size: 25000 MB
}

// Example_extendedAttributes demonstrates reading extended attributes
func Example_extendedAttributes() {
	// partition := local.NewLocalPartition("/path/to/disk.dmg")
	// vfs, _ := hfsplus.NewVFS(partition)

	// xattrs, err := vfs.GetFileExtendedAttributes("/path/to/file.txt")
	// if err != nil {
	//     log.Fatal(err)
	// }

	// for name, data := range xattrs {
	//     fmt.Printf("Extended attribute: %s (%d bytes)\n", name, len(data))
	//
	//     // Common extended attributes on macOS:
	//     // - com.apple.metadata:kMDItemWhereFroms (download source)
	//     // - com.apple.quarantine (quarantine info)
	//     // - com.apple.FinderInfo (Finder metadata)
	// }

	// Output:
	// Extended attribute: com.apple.quarantine (57 bytes)
	// Extended attribute: com.apple.FinderInfo (32 bytes)
}

// Example_batchExtraction demonstrates extracting all files
func Example_batchExtraction() {
	// partition := local.NewLocalPartition("/path/to/disk.dmg")
	// vfs, _ := hfsplus.NewVFS(partition)

	// entries, _ := vfs.hfs.ListFiles()

	// extracted := 0
	// failed := 0

	// for _, entry := range entries {
	//     file, err := vfs.hfs.GetFileByPath(entry.Name)
	//     if err != nil {
	//         failed++
	//         continue
	//     }

	//     // Extract data fork
	//     data, err := vfs.hfs.ReadFile(file, false)
	//     if err != nil {
	//         failed++
	//         continue
	//     }

	//     // Save to disk
	//     os.MkdirAll("extracted", 0755)
	//     os.WriteFile("extracted/"+entry.Name, data, 0644)
	//     extracted++

	//     // Also extract resource fork if present
	//     if entry.ResourceSize > 0 {
	//         rsrcData, _ := vfs.hfs.ReadFile(file, true)
	//         os.WriteFile("extracted/"+entry.Name+".rsrc", rsrcData, 0644)
	//     }
	// }

	// fmt.Printf("Extracted: %d files\n", extracted)
	// fmt.Printf("Failed: %d files\n", failed)

	// Output:
	// Extracted: 4950 files
	// Failed: 50 files
}
