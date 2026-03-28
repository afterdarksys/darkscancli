package local

import (
	"os"
	"path/filepath"

	"github.com/afterdarktech/darkscan/pkg/fsutil"
	"github.com/afterdarktech/darkscan/pkg/vfs"
)

type LocalFS struct{}

func New() *LocalFS {
	return &LocalFS{}
}

func (l *LocalFS) Open(name string) (vfs.File, error) {
	return os.Open(name)
}

func (l *LocalFS) Stat(name string) (os.FileInfo, error) {
	return os.Stat(name)
}

func (l *LocalFS) Walk(root string, fn filepath.WalkFunc) error {
	return fsutil.Walk(root, fn)
}

func (l *LocalFS) ListXattrs(path string) ([]string, error) {
	return fsutil.ListXattrs(path)
}

func (l *LocalFS) GetXattr(path string, attr string) ([]byte, error) {
	return fsutil.GetXattr(path, attr)
}

// LocalPartition wraps an os.File to implement vfs.Partition
type LocalPartition struct {
	file *os.File
	size int64
}

func (p *LocalPartition) ReadAt(b []byte, off int64) (n int, err error) {
	return p.file.ReadAt(b, off)
}

func (p *LocalPartition) WriteAt(b []byte, off int64) (n int, err error) {
	return p.file.WriteAt(b, off)
}

func (p *LocalPartition) Closer() error {
	return p.file.Close()
}

func (p *LocalPartition) Close() error {
	return p.file.Close()
}

func (p *LocalPartition) Size() int64 {
	return p.size
}

// NewPartition opens a local block device or disk image file for raw access.
func NewPartition(path string) (vfs.Partition, error) {
	// Require read/write access to allow block repair overrides
	f, err := os.OpenFile(path, os.O_RDWR, 0666)
	if err != nil {
		return nil, err
	}
	stat, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	
	// If it's a character or block device, Size() might return 0. 
	// To get the actual size would require an ioctl, but for simplicity we assume file size or let MFT logic handle bounds.
	size := stat.Size()
	if size == 0 { // Simple fallback, assume very large or query ioctl in robust implementation
		size = 1 << 62 
	}
	
	return &LocalPartition{file: f, size: size}, nil
}
