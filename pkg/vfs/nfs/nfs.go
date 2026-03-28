package nfs

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/afterdarksys/darkscan/pkg/vfs"
	nfsclient "github.com/vmware/go-nfs-client/nfs"
	"github.com/vmware/go-nfs-client/nfs/rpc"
)

type NFSFS struct {
	mount *nfsclient.Target
}

func New(host string, mountPath string) (*NFSFS, error) {
	mount, err := nfsclient.DialMount(host)
	if err != nil {
		return nil, fmt.Errorf("failed to dial mount: %w", err)
	}

	auth := rpc.NewAuthUnix("root", 0, 0)
	target, err := mount.Mount(mountPath, auth.Auth())
	if err != nil {
		return nil, fmt.Errorf("failed to mount path %s: %w", mountPath, err)
	}

	return &NFSFS{mount: target}, nil
}

func (n *NFSFS) Open(name string) (vfs.File, error) {
	// go-nfs-client provides an Open that returns properties similar to os.File
	f, err := n.mount.Open(name)
	if err != nil {
		return nil, err
	}

	return &nfsFileWrapper{f: f}, nil
}

// Wrapper to ensure nfsclient.File conforms securely to vfs.File.
// Due to missing native io.ReaderAt in some older go-nfs-client versions,
// we wrap its Seeker to emulate ReaderAt or assume it satisfies it natively.
type nfsFileWrapper struct {
	f *nfsclient.File
}

func (w *nfsFileWrapper) Read(p []byte) (n int, err error) {
	return w.f.Read(p)
}

func (w *nfsFileWrapper) ReadAt(p []byte, off int64) (int, error) {
	// Emulate ReadAt if not natively supported, by seeking then reading
	// Note: not thread-safe if multiple goroutines read the same file handle!
	_, err := w.f.Seek(off, io.SeekStart)
	if err != nil {
		return 0, err
	}
	buffer := make([]byte, len(p))
	n, readErr := w.f.Read(buffer)
	copy(p, buffer[:n])
	return n, readErr
}

func (w *nfsFileWrapper) Seek(offset int64, whence int) (int64, error) {
	return w.f.Seek(offset, whence)
}

func (w *nfsFileWrapper) Close() error {
	return w.f.Close()
}

func (w *nfsFileWrapper) Stat() (os.FileInfo, error) {
	// Stat not cleanly exported as standard os.FileInfo everywhere, map it if needed
	// Nfs files contain getattr information.
	return nil, fmt.Errorf("nfs Stat not implemented") 
}


func (n *NFSFS) Stat(name string) (os.FileInfo, error) {
	return nil, fmt.Errorf("nfs Stat not implemented")
}

func (n *NFSFS) Walk(root string, fn filepath.WalkFunc) error {
	// We must write a custom walk loop because standard filepath.Walk utilizes os.lstat
	// For production, this requires recursively querying n.mount.ReadDirPlus
	return runWalk(n.mount, root, fn)
}

func runWalk(target *nfsclient.Target, path string, fn filepath.WalkFunc) error {
	dirs, err := target.ReadDirPlus(path)
	if err != nil {
		return err
	}

	for _, d := range dirs {
		if d.Name() == "." || d.Name() == ".." {
			continue
		}
		
		fullPath := path + "/" + d.Name()
		if d.IsDir() {
			if err := fn(fullPath, d, nil); err != nil {
				if err == filepath.SkipDir {
					continue
				}
				return err
			}
			err = runWalk(target, fullPath, fn)
			if err != nil {
				return err
			}
		} else {
			if err := fn(fullPath, d, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

func (n *NFSFS) ListXattrs(path string) ([]string, error) {
	return nil, nil // NFSv3 does not universally support standard xattr protocols
}

func (n *NFSFS) GetXattr(path string, attr string) ([]byte, error) {
	return nil, nil
}
