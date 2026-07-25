//go:build linux || darwin

package fsutil

import (
	"golang.org/x/sys/unix"
)

// ListXattrs returns a list of extended attributes for the given file
func ListXattrs(path string) ([]string, error) {
	sz, err := unix.Listxattr(path, nil)
	if err != nil || sz <= 0 {
		return nil, err
	}

	buf := make([]byte, sz)
	sz, err = unix.Listxattr(path, buf)
	if err != nil {
		return nil, err
	}

	var attrs []string
	var start int
	for i, b := range buf[:sz] {
		if b == 0 {
			attrs = append(attrs, string(buf[start:i]))
			start = i + 1
		}
	}
	return attrs, nil
}

// GetXattr returns the value of a specific extended attribute
func GetXattr(path, name string) ([]byte, error) {
	sz, err := unix.Getxattr(path, name, nil)
	if err != nil || sz <= 0 {
		return nil, err
	}

	buf := make([]byte, sz)
	sz, err = unix.Getxattr(path, name, buf)
	if err != nil {
		return nil, err
	}
	return buf[:sz], nil
}
