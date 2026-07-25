package archive

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/yeka/zip"
)

type ZipExtractor struct{}

func (z *ZipExtractor) Name() string {
	return "ZIP"
}

func (z *ZipExtractor) CanHandle(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".zip" || ext == ".docx" || ext == ".xlsx" || ext == ".pptx" || ext == ".jar" || ext == ".apk"
}

func (z *ZipExtractor) Extract(ctx context.Context, path string, opts ExtractOptions) ([]ExtractedFile, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	var extracted []ExtractedFile
	maxBytes := opts.MaxFileSizeMB * 1024 * 1024

	for _, f := range r.File {
		select {
		case <-ctx.Done():
			return extracted, ctx.Err()
		default:
		}

		if f.FileInfo().IsDir() {
			continue
		}

		// Zip slip protection
		if strings.Contains(f.Name, "..") {
			continue
		}

		var rc io.ReadCloser
		if f.IsEncrypted() {
			if opts.PasswordCallback == nil {
				return nil, ErrEncrypted
			}
			pass, pErr := opts.PasswordCallback(path)
			if pErr != nil {
				return nil, pErr
			}
			f.SetPassword(pass)
			rc, err = f.Open()
			if err != nil {
				return nil, err
			}
		} else {
			rc, err = f.Open()
			if err != nil {
				continue
			}
		}

		// Prevent zip bombs
		lr := io.LimitReader(rc, maxBytes)

		if opts.InMemory && int64(f.UncompressedSize64) < (opts.MaxMemoryMB*1024*1024) {
			buf := new(bytes.Buffer)
			_, err := io.Copy(buf, lr)
			rc.Close()
			if err != nil {
				continue
			}
			extracted = append(extracted, ExtractedFile{
				Name:    f.Name,
				Size:    int64(buf.Len()),
				IsMem:   true,
				Content: buf.Bytes(),
			})
		} else {
			// Write to temp dir
			tmpFile, err := os.CreateTemp("", "darkscan-ext-*")
			if err != nil {
				rc.Close()
				continue
			}
			_, err = io.Copy(tmpFile, lr)
			rc.Close()
			tmpFile.Close()
			if err != nil {
				os.Remove(tmpFile.Name())
				continue
			}
			extracted = append(extracted, ExtractedFile{
				Name:  f.Name,
				Path:  tmpFile.Name(),
				Size:  int64(f.UncompressedSize64),
				IsMem: false,
			})
		}
	}

	return extracted, nil
}
