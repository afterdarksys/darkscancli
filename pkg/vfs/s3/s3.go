package s3

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/afterdarksys/darkscan/pkg/vfs"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type S3FS struct {
	client *s3.Client
	bucket string
}

func New(ctx context.Context, bucket string) (*S3FS, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to load AWS SDK config: %w", err)
	}

	client := s3.NewFromConfig(cfg)
	return &S3FS{
		client: client,
		bucket: bucket,
	}, nil
}

type tempFile struct {
	*os.File
	path string
}

func (t *tempFile) Close() error {
	err := t.File.Close()
	os.Remove(t.path)
	return err
}

func (s *S3FS) Open(name string) (vfs.File, error) {
	// Remove leading slash for S3 key if present
	key := strings.TrimPrefix(name, "/")

	out, err := s.client.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: &s.bucket,
		Key:    &key,
	})
	if err != nil {
		return nil, err
	}
	defer out.Body.Close()

	// Download to a temporary file to support fast ReaderAt/Seeker for malware engines
	tmp, err := os.CreateTemp("", "darkscan-s3-*")
	if err != nil {
		return nil, err
	}

	if _, err := io.Copy(tmp, out.Body); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, err
	}

	// Rewind to beginning
	tmp.Seek(0, 0)

	return &tempFile{
		File: tmp,
		path: tmp.Name(),
	}, nil
}

type s3FileInfo struct {
	name string
	size int64
	dir  bool
}

func (s s3FileInfo) Name() string       { return s.name }
func (s s3FileInfo) Size() int64        { return s.size }
func (s s3FileInfo) Mode() os.FileMode  { return 0644 }
func (s s3FileInfo) ModTime() time.Time { return time.Time{} } // simplified
func (s s3FileInfo) IsDir() bool        { return s.dir }
func (s s3FileInfo) Sys() interface{}   { return nil }

func (s *S3FS) Stat(name string) (os.FileInfo, error) {
	key := strings.TrimPrefix(name, "/")
	out, err := s.client.HeadObject(context.Background(), &s3.HeadObjectInput{
		Bucket: &s.bucket,
		Key:    &key,
	})
	if err != nil {
		return nil, err
	}
	return s3FileInfo{name: key, size: *out.ContentLength, dir: false}, nil
}

func (s *S3FS) Walk(root string, fn filepath.WalkFunc) error {
	prefix := strings.TrimPrefix(root, "/")
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/" // ensure trailing slash for prefix listing
	}

	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: &s.bucket,
		Prefix: &prefix,
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			return err
		}

		for _, obj := range page.Contents {
			info := s3FileInfo{
				name: *obj.Key,
				size: *obj.Size,
				dir:  false,
			}
			if err := fn(*obj.Key, info, nil); err != nil {
				if err == filepath.SkipDir {
					return nil // Skip entire walk on s3 since it's flat anyway
				}
				return err
			}
		}
	}
	return nil
}

func (s *S3FS) ListXattrs(path string) ([]string, error) {
	// S3 natively supports metadata, but for a pure malware scan, we just return nil
	// Could implement extraction of x-amz-meta headers here
	return nil, nil
}

func (s *S3FS) GetXattr(path string, attr string) ([]byte, error) {
	return nil, nil
}
