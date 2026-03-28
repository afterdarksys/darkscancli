package scanner

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/afterdarksys/darkscan/pkg/archive"
	"github.com/afterdarksys/darkscan/pkg/fsutil"
	"github.com/afterdarksys/darkscan/pkg/vfs"
	"github.com/afterdarksys/darkscan/pkg/worker"
)

type ScanResult struct {
	FilePath    string
	Infected    bool
	Threats     []Threat
	ScanEngine  string
	Error       error
}

type Threat struct {
	Name        string
	Severity    string
	Description string
	Engine      string
}

type Engine interface {
	Name() string
	Scan(ctx context.Context, path string) (*ScanResult, error)
	Update(ctx context.Context) error
	Close() error
}

type Scanner struct {
	engines          []Engine
	mu               sync.RWMutex
	archiveManager   *archive.Manager
	passwordCallback func(path string) (string, error)
	FS               vfs.FileSystem
}

func New() *Scanner {
	am := archive.NewManager()
	am.Register(&archive.ZipExtractor{})
	am.Register(&archive.TarExtractor{})

	return &Scanner{
		engines:        make([]Engine, 0),
		archiveManager: am,
		FS:             nil, // By default initialized later or injected
	}
}

func (s *Scanner) SetVFS(fs vfs.FileSystem) {
	s.FS = fs
}

// WithVFS returns a shallow copy of the Scanner bound to a specific VFS instance.
// This allows thread-safe concurrent scans across different virtual filesystems
// without duplicating the heavy scanning engines in memory.
func (s *Scanner) WithVFS(fs vfs.FileSystem) *Scanner {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return &Scanner{
		engines:          s.engines,
		archiveManager:   s.archiveManager,
		passwordCallback: s.passwordCallback,
		FS:               fs,
	}
}

func (s *Scanner) RegisterEngine(engine Engine) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.engines = append(s.engines, engine)
}

func (s *Scanner) SetPasswordCallback(cb func(path string) (string, error)) {
	s.passwordCallback = cb
}

func (s *Scanner) acquireLocalFile(ctx context.Context, path string) (string, func(), error) {
	if s.FS == nil {
		return path, func() {}, nil
	}

	f, err := s.FS.Open(path)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()

	if nameF, ok := f.(interface{ Name() string }); ok {
		return nameF.Name(), func() {}, nil
	}

	tmp, err := os.CreateTemp("", "darkscan-vfs-*")
	if err != nil {
		return "", nil, err
	}
	if _, err := io.Copy(tmp, f); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", nil, err
	}
	tmp.Close()
	return tmp.Name(), func() { os.Remove(tmp.Name()) }, nil
}

func (s *Scanner) ScanFile(ctx context.Context, path string) ([]*ScanResult, error) {
	var info os.FileInfo
	var err error
	if s.FS != nil {
		info, err = s.FS.Stat(path)
	} else {
		info, err = os.Stat(path)
	}
	
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	if info.IsDir() {
		return nil, fmt.Errorf("path is a directory")
	}

	return s.scanSingleTargetAndExtract(ctx, path)
}

func (s *Scanner) scanSingleTargetAndExtract(ctx context.Context, path string) ([]*ScanResult, error) {
	var results []*ScanResult

	localPath, cleanup, err := s.acquireLocalFile(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire VFS file locally: %w", err)
	}
	defer cleanup()

	opts := archive.ExtractOptions{
		InMemory:         true,
		MaxMemoryMB:      50,
		MaxFileSizeMB:    500,
		PasswordCallback: s.passwordCallback,
	}

	extracted, extErr := s.archiveManager.Extract(ctx, localPath, opts)
	if extErr == nil && len(extracted) > 0 {
		for _, ex := range extracted {
			if ex.IsMem {
				memReader := strings.NewReader(string(ex.Content))
				res, _ := s.ScanReader(ctx, memReader, path+"->"+ex.Name)
				results = append(results, res...)
			} else {
				res, _ := s.scanSingleTargetAndExtract(ctx, ex.Path)
				os.Remove(ex.Path)
				for _, r := range res {
					r.FilePath = path + "->" + ex.Name
					results = append(results, r)
				}
			}
		}
	} else {
		for _, engine := range s.engines {
			res, err := engine.Scan(ctx, localPath)
			if err == nil && res != nil {
				res.FilePath = path // Maintain original VFS path for reports
				results = append(results, res)
			}
		}

		var xattrs []string
		var xerr error
		if s.FS != nil {
			xattrs, xerr = s.FS.ListXattrs(path)
		} else {
			xattrs, xerr = fsutil.ListXattrs(path)
		}

		if xerr == nil && len(xattrs) > 0 {
			for _, attr := range xattrs {
				var val []byte
				if s.FS != nil {
					val, err = s.FS.GetXattr(path, attr)
				} else {
					val, err = fsutil.GetXattr(path, attr)
				}
				if err == nil && len(val) > 0 {
					memReader := strings.NewReader(string(val))
					res, _ := s.ScanReader(ctx, memReader, path+"@"+attr)
					results = append(results, res...)
				}
			}
		}
	}
	
	return results, nil
}

func (s *Scanner) ScanDirectory(ctx context.Context, path string, recursive bool) ([]*ScanResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.engines) == 0 {
		return nil, fmt.Errorf("no scan engines registered")
	}

	var results []*ScanResult
	var resMu sync.Mutex

	numWorkers := runtime.NumCPU() * 2
	pool := worker.NewPool(numWorkers, func(ctx context.Context, p string) (interface{}, error) {
		return s.scanSingleTargetAndExtract(ctx, p)
	})

	pool.Start(ctx)

	go func() {
		walkFn := func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				if !recursive && p != path {
					return filepath.SkipDir
				}
				return nil
			}

			pool.Submit(worker.Job{Path: p, Priority: 1})
			return nil
		}

		if s.FS != nil {
			_ = s.FS.Walk(path, walkFn)
		} else {
			_ = fsutil.Walk(path, walkFn)
		}
		pool.Wait()
	}()

	for res := range pool.Results() {
		if res.Err != nil {
			continue
		}
		if scanResults, ok := res.Value.([]*ScanResult); ok {
			resMu.Lock()
			results = append(results, scanResults...)
			resMu.Unlock()
		}
	}
	return results, nil
}

func (s *Scanner) scanFileInternal(ctx context.Context, path string) ([]*ScanResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	results := make([]*ScanResult, 0, len(s.engines))
	for _, engine := range s.engines {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
			result, err := engine.Scan(ctx, path)
			if err != nil {
				results = append(results, &ScanResult{
					FilePath:   path,
					ScanEngine: engine.Name(),
					Error:      err,
				})
				continue
			}
			results = append(results, result)
		}
	}
	return results, nil
}

func (s *Scanner) ScanReader(ctx context.Context, r io.Reader, name string) ([]*ScanResult, error) {
	tmpFile, err := os.CreateTemp("", "darkscan-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := io.Copy(tmpFile, r); err != nil {
		return nil, fmt.Errorf("failed to write to temp file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return nil, fmt.Errorf("failed to close temp file: %w", err)
	}

	results, err := s.scanFileInternal(ctx, tmpFile.Name())
	if err == nil {
		for _, res := range results {
			res.FilePath = name
		}
	}
	return results, err
}

func (s *Scanner) UpdateEngines(ctx context.Context) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var errs []error
	for _, engine := range s.engines {
		if err := engine.Update(ctx); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", engine.Name(), err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors updating engines: %v", errs)
	}

	return nil
}

func (s *Scanner) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var errs []error
	for _, engine := range s.engines {
		if err := engine.Close(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", engine.Name(), err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing engines: %v", errs)
	}

	return nil
}
