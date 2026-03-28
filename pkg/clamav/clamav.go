//go:build !noclamav && !windows && cgo
// +build !noclamav,!windows,cgo

package clamav

/*
#cgo LDFLAGS: -lclamav
#include <clamav.h>
#include <stdlib.h>
*/
import "C"
import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"github.com/afterdarksys/darkscan/pkg/scanner"
)

type Engine struct {
	engine      *C.struct_cl_engine
	dbPath      string
	initialized bool
	mu          sync.RWMutex
}

func New(dbPath string) (*Engine, error) {
	if dbPath == "" {
		dbPath = "/var/lib/clamav"
	}

	ret := C.cl_init(C.CL_INIT_DEFAULT)
	if ret != C.CL_SUCCESS {
		return nil, fmt.Errorf("failed to initialize ClamAV: %s", C.GoString(C.cl_strerror(ret)))
	}

	engine := C.cl_engine_new()
	if engine == nil {
		return nil, fmt.Errorf("failed to create ClamAV engine")
	}

	e := &Engine{
		engine: engine,
		dbPath: dbPath,
	}

	if err := e.loadDatabase(); err != nil {
		C.cl_engine_free(engine)
		return nil, fmt.Errorf("failed to load database: %w", err)
	}

	return e, nil
}

func (e *Engine) loadDatabase() error {
	dbPathC := C.CString(e.dbPath)
	defer C.free(unsafe.Pointer(dbPathC))

	var signo C.uint
	ret := C.cl_load(dbPathC, e.engine, &signo, C.CL_DB_STDOPT)
	if ret != C.CL_SUCCESS {
		return fmt.Errorf("failed to load database: %s", C.GoString(C.cl_strerror(ret)))
	}

	ret = C.cl_engine_compile(e.engine)
	if ret != C.CL_SUCCESS {
		return fmt.Errorf("failed to compile engine: %s", C.GoString(C.cl_strerror(ret)))
	}

	e.initialized = true
	return nil
}

func (e *Engine) Name() string {
	return "ClamAV"
}

func (e *Engine) Scan(ctx context.Context, path string) (*scanner.ScanResult, error) {
	if !e.initialized {
		return nil, fmt.Errorf("engine not initialized")
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	pathC := C.CString(path)
	defer C.free(unsafe.Pointer(pathC))

	e.mu.RLock()
	eng := e.engine
	e.mu.RUnlock()

	var virname *C.char
	var scanned C.ulong
	var opts C.struct_cl_scan_options
	ret := C.cl_scanfile(pathC, &virname, &scanned, eng, &opts)

	result := &scanner.ScanResult{
		FilePath:   path,
		ScanEngine: "ClamAV",
		Infected:   false,
		Threats:    make([]scanner.Threat, 0),
	}

	switch ret {
	case C.CL_CLEAN:
		return result, nil
	case C.CL_VIRUS:
		result.Infected = true
		result.Threats = append(result.Threats, scanner.Threat{
			Name:        C.GoString(virname),
			Severity:    "high",
			Description: fmt.Sprintf("Detected by ClamAV: %s", C.GoString(virname)),
			Engine:      "ClamAV",
		})
		return result, nil
	default:
		return result, fmt.Errorf("scan error: %s", C.GoString(C.cl_strerror(ret)))
	}
}

func (e *Engine) Update(ctx context.Context) error {
	if e.dbPath == "" {
		return fmt.Errorf("engine has no database path configured")
	}

	newEngine := C.cl_engine_new()
	if newEngine == nil {
		return fmt.Errorf("failed to create new ClamAV engine for reload")
	}

	dbPathC := C.CString(e.dbPath)
	defer C.free(unsafe.Pointer(dbPathC))

	var signo C.uint
	ret := C.cl_load(dbPathC, newEngine, &signo, C.CL_DB_STDOPT)
	if ret != C.CL_SUCCESS {
		C.cl_engine_free(newEngine)
		return fmt.Errorf("failed to load database during reload: %s", C.GoString(C.cl_strerror(ret)))
	}

	ret = C.cl_engine_compile(newEngine)
	if ret != C.CL_SUCCESS {
		C.cl_engine_free(newEngine)
		return fmt.Errorf("failed to compile engine during reload: %s", C.GoString(C.cl_strerror(ret)))
	}

	e.mu.Lock()
	oldEngine := e.engine
	e.engine = newEngine
	e.mu.Unlock()

	// Defer freeing the old engine until active scans are likely finished
	// Using a conservative 10-minute grace period to prevent crashes from long-running scans
	// TODO: Implement proper reference counting for production use
	go func() {
		time.Sleep(10 * time.Minute)
		if oldEngine != nil {
			C.cl_engine_free(oldEngine)
		}
	}()

	return nil
}

func (e *Engine) Close() error {
	if e.engine != nil {
		C.cl_engine_free(e.engine)
		e.engine = nil
		e.initialized = false
	}
	return nil
}

func GetVersion() string {
	return C.GoString(C.cl_retver())
}

func GetDatabaseDirectory() (string, error) {
	defaultPaths := []string{
		"/var/lib/clamav",
		"/usr/local/share/clamav",
		"/opt/clamav/share/clamav",
	}

	for _, path := range defaultPaths {
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			entries, err := os.ReadDir(path)
			if err == nil && len(entries) > 0 {
				return path, nil
			}
		}
	}

	return "", fmt.Errorf("ClamAV database directory not found")
}

func VerifyDatabase(dbPath string) error {
	requiredFiles := []string{"main.cvd", "daily.cvd", "bytecode.cvd"}
	alternativeFiles := []string{"main.cld", "daily.cld", "bytecode.cld"}

	for i, required := range requiredFiles {
		mainPath := filepath.Join(dbPath, required)
		altPath := filepath.Join(dbPath, alternativeFiles[i])

		if _, err := os.Stat(mainPath); err != nil {
			if _, err := os.Stat(altPath); err != nil {
				return fmt.Errorf("missing required database file: %s (or %s)", required, alternativeFiles[i])
			}
		}
	}

	return nil
}
