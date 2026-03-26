//go:build !noclamav && !windows
// +build !noclamav,!windows

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
	"unsafe"

	"github.com/afterdarktech/darkscan/pkg/scanner"
)

type Engine struct {
	engine      *C.struct_cl_engine
	dbPath      string
	initialized bool
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

	var virname *C.char
	var scanned C.ulong

	ret := C.cl_scanfile(pathC, &virname, &scanned, e.engine, C.CL_SCAN_STDOPT)

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
	freshclamPath := "/usr/bin/freshclam"
	if _, err := os.Stat(freshclamPath); os.IsNotExist(err) {
		freshclamPath = "/usr/local/bin/freshclam"
		if _, err := os.Stat(freshclamPath); os.IsNotExist(err) {
			return fmt.Errorf("freshclam not found")
		}
	}

	return fmt.Errorf("automated updates not implemented - run 'freshclam' manually to update virus definitions")
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
