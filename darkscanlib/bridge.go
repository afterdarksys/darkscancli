package main

/*
#include <stdlib.h>
#include <stdint.h>
*/
import "C"
import (
	"context"
	"encoding/json"
	"sync"
	"unsafe"

	"github.com/afterdarksys/darkscan/pkg/heuristics"
	"github.com/afterdarksys/darkscan/pkg/scanner"
)

var (
	handles = make(map[uint64]*scanner.Scanner)
	counter uint64
	mu      sync.Mutex
)

//export DarkScan_New
func DarkScan_New() C.uint64_t {
	mu.Lock()
	defer mu.Unlock()

	s := scanner.New()
	
	// Default to registering heuristics for the library
	s.RegisterEngine(heuristics.New())
	
	// ClamAV is registered via init conditionally
	registerClamAV(s)

	counter++
	handle := counter
	handles[handle] = s

	return C.uint64_t(handle)
}

//export DarkScan_Free
func DarkScan_Free(handle C.uint64_t) {
	mu.Lock()
	defer mu.Unlock()

	if s, ok := handles[uint64(handle)]; ok {
		s.Close()
		delete(handles, uint64(handle))
	}
}

//export DarkScan_ScanFile
func DarkScan_ScanFile(handle C.uint64_t, cPath *C.char) *C.char {
	mu.Lock()
	s, ok := handles[uint64(handle)]
	mu.Unlock()

	if !ok {
		return C.CString("[]")
	}

	path := C.GoString(cPath)
	results, err := s.ScanFile(context.Background(), path)
	if err != nil {
		// Return empty array on error for simplier ABI or format an error JSON
		return C.CString("[]")
	}

	b, _ := json.Marshal(results)
	return C.CString(string(b))
}

//export DarkScan_ScanDirectory
func DarkScan_ScanDirectory(handle C.uint64_t, cPath *C.char, recursive C.int) *C.char {
	mu.Lock()
	s, ok := handles[uint64(handle)]
	mu.Unlock()

	if !ok {
		return C.CString("[]")
	}

	path := C.GoString(cPath)
	rec := recursive != 0
	results, err := s.ScanDirectory(context.Background(), path, rec)
	if err != nil {
		return C.CString("[]")
	}

	b, _ := json.Marshal(results)
	return C.CString(string(b))
}

//export DarkScan_FreeString
func DarkScan_FreeString(s *C.char) {
	C.free(unsafe.Pointer(s))
}

func main() {}
