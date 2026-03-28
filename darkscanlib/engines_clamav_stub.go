//go:build noclamav || windows

package main

import (
	"github.com/afterdarksys/darkscan/pkg/scanner"
)

func registerClamAV(s *scanner.Scanner) {
	// Stub: ClamAV disabled
}
