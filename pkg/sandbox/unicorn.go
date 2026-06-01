//go:build cgo

package sandbox

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	"github.com/afterdarksys/darkscan/pkg/scanner"
)

const (
	// Max allocation for virtual sandbox RAM
	SandboxMemorySize = 8 * 1024 * 1024 // 8MB
	StartAddress      = 0x1000000
	StackAddress      = 0x2000000 // Stack starts at 32MB
)

type UnicornSandbox struct{}

func New() *UnicornSandbox {
	return &UnicornSandbox{}
}

func (s *UnicornSandbox) Name() string {
	return "UnicornSandbox"
}

func (s *UnicornSandbox) Update(ctx context.Context) error {
	return nil
}

func (s *UnicornSandbox) Close() error {
	return nil
}

func (s *UnicornSandbox) Scan(ctx context.Context, path string) (*scanner.ScanResult, error) {
	fileBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file for sandbox: %w", err)
	}

	return s.ScanReader(ctx, bytes.NewReader(fileBytes), path)
}

func (s *UnicornSandbox) ScanReader(ctx context.Context, r io.Reader, name string) (*scanner.ScanResult, error) {
	// Read payload into memory
	payload, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	// For a real EDR, we'd parse the ELF/Mach-O/PE headers using debug/pe, debug/elf, or macho packages
	// and map the correct .text, .data, .rdata sections to the virtual CPU.
	// For this Phase 3 feature, we will emulate raw mapped execution (shellcode style)
	// to detect signature anti-analysis traps (e.g., CPUID looping).

	if len(payload) > SandboxMemorySize {
		// File too large for micro-sandbox, truncate or skip
		payload = payload[:SandboxMemorySize]
	}

	// Note: We use x86 32-bit for the baseline Sandbox emulation 
	mu, err := uc.NewUnicorn(uc.ARCH_X86, uc.MODE_32)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize unicorn CPU: %w", err)
	}
	defer mu.Close()

	// 1. Setup Virtual Memory Maps
	if err := mu.MemMap(StartAddress, SandboxMemorySize); err != nil {
		return nil, fmt.Errorf("failed to map execution memory: %w", err)
	}
	if err := mu.MemWrite(StartAddress, payload); err != nil {
		return nil, fmt.Errorf("failed to write payload: %w", err)
	}

	// Map a small stack
	if err := mu.MemMap(StackAddress, 2*1024*1024); err != nil {
		return nil, fmt.Errorf("failed to map stack: %w", err)
	}
	mu.RegWrite(uc.X86_REG_ESP, StackAddress+1*1024*1024)

	// 2. Telemetry / Instrumentation Traps
	var infected bool
	var threats []scanner.Threat

	// Basic instrumentation: hook all instructions
	instructionCount := 0
	suspiciousFeatures := make(map[string]bool)

	_, err = mu.HookAdd(uc.HOOK_CODE, func(mu uc.Unicorn, addr uint64, size uint32) {
		select {
		case <-ctx.Done():
			mu.Stop()
			return
		default:
		}

		instructionCount++

		if instructionCount > 10000 {
			// Stop execution after 10K instructions (Timeout/Threshold)
			mu.Stop()
		}

		// Read the instruction bytes
		instBytes, readErr := mu.MemRead(addr, uint64(size))
		if readErr == nil {
			hexHex := hex.EncodeToString(instBytes)
			// Example signature: CPUID (0f a2)
			if hexHex == "0fa2" {
				suspiciousFeatures["Anti-Sandbox: CPUID Profiling"] = true
			}
			// Example signature: RDTSC (0f 31)
			if hexHex == "0f31" {
				suspiciousFeatures["Anti-Sandbox: Timing Attack"] = true
			}
			// Example signature: INT 3 (cc)
			if hexHex == "cc" {
				suspiciousFeatures["Anti-Sandbox: Breakpoint Trap"] = true
			}
		}
	}, StartAddress, StartAddress+uint64(len(payload)))
	if err != nil {
		return nil, fmt.Errorf("failed to add instruction hook: %w", err)
	}

	// 3. Detonate
	// We run until an error occurs (e.g., accessing unmapped memory) or we hit our 10,000 instruction limit
	mu.Start(StartAddress, StartAddress+uint64(len(payload)))

	if len(suspiciousFeatures) > 0 {
		infected = true
		for desc := range suspiciousFeatures {
			threats = append(threats, scanner.Threat{
				Name:        "Behavior.AntiAnalysis",
				Severity:    "high",
				Description: desc,
				Engine:      "UnicornSandbox",
			})
		}
	}

	return &scanner.ScanResult{
		FilePath:   name,
		Infected:   infected,
		Threats:    threats,
		ScanEngine: s.Name(),
	}, nil
}
