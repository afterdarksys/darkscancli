package carving

import (
	"testing"
)

func TestEstimateExecutableSize_PE(t *testing.T) {
	// Build a minimal buffer with:
	//   "MZ" at 0
	//   PE offset = 64 (0x40) stored at bytes 0x3C–0x3F
	//   "PE\0\0" at offset 64
	//   SizeOfImage = 0x00010000 at offset 64+0x50 = 144
	data := make([]byte, 200)
	data[0] = 0x4D // M
	data[1] = 0x5A // Z
	// PE offset at 0x3C = 64
	data[0x3C] = 0x40
	// "PE\0\0" at offset 64
	data[64] = 'P'
	data[65] = 'E'
	data[66] = 0
	data[67] = 0
	// SizeOfImage at offset 64+0x50 = 144
	sizeOffset := 64 + 0x50
	data[sizeOffset] = 0x00
	data[sizeOffset+1] = 0x00
	data[sizeOffset+2] = 0x01
	data[sizeOffset+3] = 0x00

	sig := FileSignature{Extension: "exe"}
	c := NewCarver(Options{})
	got := c.estimateExecutableSize(data, sig)
	want := int64(0x00010000)
	if got != want {
		t.Errorf("PE size: got %d, want %d", got, want)
	}
}

func TestEstimateExecutableSize_PE_TooShort(t *testing.T) {
	data := make([]byte, 10)
	sig := FileSignature{Extension: "exe"}
	c := NewCarver(Options{})
	if got := c.estimateExecutableSize(data, sig); got != 0 {
		t.Errorf("expected 0 for short data, got %d", got)
	}
}

func TestEstimateExecutableSize_PE_BadMagic(t *testing.T) {
	data := make([]byte, 200)
	data[0x3C] = 0x40
	// No "PE" at offset 64
	sig := FileSignature{Extension: "exe"}
	c := NewCarver(Options{})
	if got := c.estimateExecutableSize(data, sig); got != 0 {
		t.Errorf("expected 0 for missing PE magic, got %d", got)
	}
}

func TestEstimateExecutableSize_ELF32(t *testing.T) {
	// ELF32: magic at 0, class=1 at byte 4
	// shoff at 0x20–0x23, shentsize at 0x2E–0x2F, shnum at 0x30–0x31
	data := make([]byte, 100)
	data[0] = 0x7F
	data[1] = 'E'
	data[2] = 'L'
	data[3] = 'F'
	data[4] = 1 // 32-bit

	// shoff = 0x34 = 52
	data[0x20] = 52
	// shentsize = 40
	data[0x2E] = 40
	// shnum = 5
	data[0x30] = 5

	sig := FileSignature{Extension: "elf"}
	c := NewCarver(Options{})
	got := c.estimateExecutableSize(data, sig)
	want := int64(52 + 40*5)
	if got != want {
		t.Errorf("ELF32 size: got %d, want %d", got, want)
	}
}

func TestEstimateExecutableSize_ELF64(t *testing.T) {
	data := make([]byte, 128)
	data[0] = 0x7F
	data[1] = 'E'
	data[2] = 'L'
	data[3] = 'F'
	data[4] = 2 // 64-bit

	// shoff at 0x28–0x2B = 64
	data[0x28] = 64
	// shentsize at 0x3A–0x3B = 64
	data[0x3A] = 64
	// shnum at 0x3C–0x3D = 10
	data[0x3C] = 10

	sig := FileSignature{Extension: "elf"}
	c := NewCarver(Options{})
	got := c.estimateExecutableSize(data, sig)
	want := int64(64 + 64*10)
	if got != want {
		t.Errorf("ELF64 size: got %d, want %d", got, want)
	}
}

func TestEstimateExecutableSize_Unknown(t *testing.T) {
	data := make([]byte, 200)
	sig := FileSignature{Extension: "pdf"}
	c := NewCarver(Options{})
	if got := c.estimateExecutableSize(data, sig); got != 0 {
		t.Errorf("expected 0 for unknown extension, got %d", got)
	}
}

func TestValidateFile_HeaderMismatch(t *testing.T) {
	c := NewCarver(Options{})

	sig := FileSignature{
		Header: []byte{0xFF, 0xD8, 0xFF},
	}
	file := &CarvedFile{
		Data:      []byte{0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04},
		Signature: sig,
		Confidence: 50,
	}

	c.validateFile(file)

	found := false
	for _, e := range file.ValidationErrors {
		if e == "header mismatch" {
			found = true
		}
	}
	if !found {
		t.Error("expected header mismatch validation error")
	}
	if file.Confidence >= 50 {
		t.Errorf("confidence should have decreased from 50, got %d", file.Confidence)
	}
}

func TestValidateFile_ValidHeader(t *testing.T) {
	c := NewCarver(Options{})

	header := []byte{0xFF, 0xD8, 0xFF}
	// Create data with moderate entropy (not all zeros, not max entropy)
	data := make([]byte, 512)
	for i := range data {
		data[i] = byte(i % 32)
	}
	copy(data, header)

	sig := FileSignature{Header: header}
	file := &CarvedFile{
		Data:       data,
		Signature:  sig,
		Confidence: 50,
	}

	c.validateFile(file)

	for _, e := range file.ValidationErrors {
		if e == "header mismatch" {
			t.Errorf("unexpected header mismatch error")
		}
	}
}

func TestValidateFile_CustomValidator(t *testing.T) {
	c := NewCarver(Options{})

	header := []byte{0x89, 0x50, 0x4E, 0x47}
	data := make([]byte, 512)
	for i := range data {
		data[i] = byte(i % 64)
	}
	copy(data, header)

	sig := FileSignature{
		Header: header,
		Validator: func(d []byte) bool {
			return false // always fail
		},
	}
	file := &CarvedFile{
		Data:       data,
		Signature:  sig,
		Confidence: 80,
	}

	c.validateFile(file)

	found := false
	for _, e := range file.ValidationErrors {
		if e == "custom validation failed" {
			found = true
		}
	}
	if !found {
		t.Error("expected custom validation failed error")
	}
}
