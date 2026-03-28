package document

import (
	"archive/zip"
	"context"
	"os"
	"strings"

	"github.com/afterdarksys/darkscan/pkg/scanner"
)

// DocumentEngine implements scanner.Engine for analyzing PDFs and Office Docs
type DocumentEngine struct{}

func New() *DocumentEngine {
	return &DocumentEngine{}
}

func (e *DocumentEngine) Name() string {
	return "DocumentScanner"
}

func (e *DocumentEngine) Scan(ctx context.Context, path string) (*scanner.ScanResult, error) {
	result := &scanner.ScanResult{
		FilePath:   path,
		ScanEngine: e.Name(),
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return result, nil // Skip dirs
	}

	lowerPath := strings.ToLower(path)

	// Quick extension check or magic byte fallback could be used. 
	// For simplicity and performance, checking extensions:
	if strings.HasSuffix(lowerPath, ".pdf") {
		return e.scanPDF(path, result)
	}
	if strings.HasSuffix(lowerPath, ".docx") || strings.HasSuffix(lowerPath, ".xlsx") || strings.HasSuffix(lowerPath, ".pptm") || strings.HasSuffix(lowerPath, ".docm") || strings.HasSuffix(lowerPath, ".xlsm") || strings.HasSuffix(lowerPath, ".pptm") {
		return e.scanOfficeOOXML(path, result)
	}
	if strings.HasSuffix(lowerPath, ".doc") || strings.HasSuffix(lowerPath, ".xls") || strings.HasSuffix(lowerPath, ".ppt") {
		return e.scanOfficeOLE(path, result)
	}

	// Fallback to reading magic bytes
	f, err := os.Open(path)
	if err == nil {
		magic := make([]byte, 8)
		f.Read(magic)
		f.Close()
		
		if string(magic[:4]) == "%PDF" {
			return e.scanPDF(path, result)
		}
		
		if magic[0] == 0xD0 && magic[1] == 0xCF && magic[2] == 0x11 && magic[3] == 0xE0 && magic[4] == 0xA1 && magic[5] == 0xB1 && magic[6] == 0x1A && magic[7] == 0xE1 {
			return e.scanOfficeOLE(path, result)
		}
	}

	return result, nil
}

func (e *DocumentEngine) scanPDF(path string, res *scanner.ScanResult) (*scanner.ScanResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return res, err
	}
	defer f.Close()

	head := make([]byte, 1024*1024)
	n, _ := f.Read(head)
	s := string(head[:n])

	rules := []struct {
		Keywords []string
		Name     string
		Severity string
		Desc     string
	}{
		{[]string{"/JS ", "/JavaScript ", "/JS\r", "/JavaScript\r", "/JS\n", "/JavaScript\n"}, "Embedded JavaScript", "Suspicious", "Contains AcroJS which could execute malicious logic"},
		{[]string{"/Launch ", "/OpenAction ", "/Launch\r", "/OpenAction\r", "/Launch\n", "/OpenAction\n"}, "Auto-Execution", "High", "Contains actions that execute automatically upon opening"},
		{[]string{"/EmbeddedFiles "}, "Embedded Objects", "Suspicious", "Contains embedded files which could be dropped payloads"},
	}

	for _, r := range rules {
		for _, kw := range r.Keywords {
			if strings.Contains(s, kw) {
				res.Infected = true
				res.Threats = append(res.Threats, scanner.Threat{
					Name:        r.Name,
					Severity:    r.Severity,
					Description: r.Desc,
					Engine:      e.Name(),
				})
				break
			}
		}
	}

	return res, nil
}

func (e *DocumentEngine) scanOfficeOOXML(path string, res *scanner.ScanResult) (*scanner.ScanResult, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return res, err
	}
	defer r.Close()

	hasMacros := false
	for _, f := range r.File {
		if strings.HasSuffix(strings.ToLower(f.Name), "vbaproject.bin") {
			hasMacros = true
			
			rc, err := f.Open()
			if err == nil {
				buf := make([]byte, 1024*1024)
				n, _ := rc.Read(buf)
				rc.Close()
				s := string(buf[:n])
				
				if strings.Contains(s, "AutoOpen") || strings.Contains(s, "Document_Open") || strings.Contains(s, "Workbook_Open") {
					res.Infected = true
					res.Threats = append(res.Threats, scanner.Threat{
						Name:        "Macro Auto-Execution",
						Severity:    "Critical",
						Description: "Contains VBA macros that execute automatically",
						Engine:      e.Name(),
					})
				}
				if strings.Contains(s, "CreateObject") || strings.Contains(s, "WScript.Shell") || strings.Contains(s, "Shell") {
					res.Infected = true
					res.Threats = append(res.Threats, scanner.Threat{
						Name:        "Macro Shell Execution",
						Severity:    "Critical",
						Description: "VBA macro attempts to execute OS commands or drop objects",
						Engine:      e.Name(),
					})
				}
			}
		}
	}

	if hasMacros {
		res.Infected = true
		// Make sure not to duplicate threat names if possible, but it's okay for an array
		res.Threats = append(res.Threats, scanner.Threat{
			Name:        "VBA Macros",
			Severity:    "Suspicious",
			Description: "Document contains embedded VBA macros",
			Engine:      e.Name(),
		})
	}

	return res, nil
}

func (e *DocumentEngine) scanOfficeOLE(path string, res *scanner.ScanResult) (*scanner.ScanResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return res, err
	}
	defer f.Close()

	head := make([]byte, 2*1024*1024)
	n, _ := f.Read(head)
	s := string(head[:n])

	if strings.Contains(s, "AutoOpen") || strings.Contains(s, "Document_Open") || strings.Contains(s, "Workbook_Open") {
		res.Infected = true
		res.Threats = append(res.Threats, scanner.Threat{
			Name:        "Macro Auto-Execution",
			Severity:    "Critical",
			Description: "Contains VBA macros that execute automatically",
			Engine:      e.Name(),
		})
	}
	if strings.Contains(s, "CreateObject") || strings.Contains(s, "WScript.Shell") {
		res.Infected = true
		res.Threats = append(res.Threats, scanner.Threat{
			Name:        "Macro Shell Execution",
			Severity:    "Critical",
			Description: "VBA macro attempts to execute OS commands or drop objects",
			Engine:      e.Name(),
		})
	}

	return res, nil
}

func (e *DocumentEngine) Update(ctx context.Context) error {
	// Document scanner is static signature/regex based and does not require definition updates
	return nil
}

func (e *DocumentEngine) Close() error {
	return nil
}
