package forensics

import (
	"debug/pe"
)

func AnalyzePE(path string, feats *FileFeatures) error {
	f, err := pe.Open(path)
	if err != nil {
		return err // Not a PE file
	}
	defer f.Close()

	if feats.Type == "" {
		feats.Type = "PE"
	}

	feats.NumSections = len(f.Sections)

	imports, err := f.ImportedSymbols()
	if err == nil {
		feats.NumImports = len(imports)
		// ImpHash normally calculated here
	}

	exports, err := f.ImportedLibraries() // Getting libraries as poor man's exports check for size constraint
	if err == nil {
		feats.NumExports = len(exports)
	}

	return nil
}
