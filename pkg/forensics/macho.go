package forensics

import (
	"debug/macho"
)

func AnalyzeMachO(path string, feats *FileFeatures) error {
	f, err := macho.Open(path)
	if err != nil {
		// Try fat file
		fat, errFat := macho.OpenFat(path)
		if errFat != nil {
			return err
		}
		defer fat.Close()
		if feats.Type == "" {
			feats.Type = "Mach-O (Fat)"
		}

		// Just take first arch
		f = fat.Arches[0].File
	} else {
		defer f.Close()
		if feats.Type == "" {
			feats.Type = "Mach-O"
		}
	}

	feats.NumSections = len(f.Sections)

	imports, err := f.ImportedSymbols()
	if err == nil {
		feats.NumImports = len(imports)
	}

	// Simplified: didn't parse exports

	return nil
}
