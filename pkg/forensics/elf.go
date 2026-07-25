package forensics

import (
	"debug/elf"
)

func AnalyzeELF(path string, feats *FileFeatures) error {
	f, err := elf.Open(path)
	if err != nil {
		return err // Not an ELF file
	}
	defer f.Close()

	if feats.Type == "" {
		feats.Type = "ELF"
	}

	feats.NumSections = len(f.Sections)

	imports, err := f.ImportedSymbols()
	if err == nil {
		feats.NumImports = len(imports)
	}

	exports, err := f.DynamicSymbols()
	if err == nil {
		feats.NumExports = len(exports)
	}

	// Check for executable stack (GNU_STACK)
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_GNU_STACK {
			if prog.Flags&elf.PF_X != 0 {
				feats.HasExecutableStack = true
			}
		}
	}

	return nil
}
