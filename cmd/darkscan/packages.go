package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/afterdarksys/darkscan/pkg/darkapi"
	"github.com/spf13/cobra"
)

var packageManifestFile string

var packageCmd = &cobra.Command{
	Use:   "package",
	Short: "Software supply-chain checks via DarkAPI.io",
	Long:  `Check packages for typosquatting and known supply-chain threats using the DarkAPI.io packages API.`,
}

var packageCheckCmd = &cobra.Command{
	Use:   "check [<ecosystem>/<name>[@version]]",
	Short: "Check a package (or a whole manifest) for supply-chain threats",
	Long: `Check a single package reference such as npm/lodash@4.17.21, or pass
--file with a package.json or requirements.txt to check every dependency.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newDarkAPIClient()
		if err != nil {
			return err
		}
		ctx := context.Background()

		if packageManifestFile != "" {
			refs, err := parseManifest(packageManifestFile)
			if err != nil {
				return err
			}
			if len(refs) == 0 {
				return fmt.Errorf("no packages found in %s", packageManifestFile)
			}
			raw, err := c.PackageCheckBulk(ctx, refs)
			if err != nil {
				return err
			}
			return printIntelPayload(raw)
		}

		if len(args) != 1 {
			return fmt.Errorf("a package reference is required unless --file is given")
		}
		ref, err := parsePackageRef(args[0])
		if err != nil {
			return err
		}
		res, err := c.PackageCheck(ctx, ref)
		if err != nil {
			return err
		}

		if outputFormat == "json" {
			return printIntelPayload(res.Raw)
		}
		fmt.Printf("Package:   %s/%s", res.Ecosystem, res.Name)
		if res.Version != "" {
			fmt.Printf("@%s", res.Version)
		}
		fmt.Println()
		fmt.Printf("Malicious: %v\n", res.Malicious)
		fmt.Printf("Typosquat: %v\n", res.Typosquat)
		if res.Risk != "" {
			fmt.Printf("Risk:      %s\n", res.Risk)
		}
		if res.Reason != "" {
			fmt.Printf("Reason:    %s\n", res.Reason)
		}
		return nil
	},
}

func init() {
	packageCheckCmd.Flags().StringVar(&packageManifestFile, "file", "", "package.json or requirements.txt to check in bulk")
	packageCmd.AddCommand(packageCheckCmd)
}

// parsePackageRef parses "<ecosystem>/<name>[@version]".
func parsePackageRef(s string) (darkapi.PackageRef, error) {
	slash := strings.Index(s, "/")
	if slash <= 0 || slash == len(s)-1 {
		return darkapi.PackageRef{}, fmt.Errorf("invalid package reference %q: expected <ecosystem>/<name>[@version]", s)
	}
	ecosystem := s[:slash]
	rest := s[slash+1:]

	name, version := rest, ""
	if at := strings.LastIndex(rest, "@"); at > 0 {
		name = rest[:at]
		version = rest[at+1:]
	}
	return darkapi.PackageRef{Ecosystem: ecosystem, Name: name, Version: version}, nil
}

// parseManifest reads a package.json (npm) or requirements.txt (pypi) manifest
// into a minimal list of package references.
func parseManifest(path string) ([]darkapi.PackageRef, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	base := strings.ToLower(filepath.Base(path))
	switch {
	case base == "package.json":
		return parsePackageJSON(data)
	case base == "requirements.txt" || strings.HasSuffix(base, ".txt"):
		return parseRequirementsTxt(data), nil
	default:
		if strings.HasSuffix(base, ".json") {
			return parsePackageJSON(data)
		}
		return nil, fmt.Errorf("unsupported manifest %q (expected package.json or requirements.txt)", path)
	}
}

func parsePackageJSON(data []byte) ([]darkapi.PackageRef, error) {
	var manifest struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse package.json: %w", err)
	}

	var refs []darkapi.PackageRef
	add := func(deps map[string]string) {
		for name, version := range deps {
			refs = append(refs, darkapi.PackageRef{
				Ecosystem: "npm",
				Name:      name,
				Version:   strings.TrimLeft(version, "^~>=<v "),
			})
		}
	}
	add(manifest.Dependencies)
	add(manifest.DevDependencies)
	return refs, nil
}

func parseRequirementsTxt(data []byte) []darkapi.PackageRef {
	var refs []darkapi.PackageRef
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// Strip inline comments and environment markers.
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if i := strings.Index(line, ";"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}

		name, version := line, ""
		for _, sep := range []string{"==", ">=", "<=", "~=", "!=", ">", "<"} {
			if i := strings.Index(line, sep); i >= 0 {
				name = strings.TrimSpace(line[:i])
				version = strings.TrimSpace(line[i+len(sep):])
				break
			}
		}
		if name == "" {
			continue
		}
		refs = append(refs, darkapi.PackageRef{Ecosystem: "pypi", Name: name, Version: version})
	}
	return refs
}
