package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/spf13/cobra"
)

// Tunable defaults for the memory subcommand. These mirror the flag defaults
// and are referenced by the extraction/scanning routines below.
const (
	memChunkSize   = 4 << 20 // 4 MiB streaming window
	memOverlapSize = 512      // carry-over bytes so boundary-straddling secrets still match
)

var (
	memMinLen      int
	memEntropy     float64
	memJSON        bool
	memMaxFindings int
	memTypes       []string
	memContext     int

	memStringsMinLen int
	memStringsOffset bool
)

// memoryCmd is the parent for DFIR memory-analysis subcommands. The parent CLI
// registers this via rootCmd.AddCommand(memoryCmd).
var memoryCmd = &cobra.Command{
	Use:   "memory",
	Short: "Analyze memory dumps/captures and hunt for secrets",
	Long: `Analyze memory dumps and captures (raw .mem/.vmem/.dmp/core images or any
binary blob) for leaked keys, secrets, credentials, and tokens.

This is a DFIR/forensics building block: it streams large dumps in bounded
chunks, extracts printable ASCII and UTF-16LE strings, and runs a battery of
secret/key detectors over them. All findings are REDACTED — the full secret is
never printed.`,
}

// memoryScanCmd streams a dump and reports redacted secret findings.
var memoryScanCmd = &cobra.Command{
	Use:   "scan <dumpfile>",
	Short: "Scan a memory dump/capture for secrets and keys",
	Long: `Scan a memory dump or capture file for secrets, keys, credentials, and tokens.

The file is streamed in bounded chunks (default 4 MiB) with a carry-over overlap
window so a secret straddling a chunk boundary is still matched — multi-GB dumps
never load fully into RAM. Printable ASCII and UTF-16LE strings are extracted and
run through detectors for cloud keys, tokens, private keys, JWTs, DB connection
strings, credential pairs, and generic high-entropy secrets.

Every finding is REDACTED: only the first/last few characters are shown, and the
byte offset, detector type, Shannon entropy, and a sanitized context snippet are
reported. Identical (type,value) pairs are deduplicated.`,
	Args: cobra.ExactArgs(1),
	RunE: runMemoryScan,
}

// memoryStringsCmd prints the extracted printable strings only.
var memoryStringsCmd = &cobra.Command{
	Use:   "strings <dumpfile>",
	Short: "Extract printable ASCII+UTF-16LE strings from a dump",
	Long: `Extract and print printable strings (ASCII and UTF-16LE runs) from a memory
dump or capture. Useful as a building block for the scan detectors or for manual
triage. Use --offset to prefix each string with its byte offset in the dump.`,
	Args: cobra.ExactArgs(1),
	RunE: runMemoryStrings,
}

func init() {
	memoryScanCmd.Flags().IntVar(&memMinLen, "min-len", 6, "Minimum printable string length to consider")
	memoryScanCmd.Flags().Float64Var(&memEntropy, "entropy", 4.0, "Shannon entropy threshold for the generic high-entropy detector")
	memoryScanCmd.Flags().BoolVar(&memJSON, "json", false, "Emit findings as a JSON array")
	memoryScanCmd.Flags().IntVar(&memMaxFindings, "max-findings", 0, "Maximum findings to report (0 = unlimited)")
	memoryScanCmd.Flags().StringSliceVar(&memTypes, "types", nil, "Only run the named detectors (comma-separated)")
	memoryScanCmd.Flags().IntVar(&memContext, "context", 32, "Context bytes to include around each finding")

	memoryStringsCmd.Flags().IntVar(&memStringsMinLen, "min-len", 6, "Minimum printable string length to print")
	memoryStringsCmd.Flags().BoolVar(&memStringsOffset, "offset", false, "Prefix each string with its byte offset")

	memoryCmd.AddCommand(memoryScanCmd)
	memoryCmd.AddCommand(memoryStringsCmd)
}

// extractedString is a printable run recovered from the dump, tagged with the
// byte offset at which it began and the encoding it was decoded from.
type extractedString struct {
	Offset   int64  // byte offset of the first byte of the run in the dump
	Value    string // decoded printable text
	Encoding string // "ascii" or "utf16le"
}

// memoryFinding is a single (possibly deduplicated) secret detection.
type memoryFinding struct {
	Type    string  `json:"type"`             // detector name
	Offset  int64   `json:"offset"`           // byte offset of the first occurrence
	Preview string  `json:"preview"`          // REDACTED preview, never the full secret
	Entropy float64 `json:"entropy"`          // Shannon entropy of the matched value
	Context string  `json:"context"`          // sanitized surrounding snippet
	Count   int     `json:"count"`            // number of identical (type,value) hits
	value   string  // full value, kept internal for dedup only; not serialized
}

// secretDetector pairs a detector name with a compiled regex. A nil regex means
// the detector is handled specially (e.g. the generic entropy detector).
type secretDetector struct {
	Name    string
	Pattern *regexp.Regexp
}

// detectors returns the ordered list of regex-based secret detectors. The
// generic high-entropy detector is applied separately in scanString.
func detectors() []secretDetector {
	return []secretDetector{
		{"aws_access_key_id", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
		{"aws_secret_access_key", regexp.MustCompile(`(?i)aws.{0,20}?['"= :]([A-Za-z0-9/+]{40})`)},
		{"google_api_key", regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`)},
		{"github_token", regexp.MustCompile(`gh[porsu]_[0-9A-Za-z]{36}`)},
		{"slack_token", regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,72}`)},
		{"stripe_key", regexp.MustCompile(`(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{24,}`)},
		{"sendgrid_key", regexp.MustCompile(`SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}`)},
		{"twilio_key", regexp.MustCompile(`SK[0-9a-f]{32}`)},
		{"private_key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----`)},
		{"jwt", regexp.MustCompile(`eyJ[0-9A-Za-z_\-]+\.eyJ[0-9A-Za-z_\-]+\.[0-9A-Za-z_\-]+`)},
		{"db_connection_string", regexp.MustCompile(`(?:mysql|postgres(?:ql)?|mongodb|redis|mssql)://[^:\s/@]+:[^@\s/]+@[^\s/]+`)},
		{"email_password", regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}:[^\s:]{4,}`)},
	}
}

// genericTokenRe matches base64/hex-ish tokens the entropy detector examines.
var genericTokenRe = regexp.MustCompile(`[A-Za-z0-9+/=_\-]{20,}`)

// redact returns a masked preview of s that reveals only the first and last few
// characters. It never returns the full secret. Short values are fully masked.
func redact(s string) string {
	const keep = 4
	n := len(s)
	if n == 0 {
		return ""
	}
	if n <= keep*2 {
		return strings.Repeat("*", n)
	}
	return s[:keep] + strings.Repeat("*", n-keep*2) + s[n-keep:]
}

// entropy computes the Shannon entropy (in bits per byte) of s over its byte
// distribution. Returns 0 for the empty string.
func entropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	total := float64(len(s))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		h -= p * math.Log2(p)
	}
	return h
}

// sanitize collapses non-printable and whitespace runs so a context snippet is
// safe to print on a single line.
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' {
			b.WriteByte(' ')
		} else if unicode.IsPrint(r) {
			b.WriteRune(r)
		} else {
			b.WriteByte('.')
		}
	}
	return strings.TrimSpace(b.String())
}

// isPrintableASCII reports whether b is a printable ASCII byte (space..~).
func isPrintableASCII(b byte) bool {
	return b >= 0x20 && b <= 0x7e
}

// extractStrings recovers printable ASCII and UTF-16LE runs of at least minLen
// characters from buf. baseOffset is the dump offset of buf[0]. Runs that begin
// within the first `skip` bytes are dropped so overlap regions are not
// re-emitted by the caller (pass skip=0 for the first chunk).
func extractStrings(buf []byte, baseOffset int64, minLen, skip int) []extractedString {
	var out []extractedString

	// ASCII runs.
	start := -1
	for i := 0; i < len(buf); i++ {
		if isPrintableASCII(buf[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			if i-start >= minLen && start >= skip {
				out = append(out, extractedString{
					Offset:   baseOffset + int64(start),
					Value:    string(buf[start:i]),
					Encoding: "ascii",
				})
			}
			start = -1
		}
	}
	if start >= 0 && len(buf)-start >= minLen && start >= skip {
		out = append(out, extractedString{
			Offset:   baseOffset + int64(start),
			Value:    string(buf[start:]),
			Encoding: "ascii",
		})
	}

	// UTF-16LE runs: printable ASCII byte followed by a zero high byte.
	i := 0
	for i+1 < len(buf) {
		if isPrintableASCII(buf[i]) && buf[i+1] == 0x00 {
			runStart := i
			var sb strings.Builder
			for i+1 < len(buf) && isPrintableASCII(buf[i]) && buf[i+1] == 0x00 {
				sb.WriteByte(buf[i])
				i += 2
			}
			if sb.Len() >= minLen && runStart >= skip {
				out = append(out, extractedString{
					Offset:   baseOffset + int64(runStart),
					Value:    sb.String(),
					Encoding: "utf16le",
				})
			}
			continue
		}
		i++
	}

	return out
}

// activeDetectors filters the full detector list by the --types selection. An
// empty selection means all detectors are active.
func activeDetectors(selected []string) []secretDetector {
	all := detectors()
	if len(selected) == 0 {
		return all
	}
	want := make(map[string]bool, len(selected))
	for _, s := range selected {
		want[strings.TrimSpace(s)] = true
	}
	var out []secretDetector
	for _, d := range all {
		if want[d.Name] {
			out = append(out, d)
		}
	}
	return out
}

// wantsGeneric reports whether the generic high-entropy detector should run
// given the --types selection.
func wantsGeneric(selected []string) bool {
	if len(selected) == 0 {
		return true
	}
	for _, s := range selected {
		if strings.TrimSpace(s) == "generic_high_entropy" {
			return true
		}
	}
	return false
}

// scanString applies the active detectors and the optional generic entropy
// detector to a single extracted string, appending raw findings to the shared
// map keyed by (type,value). The offset recorded is the string's start offset
// plus the in-string match index.
func scanString(
	es extractedString,
	dets []secretDetector,
	generic bool,
	entropyThreshold float64,
	contextBytes int,
	agg map[string]*memoryFinding,
	order *[]string,
) {
	record := func(typ, value string, matchIdx int) {
		key := typ + "\x00" + value
		if f, ok := agg[key]; ok {
			f.Count++
			return
		}
		off := es.Offset + int64(matchIdx)
		f := &memoryFinding{
			Type:    typ,
			Offset:  off,
			Preview: redact(value),
			Entropy: entropy(value),
			Context: contextSnippet(es.Value, matchIdx, len(value), contextBytes),
			Count:   1,
			value:   value,
		}
		agg[key] = f
		*order = append(*order, key)
	}

	for _, d := range dets {
		loc := d.Pattern.FindStringIndex(es.Value)
		for loc != nil {
			matchIdx := loc[0]
			value := es.Value[loc[0]:loc[1]]
			// For the AWS secret detector the capture group holds the key.
			if d.Name == "aws_secret_access_key" {
				if sub := d.Pattern.FindStringSubmatchIndex(es.Value); sub != nil && len(sub) >= 4 && sub[2] >= 0 {
					matchIdx = sub[2]
					value = es.Value[sub[2]:sub[3]]
				}
			}
			record(d.Name, value, matchIdx)
			// Advance past this match to find further hits in the same string.
			rest := loc[1]
			if next := d.Pattern.FindStringIndex(es.Value[rest:]); next != nil {
				loc = []int{rest + next[0], rest + next[1]}
			} else {
				loc = nil
			}
		}
	}

	if generic {
		for _, m := range genericTokenRe.FindAllStringIndex(es.Value, -1) {
			value := es.Value[m[0]:m[1]]
			if entropy(value) >= entropyThreshold {
				record("generic_high_entropy", value, m[0])
			}
		}
	}
}

// contextSnippet returns a sanitized window of surrounding text centered on a
// match within s. matchIdx/matchLen locate the match; ctx is the number of
// bytes of context on each side.
func contextSnippet(s string, matchIdx, matchLen, ctx int) string {
	start := matchIdx - ctx
	if start < 0 {
		start = 0
	}
	end := matchIdx + matchLen + ctx
	if end > len(s) {
		end = len(s)
	}
	return sanitize(s[start:end])
}

// openDump opens the dump file for reading, returning a clean error for missing
// or unreadable files (never a panic).
func openDump(path string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read dump file %q: %w", path, err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("cannot stat dump file %q: %w", path, err)
	}
	if info.IsDir() {
		f.Close()
		return nil, fmt.Errorf("%q is a directory, not a dump file", path)
	}
	return f, nil
}

// streamChunks reads f in memChunkSize windows and invokes fn for each chunk,
// carrying a memOverlapSize overlap between consecutive chunks. The `skip`
// argument passed to fn marks how many leading bytes belong to the previous
// chunk's overlap and should not re-emit strings. baseOffset is the dump offset
// of chunk[0].
func streamChunks(f io.Reader, fn func(chunk []byte, baseOffset int64, skip int) error) error {
	reader := bufio.NewReaderSize(f, memChunkSize)
	buf := make([]byte, memChunkSize)
	var carry []byte
	var consumed int64 // dump offset of the first NEW byte in the next read

	for {
		n, err := io.ReadFull(reader, buf)
		if n > 0 {
			var chunk []byte
			var baseOffset int64
			var skip int
			if len(carry) > 0 {
				chunk = append(chunk, carry...)
				chunk = append(chunk, buf[:n]...)
				baseOffset = consumed - int64(len(carry))
				skip = len(carry)
			} else {
				chunk = buf[:n]
				baseOffset = consumed
				skip = 0
			}

			if ferr := fn(chunk, baseOffset, skip); ferr != nil {
				return ferr
			}

			consumed += int64(n)

			// Prepare the overlap carry for the next iteration.
			if n >= memOverlapSize {
				carry = append(carry[:0:0], buf[n-memOverlapSize:n]...)
			} else {
				carry = append(carry[:0:0], buf[:n]...)
			}
		}

		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("error reading dump: %w", err)
		}
	}
}

func runMemoryScan(cmd *cobra.Command, args []string) error {
	path := args[0]
	f, err := openDump(path)
	if err != nil {
		return err
	}
	defer f.Close()

	dets := activeDetectors(memTypes)
	generic := wantsGeneric(memTypes)
	if len(dets) == 0 && !generic {
		return fmt.Errorf("no valid detectors selected via --types")
	}

	agg := make(map[string]*memoryFinding)
	var order []string

	err = streamChunks(f, func(chunk []byte, baseOffset int64, skip int) error {
		for _, es := range extractStrings(chunk, baseOffset, memMinLen, skip) {
			scanString(es, dets, generic, memEntropy, memContext, agg, &order)
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Materialize findings in first-seen order.
	findings := make([]memoryFinding, 0, len(order))
	for _, key := range order {
		findings = append(findings, *agg[key])
	}
	// Stable sort by offset for deterministic output.
	sort.SliceStable(findings, func(i, j int) bool {
		return findings[i].Offset < findings[j].Offset
	})
	if memMaxFindings > 0 && len(findings) > memMaxFindings {
		findings = findings[:memMaxFindings]
	}

	if memJSON {
		return printMemoryFindingsJSON(findings)
	}
	printMemoryFindingsText(findings, path)
	return nil
}

// printMemoryFindingsJSON emits findings as a JSON array (never the full secret).
func printMemoryFindingsJSON(findings []memoryFinding) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if findings == nil {
		findings = []memoryFinding{}
	}
	return encoder.Encode(findings)
}

// printMemoryFindingsText prints a human-readable, redacted report plus a
// summary line counting findings by type.
func printMemoryFindingsText(findings []memoryFinding, path string) {
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("MEMORY SECRET SCAN")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("Dump: %s\n", path)
	fmt.Println(strings.Repeat("-", 70))

	byType := make(map[string]int)
	for _, f := range findings {
		byType[f.Type]++
		fmt.Printf("\n[%s] offset=0x%x (%d)\n", f.Type, f.Offset, f.Offset)
		fmt.Printf("  preview:  %s\n", f.Preview)
		fmt.Printf("  entropy:  %.2f\n", f.Entropy)
		if f.Count > 1 {
			fmt.Printf("  count:    %d\n", f.Count)
		}
		if f.Context != "" {
			fmt.Printf("  context:  %s\n", f.Context)
		}
	}

	fmt.Println("\n" + strings.Repeat("-", 70))
	types := make([]string, 0, len(byType))
	for t := range byType {
		types = append(types, t)
	}
	sort.Strings(types)
	var parts []string
	for _, t := range types {
		parts = append(parts, fmt.Sprintf("%s=%d", t, byType[t]))
	}
	if len(findings) == 0 {
		fmt.Println("SUMMARY: 0 findings")
	} else {
		fmt.Printf("SUMMARY: %d findings (%s)\n", len(findings), strings.Join(parts, ", "))
	}
	fmt.Println(strings.Repeat("=", 70))
}

func runMemoryStrings(cmd *cobra.Command, args []string) error {
	path := args[0]
	f, err := openDump(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()

	return streamChunks(f, func(chunk []byte, baseOffset int64, skip int) error {
		for _, es := range extractStrings(chunk, baseOffset, memStringsMinLen, skip) {
			if memStringsOffset {
				fmt.Fprintf(w, "%d:%s\n", es.Offset, es.Value)
			} else {
				fmt.Fprintln(w, es.Value)
			}
		}
		return nil
	})
}
