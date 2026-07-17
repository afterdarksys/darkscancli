package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

var (
	fuzzTarget     string
	fuzzSeed       string
	fuzzSeedDir    string
	fuzzIterations int
	fuzzTimeout    time.Duration
	fuzzOutDir     string
	fuzzRNGSeed    int64
	fuzzJSON       bool
	fuzzWorkers    int
)

var fuzzCmd = &cobra.Command{
	Use:   "fuzz",
	Short: "Mutation-based fuzzing toolkit",
	Long:  `Mutate seed inputs and feed them to a target program to discover crashes and hangs (AFL-style).`,
}

var fuzzRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run a mutation-based fuzzing session against a target command",
	Long: `Run repeatedly mutates seed inputs and executes a target command against each
mutated input, recording crashes (signal death / abnormal exit) and hangs
(execution exceeding --timeout).

The literal token @@ in --target is replaced with the path to a temp file
holding the mutated input (AFL convention). If --target has no @@, the
mutated bytes are piped to the target's stdin instead.`,
	RunE: runFuzz,
}

func init() {
	fuzzRunCmd.Flags().StringVar(&fuzzTarget, "target", "", "Target command template to execute for each mutated input (use @@ for the input file path; omit for stdin) (required)")
	fuzzRunCmd.Flags().StringVar(&fuzzSeed, "seed", "", "Path to a single seed input file")
	fuzzRunCmd.Flags().StringVar(&fuzzSeedDir, "seed-dir", "", "Path to a directory of seed input files (corpus)")
	fuzzRunCmd.Flags().IntVar(&fuzzIterations, "iterations", 1000, "Number of mutated executions to run")
	fuzzRunCmd.Flags().DurationVar(&fuzzTimeout, "timeout", 5*time.Second, "Per-execution timeout before a run is recorded as a hang")
	fuzzRunCmd.Flags().StringVar(&fuzzOutDir, "out", "./fuzz-findings", "Directory to write crashing/hanging inputs and reports")
	fuzzRunCmd.Flags().Int64Var(&fuzzRNGSeed, "rng-seed", 0, "Seed the RNG for reproducible runs (0 = time-based)")
	fuzzRunCmd.Flags().BoolVar(&fuzzJSON, "json", false, "Emit a JSON summary and per-finding records instead of text")
	fuzzRunCmd.Flags().IntVar(&fuzzWorkers, "workers", runtime.NumCPU(), "Number of concurrent worker executions")

	fuzzCmd.AddCommand(fuzzRunCmd)
}

// ---------------------------------------------------------------------------
// cobra entrypoint
// ---------------------------------------------------------------------------

func runFuzz(cmd *cobra.Command, args []string) error {
	opts := fuzzOptions{
		target:     fuzzTarget,
		seedPath:   fuzzSeed,
		seedDir:    fuzzSeedDir,
		iterations: fuzzIterations,
		timeout:    fuzzTimeout,
		outDir:     fuzzOutDir,
		rngSeed:    fuzzRNGSeed,
		workers:    fuzzWorkers,
		jsonOutput: fuzzJSON,
	}

	_, err := runFuzzEngine(context.Background(), opts, os.Stdout)
	return err
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

type fuzzOptions struct {
	target     string
	seedPath   string
	seedDir    string
	iterations int
	timeout    time.Duration
	outDir     string
	rngSeed    int64
	workers    int
	jsonOutput bool
}

type seedFile struct {
	name string
	data []byte
}

type execStatus int

const (
	statusOK execStatus = iota
	statusCrash
	statusHang
)

type execOutcome struct {
	status     execStatus
	exitCode   int
	signaled   bool
	signal     string
	stderrTail string
}

type crashRecord struct {
	Kind        string `json:"kind"`
	InputSHA256 string `json:"input_sha256"`
	Strategy    string `json:"mutation_strategy"`
	SeedSource  string `json:"seed_source"`
	ExitCode    int    `json:"exit_code,omitempty"`
	Signaled    bool   `json:"signaled,omitempty"`
	Signal      string `json:"signal,omitempty"`
	StderrTail  string `json:"stderr_tail,omitempty"`
	SavedPath   string `json:"saved_path,omitempty"`
	Timestamp   string `json:"timestamp"`
}

type fuzzSummary struct {
	Target        string        `json:"target"`
	Iterations    int           `json:"iterations"`
	Executed      int64         `json:"executed"`
	ExecErrors    int64         `json:"exec_errors"`
	DurationSec   float64       `json:"duration_seconds"`
	ExecsPerSec   float64       `json:"execs_per_sec"`
	Crashes       int64         `json:"crashes"`
	Hangs         int64         `json:"hangs"`
	UniqueCrashes int           `json:"unique_crashes"`
	OutDir        string        `json:"out_dir"`
	CrashRecords  []crashRecord `json:"crash_records,omitempty"`
	HangRecords   []crashRecord `json:"hang_records,omitempty"`
}

// fuzzState tracks execution counters and findings across the worker pool.
// Counters use atomics so workers never contend on a lock for the hot path;
// the mutex only guards the dedup maps and finding slices, which are touched
// solely on the (rare) crash/hang path.
type fuzzState struct {
	execs      atomic.Int64
	crashes    atomic.Int64
	hangs      atomic.Int64
	execErrors atomic.Int64

	mu            sync.Mutex
	seenCrashKeys map[string]bool
	seenHangKeys  map[string]bool
	uniqueSigs    map[string]bool
	crashRecords  []crashRecord
	hangRecords   []crashRecord
}

func newFuzzState() *fuzzState {
	return &fuzzState{
		seenCrashKeys: make(map[string]bool),
		seenHangKeys:  make(map[string]bool),
		uniqueSigs:    make(map[string]bool),
	}
}

func (s *fuzzState) recordCrash(dir string, data []byte, strategy, seedSource string, outcome execOutcome) {
	hash := fmt.Sprintf("%x", sha256.Sum256(data))

	signature := outcome.signal
	if signature == "" {
		signature = fmt.Sprintf("exit-%d", outcome.exitCode)
	}
	dedupKey := hash + "|" + signature

	rec := crashRecord{
		Kind:        "crash",
		InputSHA256: hash,
		Strategy:    strategy,
		SeedSource:  seedSource,
		ExitCode:    outcome.exitCode,
		Signaled:    outcome.signaled,
		Signal:      outcome.signal,
		StderrTail:  outcome.stderrTail,
		Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.uniqueSigs[signature] = true

	if s.seenCrashKeys[dedupKey] {
		s.crashRecords = append(s.crashRecords, rec)
		return
	}
	s.seenCrashKeys[dedupKey] = true

	binPath := filepath.Join(dir, hash+".bin")
	txtPath := filepath.Join(dir, hash+".txt")
	if err := os.WriteFile(binPath, data, 0o644); err == nil {
		rec.SavedPath = binPath
		writeSidecar(txtPath, rec)
	}

	s.crashRecords = append(s.crashRecords, rec)
}

func (s *fuzzState) recordHang(dir string, data []byte, strategy, seedSource string, outcome execOutcome) {
	hash := fmt.Sprintf("%x", sha256.Sum256(data))

	rec := crashRecord{
		Kind:        "hang",
		InputSHA256: hash,
		Strategy:    strategy,
		SeedSource:  seedSource,
		StderrTail:  outcome.stderrTail,
		Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.seenHangKeys[hash] {
		s.hangRecords = append(s.hangRecords, rec)
		return
	}
	s.seenHangKeys[hash] = true

	binPath := filepath.Join(dir, hash+".bin")
	txtPath := filepath.Join(dir, hash+".txt")
	if err := os.WriteFile(binPath, data, 0o644); err == nil {
		rec.SavedPath = binPath
		writeSidecar(txtPath, rec)
	}

	s.hangRecords = append(s.hangRecords, rec)
}

func writeSidecar(path string, rec crashRecord) {
	var b strings.Builder
	fmt.Fprintf(&b, "kind: %s\n", rec.Kind)
	fmt.Fprintf(&b, "mutation_strategy: %s\n", rec.Strategy)
	fmt.Fprintf(&b, "seed_source: %s\n", rec.SeedSource)
	fmt.Fprintf(&b, "timestamp: %s\n", rec.Timestamp)
	if rec.Kind == "crash" {
		fmt.Fprintf(&b, "exit_code: %d\n", rec.ExitCode)
		fmt.Fprintf(&b, "signaled: %v\n", rec.Signaled)
		if rec.Signal != "" {
			fmt.Fprintf(&b, "signal: %s\n", rec.Signal)
		}
	}
	fmt.Fprintf(&b, "input_sha256: %s\n", rec.InputSHA256)
	b.WriteString("stderr_tail:\n")
	b.WriteString(rec.StderrTail)
	b.WriteString("\n")
	_ = os.WriteFile(path, []byte(b.String()), 0o644)
}

// runFuzzEngine runs the full fuzzing session described by opts, writing
// progress/summary output to out (unless opts.jsonOutput, in which case only
// a single JSON document is written). It returns the final summary so
// callers (including tests) can assert on results directly.
func runFuzzEngine(ctx context.Context, opts fuzzOptions, out io.Writer) (fuzzSummary, error) {
	if strings.TrimSpace(opts.target) == "" {
		return fuzzSummary{}, fmt.Errorf("--target is required")
	}
	if opts.seedPath == "" && opts.seedDir == "" {
		return fuzzSummary{}, fmt.Errorf("at least one of --seed or --seed-dir is required")
	}
	if opts.iterations <= 0 {
		return fuzzSummary{}, fmt.Errorf("--iterations must be greater than 0")
	}
	workers := opts.workers
	if workers <= 0 {
		workers = 1
	}
	if opts.outDir == "" {
		return fuzzSummary{}, fmt.Errorf("--out must not be empty")
	}

	corpus, err := loadCorpus(opts.seedPath, opts.seedDir)
	if err != nil {
		return fuzzSummary{}, err
	}
	if len(corpus) == 0 {
		return fuzzSummary{}, fmt.Errorf("no seed inputs found (checked --seed=%q --seed-dir=%q)", opts.seedPath, opts.seedDir)
	}

	template := splitCommand(opts.target)
	if len(template) == 0 {
		return fuzzSummary{}, fmt.Errorf("--target could not be parsed into a command")
	}
	if _, lookErr := exec.LookPath(template[0]); lookErr != nil {
		if _, statErr := os.Stat(template[0]); statErr != nil {
			return fuzzSummary{}, fmt.Errorf("target binary not found: %s", template[0])
		}
	}

	crashDir := filepath.Join(opts.outDir, "crashes")
	hangDir := filepath.Join(opts.outDir, "hangs")
	tmpDir := filepath.Join(opts.outDir, ".cur")
	for _, d := range []string{opts.outDir, crashDir, hangDir, tmpDir} {
		if mkErr := os.MkdirAll(d, 0o755); mkErr != nil {
			return fuzzSummary{}, fmt.Errorf("failed to create output directory %s: %w", d, mkErr)
		}
	}
	defer os.RemoveAll(tmpDir)

	seed := opts.rngSeed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	master := rand.New(rand.NewSource(seed))

	state := newFuzzState()

	jobs := make(chan struct{}, workers*2)
	var wg sync.WaitGroup

	for w := 0; w < workers; w++ {
		workerRNG := rand.New(rand.NewSource(master.Int63()))
		wg.Add(1)
		go func(rng *rand.Rand) {
			defer wg.Done()
			for range jobs {
				runIteration(ctx, template, corpus, tmpDir, opts.timeout, crashDir, hangDir, rng, state)
			}
		}(workerRNG)
	}

	start := time.Now()
	stopProgress := make(chan struct{})
	var progressWG sync.WaitGroup
	if !opts.jsonOutput {
		progressWG.Add(1)
		go printProgress(out, start, opts.iterations, state, stopProgress, &progressWG)
	}

	for i := 0; i < opts.iterations; i++ {
		jobs <- struct{}{}
	}
	close(jobs)
	wg.Wait()

	if !opts.jsonOutput {
		close(stopProgress)
		progressWG.Wait()
	}

	duration := time.Since(start)
	summary := buildSummary(opts, duration, state)
	printFuzzSummary(out, opts.jsonOutput, summary)

	return summary, nil
}

func runIteration(ctx context.Context, template []string, corpus []seedFile, tmpDir string, timeout time.Duration, crashDir, hangDir string, rng *rand.Rand, state *fuzzState) {
	// Never let a bad mutation, a misbehaving target, or a bookkeeping bug
	// take down the fuzzer loop.
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "fuzz: recovered from internal panic: %v\n", r)
		}
	}()

	sf := corpus[rng.Intn(len(corpus))]
	strat := mutationStrategies[rng.Intn(len(mutationStrategies))]
	mutated := strat.fn(sf.data, rng)

	state.execs.Add(1)

	outcome, err := runOnce(ctx, template, mutated, tmpDir, timeout)
	if err != nil {
		state.execErrors.Add(1)
		return
	}

	switch outcome.status {
	case statusHang:
		state.hangs.Add(1)
		state.recordHang(hangDir, mutated, strat.name, sf.name, outcome)
	case statusCrash:
		state.crashes.Add(1)
		state.recordCrash(crashDir, mutated, strat.name, sf.name, outcome)
	}
}

func buildSummary(opts fuzzOptions, duration time.Duration, state *fuzzState) fuzzSummary {
	execs := state.execs.Load()
	rate := 0.0
	if duration.Seconds() > 0 {
		rate = float64(execs) / duration.Seconds()
	}

	state.mu.Lock()
	unique := len(state.uniqueSigs)
	crashRecords := append([]crashRecord(nil), state.crashRecords...)
	hangRecords := append([]crashRecord(nil), state.hangRecords...)
	state.mu.Unlock()

	sort.Slice(crashRecords, func(i, j int) bool { return crashRecords[i].Timestamp < crashRecords[j].Timestamp })
	sort.Slice(hangRecords, func(i, j int) bool { return hangRecords[i].Timestamp < hangRecords[j].Timestamp })

	return fuzzSummary{
		Target:        opts.target,
		Iterations:    opts.iterations,
		Executed:      execs,
		ExecErrors:    state.execErrors.Load(),
		DurationSec:   duration.Seconds(),
		ExecsPerSec:   rate,
		Crashes:       state.crashes.Load(),
		Hangs:         state.hangs.Load(),
		UniqueCrashes: unique,
		OutDir:        opts.outDir,
		CrashRecords:  crashRecords,
		HangRecords:   hangRecords,
	}
}

func printProgress(out io.Writer, start time.Time, total int, state *fuzzState, stop <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			printStatusLine(out, start, total, state)
		}
	}
}

func printStatusLine(out io.Writer, start time.Time, total int, state *fuzzState) {
	execs := state.execs.Load()
	elapsed := time.Since(start).Seconds()
	rate := 0.0
	if elapsed > 0 {
		rate = float64(execs) / elapsed
	}
	state.mu.Lock()
	unique := len(state.uniqueSigs)
	state.mu.Unlock()
	fmt.Fprintf(out, "\r[fuzz] execs=%d/%d execs/sec=%.1f crashes=%d hangs=%d unique=%d   ",
		execs, total, rate, state.crashes.Load(), state.hangs.Load(), unique)
}

func printFuzzSummary(out io.Writer, jsonOutput bool, summary fuzzSummary) {
	if jsonOutput {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(summary)
		return
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, strings.Repeat("=", 70))
	fmt.Fprintln(out, "FUZZ SUMMARY")
	fmt.Fprintln(out, strings.Repeat("=", 70))
	fmt.Fprintf(out, "Target:          %s\n", summary.Target)
	fmt.Fprintf(out, "Executions:      %d/%d\n", summary.Executed, summary.Iterations)
	fmt.Fprintf(out, "Duration:        %s\n", time.Duration(summary.DurationSec*float64(time.Second)).Round(time.Millisecond))
	fmt.Fprintf(out, "Execs/sec:       %.1f\n", summary.ExecsPerSec)
	fmt.Fprintf(out, "Exec errors:     %d\n", summary.ExecErrors)
	fmt.Fprintf(out, "Crashes:         %d (unique: %d)\n", summary.Crashes, summary.UniqueCrashes)
	fmt.Fprintf(out, "Hangs:           %d\n", summary.Hangs)
	fmt.Fprintf(out, "Findings dir:    %s\n", summary.OutDir)
	fmt.Fprintln(out, strings.Repeat("=", 70))
}

// ---------------------------------------------------------------------------
// Corpus loading
// ---------------------------------------------------------------------------

func loadCorpus(seedPath, seedDir string) ([]seedFile, error) {
	var corpus []seedFile

	if seedPath != "" {
		data, err := os.ReadFile(seedPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read seed file %s: %w", seedPath, err)
		}
		corpus = append(corpus, seedFile{name: filepath.Base(seedPath), data: data})
	}

	if seedDir != "" {
		entries, err := os.ReadDir(seedDir)
		if err != nil {
			return nil, fmt.Errorf("failed to read seed directory %s: %w", seedDir, err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			p := filepath.Join(seedDir, e.Name())
			data, err := os.ReadFile(p)
			if err != nil {
				return nil, fmt.Errorf("failed to read seed file %s: %w", p, err)
			}
			corpus = append(corpus, seedFile{name: e.Name(), data: data})
		}
	}

	return corpus, nil
}

// ---------------------------------------------------------------------------
// Target execution
// ---------------------------------------------------------------------------

// splitCommand tokenizes a target template on whitespace, honoring simple
// single/double-quoted substrings so paths or arguments containing spaces
// can be expressed (e.g. --target "/path/to/prog @@").
func splitCommand(template string) []string {
	var args []string
	var cur strings.Builder
	inQuotes := false
	var quoteChar byte

	flush := func() {
		if cur.Len() > 0 {
			args = append(args, cur.String())
			cur.Reset()
		}
	}

	for i := 0; i < len(template); i++ {
		c := template[i]
		switch {
		case inQuotes:
			if c == quoteChar {
				inQuotes = false
			} else {
				cur.WriteByte(c)
			}
		case c == '"' || c == '\'':
			inQuotes = true
			quoteChar = c
		case c == ' ' || c == '\t':
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()

	return args
}

// tailBuffer is an io.Writer that retains only the last max bytes written,
// used to bound memory use while still capturing a useful stderr tail from
// targets that misbehave and produce large amounts of output.
type tailBuffer struct {
	buf []byte
	max int
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if t.max > 0 && len(t.buf) > t.max {
		t.buf = t.buf[len(t.buf)-t.max:]
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	return string(t.buf)
}

// runOnce writes data to a temp file (if the target template uses @@) or
// pipes it to stdin, then executes the target under a timeout. It never
// panics: any internal panic is recovered and surfaced as an error.
func runOnce(parent context.Context, template []string, data []byte, tmpDir string, timeout time.Duration) (outcome execOutcome, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("recovered from panic during execution: %v", r)
		}
	}()

	if len(template) == 0 {
		return outcome, fmt.Errorf("empty target command")
	}

	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	argv := make([]string, len(template))
	copy(argv, template)

	var tmpFile string
	usesFile := false
	for i, a := range argv {
		if !strings.Contains(a, "@@") {
			continue
		}
		if tmpFile == "" {
			f, ferr := os.CreateTemp(tmpDir, "fuzz-*.bin")
			if ferr != nil {
				return outcome, fmt.Errorf("failed to create temp input: %w", ferr)
			}
			if _, werr := f.Write(data); werr != nil {
				f.Close()
				os.Remove(f.Name())
				return outcome, fmt.Errorf("failed to write temp input: %w", werr)
			}
			tmpFile = f.Name()
			f.Close()
		}
		argv[i] = strings.ReplaceAll(a, "@@", tmpFile)
		usesFile = true
	}
	if tmpFile != "" {
		defer os.Remove(tmpFile)
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	if !usesFile {
		cmd.Stdin = bytes.NewReader(data)
	}

	stderrTail := &tailBuffer{max: 4096}
	cmd.Stdout = io.Discard
	cmd.Stderr = stderrTail

	runErr := cmd.Run()

	if ctx.Err() == context.DeadlineExceeded {
		outcome.status = statusHang
		outcome.stderrTail = stderrTail.String()
		return outcome, nil
	}

	if runErr == nil {
		outcome.status = statusOK
		return outcome, nil
	}

	exitErr, ok := runErr.(*exec.ExitError)
	if !ok {
		// Not an exit error from the child (e.g. binary missing, permission
		// denied, or another exec-level failure): surface it as an execution
		// error rather than a target crash.
		return outcome, fmt.Errorf("failed to execute target: %w", runErr)
	}

	outcome.exitCode = exitErr.ExitCode()
	outcome.stderrTail = stderrTail.String()

	if ws, wsOK := exitErr.Sys().(syscall.WaitStatus); wsOK && ws.Signaled() {
		outcome.signaled = true
		outcome.signal = ws.Signal().String()
		outcome.status = statusCrash
		return outcome, nil
	}

	// Some targets are wrapped by a shell, which reports 128+signal as its
	// own exit code rather than dying by signal itself; treat that range as
	// a crash too.
	if outcome.exitCode > 128 {
		outcome.status = statusCrash
		return outcome, nil
	}

	outcome.status = statusOK
	return outcome, nil
}

// ---------------------------------------------------------------------------
// Mutation strategies
// ---------------------------------------------------------------------------

type mutation struct {
	name string
	fn   func([]byte, *rand.Rand) []byte
}

var mutationStrategies = []mutation{
	{"bitflip", mutateBitFlip},
	{"multi-bitflip", mutateMultiBitFlip},
	{"byteflip", mutateByteFlip},
	{"byte-arith", mutateByteArith},
	{"interesting", mutateInteresting},
	{"random-byte", mutateRandomByte},
	{"block-insert", mutateBlockInsert},
	{"block-delete", mutateBlockDelete},
	{"block-duplicate", mutateBlockDuplicate},
	{"havoc", mutateHavoc},
}

// havocPool lists the mutators havoc is allowed to stack. It is declared
// independently of mutationStrategies (rather than derived from it) because
// mutationStrategies' initializer includes mutateHavoc itself: deriving this
// list from mutationStrategies would create an initialization cycle
// (mutationStrategies -> mutateHavoc -> derived-list -> mutationStrategies).
var havocPool = []func([]byte, *rand.Rand) []byte{
	mutateBitFlip,
	mutateMultiBitFlip,
	mutateByteFlip,
	mutateByteArith,
	mutateInteresting,
	mutateRandomByte,
	mutateBlockInsert,
	mutateBlockDelete,
	mutateBlockDuplicate,
}

var interestingByteSequences = [][]byte{
	{0x00},
	{0xff},
	{0x7f},
	{0x80},
	{0x00, 0x00},
	{0xff, 0xff},
	{0x7f, 0xff, 0xff, 0xff}, // INT32_MAX
	{0x80, 0x00, 0x00, 0x00}, // INT32_MIN
	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
}

func cloneBytes(data []byte) []byte {
	out := make([]byte, len(data))
	copy(out, data)
	return out
}

func mutateBitFlip(data []byte, rng *rand.Rand) []byte {
	out := cloneBytes(data)
	if len(out) == 0 {
		return out
	}
	idx := rng.Intn(len(out))
	bit := uint(rng.Intn(8))
	out[idx] ^= 1 << bit
	return out
}

func mutateMultiBitFlip(data []byte, rng *rand.Rand) []byte {
	out := cloneBytes(data)
	if len(out) == 0 {
		return out
	}
	n := 2 + rng.Intn(7)
	for i := 0; i < n; i++ {
		idx := rng.Intn(len(out))
		bit := uint(rng.Intn(8))
		out[idx] ^= 1 << bit
	}
	return out
}

func mutateByteFlip(data []byte, rng *rand.Rand) []byte {
	out := cloneBytes(data)
	if len(out) == 0 {
		return out
	}
	n := 1 + rng.Intn(4)
	for i := 0; i < n; i++ {
		idx := rng.Intn(len(out))
		out[idx] ^= 0xff
	}
	return out
}

func mutateByteArith(data []byte, rng *rand.Rand) []byte {
	out := cloneBytes(data)
	if len(out) == 0 {
		return out
	}
	idx := rng.Intn(len(out))
	delta := rng.Intn(71) - 35 // -35..35
	out[idx] = byte(int(out[idx]) + delta)
	return out
}

func mutateInteresting(data []byte, rng *rand.Rand) []byte {
	out := cloneBytes(data)
	if len(out) == 0 {
		return out
	}
	val := interestingByteSequences[rng.Intn(len(interestingByteSequences))]
	idx := rng.Intn(len(out))
	for i := 0; i < len(val) && idx+i < len(out); i++ {
		out[idx+i] = val[i]
	}
	return out
}

func mutateRandomByte(data []byte, rng *rand.Rand) []byte {
	out := cloneBytes(data)
	if len(out) == 0 {
		return out
	}
	idx := rng.Intn(len(out))
	out[idx] = byte(rng.Intn(256))
	return out
}

func mutateBlockInsert(data []byte, rng *rand.Rand) []byte {
	blockLen := 1 + rng.Intn(16)
	block := make([]byte, blockLen)
	for i := range block {
		block[i] = byte(rng.Intn(256))
	}
	idx := 0
	if len(data) > 0 {
		idx = rng.Intn(len(data) + 1)
	}
	out := make([]byte, 0, len(data)+blockLen)
	out = append(out, data[:idx]...)
	out = append(out, block...)
	out = append(out, data[idx:]...)
	return out
}

func mutateBlockDelete(data []byte, rng *rand.Rand) []byte {
	if len(data) == 0 {
		return cloneBytes(data)
	}
	start := rng.Intn(len(data))
	maxLen := len(data) - start
	delLen := 1 + rng.Intn(maxLen)
	out := make([]byte, 0, len(data)-delLen)
	out = append(out, data[:start]...)
	out = append(out, data[start+delLen:]...)
	return out
}

func mutateBlockDuplicate(data []byte, rng *rand.Rand) []byte {
	if len(data) == 0 {
		return cloneBytes(data)
	}
	start := rng.Intn(len(data))
	maxLen := len(data) - start
	blkLen := 1 + rng.Intn(maxLen)
	block := make([]byte, blkLen)
	copy(block, data[start:start+blkLen])

	insertAt := rng.Intn(len(data) + 1)
	out := make([]byte, 0, len(data)+blkLen)
	out = append(out, data[:insertAt]...)
	out = append(out, block...)
	out = append(out, data[insertAt:]...)
	return out
}

func mutateHavoc(data []byte, rng *rand.Rand) []byte {
	out := cloneBytes(data)
	n := 2 + rng.Intn(5)
	for i := 0; i < n; i++ {
		fn := havocPool[rng.Intn(len(havocPool))]
		out = fn(out, rng)
	}
	return out
}
