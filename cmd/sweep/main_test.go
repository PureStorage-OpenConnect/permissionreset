package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/cmdflags/cmdflagstest"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/platform"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/run"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/treegen"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/tuning"
)

const (
	fixtureHost         = "sweeper-host"
	fixtureServer       = "192.0.2.1"
	fixtureExport       = "/export"
	fixtureMountPoint   = "/mnt/sweep"
	fixtureLocalScratch = "/mnt/sweep/tree"
	fixtureServerPath   = "/export/tree"
	fixtureTrialFiles   = 12_345
)

// fixtureMounts is the only mount table the command tests ever see. A test that
// resolves a mount must go through deps.openMounts, so a test that must not
// resolve one can fail by replacing this reader with a t.Fatal.
const fixtureMounts = "192.0.2.1:/export /mnt/sweep nfs4 rw,vers=4.1 0 0\n" +
	"/dev/sda1 / ext4 rw 0 0\n"

// scriptedRunner answers with rates from a script rather than measuring
// anything. It is handed out by the fixtures below in the order execute builds
// runners: the stock-baseline runner first, the search runner second.
type scriptedRunner struct {
	t          *testing.T
	name       string
	queue      []float64
	repeat     float64
	calls      int
	onCall     func(int)
	failOnCall map[int]error
	forbid     bool

	// cfg is the run.Config execute built for this runner. Recorded because the
	// configuration is the whole point of the trial adapter: a sweep of the wrong
	// root, or of a config that is not the real repair path, measures nothing an
	// operator will ever reproduce.
	cfg               run.Config
	configured        bool
	expectedPaths     int64
	expectedHistory   []int64
	measurement       tuning.ClientMeasurement
	haveMeasurement   bool
	measurementSerial float64
}

func (r *scriptedRunner) Trial(ctx context.Context, params tuning.Params) (float64, error) {
	r.t.Helper()
	if r.forbid {
		r.t.Fatalf("%s runner used a trial it should never have reached", r.name)
	}
	r.calls++
	r.expectedHistory = append(r.expectedHistory, r.expectedPaths)
	if r.onCall != nil {
		r.onCall(r.calls)
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if err := r.failOnCall[r.calls]; err != nil {
		return 0, err
	}
	r.measurementSerial++
	r.measurement = tuning.ClientMeasurement{CPUPct: 40 + r.measurementSerial, CPUUserPct: 20, CPUSysPct: 18,
		CPUSoftirqPct: 3.5, RlimitNofile: 1024}
	r.haveMeasurement = true
	if len(r.queue) > 0 {
		rate := r.queue[0]
		r.queue = r.queue[1:]
		return rate, nil
	}
	if r.repeat == 0 {
		r.t.Fatalf("%s runner ran out of scripted rates after %d calls", r.name, r.calls)
	}
	return r.repeat, nil
}

// LastMeasurement stands in for a real /proc/stat sample so the persistence path
// records a per-client entry.
func (r *scriptedRunner) LastMeasurement() (tuning.ClientMeasurement, bool) {
	return r.measurement, r.haveMeasurement
}

func (r *scriptedRunner) SetExpectedPaths(n int64) { r.expectedPaths = n }

// otherEntry is an unrelated key that must survive every save.
func otherEntry() tuning.Entry {
	return tuning.Entry{
		Clients: []string{"other-host"}, Server: "192.0.2.9", Export: "/other", Transport: "kernel",
		Params:   tuning.Params{Workers: 128, BatchSize: 50},
		Measured: tuning.Measured{OpsPerSec: 10, BaselineOpsPerSec: 9, Confidence: "high"},
	}
}

// fixtureDeps wires every seam to something in-memory. runners are handed out in
// call order.
func fixtureDeps(t *testing.T, saved *tuning.File, runners ...TrialRunner) commandDeps {
	t.Helper()
	handed := 0
	return commandDeps{
		newProvisioner: func(_, _ string, base treegen.Config) ScratchProvisioner {
			return &fakeProvisioner{t: t, existing: manifestFor(base.Scale, fixtureTrialFiles), failOnGenerate: true}
		},
		newRunner: func(cfg run.Config, _ cacheController, _ io.Writer) TrialRunner {
			if handed >= len(runners) {
				t.Fatalf("execute built %d runners, fixture provides %d", handed+1, len(runners))
			}
			r := runners[handed]
			handed++
			if sr, ok := r.(*scriptedRunner); ok {
				sr.cfg = cfg
				sr.configured = true
			}
			return r
		},
		load: func(string) (tuning.File, error) {
			return tuning.File{Version: tuning.Version, Tunings: []tuning.Entry{otherEntry()}}, nil
		},
		save: func(_ string, file tuning.File) error {
			*saved = file
			return nil
		},
		now:          func() time.Time { return time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC) },
		hostname:     func() (string, error) { return fixtureHost, nil },
		softNofile:   func() (uint64, error) { return 1 << 20, nil },
		openMounts:   func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(fixtureMounts)), nil },
		openTrialLog: openTrialLog,
	}
}

// commandFixture scripts a whole sweep. rates[0] is the opening stock baseline,
// rates[len-1] the closing one, and rates[1] every ladder and confirmation
// trial — the scripts here hold the three confirmation values equal, so their
// median is rates[1].
func commandFixture(t *testing.T, rates []float64) (commandDeps, *tuning.File) {
	t.Helper()
	if len(rates) < 3 {
		t.Fatalf("a fixture script needs an opening baseline, a trial rate and a closing baseline")
	}
	var saved tuning.File
	baseline := &scriptedRunner{t: t, name: "baseline", queue: []float64{rates[0], rates[len(rates)-1]}}
	trials := &scriptedRunner{t: t, name: "search", repeat: rates[1]}
	return fixtureDeps(t, &saved, baseline, trials), &saved
}

// configuredFixture is commandFixture with the two runners handed back, so a
// test can read the run.Config each one was built with.
func configuredFixture(t *testing.T, rates []float64) (commandDeps, *scriptedRunner, *scriptedRunner) {
	t.Helper()
	var saved tuning.File
	baseline := &scriptedRunner{t: t, name: "baseline", queue: []float64{rates[0], rates[len(rates)-1]}}
	trials := &scriptedRunner{t: t, name: "search", repeat: rates[1]}
	return fixtureDeps(t, &saved, baseline, trials), baseline, trials
}

func defaultCommandFixture(t *testing.T) commandDeps {
	t.Helper()
	deps, _ := commandFixture(t, []float64{100, 180, 180, 180, 100})
	return deps
}

func TestSweepProcessEscalatesSecondSignal(t *testing.T) {
	sigChReady := make(chan chan<- os.Signal, 1)
	escalated := make(chan os.Signal, 1)
	ctxCanceled := make(chan struct{})
	var errOut strings.Builder
	proc := sweepProcess{
		notifyContext: func(parent context.Context, _ ...os.Signal) (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(parent)
			return ctx, cancel
		},
		notify:     func(ch chan<- os.Signal, _ ...os.Signal) { sigChReady <- ch },
		stopSignal: func(chan<- os.Signal) {},
		escalate: func(sig os.Signal, stop func(), _ ...chan<- os.Signal) {
			stop()
			escalated <- sig
		},
		run: func(ctx context.Context) int {
			ch := <-sigChReady
			ch <- os.Interrupt
			ch <- os.Interrupt
			<-ctx.Done()
			close(ctxCanceled)
			return 130
		},
		errOut: &errOut,
	}

	if code := runSweepProcess(proc); code != 130 {
		t.Fatalf("code = %d, want 130", code)
	}
	select {
	case sig := <-escalated:
		if sig != os.Interrupt {
			t.Fatalf("escalated signal = %v, want interrupt", sig)
		}
	default:
		t.Fatal("sweep process did not escalate the second signal")
	}
	select {
	case <-ctxCanceled:
	default:
		t.Fatal("escalation did not stop the sweep context")
	}
	if want := "interrupt received — finishing in-flight work..."; !strings.Contains(errOut.String(), want) {
		t.Fatalf("stderr = %q, want %q", errOut.String(), want)
	}
}

// interruptingCommandFixture cancels partway through the first ladder, which is
// how a real SIGINT reaches the search.
func interruptingCommandFixture(t *testing.T, cancel context.CancelFunc) (commandDeps, *tuning.File) {
	t.Helper()
	var saved tuning.File
	baseline := &scriptedRunner{t: t, name: "baseline", queue: []float64{100}}
	trials := &scriptedRunner{t: t, name: "search", repeat: 180,
		onCall: func(n int) {
			if n == 3 {
				cancel()
			}
		}}
	return fixtureDeps(t, &saved, baseline, trials), &saved
}

// forcedTreeFixture adopts a tree of exactly files entries under --force and
// measures it at rate paths/sec.
func forcedTreeFixture(t *testing.T, files int64, rate float64) (commandDeps, *fakeProvisioner) {
	t.Helper()
	var saved tuning.File
	baseline := &scriptedRunner{t: t, name: "baseline", queue: []float64{rate}}
	trials := &scriptedRunner{t: t, name: "search", forbid: true}
	deps := fixtureDeps(t, &saved, baseline, trials)
	prov := &fakeProvisioner{t: t, enumerated: files, failOnGenerate: true}
	deps.newProvisioner = func(_, _ string, _ treegen.Config) ScratchProvisioner { return prov }
	deps.save = func(string, tuning.File) error {
		t.Fatal("save called for a rejected tree")
		return nil
	}
	return deps, prov
}

func generatedTreeFixture(t *testing.T, baselineRates []float64) (commandDeps, *tuning.File, *fakeProvisioner, *scriptedRunner) {
	t.Helper()
	var saved tuning.File
	baseline := &scriptedRunner{t: t, name: "baseline", queue: baselineRates}
	trials := &scriptedRunner{t: t, name: "search", repeat: 1800}
	deps := fixtureDeps(t, &saved, baseline, trials)
	prov := &fakeProvisioner{t: t, pathsPerCopy: 1000}
	deps.newProvisioner = func(_, _ string, _ treegen.Config) ScratchProvisioner { return prov }
	return deps, &saved, prov, baseline
}

// specAndPrincipals writes the two files every invocation must read.
func specAndPrincipals(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	specPath := filepath.Join(dir, "spec.yaml")
	body := "protocol: nfsv4\ndefault:\n  acl:\n    - \"A::OWNER@:rwaDxtTcCoy\"\n    - \"A:g:GROUP@:rxtncy\"\n    - \"A::EVERYONE@:rxtncy\"\n"
	if err := os.WriteFile(specPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	principals := filepath.Join(dir, "principals.json")
	roster := `{"domain":"example.test","roles":{"owner":"alice","group":"eng"}}`
	if err := os.WriteFile(principals, []byte(roster), 0o644); err != nil {
		t.Fatal(err)
	}
	return specPath, principals
}

// validArgs is the ordinary userspace invocation: a local scratch path under a
// mount whose source matches the requested server and export.
func validArgs(t *testing.T) []string {
	t.Helper()
	specPath, principals := specAndPrincipals(t)
	return []string{
		"--transport", "userspace",
		"--server", fixtureServer,
		"--export", fixtureExport,
		"--scratch", fixtureLocalScratch,
		"--spec", specPath,
		"--principals", principals,
	}
}

// serverPathArgs names the tree by its server-side path only, so nothing may
// consult a mount table.
func serverPathArgs(t *testing.T) []string {
	t.Helper()
	specPath, principals := specAndPrincipals(t)
	return []string{
		"--transport", "userspace",
		"--server", fixtureServer,
		"--export", fixtureExport,
		"--scratch-server-path", fixtureServerPath,
		"--spec", specPath,
		"--principals", principals,
	}
}

// forcedArgs sweeps a tree permissionreset did not generate, which is also the one
// invocation that needs no principal roster.
func forcedArgs(t *testing.T) []string {
	t.Helper()
	specPath, _ := specAndPrincipals(t)
	return []string{
		"--transport", "userspace",
		"--server", fixtureServer,
		"--export", fixtureExport,
		"--scratch", fixtureLocalScratch,
		"--spec", specPath,
		"--force",
	}
}

func kernelArgs(t *testing.T) []string {
	t.Helper()
	specPath, principals := specAndPrincipals(t)
	return []string{
		"--transport", "kernel",
		"--scratch", fixtureLocalScratch,
		"--spec", specPath,
		"--principals", principals,
	}
}

func expectedKey(t *testing.T) tuning.Key {
	t.Helper()
	key, err := tuning.UserspaceKey([]string{fixtureHost}, fixtureServer, fixtureExport)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func expectedKernelKey(t *testing.T) tuning.Key {
	t.Helper()
	key, err := tuning.NewKey([]string{fixtureHost}, fixtureServer, fixtureExport, "kernel")
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func findSavedEntry(t *testing.T, file tuning.File, key tuning.Key) tuning.Entry {
	t.Helper()
	entry, ok := file.Lookup(key)
	if !ok {
		t.Fatalf("no entry saved for %s; file = %+v", key.String(), file)
	}
	return entry
}

func readTrialLog(t *testing.T, path string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		t.Fatalf("trial log is not newline terminated: %q", data)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	records := make([]map[string]any, 0, len(lines))
	for i, line := range lines {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("line %d is not independent JSON: %v\n%s", i+1, err, line)
		}
		records = append(records, record)
	}
	return records
}

func TestExecuteAnnouncesTrialLogBeforeFirstTrial(t *testing.T) {
	var out strings.Builder
	var seen string
	var saved tuning.File
	baseline := &scriptedRunner{t: t, name: "baseline", queue: []float64{100, 100}, onCall: func(int) { seen = out.String() }}
	trials := &scriptedRunner{t: t, name: "search", repeat: 180}
	deps := fixtureDeps(t, &saved, baseline, trials)
	path := filepath.Join(t.TempDir(), "trials.jsonl")
	if code := execute(context.Background(), append(validArgs(t), "--trial-log", path), deps, &out, io.Discard); code != 0 {
		t.Fatalf("execute() = %d", code)
	}
	if !strings.Contains(seen, "trial log: "+path) {
		t.Fatalf("output at first trial = %q, want the path announced before measuring", seen)
	}
}

func TestExecuteLogsEveryTrialAndFinalSummary(t *testing.T) {
	deps, saved := commandFixture(t, []float64{100, 180, 180, 180, 95})
	path := filepath.Join(t.TempDir(), "trials.jsonl")
	args := append(validArgs(t), "--trial-log", path)
	var out strings.Builder
	if code := execute(context.Background(), args, deps, &out, io.Discard); code != 0 {
		t.Fatalf("execute() = %d", code)
	}

	records := readTrialLog(t, path)
	if len(records) != 40 {
		t.Fatalf("records = %d, want 39 trials plus one summary", len(records))
	}
	wantPhases := map[string]bool{
		"opening_baseline": false,
		"ladder":           false,
		"confirmation":     false,
		"closing_baseline": false,
	}
	for i, record := range records[:len(records)-1] {
		if got := int(record["seq"].(float64)); got != i+1 {
			t.Fatalf("record %d seq = %d, want %d", i, got, i+1)
		}
		phase, _ := record["phase"].(string)
		if _, ok := wantPhases[phase]; ok {
			wantPhases[phase] = true
		}
		params, ok := record["params"].(map[string]any)
		if !ok || len(params) != 5 {
			t.Fatalf("record %d params = %#v, want full five-tuple", i+1, record["params"])
		}
		if got := int(record["files"].(float64)); got != fixtureTrialFiles {
			t.Fatalf("record %d files = %d, want %d", i+1, got, fixtureTrialFiles)
		}
		if client, ok := record["client"].(map[string]any); !ok || client["cpu_pct"] == nil {
			t.Fatalf("record %d client = %#v, want this trial's CPU sample", i+1, record["client"])
		}
		if _, ok := record["duration_s"]; !ok {
			t.Fatalf("record %d has no duration_s field: %#v", i+1, record)
		}
	}
	for phase, seen := range wantPhases {
		if !seen {
			t.Fatalf("phase %q was not recorded", phase)
		}
	}
	if got := records[0]["knob"]; got != nil {
		t.Fatalf("opening baseline knob = %#v, want null", got)
	}
	if got := records[0]["value"]; got != nil {
		t.Fatalf("opening baseline value = %#v, want null", got)
	}

	var firstWorkers map[string]any
	for _, record := range records {
		if record["phase"] == "ladder" && record["knob"] == "workers" {
			firstWorkers = record
			break
		}
	}
	if firstWorkers == nil {
		t.Fatal("no workers ladder record")
	}
	params := firstWorkers["params"].(map[string]any)
	if got := int(params["connections"].(float64)); got != 1 {
		t.Fatalf("first workers record connections = %d, want frozen connections winner 1", got)
	}
	if got := int(params["slots"].(float64)); got != 0 {
		t.Fatalf("first workers record slots = %d, want frozen slots winner 0", got)
	}

	summary := records[len(records)-1]
	if summary["type"] != "summary" {
		t.Fatalf("final record type = %#v, want summary", summary["type"])
	}
	if summary["key"] != expectedKey(t).String() || summary["transport"] != "userspace" {
		t.Fatalf("summary identity = %#v", summary)
	}
	entry := findSavedEntry(t, *saved, expectedKey(t))
	if summary["confidence"] != entry.Measured.Confidence || summary["exit_disposition"] != "success" {
		t.Fatalf("summary outcome = %#v, saved measurement = %+v", summary, entry.Measured)
	}
	if summary["sweep_commit"] != commit || int(summary["trial_files"].(float64)) != fixtureTrialFiles {
		t.Fatalf("summary provenance = %#v", summary)
	}
	if summary["confirmed_median_ops_per_sec"] != float64(180) || summary["opening_baseline_ops_per_sec"] != float64(100) ||
		summary["closing_baseline_ops_per_sec"] != float64(95) || summary["baseline_drift"] != float64(0.05) {
		t.Fatalf("summary measurements = %#v", summary)
	}
	treeShape, ok := summary["tree_shape"].(map[string]any)
	if !ok || treeShape["scale"] != "large" || int(treeShape["copies"].(float64)) != treegen.Scales["large"].Copies ||
		int(treeShape["seed_files"].(float64)) != treegen.Scales["large"].SeedFiles ||
		int(treeShape["max_depth"].(float64)) != treegen.Scales["large"].MaxDepth ||
		int(treeShape["files_per_subtree"].(float64)) != fixtureFilesPerSubtree {
		t.Fatalf("summary tree shape = %#v", summary["tree_shape"])
	}
	winner, ok := summary["winner"].(map[string]any)
	if !ok || int(winner["connections"].(float64)) != entry.Params.Connections ||
		int(winner["slots"].(float64)) != entry.Params.Slots || int(winner["workers"].(float64)) != entry.Params.Workers ||
		int(winner["batch_size"].(float64)) != entry.Params.BatchSize ||
		int(winner["max_ops_per_compound"].(float64)) != entry.Params.MaxOpsPerCompound {
		t.Fatalf("summary winner = %#v, persisted = %+v", summary["winner"], entry.Params)
	}
	if !strings.Contains(out.String(), "trial log: "+path) {
		t.Fatalf("output = %q, want trial log path announced", out.String())
	}
}

func TestExecuteKeepsOverrideLogNameWhenItsSanitizedKeyMatchesTheDefaultPrefix(t *testing.T) {
	deps, saved := commandFixture(t, []float64{100, 180, 180, 180, 100})
	dir := t.TempDir()
	override := filepath.Join(dir, "permissionreset-trials-operator-choice.jsonl")
	args := append(validArgs(t), "--trial-log", override)
	var out strings.Builder
	if code := execute(context.Background(), args, deps, &out, io.Discard); code != 0 {
		t.Fatalf("execute() = %d", code)
	}
	_ = findSavedEntry(t, *saved, expectedKey(t))
	if !strings.Contains(out.String(), "trial log: "+override+"\n") {
		t.Fatalf("output = %q, want exact override path %q", out.String(), override)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(override) {
		t.Fatalf("override directory entries = %v, want only %q", entries, filepath.Base(override))
	}
}

func TestExecuteLogsCalibrationTrialForGeneratedScratch(t *testing.T) {
	deps, _, _, _ := generatedTreeFixture(t, []float64{1000, 1000, 1000})
	path := filepath.Join(t.TempDir(), "trials.jsonl")
	args := append(regenerateArgs(t), "--trial-log", path)
	if code := execute(context.Background(), args, deps, io.Discard, io.Discard); code != 0 {
		t.Fatalf("execute() = %d", code)
	}
	records := readTrialLog(t, path)
	if got := records[0]["phase"]; got != "calibration" {
		t.Fatalf("first phase = %#v, want calibration", got)
	}
	if got := int(records[0]["files"].(float64)); got != 4_000 {
		t.Fatalf("calibration files = %d, want probe manifest's 4000", got)
	}
	if records[0]["knob"] != nil || records[0]["value"] != nil {
		t.Fatalf("calibration knob/value = %#v/%#v, want null", records[0]["knob"], records[0]["value"])
	}
}

func TestExecuteDerivesAndAnnouncesDefaultTrialLogPath(t *testing.T) {
	deps, saved := commandFixture(t, []float64{100, 180, 180, 180, 100})
	var out strings.Builder
	if code := execute(context.Background(), validArgs(t), deps, &out, io.Discard); code != 0 {
		t.Fatalf("execute() = %d", code)
	}
	_ = findSavedEntry(t, *saved, expectedKey(t))
	const marker = "trial log: "
	start := strings.Index(out.String(), marker)
	if start < 0 {
		t.Fatalf("output = %q, want default trial log path", out.String())
	}
	path := strings.SplitN(out.String()[start+len(marker):], "\n", 2)[0]
	if filepath.Dir(path) != filepath.Dir(tuning.PathForExecutable(os.Args[0])) {
		t.Fatalf("default trial log directory = %q", filepath.Dir(path))
	}
	if !strings.HasPrefix(filepath.Base(path), trialLogPrefix) {
		t.Fatalf("default trial log name = %q", filepath.Base(path))
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("default trial log was not created: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })
}

func TestExecuteLogsFailedTrialAndContinuesSearch(t *testing.T) {
	var saved tuning.File
	baseline := &scriptedRunner{t: t, name: "baseline", queue: []float64{100, 100}}
	trials := &scriptedRunner{t: t, name: "search", repeat: 180,
		failOnCall: map[int]error{2: errors.New("candidate failed")}}
	deps := fixtureDeps(t, &saved, baseline, trials)
	path := filepath.Join(t.TempDir(), "trials.jsonl")
	args := append(validArgs(t), "--trial-log", path)
	if code := execute(context.Background(), args, deps, io.Discard, io.Discard); code != 0 {
		t.Fatalf("execute() = %d", code)
	}

	records := readTrialLog(t, path)
	failed := records[2]
	if failed["phase"] != "ladder" || failed["knob"] != "connections" || int(failed["value"].(float64)) != 2 {
		t.Fatalf("failed trial identity = %#v", failed)
	}
	if failed["error"] != "candidate failed" || failed["ops_per_sec"] != nil {
		t.Fatalf("failed trial outcome = %#v", failed)
	}
}

func TestExecuteLeavesCompleteTrialLogWithoutSummaryOnInterrupt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	deps, saved := interruptingCommandFixture(t, cancel)
	path := filepath.Join(t.TempDir(), "trials.jsonl")
	args := append(validArgs(t), "--trial-log", path)
	if code := execute(ctx, args, deps, io.Discard, io.Discard); code != 130 {
		t.Fatalf("execute() = %d, want 130", code)
	}
	_ = findSavedEntry(t, *saved, expectedKey(t))
	records := readTrialLog(t, path)
	if len(records) != 4 {
		t.Fatalf("records = %d, want opening baseline and three ladder trials", len(records))
	}
	for _, record := range records {
		if record["type"] == "summary" {
			t.Fatalf("interrupted log contains summary: %#v", record)
		}
	}
}

type failAfterWriter struct {
	remaining int
	calls     int
}

func (w *failAfterWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.remaining == 0 {
		return 0, errors.New("disk full")
	}
	w.remaining--
	return len(p), nil
}

func TestExecuteContinuesWhenTrialLogWriteFailsMidSweep(t *testing.T) {
	deps, saved := commandFixture(t, []float64{100, 180, 180, 180, 100})
	dst := &failAfterWriter{remaining: 2}
	var errOut strings.Builder
	deps.openTrialLog = func(path string, gotErrOut io.Writer) *trialLogWriter {
		log := newTrialLogWriter(dst, gotErrOut)
		log.path = path
		return log
	}
	path := filepath.Join(t.TempDir(), "trials.jsonl")
	args := append(validArgs(t), "--trial-log", path)
	if code := execute(context.Background(), args, deps, io.Discard, &errOut); code != 0 {
		t.Fatalf("execute() = %d; stderr = %q", code, errOut.String())
	}
	entry := findSavedEntry(t, *saved, expectedKey(t))
	if entry.Measured.Confidence != "high" || entry.Measured.OpsPerSec != 180 {
		t.Fatalf("saved entry = %+v, want the unaffected winner", entry)
	}
	if got := strings.Count(errOut.String(), "warning: trial log"); got != 1 {
		t.Fatalf("trial log warnings = %d, want exactly one; stderr = %q", got, errOut.String())
	}
	if dst.calls != 3 {
		t.Fatalf("sidecar writes = %d, want two successes and the first failed append only", dst.calls)
	}
}

func TestExecuteContinuesWhenTrialLogCannotBeWritten(t *testing.T) {
	deps, saved := commandFixture(t, []float64{100, 180, 180, 180, 100})
	path := t.TempDir()
	args := append(validArgs(t), "--trial-log", path)
	var errOut strings.Builder
	if code := execute(context.Background(), args, deps, io.Discard, &errOut); code != 0 {
		t.Fatalf("execute() = %d; stderr = %q", code, errOut.String())
	}
	entry := findSavedEntry(t, *saved, expectedKey(t))
	if entry.Measured.Confidence != "high" || entry.Measured.OpsPerSec != 180 {
		t.Fatalf("saved entry = %+v, want the unaffected winner", entry)
	}
	if got := strings.Count(errOut.String(), "warning: trial log"); got != 1 {
		t.Fatalf("trial log warnings = %d, want exactly one; stderr = %q", got, errOut.String())
	}
}

func TestExecuteDisablesTrialLogWithExplicitEmptyFlag(t *testing.T) {
	deps, saved := commandFixture(t, []float64{100, 180, 180, 180, 100})
	oldDir := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(oldDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
	var out strings.Builder
	args := append(validArgs(t), "--trial-log=")
	if code := execute(context.Background(), args, deps, &out, io.Discard); code != 0 {
		t.Fatalf("execute() = %d", code)
	}
	_ = findSavedEntry(t, *saved, expectedKey(t))
	entries, err := os.ReadDir(oldDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("disabled trial log created files: %v", entries)
	}
	if strings.Contains(out.String(), "trial log:") {
		t.Fatalf("disabled trial log was announced: %q", out.String())
	}
}

func TestExecuteRefusesWhenNoSearchRungFitsDescriptorLimit(t *testing.T) {
	deps := defaultCommandFixture(t)
	// Set a limit below the smallest workers rung (64) plus the live reserve.
	tooLow := uint64(64) + tuning.LiveDescriptorReserve() - 1
	deps.softNofile = func() (uint64, error) { return tooLow, nil }
	deps.save = func(string, tuning.File) error {
		t.Fatal("save called with no descriptor-safe search rung")
		return nil
	}
	var errOut strings.Builder
	if code := execute(context.Background(), kernelArgs(t), deps, io.Discard, &errOut); code == 0 {
		t.Fatal("execute() accepted a host where no workers rung fits")
	}
	if !strings.Contains(errOut.String(), "no workers ladder value fits") || !strings.Contains(errOut.String(), "raise ulimit -n") {
		t.Fatalf("stderr = %q, want actionable descriptor-limit refusal", errOut.String())
	}
}

func TestPersistValidationRejectsEntryTheReaderWouldReject(t *testing.T) {
	entry := tuning.Entry{Transport: "userspace", Params: tuning.Params{Connections: 0, Workers: 128, BatchSize: 50}}
	deps := commandDeps{
		load: func(string) (tuning.File, error) { t.Fatal("load called before validation"); return tuning.File{}, nil },
		save: func(string, tuning.File) error { t.Fatal("save called before validation"); return nil },
	}
	if err := persist(deps, "tuning.yaml", entry, 1024, io.Discard); err == nil || !strings.Contains(err.Error(), "connections absent or zero") {
		t.Fatalf("error = %v, want the shared reader contract", err)
	}
}

func TestExecuteWritesHighConfidenceWinnerAndPreservesOtherKeys(t *testing.T) {
	deps, saved := commandFixture(t, []float64{100, 180, 180, 180, 95})
	code := execute(context.Background(), validArgs(t), deps, io.Discard, io.Discard)
	if code != 0 {
		t.Fatalf("execute() = %d", code)
	}
	entry := findSavedEntry(t, *saved, expectedKey(t))
	if entry.Measured.Confidence != "high" || entry.Measured.BaselineOpsPerSec != 100 || entry.Measured.OpsPerSec != 180 {
		t.Fatalf("measurement = %+v", entry.Measured)
	}
	if len(saved.Tunings) != 2 {
		t.Fatalf("tunings = %d, want preserved second key", len(saved.Tunings))
	}
	if entry.Measured.TrialFiles != fixtureTrialFiles {
		t.Fatalf("trial files = %d, want the manifest's %d", entry.Measured.TrialFiles, fixtureTrialFiles)
	}
	if entry.Measured.SweptAt.Location() != time.UTC || entry.Measured.SweepCommit != commit {
		t.Fatalf("provenance = %+v", entry.Measured)
	}
	if len(entry.Measured.PerClient) != 1 || entry.Measured.PerClient[0].Client != fixtureHost {
		t.Fatalf("per-client = %+v", entry.Measured.PerClient)
	}
}

func TestExecuteMarksDriftAboveTenPercentLow(t *testing.T) {
	deps, saved := commandFixture(t, []float64{100, 180, 180, 180, 89})
	if code := execute(context.Background(), validArgs(t), deps, io.Discard, io.Discard); code != 0 {
		t.Fatalf("code = %d", code)
	}
	if got := findSavedEntry(t, *saved, expectedKey(t)).Measured.Confidence; got != "low" {
		t.Fatalf("confidence = %q, want low", got)
	}
}

// Exactly ten percent is still high: the boundary belongs to the confident side.
func TestExecuteKeepsTenPercentDriftHigh(t *testing.T) {
	deps, saved := commandFixture(t, []float64{100, 180, 180, 180, 90})
	if code := execute(context.Background(), validArgs(t), deps, io.Discard, io.Discard); code != 0 {
		t.Fatalf("code = %d", code)
	}
	if got := findSavedEntry(t, *saved, expectedKey(t)).Measured.Confidence; got != "high" {
		t.Fatalf("confidence = %q, want high", got)
	}
}

func TestExecuteSavesBestSoFarOnSIGINT(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	deps, saved := interruptingCommandFixture(t, cancel)
	if code := execute(ctx, validArgs(t), deps, io.Discard, io.Discard); code != 130 {
		t.Fatalf("code = %d", code)
	}
	entry := findSavedEntry(t, *saved, expectedKey(t))
	if got := entry.Measured.Confidence; got != "partial" {
		t.Fatalf("confidence = %q, want partial", got)
	}
	// A partial result has no confirmation, so it must not carry a winner rate.
	if entry.Measured.OpsPerSec != 0 {
		t.Fatalf("interrupted sweep invented a confirmed rate of %v", entry.Measured.OpsPerSec)
	}
	if entry.Measured.BaselineOpsPerSec != 100 {
		t.Fatalf("baseline = %v, want the measured opening baseline", entry.Measured.BaselineOpsPerSec)
	}
}

func TestExecuteDoesNotOverwriteMalformedExistingTuning(t *testing.T) {
	deps := defaultCommandFixture(t)
	deps.load = func(string) (tuning.File, error) { return tuning.File{}, errors.New("bad yaml") }
	deps.save = func(string, tuning.File) error { t.Fatal("save called after malformed load"); return nil }
	if code := execute(context.Background(), validArgs(t), deps, io.Discard, io.Discard); code == 0 {
		t.Fatal("execute() succeeded with malformed existing tuning")
	}
}

// An absent tuning file is not a malformed one: the first sweep on a host must
// create it.
func TestExecuteCreatesAnAbsentTuningFile(t *testing.T) {
	deps, saved := commandFixture(t, []float64{100, 180, 180, 180, 100})
	deps.load = func(string) (tuning.File, error) {
		return tuning.File{}, &os.PathError{Op: "open", Path: "tuning", Err: os.ErrNotExist}
	}
	if code := execute(context.Background(), validArgs(t), deps, io.Discard, io.Discard); code != 0 {
		t.Fatalf("code = %d", code)
	}
	if saved.Version != tuning.Version || len(saved.Tunings) != 1 {
		t.Fatalf("saved = %+v", *saved)
	}
}

func TestExecuteRejectsForcedTreeBelowTenSecondFloor(t *testing.T) {
	deps, prov := forcedTreeFixture(t, 500, 100) // 500 files at 100 ops/sec = 5 seconds.
	var errOut strings.Builder
	if code := execute(context.Background(), forcedArgs(t), deps, io.Discard, &errOut); code == 0 {
		t.Fatal("execute() accepted startup-noise-sized forced tree")
	}
	if !strings.Contains(errOut.String(), "measured 500 files") || !strings.Contains(errOut.String(), "requires 1000") {
		t.Fatalf("stderr = %q", errOut.String())
	}
	if prov.removes != 0 || len(prov.generated) != 0 {
		t.Fatalf("forced tree was provisioned or removed: generated=%v removals=%d", prov.generated, prov.removes)
	}
}

func TestExecuteGrowsAnAutomaticallySizedTreeOnceAndPersistsTheFreshBaseline(t *testing.T) {
	// Calibration sizes 30 copies. The first full-tree baseline resizes the
	// 30-second target to 180 copies, and the second proves it is long enough.
	deps, saved, prov, baseline := generatedTreeFixture(t, []float64{1000, 6000, 5500, 5000})
	var out strings.Builder
	if code := execute(context.Background(), regenerateArgs(t), deps, &out, io.Discard); code != 0 {
		t.Fatalf("execute() = %d; output = %q", code, out.String())
	}
	if diff := cmpInts(prov.generated, []int{4, 30, 199}); diff != "" {
		t.Fatal(diff)
	}
	if prov.removes != 2 {
		t.Fatalf("removals = %d, want probe and growth removals", prov.removes)
	}
	entry := findSavedEntry(t, *saved, expectedKey(t))
	if entry.Measured.BaselineOpsPerSec != 5500 || entry.Measured.TrialFiles != 199_000 {
		t.Fatalf("measurement = %+v, want the rebuilt tree and its baseline", entry.Measured)
	}
	if len(baseline.expectedHistory) < 3 {
		t.Fatalf("baseline expected-path history = %v, want calibration and both full-tree baselines", baseline.expectedHistory)
	}
	if got := baseline.expectedHistory[2]; got != 199_000 {
		t.Fatalf("rebuilt-tree baseline expected paths = %d, want 199000 before that trial starts", got)
	}
	if !strings.Contains(out.String(), "Growing the trial tree from 30 to 199 copies") {
		t.Fatalf("output = %q, want the pre-growth and replacement copy counts", out.String())
	}
	if !strings.Contains(out.String(), "opening 5500, closing 5000") {
		t.Fatalf("output = %q, want drift computed from the post-growth opening baseline", out.String())
	}
}

func TestExecuteDoesNotGrowAnExplicitCopyCountBelowTheFloor(t *testing.T) {
	deps, _, prov, _ := generatedTreeFixture(t, []float64{1000, 6000})
	deps.save = func(string, tuning.File) error {
		t.Fatal("save called for an explicit tree below the floor")
		return nil
	}
	args := append(regenerateArgs(t), "--copies", "30")
	var errOut strings.Builder
	if code := execute(context.Background(), args, deps, io.Discard, &errOut); code == 0 {
		t.Fatal("execute() accepted an explicit tree below the floor")
	}
	if diff := cmpInts(prov.generated, []int{4, 30}); diff != "" {
		t.Fatal(diff)
	}
	if prov.removes != 1 {
		t.Fatalf("removals = %d, want the probe removal only", prov.removes)
	}
	if !strings.Contains(errOut.String(), "requires 60000") {
		t.Fatalf("stderr = %q, want the existing floor refusal", errOut.String())
	}
}

func TestExecuteNamesTheScratchRootWhenGrowthTeardownIsInterrupted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	deps, _, _, _ := generatedTreeFixture(t, []float64{1000, 6000})
	originalNew := deps.newProvisioner
	deps.newProvisioner = func(localRoot, trialRoot string, base treegen.Config) ScratchProvisioner {
		p := originalNew(localRoot, trialRoot, base).(*fakeProvisioner)
		p.cancelOnRemove = 2 // probe removal is first; growth teardown is second.
		p.cancel = cancel
		return p
	}
	deps.save = func(string, tuning.File) error {
		t.Fatal("save called after growth teardown interruption")
		return nil
	}
	var errOut strings.Builder
	if code := execute(ctx, regenerateArgs(t), deps, io.Discard, &errOut); code != 130 {
		t.Fatalf("code = %d, want 130; stderr = %q", code, errOut.String())
	}
	want := "the tree at " + fixtureServerPath + " may be partial or markerless"
	if !strings.Contains(errOut.String(), want) {
		t.Fatalf("stderr = %q, want %q", errOut.String(), want)
	}
}

func TestExecuteReportsRegenerationAdviceWhenGrowthIsInterrupted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	deps, _, _, _ := generatedTreeFixture(t, []float64{1000, 6000})
	provCancel := false
	// The fake provisioner has no filesystem removal seam, so cancel on the third
	// generation call: after the old tree is removed and growth provision begins.
	originalNew := deps.newProvisioner
	deps.newProvisioner = func(localRoot, trialRoot string, base treegen.Config) ScratchProvisioner {
		p := originalNew(localRoot, trialRoot, base).(*fakeProvisioner)
		p.cancelOnGenerate = 3
		p.cancel = func() {
			provCancel = true
			cancel()
		}
		return p
	}
	deps.save = func(string, tuning.File) error {
		t.Fatal("save called after growth interruption")
		return nil
	}
	var errOut strings.Builder
	if code := execute(ctx, regenerateArgs(t), deps, io.Discard, &errOut); code != 130 {
		t.Fatalf("code = %d, want 130; stderr = %q", code, errOut.String())
	}
	if !provCancel {
		t.Fatal("fixture did not interrupt growth generation")
	}
	if !strings.Contains(errOut.String(), "--regenerate-scratch") || !strings.Contains(errOut.String(), "partial or markerless") {
		t.Fatalf("stderr = %q, want partial-tree regeneration advice", errOut.String())
	}
}

func TestExecuteStopsAfterOneGrowthRoundWhenTheRebuiltTreeIsStillTooSmall(t *testing.T) {
	deps, _, prov, _ := generatedTreeFixture(t, []float64{1000, 6000, 21_000})
	deps.save = func(string, tuning.File) error {
		t.Fatal("save called for a tree still below the floor")
		return nil
	}
	var errOut strings.Builder
	if code := execute(context.Background(), regenerateArgs(t), deps, io.Discard, &errOut); code == 0 {
		t.Fatal("execute() accepted a rebuilt tree still below the floor")
	}
	if diff := cmpInts(prov.generated, []int{4, 30, 199}); diff != "" {
		t.Fatal(diff)
	}
	if prov.removes != 2 {
		t.Fatalf("removals = %d, want no second growth rebuild", prov.removes)
	}
	if !strings.Contains(errOut.String(), "requires 210000") {
		t.Fatalf("stderr = %q, want the existing floor refusal after one growth", errOut.String())
	}
}

func TestExecuteRefusesRatherThanRebuildWhenMaxTrialFilesPreventsGrowth(t *testing.T) {
	deps, _, prov, _ := generatedTreeFixture(t, []float64{1000, 3000})
	deps.save = func(string, tuning.File) error {
		t.Fatal("save called for a ceiling-limited tree below the floor")
		return nil
	}
	var out, errOut strings.Builder
	args := append(regenerateArgs(t), "--max-trial-files", "20000")
	if code := execute(context.Background(), args, deps, &out, &errOut); code == 0 {
		t.Fatal("execute() accepted a ceiling-limited tree below the floor")
	}
	if diff := cmpInts(prov.generated, []int{4, 20}); diff != "" {
		t.Fatal(diff)
	}
	if prov.removes != 1 {
		t.Fatalf("removals = %d, want only the probe teardown", prov.removes)
	}
	if !strings.Contains(out.String(), "--max-trial-files 20000 ceiling prevents growth beyond the existing 20 copies") {
		t.Fatalf("output = %q, want the ceiling named as the growth blocker", out.String())
	}
	if !strings.Contains(errOut.String(), "requires 30000") {
		t.Fatalf("stderr = %q, want the existing below-floor refusal", errOut.String())
	}
}

// The regression test for the assumption this plan removes: a userspace sweep over a
// reused tree named by --scratch-server-path, with a backend that needs no local mount,
// must start with no mount present and without opening /proc/mounts.
func TestExecuteRunsWithNoLocalMountWhenBackendDoesNotNeedOne(t *testing.T) {
	deps, saved := commandFixture(t, []float64{100, 180, 180, 180, 100})
	deps.newProvisioner = func(_, trialRoot string, base treegen.Config) ScratchProvisioner {
		return &fakeProvisioner{t: t, noLocalMount: true,
			existing: manifestFor(base.Scale, 12_345), failOnGenerate: true}
	}
	deps.openMounts = func() (io.ReadCloser, error) { t.Fatal("/proc/mounts opened"); return nil, nil }
	args := serverPathArgs(t) // --scratch-server-path set, --scratch absent
	if code := execute(context.Background(), args, deps, io.Discard, io.Discard); code != 0 {
		t.Fatalf("code = %d", code)
	}
	if got := findSavedEntry(t, *saved, expectedKey(t)).Params.Connections; got == 0 {
		t.Fatal("no entry saved for the mountless run")
	}
}

func TestExecuteCleansScratchBeforeProvisionerConstruction(t *testing.T) {
	deps := defaultCommandFixture(t)
	deps.newProvisioner = func(localRoot, _ string, base treegen.Config) ScratchProvisioner {
		if localRoot != fixtureLocalScratch {
			t.Fatalf("provisioner local root = %q, want cleaned %q", localRoot, fixtureLocalScratch)
		}
		return &fakeProvisioner{t: t, existing: manifestFor(base.Scale, fixtureTrialFiles), failOnGenerate: true}
	}
	args := validArgs(t)
	for i, arg := range args {
		if arg == "--scratch" {
			args[i+1] += "/"
			break
		}
	}
	if code := execute(context.Background(), args, deps, io.Discard, io.Discard); code != 0 {
		t.Fatalf("execute() = %d", code)
	}
}

func TestResolveRootsCleansScratchBeforeProvisioning(t *testing.T) {
	deps := defaultCommandFixture(t)
	roots, err := resolveRoots(deps, rootRequest{
		scratch: fixtureLocalScratch + "/", server: fixtureServer, export: fixtureExport,
		transport: "userspace", needLocal: true, needsMount: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if roots.localRoot != fixtureLocalScratch || roots.trialRoot != fixtureServerPath {
		t.Fatalf("roots = %+v, want cleaned local and server paths", roots)
	}
}

func TestExecuteRefusesMissingLocalPathAndNamesTheConsumer(t *testing.T) {
	deps := defaultCommandFixture(t) // POSIX backend: NeedsLocalMount() == true
	var errOut strings.Builder
	if code := execute(context.Background(), serverPathArgs(t), deps, io.Discard, &errOut); code == 0 {
		t.Fatal("execute() accepted a POSIX generation backend with no local path")
	}
	if !strings.Contains(errOut.String(), "--scratch") || !strings.Contains(errOut.String(), "generation") {
		t.Fatalf("stderr = %q, want both the flag and the consumer named", errOut.String())
	}
}

func TestExecuteRejectsBadInvocations(t *testing.T) {
	cases := []struct {
		name string
		want string
		edit func(specPath, principals string) []string
	}{
		// The substring is the guard's own wording, not just the word "transport",
		// which every later validation failure would also print.
		{"unknown transport", "unknown --transport", func(s, p string) []string {
			return []string{"--transport", "kernell", "--scratch", fixtureLocalScratch, "--spec", s, "--principals", p}
		}},
		{"no spec", "--spec", func(s, p string) []string {
			return []string{"--scratch", fixtureLocalScratch, "--principals", p}
		}},
		{"no principals", "--principals", func(s, p string) []string {
			return []string{"--scratch", fixtureLocalScratch, "--spec", s}
		}},
		{"no scratch at all", "--scratch-server-path", func(s, p string) []string {
			return []string{"--spec", s, "--principals", p}
		}},
		{"userspace without a server", "--server", func(s, p string) []string {
			return []string{"--transport", "userspace", "--export", fixtureExport,
				"--scratch-server-path", fixtureServerPath, "--spec", s, "--principals", p}
		}},
		{"trial duration below the floor", "10s", func(s, p string) []string {
			return []string{"--trial-duration", "3s", "--scratch", fixtureLocalScratch, "--spec", s, "--principals", p}
		}},
		{"nonpositive tree workers", "--tree-workers", func(s, p string) []string {
			return []string{"--tree-workers", "0", "--scratch", fixtureLocalScratch, "--spec", s, "--principals", p}
		}},
		{"scratch is the mount point", "mount point", func(s, p string) []string {
			return []string{"--scratch", fixtureMountPoint, "--spec", s, "--principals", p}
		}},
		{"scratch is the export root", "export root", func(s, p string) []string {
			return []string{"--transport", "userspace", "--server", fixtureServer, "--export", fixtureExport,
				"--scratch-server-path", fixtureExport, "--spec", s, "--principals", p}
		}},
		{"disagreeing scratch paths", "/export/elsewhere", func(s, p string) []string {
			return []string{"--transport", "userspace", "--server", fixtureServer, "--export", fixtureExport,
				"--scratch", fixtureLocalScratch, "--scratch-server-path", "/export/elsewhere",
				"--spec", s, "--principals", p}
		}},
		// Zero is the ambiguous value, not the invalid one: the transport reads it as
		// "use my default". Negatives are nfs41's to reject.
		{"zero rpc timeout", "30s default", func(s, p string) []string {
			return []string{"--rpc-timeout", "0", "--scratch", fixtureLocalScratch, "--spec", s, "--principals", p}
		}},
		{"zero retry base delay", "--retry-base-delay", func(s, p string) []string {
			return []string{"--retry-base-delay", "0", "--scratch", fixtureLocalScratch, "--spec", s, "--principals", p}
		}},
		{"reuse and regenerate together", "--regenerate-scratch", func(s, p string) []string {
			return []string{"--reuse-scratch", "--regenerate-scratch", "--scratch", fixtureLocalScratch,
				"--spec", s, "--principals", p}
		}},
		{"reuse false without regenerate", "--reuse-scratch=false requires --regenerate-scratch", func(s, p string) []string {
			return []string{"--reuse-scratch=false", "--scratch", fixtureLocalScratch,
				"--spec", s, "--principals", p}
		}},
		{"force and regenerate together", "--force and --regenerate-scratch", func(s, p string) []string {
			return []string{"--force", "--regenerate-scratch", "--scratch", fixtureLocalScratch,
				"--spec", s, "--principals", p}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var saved tuning.File
			deps := fixtureDeps(t, &saved,
				&scriptedRunner{t: t, name: "baseline", forbid: true},
				&scriptedRunner{t: t, name: "search", forbid: true})
			deps.save = func(string, tuning.File) error { t.Fatal("save called for a rejected invocation"); return nil }
			specPath, principals := specAndPrincipals(t)
			var errOut strings.Builder
			if code := execute(context.Background(), tc.edit(specPath, principals), deps, io.Discard, &errOut); code == 0 {
				t.Fatalf("execute() accepted %s", tc.name)
			}
			if !strings.Contains(errOut.String(), tc.want) {
				t.Fatalf("stderr = %q, want mention of %q", errOut.String(), tc.want)
			}
		})
	}
}

// --pfind must not exist: an external enumerator cannot be fused with the fix,
// so a sweep of it would measure a path no repair takes.
func TestExecuteHasNoPfindFlag(t *testing.T) {
	var saved tuning.File
	deps := fixtureDeps(t, &saved,
		&scriptedRunner{t: t, name: "baseline", forbid: true},
		&scriptedRunner{t: t, name: "search", forbid: true})
	deps.save = func(string, tuning.File) error { t.Fatal("save called"); return nil }
	args := append(validArgs(t), "--pfind")
	if code := execute(context.Background(), args, deps, io.Discard, io.Discard); code == 0 {
		t.Fatal("--pfind was accepted")
	}
}

// An ordinary search failure leaves the operator's tuning file exactly as it was.
func TestExecuteLeavesTuningUnchangedOnSearchFailure(t *testing.T) {
	var saved tuning.File
	deps := fixtureDeps(t, &saved,
		&scriptedRunner{t: t, name: "baseline", queue: []float64{100}},
		&failingRunner{err: errors.New("every trial failed")})
	deps.save = func(string, tuning.File) error { t.Fatal("save called after a failed search"); return nil }
	if code := execute(context.Background(), validArgs(t), deps, io.Discard, io.Discard); code == 0 {
		t.Fatal("execute() succeeded with a failed search")
	}
}

type failingRunner struct{ err error }

func (f *failingRunner) Trial(context.Context, tuning.Params) (float64, error) { return 0, f.err }

// Every trial must run the real repair over the tree addressed the way its own
// transport addresses it. The five tuning fields are mapped inside the runner and
// are pinned in TestRunTrialMapsEveryTunedFieldAndForcesTheRealRepairPath; what is
// pinned here is the configuration execute hands that runner.
func TestExecuteConfiguresEveryRunnerForTheRealRepairPath(t *testing.T) {
	t.Run("userspace addresses the tree by its server-side path", func(t *testing.T) {
		deps, baseline, trials := configuredFixture(t, []float64{100, 180, 180, 180, 100})
		if code := execute(context.Background(), validArgs(t), deps, io.Discard, io.Discard); code != 0 {
			t.Fatalf("code = %d", code)
		}
		for _, r := range []*scriptedRunner{baseline, trials} {
			if !r.configured {
				t.Fatalf("%s runner was never built with a config", r.name)
			}
			if r.cfg.Root != fixtureServerPath {
				t.Fatalf("%s root = %q, want the server-side path %q", r.name, r.cfg.Root, fixtureServerPath)
			}
			if r.cfg.Server != fixtureServer || r.cfg.Export != fixtureExport {
				t.Fatalf("%s config lost the userspace target: %+v", r.name, r.cfg)
			}
			if r.cfg.Transport != "userspace" || !r.cfg.Quiet {
				t.Fatalf("%s config = %+v, want the userspace transport run quietly", r.name, r.cfg)
			}
			if r.cfg.Spec == nil {
				t.Fatalf("%s config carries no parsed spec, so every trial would reparse or fail", r.name)
			}
			if r.cfg.Pfind || r.cfg.Compare || r.cfg.DryRun || r.cfg.Validate {
				t.Fatalf("%s config = %+v, want none of the modes that skip real work", r.name, r.cfg)
			}
		}
		for _, r := range []*scriptedRunner{baseline, trials} {
			if r.expectedPaths != fixtureTrialFiles {
				t.Fatalf("%s expected paths = %d, want prepared count %d", r.name, r.expectedPaths, fixtureTrialFiles)
			}
		}
		// One spec, loaded once, shared by every trial: reloading it per trial would
		// charge parse time to some trials and not others.
		if baseline.cfg.Spec != trials.cfg.Spec {
			t.Fatal("the two runners were given different spec pointers")
		}
	})

	t.Run("kernel addresses the tree by its local mount path", func(t *testing.T) {
		deps, baseline, trials := configuredFixture(t, []float64{100, 180, 180, 180, 100})
		if code := execute(context.Background(), kernelArgs(t), deps, io.Discard, io.Discard); code != 0 {
			t.Fatalf("code = %d", code)
		}
		for _, r := range []*scriptedRunner{baseline, trials} {
			if r.cfg.Root != fixtureLocalScratch {
				t.Fatalf("%s root = %q, want the local path %q -- the kernel transport cannot use a server-side path",
					r.name, r.cfg.Root, fixtureLocalScratch)
			}
			if r.cfg.Server != "" || r.cfg.Export != "" {
				t.Fatalf("%s config = %+v, want no userspace target on the kernel transport", r.name, r.cfg)
			}
			if r.cfg.Spec == nil {
				t.Fatalf("%s config carries no parsed spec", r.name)
			}
		}
	})
}

// An interrupt that arrives before any trial produced a rate has measured
// nothing. result.Best is still the untested stock baseline, and writing it would
// hand the repair binary a tuning no run ever observed.
func TestExecuteSavesNothingWhenInterruptedBeforeAnyTrialSucceeds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var saved tuning.File
	baseline := &scriptedRunner{t: t, name: "baseline", queue: []float64{100}}
	trials := &scriptedRunner{t: t, name: "search", repeat: 180,
		onCall: func(n int) {
			if n == 1 {
				cancel()
			}
		}}
	deps := fixtureDeps(t, &saved, baseline, trials)
	deps.save = func(string, tuning.File) error {
		t.Fatal("saved a tuning that nothing measured")
		return nil
	}
	var errOut strings.Builder
	if code := execute(ctx, validArgs(t), deps, io.Discard, &errOut); code != 130 {
		t.Fatalf("code = %d, want 130", code)
	}
	if !strings.Contains(errOut.String(), "nothing was measured") {
		t.Fatalf("stderr = %q, want it to say nothing was measured", errOut.String())
	}
}

// interruptingProvisioner cancels the sweep from inside generation, which is
// where a real Ctrl-C most often lands: preparation is the longest phase of a
// regenerating sweep.
//
// err is what generation reports afterwards, and both shapes are real.
// treegen's seed phase returns ctx.Err() wrapped, while its fan-out+stamp phase
// stops its workers and returns success over a truncated tree. A caller that
// tests only the returned error sees the first and misses the second.
type interruptingProvisioner struct {
	cancel context.CancelFunc
	// cancelOn is the generation call that cancels: 1 is the four-copy probe,
	// 2 the full tree. err is what that call reports afterwards.
	cancelOn  int
	err       error
	generated int
	lastScale treegen.Scale
}

const interruptingPathsPerCopy = 1000

func (p *interruptingProvisioner) generate(shape treegen.Config) error {
	p.generated++
	p.lastScale = shape.Scale
	if p.generated != p.cancelOn {
		return nil
	}
	if p.cancel != nil {
		p.cancel()
	}
	return p.err
}

func (p *interruptingProvisioner) Probe(_ context.Context, shape treegen.Config) error {
	return p.generate(shape)
}

func (p *interruptingProvisioner) Provision(_ context.Context, shape treegen.Config) error {
	return p.generate(shape)
}

func (p *interruptingProvisioner) Inspect(context.Context) (treegen.Manifest, bool, error) {
	if p.generated == 0 {
		return treegen.Manifest{}, false, nil
	}
	m := manifestFor(p.lastScale, int64(p.lastScale.Copies)*interruptingPathsPerCopy)
	m.GeneratedTarget = fixtureLocalScratch
	return m, true, nil
}

func (p *interruptingProvisioner) EnumerateCount(context.Context) (int64, error) { return 0, nil }
func (p *interruptingProvisioner) Remove(context.Context) error                  { return nil }
func (p *interruptingProvisioner) NeedsLocalMount() bool                         { return true }

// regenerateArgs is the invocation that builds a tree, which reuse (the
// default) never does.
func regenerateArgs(t *testing.T) []string {
	t.Helper()
	return append(validArgs(t), "--regenerate-scratch")
}

// An interrupt during preparation must end exactly the way an interrupt during
// the search does: nothing measured, tuning file untouched, exit 130. Before
// this, cancellation fell out of prepareScratch onto the ordinary failure path
// and told the operator "error: probe generation: seed build: context canceled"
// with exit 1 — blaming their array or their flags for their own Ctrl-C, and
// saying nothing about the tuning file.
func TestExecuteSavesNothingWhenInterruptedDuringPreparation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cancelOn int
		err      error
		// baselineRates is what the stock runner may serve before the interrupt.
		// The probe case never reaches calibration; the full-tree case does.
		baselineRates []float64
	}{
		// The seed phase's shape: cancellation is reported as an error.
		{name: "generation reports the cancellation", cancelOn: 1,
			err: fmt.Errorf("seed build: %w", context.Canceled)},
		// The fan-out+stamp phase's shape: workers stop, a manifest is written for
		// the truncated tree, and generation returns success. This is the case that
		// errors.Is(err, context.Canceled) alone cannot see.
		{name: "generation reports success over a truncated tree", cancelOn: 2,
			baselineRates: []float64{interruptingPathsPerCopy}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var saved tuning.File
			baseline := &scriptedRunner{t: t, name: "baseline", queue: tc.baselineRates,
				forbid: len(tc.baselineRates) == 0}
			trials := &scriptedRunner{t: t, name: "search", forbid: true}
			deps := fixtureDeps(t, &saved, baseline, trials)
			deps.newProvisioner = func(string, string, treegen.Config) ScratchProvisioner {
				return &interruptingProvisioner{cancel: cancel, cancelOn: tc.cancelOn, err: tc.err}
			}
			deps.save = func(string, tuning.File) error {
				t.Fatal("saved a tuning after an interrupt that measured nothing")
				return nil
			}
			var errOut strings.Builder
			if code := execute(ctx, regenerateArgs(t), deps, io.Discard, &errOut); code != 130 {
				t.Fatalf("code = %d, want 130; stderr = %q", code, errOut.String())
			}
			if !strings.Contains(errOut.String(), "nothing was measured") {
				t.Fatalf("stderr = %q, want it to say nothing was measured", errOut.String())
			}
			if !strings.Contains(errOut.String(), "is unchanged") {
				t.Fatalf("stderr = %q, want it to say the tuning file is unchanged", errOut.String())
			}
			// This run generated, so the partial-tree warning belongs here. Its
			// counterpart, TestExecuteDoesNotTellAReuseRunToRegenerateTheTree, asserts
			// the same advice is absent on the path that creates nothing.
			if !strings.Contains(errOut.String(), "--regenerate-scratch") {
				t.Fatalf("stderr = %q, want the generating run told to regenerate its partial tree", errOut.String())
			}
		})
	}
}

// interruptingReuseProvisioner cancels while the tree is being adopted rather
// than generated. Reuse is the default invocation, and it creates nothing, so
// this is the shape that must not be told to regenerate the directory.
type interruptingReuseProvisioner struct {
	cancel context.CancelFunc
}

func (p *interruptingReuseProvisioner) Probe(context.Context, treegen.Config) error {
	panic("reuse must not generate")
}

func (p *interruptingReuseProvisioner) Provision(context.Context, treegen.Config) error {
	panic("reuse must not generate")
}

func (p *interruptingReuseProvisioner) Inspect(context.Context) (treegen.Manifest, bool, error) {
	p.cancel()
	return treegen.Manifest{}, false, context.Canceled
}

func (p *interruptingReuseProvisioner) EnumerateCount(context.Context) (int64, error) { return 0, nil }
func (p *interruptingReuseProvisioner) Remove(context.Context) error                  { return nil }
func (p *interruptingReuseProvisioner) NeedsLocalMount() bool                         { return true }

// The advice to regenerate the scratch directory is only true of a run that was
// generating. Reuse -- the default -- adopts a tree this invocation did not
// create, and a --force reuse legally carries no --principals, so the tree may
// be a colleague's and unrecreatable by this tool. Printing that advice there
// tells the operator to destroy someone else's data on the tool's own
// instruction.
func TestExecuteDoesNotTellAReuseRunToRegenerateTheTree(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var saved tuning.File
	baseline := &scriptedRunner{t: t, name: "baseline", forbid: true}
	trials := &scriptedRunner{t: t, name: "search", forbid: true}
	deps := fixtureDeps(t, &saved, baseline, trials)
	deps.newProvisioner = func(string, string, treegen.Config) ScratchProvisioner {
		return &interruptingReuseProvisioner{cancel: cancel}
	}
	deps.save = func(string, tuning.File) error {
		t.Fatal("saved a tuning after an interrupt that measured nothing")
		return nil
	}
	var errOut strings.Builder
	// validArgs is the default invocation, and --reuse-scratch defaults to true.
	if code := execute(ctx, validArgs(t), deps, io.Discard, &errOut); code != 130 {
		t.Fatalf("code = %d, want 130; stderr = %q", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "nothing was measured") {
		t.Fatalf("stderr = %q, want it to say nothing was measured", errOut.String())
	}
	if strings.Contains(errOut.String(), "--regenerate-scratch") {
		t.Fatalf("stderr = %q, want no instruction to regenerate a tree this run never created", errOut.String())
	}
}

// A timeout is not an interrupt. Both switch arms test ctx, and an expired
// deadline satisfies the cancellation arm's condition too, so only the order of
// the arms keeps a timeout from being reported as the operator's own Ctrl-C.
// The context here is genuinely past its deadline: with a live context the
// swapped order passes and the ordering goes unpinned.
func TestExecuteReportsAPreparationDeadlineAsAFailure(t *testing.T) {
	for _, tc := range []struct {
		name          string
		cancelOn      int
		err           error
		baselineRates []float64
	}{
		// Generation reports the deadline, the way treegen's seed phase reports a
		// cancellation.
		{name: "generation reports the deadline", cancelOn: 1,
			err: fmt.Errorf("probe generation: %w", context.DeadlineExceeded)},
		// Generation reports success over a truncated tree. Only ctx carries the
		// deadline, so this is the case the returned error alone cannot see.
		{name: "generation reports success", cancelOn: 2,
			baselineRates: []float64{interruptingPathsPerCopy}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			defer cancel()
			var saved tuning.File
			baseline := &scriptedRunner{t: t, name: "baseline", queue: tc.baselineRates,
				forbid: len(tc.baselineRates) == 0}
			trials := &scriptedRunner{t: t, name: "search", forbid: true}
			deps := fixtureDeps(t, &saved, baseline, trials)
			deps.newProvisioner = func(string, string, treegen.Config) ScratchProvisioner {
				return &interruptingProvisioner{cancelOn: tc.cancelOn, err: tc.err}
			}
			deps.save = func(string, tuning.File) error {
				t.Fatal("saved a tuning after a failed preparation")
				return nil
			}
			var errOut strings.Builder
			if code := execute(ctx, regenerateArgs(t), deps, io.Discard, &errOut); code != 1 {
				t.Fatalf("code = %d, want 1; stderr = %q", code, errOut.String())
			}
			if strings.Contains(errOut.String(), "interrupted") {
				t.Fatalf("stderr = %q, want a timeout not to be reported as an interrupt", errOut.String())
			}
			if !strings.Contains(errOut.String(), "ran out of time") {
				t.Fatalf("stderr = %q, want the timeout named as such", errOut.String())
			}
		})
	}
}

// A sweep is hours long, so points are reported as they are measured. Reporting
// them after the search returns leaves an operator with no output at all until
// the run is over.
func TestExecuteReportsEachPointAsItIsMeasured(t *testing.T) {
	var out strings.Builder
	var saved tuning.File
	var seenByThirdTrial string
	baseline := &scriptedRunner{t: t, name: "baseline", queue: []float64{100, 100}}
	trials := &scriptedRunner{t: t, name: "search", repeat: 180,
		onCall: func(n int) {
			if n == 3 {
				seenByThirdTrial = out.String()
			}
		}}
	deps := fixtureDeps(t, &saved, baseline, trials)
	if code := execute(context.Background(), validArgs(t), deps, &out, io.Discard); code != 0 {
		t.Fatalf("code = %d", code)
	}
	if !strings.Contains(seenByThirdTrial, "connections=1 180 paths/s") ||
		!strings.Contains(seenByThirdTrial, "connections=2 180 paths/s") {
		t.Fatalf("output before the third trial = %q, want the first two points already reported", seenByThirdTrial)
	}
}

// Every userspace-only field, not just connections, must be absent from a kernel
// entry: the kernel search sweeps none of their ladders.
func TestExecuteZeroesEveryUserspaceOnlyFieldInAKernelEntry(t *testing.T) {
	deps, saved := commandFixture(t, []float64{100, 180, 180, 180, 100})
	if code := execute(context.Background(), kernelArgs(t), deps, io.Discard, io.Discard); code != 0 {
		t.Fatalf("code = %d", code)
	}
	entry := findSavedEntry(t, *saved, expectedKernelKey(t))
	if entry.Params.Connections != 0 || entry.Params.Slots != 0 || entry.Params.MaxOpsPerCompound != 0 {
		t.Fatalf("kernel entry records userspace-only values nothing measured: %+v", entry.Params)
	}
	if entry.Params.Workers == 0 || entry.Params.BatchSize == 0 {
		t.Fatalf("kernel entry lost its measured params: %+v", entry.Params)
	}
}

// What the sweeper prints as the winner must be what it writes to the tuning
// file. That line is an operator's only cross-check that the persisted entry
// belongs to the run they just watched, so it is built from the same entry that
// is saved and is compared against the saved entry here.
func TestExecutePrintsTheWinnerItPersists(t *testing.T) {
	cases := []struct {
		name string
		args func(*testing.T) []string
		key  func(*testing.T) tuning.Key
	}{
		{"userspace", validArgs, expectedKey},
		// The kernel case is the one that can drift: the entry's userspace-only
		// fields are zeroed on the way to disk, and a printed line built from
		// anything but that entry would still show the baseline values.
		{"kernel", kernelArgs, expectedKernelKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps, saved := commandFixture(t, []float64{100, 180, 180, 180, 100})
			var out strings.Builder
			if code := execute(context.Background(), tc.args(t), deps, &out, io.Discard); code != 0 {
				t.Fatalf("code = %d", code)
			}
			entry := findSavedEntry(t, *saved, tc.key(t))
			want := fmt.Sprintf("winner: connections=%d slots=%d workers=%d batch-size=%d max-ops-per-compound=%d at %.0f paths/s",
				entry.Params.Connections, entry.Params.Slots, entry.Params.Workers,
				entry.Params.BatchSize, entry.Params.MaxOpsPerCompound, entry.Measured.OpsPerSec)
			if !strings.Contains(out.String(), want) {
				t.Fatalf("output = %q, want it to report the persisted winner %q", out.String(), want)
			}
		})
	}
}

// client_bound is the any-of summary of the per-client samples, so it must follow
// the sample rather than sit at its zero value.
func TestExecuteRecordsClientBoundFromTheWinnerSample(t *testing.T) {
	for _, bound := range []bool{false, true} {
		var saved tuning.File
		baseline := &scriptedRunner{t: t, name: "baseline", queue: []float64{100, 100}}
		trials := &boundRunner{rate: 180, bound: bound}
		deps := fixtureDeps(t, &saved, baseline, trials)
		if code := execute(context.Background(), validArgs(t), deps, io.Discard, io.Discard); code != 0 {
			t.Fatalf("code = %d", code)
		}
		entry := findSavedEntry(t, saved, expectedKey(t))
		if entry.Measured.ClientBound != bound {
			t.Fatalf("client_bound = %v, want %v from the sample", entry.Measured.ClientBound, bound)
		}
		if len(entry.Measured.PerClient) != 1 || entry.Measured.PerClient[0].Bound != bound {
			t.Fatalf("per-client = %+v, want one sample marked %v", entry.Measured.PerClient, bound)
		}
	}
}

// boundRunner answers at a fixed rate and reports a client sample whose bound
// flag the test chooses.
type boundRunner struct {
	rate  float64
	bound bool
}

func (b *boundRunner) Trial(context.Context, tuning.Params) (float64, error) { return b.rate, nil }

func (b *boundRunner) LastMeasurement() (tuning.ClientMeasurement, bool) {
	return tuning.ClientMeasurement{CPUPct: 95, RlimitNofile: 1024, Bound: b.bound}, true
}

// --force and the kernel transport each need a local path of their own, whatever
// the generation backend needs, and the refusal has to name which one.
func TestExecuteRefusesMissingLocalPathForEachConsumer(t *testing.T) {
	cases := []struct {
		name string
		want string
		args func(t *testing.T) []string
	}{
		{"--force counts entries locally", "--force", func(t *testing.T) []string {
			return append(serverPathArgs(t), "--force")
		}},
		{"the kernel transport has no server-side addressing", "kernel transport", func(t *testing.T) []string {
			specPath, principals := specAndPrincipals(t)
			return []string{"--transport", "kernel", "--scratch-server-path", fixtureServerPath,
				"--spec", specPath, "--principals", principals}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var saved tuning.File
			deps := fixtureDeps(t, &saved,
				&scriptedRunner{t: t, name: "baseline", forbid: true},
				&scriptedRunner{t: t, name: "search", forbid: true})
			// A backend that needs no local mount of its own, so the requirement can
			// only come from the flag or the transport under test.
			deps.newProvisioner = func(_, _ string, base treegen.Config) ScratchProvisioner {
				return &fakeProvisioner{t: t, noLocalMount: true,
					existing: manifestFor(base.Scale, fixtureTrialFiles), failOnGenerate: true}
			}
			deps.save = func(string, tuning.File) error { t.Fatal("save called for a rejected invocation"); return nil }
			var errOut strings.Builder
			if code := execute(context.Background(), tc.args(t), deps, io.Discard, &errOut); code == 0 {
				t.Fatalf("execute() accepted %s with no local path", tc.name)
			}
			if !strings.Contains(errOut.String(), "--scratch") || !strings.Contains(errOut.String(), tc.want) {
				t.Fatalf("stderr = %q, want the flag and %q named", errOut.String(), tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Platform gating
// ---------------------------------------------------------------------------

// The honest macOS answer. No provisioner sweep can build works without a
// mount, and macOS cannot mount a 4.1 export, so the command refuses at startup
// with a sentence that says what is missing -- rather than dying later in
// resolveRoots on a missing /proc/mounts, which names a Linux kernel path and
// tells the operator nothing about their command line.
func TestSweepRefusesWhenNoScratchBackendCanWorkHere(t *testing.T) {
	cmdflagstest.With(t, &caps, platform.Darwin())

	var out, errOut bytes.Buffer
	code := execute(t.Context(), append(serverPathArgs(t), "--reuse-scratch"),
		productionDeps(), &out, &errOut)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	got := errOut.String()
	if strings.Contains(got, "/proc/mounts") {
		t.Fatalf("error = %q; the operator must not meet /proc/mounts", got)
	}
	for _, want := range []string{"kernel NFSv4.1 mount", "darwin"} {
		if !strings.Contains(got, want) {
			t.Errorf("error = %q, want it to mention %q", got, want)
		}
	}
}

// The refusal is keyed on the provisioner, not on GOOS. Inject one that needs
// no mount and the command proceeds -- the case that must survive the arrival
// of a userspace provisioner.
func TestSweepProceedsWhenProvisionerNeedsNoMount(t *testing.T) {
	cmdflagstest.With(t, &caps, platform.Darwin())

	deps := productionDeps()
	deps.newProvisioner = func(_, _ string, _ treegen.Config) ScratchProvisioner {
		return &fakeProvisioner{t: t, noLocalMount: true}
	}

	var out, errOut bytes.Buffer
	code := execute(t.Context(), append(serverPathArgs(t), "--reuse-scratch"), deps, &out, &errOut)

	if got := errOut.String(); strings.Contains(got, "kernel NFSv4.1 mount") {
		t.Fatalf("the startup refusal fired for a mount-free provisioner: %q (exit %d)", got, code)
	}
}

// --transport is refused by VALUE, not by presence: userspace is the value that
// works here and the one docs/transports.md teaches.
func TestSweepRejectsKernelTransportByValue(t *testing.T) {
	cmdflagstest.With(t, &caps, platform.Darwin())

	var out, errOut bytes.Buffer
	code := execute(t.Context(), []string{"--transport", "kernel"}, productionDeps(), &out, &errOut)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	got := errOut.String()
	// The wording is internal/cmdflags', shared with permissionreset: it names the
	// missing capability and the value that works, never an operating system.
	for _, want := range []string{"--transport=kernel", "system.nfs4_acl", "--transport=userspace"} {
		if !strings.Contains(got, want) {
			t.Errorf("error = %q, want it to mention %q", got, want)
		}
	}
	if strings.Contains(got, "requires Linux") {
		t.Fatalf("error = %q; the refusal must name the capability, not an OS", got)
	}
}

// ...and --transport=userspace is accepted, which is the half the previous
// revision got wrong.
func TestSweepAcceptsUserspaceTransportOnDarwin(t *testing.T) {
	cmdflagstest.With(t, &caps, platform.Darwin())

	var out, errOut bytes.Buffer
	execute(t.Context(), []string{"--transport", "userspace", "-help"}, productionDeps(), &out, &errOut)
	if got := errOut.String(); strings.Contains(got, "unavailable on this build") {
		t.Fatalf("--transport=userspace was refused on darwin: %q", got)
	}
}

// The flag stays visible on darwin, because one of its values works there.
func TestSweepKeepsTransportFlagVisibleOnDarwin(t *testing.T) {
	cmdflagstest.With(t, &caps, platform.Darwin())

	var out, errOut bytes.Buffer
	if code := execute(t.Context(), []string{"-help"}, productionDeps(), &out, &errOut); code != 0 {
		t.Fatalf("-help exit code = %d, want 0", code)
	}
	if help := out.String() + errOut.String(); !strings.Contains(help, "-transport") {
		t.Error("-transport is hidden on darwin; --transport=userspace works there and must be discoverable")
	}
}

// Every flag this command registers is classified. Per-flag assertions naming
// -transport by hand cannot see a mount-dependent flag someone adds later, and
// on macOS the compiler will not catch it either.
func TestEverySweepFlagIsClassified(t *testing.T) {
	// portable: works identically on every platform this version ships.
	portable := map[string]bool{
		"scratch": true, "scratch-server-path": true, "server": true, "export": true,
		"spec": true, "principals": true, "scale": true, "copies": true,
		"seed-files": true, "max-depth": true, "tree-workers": true, "seed": true,
		"safety-principal": true, "files-per-subtree": true, "trial-duration": true,
		"max-generate-time": true, "max-trial-files": true, "reuse-scratch": true,
		"regenerate-scratch": true, "force": true, "rpc-timeout": true,
		"retry-budget": true, "retry-base-delay": true, "trial-log": true,
		"unsafe-allow-non-pure-server": true, "version": true,
		// The AUTH_SYS flags are ungated on purpose: they are how you present a
		// different identity on any platform, without sudo -u.
		"auth-uid": true, "auth-gid": true, "auth-gids": true, "auth-hostname": true,
		// transport is value-gated, not presence-gated: the flag is portable,
		// one of its values is not. TestSweepRejectsKernelTransportByValue
		// covers it.
		"transport": true,
	}
	// gated: refused outright where the capability is absent. sweep has none
	// today -- --pfind is deliberately never registered here.
	gated := map[string]bool{}

	fs, _ := registerSweepFlags(flag.NewFlagSet("classify", flag.ContinueOnError), io.Discard)
	fs.VisitAll(func(f *flag.Flag) {
		if portable[f.Name] == gated[f.Name] { // in neither, or in both
			t.Errorf("flag -%s is unclassified: add it to `portable` if it works on every "+
				"platform, or gate it and add it to `gated`. On macOS the compiler will not "+
				"catch a mount-dependent flag; this test is what does.", f.Name)
		}
	})

	// VisitAll above catches an UNCLASSIFIED flag, never a MISCLASSIFIED one:
	// a gated flag listed in `portable` passes it and still refuses on macOS.
	// Ask the gate what it actually refuses. Registration runs under absent
	// capabilities because Gate records a flag only when its capability is gone.
	cmdflagstest.With(t, &caps, platform.Darwin())

	_, f := registerSweepFlags(flag.NewFlagSet("gatecheck", flag.ContinueOnError), io.Discard)
	actual := map[string]bool{}
	for _, name := range f.gate.GatedNames() {
		actual[name] = true
		if !gated[name] {
			t.Errorf("flag -%s is gated by the Gate but listed as portable; a macOS operator "+
				"is refused a flag this test certified as working everywhere", name)
		}
	}
	for name := range gated {
		if !actual[name] {
			t.Errorf("flag -%s is listed in `gated` but the Gate does not refuse it; the "+
				"classification is documentation, not a constraint", name)
		}
	}
}

// sweep's trials are real repairs, so a userspace sweep needs the same
// credential control permissionreset has. Without this the flags exist on one binary
// and not the other, which is worse than not having them: the operator learns
// the flag from the docs and it silently is not there.
func TestSweepAcceptsTheAuthFlags(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := execute(t.Context(), []string{"-help"}, productionDeps(), &out, &errOut); code != 0 {
		t.Fatalf("-help exit code = %d, want 0", code)
	}
	help := out.String() + errOut.String()
	for _, want := range []string{"-auth-uid", "-auth-gid", "-auth-gids", "-auth-hostname"} {
		if !strings.Contains(help, want) {
			t.Errorf("%s missing from sweep --help", want)
		}
	}
}

// The credential reaches the trial config, not just the flag set. This reuses
// the existing configured-fixture path rather than inventing a second one.
func TestSweepPassesTheCredentialIntoTheTrialConfig(t *testing.T) {
	deps, baseline, trials := configuredFixture(t, []float64{100, 180, 180, 180, 100})
	args := append(validArgs(t), "--auth-uid", "10010", "--auth-gid", "10000",
		"--auth-gids", "10020,10021", "--auth-hostname", "lab-client")
	if code := execute(context.Background(), args, deps, io.Discard, io.Discard); code != 0 {
		t.Fatalf("code = %d", code)
	}
	for _, r := range []*scriptedRunner{baseline, trials} {
		if r.cfg.Auth == nil || r.cfg.Auth.UID != 10010 {
			t.Fatalf("%s trial config Auth = %+v, want the credential from --auth-uid 10010", r.name, r.cfg.Auth)
		}
		if r.cfg.Auth.GID != 10000 || r.cfg.Auth.Machine != "lab-client" {
			t.Fatalf("%s trial config Auth = %+v, want gid 10000 machine lab-client", r.name, r.cfg.Auth)
		}
		if len(r.cfg.Auth.AuxGIDs) != 2 {
			t.Fatalf("%s aux gids = %v, want two", r.name, r.cfg.Auth.AuxGIDs)
		}
	}
}

// The per-trial config must follow --transport, not the build platform. Both
// subtests run under Linux capabilities, where caps.KernelTransport is true, so
// a wiring that reads caps instead of the selected transport fails the
// userspace case.
func TestTrialLocalIdentityAuthoritativeFollowsTheSelectedTransport(t *testing.T) {
	for _, tc := range []struct {
		transport string
		args      func(*testing.T) []string
		want      bool
	}{
		{"kernel", kernelArgs, true},
		{"userspace", validArgs, false},
	} {
		t.Run(tc.transport, func(t *testing.T) {
			cmdflagstest.With(t, &caps, platform.Linux())

			deps, baseline, trials := configuredFixture(t, []float64{100, 180, 180, 180, 100})
			if code := execute(context.Background(), tc.args(t), deps, io.Discard, io.Discard); code != 0 {
				t.Fatalf("code = %d", code)
			}
			for _, r := range []*scriptedRunner{baseline, trials} {
				if !r.configured {
					t.Fatalf("%s runner was never built with a config", r.name)
				}
				if r.cfg.LocalIdentityAuthoritative != tc.want {
					t.Fatalf("%s LocalIdentityAuthoritative = %v with --transport=%s, want %v",
						r.name, r.cfg.LocalIdentityAuthoritative, tc.transport, tc.want)
				}
			}
		})
	}
}
