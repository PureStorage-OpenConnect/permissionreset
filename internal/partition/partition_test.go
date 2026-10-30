package partition

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/evidence"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/run"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/stats"
)

const testSpec = "protocol: posix\ndefault:\n  mode: \"0755\"\nexclude:\n  - .snapshot\n"

// writeManifest writes a spec and a manifest whose partitions block is parts
// (YAML list items), and returns the manifest path.
func writeManifest(t *testing.T, root, parts string, extra ...string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "spec.yaml"), []byte(testSpec), 0o644); err != nil {
		t.Fatal(err)
	}
	body := "version: 1\nroot: " + root + "\nspec: spec.yaml\nstate_dir: state\n" + strings.Join(extra, "") +
		"partitions:\n" + parts
	path := filepath.Join(dir, "m.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadBuildsResidualFirst(t *testing.T) {
	p, err := Load(writeManifest(t, "/data", "  - {name: a, path: proj/a}\n  - {name: b, path: home}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Jobs) != 3 || p.Jobs[0].Name != ResidualName {
		t.Fatalf("jobs = %+v, want residual then a, b", p.Jobs)
	}
	if want := []string{"/data/proj/a", "/data/home"}; !reflect.DeepEqual(p.Jobs[0].Handoff, want) {
		t.Errorf("residual handoff = %v, want %v", p.Jobs[0].Handoff, want)
	}
	if p.Jobs[1].Root != "/data/proj/a" || p.Jobs[1].Handoff != nil {
		t.Errorf("job a = %+v", p.Jobs[1])
	}
	if !p.Evidence {
		t.Error("evidence should default on")
	}
	if filepath.Base(p.StateDir) != "state" || !filepath.IsAbs(p.StateDir) {
		t.Errorf("state dir %s not resolved against the manifest", p.StateDir)
	}
}

func TestLoadRefusesOverlapAndBadPaths(t *testing.T) {
	for name, tc := range map[string]struct{ parts, want string }{
		"duplicate path": {"  - {name: a, path: x}\n  - {name: b, path: x}\n", "both name x"},
		"parent child":   {"  - {name: a, path: x}\n  - {name: b, path: x/y}\n", "partitions may not nest"},
		"child before":   {"  - {name: b, path: x/y/z}\n  - {name: a, path: x}\n", "partitions may not nest"},
		"sort trap":      {"  - {name: a, path: x}\n  - {name: c, path: x-y}\n  - {name: b, path: x/y}\n", "partitions may not nest"},
		"duplicate name": {"  - {name: a, path: x}\n  - {name: A, path: y}\n", "duplicates"},
		"reserved name":  {"  - {name: residual, path: x}\n", "reserved"},
		"bad name":       {"  - {name: ../x, path: x}\n", "must be 1-64"},
		"absolute":       {"  - {name: a, path: /x}\n", "relative"},
		"unclean":        {"  - {name: a, path: x/../y}\n", "not clean"},
		"dot":            {"  - {name: a, path: .}\n", "strictly under"},
		"escapes":        {"  - {name: a, path: ../x}\n", "strictly under"},
		"glob":           {"  - {name: a, path: x*}\n", "glob"},
		"excluded":       {"  - {name: a, path: x/.snapshot}\n", "excluded"},
		"under excluded": {"  - {name: a, path: .snapshot/x}\n", "excluded"},
		"none":           {"  []\n", "at least one"},
		"unknown key":    {"  - {name: a, path: x, mode: fast}\n", "not found"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Load(writeManifest(t, "/data", tc.parts))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
	if _, err := Load(writeManifest(t, "/", "  - {name: a, path: x}\n")); err == nil {
		t.Error("root / accepted")
	}
	// Siblings that share a prefix are disjoint.
	if _, err := Load(writeManifest(t, "/data", "  - {name: a, path: x}\n  - {name: b, path: x-y}\n  - {name: c, path: xy/z}\n")); err != nil {
		t.Errorf("disjoint siblings refused: %v", err)
	}
}

func TestLoadRefusesManifestExcludeOverAPartition(t *testing.T) {
	_, err := Load(writeManifest(t, "/data", "  - {name: a, path: logs/old}\n", "exclude:\n  - logs/*\n"))
	if err == nil || !strings.Contains(err.Error(), "excluded") {
		t.Errorf("err = %v, want an exclusion refusal", err)
	}
}

func TestCheckIdentityRefusesAliasesAndSymlinks(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"a", "b"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(root, "a"), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	p, err := Load(writeManifest(t, root, "  - {name: a, path: a}\n  - {name: b, path: b}\n"))
	if err != nil {
		t.Fatal(err)
	}
	ids, err := CheckIdentity(p, true)
	if err != nil || len(ids) != 3 {
		t.Fatalf("CheckIdentity: %v %v", ids, err)
	}

	p, _ = Load(writeManifest(t, root, "  - {name: l, path: link}\n"))
	if _, err := CheckIdentity(p, false); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("symlinked partition root: err = %v", err)
	}

	// A bind mount is two names for one directory: fake one by reporting a's
	// stat for b.
	p, _ = Load(writeManifest(t, root, "  - {name: a, path: a}\n  - {name: b, path: b}\n"))
	lstat = func(name string) (os.FileInfo, error) {
		if name == filepath.Join(root, "b") {
			name = filepath.Join(root, "a")
		}
		return os.Lstat(name)
	}
	t.Cleanup(func() { lstat = os.Lstat })
	if _, err := CheckIdentity(p, false); err == nil || !strings.Contains(err.Error(), "same directory") {
		t.Errorf("aliased partition roots: err = %v", err)
	}
}

// fakeRunner records the jobs it ran and fails the ones named in fail.
type fakeRunner struct {
	ran   []string
	paths map[string][]AttemptPaths
	fail  map[string]bool
	// handoffs overrides what the residual reports reaching; nil reports all.
	handoffs []string
}

func (f *fakeRunner) run(_ context.Context, job Job, paths AttemptPaths) (run.Result, int, error) {
	f.ran = append(f.ran, job.Name)
	if f.paths == nil {
		f.paths = map[string][]AttemptPaths{}
	}
	f.paths[job.Name] = append(f.paths[job.Name], paths)
	if paths.Checkpoint != "" {
		os.MkdirAll(filepath.Dir(paths.Checkpoint), 0o755)
		os.WriteFile(paths.Checkpoint, []byte("CKPT"), 0o644)
	}
	res := run.Result{Stats: stats.Snapshot{Enumerated: 10, Applied: 10}}
	if paths.EvidenceDir != "" {
		res.Evidence = &evidence.Manifest{Status: evidence.StatusComplete, RecordsWritten: 10}
	}
	if len(job.Handoff) > 0 {
		res.HandedOff = job.Handoff
		if f.handoffs != nil {
			res.HandedOff = f.handoffs
		}
	}
	if f.fail[job.Name] {
		res.Stats.Errors, res.TotalErrors = 2, 2
		res.Evidence = &evidence.Manifest{Status: evidence.StatusComplete}
		return res, 1, errors.New("permission repair run failed")
	}
	return res, 0, nil
}

func loadTree(t *testing.T) *Plan {
	t.Helper()
	p, err := Load(writeManifest(t, "/data", "  - {name: a, path: a}\n  - {name: b, path: b}\n  - {name: c, path: c}\n"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestRestartRunsOnlyWhatFailed is the acceptance criterion: a resume neither
// replays completed siblings nor drops the unfinished partition, and the
// unfinished one resumes its own checkpoint.
func TestRestartRunsOnlyWhatFailed(t *testing.T) {
	p := loadTree(t)
	f := &fakeRunner{fail: map[string]bool{"b": true}}
	rep, err := Execute(context.Background(), p, Options{Mode: ModeApply, ToolVersion: "v1"}, f.run)
	if !errors.Is(err, ErrIncomplete) {
		t.Fatalf("first run err = %v, want ErrIncomplete", err)
	}
	if want := []string{"residual", "a", "b", "c"}; !reflect.DeepEqual(f.ran, want) {
		t.Errorf("first run ran %v, want %v: a failure must not stop its siblings", f.ran, want)
	}
	if rep.Complete || rep.Totals.Enumerated != 40 || rep.Totals.Failed != 2 {
		t.Errorf("report = %+v", rep)
	}

	// Without --resume the state is refused, not overwritten.
	if _, err := Execute(context.Background(), p, Options{Mode: ModeApply, ToolVersion: "v1"}, f.run); err == nil || !strings.Contains(err.Error(), "--resume") {
		t.Errorf("rerun without --resume: err = %v", err)
	}

	f2 := &fakeRunner{}
	rep, err = Execute(context.Background(), p, Options{Mode: ModeApply, Resume: true, ToolVersion: "v1"}, f2.run)
	if err != nil {
		t.Fatalf("resume: %v (%v)", err, rep.Reasons)
	}
	if want := []string{"b"}; !reflect.DeepEqual(f2.ran, want) {
		t.Errorf("resume ran %v, want only %v", f2.ran, want)
	}
	if bp := f2.paths["b"][0]; !bp.Resume || !strings.HasSuffix(bp.EvidenceDir, "b/attempt-2/evidence") {
		t.Errorf("b's second attempt paths = %+v, want a resumed checkpoint and a fresh evidence dir", bp)
	}
	// Totals reconcile exactly with the attempts: 4 first-run attempts plus 1.
	if rep.Totals.Enumerated != 50 || !rep.Complete || !rep.EvidenceComplete {
		t.Errorf("report after resume = %+v", rep)
	}
	ps := (&State{Partitions: rep.Partitions}).part("b")
	if len(ps.Attempts) != 2 || ps.Attempts[0].Reasons == nil || ps.Attempts[1].Reasons != nil {
		t.Errorf("b attempts = %+v", ps.Attempts)
	}

	// A completed state resumes to a no-op.
	f3 := &fakeRunner{}
	if _, err := Execute(context.Background(), p, Options{Mode: ModeApply, Resume: true, ToolVersion: "v1"}, f3.run); err != nil || len(f3.ran) != 0 {
		t.Errorf("resume of a complete run ran %v, err %v", f3.ran, err)
	}
}

func TestResumeRefusesAChangedBinding(t *testing.T) {
	p := loadTree(t)
	f := &fakeRunner{fail: map[string]bool{"a": true}}
	Execute(context.Background(), p, Options{Mode: ModeApply, ToolVersion: "v1",
		Identities: map[string]Identity{"residual": {1, 1}, "a": {1, 2}, "b": {1, 3}, "c": {1, 4}}}, f.run)

	for name, tc := range map[string]struct {
		o    Options
		edit func(*Plan)
		want string
	}{
		"tool version": {o: Options{Mode: ModeApply, ToolVersion: "v2"}, want: "tool version"},
		"mode":         {o: Options{Mode: ModeValidate, ToolVersion: "v1"}, want: "cannot be resumed as validate"},
		"manifest":     {o: Options{Mode: ModeApply, ToolVersion: "v1"}, edit: func(p *Plan) { p.Digest = "x" }, want: "different manifest"},
		"renamed root": {o: Options{Mode: ModeApply, ToolVersion: "v1",
			Identities: map[string]Identity{"residual": {1, 1}, "a": {1, 9}, "b": {1, 3}, "c": {1, 4}}}, want: "renamed or replaced"},
	} {
		t.Run(name, func(t *testing.T) {
			q := *p
			if tc.edit != nil {
				tc.edit(&q)
			}
			tc.o.Resume = true
			if tc.o.Identities == nil && name != "renamed root" {
				tc.o.Identities = map[string]Identity{"residual": {1, 1}, "a": {1, 2}, "b": {1, 3}, "c": {1, 4}}
			}
			_, err := Execute(context.Background(), &q, tc.o, (&fakeRunner{}).run)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// TestUnreachedPartitionRootIsIncomplete: a partition beneath something the
// residual stopped at (a mount boundary, an unreadable directory) is not part
// of the walked tree, however clean its own run.
func TestUnreachedPartitionRootIsIncomplete(t *testing.T) {
	p := loadTree(t)
	f := &fakeRunner{handoffs: []string{"/data/a", "/data/c"}}
	rep, err := Execute(context.Background(), p, Options{Mode: ModeApply, ToolVersion: "v1"}, f.run)
	if !errors.Is(err, ErrIncomplete) || !reflect.DeepEqual(rep.Unreached, []string{"/data/b"}) {
		t.Errorf("err = %v, unreached = %v", err, rep.Unreached)
	}
}

func TestOnlyRunsTheNamedPartitions(t *testing.T) {
	p := loadTree(t)
	f := &fakeRunner{}
	rep, err := Execute(context.Background(), p, Options{Mode: ModeApply, ToolVersion: "v1", Only: []string{"c"}}, f.run)
	if !reflect.DeepEqual(f.ran, []string{"c"}) || !errors.Is(err, ErrIncomplete) || rep.Complete {
		t.Errorf("ran %v err %v complete %t", f.ran, err, rep.Complete)
	}
	if _, err := Execute(context.Background(), p, Options{Mode: ModeApply, Resume: true, ToolVersion: "v1", Only: []string{"zz"}}, f.run); err == nil {
		t.Error("unknown --partition accepted")
	}
}

func TestDriverCrashMidPartitionIsRetried(t *testing.T) {
	p := loadTree(t)
	st := newState(p, ModeApply, "v1", nil)
	st.Partitions[0].Status = StatusComplete
	st.Partitions[0].Attempts = []Attempt{{N: 1, HandedOff: []string{"/data/a", "/data/b", "/data/c"}}}
	st.Partitions[1].Status = StatusRunning
	st.Partitions[1].Attempts = []Attempt{{N: 1}}
	if err := os.MkdirAll(p.StateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := st.save(p.StateDir); err != nil {
		t.Fatal(err)
	}
	f := &fakeRunner{}
	rep, err := Execute(context.Background(), p, Options{Mode: ModeApply, Resume: true, ToolVersion: "v1"}, f.run)
	if err != nil || !reflect.DeepEqual(f.ran, []string{"a", "b", "c"}) {
		t.Fatalf("ran %v err %v", f.ran, err)
	}
	if a := rep.Partitions[1].Attempts[0]; a.ExitCode != -1 || len(a.Reasons) == 0 || !a.Uncounted {
		t.Errorf("crashed attempt = %+v, want it marked failed and uncounted", a)
	}
	// Found live on c09-33: a SIGKILLed attempt records no counts, so the
	// totals must say they are a lower bound rather than pass as exact.
	if want := []string{rep.Partitions[1].Name + "#1"}; !reflect.DeepEqual(rep.UncountedAttempts, want) {
		t.Errorf("UncountedAttempts = %v, want %v", rep.UncountedAttempts, want)
	}
}

func TestSecondDriverIsRefused(t *testing.T) {
	p := loadTree(t)
	if err := os.MkdirAll(p.StateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	release, err := lockDir(p.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := Execute(context.Background(), p, Options{Mode: ModeApply, ToolVersion: "v1"}, (&fakeRunner{}).run); err == nil || !strings.Contains(err.Error(), "another partitioned run") {
		t.Errorf("err = %v", err)
	}
}

func TestDryRunKeepsNoState(t *testing.T) {
	p := loadTree(t)
	f := &fakeRunner{}
	if _, err := Execute(context.Background(), p, Options{Mode: ModeDryRun, ToolVersion: "v1"}, f.run); err != nil {
		t.Fatal(err)
	}
	if len(f.ran) != 4 || f.paths["a"][0] != (AttemptPaths{}) {
		t.Errorf("dry run ran %v with paths %+v", f.ran, f.paths["a"])
	}
	if _, err := os.Stat(p.StateDir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("dry run created %s", p.StateDir)
	}
}

func TestCancellationStopsBeforeTheNextPartition(t *testing.T) {
	p := loadTree(t)
	ctx, cancel := context.WithCancel(context.Background())
	f := &fakeRunner{}
	runOne := func(c context.Context, j Job, a AttemptPaths) (run.Result, int, error) {
		res, code, err := f.run(c, j, a)
		if j.Name == "a" {
			cancel()
			res.Interrupted = true
		}
		return res, code, err
	}
	rep, err := Execute(ctx, p, Options{Mode: ModeApply, ToolVersion: "v1"}, runOne)
	if !errors.Is(err, ErrIncomplete) || !reflect.DeepEqual(f.ran, []string{"residual", "a"}) {
		t.Errorf("ran %v err %v", f.ran, err)
	}
	if rep.Partitions[1].Status != StatusFailed || rep.Partitions[2].Status != StatusPending {
		t.Errorf("statuses %s %s", rep.Partitions[1].Status, rep.Partitions[2].Status)
	}
}

func TestShippedExampleManifestLoads(t *testing.T) {
	p, err := Load("../../examples/partitions/manifest.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Jobs) != 4 {
		t.Errorf("example has %d jobs, want residual plus 3", len(p.Jobs))
	}
}
