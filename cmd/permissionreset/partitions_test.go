package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/partition"
	runpkg "github.com/PureStorage-OpenConnect/permissionreset/internal/run"
)

const partitionSpec = "protocol: posix\ndefault:\n  mode: \"0755\"\nrules:\n" +
	"  - match:\n      type: directory\n    mode: \"0755\"\n" +
	"  - match:\n      type: file\n    mode: \"0644\"\n"

// partitionFixture builds root/{top.txt, proj/{a/f, b/f, c.txt}} with every
// mode wrong, and a manifest partitioning proj/a and proj/b.
func partitionFixture(t *testing.T) (root, manifest string) {
	t.Helper()
	root = t.TempDir()
	for _, d := range []string{"proj/a", "proj/b"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"top.txt", "proj/a/f", "proj/b/f", "proj/c.txt"} {
		if err := os.WriteFile(filepath.Join(root, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "spec.yaml"), []byte(partitionSpec), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest = filepath.Join(dir, "m.yaml")
	body := "version: 1\nroot: " + root + "\nspec: spec.yaml\nstate_dir: state\npartitions:\n" +
		"  - {name: a, path: proj/a}\n  - {name: b, path: proj/b}\n"
	if err := os.WriteFile(manifest, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, manifest
}

func perm(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func TestPartitionedApplyFailsOnePartitionThenResumesIt(t *testing.T) {
	requireKernelTransport(t)
	root, manifest := partitionFixture(t)
	failB := filepath.Join(root, "proj/b")
	var roots []string
	failing := true
	old := runCommand
	t.Cleanup(func() { runCommand = old })
	runCommand = func(ctx context.Context, cfg runpkg.Config, out io.Writer) (runpkg.Result, error) {
		roots = append(roots, cfg.Root)
		if cfg.ExcludeRoot != root {
			t.Errorf("partition %s: ExcludeRoot = %q, want the manifest root", cfg.Root, cfg.ExcludeRoot)
		}
		if failing && cfg.Root == failB {
			return runpkg.Result{}, errors.New("simulated partition failure")
		}
		return old(ctx, cfg, out)
	}

	var out, errOut strings.Builder
	args := []string{"--partitions", manifest, "--apply", "--workers=2", "--quiet"}
	if code := runWithFlagSet(args, &out, &errOut); code != 1 {
		t.Fatalf("first run exit = %d, want 1\nstdout:\n%s\nstderr:\n%s", code, out.String(), errOut.String())
	}
	if want := []string{root, filepath.Join(root, "proj/a"), failB}; !reflect.DeepEqual(roots, want) {
		t.Errorf("ran %v, want %v", roots, want)
	}
	for p, want := range map[string]os.FileMode{
		".": 0o755, "top.txt": 0o644, "proj": 0o755, "proj/c.txt": 0o644, // residual
		"proj/a": 0o755, "proj/a/f": 0o644, // partition a, root included
		"proj/b": 0o700, "proj/b/f": 0o600, // failed partition: untouched
	} {
		if got := perm(t, filepath.Join(root, p)); got != want {
			t.Errorf("%s mode = %o, want %o", p, got, want)
		}
	}

	roots, failing = nil, false
	out.Reset()
	errOut.Reset()
	if code := runWithFlagSet(append(args, "--resume"), &out, &errOut); code != 0 {
		t.Fatalf("resume exit = %d\nstdout:\n%s\nstderr:\n%s", code, out.String(), errOut.String())
	}
	if want := []string{failB}; !reflect.DeepEqual(roots, want) {
		t.Errorf("resume ran %v, want only %v", roots, want)
	}
	if got := perm(t, filepath.Join(root, "proj/b/f")); got != 0o644 {
		t.Errorf("proj/b/f after resume = %o", got)
	}

	data, err := os.ReadFile(filepath.Join(filepath.Dir(manifest), "state", ReportName))
	if err != nil {
		t.Fatal(err)
	}
	var rep partition.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatal(err)
	}
	if !rep.Complete || !rep.EvidenceComplete || len(rep.Unreached) != 0 {
		t.Errorf("report: complete=%t evidence=%t unreached=%v reasons=%v", rep.Complete, rep.EvidenceComplete, rep.Unreached, rep.Reasons)
	}
	// residual: root, top.txt, proj, proj/c.txt; a: proj/a, f; b: proj/b, f.
	// The root starts 0755 (TempDir), so it is skipped rather than applied.
	if rep.Totals.Enumerated != 8 || rep.Totals.Applied+rep.Totals.Skipped != 8 || rep.Totals.Failed != 0 {
		t.Errorf("totals = %+v, want 8 enumerated, all applied or skipped", rep.Totals)
	}
	res := rep.Partitions[0]
	if want := []string{filepath.Join(root, "proj/a"), failB}; !reflect.DeepEqual(res.Attempts[0].HandedOff, want) {
		t.Errorf("residual handed off %v, want %v", res.Attempts[0].HandedOff, want)
	}
	for _, ps := range rep.Partitions {
		for _, a := range ps.Attempts {
			if a.EvidenceStatus == "complete" {
				if _, err := os.Stat(filepath.Join(a.EvidenceDir, "manifest.json")); err != nil {
					t.Errorf("%s attempt %d: %v", ps.Name, a.N, err)
				}
			}
		}
	}
}

func TestPartitionsRefusesConflictingFlags(t *testing.T) {
	_, manifest := partitionFixture(t)
	for _, extra := range [][]string{
		{"--spec", "x.yaml"}, {"--exclude", "*.tmp"}, {"--checkpoint", "c"}, {"--evidence-dir", "e"}, {"--log", "l"}, {"/some/target"},
	} {
		var out, errOut strings.Builder
		args := append([]string{"--partitions", manifest}, extra...)
		if code := runWithFlagSet(args, &out, &errOut); code != 1 {
			t.Errorf("%v: exit %d, want 1 (stderr %q)", extra, code, errOut.String())
		}
	}
	var out, errOut strings.Builder
	if code := runWithFlagSet([]string{"--partition", "a", "/t"}, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "requires --partitions") {
		t.Errorf("--partition alone: exit %d stderr %q", code, errOut.String())
	}
}

func TestPartitionedDryRunChangesNothing(t *testing.T) {
	requireKernelTransport(t)
	root, manifest := partitionFixture(t)
	var out, errOut strings.Builder
	if code := runWithFlagSet([]string{"--partitions", manifest, "--workers=2", "--quiet"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out.String(), errOut.String())
	}
	if got := perm(t, filepath.Join(root, "proj/a/f")); got != 0o600 {
		t.Errorf("dry run changed proj/a/f to %o", got)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(manifest), "state")); !errors.Is(err, os.ErrNotExist) {
		t.Error("dry run created the state directory")
	}
}
