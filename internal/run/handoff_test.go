package run

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/checkpoint"
)

// handoffTree is root/{top.txt, a/{x.txt, owned/{y.txt}}, b/{z.txt}}, every
// mode wrong.
func handoffTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"a/owned", "b"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"top.txt", "a/x.txt", "a/owned/y.txt", "b/z.txt"} {
		if err := os.WriteFile(filepath.Join(root, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func modeOf(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// TestHandoffPrunesWithoutCountingAnExclusion pins the residual's half of the
// boundary: a handed-off directory is neither fixed nor descended, is not an
// exclusion, and is reported by path.
func TestHandoffPrunesWithoutCountingAnExclusion(t *testing.T) {
	root := handoffTree(t)
	specPath, s := writeSpec(t, posixSpec)
	owned := filepath.Join(root, "a/owned")
	var out, errOut strings.Builder
	res, err := Run(context.Background(), Config{
		Root: root, SpecPath: specPath, Spec: s, Transport: "kernel", Workers: 2, BatchSize: 1,
		Apply: true, Quiet: true, Handoff: []string{owned}, CheckpointPath: filepath.Join(t.TempDir(), "ckpt"),
		ErrOut: &errOut,
	}, &out)
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, errOut.String())
	}
	if !reflect.DeepEqual(res.HandedOff, []string{owned}) {
		t.Errorf("HandedOff = %v, want [%s]", res.HandedOff, owned)
	}
	if res.Stats.Excluded != 0 {
		t.Errorf("Excluded = %d, want 0: a handoff is not an exclusion", res.Stats.Excluded)
	}
	// root, top.txt, a, a/x.txt, b, b/z.txt
	if res.Stats.Enumerated != 6 {
		t.Errorf("Enumerated = %d, want 6", res.Stats.Enumerated)
	}
	if got := modeOf(t, owned); got != 0o700 {
		t.Errorf("handed-off root mode = %o, want 0700 untouched: the partition owns it", got)
	}
	if got := modeOf(t, filepath.Join(owned, "y.txt")); got != 0o600 {
		t.Errorf("handed-off file mode = %o, want 0600 untouched", got)
	}
	if got := modeOf(t, filepath.Join(root, "a/x.txt")); got != 0o644 {
		t.Errorf("residual file mode = %o, want 0644", got)
	}
}

// TestExcludeRootAnchorsSlashPatternsAtTheManifestRoot: a partition walking
// root/a must read `a/x.txt` as the manifest root reads it.
func TestExcludeRootAnchorsSlashPatternsAtTheManifestRoot(t *testing.T) {
	root := handoffTree(t)
	specPath, s := writeSpec(t, posixSpec)
	var out, errOut strings.Builder
	res, err := Run(context.Background(), Config{
		Root: filepath.Join(root, "a"), ExcludeRoot: root, SpecPath: specPath, Spec: s, Transport: "kernel",
		Workers: 2, BatchSize: 1, Apply: true, Quiet: true, Exclude: []string{"a/x.txt"}, ErrOut: &errOut,
	}, &out)
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, errOut.String())
	}
	if res.Stats.Excluded != 1 {
		t.Errorf("Excluded = %d, want 1 (a/x.txt, anchored at the manifest root)", res.Stats.Excluded)
	}
	if got := modeOf(t, filepath.Join(root, "a/x.txt")); got != 0o600 {
		t.Errorf("excluded file mode = %o, want 0600", got)
	}
	if got := modeOf(t, filepath.Join(root, "a")); got != 0o755 {
		t.Errorf("partition root mode = %o, want 0755: the partition owns its root", got)
	}
}

// TestHandoffIsPartOfTheCheckpointBinding: a checkpoint written with one
// handoff set means something different under another, so resume refuses.
func TestHandoffIsPartOfTheCheckpointBinding(t *testing.T) {
	root := handoffTree(t)
	specPath, s := writeSpec(t, posixSpec)
	ckpt := filepath.Join(t.TempDir(), "ckpt")
	cfg := Config{
		Root: root, SpecPath: specPath, Spec: s, Transport: "kernel", Workers: 2, BatchSize: 1,
		Apply: true, Quiet: true, CheckpointPath: ckpt, Handoff: []string{filepath.Join(root, "a/owned")},
	}
	var out, errOut strings.Builder
	cfg.ErrOut = &errOut
	if _, err := Run(context.Background(), cfg, &out); err != nil {
		t.Fatalf("first run: %v\n%s", err, errOut.String())
	}
	cfg.Handoff, cfg.Resume = []string{filepath.Join(root, "b")}, true
	errOut.Reset()
	if _, err := Run(context.Background(), cfg, &out); err == nil || !strings.Contains(errOut.String(), "run binding changed") {
		t.Fatalf("resume under another handoff set: err=%v stderr=%q, want a binding refusal", err, errOut.String())
	}

	// And a run with neither handoff nor anchoring hashes what it always did.
	var h *handoffSet
	plain, err := checkpoint.RunHash(specPath, root, "posix", "v", h.binding([]string{"*.tmp"}, false, ""))
	if err != nil {
		t.Fatal(err)
	}
	legacy, _ := checkpoint.RunHash(specPath, root, "posix", "v", []string{"*.tmp"})
	if plain != legacy {
		t.Error("an unpartitioned run's checkpoint binding changed")
	}
}

func TestHandoffRefusesPathsOutsideTheRoot(t *testing.T) {
	for _, h := range []string{"/elsewhere", "/r", "/r/../x"} {
		if _, err := newHandoff(Config{Root: "/r", Handoff: []string{h}}); err == nil {
			t.Errorf("handoff %s under root /r: want refusal", h)
		}
	}
	if _, err := newHandoff(Config{Root: "/r", Handoff: []string{"/r/a"}, Pfind: true}); err == nil {
		t.Error("handoff with pfind: want refusal")
	}
}
