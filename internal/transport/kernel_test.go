//go:build !windows

package transport

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestKernelReadDirClassifiesEntries(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("file.txt", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}

	k, err := NewKernel(root)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	r, err := k.Root()
	if err != nil {
		t.Fatal(err)
	}
	if r.Path != root {
		t.Fatalf("Root().Path = %q, want %q", r.Path, root)
	}
	if r.FH != nil {
		t.Fatalf("Root().FH = %v, want nil on kernel transport", r.FH)
	}

	ents, err := k.ReadDir(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 3 {
		t.Fatalf("got %d entries, want 3", len(ents))
	}

	byName := map[string]Dirent{}
	for _, e := range ents {
		byName[e.Name] = e
	}

	if !byName["sub"].IsDir {
		t.Error("sub: IsDir = false, want true")
	}
	if byName["sub"].Ref.Path != filepath.Join(root, "sub") {
		t.Errorf("sub: Ref.Path = %q", byName["sub"].Ref.Path)
	}
	if byName["file.txt"].IsDir || byName["file.txt"].IsSymlink {
		t.Error("file.txt: classified as dir or symlink")
	}
	if !byName["link"].IsSymlink {
		t.Error("link: IsSymlink = false, want true")
	}
	if byName["link"].IsDir {
		t.Error("link: IsDir = true, symlinks must never be classified as directories")
	}
}

// TestKernelReadDirDoesNotStat pins the design rule in CLAUDE.md: "Stat in apply
// workers, never in enumerator." A per-entry lstat here would add one round trip
// per object to every run, and on the primary protocol: nfsv4 path nothing would
// consume the result.
func TestKernelReadDirDoesNotStat(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	k, _ := NewKernel(root)
	defer k.Close()
	r, _ := k.Root()
	ents, err := k.ReadDir(r)
	if err != nil {
		t.Fatal(err)
	}
	e := ents[0]
	if e.AttrsKnown {
		t.Error("AttrsKnown = true; the kernel transport must not stat during enumeration")
	}
	if e.Mode != 0 || e.FSID != 0 {
		t.Errorf("Mode = 0%o, FSID = %d; both must be zero when AttrsKnown is false", e.Mode, e.FSID)
	}
}

func TestKernelStatReportsAttributes(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "file.txt")
	if err := os.WriteFile(p, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("file.txt", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	k, _ := NewKernel(root)
	defer k.Close()

	a, err := k.Stat(Ref{Path: p})
	if err != nil {
		t.Fatal(err)
	}
	if a.Mode != 0o640 {
		t.Errorf("Mode = 0%o, want 0640", a.Mode)
	}
	if a.FSID == 0 {
		t.Error("FSID = 0, want the device number")
	}
	if a.IsDir || a.IsSymlink {
		t.Error("file.txt reported as dir or symlink")
	}

	// Stat must not follow symlinks: the link's own attributes, not the target's.
	l, err := k.Stat(Ref{Path: filepath.Join(root, "link")})
	if err != nil {
		t.Fatal(err)
	}
	if !l.IsSymlink {
		t.Error("link: IsSymlink = false; Stat must not follow symlinks")
	}
}

// TestKernelStatReturnsItsError is finding 4 from the Task 1 review: a swallowed
// error leaves FSID at zero, which --one-filesystem reads as "different
// filesystem" and silently skips an entire subtree while exiting zero.
func TestKernelStatReturnsItsError(t *testing.T) {
	k, _ := NewKernel(t.TempDir())
	defer k.Close()
	if _, err := k.Stat(Ref{Path: filepath.Join(t.TempDir(), "does-not-exist")}); err == nil {
		t.Fatal("want an error for a missing path, got nil")
	}
}

func TestKernelReadDirIsSortedByName(t *testing.T) {
	root := t.TempDir()
	for _, n := range []string{"zebra", "alpha", "middle"} {
		if err := os.WriteFile(filepath.Join(root, n), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	k, _ := NewKernel(root)
	defer k.Close()
	r, _ := k.Root()
	ents, err := k.ReadDir(r)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"alpha", "middle", "zebra"}
	for i, w := range want {
		if ents[i].Name != w {
			t.Fatalf("entry %d = %q, want %q", i, ents[i].Name, w)
		}
	}
}

func TestKernelChmodAndProbe(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "f")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	k, _ := NewKernel(root)
	defer k.Close()

	ref := Ref{Path: p}
	if err := k.Chmod(ref, 0o644); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %v, want 0644", fi.Mode().Perm())
	}

	if _, _, cleanup, err := k.ProbeTarget(Ref{Path: root}); err != nil {
		t.Fatalf("ProbeTarget on a writable tmpdir failed: %v", err)
	} else {
		cleanup()
	}
}

// TestProbeTargetYieldsAnApplyableTarget is finding 2 from the Task 1 review.
// Preflight has to apply the real spec to a throwaway object, because that is
// what catches idmapd misconfiguration and missing ACL support. A probe that only
// creates and unlinks a file passes on an export where every later write fails.
func TestProbeTargetYieldsAnApplyableTarget(t *testing.T) {
	root := t.TempDir()
	k, _ := NewKernel(root)
	defer k.Close()

	target, isDir, cleanup, err := k.ProbeTarget(Ref{Path: root})
	if err != nil {
		t.Fatal(err)
	}
	// Finding C of the Task 2 review: the caller needs to know whether to apply
	// the spec's file or directory rules. The kernel probe is a regular file.
	if isDir {
		t.Error("isDir = true for a temp file; preflight would apply directory rules to it")
	}
	if target.Path == "" {
		t.Fatal("target.Path is empty; the caller has nothing to apply the spec to")
	}
	if _, err := os.Stat(target.Path); err != nil {
		t.Fatalf("target does not exist, so the spec cannot be applied to it: %v", err)
	}
	if filepath.Dir(target.Path) != root {
		t.Errorf("target %q is not under the probed directory %q", target.Path, root)
	}

	if err := cleanup(); err != nil {
		t.Fatalf("cleanup returned an error: %v", err)
	}
	if _, err := os.Stat(target.Path); !os.IsNotExist(err) {
		t.Error("cleanup left the probe file behind in the caller's tree")
	}
}

// TestProbeTargetCleanupToleratesAnUndeletableFile pins finding 5: the unlink
// result must not become the probe's verdict. On a delete-restricted export a run
// that works today would otherwise abort at preflight.
func TestProbeTargetCleanupToleratesAnUndeletableFile(t *testing.T) {
	root := t.TempDir()
	k, _ := NewKernel(root)
	defer k.Close()

	target, _, cleanup, err := k.ProbeTarget(Ref{Path: root})
	if err != nil {
		t.Fatal(err)
	}
	// Remove it out from under the cleanup, so the cleanup's own unlink fails.
	if err := os.Remove(target.Path); err != nil {
		t.Fatal(err)
	}
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup surfaced an unlink failure as an error: %v", err)
	}
}

// ReadDirBatches never hands fn more than n children, hands every child exactly
// once, and reports delivered=false for a listing that failed or was empty.
func TestKernelReadDirBatches(t *testing.T) {
	root := t.TempDir()
	const files = 100
	for i := 0; i < files; i++ {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("f%03d", i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	os.Mkdir(filepath.Join(root, "sub"), 0o755)
	os.Symlink("sub", filepath.Join(root, "link"))
	k, err := NewKernel(root)
	if err != nil {
		t.Fatal(err)
	}

	seen := map[string]Dirent{}
	batches := 0
	delivered, err := k.ReadDirBatches(Ref{Path: root}, 7, func(b []Dirent) error {
		batches++
		if len(b) > 7 {
			t.Errorf("batch of %d, want <= 7", len(b))
		}
		for _, d := range b {
			if _, dup := seen[d.Name]; dup {
				t.Errorf("%s handed out twice", d.Name)
			}
			seen[d.Name] = d
		}
		return nil
	})
	if err != nil || !delivered {
		t.Fatalf("delivered=%v err=%v", delivered, err)
	}
	if len(seen) != files+2 || batches < (files+2)/7 {
		t.Errorf("%d children in %d batches, want %d in >= %d", len(seen), batches, files+2, (files+2)/7)
	}
	if !seen["sub"].IsDir || !seen["link"].IsSymlink || seen["link"].IsDir {
		t.Errorf("types: sub=%+v link=%+v", seen["sub"], seen["link"])
	}
	if seen["f000"].Ref.Path != root+"/f000" {
		t.Errorf("path %q", seen["f000"].Ref.Path)
	}

	stop := errors.New("stop")
	n := 0
	if _, err := k.ReadDirBatches(Ref{Path: root}, 7, func([]Dirent) error { n++; return stop }); err != stop || n != 1 {
		t.Errorf("fn error: err=%v calls=%d, want stop after 1", err, n)
	}
	if d, err := k.ReadDirBatches(Ref{Path: filepath.Join(root, "sub")}, 7, func([]Dirent) error { return nil }); d || err != nil {
		t.Errorf("empty dir: delivered=%v err=%v", d, err)
	}
	if d, err := k.ReadDirBatches(Ref{Path: filepath.Join(root, "missing")}, 7, func([]Dirent) error { return nil }); d || err == nil {
		t.Errorf("missing dir: delivered=%v err=%v", d, err)
	}
}
