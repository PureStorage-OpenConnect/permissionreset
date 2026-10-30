package walk

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

func makeTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	dirs := []string{
		"a/b/c",
		"a/d",
		"e",
	}
	for _, d := range dirs {
		os.MkdirAll(filepath.Join(root, d), 0755)
	}
	files := []string{
		"a/f1.txt",
		"a/b/f2.txt",
		"a/b/c/f3.sh",
		"a/d/f4.txt",
		"e/f5.dat",
	}
	for _, f := range files {
		os.WriteFile(filepath.Join(root, f), []byte("x"), 0644)
	}
	return root
}

func TestParallelWalkFindsAll(t *testing.T) {
	root := makeTree(t)
	ch := make(chan Entry, 100)
	errs := &WalkErrors{}

	go func() {
		ParallelWalk(root, ch, 4, errs, nil)
		close(ch)
	}()

	var paths []string
	for e := range ch {
		rel, _ := filepath.Rel(root, e.Path)
		paths = append(paths, rel)
	}
	sort.Strings(paths)

	want := []string{
		".", "a", "a/b", "a/b/c", "a/b/c/f3.sh", "a/b/f2.txt",
		"a/d", "a/d/f4.txt", "a/f1.txt", "e", "e/f5.dat",
	}
	sort.Strings(want)

	if len(paths) != len(want) {
		t.Fatalf("got %d entries, want %d\ngot:  %v\nwant: %v", len(paths), len(want), paths, want)
	}
	for i := range want {
		if paths[i] != want[i] {
			t.Errorf("paths[%d] = %q, want %q", i, paths[i], want[i])
		}
	}

	if errs.Count() != 0 {
		t.Errorf("walk errors = %d, want 0", errs.Count())
	}
}

func TestParallelWalkSymlinkSkipped(t *testing.T) {
	root := makeTree(t)
	os.Symlink("/nonexistent", filepath.Join(root, "link"))

	ch := make(chan Entry, 100)
	errs := &WalkErrors{}
	go func() {
		ParallelWalk(root, ch, 4, errs, nil)
		close(ch)
	}()

	symlinks := 0
	for e := range ch {
		if e.IsSymlink {
			symlinks++
		}
	}
	if symlinks != 1 {
		t.Errorf("symlinks = %d, want 1", symlinks)
	}
}

func TestParallelWalkDirTypes(t *testing.T) {
	root := makeTree(t)
	ch := make(chan Entry, 100)
	errs := &WalkErrors{}
	go func() {
		ParallelWalk(root, ch, 4, errs, nil)
		close(ch)
	}()

	for e := range ch {
		name := filepath.Base(e.Path)
		if e.IsDir {
			if filepath.Ext(name) != "" && name != root {
				t.Errorf("%q marked as dir but has extension", e.Path)
			}
		}
	}
}

// kernelTransport returns a kernel transport over a tmpdir tree, which is what
// every Prepass test that predates the transport seam needs in order to keep
// exercising the syscall path it was written against.
func kernelTransport(t *testing.T, root string) transport.Transport {
	t.Helper()
	k, err := transport.NewKernel(root)
	if err != nil {
		t.Fatalf("NewKernel(%q): %v", root, err)
	}
	t.Cleanup(func() { k.Close() })
	return k
}

func TestPrepass(t *testing.T) {
	root := makeTree(t)
	os.Chmod(filepath.Join(root, "a", "b"), 0000)

	var mu sync.Mutex
	var fixed []string
	fixFunc := func(ref transport.Ref) (bool, string, FixResult) {
		if err := os.Chmod(ref.Path, 0755); err != nil {
			return false, "ERR", FixResult{}
		}
		mu.Lock()
		rel, _ := filepath.Rel(root, ref.Path)
		fixed = append(fixed, rel)
		mu.Unlock()
		return true, "OK", FixResult{}
	}
	logFunc := func(string) {}

	// ch == nil: fix-only mode, the --pfind path.
	res := Prepass(root, nil, nil, PrepassOptions{Transport: kernelTransport(t, root), Fix: fixFunc, Log: logFunc, Workers: 4})
	nFixed, nErrors := res.Fixed, res.Errors

	if nErrors != 0 {
		t.Errorf("prepass errors = %d, want 0", nErrors)
	}
	// Only a/b was non-traversable and needed fixing
	if nFixed != 1 {
		t.Errorf("prepass fixed = %d, want 1", nFixed)
	}

	// Verify a/b is now traversable
	_, err := os.ReadDir(filepath.Join(root, "a", "b"))
	if err != nil {
		t.Errorf("a/b should be traversable after prepass: %v", err)
	}
}

// TestPrepassStop proves Stop ends the walk without fixing or counting what it
// left: once it fires no directory is fixed, and the result says the walk was
// stopped rather than reporting a smaller tree.
func TestPrepassStop(t *testing.T) {
	root := makeTree(t)
	os.Chmod(filepath.Join(root, "a", "b"), 0000)
	t.Cleanup(func() { os.Chmod(filepath.Join(root, "a", "b"), 0755) })

	var fixes atomic.Int64
	fixFunc := func(ref transport.Ref) (bool, string, FixResult) {
		fixes.Add(1)
		return os.Chmod(ref.Path, 0755) == nil, "", FixResult{}
	}
	ch := make(chan Entry, 1000)
	res := Prepass(root, ch, nil, PrepassOptions{
		Transport: kernelTransport(t, root), Fix: fixFunc, Workers: 4,
		Stop: func() bool { return true },
	})
	close(ch)
	if len(ch) != 0 || fixes.Load() != 0 || res.Fixed != 0 || res.Errors != 0 {
		t.Fatalf("stopped walk emitted %d, fixed %d (result %+v)", len(ch), fixes.Load(), res)
	}
	if !res.Stopped {
		t.Fatal("Stopped = false after Stop fired")
	}

	res = Prepass(root, nil, nil, PrepassOptions{Transport: kernelTransport(t, root), Fix: fixFunc, Workers: 4, Stop: func() bool { return false }})
	if res.Stopped || res.Fixed != 1 {
		t.Fatalf("Stop returning false changed the walk: %+v", res)
	}
}

// TestPrepassEntryCarriesFixResult proves a directory whose fast-path readdir
// failed carries the FixFunc's outcome on its emitted Entry (Entry.Fix), so a
// consumer like run.go's worker can tell the real apply already ran during
// the fix and skip reprocessing it -- while a directory whose fast-path
// readdir succeeded without ever calling FixFunc carries the zero value,
// since nothing it did needs to be reported or skipped.
func TestPrepassEntryCarriesFixResult(t *testing.T) {
	root := makeTree(t)
	os.Chmod(filepath.Join(root, "a", "b"), 0000)

	fixFunc := func(ref transport.Ref) (bool, string, FixResult) {
		if err := os.Chmod(ref.Path, 0755); err != nil {
			return false, "ERR", FixResult{}
		}
		return true, "", FixResult{Done: true, Applied: true, LogMsg: "OK: fixed " + ref.Path}
	}

	ch := make(chan Entry, 64)
	errs := &WalkErrors{}
	go func() {
		Prepass(root, ch, errs, PrepassOptions{Transport: kernelTransport(t, root), Fix: fixFunc, Workers: 4})
		close(ch)
	}()

	var sawFixedDone, sawUnfixedDir bool
	for e := range ch {
		if !e.IsDir {
			continue
		}
		rel, _ := filepath.Rel(root, e.Path)
		if rel == filepath.Join("a", "b") {
			if !e.Fix.Done {
				t.Errorf("a/b: Fix.Done = false, want true (FixFunc ran and reported Done)")
			}
			if !e.Fix.Applied {
				t.Error("a/b: Fix.Applied = false, want true")
			}
			if e.Fix.LogMsg == "" {
				t.Error("a/b: Fix.LogMsg empty, want the FixFunc's message")
			}
			sawFixedDone = true
			continue
		}
		// Every other directory's fast-path readdir succeeded without calling
		// FixFunc at all, so its Fix must be the zero value.
		if e.Fix != (FixResult{}) {
			t.Errorf("%s: Fix = %+v, want zero value (FixFunc never ran for it)", e.Path, e.Fix)
		}
		sawUnfixedDir = true
	}
	if !sawFixedDone {
		t.Fatal("never saw a/b's directory Entry")
	}
	if !sawUnfixedDir {
		t.Fatal("never saw a directory Entry that did not need fixing")
	}
}

func TestPrepassSymlinkDirSkipped(t *testing.T) {
	root := makeTree(t)
	os.Symlink(filepath.Join(root, "a"), filepath.Join(root, "link_to_a"))

	var mu sync.Mutex
	var fixed []string
	fixFunc := func(ref transport.Ref) (bool, string, FixResult) {
		mu.Lock()
		rel, _ := filepath.Rel(root, ref.Path)
		fixed = append(fixed, rel)
		mu.Unlock()
		return true, "", FixResult{}
	}

	nFixed := Prepass(root, nil, nil, PrepassOptions{Transport: kernelTransport(t, root), Fix: fixFunc, Workers: 4}).Fixed

	for _, f := range fixed {
		if f == "link_to_a" {
			t.Error("prepass should not follow symlink directory link_to_a")
		}
	}
	// All dirs already traversable, none needed fixing
	if nFixed != 0 {
		t.Errorf("prepass fixed = %d, want 0", nFixed)
	}
}

func TestEntryStatSymlink(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "link")
	os.Symlink("/nonexistent", link)

	e := Entry{Path: link, NeedStat: true}
	if !e.Stat() {
		t.Fatal("Stat() returned false for symlink")
	}
	if !e.IsSymlink {
		t.Error("IsSymlink should be true for symlink")
	}
	if e.IsDir {
		t.Error("IsDir should be false for symlink")
	}
}

func TestParallelWalkSkipDir(t *testing.T) {
	root := makeTree(t)
	skipTarget := filepath.Join(root, "a", "b")

	ch := make(chan Entry, 100)
	errs := &WalkErrors{}
	opts := &WalkOptions{
		SkipDir: func(dir string) bool { return dir == skipTarget },
	}
	go func() {
		ParallelWalk(root, ch, 4, errs, opts)
		close(ch)
	}()

	var paths []string
	for e := range ch {
		paths = append(paths, e.Path)
	}

	for _, p := range paths {
		rel, _ := filepath.Rel(root, p)
		if rel == "a/b" || rel == "a/b/c" || rel == "a/b/f2.txt" || rel == "a/b/c/f3.sh" {
			t.Errorf("skipped dir subtree should not appear: %s", rel)
		}
	}
}

func TestParallelWalkRegisterDir(t *testing.T) {
	root := makeTree(t)
	var mu sync.Mutex
	registered := map[string]int{}

	ch := make(chan Entry, 100)
	errs := &WalkErrors{}
	opts := &WalkOptions{
		RegisterDir: func(dir string, count int) {
			mu.Lock()
			registered[dir] = count
			mu.Unlock()
		},
	}
	go func() {
		ParallelWalk(root, ch, 4, errs, opts)
		close(ch)
	}()
	for range ch {
	}

	// root/a has 1 file (f1.txt) + 2 subdirs (b, d) = 3
	aDir := filepath.Join(root, "a")
	if c, ok := registered[aDir]; !ok || c != 3 {
		t.Errorf("a dir entryCount = %d, want 3", c)
	}
	// root/e has 1 file (f5.dat), 0 subdirs = 1
	eDir := filepath.Join(root, "e")
	if c, ok := registered[eDir]; !ok || c != 1 {
		t.Errorf("e dir entryCount = %d, want 1", c)
	}
}

func TestWalkErrorsOnBadDir(t *testing.T) {
	root := t.TempDir()
	bad := filepath.Join(root, "noaccess")
	os.Mkdir(bad, 0755)
	os.WriteFile(filepath.Join(bad, "file.txt"), []byte("x"), 0644)
	os.Chmod(bad, 0000)
	defer os.Chmod(bad, 0755)

	ch := make(chan Entry, 100)
	errs := &WalkErrors{}
	go func() {
		ParallelWalk(root, ch, 4, errs, nil)
		close(ch)
	}()
	for range ch {
	}

	if errs.Count() == 0 {
		t.Error("expected walk errors for unreadable directory")
	}
}

// collect drains ch into a sorted, comparable set of "path|kind" strings.
func collect(root string, ch <-chan Entry) []string {
	var got []string
	for e := range ch {
		rel, _ := filepath.Rel(root, e.Path)
		kind := "file"
		switch {
		case e.IsSymlink:
			kind = "symlink"
		case e.IsDir:
			kind = "dir"
		}
		got = append(got, rel+"|"+kind)
	}
	sort.Strings(got)
	return got
}

// The fused Prepass replaced a separate ParallelWalk sweep, so it must produce
// exactly the entry set that sweep produced — same paths, same dir/symlink
// tagging. This is the test that would catch the fusion dropping or duplicating
// entries; a difference here means the tree is being applied differently, not
// just enumerated differently.
func TestPrepassEmitsSameEntriesAsParallelWalk(t *testing.T) {
	root := makeTree(t)
	os.Symlink(filepath.Join(root, "a"), filepath.Join(root, "link_to_a"))

	walkCh := make(chan Entry, 200)
	go func() {
		ParallelWalk(root, walkCh, 4, &WalkErrors{}, nil)
		close(walkCh)
	}()
	want := collect(root, walkCh)

	tr := kernelTransport(t, root)
	fuseCh := make(chan Entry, 200)
	go func() {
		Prepass(root, fuseCh, &WalkErrors{}, PrepassOptions{
			Transport: tr,
			Fix:       func(transport.Ref) (bool, string, FixResult) { return true, "", FixResult{} },
			Workers:   4,
		})
		close(fuseCh)
	}()
	got := collect(root, fuseCh)

	if len(got) != len(want) {
		t.Fatalf("entry count = %d, want %d\n got: %v\nwant: %v", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// A directory that had to be fixed must still be enumerated. Before the fusion
// the fix and the enumeration were separate sweeps, so this could not regress;
// now a fix that returns without re-reading would silently drop a subtree.
func TestPrepassEmitsChildrenOfFixedDir(t *testing.T) {
	root := makeTree(t)
	locked := filepath.Join(root, "a", "b")
	os.Chmod(locked, 0000)
	defer os.Chmod(locked, 0755)

	tr := kernelTransport(t, root)
	ch := make(chan Entry, 200)
	var nFixed int
	go func() {
		nFixed = Prepass(root, ch, &WalkErrors{}, PrepassOptions{
			Transport: tr,
			Fix: func(r transport.Ref) (bool, string, FixResult) {
				return os.Chmod(r.Path, 0755) == nil, "OK", FixResult{}
			},
			Workers: 4,
		}).Fixed
		close(ch)
	}()
	got := collect(root, ch)

	if nFixed != 1 {
		t.Errorf("fixed = %d, want 1", nFixed)
	}
	for _, want := range []string{"a/b|dir", "a/b/f2.txt|file", "a/b/c|dir", "a/b/c/f3.sh|file"} {
		found := false
		for _, g := range got {
			if g == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing %q from fused walk of a fixed dir; got %v", want, got)
		}
	}
}

// A directory is emitted only after its own readdir, so the consumer cannot
// apply a restrictive ACL to it before its children have been discovered.
func TestPrepassEmitsDirAfterItsChildren(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "d"), 0755)
	os.WriteFile(filepath.Join(root, "d", "f.txt"), []byte("x"), 0644)

	tr := kernelTransport(t, root)
	ch := make(chan Entry, 50)
	go func() {
		Prepass(root, ch, &WalkErrors{}, PrepassOptions{
			Transport: tr,
			Fix:       func(transport.Ref) (bool, string, FixResult) { return true, "", FixResult{} },
			Workers:   1,
		})
		close(ch)
	}()

	var order []string
	for e := range ch {
		rel, _ := filepath.Rel(root, e.Path)
		order = append(order, rel)
	}

	iChild, iDir := -1, -1
	for i, p := range order {
		switch p {
		case "d/f.txt":
			iChild = i
		case "d":
			iDir = i
		}
	}
	if iChild == -1 || iDir == -1 {
		t.Fatalf("missing entries in %v", order)
	}
	if iDir < iChild {
		t.Errorf("dir 'd' emitted at %d, before its child at %d — a consumer could lock the walk out", iDir, iChild)
	}
}

// Fix-only mode drives the --pfind path, where an external enumerator owns the
// entry stream. Registering directories there would double-count against the
// checkpoint, so RegisterDir must stay silent.
func TestPrepassFixOnlyDoesNotRegisterDirs(t *testing.T) {
	root := makeTree(t)

	var mu sync.Mutex
	registered := 0
	opts := PrepassOptions{
		Transport:   kernelTransport(t, root),
		Fix:         func(transport.Ref) (bool, string, FixResult) { return true, "", FixResult{} },
		RegisterDir: func(string, int) { mu.Lock(); registered++; mu.Unlock() },
		Workers:     4,
	}

	if errs := Prepass(root, nil, nil, opts).Errors; errs != 0 {
		t.Errorf("fix-only errors = %d, want 0", errs)
	}
	if registered != 0 {
		t.Errorf("RegisterDir called %d times in fix-only mode, want 0", registered)
	}

	ch := make(chan Entry, 200)
	go func() {
		Prepass(root, ch, &WalkErrors{}, opts)
		close(ch)
	}()
	for range ch {
	}
	if registered == 0 {
		t.Error("RegisterDir never called in enumerating mode")
	}
}

// Fusing the fix into the enumeration removed the phase boundary whose two
// clocks used to show where a run's time went. These counters are the
// replacement, so they have to actually be wired to the calls they name — a
// zero here means the summary silently reports nothing useful.
func TestPrepassReportsFixAndReaddirTime(t *testing.T) {
	root := makeTree(t)
	locked := filepath.Join(root, "a", "b")
	os.Chmod(locked, 0000)
	defer os.Chmod(locked, 0755)

	tr := kernelTransport(t, root)
	ch := make(chan Entry, 200)
	var res PrepassResult
	go func() {
		res = Prepass(root, ch, &WalkErrors{}, PrepassOptions{
			Transport: tr,
			Fix:       func(r transport.Ref) (bool, string, FixResult) { return os.Chmod(r.Path, 0755) == nil, "", FixResult{} },
			Workers:   4,
		})
		close(ch)
	}()
	for range ch {
	}

	if res.ReaddirTime <= 0 {
		t.Error("ReaddirTime = 0, want > 0")
	}
	if res.FixTime <= 0 {
		t.Errorf("FixTime = %v, want > 0 — a dir needed fixing", res.FixTime)
	}
}

// A tree that needs no fixing must report no fix time, so the two figures stay
// separable rather than both tracking total work.
func TestPrepassNoFixMeansNoFixTime(t *testing.T) {
	root := makeTree(t)

	tr := kernelTransport(t, root)
	ch := make(chan Entry, 200)
	var res PrepassResult
	go func() {
		res = Prepass(root, ch, &WalkErrors{}, PrepassOptions{
			Transport: tr,
			Fix:       func(transport.Ref) (bool, string, FixResult) { return true, "", FixResult{} },
			Workers:   4,
		})
		close(ch)
	}()
	for range ch {
	}

	if res.Fixed != 0 {
		t.Errorf("Fixed = %d, want 0", res.Fixed)
	}
	if res.FixTime != 0 {
		t.Errorf("FixTime = %v, want 0 when nothing was fixed", res.FixTime)
	}
	if res.ReaddirTime <= 0 {
		t.Error("ReaddirTime = 0, want > 0")
	}
}

// fakeTransport serves a fixed in-memory tree, so the walk can be exercised
// without a filesystem and without an NFS server.
//
// attrs backs Stat. It is consulted only when a Dirent arrives with AttrsKnown
// false, which is how this fake reproduces the kernel transport's behavior; an
// entry with AttrsKnown true must never reach Stat at all, and a missing key is
// reported as an error rather than as a zero Attr so that a walk which stats
// when it should not is a visible failure instead of a silent FSID-zero compare.
type fakeTransport struct {
	dirs  map[string][]transport.Dirent
	attrs map[string]transport.Attr

	mu       sync.Mutex
	stats    []string // every path Stat was called on, in call order
	readdirs []string // every path ReadDir was called on, in call order
}

func (f *fakeTransport) Root() (transport.Ref, error) { return transport.Ref{Path: "/root"}, nil }

func (f *fakeTransport) ReadDir(r transport.Ref) ([]transport.Dirent, error) {
	f.mu.Lock()
	f.readdirs = append(f.readdirs, r.Path)
	f.mu.Unlock()
	ents, ok := f.dirs[r.Path]
	if !ok {
		return nil, fmt.Errorf("no such directory: %s", r.Path)
	}
	return ents, nil
}

func (f *fakeTransport) readDirCalledOn(path string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.readdirs {
		if p == path {
			return true
		}
	}
	return false
}

func (f *fakeTransport) Stat(r transport.Ref) (transport.Attr, error) {
	f.mu.Lock()
	f.stats = append(f.stats, r.Path)
	f.mu.Unlock()
	a, ok := f.attrs[r.Path]
	if !ok {
		return transport.Attr{}, fmt.Errorf("fakeTransport: no attrs for %s", r.Path)
	}
	return a, nil
}

func (f *fakeTransport) statCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.stats)
}

func (f *fakeTransport) ReadDirSetACL(ref transport.Ref, acl []byte) ([]transport.Dirent, bool, error) {
	entries, err := f.ReadDir(ref)
	if err != nil {
		return nil, false, err
	}
	if len(acl) > 0 {
		return entries, true, nil
	}
	return entries, false, nil
}
func (f *fakeTransport) SetACL(transport.Ref, []byte) error   { return nil }
func (f *fakeTransport) GetACL(transport.Ref) ([]byte, error) { return nil, nil }
func (f *fakeTransport) GetACLBatch(refs []transport.Ref) ([][]byte, error) {
	return make([][]byte, len(refs)), nil
}
func (f *fakeTransport) Chmod(transport.Ref, uint32) error   { return nil }
func (f *fakeTransport) Chown(transport.Ref, int, int) error { return nil }
func (f *fakeTransport) Close() error                        { return nil }

func (f *fakeTransport) ProbeTarget(transport.Ref) (transport.Ref, bool, func() error, error) {
	return transport.Ref{Path: "/root/probe"}, true, func() error { return nil }, nil
}

func TestPrepassEnumeratesThroughTheTransport(t *testing.T) {
	ft := &fakeTransport{
		dirs: map[string][]transport.Dirent{
			"/root": {
				{Name: "a.txt", Ref: transport.Ref{Path: "/root/a.txt", FH: []byte{1}}, AttrsKnown: true, Mode: 0o644, FSID: 7},
				{Name: "sub", Ref: transport.Ref{Path: "/root/sub", FH: []byte{2}}, IsDir: true, AttrsKnown: true, Mode: 0o755, FSID: 7},
				// A symlink to a directory, reported with IsDir AND IsSymlink both
				// set. The kernel transport leaves IsDir false here, but a
				// userspace ReadDir deriving IsDir straight from FATTR4_TYPE
				// could legitimately set both, and the walk must still refuse to
				// descend -- that is why walk.go tests IsSymlink first. Setting
				// both is what makes the trap.txt and ReadDir assertions below
				// load-bearing: with the branch order reversed, "/root/link" is
				// a readable directory in this fake, so the descent succeeds and
				// shows up in the output rather than erroring out.
				{Name: "link", Ref: transport.Ref{Path: "/root/link", FH: []byte{4}}, IsDir: true, IsSymlink: true, AttrsKnown: true, Mode: 0o777, FSID: 7},
				// A file whose attributes did NOT come back with the listing.
				// Mode here is deliberately non-zero and deliberately a lie:
				// AttrsKnown false means it was never asked for, so the walk
				// must not propagate it.
				{Name: "unknown.txt", Ref: transport.Ref{Path: "/root/unknown.txt", FH: []byte{5}}, Mode: 0o644},
			},
			"/root/sub": {
				{Name: "b.txt", Ref: transport.Ref{Path: "/root/sub/b.txt", FH: []byte{3}}, AttrsKnown: true, Mode: 0o600, FSID: 7},
			},
			"/root/link": {
				{Name: "trap.txt", Ref: transport.Ref{Path: "/root/link/trap.txt"}, AttrsKnown: true, Mode: 0o644, FSID: 7},
			},
		},
		// Only the root needs an Attr: it has no parent Dirent to carry one.
		attrs: map[string]transport.Attr{
			"/root": {Mode: 0o755, FSID: 7, IsDir: true},
		},
	}

	ch := make(chan Entry, 16)
	var errs WalkErrors
	res := Prepass("/root", ch, &errs, PrepassOptions{
		Transport: ft,
		Fix:       func(transport.Ref) (bool, string, FixResult) { return true, "", FixResult{} },
		Workers:   4,
	})
	close(ch)

	if res.Errors != 0 {
		t.Fatalf("Errors = %d, want 0", res.Errors)
	}

	got := map[string]Entry{}
	for e := range ch {
		got[e.Path] = e
	}
	for _, want := range []string{"/root", "/root/a.txt", "/root/sub", "/root/sub/b.txt", "/root/link", "/root/unknown.txt"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing entry %q; got %v", want, got)
		}
	}
	if !got["/root/sub"].IsDir {
		t.Error("/root/sub: IsDir = false")
	}

	// Symlinks are tagged and never followed. Asserted three ways because the
	// detection mechanism moved from an inline os.DirEntry mode test to the
	// Dirent.IsSymlink field, and the old test asserted only that the link was
	// absent from the fixed set -- which stayed true even with the symlink
	// branch deleted, since a readable directory needs no fixing.
	if !got["/root/link"].IsSymlink {
		t.Error("/root/link: IsSymlink = false, want true")
	}
	if got["/root/link"].IsDir {
		t.Error("/root/link: IsDir = true; a symlink to a directory must not be classified as one")
	}
	if _, ok := got["/root/link/trap.txt"]; ok {
		t.Error("/root/link/trap.txt was emitted: the walk descended through a symlink")
	}
	if ft.readDirCalledOn("/root/link") {
		t.Errorf("ReadDir was called on the symlink /root/link; calls: %v", ft.readdirs)
	}

	// The D1 guard: Dirent.Mode is meaningless when AttrsKnown is false, so it
	// must not reach Entry.Mode. Zero is what the apply workers read as "not
	// known", which makes them stat. Propagating 0o644 here would let a file
	// whose real mode differs be silently skipped under --compare.
	if m := got["/root/unknown.txt"].Mode; m != 0 {
		t.Errorf("unknown.txt Mode = 0%o, want 0: AttrsKnown was false, so the mode was never asked for", m)
	}
	if got["/root/sub/b.txt"].Mode != 0o600 {
		t.Errorf("b.txt Mode = 0%o, want 0600", got["/root/sub/b.txt"].Mode)
	}
	if len(got["/root/a.txt"].FH) != 1 || got["/root/a.txt"].FH[0] != 1 {
		t.Errorf("a.txt FH = %v, want [1]", got["/root/a.txt"].FH)
	}
	if got["/root/a.txt"].NeedStat {
		t.Error("NeedStat must be false: Prepass emits files unstat'ed on both transports")
	}

	// The stat budget from Step 4's count. Only the root is stat'ed, because it
	// has no parent Dirent to carry its mode. Every other object's attributes
	// arrived with the listing, and RootFSID is zero here so no boundary check
	// runs. A regression that stats per entry shows up as a number, not a hang.
	if n := ft.statCount(); n != 1 {
		t.Errorf("Stat called %d times, want 1 (the root only); calls: %v", n, ft.stats)
	}
}

// TestPrepassSkipsOtherFilesystems covers the AttrsKnown == true branch of
// sameFilesystem — the branch the userspace transport always takes, where FSID
// came free in the READDIR bitmask.
//
// Every Dirent therefore sets AttrsKnown, and it is load-bearing: with it unset
// the fake's Stat is consulted, both children compare unequal to RootFSID, and
// the test passes while proving nothing. It would keep passing with the boundary
// check deleted outright. The positive assertion on /root/same is what makes the
// negative one mean something.
func TestPrepassSkipsOtherFilesystems(t *testing.T) {
	ft := &fakeTransport{
		dirs: map[string][]transport.Dirent{
			"/root": {
				{Name: "same", Ref: transport.Ref{Path: "/root/same"}, IsDir: true, AttrsKnown: true, Mode: 0o755, FSID: 7},
				{Name: "other", Ref: transport.Ref{Path: "/root/other"}, IsDir: true, AttrsKnown: true, Mode: 0o755, FSID: 99},
			},
			"/root/same":  {},
			"/root/other": {{Name: "hidden", Ref: transport.Ref{Path: "/root/other/hidden"}, AttrsKnown: true, FSID: 99}},
		},
		attrs: map[string]transport.Attr{
			"/root": {Mode: 0o755, FSID: 7, IsDir: true},
		},
	}

	ch := make(chan Entry, 16)
	var errs WalkErrors
	registered := map[string]int{}
	var mu sync.Mutex
	Prepass("/root", ch, &errs, PrepassOptions{
		Transport: ft,
		Fix:       func(transport.Ref) (bool, string, FixResult) { return true, "", FixResult{} },
		Workers:   4,
		RootFSID:  7,
		RegisterDir: func(d string, n int) {
			mu.Lock()
			registered[d] = n
			mu.Unlock()
		},
	})
	close(ch)

	seen := map[string]bool{}
	for e := range ch {
		seen[e.Path] = true
	}
	if seen["/root/other/hidden"] {
		t.Error("descended across a filesystem boundary")
	}
	if !seen["/root/same"] {
		t.Error("/root/same was skipped; the boundary check rejected a same-filesystem child")
	}
	// The other filesystem is never emitted, so it never signals completion;
	// counting it would keep /root from ever completing in a checkpoint.
	if registered["/root"] != 1 {
		t.Errorf("/root registered with %d children, want 1 (other filesystem not counted)", registered["/root"])
	}
	// AttrsKnown was true on both children, so the Stat branch must not have run
	// for either of them. Only the root is stat'ed.
	if n := ft.statCount(); n != 1 {
		t.Errorf("Stat called %d times, want 1; sameFilesystem stat'ed a child whose FSID it already had: %v", n, ft.stats)
	}
}

// TestPrepassStatsForTheBoundaryWhenAttrsAreUnknown covers the other branch —
// the kernel transport, where ReadDir does not stat and sameFilesystem has to
// pay for one round trip per subdirectory. That cost is the pre-transport
// behavior and is budgeted; what must not happen is a swallowed error.
func TestPrepassStatsForTheBoundaryWhenAttrsAreUnknown(t *testing.T) {
	ft := &fakeTransport{
		dirs: map[string][]transport.Dirent{
			"/root": {
				{Name: "same", Ref: transport.Ref{Path: "/root/same"}, IsDir: true},
				{Name: "other", Ref: transport.Ref{Path: "/root/other"}, IsDir: true},
				{Name: "broken", Ref: transport.Ref{Path: "/root/broken"}, IsDir: true},
			},
			"/root/same":   {},
			"/root/other":  {{Name: "hidden", Ref: transport.Ref{Path: "/root/other/hidden"}}},
			"/root/broken": {{Name: "hidden2", Ref: transport.Ref{Path: "/root/broken/hidden2"}}},
		},
		// /root/broken is deliberately absent, so its Stat fails.
		attrs: map[string]transport.Attr{
			"/root":       {Mode: 0o755, FSID: 7, IsDir: true},
			"/root/same":  {Mode: 0o755, FSID: 7, IsDir: true},
			"/root/other": {Mode: 0o755, FSID: 99, IsDir: true},
		},
	}

	ch := make(chan Entry, 16)
	var errs WalkErrors
	Prepass("/root", ch, &errs, PrepassOptions{
		Transport: ft,
		Fix:       func(transport.Ref) (bool, string, FixResult) { return true, "", FixResult{} },
		Workers:   4,
		RootFSID:  7,
	})
	close(ch)

	seen := map[string]bool{}
	for e := range ch {
		seen[e.Path] = true
	}
	if !seen["/root/same"] {
		t.Error("/root/same was skipped despite matching FSID")
	}
	if seen["/root/other/hidden"] {
		t.Error("descended across a filesystem boundary")
	}
	if seen["/root/broken/hidden2"] {
		t.Error("descended into a subtree whose FSID could not be determined")
	}
	// This is finding 4 of the Task 1 review, in its walk-layer form: a subtree
	// skipped because Stat failed must raise the error count, or the run reports
	// success on a tree it never read and exits zero.
	if errs.Count() == 0 {
		t.Error("a failed boundary Stat skipped a subtree without counting an error; the run would exit 0")
	}
}

// TestKernelWalkCarriesNoFilehandle is the proof that Task 12b left the kernel
// transport alone rather than the assertion that it did.
//
// Threading transport.Ref through apply only changes behavior where a filehandle
// exists. On the kernel transport none does: getdents supplies a name and a type
// and nothing more, so every Dirent.Ref.FH is nil, every Entry.FH is nil, and
// Entry.Ref() therefore reconstructs exactly the transport.Ref{Path: path} that
// apply used to fabricate for itself. Every kernel call site sees the identical
// value it saw before the signature change, which is why the log strings the
// internal/apply tests pin are unchanged.
func TestKernelWalkCarriesNoFilehandle(t *testing.T) {
	root := makeTree(t)
	tr := kernelTransport(t, root)

	rootRef, err := tr.Root()
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	if rootRef.FH != nil {
		t.Errorf("kernel Root().FH = %x, want nil", rootRef.FH)
	}

	ents, err := tr.ReadDir(rootRef)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(ents) == 0 {
		t.Fatal("ReadDir returned nothing; the rest of this test would be vacuous")
	}
	for _, e := range ents {
		if e.Ref.FH != nil {
			t.Errorf("kernel ReadDir %q returned FH %x, want nil", e.Name, e.Ref.FH)
		}
	}

	ch := make(chan Entry, 256)
	var consumer sync.WaitGroup
	var mu sync.Mutex
	var seen int
	consumer.Add(1)
	go func() {
		defer consumer.Done()
		for e := range ch {
			mu.Lock()
			seen++
			if e.FH != nil {
				t.Errorf("kernel walk emitted %s with FH %x, want nil", e.Path, e.FH)
			}
			// This is the value apply now receives. It must equal the literal
			// apply used to build from the path alone.
			ref := e.Ref()
			if ref.Path != e.Path || ref.FH != nil {
				t.Errorf("Entry.Ref() = {Path:%q FH:%x}, want {Path:%q FH:nil}", ref.Path, ref.FH, e.Path)
			}
			mu.Unlock()
		}
	}()

	fixFunc := func(ref transport.Ref) (bool, string, FixResult) { return true, "", FixResult{} }
	Prepass(root, ch, nil, PrepassOptions{Transport: tr, Fix: fixFunc, Workers: 4})
	close(ch)
	consumer.Wait()

	mu.Lock()
	defer mu.Unlock()
	// 5 files plus 6 directories (root, a, a/b, a/b/c, a/d, e).
	if seen != 11 {
		t.Fatalf("walk emitted %d entries, want 11", seen)
	}
}

// An excluded directory is pruned: neither it nor anything beneath it reaches
// the consumer. The pruning is what makes an exclude cheap, so the assertion is
// on the child too, not just on the directory.
func TestPrepassPrunesExcludedDirectory(t *testing.T) {
	root := makeTree(t)
	tr := kernelTransport(t, root)
	ch := make(chan Entry, 200)
	var excluded []string
	var mu sync.Mutex
	go func() {
		Prepass(root, ch, &WalkErrors{}, PrepassOptions{
			Transport: tr,
			Fix:       func(transport.Ref) (bool, string, FixResult) { return true, "", FixResult{} },
			Workers:   4,
			Exclude: func(p string) bool {
				if filepath.Base(p) != "b" {
					return false
				}
				mu.Lock()
				excluded = append(excluded, p)
				mu.Unlock()
				return true
			},
		})
		close(ch)
	}()
	got := collect(root, ch)

	for _, g := range got {
		if strings.HasPrefix(g, "a/b") {
			t.Errorf("excluded subtree leaked entry %q", g)
		}
	}
	for _, want := range []string{"a|dir", "a/f1.txt|file", "a/d|dir", "e|dir"} {
		if !contains(got, want) {
			t.Errorf("missing in-scope entry %q; got %v", want, got)
		}
	}
	// The predicate is consulted exactly once per candidate path, which is what
	// lets the caller count exclusions from inside it.
	if len(excluded) != 1 {
		t.Errorf("exclude predicate fired %d times for one directory, want 1: %v", len(excluded), excluded)
	}
}

func TestPrepassExcludesFiles(t *testing.T) {
	root := makeTree(t)
	tr := kernelTransport(t, root)
	ch := make(chan Entry, 200)
	go func() {
		Prepass(root, ch, &WalkErrors{}, PrepassOptions{
			Transport: tr,
			Fix:       func(transport.Ref) (bool, string, FixResult) { return true, "", FixResult{} },
			Workers:   4,
			Exclude:   func(p string) bool { return filepath.Ext(p) == ".txt" },
		})
		close(ch)
	}()
	got := collect(root, ch)
	for _, g := range got {
		if strings.HasSuffix(g, ".txt|file") {
			t.Errorf("excluded file leaked: %q", g)
		}
	}
	if !contains(got, "a/b/c/f3.sh|file") || !contains(got, "e/f5.dat|file") {
		t.Errorf("non-matching files must survive; got %v", got)
	}
}

// Excluded entries must not be counted in the per-directory entry count: that
// count is how many completion signals the checkpoint waits for, and an entry no
// consumer ever sees never signals, so counting it would leave the parent
// permanently incomplete.
func TestPrepassExcludedEntriesAreNotRegistered(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "keep"), 0755)
	os.MkdirAll(filepath.Join(root, "drop"), 0755)
	os.WriteFile(filepath.Join(root, "f.txt"), []byte("x"), 0644)

	tr := kernelTransport(t, root)
	ch := make(chan Entry, 100)
	counts := map[string]int{}
	var mu sync.Mutex
	go func() {
		Prepass(root, ch, &WalkErrors{}, PrepassOptions{
			Transport: tr,
			Fix:       func(transport.Ref) (bool, string, FixResult) { return true, "", FixResult{} },
			Workers:   1,
			Exclude:   func(p string) bool { return filepath.Base(p) == "drop" },
			RegisterDir: func(dir string, n int) {
				mu.Lock()
				counts[dir] = n
				mu.Unlock()
			},
		})
		close(ch)
	}()
	collect(root, ch)

	if got := counts[root]; got != 2 {
		t.Errorf("root entry count = %d, want 2 (keep + f.txt, not the excluded dir)", got)
	}
}

func TestParallelWalkExcludes(t *testing.T) {
	root := makeTree(t)
	ch := make(chan Entry, 200)
	go func() {
		ParallelWalk(root, ch, 4, &WalkErrors{}, &WalkOptions{
			Exclude: func(p string) bool { return filepath.Base(p) == "b" },
		})
		close(ch)
	}()
	got := collect(root, ch)
	for _, g := range got {
		if strings.HasPrefix(g, "a/b") {
			t.Errorf("excluded subtree leaked entry %q", g)
		}
	}
	if !contains(got, "a/d|dir") {
		t.Errorf("in-scope sibling missing; got %v", got)
	}
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

func TestParallelWalkNewlineInFilename(t *testing.T) {
	root := t.TempDir()
	name := "file\nwith\nnewlines.txt"
	if err := os.WriteFile(filepath.Join(root, name), []byte("x"), 0644); err != nil {
		t.Fatalf("create file with newline: %v", err)
	}

	ch := make(chan Entry, 100)
	errs := &WalkErrors{}
	go func() {
		ParallelWalk(root, ch, 4, errs, nil)
		close(ch)
	}()

	var found bool
	for e := range ch {
		if filepath.Base(e.Path) == name {
			found = true
			if e.IsDir || e.IsSymlink {
				t.Error("newline file misclassified")
			}
		}
	}
	if !found {
		t.Error("file with newlines in name was not enumerated")
	}
	if errs.Count() != 0 {
		t.Errorf("walk errors = %d, want 0", errs.Count())
	}
}

func TestParallelWalkSpecialFileFIFO(t *testing.T) {
	root := t.TempDir()
	fifo := filepath.Join(root, "pipe")
	if err := syscall.Mkfifo(fifo, 0644); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}

	ch := make(chan Entry, 100)
	errs := &WalkErrors{}
	go func() {
		ParallelWalk(root, ch, 4, errs, nil)
		close(ch)
	}()

	var found bool
	for e := range ch {
		if filepath.Base(e.Path) == "pipe" {
			found = true
			if e.IsDir {
				t.Error("FIFO classified as directory")
			}
			if e.IsSymlink {
				t.Error("FIFO classified as symlink")
			}
		}
	}
	if !found {
		t.Error("FIFO was not enumerated")
	}
	if errs.Count() != 0 {
		t.Errorf("walk errors = %d, want 0", errs.Count())
	}
}

func TestParallelWalkDeletionDuringTraversal(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 5; i++ {
		sub := filepath.Join(root, fmt.Sprintf("d%d", i))
		os.Mkdir(sub, 0755)
		for j := 0; j < 10; j++ {
			os.WriteFile(filepath.Join(sub, fmt.Sprintf("f%d", j)), []byte("x"), 0644)
		}
	}
	victim := filepath.Join(root, "d0")

	ch := make(chan Entry, 200)
	errs := &WalkErrors{}
	var deleteOnce sync.Once
	go func() {
		ParallelWalk(root, ch, 1, errs, &WalkOptions{
			RegisterDir: func(dir string, _ int) {
				deleteOnce.Do(func() {
					os.RemoveAll(victim)
				})
			},
		})
		close(ch)
	}()
	for range ch {
	}
	// Walk must complete without panic. Errors are acceptable — a deleted
	// subtree may produce walk errors, or it may have been enumerated before
	// the deletion. Either outcome is correct.
}

func TestParallelWalkRenameDuringTraversal(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 5; i++ {
		sub := filepath.Join(root, fmt.Sprintf("d%d", i))
		os.Mkdir(sub, 0755)
		for j := 0; j < 10; j++ {
			os.WriteFile(filepath.Join(sub, fmt.Sprintf("f%d", j)), []byte("x"), 0644)
		}
	}

	ch := make(chan Entry, 200)
	errs := &WalkErrors{}
	var renameOnce sync.Once
	go func() {
		ParallelWalk(root, ch, 1, errs, &WalkOptions{
			RegisterDir: func(dir string, _ int) {
				renameOnce.Do(func() {
					os.Rename(filepath.Join(root, "d1"), filepath.Join(root, "d1_renamed"))
				})
			},
		})
		close(ch)
	}()
	for range ch {
	}
	// Walk must complete without panic. The renamed directory may appear
	// under its old name, new name, both, or neither depending on timing.
	// Errors from a missing directory are acceptable.
}

// fakePfind writes a shell script named "pfind" into a temp directory and
// prepends it to PATH so exec.LookPath finds it. Returns cleanup via t.Setenv.
func fakePfind(t *testing.T, script string) {
	t.Helper()
	bin := t.TempDir()
	path := filepath.Join(bin, "pfind")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
}

func TestPfindNotFoundFallsBackToParallelWalk(t *testing.T) {
	// Empty PATH so LookPath cannot find pfind.
	t.Setenv("PATH", t.TempDir())
	root := makeTree(t)
	ch := make(chan Entry, 256)
	var errs WalkErrors
	go func() {
		if err := Pfind(root, ch, &errs, nil); err != nil {
			t.Errorf("Pfind fallback error: %v", err)
		}
		close(ch)
	}()
	var n int
	for range ch {
		n++
	}
	if n == 0 {
		t.Fatal("Pfind with no pfind binary should fall back to ParallelWalk and enumerate entries")
	}
}

func TestPfindNonzeroExitReportsError(t *testing.T) {
	fakePfind(t, "exit 1")
	root := makeTree(t)
	ch := make(chan Entry, 256)
	var errs WalkErrors
	err := Pfind(root, ch, &errs, nil)
	// Drain any entries that arrived before the exit.
	close(ch)
	for range ch {
	}
	if err == nil && errs.Count() == 0 {
		t.Fatal("pfind exiting 1 should produce an error or walk error")
	}
}

func TestPfindOutputIsParsed(t *testing.T) {
	root := makeTree(t)
	// Fake pfind that outputs known paths, one per line.
	script := fmt.Sprintf("find %q -mindepth 1", root)
	fakePfind(t, script)

	// Verify our fake pfind is found.
	if _, err := exec.LookPath("pfind"); err != nil {
		t.Fatalf("fake pfind not on PATH: %v", err)
	}

	ch := make(chan Entry, 4096)
	var errs WalkErrors
	go func() {
		if err := Pfind(root, ch, &errs, nil); err != nil {
			t.Errorf("Pfind error: %v", err)
		}
		close(ch)
	}()
	var paths []string
	for e := range ch {
		paths = append(paths, e.Path)
	}
	if len(paths) == 0 {
		t.Fatal("pfind produced no entries")
	}
	if errs.Count() != 0 {
		t.Errorf("walk errors = %d, want 0", errs.Count())
	}
	for _, p := range paths {
		if !strings.HasPrefix(p, root) {
			t.Errorf("entry %q does not start with root %q", p, root)
		}
	}
}
