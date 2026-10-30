package walk

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/checkpoint"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// PS-11: bounded directory enumeration. These tests prove that a batching
// transport is read batch by batch, that no child is lost or duplicated, that a
// directory still reaches the consumer only after its whole listing, and that a
// stalled consumer neither deadlocks the walk nor multiplies its goroutines or
// open directory handles.

// batchingFake adds a DirBatcher to fakeTransport. It records the largest
// batch it handed out and can fail one directory's listing after failAfter
// batches, which is the partial-listing case the kernel transport can hit.
type batchingFake struct {
	*fakeTransport
	failDir   string
	failAfter int

	mu       sync.Mutex
	maxBatch int
}

func (b *batchingFake) ReadDirBatches(r transport.Ref, n int, fn func([]transport.Dirent) error) (bool, error) {
	ents, err := b.fakeTransport.ReadDir(r)
	if err != nil {
		return false, err
	}
	delivered := false
	for i, k := 0, 0; i < len(ents); i, k = i+n, k+1 {
		if r.Path == b.failDir && k == b.failAfter {
			return delivered, errors.New("injected listing failure")
		}
		j := min(i+n, len(ents))
		b.mu.Lock()
		b.maxBatch = max(b.maxBatch, j-i)
		b.mu.Unlock()
		delivered = true
		if err := fn(ents[i:j]); err != nil {
			return delivered, err
		}
	}
	return delivered, nil
}

// wideFake is a root holding files regular files and dirs subdirectories, each
// subdirectory holding one file.
func wideFake(files, dirs int) *fakeTransport {
	ft := &fakeTransport{dirs: map[string][]transport.Dirent{}, attrs: map[string]transport.Attr{}}
	var root []transport.Dirent
	for i := 0; i < files; i++ {
		p := fmt.Sprintf("/root/f%06d", i)
		root = append(root, transport.Dirent{Name: filepath.Base(p), Ref: transport.Ref{Path: p}, AttrsKnown: true, Mode: 0o644})
	}
	for i := 0; i < dirs; i++ {
		p := fmt.Sprintf("/root/d%04d", i)
		root = append(root, transport.Dirent{Name: filepath.Base(p), Ref: transport.Ref{Path: p}, IsDir: true, AttrsKnown: true, Mode: 0o755})
		ft.dirs[p] = []transport.Dirent{{Name: "x", Ref: transport.Ref{Path: p + "/x"}, AttrsKnown: true, Mode: 0o644}}
	}
	ft.dirs["/root"] = root
	ft.attrs["/root"] = transport.Attr{Mode: 0o755, IsDir: true}
	return ft
}

func drain(ch <-chan Entry) map[string]int {
	seen := map[string]int{}
	for e := range ch {
		seen[e.Path]++
	}
	return seen
}

func TestPrepassBatchesBoundTheListingAsADirectoryGrows(t *testing.T) {
	const batch = 64
	for _, files := range []int{1000, 10000} {
		t.Run(strconv.Itoa(files), func(t *testing.T) {
			bf := &batchingFake{fakeTransport: wideFake(files, 10)}
			ch := make(chan Entry, 16)
			var mu sync.Mutex
			registered := map[string]int{}
			var res PrepassResult
			go func() {
				res = Prepass("/root", ch, &WalkErrors{}, PrepassOptions{
					Transport:    bf,
					Fix:          func(transport.Ref) (bool, string, FixResult) { return true, "", FixResult{} },
					Workers:      4,
					ReadDirBatch: batch,
					RegisterDir: func(dir string, n int) {
						mu.Lock()
						registered[dir] = n
						mu.Unlock()
					},
				})
				close(ch)
			}()
			seen := drain(ch)

			if bf.maxBatch > batch {
				t.Errorf("largest batch %d, want <= %d", bf.maxBatch, batch)
			}
			// root + its files + 10 dirs + one file in each.
			if want := 1 + files + 10 + 10; len(seen) != want {
				t.Errorf("emitted %d distinct paths, want %d", len(seen), want)
			}
			for p, n := range seen {
				if n != 1 {
					t.Errorf("%s emitted %d times", p, n)
				}
			}
			if registered["/root"] != files+10 {
				t.Errorf("root registered with %d children, want %d", registered["/root"], files+10)
			}
			if res.ReaddirErrors != 0 || res.Errors != 0 {
				t.Errorf("errors: %+v", res)
			}
		})
	}
}

// A listing that fails after handing on some children must not be fixed and
// retried (the children would go out twice) and must not be registered (the
// checkpoint would complete a directory it never fully read).
func TestPrepassPartialListingIsAnErrorNotARetry(t *testing.T) {
	ft := wideFake(0, 1)
	var sub []transport.Dirent
	for i := 0; i < 5; i++ {
		p := fmt.Sprintf("/root/d0000/f%d", i)
		sub = append(sub, transport.Dirent{Name: filepath.Base(p), Ref: transport.Ref{Path: p}, AttrsKnown: true, Mode: 0o644})
	}
	ft.dirs["/root/d0000"] = sub
	bf := &batchingFake{fakeTransport: ft, failDir: "/root/d0000", failAfter: 1}

	var fixes atomic.Int32
	var mu sync.Mutex
	registered := map[string]bool{}
	errs := &WalkErrors{}
	ch := make(chan Entry, 64)
	var res PrepassResult
	go func() {
		res = Prepass("/root", ch, errs, PrepassOptions{
			Transport: bf,
			Fix: func(transport.Ref) (bool, string, FixResult) {
				fixes.Add(1)
				return true, "", FixResult{}
			},
			Workers:      2,
			ReadDirBatch: 2,
			RegisterDir: func(dir string, _ int) {
				mu.Lock()
				registered[dir] = true
				mu.Unlock()
			},
		})
		close(ch)
	}()
	seen := drain(ch)

	if fixes.Load() != 0 {
		t.Errorf("Fix called %d times on a partial listing, want 0", fixes.Load())
	}
	for _, p := range []string{"/root/d0000/f0", "/root/d0000/f1"} {
		if seen[p] != 1 {
			t.Errorf("%s emitted %d times, want 1", p, seen[p])
		}
	}
	if seen["/root/d0000"] != 1 {
		t.Errorf("the partly listed directory itself emitted %d times, want 1", seen["/root/d0000"])
	}
	if registered["/root/d0000"] {
		t.Error("partly listed directory was registered; a checkpoint could mark it complete")
	}
	if !registered["/root"] {
		t.Error("root not registered")
	}
	if errs.Count() != 1 || res.ReaddirErrors != 1 {
		t.Errorf("errs=%d ReaddirErrors=%d, want 1 and 1", errs.Count(), res.ReaddirErrors)
	}
}

// The ordering guarantee under batching: a consumer that makes every directory
// unreadable (no r) the moment it receives it still gets every child, because a
// directory is emitted only after all of its batches.
//
// It keeps traverse (x) on purpose. A directory is emitted while child
// goroutines it spawned may still be listing below it, and on the kernel
// transport they resolve by path, so a consumer that removed traverse could
// still lock them out. That hazard predates PS-11 and is unchanged by it: see
// Prepass's ORDERING HAZARD comment, and apply.CheckTraversePreserved, which
// refuses specs that would do it.
func TestPrepassRestrictiveApplyCannotLockOutABatchedListing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	root := t.TempDir()
	want := map[string]bool{}
	wide := filepath.Join(root, "wide")
	os.Mkdir(wide, 0o755)
	want[wide] = true
	for i := 0; i < 40; i++ {
		d := filepath.Join(wide, fmt.Sprintf("d%02d", i))
		os.Mkdir(d, 0o755)
		want[d] = true
		for j := 0; j < 3; j++ {
			f := filepath.Join(d, fmt.Sprintf("f%d", j))
			os.WriteFile(f, nil, 0o644)
			want[f] = true
		}
	}
	for i := 0; i < 100; i++ {
		f := filepath.Join(wide, fmt.Sprintf("f%03d", i))
		os.WriteFile(f, nil, 0o644)
		want[f] = true
	}
	var locked []string
	t.Cleanup(func() {
		// Parents were locked after their children: unlock them first.
		for i := len(locked) - 1; i >= 0; i-- {
			os.Chmod(locked[i], 0o755)
		}
	})

	ch := make(chan Entry)
	errs := &WalkErrors{}
	go func() {
		Prepass(root, ch, errs, PrepassOptions{
			Transport:    kernelTransport(t, root),
			Fix:          func(transport.Ref) (bool, string, FixResult) { return false, "", FixResult{} },
			Workers:      2,
			ReadDirBatch: 8,
		})
		close(ch)
	}()
	got := map[string]bool{}
	for e := range ch {
		got[e.Path] = true
		if e.IsDir && e.Path != root {
			if err := os.Chmod(e.Path, 0o311); err == nil {
				locked = append(locked, e.Path)
			}
		}
	}
	for p := range want {
		if !got[p] {
			t.Errorf("never emitted: %s", p)
		}
	}
	if errs.Count() != 0 {
		t.Errorf("walk errors = %d, want 0", errs.Count())
	}
}

func openFDs(t *testing.T) int {
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip("no /proc/self/fd")
	}
	return len(ents)
}

// With worker tokens exhausted and the consumer stalled, the walk must finish
// without deadlock, with goroutines capped by the token pool and at most one
// open listing per goroutine, on a tree both deep and wide.
func TestPrepassStalledConsumerStaysBounded(t *testing.T) {
	root := t.TempDir()
	total := 1 // root
	dir := root
	for i := 0; i < 40; i++ {
		for j := 0; j < 3; j++ {
			os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%d", j)), nil, 0o644)
			total++
		}
		for j := 0; j < 2; j++ {
			sib := filepath.Join(dir, fmt.Sprintf("s%d", j))
			os.Mkdir(sib, 0o755)
			os.WriteFile(filepath.Join(sib, "x"), nil, 0o644)
			total += 2
		}
		dir = filepath.Join(dir, "deep")
		os.Mkdir(dir, 0o755)
		total++
	}
	for i := 0; i < 3000; i++ {
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("w%04d", i)), nil, 0o644)
		total++
	}

	const workers = 4
	tr := kernelTransport(t, root)
	runtime.GC()
	baseG, baseFD := runtime.NumGoroutine(), openFDs(t)

	var maxG, maxFD atomic.Int64
	stopSample := make(chan struct{})
	sampled := make(chan struct{})
	go func() {
		defer close(sampled)
		for {
			select {
			case <-stopSample:
				return
			default:
			}
			if g := int64(runtime.NumGoroutine()); g > maxG.Load() {
				maxG.Store(g)
			}
			if n, err := os.ReadDir("/proc/self/fd"); err == nil && int64(len(n)) > maxFD.Load() {
				maxFD.Store(int64(len(n)))
			}
			time.Sleep(200 * time.Microsecond)
		}
	}()

	ch := make(chan Entry) // unbuffered: every send waits on the consumer
	done := make(chan struct{})
	go func() {
		Prepass(root, ch, &WalkErrors{}, PrepassOptions{
			Transport:    tr,
			Fix:          func(transport.Ref) (bool, string, FixResult) { return true, "", FixResult{} },
			Workers:      workers,
			ReadDirBatch: 16,
		})
		close(ch)
		close(done)
	}()
	n := 0
	timeout := time.After(60 * time.Second)
loop:
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				break loop
			}
			n++
			if n%50 == 0 {
				time.Sleep(time.Millisecond) // a consumer slower than the walk
			}
		case <-timeout:
			buf := make([]byte, 1<<20)
			t.Fatalf("walk did not finish (deadlock?) after %d entries\n%s", n, buf[:runtime.Stack(buf, true)])
		}
	}
	<-done
	close(stopSample)
	<-sampled

	if n != total {
		t.Errorf("emitted %d entries, want %d", n, total)
	}
	// Extra goroutines: the producer, the sampler and one per token.
	if extra := maxG.Load() - int64(baseG); extra > workers+2 {
		t.Errorf("peak goroutines %d above baseline, want <= %d", extra, workers+2)
	}
	// Open handles: one listing per goroutine in process (tokens + the
	// producer), plus the sampler's own /proc/self/fd read.
	if extra := maxFD.Load() - int64(baseFD); extra > workers+2 {
		t.Errorf("peak open fds %d above baseline, want <= %d", extra, workers+2)
	}
}

func TestParallelWalkListsAcrossBatches(t *testing.T) {
	root := t.TempDir()
	const files = 2*DefaultReadDirBatch + 7
	for i := 0; i < files; i++ {
		os.WriteFile(filepath.Join(root, fmt.Sprintf("f%05d", i)), nil, 0o644)
	}
	ch := make(chan Entry, 64)
	var count int
	go func() {
		ParallelWalk(root, ch, 4, &WalkErrors{}, &WalkOptions{RegisterDir: func(_ string, n int) { count = n }})
		close(ch)
	}()
	seen := drain(ch)
	if len(seen) != files+1 || count != files {
		t.Errorf("emitted %d, registered %d; want %d and %d", len(seen), count, files+1, files)
	}
}

// noBatch hides the kernel transport's DirBatcher, giving the pre-PS-11
// whole-listing behavior for comparison.
type noBatch struct{ transport.Transport }

// TestWideDirectoryHeapMeasure is the opt-in memory measurement behind PS-11's
// acceptance criterion: peak heap while walking one directory of N files, at N
// and 10N, with and without batching. Set WALK_WIDE_MEASURE=1 (and TMPDIR to a
// disk with room for 220K empty files).
func TestWideDirectoryHeapMeasure(t *testing.T) {
	if os.Getenv("WALK_WIDE_MEASURE") == "" {
		t.Skip("set WALK_WIDE_MEASURE=1 to measure")
	}
	type row struct {
		files int
		mode  string
		peak  uint64
		dur   time.Duration
	}
	var rows []row
	for _, files := range []int{20000, 200000} {
		root := t.TempDir()
		wide := filepath.Join(root, "wide")
		os.Mkdir(wide, 0o755)
		for i := 0; i < files; i++ {
			// ~100-byte paths, like the live trees.
			name := fmt.Sprintf("file-%08d-padding-padding-padding-padding-padding.txt", i)
			if err := os.WriteFile(filepath.Join(wide, name), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		k := kernelTransport(t, root)
		for _, mode := range []string{"whole", "batched"} {
			var tr transport.Transport = k
			if mode == "whole" {
				tr = noBatch{k}
			}
			runtime.GC()
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			base := ms.HeapInuse
			var peak atomic.Uint64
			stop := make(chan struct{})
			sampled := make(chan struct{})
			go func() {
				defer close(sampled)
				var m runtime.MemStats
				for {
					select {
					case <-stop:
						return
					default:
					}
					runtime.ReadMemStats(&m)
					if m.HeapInuse > base && m.HeapInuse-base > peak.Load() {
						peak.Store(m.HeapInuse - base)
					}
					time.Sleep(time.Millisecond)
				}
			}()
			ch := make(chan Entry, 128)
			start := time.Now()
			go func() {
				Prepass(root, ch, &WalkErrors{}, PrepassOptions{
					Transport: tr,
					Fix:       func(transport.Ref) (bool, string, FixResult) { return true, "", FixResult{} },
					Workers:   4,
				})
				close(ch)
			}()
			n := 0
			for range ch {
				n++
			}
			dur := time.Since(start)
			close(stop)
			<-sampled
			if n != files+2 {
				t.Fatalf("%s: emitted %d, want %d", mode, n, files+2)
			}
			rows = append(rows, row{files, mode, peak.Load(), dur})
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].mode < rows[j].mode })
	t.Logf("%-8s %8s %12s %10s", "mode", "files", "peak heap", "elapsed")
	for _, r := range rows {
		t.Logf("%-8s %8d %9.1f MiB %10s", r.mode, r.files, float64(r.peak)/(1<<20), r.dur.Round(time.Millisecond))
	}
}

// A checkpointed walk completes every directory and leaves no pending state,
// however the apply side's completions race the walk's RegisterDir calls.
// Before PS-11 a completion that beat RegisterDir was dropped: the directory
// and all its ancestors stayed pending for the rest of the run and were never
// recorded, so a resume redid them.
func TestCheckpointedWalkCompletesEveryDirectory(t *testing.T) {
	root := t.TempDir()
	dirs := []string{root}
	for i := 0; i < 20; i++ {
		d := filepath.Join(root, fmt.Sprintf("d%02d", i))
		os.Mkdir(d, 0o755)
		dirs = append(dirs, d)
		for j := 0; j < 50; j++ {
			os.WriteFile(filepath.Join(d, fmt.Sprintf("f%d", j)), nil, 0o644)
		}
		sub := filepath.Join(d, "sub")
		os.Mkdir(sub, 0o755)
		dirs = append(dirs, sub)
		os.WriteFile(filepath.Join(sub, "x"), nil, 0o644)
	}
	for round := 0; round < 10; round++ {
		path := filepath.Join(t.TempDir(), "ckpt")
		var h [32]byte
		c, err := checkpoint.Open(path, h, false)
		if err != nil {
			t.Fatal(err)
		}
		ch := make(chan Entry, 400)
		go func() {
			Prepass(root, ch, &WalkErrors{}, PrepassOptions{
				Transport:    kernelTransport(t, root),
				Fix:          func(transport.Ref) (bool, string, FixResult) { return true, "", FixResult{} },
				Workers:      4,
				ReadDirBatch: 16,
				RegisterDir:  c.RegisterDir,
			})
			close(ch)
		}()
		var wg sync.WaitGroup
		for w := 0; w < 4; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for e := range ch {
					if e.IsDir {
						c.DirApplyDone(e.Path)
					} else {
						c.EntryDone(e.DirPath)
					}
				}
			}()
		}
		wg.Wait()
		// The root's completion notifies its parent, which is outside the walk
		// and never registered: exactly one bank remains, whatever the tree size.
		if reg, banked := c.PendingDirs(); reg != 0 || banked != 1 {
			t.Errorf("round %d: %d directories still pending, %d banked, want 0 and 1", round, reg, banked)
		}
		if n, sample := c.DuplicateCompletions(); n != 0 {
			t.Errorf("round %d: %d duplicate completions (%s)", round, n, sample)
		}
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		r, err := checkpoint.Open(path, h, true)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range dirs {
			if !r.DirCompleted(d) {
				t.Errorf("round %d: %s not recorded complete", round, d)
			}
		}
		r.Close()
	}
}

// A resume that skips an already-completed subtree still completes its parent:
// the skip reports the subtree done, so the root is recorded on this run
// instead of being redone by every later resume.
func TestResumeSkipLetsTheParentComplete(t *testing.T) {
	root := t.TempDir()
	done := filepath.Join(root, "done")
	todo := filepath.Join(root, "todo")
	for _, d := range []string{done, todo} {
		os.Mkdir(d, 0o755)
		os.WriteFile(filepath.Join(d, "f"), nil, 0o644)
	}
	path := filepath.Join(t.TempDir(), "ckpt")
	var h [32]byte

	// Run 1 completed "done" and nothing else.
	c, err := checkpoint.Open(path, h, false)
	if err != nil {
		t.Fatal(err)
	}
	c.RegisterDir(done, 1)
	c.EntryDone(done)
	c.DirApplyDone(done)
	c.Close()

	c, err = checkpoint.Open(path, h, true)
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan Entry, 16)
	go func() {
		Prepass(root, ch, &WalkErrors{}, PrepassOptions{
			Transport:   kernelTransport(t, root),
			Fix:         func(transport.Ref) (bool, string, FixResult) { return true, "", FixResult{} },
			Workers:     2,
			SkipDir:     c.SkipCompleted,
			RegisterDir: c.RegisterDir,
		})
		close(ch)
	}()
	for e := range ch {
		if e.Path == done || filepath.Dir(e.Path) == done {
			t.Errorf("resumed walk emitted %s from the completed subtree", e.Path)
		}
		if e.IsDir {
			c.DirApplyDone(e.Path)
		} else {
			c.EntryDone(e.DirPath)
		}
	}
	c.Close()
	r, err := checkpoint.Open(path, h, true)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for _, d := range []string{root, todo, done} {
		if !r.DirCompleted(d) {
			t.Errorf("%s not recorded complete after the resume", d)
		}
	}
}
