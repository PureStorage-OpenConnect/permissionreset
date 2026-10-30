package checkpoint

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
)

// Completions that arrive before RegisterDir are banked and applied when it is
// called (PS-11, #80). They used to be dropped, leaving the directory pending
// for the rest of the run and never recorded.
func TestCompletionsBeforeRegisterAreKept(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ckpt.bin")
	h := specHash(t)
	c, err := Open(path, h, false)
	if err != nil {
		t.Fatal(err)
	}
	c.EntryDone("/data/a")
	c.EntryDone("/data/a")
	c.DirApplyDone("/data/a")
	c.ChildDirDone("/data/a") // a child directory that finished first
	if reg, banked := c.PendingDirs(); reg != 0 || banked != 1 {
		t.Fatalf("before register: pending=%d banked=%d, want 0 and 1", reg, banked)
	}
	c.RegisterDir("/data/a", 3)
	// The one bank left is /data itself: the parent /data/a's completion
	// notifies, never registered here.
	if reg, banked := c.PendingDirs(); reg != 0 || banked != 1 || !c.bankedForTest("/data") {
		t.Errorf("after register: pending=%d banked=%d, want 0 and 1 (/data)", reg, banked)
	}
	if n, _ := c.DuplicateCompletions(); n != 0 {
		t.Errorf("duplicates = %d", n)
	}
	c.Close()
	r, err := Open(path, h, true)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if !r.DirCompleted("/data/a") {
		t.Error("/data/a not recorded complete")
	}
}

// Banking keeps the duplicate detector: an early self-apply reported twice, or
// more early children than RegisterDir expects, leaves the directory incomplete
// and counts a duplicate.
func TestBankedDuplicatesAreDetected(t *testing.T) {
	c, err := Open(filepath.Join(t.TempDir(), "ckpt.bin"), specHash(t), false)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.DirApplyDone("/data/s")
	c.DirApplyDone("/data/s")
	c.EntryDone("/data/c")
	c.EntryDone("/data/c")
	c.DirApplyDone("/data/c")
	c.RegisterDir("/data/s", 0)
	c.RegisterDir("/data/c", 1)
	if n, _ := c.DuplicateCompletions(); n != 2 {
		t.Errorf("duplicates = %d, want 2", n)
	}
	if c.isCompleteForTest("/data/c") {
		t.Error("/data/c completed despite an extra child")
	}
}

// Registration racing every kind of completion, many times over: each
// directory completes exactly once and nothing is left pending or banked.
func TestRegisterRacesCompletions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ckpt.bin")
	h := specHash(t)
	c, err := Open(path, h, false)
	if err != nil {
		t.Fatal(err)
	}
	const dirs, children = 500, 8
	var wg sync.WaitGroup
	for i := 0; i < dirs; i++ {
		d := fmt.Sprintf("/data/d%03d", i)
		wg.Add(2 + children)
		go func() { defer wg.Done(); c.RegisterDir(d, children) }()
		go func() { defer wg.Done(); c.DirApplyDone(d) }()
		for j := 0; j < children; j++ {
			go func() { defer wg.Done(); c.EntryDone(d) }()
		}
	}
	wg.Wait()
	// /data, the unregistered parent every completion notifies, is the only bank.
	if reg, banked := c.PendingDirs(); reg != 0 || banked != 1 || !c.bankedForTest("/data") {
		t.Errorf("pending=%d banked=%d, want 0 and 1 (/data)", reg, banked)
	}
	if n, s := c.DuplicateCompletions(); n != 0 {
		t.Errorf("duplicates = %d (%s)", n, s)
	}
	c.Close()
	r, err := Open(path, h, true)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.CompletedCount() != dirs {
		t.Errorf("recorded %d, want %d", r.CompletedCount(), dirs)
	}
}

func (c *Checkpoint) isCompleteForTest(dir string) bool {
	_, pending := c.pending.Load(dir)
	return !pending
}

func (c *Checkpoint) bankedForTest(dir string) bool {
	c.earlyMu.Lock()
	defer c.earlyMu.Unlock()
	return c.early[dir] != nil
}
