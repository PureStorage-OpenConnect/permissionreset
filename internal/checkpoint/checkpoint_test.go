package checkpoint

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func specHash(t *testing.T) [32]byte {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "spec.yaml")
	os.WriteFile(p, []byte("protocol: posix\n"), 0644)
	h, err := SpecHash(p)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestCreateAndResume(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ckpt.bin")
	h := specHash(t)

	// Create and register dirs
	c, err := Open(path, h, false)
	if err != nil {
		t.Fatal(err)
	}
	c.RegisterDir("/data/a", 3)
	c.RegisterDir("/data/b", 2)
	c.RegisterDir("/data/empty", 0)
	c.DirApplyDone("/data/empty") // empty dir completes after its own apply

	c.EntryDone("/data/a")
	c.EntryDone("/data/a")
	c.EntryDone("/data/a")
	c.DirApplyDone("/data/a") // dir's own apply completes /data/a

	c.EntryDone("/data/b")
	// /data/b NOT completed (1 entry + dir apply remaining)

	c.Close()

	// Resume
	c2, err := Open(path, h, true)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()

	if !c2.DirCompleted("/data/a") {
		t.Error("/data/a should be completed")
	}
	if !c2.DirCompleted("/data/empty") {
		t.Error("/data/empty should be completed")
	}
	if c2.DirCompleted("/data/b") {
		t.Error("/data/b should NOT be completed")
	}
	if c2.DirCompleted("/data/c") {
		t.Error("/data/c was never registered")
	}
	if c2.CompletedCount() != 2 {
		t.Errorf("CompletedCount = %d, want 2", c2.CompletedCount())
	}
}

func TestSpecHashMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ckpt.bin")
	h := specHash(t)

	c, err := Open(path, h, false)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()

	// Try to resume with a different hash
	var badHash [32]byte
	badHash[0] = 0xFF
	_, err = Open(path, badHash, true)
	if err == nil {
		t.Error("expected error for spec hash mismatch")
	}
}

func TestTruncatedRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ckpt.bin")
	h := specHash(t)

	c, err := Open(path, h, false)
	if err != nil {
		t.Fatal(err)
	}
	c.RegisterDir("/data/x", 1)
	c.EntryDone("/data/x")
	c.DirApplyDone("/data/x")
	c.Close()

	// Append partial bytes to simulate SIGKILL mid-write
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	f.Write([]byte{0x01, 0x02, 0x03}) // partial record
	f.Close()

	// Resume should truncate partial and still find /data/x
	c2, err := Open(path, h, true)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()

	if !c2.DirCompleted("/data/x") {
		t.Error("/data/x should survive truncation of partial trailing record")
	}
	if c2.CompletedCount() != 1 {
		t.Errorf("CompletedCount = %d, want 1", c2.CompletedCount())
	}
}

func TestConcurrentFileDone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ckpt.bin")
	h := specHash(t)

	c, err := Open(path, h, false)
	if err != nil {
		t.Fatal(err)
	}

	n := 1000
	c.RegisterDir("/data/concurrent", n)

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.EntryDone("/data/concurrent")
		}()
	}
	wg.Wait()
	c.DirApplyDone("/data/concurrent")
	c.Close()

	// Verify it completed
	c2, err := Open(path, h, true)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()

	if !c2.DirCompleted("/data/concurrent") {
		t.Error("/data/concurrent should be completed after 1000 concurrent FileDone calls")
	}
}

func TestResumeNonExistent(t *testing.T) {
	h := specHash(t)
	_, err := Open("/nonexistent/path/ckpt.bin", h, true)
	if err == nil {
		t.Error("expected error for non-existent checkpoint file")
	}
}

func TestNewCheckpointEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ckpt.bin")
	h := specHash(t)

	c, err := Open(path, h, false)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()

	// Resume empty checkpoint
	c2, err := Open(path, h, true)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()

	if c2.CompletedCount() != 0 {
		t.Errorf("empty checkpoint should have 0 completed, got %d", c2.CompletedCount())
	}
	if c2.DirCompleted("/anything") {
		t.Error("nothing should be completed in empty checkpoint")
	}
}

func TestMultipleFlushCycles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ckpt.bin")
	h := specHash(t)

	c, err := Open(path, h, false)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 100; i++ {
		dir := fmt.Sprintf("/data/dir_%04d", i)
		c.RegisterDir(dir, 1)
		c.EntryDone(dir)
		c.DirApplyDone(dir)
	}
	c.Flush()

	for i := 100; i < 200; i++ {
		dir := fmt.Sprintf("/data/dir_%04d", i)
		c.RegisterDir(dir, 1)
		c.EntryDone(dir)
		c.DirApplyDone(dir)
	}
	c.Close()

	c2, err := Open(path, h, true)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()

	if c2.CompletedCount() != 200 {
		t.Errorf("CompletedCount = %d, want 200", c2.CompletedCount())
	}
}

func TestFailedEntryPreventsCompletion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ckpt.bin")
	h := specHash(t)

	c, err := Open(path, h, false)
	if err != nil {
		t.Fatal(err)
	}

	// Dir with 3 entries; only 2 succeed (caller skips EntryDone on failure)
	c.RegisterDir("/data/partial", 3)
	c.EntryDone("/data/partial")
	c.EntryDone("/data/partial")
	// third entry failed — no EntryDone call
	c.DirApplyDone("/data/partial")
	c.Close()

	c2, err := Open(path, h, true)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()

	if c2.DirCompleted("/data/partial") {
		t.Error("dir with failed entry must not be checkpointed as complete")
	}
}

func TestDirApplyRequiredForCompletion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ckpt.bin")
	h := specHash(t)

	c, err := Open(path, h, false)
	if err != nil {
		t.Fatal(err)
	}

	// All children done but dir's own apply never called
	c.RegisterDir("/data/noapply", 2)
	c.EntryDone("/data/noapply")
	c.EntryDone("/data/noapply")
	// no DirApplyDone
	c.Close()

	c2, err := Open(path, h, true)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()

	if c2.DirCompleted("/data/noapply") {
		t.Error("dir must not complete without DirApplyDone")
	}
}

func TestChildCompletesBeforeParentRegistered(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ckpt.bin")
	h := specHash(t)

	c, err := Open(path, h, false)
	if err != nil {
		t.Fatal(err)
	}

	// Child completes before parent is registered (race scenario)
	c.RegisterDir("/data/parent/child", 0)
	c.DirApplyDone("/data/parent/child")
	// child calls ChildDirDone on parent — but parent not registered yet

	// Now register parent (1 child + dir apply = count 1+1=2)
	c.RegisterDir("/data/parent", 1)
	c.DirApplyDone("/data/parent")
	c.Close()

	c2, err := Open(path, h, true)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()

	if !c2.DirCompleted("/data/parent/child") {
		t.Error("/data/parent/child should be complete")
	}
	if !c2.DirCompleted("/data/parent") {
		t.Error("/data/parent should be complete — early child completion must be drained")
	}
}

// The exclude list is part of the run binding: a directory recorded complete
// under one exclude set was walked with part of its subtree pruned, so resuming
// with a different set would report never-visited objects as done.
func TestRunHashBindsExcludePatterns(t *testing.T) {
	dir := t.TempDir()
	specPath := filepath.Join(dir, "spec.yaml")
	if err := os.WriteFile(specPath, []byte("protocol: posix\n"), 0600); err != nil {
		t.Fatal(err)
	}
	base, err := RunHash(specPath, "/mnt/t", "posix", "1.0", nil)
	if err != nil {
		t.Fatal(err)
	}
	withOne, err := RunHash(specPath, "/mnt/t", "posix", "1.0", []string{".snapshot"})
	if err != nil {
		t.Fatal(err)
	}
	withTwo, err := RunHash(specPath, "/mnt/t", "posix", "1.0", []string{".snapshot", "*.tmp"})
	if err != nil {
		t.Fatal(err)
	}
	reordered, err := RunHash(specPath, "/mnt/t", "posix", "1.0", []string{"*.tmp", ".snapshot"})
	if err != nil {
		t.Fatal(err)
	}
	if base == withOne {
		t.Error("RunHash must differ: no excludes vs one exclude")
	}
	if withOne == withTwo {
		t.Error("RunHash must differ: one exclude vs two excludes")
	}
	if withTwo == reordered {
		t.Error("RunHash must differ: exclude order must be bound")
	}
	if base == withTwo {
		t.Error("RunHash must differ: no excludes vs two excludes")
	}
	// Verify resume is actually refused when excludes change.
	pathA := filepath.Join(dir, "ckpt-excl.bin")
	cA, err := Open(pathA, withOne, false)
	if err != nil {
		t.Fatal(err)
	}
	cA.Close()
	if _, err := Open(pathA, withTwo, true); err == nil {
		t.Error("Open with different exclude hash must refuse resume")
	} else if !strings.Contains(err.Error(), "run binding changed") {
		t.Errorf("refusal message should name the binding, got: %v", err)
	}

	again, err := RunHash(specPath, "/mnt/t", "posix", "1.0", []string{".snapshot", "*.tmp"})
	if err != nil {
		t.Fatal(err)
	}
	if again != withTwo {
		t.Error("RunHash must be stable for the same exclude list")
	}
}
