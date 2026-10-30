package checkpoint

import (
	"path/filepath"
	"testing"
)

// TestDuplicateCompletionIsDetected pins the one hazard COMPOUND batching could
// introduce, at the layer where it does damage.
//
// The sequence is the plan's: a directory with three children receives four
// child completions. With a single counter carrying the directory's own apply as
// a +1, that is indistinguishable from three children plus the self-apply -- the
// counter reaches zero, the directory is recorded complete, and the extra report
// arrives after the entry has already been deleted and is silently dropped. The
// consequence is not a wrong number in a summary: on resume DirCompleted returns
// true, walk.go's SkipDir returns BEFORE readdir, so the outstanding child and
// the entire subtree below this directory are never visited, and the skip is
// counted as fixed. Silent under-application reported as success.
//
// Two things are asserted, and the second matters more than the first. The
// duplicate is reported, and the directory is NOT completed: a duplicate must
// cost re-work, never data.
func TestDuplicateCompletionIsDetected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ckpt.bin")
	h := specHash(t)

	c, err := Open(path, h, false)
	if err != nil {
		t.Fatal(err)
	}

	c.RegisterDir("/data/dup", 3)
	c.EntryDone("/data/dup")
	c.EntryDone("/data/dup")
	c.EntryDone("/data/dup")
	c.EntryDone("/data/dup") // the duplicate: one object reported success twice
	c.DirApplyDone("/data/dup")

	dups, sample := c.DuplicateCompletions()
	if dups == 0 {
		t.Error("a fourth completion for a three-child directory must be detected, not absorbed")
	}
	if sample != "/data/dup" {
		t.Errorf("duplicate sample = %q, want /data/dup", sample)
	}
	c.Close()

	c2, err := Open(path, h, true)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if c2.DirCompleted("/data/dup") {
		t.Error("a directory whose accounting is known to be wrong must not be recorded complete: " +
			"on resume SkipDir fires before readdir, so the unfinished child and its whole subtree are skipped and counted as fixed")
	}
}

// TestDuplicateDirApplyIsDetected covers the other half. A directory's own apply
// reported twice cannot drive the child count negative, so it needs its own
// detection, and it must not be able to substitute for a missing child.
func TestDuplicateDirApplyIsDetected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ckpt.bin")
	h := specHash(t)

	c, err := Open(path, h, false)
	if err != nil {
		t.Fatal(err)
	}

	c.RegisterDir("/data/twice", 2)
	c.EntryDone("/data/twice")
	c.DirApplyDone("/data/twice")
	c.DirApplyDone("/data/twice") // duplicate; one child is still outstanding

	if dups, _ := c.DuplicateCompletions(); dups == 0 {
		t.Error("a repeated DirApplyDone must be detected")
	}
	c.Close()

	// Reopened, not queried live: DirCompleted answers from the set loaded at
	// Open, so asking the same instance that recorded the completion would be
	// vacuously false and would assert nothing.
	c2, err := Open(path, h, true)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if c2.DirCompleted("/data/twice") {
		t.Error("the second DirApplyDone must not stand in for the missing child")
	}
}

// TestNoDuplicatesOnTheNormalPath is the control. Every assertion above is about
// a counter going somewhere it should not, so a detector that fired on correct
// input would be worse than none: the run would report an internal error and
// refuse to complete directories that are genuinely finished.
func TestNoDuplicatesOnTheNormalPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ckpt.bin")
	h := specHash(t)

	c, err := Open(path, h, false)
	if err != nil {
		t.Fatal(err)
	}

	// A parent with two files and one subdirectory, completed in the order the
	// walk and the apply workers actually produce: the child directory finishes
	// on its own and notifies the parent through ChildDirDone.
	c.RegisterDir("/data/norm", 3)
	c.RegisterDir("/data/norm/sub", 1)
	c.EntryDone("/data/norm/sub")
	c.DirApplyDone("/data/norm/sub")
	c.EntryDone("/data/norm")
	c.EntryDone("/data/norm")
	c.DirApplyDone("/data/norm")

	if dups, sample := c.DuplicateCompletions(); dups != 0 {
		t.Errorf("correct accounting reported %d duplicates (first %q); the detector must not fire on the normal path", dups, sample)
	}
	c.Close()

	c2, err := Open(path, h, true)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if !c2.DirCompleted("/data/norm/sub") {
		t.Error("/data/norm/sub should be complete")
	}
	if !c2.DirCompleted("/data/norm") {
		t.Error("/data/norm should be complete")
	}
}

// TestInterruptedMidBatchLeavesNoDirectoryComplete asserts the safe direction
// for an interruption while a batch is in flight.
//
// A bundle of seven can be cut off anywhere: the process dies, or the COMPOUND
// fails partway and the tail is requeued and never retried. Whichever objects
// were mid-flight simply never report. The requirement is one-directional: no
// directory containing an unfinished object may appear in DirCompleted. Losing
// the completions of objects that DID finish is acceptable and costs one read
// each on the resume, which --resume forces --compare for.
func TestInterruptedMidBatchLeavesNoDirectoryComplete(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ckpt.bin")
	h := specHash(t)

	c, err := Open(path, h, false)
	if err != nil {
		t.Fatal(err)
	}

	// Three directories of seven objects each, the bundle width. Every object of
	// the first is reported; the second and third are interrupted with objects
	// still in flight, at the two boundaries that matter -- one short of its
	// children, and children complete but the directory's own apply never
	// reported.
	for _, d := range []string{"/t/whole", "/t/cut", "/t/noself"} {
		c.RegisterDir(d, 7)
	}
	for range 7 {
		c.EntryDone("/t/whole")
	}
	c.DirApplyDone("/t/whole")

	for range 6 {
		c.EntryDone("/t/cut") // the seventh was in flight when the run stopped
	}
	c.DirApplyDone("/t/cut")

	for range 7 {
		c.EntryDone("/t/noself")
	}
	// /t/noself's own SETATTR was in the same interrupted bundle.

	c.Close()

	c2, err := Open(path, h, true)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()

	if !c2.DirCompleted("/t/whole") {
		t.Error("/t/whole finished every object and must be recorded complete, or a resume redoes the whole tree")
	}
	for _, d := range []string{"/t/cut", "/t/noself"} {
		if c2.DirCompleted(d) {
			t.Errorf("%s has an unfinished object and must not be complete: SkipDir returns before readdir, so its subtree would be skipped in silence", d)
		}
	}
	if dups, _ := c2.DuplicateCompletions(); dups != 0 {
		t.Errorf("an interruption is not a duplicate; got %d", dups)
	}
}
