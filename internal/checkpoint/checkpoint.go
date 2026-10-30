package checkpoint

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

const (
	headerSize    = 48
	recordSize    = 16
	magic         = "CKPT"
	version       = uint16(1)
	flushInterval = 5 * time.Second

	// loadChunkRecords is how many records resume reads per call: 64 KiB, so a
	// resume makes one read per 4,096 directories rather than one per directory.
	loadChunkRecords = 4096
)

// hash128 produces a 128-bit hash of a path using two independent FNV-64 seeds.
func hash128(path string) [16]byte {
	h1 := fnv.New64a()
	h1.Write([]byte(path))
	h2 := fnv.New64()
	h2.Write([]byte(path))
	var out [16]byte
	binary.LittleEndian.PutUint64(out[0:8], h1.Sum64())
	binary.LittleEndian.PutUint64(out[8:16], h2.Sum64())
	return out
}

// RunHash computes a SHA-256 over the spec file contents and run-binding
// parameters (target path, protocol, tool version, effective exclude patterns).
// Changing any of these invalidates a checkpoint on resume, preventing
// accidental cross-run reuse.
//
// The exclude list is part of the binding because it changes what "complete"
// means. A directory recorded complete under one exclude set was walked with
// some of its subtree pruned; resuming with a narrower set would skip that
// directory outright and report the newly in-scope objects as done. The patterns
// are hashed in their effective order, not sorted: reordering them can change
// nothing observable today, but pinning the order costs nothing and keeps the
// binding honest if precedence ever matters.
func RunHash(specPath, target, protocol, toolVersion string, excludes []string) ([32]byte, error) {
	data, err := os.ReadFile(specPath)
	if err != nil {
		return [32]byte{}, err
	}
	h := sha256.New()
	h.Write(data)
	h.Write([]byte("\x00"))
	h.Write([]byte(target))
	h.Write([]byte("\x00"))
	h.Write([]byte(protocol))
	h.Write([]byte("\x00"))
	h.Write([]byte(toolVersion))
	for _, p := range excludes {
		h.Write([]byte("\x00"))
		h.Write([]byte(p))
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// SpecHash is kept for backward compatibility but callers should prefer RunHash.
func SpecHash(specPath string) ([32]byte, error) {
	data, err := os.ReadFile(specPath)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(data), nil
}

// dirState is one registered directory's outstanding work.
//
// The directory's own permission apply is tracked SEPARATELY from its children
// rather than as a +1 on one counter, and that separation is the whole point of
// this type. With a single counter, a duplicate completion report for one child
// is indistinguishable from a different child finishing: it drives the counter to
// zero one decrement early, the directory is recorded complete while a child is
// still outstanding, and on resume walk.go's SkipDir fires before readdir, so the
// unfinished child and the whole subtree below it are skipped and counted as
// fixed. Silent under-application reported as success.
//
// Split, a duplicate cannot do that. Completion now requires children == 0 AND
// selfDone, and the two signals come from different call sites for different
// events, so an extra child report drives children NEGATIVE instead of
// completing the directory early: detected on the spot, and fail-lossy rather
// than fail-dangerous, since a directory that never completes is simply re-done
// on the next run. The same holds for a repeated DirApplyDone, which finds
// selfDone already set.
//
// This does not make every duplicate impossible upstream -- nothing at this
// layer can, because the accounting counts events and not identities. It makes
// every duplicate turn into lost work plus a loud report instead of lost data
// plus a clean exit.
type dirState struct {
	children atomic.Int64
	selfDone atomic.Bool
	// completed guards the transition to complete so that the child arriving
	// last and the self-apply arriving last cannot both fire it.
	completed atomic.Bool
}

// earlyCompletions is what arrived for a directory before RegisterDir: child
// completions (files, symlinks and child directories alike) and its own apply.
type earlyCompletions struct {
	children int64
	self     bool
}

// Checkpoint tracks completed directories for resume support.
type Checkpoint struct {
	file      *os.File
	bufW      *bufio.Writer
	mu        sync.Mutex
	completed [][16]byte // sorted, read-only after Open
	pending   sync.Map   // path string -> *dirState
	// early banks completions that arrive before their directory's
	// RegisterDir; see lookupOrBank. Guarded by earlyMu, which RegisterDir also
	// holds while it publishes the directory, so a completion is either banked
	// before the drain or finds the directory pending, never neither.
	earlyMu sync.Mutex
	early   map[string]*earlyCompletions
	// duplicates counts completion reports that arrived for work already
	// accounted for. Any non-zero value is an internal error in the layer above,
	// not a condition of the tree, and the run reports it rather than silently
	// writing a checkpoint whose meaning it can no longer vouch for.
	duplicates atomic.Int64
	dupSample  atomic.Value // string: the first offending path, for the report
	stopFlush  chan struct{}
	flushDone  chan struct{}
}

// Open creates or resumes a checkpoint file.
// If resume is true, loads existing completed directories and validates the spec hash.
// If resume is false, creates a new file (truncating any existing one).
func Open(path string, specHash [32]byte, resume bool) (*Checkpoint, error) {
	c := &Checkpoint{
		stopFlush: make(chan struct{}),
		flushDone: make(chan struct{}),
	}

	if resume {
		if err := c.load(path, specHash); err != nil {
			return nil, fmt.Errorf("resume checkpoint: %w", err)
		}
	} else {
		f, err := os.Create(path)
		if err != nil {
			return nil, err
		}
		c.file = f
		if err := c.writeHeader(specHash); err != nil {
			f.Close()
			return nil, err
		}
	}

	c.bufW = bufio.NewWriterSize(c.file, 64*1024)
	go c.flusher()
	return c, nil
}

func (c *Checkpoint) writeHeader(specHash [32]byte) error {
	var hdr [headerSize]byte
	copy(hdr[0:4], magic)
	binary.LittleEndian.PutUint16(hdr[4:6], version)
	// hdr[6:8] flags = 0
	copy(hdr[8:40], specHash[:])
	// hdr[40:48] reserved
	_, err := c.file.Write(hdr[:])
	return err
}

func (c *Checkpoint) load(path string, specHash [32]byte) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}

	// Read and validate header
	var hdr [headerSize]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		f.Close()
		return fmt.Errorf("read header: %w", err)
	}
	if string(hdr[0:4]) != magic {
		f.Close()
		return fmt.Errorf("invalid checkpoint magic")
	}
	ver := binary.LittleEndian.Uint16(hdr[4:6])
	if ver != version {
		f.Close()
		return fmt.Errorf("unsupported checkpoint version %d", ver)
	}
	var savedHash [32]byte
	copy(savedHash[:], hdr[8:40])
	if savedHash != specHash {
		f.Close()
		return fmt.Errorf("run binding changed since checkpoint was created (spec, target, protocol, tool version, or exclude list); delete the checkpoint file to start fresh")
	}

	// Read records, truncate partial trailing record
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	dataSize := info.Size() - headerSize
	if dataSize < 0 {
		f.Close()
		return fmt.Errorf("checkpoint file too small")
	}
	completeRecords := dataSize / recordSize
	validSize := headerSize + completeRecords*recordSize
	if info.Size() != validSize {
		if err := f.Truncate(validSize); err != nil {
			f.Close()
			return fmt.Errorf("truncate partial record: %w", err)
		}
	}

	// Load hashes
	if _, err := f.Seek(headerSize, io.SeekStart); err != nil {
		f.Close()
		return err
	}
	c.completed, err = readRecords(f, completeRecords)
	if err != nil {
		f.Close()
		return err
	}

	// Sort for binary search
	slices.SortFunc(c.completed, cmp128)

	// Seek to end for appending new records
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return err
	}

	c.file = f
	return nil
}

// readRecords reads n records from r into a slice sized exactly n, through one
// fixed 64 KiB buffer: one read per loadChunkRecords records, and no second copy
// of the records beyond that buffer. Duplicates are kept, as they always were.
func readRecords(r io.Reader, n int64) ([][16]byte, error) {
	out := make([][16]byte, n)
	buf := make([]byte, loadChunkRecords*recordSize)
	for i := int64(0); i < n; {
		k := min(n-i, loadChunkRecords)
		b := buf[:k*recordSize]
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		for j := int64(0); j < k; j++ {
			copy(out[i+j][:], b[j*recordSize:])
		}
		i += k
	}
	return out, nil
}

// cmp128 orders hashes as unsigned big-endian 128-bit integers, which is the
// same order as comparing their bytes left to right.
func cmp128(a, b [16]byte) int {
	if x, y := binary.BigEndian.Uint64(a[0:8]), binary.BigEndian.Uint64(b[0:8]); x != y {
		if x < y {
			return -1
		}
		return 1
	}
	x, y := binary.BigEndian.Uint64(a[8:16]), binary.BigEndian.Uint64(b[8:16])
	switch {
	case x < y:
		return -1
	case x > y:
		return 1
	}
	return 0
}

// DirCompleted returns true if the directory was fully processed in a previous run.
func (c *Checkpoint) DirCompleted(dirPath string) bool {
	if len(c.completed) == 0 {
		return false
	}
	_, found := slices.BinarySearchFunc(c.completed, hash128(dirPath), cmp128)
	return found
}

// SkipCompleted is DirCompleted for the walk's SkipDir hook: when a resume
// skips a directory an earlier run completed, it also reports that directory
// done to its parent. Without that the parent, counting the skipped directory
// among its children, could never complete on the resumed run, and neither
// could any ancestor (PS-11, #80).
func (c *Checkpoint) SkipCompleted(dirPath string) bool {
	if !c.DirCompleted(dirPath) {
		return false
	}
	if parent := parentPath(dirPath); parent != "" && parent != dirPath {
		c.ChildDirDone(parent)
	}
	return true
}

// CompletedCount returns the number of directories loaded from a previous checkpoint.
func (c *Checkpoint) CompletedCount() int {
	return len(c.completed)
}

// RegisterDir records that a directory has entryCount children, plus its own
// permission apply signalled separately by DirApplyDone, to complete before it
// is considered done. Completions that arrived before this call were banked by
// lookupOrBank and are applied here.
func (c *Checkpoint) RegisterDir(dirPath string, entryCount int) {
	st := &dirState{}
	st.children.Store(int64(entryCount))

	c.earlyMu.Lock()
	c.pending.Store(dirPath, st)
	early := c.early[dirPath]
	delete(c.early, dirPath)
	c.earlyMu.Unlock()

	if early == nil {
		return
	}
	if early.self {
		st.selfDone.Store(true)
	}
	c.settle(dirPath, st, st.children.Add(-early.children))
}

// lookupOrBank returns dirPath's state when it is registered. Otherwise it
// banks the completion for RegisterDir to apply and returns nil.
//
// The walk emits a directory's children, and the directory itself, before it
// calls RegisterDir, so on any tree an apply worker can report first. These
// completions used to be dropped (PS-11, #80): the directory then never
// reached zero, stayed in pending for the rest of the run, was never written
// to the checkpoint, and kept its parent and every ancestor from completing
// too, so pending grew with the tree and a resume redid work that was done.
//
// The walk root's own completion notifies its parent, which is outside the walk
// and never registers, so one bank always remains at the end of a run.
//
// The fast path is lock-free: a registered directory never needs the bank. A
// completion for a directory that already completed also lands in the bank,
// since nothing here remembers completed paths; that is a duplicate report from
// the layer above, and it costs one entry rather than a wrong checkpoint.
func (c *Checkpoint) lookupOrBank(dirPath string, self bool) *dirState {
	if v, ok := c.pending.Load(dirPath); ok {
		return v.(*dirState)
	}
	c.earlyMu.Lock()
	defer c.earlyMu.Unlock()
	if v, ok := c.pending.Load(dirPath); ok {
		return v.(*dirState)
	}
	if c.early == nil {
		c.early = make(map[string]*earlyCompletions)
	}
	e := c.early[dirPath]
	if e == nil {
		e = &earlyCompletions{}
		c.early[dirPath] = e
	}
	if self {
		if e.self {
			c.recordDuplicate(dirPath)
		}
		e.self = true
	} else {
		e.children++
	}
	return nil
}

// EntryDone accounts for one successfully processed non-directory entry (file or
// symlink) in dirPath. When every child and the directory's own apply are
// accounted for, the directory is marked complete and its parent is notified.
func (c *Checkpoint) EntryDone(dirPath string) {
	c.childDone(dirPath)
}

// DirApplyDone signals that the directory's own permission apply succeeded. It
// is one of the two conditions completion requires, and it is not a child
// decrement: see dirState for why the two are counted apart.
func (c *Checkpoint) DirApplyDone(dirPath string) {
	st := c.lookupOrBank(dirPath, true)
	if st == nil {
		return
	}
	if st.selfDone.Swap(true) {
		c.recordDuplicate(dirPath)
		return
	}
	c.settle(dirPath, st, st.children.Load())
}

// ChildDirDone is called when a child directory completes.
func (c *Checkpoint) ChildDirDone(parentDir string) {
	c.childDone(parentDir)
}

func (c *Checkpoint) childDone(dirPath string) {
	if st := c.lookupOrBank(dirPath, false); st != nil {
		c.settle(dirPath, st, st.children.Add(-1))
	}
}

// PendingDirs reports how many directories are registered but not complete,
// and how many unregistered directories have banked completions. Both are
// bounded by work in flight, not tree size; tests use them to prove it.
func (c *Checkpoint) PendingDirs() (registered, banked int) {
	c.pending.Range(func(any, any) bool { registered++; return true })
	c.earlyMu.Lock()
	banked = len(c.early)
	c.earlyMu.Unlock()
	return registered, banked
}

// settle decides whether dirPath is now complete, given the child count a caller
// has just observed.
//
// A negative child count is the duplicate detector. It means more child
// completions arrived than RegisterDir was told to expect, which cannot happen
// from a correct caller and is the one accounting error that loses data rather
// than time. The directory is deliberately NOT completed in that case: leaving it
// incomplete makes the next run re-read it, which is the safe direction, and the
// count is reported so the run does not exit zero on a silent skip.
func (c *Checkpoint) settle(dirPath string, st *dirState, children int64) {
	if children < 0 {
		c.recordDuplicate(dirPath)
		return
	}
	if children != 0 || !st.selfDone.Load() {
		return
	}
	// Both conditions can be observed as met by two different goroutines: the
	// last child and the self-apply can land concurrently and each see the other
	// already done. Exactly one of them completes the directory.
	if st.completed.Swap(true) {
		return
	}
	c.pending.Delete(dirPath)
	c.completeDir(dirPath)
}

func (c *Checkpoint) recordDuplicate(dirPath string) {
	c.duplicates.Add(1)
	c.dupSample.CompareAndSwap(nil, dirPath)
}

// DuplicateCompletions reports how many completion signals arrived for work that
// was already accounted for, and one offending directory.
//
// A non-zero count is an internal error in the layer that reports completions,
// never a property of the tree being repaired. It is surfaced rather than logged
// and forgotten because the failure it guards against — a directory recorded
// complete while a child is outstanding — is invisible in the run's own output:
// the resume skips the subtree and counts the skip as fixed.
func (c *Checkpoint) DuplicateCompletions() (int64, string) {
	sample, _ := c.dupSample.Load().(string)
	return c.duplicates.Load(), sample
}

func (c *Checkpoint) completeDir(dirPath string) {
	c.markComplete(dirPath)
	// Notify parent
	parent := parentPath(dirPath)
	if parent != "" && parent != dirPath {
		c.ChildDirDone(parent)
	}
}

func parentPath(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			if i == 0 {
				return "/"
			}
			return p[:i]
		}
	}
	return ""
}

func (c *Checkpoint) markComplete(dirPath string) {
	h := hash128(dirPath)
	c.mu.Lock()
	c.bufW.Write(h[:])
	c.mu.Unlock()
}

// Flush writes buffered data to disk and fsyncs.
func (c *Checkpoint) Flush() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.bufW.Flush(); err != nil {
		return err
	}
	return c.file.Sync()
}

// Close stops the background flusher, flushes, and closes the file.
func (c *Checkpoint) Close() error {
	close(c.stopFlush)
	<-c.flushDone
	if err := c.Flush(); err != nil {
		c.file.Close()
		return err
	}
	return c.file.Close()
}

func (c *Checkpoint) flusher() {
	defer close(c.flushDone)
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopFlush:
			return
		case <-ticker.C:
			c.Flush()
		}
	}
}
