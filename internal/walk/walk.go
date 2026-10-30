// Package walk provides parallel directory enumeration for permission repair.
//
// TRUSTED-TREE OPERATING MODEL: the tool assumes exclusive write access to the
// target tree during a repair run. Symlinks are detected at enumeration via
// Lstat and skipped, and the target root is resolved through EvalSymlinks before
// traversal begins. On NFS, subsequent operations (setxattr, chmod, chown) are
// bound to server-side filehandles obtained from READDIR or LOOKUP, not to local
// paths, so a local symlink swap between detection and application does not
// redirect the server-side operation. The remaining TOCTOU window — an object
// replaced on the server between enumeration and apply — requires concurrent
// write access to the same export, which the operating model excludes. Operators
// should restrict NFS export access or use a dedicated filesystem during repair.
package walk

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

func isDescriptorExhaustion(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.EMFILE || errno == syscall.ENFILE
	}
	return false
}

type Entry struct {
	Path      string
	DirPath   string // parent directory (set by walker for checkpoint tracking)
	IsDir     bool
	IsSymlink bool
	Mode      uint32 // current permission bits, avoids double-stat

	// FH is the NFS filehandle, set only by the userspace transport and nil on
	// the kernel transport. It lets the apply worker address the object without
	// a LOOKUP, which is the whole point of asking READDIR for FATTR4_FILEHANDLE.
	FH []byte

	// NeedStat means Path has not been stat'ed yet, so IsDir, IsSymlink, and
	// Mode are unset and the consumer must stat it. Only the pfind enumerator
	// sets this: it emits paths only. Both transports fill these in for free.
	NeedStat bool

	// ACLApplied means the directory's NFSv4 ACL was already set during
	// enumeration (folded into the READDIR COMPOUND). The apply worker should
	// skip the ACL write for this entry.
	ACLApplied bool

	// Fix carries the outcome of the prepass's FixFunc call for this directory,
	// when the fast-path readdir failed and FixFunc ran to restore
	// traversability. Fix.Done means FixFunc's real spec apply already ran to
	// completion -- the apply worker should not reprocess this directory, just
	// count Fix.Applied and log/checkpoint it the way it does an ACLApplied
	// entry. Zero value (Done false) means no reprocessing was skipped: either
	// the fast path succeeded without calling FixFunc at all, or FixFunc only
	// restored traversability without performing the real apply (e.g. the posix
	// chmod-755 fallback), so the worker's ordinary apply still needs to run.
	Fix FixResult
}

// FixResult is what a FixFunc call reports back through Prepass to the
// directory's emitted Entry. See Entry.Fix.
type FixResult struct {
	Done    bool   // the real spec apply already ran; do not reprocess
	Applied bool   // a change was made (for stats, only meaningful when Done)
	LogMsg  string // audit line already recorded for this directory, if any
}

// WalkOptions configures optional walker behavior.
type WalkOptions struct {
	SkipDir       func(dir string) bool           // if non-nil, skip dirs where this returns true
	RegisterDir   func(dir string, fileCount int) // if non-nil, called after readdir with count of non-dir entries emitted
	OneFilesystem bool                            // if true, do not cross filesystem boundaries
	// Exclude, when non-nil, takes a path out of scope. An excluded file is not
	// emitted; an excluded directory is pruned, so nothing beneath it is
	// enumerated either. It is consulted exactly once per candidate path, which
	// is what lets the caller count exclusions from inside the predicate.
	Exclude func(path string) bool
}

// Ref is how a consumer addresses this entry through a transport. It carries the
// filehandle as well as the path, so an object the enumeration already resolved
// is not resolved again by LOOKUP in the apply worker.
//
// This is a method rather than a literal at each call site because dropping FH
// here is invisible — the run still succeeds, just with an extra round trip per
// object — so there is exactly one place to get it wrong and one place to test.
func (e *Entry) Ref() transport.Ref {
	return transport.Ref{Path: e.Path, FH: e.FH}
}

// Stat fills in IsDir and Mode for an entry that was streamed without a stat.
// Returns false if the path could not be stat'ed (e.g. removed mid-run).
func (e *Entry) Stat() bool {
	if !e.NeedStat {
		return true
	}
	var st syscall.Stat_t
	if err := syscall.Lstat(e.Path, &st); err != nil {
		return false
	}
	e.IsDir = st.Mode&syscall.S_IFMT == syscall.S_IFDIR
	e.IsSymlink = st.Mode&syscall.S_IFMT == syscall.S_IFLNK
	e.Mode = uint32(st.Mode) & 07777
	e.NeedStat = false
	return true
}

// Pfind streams paths from pfind into a channel. Falls back to ParallelWalk if unavailable.
// Entries are emitted with NeedStat set; the consumer must call Entry.Stat().
// WalkErrors tracks errors encountered during enumeration so the caller can
// detect incomplete walks.
type WalkErrors struct {
	count atomic.Int64
}

func (w *WalkErrors) Add(n int64)  { w.count.Add(n) }
func (w *WalkErrors) Count() int64 { return w.count.Load() }

// Pfind streams paths from an external pfind process. exclude, when non-nil,
// drops paths from the stream. The caller should pass MatchOrUnder rather than
// Match so children of an excluded directory are caught. pfind has already read
// the excluded subtree by the time its output arrives here, so exclusion saves
// the apply work but not the enumeration.
func Pfind(root string, ch chan<- Entry, errs *WalkErrors, exclude func(path string) bool) error {
	opts := &WalkOptions{Exclude: exclude}
	pfind, err := exec.LookPath("pfind")
	if err != nil {
		return ParallelWalk(root, ch, 32, errs, opts)
	}

	cmd := exec.Command(pfind, root)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return ParallelWalk(root, ch, 32, errs, opts)
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		path := scanner.Text()
		if path == "" {
			continue
		}
		if exclude != nil && exclude(path) {
			continue
		}
		ch <- Entry{Path: path, NeedStat: true}
	}
	if err := scanner.Err(); err != nil {
		errs.Add(1)
	}

	if err := cmd.Wait(); err != nil {
		errs.Add(1)
		return err
	}
	return nil
}

// ParallelWalk enumerates using concurrent goroutines doing readdir.
// No GIL means this can saturate NFS metadata ops from Go alone.
func ParallelWalk(root string, ch chan<- Entry, concurrency int, errs *WalkErrors, opts *WalkOptions) error {
	var wg sync.WaitGroup
	tokens := make(chan struct{}, concurrency)

	var rootDev uint64
	if opts != nil && opts.OneFilesystem {
		var rst syscall.Stat_t
		if err := syscall.Stat(root, &rst); err != nil {
			return fmt.Errorf("stat root for device ID: %w", err)
		}
		rootDev = uint64(rst.Dev)
	}

	var walk func(dir string)
	walk = func(dir string) {
		defer wg.Done()

		if opts != nil && opts.SkipDir != nil && opts.SkipDir(dir) {
			return
		}

		// Listed in bounded batches like Prepass (PS-11), with child
		// directories collected and descended only after the handle closes, so
		// open handles stay bounded by concurrency rather than by depth.
		f, err := os.Open(dir)
		if err != nil {
			errs.Add(1)
			return
		}
		entryCount := 0
		var childDirs []string
		complete := true
		for {
			entries, err := f.ReadDir(DefaultReadDirBatch)
			for _, e := range entries {
				path := dir + "/" + e.Name()
				// Excluded entries are dropped before any type dispatch, and are
				// deliberately NOT counted in entryCount: the count is the number of
				// completion signals this directory will receive, and an entry that
				// never reaches a consumer never sends one.
				if opts != nil && opts.Exclude != nil && opts.Exclude(path) {
					continue
				}
				if e.Type()&os.ModeSymlink != 0 {
					ch <- Entry{Path: path, DirPath: dir, IsSymlink: true}
					entryCount++
					continue
				}
				if e.IsDir() {
					if opts != nil && opts.OneFilesystem {
						var cst syscall.Stat_t
						if err := syscall.Stat(path, &cst); err != nil || uint64(cst.Dev) != rootDev {
							continue // out of scope, never signals: not counted
						}
					}
					entryCount++
					childDirs = append(childDirs, path)
				} else {
					ch <- Entry{Path: path, DirPath: dir, IsDir: false}
					entryCount++
				}
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				// Partway through: what was found is kept, the directory is not
				// registered, so a checkpoint never marks it complete.
				errs.Add(1)
				complete = false
				break
			}
		}
		f.Close()

		for _, path := range childDirs {
			wg.Add(1)
			select {
			case tokens <- struct{}{}:
				go func(p string) {
					walk(p)
					<-tokens
				}(path)
			default:
				walk(path)
			}
		}

		var st syscall.Stat_t
		if err := syscall.Stat(dir, &st); err == nil {
			ch <- Entry{Path: dir, DirPath: dir, IsDir: true, Mode: uint32(st.Mode) & 07777}
		} else {
			errs.Add(1)
		}

		if opts != nil && opts.RegisterDir != nil && complete {
			opts.RegisterDir(dir, entryCount)
		}
	}

	wg.Add(1)
	walk(root)
	wg.Wait()
	return nil
}

// Walk uses sequential os.ReadDir for enumeration.
func Walk(root string, ch chan<- Entry) error {
	return walkDir(root, ch)
}

func walkDir(dir string, ch chan<- Entry) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	for _, e := range entries {
		path := dir + "/" + e.Name()
		if e.Type()&os.ModeSymlink != 0 {
			ch <- Entry{Path: path, IsSymlink: true}
			continue
		}
		if e.IsDir() {
			walkDir(path, ch)
		} else {
			var fst syscall.Stat_t
			if err := syscall.Lstat(path, &fst); err == nil {
				ch <- Entry{Path: path, IsDir: false, Mode: uint32(fst.Mode) & 07777}
			}
		}
	}

	var st syscall.Stat_t
	if err := syscall.Stat(dir, &st); err == nil {
		ch <- Entry{Path: dir, IsDir: true, Mode: uint32(st.Mode) & 07777}
	} else {
		ch <- Entry{Path: dir, IsDir: true}
	}
	return nil
}

// FixFunc fixes one directory that could not be read, returning whether it is
// traversable afterwards, a line to log ("" for nothing to say), and a
// FixResult recording whether the fix already performed the real spec apply
// (see Entry.Fix).
type FixFunc func(ref transport.Ref) (bool, string, FixResult)

// PrepassResult reports what one Prepass sweep did.
//
// FixTime and ReaddirTime are summed across workers, not wall-clock: with N
// directories in flight their total runs to roughly N x elapsed. They exist
// because fusing the fix into the enumeration removed the phase boundary whose
// separate timings used to show where a run's time went — this is that answer,
// measured directly instead of inferred from two clocks.
type PrepassResult struct {
	Fixed         int
	Errors        int
	ReaddirErrors int
	FixTime       time.Duration
	ReaddirTime   time.Duration
	// Stopped is true when PrepassOptions.Stop ended the walk early.
	Stopped bool
}

// DefaultReadDirBatch is how many children Prepass holds per directory listing
// on a batching transport. At about 150 bytes per kernel Dirent (a ~100-byte
// path plus the struct) that is ~150 KiB per directory in flight, against one
// extra getdents round per 1,024 children, which the kernel issues in 32 KiB
// buffers anyway.
const DefaultReadDirBatch = 1024

// PrepassOptions configures Prepass.
type PrepassOptions struct {
	Transport   transport.Transport              // required: the source of every readdir
	Fix         FixFunc                          // required: fix a directory that could not be read
	Log         func(string)                     // optional: sink for fix log lines
	SkipDir     func(dir string) bool            // optional: skip dirs where this returns true
	RegisterDir func(dir string, entryCount int) // optional: called after readdir, enumerating mode only
	// Exclude, when non-nil, takes a path out of scope. An excluded file is
	// never emitted; an excluded directory is neither fixed nor descended, so
	// its subtree is never read at all. Consulted exactly once per candidate
	// path, so the caller may count exclusions from inside the predicate.
	Exclude func(path string) bool
	Workers int // max directories in flight
	// ReadDirBatch caps how many children one directory listing holds at once
	// on a transport that implements transport.DirBatcher. Zero means
	// DefaultReadDirBatch.
	ReadDirBatch int
	// DirACL, when non-nil, returns pre-encoded NFSv4 ACL bytes for a
	// directory. When set, the walk folds the SETATTR into the READDIR
	// COMPOUND on the fast path (directory already traversable), saving one
	// round-trip per directory. Nil return means no ACL to apply. The caller
	// is responsible for setting the conditions (NFSv4 protocol, not dry-run,
	// not compare, not validate).
	DirACL func(path string) []byte
	// Stop, when non-nil and true, ends the walk early: no further directory
	// is read, fixed or descended. Directories it leaves are not counted
	// anywhere, so the result shows the enumeration as incomplete
	// (PrepassResult.Stopped) rather than the tree as smaller than it is.
	Stop func() bool
	// RootFSID, when non-zero, stops the walk at a filesystem boundary. The
	// kernel transport reports st_dev here; the userspace transport reports
	// FATTR4_FSID, which is what the kernel derives st_dev from on an NFS mount.
	RootFSID uint64
}

// sameFilesystem answers the --one-filesystem question for one child.
//
// The userspace transport already knows: FATTR4_FSID rode along in the READDIR
// bitmask, so AttrsKnown is true and this is a field compare. The kernel
// transport does not, because ReadDir deliberately does not stat, so this costs
// one Stat per subdirectory — which is exactly what the pre-transport code did
// at walk.go's RootDev check, and no more.
//
// A Stat failure returns false, matching the old behavior of skipping on error,
// but it increments the error counter first. Skipping a subtree silently and
// then exiting zero is the failure mode this exists to avoid: the run reports
// success on a tree it never read.
//
// errs is a parameter rather than a field on PrepassOptions because Prepass
// already threads *WalkErrors separately from its options, and the counter must
// be the same one the caller checks for the nonzero exit.
func sameFilesystem(o PrepassOptions, errs *WalkErrors, e transport.Dirent) bool {
	if e.AttrsKnown {
		return e.FSID == o.RootFSID
	}
	a, err := o.Transport.Stat(e.Ref)
	if err != nil {
		if o.Log != nil {
			o.Log(fmt.Sprintf("[pre-pass] ERR: stat %s for --one-filesystem: %v", e.Ref.Path, err))
		}
		if errs != nil {
			errs.Add(1)
		}
		return false
	}
	return a.FSID == o.RootFSID
}

// childDir is the part of a Dirent that descending into it needs. Prepass
// collects these instead of holding the Dirent slice they came from: the slice
// also carries every non-directory child, each with its own path string and
// filehandle, and that is the bulk of what a readdir returns on a wide tree.
type childDir struct {
	ref       transport.Ref
	mode      uint32
	modeKnown bool
}

// Prepass fixes directory permissions top-down and, when ch is non-nil, streams
// every entry it finds — so the tree is read ONCE for both jobs.
//
// Each directory is fixed, then immediately read to discover its children, which
// are queued as independent tasks. That preserves the only ordering constraint
// that matters — a directory is always fixed before it is read — without the
// level-by-level barriers an explicit BFS needs. With barriers, every level waits
// on its slowest directory twice (once to fix, once to list), so a tree with a few
// huge directories per level idles most workers; here a deep branch keeps
// descending while a wide one is still being listed.
//
// Optimization: if the directory is already traversable (owner/group/other has
// execute), we attempt readdir first without fixing. If readdir succeeds, the
// fix is skipped entirely — the entry stream still carries the directory, so the
// correct permissions get applied by the consumer. This reduces the pass to
// readdir-only for trees that are already traversable but have wrong ACLs.
//
// WHY THIS EMITS RATHER THAN A SEPARATE ParallelWalk RUNNING AFTER IT:
// the two were the same recursive readdir with the same token pool, differing
// only in that this one threw away what it read. Running both meant reading
// every directory twice — 27M READDIRs for a 13.5M-directory tree, on a phase
// that is purely round-trip bound. The readdir this function already performs is
// the enumeration.
//
// ORDERING HAZARD, unchanged by the fusion but worth stating: the consumer
// applies a directory's final permissions asynchronously, and the directory is
// emitted after its own readdir but while its subtree is still being walked. A
// spec whose directory ACL removes traverse for the running identity can
// therefore lock the walk out of not-yet-read children. ParallelWalk had exactly
// the same race for the same reason; specs in use preserve traverse for the
// runner. Closing it properly means emitting directories bottom-up on a
// per-directory refcount — NOT by having a parent wait on its children, which
// deadlocks against the bounded token pool.
//
// Pass ch == nil for fix-only behavior (the --pfind path, where an external
// enumerator produces the entries instead). RegisterDir is not called in that
// mode, matching what Pfind does.
func Prepass(root string, ch chan<- Entry, errs *WalkErrors, o PrepassOptions) PrepassResult {
	var fixed, fixErrors, readdirErrors, fixNanos, readdirNanos atomic.Int64

	workers := o.Workers
	if workers < 1 {
		workers = 1
	}
	logFunc := o.Log
	if logFunc == nil {
		logFunc = func(string) {}
	}

	// Timing the two round-trip sources separately is the point of the split:
	// fusing the phases removed the wall-clock boundary that used to show where
	// the time went, and "readdir vs fix" is the question that boundary was
	// answering. Both are summed across workers, so they measure work done, not
	// elapsed, and their total will exceed wall-clock by roughly the achieved
	// concurrency. Two vDSO clock reads per directory are noise next to an NFS
	// round trip.
	readDir := func(ref transport.Ref) ([]transport.Dirent, error) {
		t := time.Now()
		entries, err := o.Transport.ReadDir(ref)
		readdirNanos.Add(int64(time.Since(t)))
		return entries, err
	}
	var wasStopped atomic.Bool
	stopped := func() bool {
		if o.Stop != nil && o.Stop() {
			wasStopped.Store(true)
			return true
		}
		return false
	}
	fix := func(ref transport.Ref) (bool, string, FixResult) {
		t := time.Now()
		ok, msg, fr := o.Fix(ref)
		fixNanos.Add(int64(time.Since(t)))
		return ok, msg, fr
	}

	// A transport that lists in bounded batches (the kernel transport) is read
	// that way, so a directory's listing costs at most batch Dirents however wide
	// it is (PS-11). Without one, ReadDir materializes the whole listing.
	batch := o.ReadDirBatch
	if batch < 1 {
		batch = DefaultReadDirBatch
	}
	batcher, _ := o.Transport.(transport.DirBatcher)
	listBatched := func(ref transport.Ref, fn func([]transport.Dirent) error) (bool, error) {
		// Only the transport's own time counts as readdir time. A consumer
		// blocked on a full channel is the apply side's time, not the listing's.
		var inFn time.Duration
		t := time.Now()
		delivered, err := batcher.ReadDirBatches(ref, batch, func(b []transport.Dirent) error {
			t0 := time.Now()
			ferr := fn(b)
			inFn += time.Since(t0)
			return ferr
		})
		readdirNanos.Add(int64(time.Since(t) - inFn))
		return delivered, err
	}

	// Tokens bound how many directories are in flight. When none is free the
	// caller recurses inline rather than blocking, so work never stalls and
	// goroutine count stays capped.
	tokens := make(chan struct{}, workers)
	var wg sync.WaitGroup

	// process takes the directory's own mode as a parameter, filled from
	// whichever source already has it: the parent's Dirent when AttrsKnown is
	// true (the userspace transport, where FATTR4_MODE rode along with the
	// listing), otherwise modeKnown is false and the emission below pays for one
	// Stat — which is what this function did unconditionally before the
	// transport existed. The root always arrives with modeKnown false: it has no
	// parent Dirent to carry a mode.
	var process func(ref transport.Ref, dirMode uint32, modeKnown bool)
	process = func(ref transport.Ref, dirMode uint32, modeKnown bool) {
		defer wg.Done()

		if stopped() {
			return
		}
		var listingIncomplete bool
		if o.SkipDir != nil && o.SkipDir(ref.Path) {
			fixed.Add(1)
			return
		}

		// Fast path: try readdir before fixing. If the dir is already
		// traversable, we save one setxattr round-trip per directory.
		// When DirACL is set, fold the SETATTR into the READDIR COMPOUND.
		var aclApplied bool
		var fixResult FixResult
		var aclBytes []byte
		if o.DirACL != nil {
			aclBytes = o.DirACL(ref.Path)
		}

		// entryCount counts every child, directories included, matching what
		// ParallelWalk reported to RegisterDir — the checkpoint's per-directory
		// accounting is calibrated to that total.
		//
		// Child directories are collected here and descended into below rather
		// than recursed into from inside the listing. The descent is what makes the
		// difference: process recurses inline whenever no token is free, so a
		// single goroutine can be many levels deep, and every frame in that chain
		// used to keep its whole dirent slice reachable — workers × depth ×
		// dirents-per-directory live at once, on a tree where the dirents carry a
		// full path string and a filehandle each. Finishing the listing first, then
		// descending, leaves only the child directory refs pinned per level, and
		// closes the directory handle before the recursion opens another.
		entryCount := 0
		var childDirs []childDir
		consume := func(entries []transport.Dirent) error {
			for _, e := range entries {
				// The exclude test precedes every type dispatch, so an excluded
				// directory is pruned before its own fix as well as before its
				// readdir. Excluded entries are deliberately left out of entryCount:
				// that count is how many completion signals the checkpoint waits for,
				// and an entry no consumer ever sees never signals.
				if o.Exclude != nil && o.Exclude(e.Ref.Path) {
					continue
				}

				// Symlinks are never followed, so this must come before the IsDir
				// test: a symlink to a directory reports IsDir false but would
				// otherwise fall through to the file branch untagged.
				if e.IsSymlink {
					if ch != nil {
						ch <- Entry{Path: e.Ref.Path, DirPath: ref.Path, IsSymlink: true, FH: e.Ref.FH}
					}
					entryCount++
					continue
				}

				if e.IsDir {
					// A directory on another filesystem is out of scope like an
					// excluded one, and for the same reason is left out of
					// entryCount: it is never emitted, so it never signals, and
					// counting it kept its parent from ever completing (PS-11).
					if o.RootFSID != 0 && !sameFilesystem(o, errs, e) {
						continue
					}
					entryCount++
					childDirs = append(childDirs, childDir{ref: e.Ref, mode: e.Mode, modeKnown: e.AttrsKnown})
					continue
				}

				// Dirent.Mode is only meaningful when AttrsKnown, same as on the
				// directory branch above. Leaving it zero is not a loss: Entry.Mode
				// zero means "not known" to the apply workers, which then stat.
				// Trusting an unset mode instead would be a silent wrong result --
				// under --compare a file whose real mode is 0600 but whose bogus
				// cached mode happened to equal the spec would be skipped and the
				// run would still report success.
				var mode uint32
				if e.AttrsKnown {
					mode = e.Mode
				}
				if ch != nil {
					ch <- Entry{Path: e.Ref.Path, DirPath: ref.Path, IsDir: false, Mode: mode, FH: e.Ref.FH}
				}
				entryCount++
			}
			return nil
		}

		var delivered bool
		var err error
		if batcher != nil {
			// The kernel's ReadDirSetACL is a readdir followed by a SetACL anyway,
			// so doing the two here keeps its semantics exactly: the ACL is written
			// only after the whole listing, and a failed write leaves the directory
			// to the ordinary apply path.
			delivered, err = listBatched(ref, consume)
			if err == nil && len(aclBytes) > 0 {
				t := time.Now()
				aclApplied = o.Transport.SetACL(ref, aclBytes) == nil
				readdirNanos.Add(int64(time.Since(t)))
			}
		} else {
			var entries []transport.Dirent
			if len(aclBytes) > 0 {
				t := time.Now()
				entries, aclApplied, err = o.Transport.ReadDirSetACL(ref, aclBytes)
				readdirNanos.Add(int64(time.Since(t)))
			} else {
				entries, err = readDir(ref)
			}
			if err == nil {
				_ = consume(entries)
			}
		}
		listingFailed := func(err error) {
			readdirErrors.Add(1)
			if errs != nil {
				errs.Add(1)
			}
			logFunc(fmt.Sprintf("readdir %s: %v (listing incomplete)", ref.Path, err))
			listingIncomplete = true
		}
		if err != nil && delivered {
			// The listing failed partway through. Children already handed on
			// cannot be taken back, and a fix-and-retry would hand them on twice,
			// so the directory is counted as an error and left unregistered: the
			// checkpoint never completes it and a resume reads it again. The
			// children it did find are still descended, and the directory's own
			// Entry still goes out after them, so nothing found is lost.
			listingFailed(err)
		} else if err != nil {
			if isDescriptorExhaustion(err) {
				readdirErrors.Add(1)
				logFunc(fmt.Sprintf("readdir %s: %v (file descriptor exhaustion — raise ulimit -n)", ref.Path, err))
				return
			}
			// Dir not traversable — fix it first, then retry readdir.
			if stopped() {
				return
			}
			ok, msg, fr := fix(ref)
			if msg != "" {
				logFunc(msg)
			}
			if !ok {
				fixErrors.Add(1)
				return
			}
			fixed.Add(1)
			fixResult = fr
			if batcher != nil {
				delivered, err = listBatched(ref, consume)
			} else {
				var entries []transport.Dirent
				entries, err = readDir(ref)
				if err == nil {
					_ = consume(entries)
				}
			}
			if err != nil && delivered {
				listingFailed(err)
			} else if err != nil {
				if isDescriptorExhaustion(err) {
					readdirErrors.Add(1)
					logFunc(fmt.Sprintf("readdir %s: %v (file descriptor exhaustion — raise ulimit -n)", ref.Path, err))
				} else {
					fixErrors.Add(1)
				}
				return
			}
		}

		// Descend before emitting this directory's own Entry, which is the order
		// the loop above used to produce and is load-bearing on the kernel
		// transport: a child readdir resolves by path, so it needs this directory
		// to still be traversable. Emitting the parent first would let an apply
		// worker write a restrictive mode here while children are still unread.
		for _, c := range childDirs {
			wg.Add(1)
			select {
			case tokens <- struct{}{}:
				go func(r transport.Ref, m uint32, known bool) {
					process(r, m, known)
					<-tokens
				}(c.ref, c.mode, c.modeKnown)
			default:
				process(c.ref, c.mode, c.modeKnown)
			}
		}

		if ch == nil {
			return
		}

		// The directory itself goes out AFTER its readdir, so the consumer
		// cannot apply a restrictive ACL to it before we have its children.
		//
		// Passing 0 as the mode when it is not known would be wrong rather than
		// merely lossy: applyPosix treats a zero cachedMode as unknown and stats
		// again, so the saving is nil and the intent is muddied. The Stat here is
		// the one the pre-transport code performed for every directory; on the
		// userspace transport it never runs, because the parent's listing
		// already carried the mode.
		if !modeKnown {
			a, err := o.Transport.Stat(ref)
			if err != nil {
				if errs != nil {
					errs.Add(1)
				}
			} else {
				dirMode, modeKnown = a.Mode, true
			}
		}
		if modeKnown {
			ch <- Entry{Path: ref.Path, DirPath: ref.Path, IsDir: true, Mode: dirMode, FH: ref.FH, ACLApplied: aclApplied, Fix: fixResult}
		}

		if o.RegisterDir != nil && !listingIncomplete {
			o.RegisterDir(ref.Path, entryCount)
		}
	}

	// The root has no parent Dirent, so its mode is never known up front and its
	// Ref comes from the transport when the transport's own root is the tree
	// being walked — that is what carries the root filehandle on the userspace
	// transport.
	rootRef := transport.Ref{Path: root}
	if r, err := o.Transport.Root(); err == nil && r.Path == root {
		rootRef = r
	}

	wg.Add(1)
	process(rootRef, 0, false)
	wg.Wait()

	return PrepassResult{
		Fixed:         int(fixed.Load()),
		Errors:        int(fixErrors.Load()),
		ReaddirErrors: int(readdirErrors.Load()),
		FixTime:       time.Duration(fixNanos.Load()),
		ReaddirTime:   time.Duration(readdirNanos.Load()),
		Stopped:       wasStopped.Load(),
	}
}
