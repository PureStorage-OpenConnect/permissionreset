// Package restore is --restore-from: it writes each object's raw
// system.nfs4_acl from a reference tree (a snapshot path, usually) onto the live
// object at the same relative path, byte for byte and only where the live bytes
// differ (#56, docs/design-acl-restore.md).
//
// It has its own driver rather than threading a second source of truth through
// internal/run, which is spec-shaped from the preflight down. What it shares
// with the repair is the transport, the principal guards in internal/apply, the
// audit-bypass proof, the checkpoint and the evidence sink.
//
// The walk descends both trees together, one directory pair at a time, and
// joins the two sorted listings by name, so each child's type on both sides
// comes from READDIR with no per-object stat. A directory's own ACL is written
// only after everything under it has been handled, and the root last: the
// reference ACL of a directory may deny the running identity list or traverse,
// and writing it first could lock the walk out of the children it still has to
// restore.
package restore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/apply"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/auditproof"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/checkpoint"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/evidence"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/idmap"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs4acl"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/spec"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// Mode is what a run does with each compared pair.
type Mode int

const (
	// DryRun pairs the two trees and reports what an apply would compare. It
	// reads no ACL on either side: a dry run has no audit-bypass proof, a live
	// read without the proven bypass can empty inherited auditing (PS-02), and
	// whether the reference is a read-only snapshot is only probed under Apply.
	DryRun Mode = iota
	// Apply proves the bypass, compares every pair byte for byte and writes the
	// reference bytes where they differ.
	Apply
	// Validate proves the bypass and compares every pair byte for byte, with no
	// writes. Any mismatch fails the run.
	Validate
)

func (m Mode) String() string {
	switch m {
	case Apply:
		return "apply"
	case Validate:
		return "validate"
	default:
		return "dry-run"
	}
}

// ErrAuditVanished refuses a write that would remove audit entries: the live
// ACL has some and the reference has none. Auditing added since the snapshot,
// or a reference read that lost the entries, both produce it, and neither
// should be written over silently.
var ErrAuditVanished = errors.New("the live ACL has audit ACEs and the reference has none, so restoring it would remove them; " +
	"pass --allow-audit-removal if the reference is right")

// ErrAuditedObject is the restore's form of apply.ErrAuditedObject, and lifts
// with the same flag (design section 9, decision 2).
var ErrAuditedObject = errors.New("the live or reference ACL carries audit ACEs, so the restore was not written -- " +
	"on FlashArray an NFS ACL write marks the SACL and DACL protected (S:AI -> S:P, D:AI -> D:P), and the kernel " +
	"transport cannot tell FlashArray from FlashBlade; pass --allow-audited-dacl-reset to write it anyway (expected on FlashBlade)")

// ErrWritableReference refuses an --apply whose reference is writable. A
// snapshot is read-only, so a writable reference is either a deliberate copy
// or the two paths the wrong way round.
var ErrWritableReference = errors.New("the reference is writable; a snapshot is not. Check that the reference and the " +
	"target are not the wrong way round, then pass --allow-writable-reference to restore from it")

// Config is one restore run.
type Config struct {
	// Reference and Target are the resolved roots of the reference and the
	// live tree. The caller checks that both are directories and that neither
	// contains the other.
	Reference, Target string
	// Ref and Live are the transports rooted at Reference and Target.
	Ref, Live transport.Transport

	Mode    Mode
	Workers int

	// Excluder matches live paths; nil excludes nothing. Its patterns are the
	// Excludes, which bind the checkpoint.
	Excluder *spec.Excluder
	Excludes []string

	OneFilesystem bool

	// ReplacedCheck skips a pair whose file ids differ: an object deleted and
	// recreated under the same name since the snapshot, which would otherwise
	// get the old object's ACL (design section 4.6). It needs transports that
	// implement transport.InoLister; without one the check cannot run and Run
	// says so. FlashBlade keeps file ids in .snapshot (lab, Purity//FB 4.8.7).
	ReplacedCheck bool

	Checkpoint *checkpoint.Checkpoint // nil: no checkpoint
	Evidence   *evidence.Sink         // nil: no evidence; Run closes it
	Log        io.Writer              // error records; nil sends the first few to ErrOut

	AllowAuditedDACLReset  bool
	AllowAuditRemoval      bool
	AllowWritableReference bool
	// ReferenceWritable is the caller's answer, under Apply only, to whether
	// Reference accepts writes. An apply refuses a writable reference unless
	// AllowWritableReference. Other modes ignore it.
	ReferenceWritable bool

	Resolver idmap.Resolver

	// Prove proves the audit bypass before the first ACL read. Nil proves it on
	// a disposable probe under Target through Live.
	Prove func() (auditproof.Proof, error)
}

// Counts are every outcome, apart.
type Counts struct {
	Compared        int64 `json:"compared"` // pairs whose ACLs were read and compared
	Restored        int64 `json:"restored"`
	Same            int64 `json:"same"`
	Would           int64 `json:"would"`
	Mismatch        int64 `json:"mismatch"`
	DeletedSince    int64 `json:"deleted_since"`
	CreatedSince    int64 `json:"created_since"`
	Symlink         int64 `json:"symlink"`
	TypeChanged     int64 `json:"type_changed"`
	Excluded        int64 `json:"excluded"`
	OtherFilesystem int64 `json:"other_filesystem"`
	ReplacedSince   int64 `json:"replaced_since"`
	Resumed         int64 `json:"resumed_dirs"`
	Refused         int64 `json:"refused"`
	ReadErrors      int64 `json:"read_errors"`
	WriteErrors     int64 `json:"write_errors"`
	ListErrors      int64 `json:"list_errors"`
}

// Errors is every failure that makes the run exit non-zero, mismatches aside.
func (c Counts) Errors() int64 { return c.Refused + c.ReadErrors + c.WriteErrors + c.ListErrors }

// Result is what a run did.
type Result struct {
	Mode            string             `json:"mode"`
	Reference       string             `json:"reference"`
	Target          string             `json:"target"`
	Counts          Counts             `json:"counts"`
	RefusedBy       map[string]int64   `json:"refused_by,omitempty"`
	Proof           string             `json:"audit_bypass_proof,omitempty"`
	Interrupted     bool               `json:"interrupted"`
	EvidenceStopped bool               `json:"evidence_stopped"`
	Elapsed         float64            `json:"elapsed_seconds"`
	Evidence        *evidence.Manifest `json:"evidence,omitempty"`
}

// OK reports whether the run did everything it set out to do.
func (r Result) OK() bool {
	return !r.Interrupted && !r.EvidenceStopped && r.Counts.Errors() == 0 && r.Counts.Mismatch == 0
}

const errOutLimit = 20

// Run restores (or compares) Target from Reference. A non-nil error means the
// run refused to start or could not finish its bookkeeping; per-object failures
// are counted in the Result instead.
func Run(ctx context.Context, cfg Config, out, errOut io.Writer) (res Result, runErr error) {
	start := time.Now()
	res = Result{Mode: cfg.Mode.String(), Reference: cfg.Reference, Target: cfg.Target}
	e := &engine{cfg: cfg, ctx: ctx, errOut: errOut, refusedBy: map[string]int64{}}
	reachedEnd := false
	defer func() {
		res.Counts = e.counts()
		res.RefusedBy = e.refusedByCopy()
		res.EvidenceStopped = e.stopped.Load()
		res.Elapsed = time.Since(start).Seconds()
		if cfg.Evidence != nil {
			var reasons []string
			if res.Interrupted {
				reasons = append(reasons, "run interrupted")
			}
			m, err := cfg.Evidence.Close(reachedEnd && !res.Interrupted && !res.EvidenceStopped, reasons...)
			res.Evidence = &m
			if err != nil && runErr == nil {
				runErr = fmt.Errorf("close evidence: %w", err)
			}
		}
	}()

	if cfg.Workers < 1 {
		cfg.Workers = 1
		e.cfg.Workers = 1
	}
	fmt.Fprintf(out, "Restore %s: ACLs from %s\n", cfg.Mode, cfg.Reference)
	fmt.Fprintf(out, "                 onto %s\n", cfg.Target)
	if len(cfg.Excludes) > 0 {
		fmt.Fprintf(out, "Excluding: %s\n", strings.Join(cfg.Excludes, " "))
	}

	if cfg.Mode == Apply && cfg.ReferenceWritable && !cfg.AllowWritableReference {
		return res, ErrWritableReference
	}

	if cfg.Mode != DryRun {
		// PS-02: the proof comes before any live or reference read, and a
		// failure fails the run closed. It runs on the live filesystem, since a
		// snapshot is read-only.
		prove := cfg.Prove
		if prove == nil {
			prove = func() (auditproof.Proof, error) {
				return auditproof.Prove(cfg.Live, transport.Ref{Path: cfg.Target})
			}
		}
		proof, err := prove()
		if err != nil {
			return res, fmt.Errorf("audit-bypass proof failed, nothing was read or written: %w", err)
		}
		res.Proof = proof.String()
		fmt.Fprintf(errOut, "NOTE: %s (on the live filesystem; the reference is read with the same identity)\n", proof)
	} else {
		fmt.Fprintln(errOut, "NOTE: dry run: no ACL is read on either side (no audit-bypass proof runs without --apply or --validate), so every pair is reported as WOULD compare; --validate compares them")
	}

	if cfg.ReplacedCheck {
		_, okR := cfg.Ref.(transport.InoLister)
		_, okL := cfg.Live.(transport.InoLister)
		if !okR || !okL {
			fmt.Fprintln(errOut, "NOTE: this transport cannot list file ids, so objects recreated since the reference are not detected")
			e.cfg.ReplacedCheck = false
		}
	}

	if cfg.OneFilesystem {
		ra, err := cfg.Ref.Stat(transport.Ref{Path: cfg.Reference})
		if err != nil {
			return res, fmt.Errorf("--one-filesystem: %w", err)
		}
		la, err := cfg.Live.Stat(transport.Ref{Path: cfg.Target})
		if err != nil {
			return res, fmt.Errorf("--one-filesystem: %w", err)
		}
		e.refFSID, e.liveFSID = ra.FSID, la.FSID
	}

	root := &dirNode{rel: ""}
	if cfg.Checkpoint != nil && cfg.Checkpoint.DirCompleted(cfg.Target) {
		e.c.resumed.Add(1)
		fmt.Fprintln(out, "Checkpoint: the whole tree is already complete")
	} else {
		e.runPool(root)
	}

	res.Interrupted = ctx.Err() != nil
	reachedEnd = true
	if cfg.Checkpoint != nil {
		if n, sample := cfg.Checkpoint.DuplicateCompletions(); n > 0 {
			return res, fmt.Errorf("internal error: %d duplicate checkpoint completions (first: %s); the checkpoint is not trustworthy", n, sample)
		}
	}
	if s := e.suppressed.Load(); s > 0 {
		fmt.Fprintf(errOut, "... %d more errors not shown; pass --log to keep them all\n", s)
	}
	if s := e.replSuppressed.Load(); s > 0 {
		fmt.Fprintf(errOut, "... %d more replaced-since paths not shown; pass --log to keep them all\n", s)
	}
	printSummary(out, e.counts(), e.refusedByCopy(), cfg.Mode, res.Interrupted, e.stopped.Load(), time.Since(start))
	return res, nil
}

// dirNode is one directory pair in flight. pending counts what must finish
// before the directory's own ACL is handled: one for its listing, plus one per
// child handed to a worker (a file pair, or a child directory pair whose whole
// subtree must finish first).
type dirNode struct {
	rel     string
	parent  *dirNode
	pending atomic.Int64
}

type jobKind int

const (
	jobList jobKind = iota // list a directory pair and hand out its children
	jobFile                // compare/restore one non-directory pair
	jobSelf                // compare/restore a directory pair's own ACL
)

type job struct {
	kind jobKind
	node *dirNode // jobList, jobSelf: the directory; jobFile: its parent
	name string   // jobFile
}

type counters struct {
	compared, restored, same, would, mismatch                          atomic.Int64
	deleted, created, symlink, typeChanged, excluded, otherFS, resumed atomic.Int64
	replaced                                                           atomic.Int64
	refused, readErr, writeErr, listErr                                atomic.Int64
}

type engine struct {
	cfg    Config
	ctx    context.Context
	errOut io.Writer

	refFSID, liveFSID uint64

	c          counters
	refusedMu  sync.Mutex
	refusedBy  map[string]int64
	stopped    atomic.Bool // the evidence or log failed: make no further changes
	logMu      sync.Mutex
	shown      atomic.Int64
	suppressed atomic.Int64

	// replaced-since skips are shown like errors, with their own cap, so a
	// burst of them cannot hide an error and the reverse.
	replShown      atomic.Int64
	replSuppressed atomic.Int64

	// The work stack. LIFO, so the walk runs roughly depth first and the
	// stack holds about one listing per level rather than a whole level.
	mu          sync.Mutex
	cond        *sync.Cond
	stack       []job
	outstanding int // pushed and not yet finished
}

func (e *engine) counts() Counts {
	c := &e.c
	return Counts{
		Compared: c.compared.Load(), Restored: c.restored.Load(), Same: c.same.Load(), Would: c.would.Load(),
		Mismatch: c.mismatch.Load(), DeletedSince: c.deleted.Load(), CreatedSince: c.created.Load(),
		Symlink: c.symlink.Load(), TypeChanged: c.typeChanged.Load(), Excluded: c.excluded.Load(),
		OtherFilesystem: c.otherFS.Load(), ReplacedSince: c.replaced.Load(), Resumed: c.resumed.Load(), Refused: c.refused.Load(),
		ReadErrors: c.readErr.Load(), WriteErrors: c.writeErr.Load(), ListErrors: c.listErr.Load(),
	}
}

func (e *engine) refusedByCopy() map[string]int64 {
	e.refusedMu.Lock()
	defer e.refusedMu.Unlock()
	if len(e.refusedBy) == 0 {
		return nil
	}
	out := make(map[string]int64, len(e.refusedBy))
	for k, v := range e.refusedBy {
		out[k] = v
	}
	return out
}

func (e *engine) runPool(root *dirNode) {
	e.cond = sync.NewCond(&e.mu)
	e.push(job{kind: jobList, node: root})
	var wg sync.WaitGroup
	for i := 0; i < e.cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				j, ok := e.pop()
				if !ok {
					return
				}
				if e.ctx.Err() == nil && !e.stopped.Load() {
					e.do(j)
				}
				e.finish()
			}
		}()
	}
	wg.Wait()
}

func (e *engine) push(j job) {
	e.mu.Lock()
	e.stack = append(e.stack, j)
	e.outstanding++
	e.mu.Unlock()
	e.cond.Signal()
}

func (e *engine) pop() (job, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for len(e.stack) == 0 {
		if e.outstanding == 0 {
			return job{}, false
		}
		e.cond.Wait()
	}
	j := e.stack[len(e.stack)-1]
	e.stack = e.stack[:len(e.stack)-1]
	return j, true
}

func (e *engine) finish() {
	e.mu.Lock()
	e.outstanding--
	done := e.outstanding == 0
	e.mu.Unlock()
	if done {
		e.cond.Broadcast()
	}
}

func (e *engine) do(j job) {
	switch j.kind {
	case jobList:
		e.listPair(j.node)
	case jobFile:
		rel := path.Join(j.node.rel, j.name)
		if e.processPair(rel, false) && e.cfg.Checkpoint != nil {
			e.cfg.Checkpoint.EntryDone(e.live(j.node.rel))
		}
		e.childFinished(j.node)
	case jobSelf:
		if e.processPair(j.node.rel, true) && e.cfg.Checkpoint != nil {
			e.cfg.Checkpoint.DirApplyDone(e.live(j.node.rel))
		}
		if j.node.parent != nil {
			e.childFinished(j.node.parent)
		}
	}
}

// childFinished counts one of n's children done, and hands out n's own ACL
// once nothing under it is outstanding.
func (e *engine) childFinished(n *dirNode) {
	if n.pending.Add(-1) == 0 {
		e.push(job{kind: jobSelf, node: n})
	}
}

func (e *engine) ref(rel string) string  { return joinRel(e.cfg.Reference, rel) }
func (e *engine) live(rel string) string { return joinRel(e.cfg.Target, rel) }

func joinRel(root, rel string) string {
	if rel == "" {
		return root
	}
	return root + "/" + rel
}

type side uint8

const (
	missing side = iota
	isFile
	isDir
	isSymlink
)

func kindOf(d transport.Dirent) side {
	switch {
	case d.IsSymlink:
		return isSymlink
	case d.IsDir:
		return isDir
	default:
		return isFile
	}
}

// listPair lists one directory pair, joins the listings by name, records each
// skip, and hands out the pairs to compare.
func (e *engine) listPair(n *dirNode) {
	n.pending.Store(1) // the listing itself
	refDir, liveDir := e.ref(n.rel), e.live(n.rel)
	refEnts, err := e.readDir(e.cfg.Ref, refDir)
	if err != nil {
		e.c.listErr.Add(1)
		e.errorf("ERR: readdir reference %s: %v", refDir, err)
		e.abandon(n)
		return
	}
	liveEnts, err := e.readDir(e.cfg.Live, liveDir)
	if err != nil {
		e.c.listErr.Add(1)
		e.errorf("ERR: readdir %s: %v", liveDir, err)
		e.abandon(n)
		return
	}

	signals := 0 // children that will report completion to the checkpoint
	skip := func(ctr *atomic.Int64, reason, p string) {
		ctr.Add(1)
		e.audit(fmt.Sprintf("SKIP: %s %s", reason, p))
		signals++
		if e.cfg.Checkpoint != nil {
			e.cfg.Checkpoint.EntryDone(liveDir)
		}
	}

	// Both listings are sorted by name (the Transport contract), so a merge
	// join pairs them without holding a map.
	i, k := 0, 0
	for i < len(refEnts) || k < len(liveEnts) {
		var name string
		var refIno, liveIno uint64
		rk, lk := missing, missing
		switch {
		case k >= len(liveEnts) || (i < len(refEnts) && refEnts[i].Name < liveEnts[k].Name):
			name, rk = refEnts[i].Name, kindOf(refEnts[i])
			i++
		case i >= len(refEnts) || liveEnts[k].Name < refEnts[i].Name:
			name, lk = liveEnts[k].Name, kindOf(liveEnts[k])
			k++
		default:
			name, rk, lk = refEnts[i].Name, kindOf(refEnts[i]), kindOf(liveEnts[k])
			refIno, liveIno = refEnts[i].Ino, liveEnts[k].Ino
			i++
			k++
		}
		rel := path.Join(n.rel, name)
		livePath := e.live(rel)

		// Excludes match the live path, as a repair's do, and prune.
		if e.cfg.Excluder != nil && e.cfg.Excluder.Match(livePath) {
			e.c.excluded.Add(1)
			e.audit("EXCLUDE: " + livePath)
			continue
		}
		switch {
		case lk == missing:
			skip(&e.c.deleted, "deleted-since", livePath)
		case rk == missing:
			// Created since the reference: nothing to restore it from. Not a
			// child the checkpoint counts, since nothing is done to it.
			e.c.created.Add(1)
			e.audit("SKIP: created-since " + livePath)
		case rk == isSymlink || lk == isSymlink:
			skip(&e.c.symlink, "symlink", livePath)
		case rk != lk:
			skip(&e.c.typeChanged, "type-changed", livePath)
		case e.replacedSince(rel, liveDir, refIno, liveIno, &signals):
			// Counted and recorded inside; a directory is not descended.
		case rk == isFile:
			signals++
			n.pending.Add(1)
			e.push(job{kind: jobFile, node: n, name: name})
		default: // directory on both sides
			if e.cfg.OneFilesystem && !e.sameFilesystem(rel) {
				skip(&e.c.otherFS, "other-filesystem", livePath)
				continue
			}
			signals++
			if e.cfg.Checkpoint != nil && e.cfg.Checkpoint.SkipCompleted(livePath) {
				e.c.resumed.Add(1)
				continue
			}
			n.pending.Add(1)
			e.push(job{kind: jobList, node: &dirNode{rel: rel, parent: n}})
		}
	}
	if e.cfg.Checkpoint != nil {
		e.cfg.Checkpoint.RegisterDir(liveDir, signals)
	}
	e.childFinished(n) // the listing is done
}

// readDir lists dir with file ids when the replaced check needs them.
func (e *engine) readDir(t transport.Transport, dir string) ([]transport.Dirent, error) {
	if e.cfg.ReplacedCheck {
		if l, ok := t.(transport.InoLister); ok {
			return l.ReadDirIno(transport.Ref{Path: dir})
		}
	}
	return t.ReadDir(transport.Ref{Path: dir})
}

// replacedSince reports whether a same-type pair is an object recreated since
// the reference: its file ids differ. READDIR's ids are confirmed with an
// lstat on both sides before a pair is skipped, so an id READDIR reports
// differently from stat (a mount point's, say) cannot skip a real pair. It
// records the skip, or a read error, itself.
func (e *engine) replacedSince(rel, liveDir string, refIno, liveIno uint64, signals *int) bool {
	if !e.cfg.ReplacedCheck || refIno == 0 || liveIno == 0 || refIno == liveIno {
		return false
	}
	livePath := e.live(rel)
	ra, err := e.cfg.Ref.Stat(transport.Ref{Path: e.ref(rel)})
	if err != nil {
		e.c.readErr.Add(1)
		e.errorf("ERR: replaced check: %v", err)
		return true
	}
	la, err := e.cfg.Live.Stat(transport.Ref{Path: livePath})
	if err != nil {
		e.c.readErr.Add(1)
		e.errorf("ERR: replaced check: %v", err)
		return true
	}
	if ra.Ino == 0 || la.Ino == 0 || ra.Ino == la.Ino {
		return false
	}
	e.c.replaced.Add(1)
	e.noticef("SKIP: replaced-since %s (file id %d, reference %d)", livePath, la.Ino, ra.Ino)
	*signals++
	if e.cfg.Checkpoint != nil {
		e.cfg.Checkpoint.EntryDone(liveDir)
	}
	return true
}

// abandon gives up on a directory pair whose listing failed: neither its
// subtree nor its own ACL is handled, and it is never recorded complete, so a
// resume tries it again. Its parent still gets its own turn.
func (e *engine) abandon(n *dirNode) {
	if n.parent != nil {
		e.childFinished(n.parent)
	}
}

func (e *engine) sameFilesystem(rel string) bool {
	ra, err := e.cfg.Ref.Stat(transport.Ref{Path: e.ref(rel)})
	if err != nil {
		e.c.readErr.Add(1)
		e.errorf("ERR: --one-filesystem: %v", err)
		return false
	}
	la, err := e.cfg.Live.Stat(transport.Ref{Path: e.live(rel)})
	if err != nil {
		e.c.readErr.Add(1)
		e.errorf("ERR: --one-filesystem: %v", err)
		return false
	}
	return ra.FSID == e.refFSID && la.FSID == e.liveFSID
}

// processPair compares (and on an apply, restores) one pair already known to
// be the same non-symlink type. It returns true when the pair was handled
// without an error, which is what lets the checkpoint count it done.
func (e *engine) processPair(rel string, dir bool) bool {
	refPath, livePath := e.ref(rel), e.live(rel)
	kind := "file"
	if dir {
		kind = "dir"
	}

	if e.cfg.Mode == DryRun {
		e.c.would.Add(1)
		e.audit(fmt.Sprintf("WOULD: compare %s %s with %s", kind, livePath, refPath))
		return true
	}

	refACL, err := e.cfg.Ref.GetACL(transport.Ref{Path: refPath})
	if err != nil {
		e.c.readErr.Add(1)
		e.errorf("ERR: getxattr reference %s: %v", refPath, err)
		return false
	}
	liveRef := transport.Ref{Path: livePath}
	liveACL, err := e.cfg.Live.GetACL(liveRef)
	if err != nil {
		e.c.readErr.Add(1)
		e.errorf("ERR: getxattr %s: %v", livePath, err)
		return false
	}
	e.c.compared.Add(1)

	// Raw bytes, not structure: these bytes are what the array itself
	// produced on a read, so an object that already matches reads back
	// byte-identical (design section 4.3).
	if bytes.Equal(refACL, liveACL) {
		e.c.same.Add(1)
		e.audit("SAME: " + livePath)
		return true
	}
	if e.cfg.Mode == Validate {
		e.c.mismatch.Add(1)
		e.errorf("MISMATCH: %s: %s (live vs reference %s)", livePath, apply.DescribeACLMismatch(liveACL, refACL, e.cfg.Resolver), refPath)
		return true
	}

	// The guards apply only to an object about to be written: a pair that
	// already matches is left alone whatever it names.
	_, _, _, liveSacl, err := nfs4acl.SplitRaw(liveACL)
	if err != nil {
		e.refuse(err, fmt.Errorf("%s: parse live ACL: %w", livePath, err))
		return false
	}
	refSacl, err := apply.CheckRestorable(refACL)
	if err != nil {
		e.refuse(err, fmt.Errorf("%s: reference %s: %w", livePath, refPath, err))
		return false
	}
	if liveSacl > 0 && refSacl == 0 && !e.cfg.AllowAuditRemoval {
		e.refuse(ErrAuditVanished, fmt.Errorf("%s: %w (%d live audit ACEs)", livePath, ErrAuditVanished, liveSacl))
		return false
	}
	if (liveSacl > 0 || refSacl > 0) && !e.cfg.AllowAuditedDACLReset {
		e.refuse(ErrAuditedObject, fmt.Errorf("%s: %w (%d live, %d reference audit ACEs)", livePath, ErrAuditedObject, liveSacl, refSacl))
		return false
	}

	if e.stopped.Load() {
		return false
	}
	if err := e.cfg.Live.SetACL(liveRef, refACL); err != nil {
		e.c.writeErr.Add(1)
		e.errorf("ERR: setxattr %s: %v", livePath, err)
		return false
	}
	e.c.restored.Add(1)
	rec := fmt.Sprintf("OK: restore nfs4_acl %s from %s", livePath, refPath)
	if e.cfg.Evidence != nil && e.cfg.Evidence.Profile() == evidence.ProfileDetailed {
		rec += "\tbefore=" + formatACL(liveACL)
	}
	e.audit(rec)
	return true
}

func formatACL(raw []byte) string {
	lines, err := nfs4acl.FormatACL(raw)
	if err != nil {
		return "undecodable"
	}
	return strings.Join(lines, ",")
}

// refuse counts a guard refusal under the guard's name and records it.
func (e *engine) refuse(sentinel, err error) {
	e.c.refused.Add(1)
	e.refusedMu.Lock()
	e.refusedBy[guardName(sentinel)]++
	e.refusedMu.Unlock()
	e.errorf("ERR: %v", err)
}

func guardName(err error) string {
	switch {
	case errors.Is(err, apply.ErrUnmappedPrincipal):
		return "unmapped_principal"
	case errors.Is(err, apply.ErrSyntheticRangePrincipal):
		return "synthetic_range_principal"
	case errors.Is(err, apply.ErrUnpreservableAudit):
		return "unpreservable_audit"
	case errors.Is(err, ErrAuditVanished):
		return "audit_vanished"
	case errors.Is(err, ErrAuditedObject):
		return "audited_object"
	default:
		return "unparseable_acl"
	}
}

// audit writes one evidence record. A refused write stops further changes.
func (e *engine) audit(rec string) {
	if e.cfg.Evidence == nil {
		return
	}
	if !e.cfg.Evidence.Write(rec) {
		e.stop("evidence write", e.cfg.Evidence.Err())
	}
}

// errorf writes an error (or mismatch) record to the evidence and the log. With
// no log, the first few go to errOut so they are not lost silently.
func (e *engine) errorf(format string, args ...any) {
	e.show(fmt.Sprintf(format, args...), &e.shown, &e.suppressed)
}

// noticef is errorf for a skip the operator must see by path: an object
// recreated since the reference keeps its new ACL, and may need restoring by
// hand. The other skips (deleted, created, symlink, type changed, excluded)
// are expected and stay in the evidence only.
func (e *engine) noticef(format string, args ...any) {
	e.show(fmt.Sprintf(format, args...), &e.replShown, &e.replSuppressed)
}

// show writes msg to the evidence and the log, or with no log, up to
// errOutLimit of them (counted by shown) to errOut.
func (e *engine) show(msg string, shown, suppressed *atomic.Int64) {
	e.audit(msg)
	if e.cfg.Log == nil {
		if shown.Add(1) <= errOutLimit {
			e.logMu.Lock()
			fmt.Fprintln(e.errOut, msg)
			e.logMu.Unlock()
		} else {
			suppressed.Add(1)
		}
		return
	}
	e.logMu.Lock()
	_, err := fmt.Fprintln(e.cfg.Log, msg)
	e.logMu.Unlock()
	if err != nil {
		e.stop("error log write", err)
	}
}

func (e *engine) stop(what string, err error) {
	if e.stopped.CompareAndSwap(false, true) {
		fmt.Fprintf(e.errOut, "ERROR: %s failed: %v; making no further changes\n", what, err)
	}
}

func printSummary(out io.Writer, c Counts, refusedBy map[string]int64, mode Mode, interrupted, stopped bool, elapsed time.Duration) {
	heading := "Restore complete"
	if mode == Validate {
		heading = "Restore validation complete"
	} else if mode == DryRun {
		heading = "Restore dry run complete"
	}
	if interrupted || stopped {
		heading += " (INCOMPLETE)"
	}
	fmt.Fprintln(out, "\n"+heading)
	switch mode {
	case DryRun:
		fmt.Fprintf(out, "  Would compare:    %d\n", c.Would)
	case Validate:
		fmt.Fprintf(out, "  Compared:         %d\n", c.Compared)
		fmt.Fprintf(out, "  Same:             %d\n", c.Same)
		fmt.Fprintf(out, "  Mismatch:         %d\n", c.Mismatch)
	default:
		fmt.Fprintf(out, "  Compared:         %d\n", c.Compared)
		fmt.Fprintf(out, "  Restored:         %d\n", c.Restored)
		fmt.Fprintf(out, "  Same:             %d (already byte-identical)\n", c.Same)
	}
	fmt.Fprintf(out, "  Deleted since:    %d (in the reference only; nothing done)\n", c.DeletedSince)
	fmt.Fprintf(out, "  Created since:    %d (live only; nothing done)\n", c.CreatedSince)
	fmt.Fprintf(out, "  Symlinks:         %d (on either side; not followed)\n", c.Symlink)
	fmt.Fprintf(out, "  Type changed:     %d (nothing done, not descended)\n", c.TypeChanged)
	fmt.Fprintf(out, "  Replaced since:   %d (same name, different file id; nothing done, not descended)\n", c.ReplacedSince)
	if c.Excluded > 0 {
		fmt.Fprintf(out, "  Excluded:         %d\n", c.Excluded)
	}
	if c.OtherFilesystem > 0 {
		fmt.Fprintf(out, "  Other filesystem: %d\n", c.OtherFilesystem)
	}
	if c.Resumed > 0 {
		fmt.Fprintf(out, "  Resumed:          %d directories already complete in the checkpoint\n", c.Resumed)
	}
	fmt.Fprintf(out, "  Refused:          %d", c.Refused)
	if len(refusedBy) > 0 {
		var parts []string
		for _, k := range []string{"audited_object", "audit_vanished", "unmapped_principal", "synthetic_range_principal", "unpreservable_audit", "unparseable_acl"} {
			if v := refusedBy[k]; v > 0 {
				parts = append(parts, fmt.Sprintf("%s %d", k, v))
			}
		}
		fmt.Fprintf(out, " (%s)", strings.Join(parts, ", "))
	}
	fmt.Fprintln(out)
	fmt.Fprintf(out, "  Errors:           %d (read %d, write %d, list %d)\n", c.ReadErrors+c.WriteErrors+c.ListErrors, c.ReadErrors, c.WriteErrors, c.ListErrors)
	fmt.Fprintf(out, "  Elapsed:          %.1fs\n", elapsed.Seconds())
	if s := elapsed.Seconds(); s > 0 && c.Compared > 0 {
		fmt.Fprintf(out, "  Rate:             %.0f pairs/sec compared\n", float64(c.Compared)/s)
	}
}
