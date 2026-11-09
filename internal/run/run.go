// Package run owns one complete permission-repair run independently of the
// command-line interface that configured it.
package run

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/apply"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/checkpoint"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/evidence"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/idmap"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs4acl"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/spec"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/stats"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/walk"
)

// rootSquashHint explains a userspace failure that a squashed root credential
// would have produced. It is an explanation of something that already went
// wrong, not a warning issued before anything has: uid 0 is a perfectly
// ordinary way to run against an export that does not squash, so the fact is
// worth saying only once it might be the reason for a failure the operator is
// already looking at.
//
// It writes nothing on the kernel transport, where the mount authenticates and
// AUTH_SYS never goes on the wire, and nothing for any other uid.
func rootSquashHint(errOut io.Writer, cfg Config) {
	if cfg.Transport != "userspace" {
		return
	}
	uid := nfs41.CurrentAuthSys().UID
	if cfg.Auth != nil {
		uid = cfg.Auth.UID
	}
	if uid != 0 {
		return
	}
	fmt.Fprintln(errOut, "note: the AUTH_SYS uid was 0. Exports commonly squash root to nobody, "+
		"so a userspace run can connect and still be denied on every object. If that is what "+
		"happened here, give --auth-uid/--auth-gid for an identity the array's directory knows.")
}

// runPreflight runs apply.ProbePreflight against the real target and renders
// its outcome for the operator. It is the one call site for both the apply
// path and --validate (runValidate calls it directly), so a privilege or
// retention failure is reported identically no matter which flag triggered
// it.
//
// ErrAuditPrivilege and ErrAuditNotRetained are handled before the generic
// message: each names a specific, actionable cause for a sacl: spec, and the
// "common causes" list below -- aimed at identity mapping and ACL support --
// would otherwise bury it. They can also come from apply.ProveAuditBypass's
// privilege proof (PS-02), ahead of any live root read, and are rendered the
// same way either way.
func runPreflight(tr transport.Transport, cfg Config, errOut io.Writer) error {
	var err error

	// CheckKeepDACLTarget reads root's live ACL, and a DACL reset that keeps
	// auditing (an acl: rule with no sacl: key, without --sacl) reads every
	// object's. On at least one array an unprivileged read has been observed
	// to empty inherited auditing (PS-02, #71), so reading an object to keep
	// its auditing can itself destroy it. Prove the audit bypass on a
	// disposable probe target FIRST -- never touching root -- and fail closed
	// before any live read runs at all. This must stay the first thing
	// runPreflight does.
	if needsAuditBypassProof(cfg) {
		err = proveAndReport(tr, cfg, errOut)
	}

	// A DACL-keeping rule writes the DACL it reads back to the array, so check
	// the root before the probe writes anything: if the root already shows an
	// unmapped principal, the whole run is refused instead of failing per object.
	if err == nil && len(cfg.Spec.KeepDACLRules()) > 0 {
		err = apply.CheckKeepDACLTarget(tr, transport.Ref{Path: cfg.Root})
	}
	if err == nil {
		err = apply.ProbePreflight(tr, transport.Ref{Path: cfg.Root}, cfg.Spec)
	}
	if err == nil {
		if cfg.Spec.Protocol == "nfsv4" && !cfg.Validate {
			unmappedReadBackWarning(tr, cfg, errOut)
		}
		return nil
	}
	return renderPreflightErr(err, cfg, errOut)
}

// needsAuditBypassProof reports whether the run reads existing objects' NFSv4
// ACLs, so the audit bypass must be proven on a disposable probe first (PS-02,
// #71): a DACL-keeping rule reads root and every object, a DACL reset that
// keeps auditing reads every object -- on --validate too, which reads every
// object whatever the spec says -- and --compare reads every object before
// the blind write it may then skip, which would leave an audit ACL the read
// emptied in place.
func needsAuditBypassProof(cfg Config) bool {
	if cfg.Spec.Protocol != "nfsv4" {
		return false
	}
	return len(cfg.Spec.KeepDACLRules()) > 0 ||
		(!cfg.Sacl && len(cfg.Spec.MissingSACL()) > 0) ||
		cfg.Validate || cfg.Compare
}

// proveAuditBypass runs only the audit-bypass proof and renders a failure the
// way runPreflight does. --validate uses it for a spec with no sacl: key: the
// full preflight would also write the spec's ACL to the probe, which proves
// nothing a read-only run needs.
func proveAuditBypass(tr transport.Transport, cfg Config, errOut io.Writer) error {
	if err := proveAndReport(tr, cfg, errOut); err != nil {
		return renderPreflightErr(err, cfg, errOut)
	}
	return nil
}

// proveAndReport runs the audit-bypass proof and, when it passes, prints one
// line saying so. Both callers run it before any live ACL read, so the line's
// place in the output shows the proof came first (#31). A failure is returned
// unprinted, for the caller to render.
func proveAndReport(tr transport.Transport, cfg Config, errOut io.Writer) error {
	proof, err := apply.ProveAuditBypass(tr, transport.Ref{Path: cfg.Root})
	if err != nil {
		return err
	}
	fmt.Fprintf(errOut, "NOTE: %s\n", proof)
	return nil
}

// renderPreflightErr prints a preflight or audit-bypass failure with its
// operator text and returns the run error for it.
func renderPreflightErr(err error, cfg Config, errOut io.Writer) error {
	switch {
	case errors.Is(err, apply.ErrUnmappedPrincipal):
		fmt.Fprintf(errOut, "ERROR: %v\n", err)
		unmappedPrincipalHint(errOut)
		return fmt.Errorf("%w: %w", errRunFailed, err)
	case errors.Is(err, apply.ErrSyntheticRangePrincipal):
		fmt.Fprintf(errOut, "ERROR: %v\n", err)
		fmt.Fprintln(errOut, "FlashBlade shows a SID with no RFC 2307 id as 1000000000 + RID, and on an NFS write it")
		fmt.Fprintln(errOut, "reads every id at or above 1000000000 that way, including real uidNumbers/gidNumbers that")
		fmt.Fprintln(errOut, "high and the ids it gives BUILTIN\\* and other well-known SIDs. The entry would come back")
		fmt.Fprintln(errOut, "naming a different SID, with nothing reported. Nothing was written. See RISKS.md #12.")
		return fmt.Errorf("%w: %w", errRunFailed, err)
	case errors.Is(err, apply.ErrAuditPrivilege):
		fmt.Fprintf(errOut, "ERROR: %v\n", err)
		fmt.Fprintln(errOut, "Writing audit (SACL) ACEs needs the array's audit bypass. That means one of:")
		fmt.Fprintln(errOut, "  - root over AUTH_SYS with root squash off on the export")
		fmt.Fprintln(errOut, "    (kernel: mount NFSv4.1 as root; userspace: --auth-uid 0), or")
		fmt.Fprintln(errOut, "  - an identity the array grants the audit bypass directly.")
		fmt.Fprintln(errOut, "Domain Admins membership is not enough.")
	case errors.Is(err, apply.ErrAuditNotRetained):
		fmt.Fprintf(errOut, "ERROR: %v\n", err)
		fmt.Fprintln(errOut, "The array accepted the preflight write, but the read-back carries no audit ACEs:")
		fmt.Fprintln(errOut, "it dropped them instead of keeping them.")
	default:
		fmt.Fprintf(errOut, "ERROR: preflight probe failed: %v\n", err)
		fmt.Fprintln(errOut, "Fix the spec or environment before running. Common causes:")
		fmt.Fprintln(errOut, "  - NFSv4 user@domain principal not resolvable by idmapd (EINVAL)")
		fmt.Fprintln(errOut, "  - insufficient permissions on target directory")
		fmt.Fprintln(errOut, "  - NFS mount not supporting NFSv4 ACLs")
		rootSquashHint(errOut, cfg)
	}
	return errRunFailed
}

// unmappedReadBackWarning warns, without stopping the run, about spec
// principals the array reads back as nobody (apply.ProbeUnmappedPrincipals).
// On FlashArray that is expected for a principal with no RFC 2307 id: the SID
// is stored and SMB shows the right account (#50), so the reset is correct.
// What breaks is everything that trusts the NFS view afterwards. A failed
// probe is a warning too: the ordinary preflight already passed, and an array
// that refuses a principal fails the objects that name it on its own.
func unmappedReadBackWarning(tr transport.Transport, cfg Config, errOut io.Writer) {
	who, err := apply.ProbeUnmappedPrincipals(tr, transport.Ref{Path: cfg.Root}, cfg.Spec)
	if err != nil {
		fmt.Fprintf(errOut, "WARNING: could not check how the array reads back the spec's principals: %v\n", err)
		return
	}
	if len(who) == 0 {
		return
	}
	fmt.Fprintln(errOut, "WARNING: the array reads these spec principals back as nobody (65534) over NFS:")
	for _, w := range who {
		fmt.Fprintf(errOut, "  %s\n", w)
	}
	fmt.Fprintln(errOut, "They have no RFC 2307 uidNumber/gidNumber the array resolves. FlashArray still stores each")
	fmt.Fprintln(errOut, "one's SID, so SMB shows the right account and this reset is correct. The NFS view, though,")
	fmt.Fprintln(errOut, "shows them all as one identity:")
	fmt.Fprintln(errOut, "  - --compare cannot see that these objects already match, and rewrites them on every run;")
	fmt.Fprintln(errOut, "  - a tool that reads these ACLs over NFS and writes them back stores nobody in their")
	fmt.Fprintln(errOut, "    place, which is why a DACL-keeping sacl: rule refuses such objects (RISKS.md #11).")
	fmt.Fprintln(errOut, "Check the result from SMB, not NFS. Give each principal a uidNumber/gidNumber to avoid this.")
	fmt.Fprintln(errOut, "The run continues.")
}

// unmappedPrincipalHint explains ErrUnmappedPrincipal to the operator when
// the preflight refuses the whole run. A single object refused during the walk
// carries the shorter ErrUnmappedPrincipal text in its own error line.
func unmappedPrincipalHint(errOut io.Writer) {
	fmt.Fprintln(errOut, "The array shows a SID it has no RFC 2307 id for as nobody (65534), and folds every")
	fmt.Fprintln(errOut, "such SID -- users, groups, Domain Users, BUILTIN\\* -- into that one identity. Writing")
	fmt.Fprintln(errOut, "the ACL back over NFS replaces each of them with the array's local nobody SID, and the")
	fmt.Fprintln(errOut, "NFS view does not change, so the damage is visible only from SMB.")
	fmt.Fprintln(errOut, "Nothing was written to the refused objects. To proceed, either:")
	fmt.Fprintln(errOut, "  - give every principal in these DACLs a uidNumber/gidNumber the array resolves, or")
	fmt.Fprintln(errOut, "  - add the SACL from the SMB side, where no SID-to-uid translation happens.")
	fmt.Fprintln(errOut, "See benchmarks/sacl-unmapped-sid-20261020/RESULTS.md.")
}

type Config struct {
	Root, SpecPath, Transport, Server, Export                              string
	Spec                                                                   *spec.Spec
	Workers, BatchSize, Connections, Slots, MaxOpsPerCompound, RetryBudget int
	RPCTimeout, RetryBaseDelay                                             time.Duration
	Apply, DryRun, Compare, Validate, SetOwner, OneFilesystem, Pfind       bool
	SkipIdentityCheck, Quiet, AllowNonPureServer                           bool
	// Sacl is the operator's --sacl, SACL mode. Without it a spec that names
	// sacl: anywhere is refused. With it, the SACL guard below refuses an
	// NFSv4 spec that sets acl: on some rule without also naming a sacl: key
	// (sacl: [] included) for that rule.
	Sacl bool
	// AcceptDACLFlattening is --accept-dacl-flattening. Under --sacl, an
	// apply with a DACL-keeping rule is refused without it (ErrDACLFlattening).
	AcceptDACLFlattening bool
	// AllowHighIDs is --allow-high-ids. An apply whose spec names an id at or
	// above 1000000000 is refused without it (ErrHighIDPrincipal).
	AllowHighIDs bool
	// AllowAuditedDACLReset is --allow-audited-dacl-reset. A DACL reset
	// refuses each object that carries audit ACEs without it
	// (apply.ErrAuditedObject).
	AllowAuditedDACLReset bool
	// RPCStats adds the write-path report to the summary: achieved gather
	// depth, arrival rate, client CPU saturation, and the linger verdict. The
	// counters it reads increment unconditionally, so the flag costs nothing at
	// runtime and only decides whether the numbers are printed. Userspace only
	// -- the kernel transport has no write loop to report on.
	RPCStats bool
	// Auth overrides the AUTH_SYS credential the userspace transport presents.
	// Nil leaves nfs41 to build one from the process. Userspace only -- the
	// kernel transport authenticates through the mount, which this program does
	// not perform.
	Auth *nfs41.AuthSys
	// LocalIdentityAuthoritative is whether a name this host cannot resolve is a
	// reason to refuse the run.
	//
	// True on the kernel transport, where the local directory is exactly what
	// the repair will consult, so an unresolvable name is a typo worth catching
	// before a million objects. False on the userspace transport, where the
	// ARRAY resolves principals from the wire string and a local miss proves
	// nothing -- making it fatal there would turn --skip-identity-check into a
	// requirement, which is backwards.
	//
	// It is a consequence, not a platform: both commands set it from the
	// transport the operator selected, so internal/run never imports
	// internal/platform and a Linux --transport=userspace run behaves the same
	// as a macOS one.
	LocalIdentityAuthoritative bool

	CheckpointPath string
	Resume         bool
	Version        string
	// Exclude carries the patterns from the command line. They are unioned with
	// Spec.Exclude here rather than by the caller, so every caller of Run gets
	// the spec's own exclusions whether or not it knows about the flag.
	Exclude []string
	// ExcludeRoot anchors slash exclude patterns. Empty means Root. A partition
	// sets it to the manifest root, so `logs/*.gz` names the same objects
	// whichever partition reaches them (PS-12, #81).
	ExcludeRoot string
	// Handoff lists directories under Root that another partition owns. Each is
	// pruned like an excluded directory -- not fixed, not descended -- but
	// counted in Result.HandedOff and recorded as HANDOFF:, never as an
	// exclusion, so the partition driver can prove every partition root was
	// reached exactly once. Part of the checkpoint binding.
	Handoff []string
	// Log receives only what went wrong: walk and apply errors, pre-pass
	// directory-fix failures, and validation mismatches. Its size is bounded by
	// the number of problems, not by the size of the tree. A failed write to it
	// stops the run from scheduling further changes, as an evidence failure does.
	Log io.Writer
	// Evidence receives every record -- one OK:/WOULD:/FALLBACK:/SKIP:/EXCLUDE:
	// line per object touched, and the error lines Log gets -- in sharded files
	// behind a bounded queue. It is opt-in because at a hundred million objects
	// it is many gigabytes. Run closes it before returning and puts its manifest
	// in Result.Evidence. Once it fails, Run schedules no further changes:
	// evidence is required, so a change it cannot record is not made.
	Evidence *evidence.Sink
	ErrOut   io.Writer
}

// isErrorLine reports whether a log line is a failure record rather than a
// per-object audit record. The two travel together out of the pre-pass, whose
// Fix function returns one string for both outcomes.
func isErrorLine(msg string) bool {
	return strings.HasPrefix(msg, "ERR:") || strings.HasPrefix(msg, "[pre-pass] ERR:")
}

// Result is everything a caller can learn about a finished run without having
// parsed the human-readable output. The fields beyond Stats/Elapsed/WalkErrors
// exist because Run resolves them and nothing outside it can: the effective
// worker count after transport-aware defaulting, which filesystem actually
// answered, the per-phase timings, and the two conditions -- interruption and
// duplicate completion signals -- that make a run's counts untrustworthy.
// cmd/permissionreset renders them into the JSON run summary.
type Result struct {
	Stats      stats.Snapshot
	Elapsed    time.Duration
	WalkErrors int64

	// Excludes is the effective pattern list, spec plus command line, after the
	// union. The command records it in the JSON summary; nothing else needs it.
	Excludes []string

	// Effective options, after defaulting. Workers is what ran, not what was
	// typed; DryRun and Compare likewise reflect --apply's default and the
	// Compare that --resume forces on.
	Workers          int
	WorkersDefaulted bool
	DryRun           bool
	Compare          bool

	// Which filesystem answered. FilesystemIDSource is "st_dev" on the kernel
	// transport, "fsid" in userspace, "unknown" when it could not be read --
	// the numbers are not comparable across the two, so the label travels with
	// the value.
	Platform           string
	FilesystemID       uint64
	FilesystemIDSource string

	// Wall-clock phase split. PrepassSeconds is zero on a fused run, where
	// there is no separate pre-pass to time; Fused says which shape ran.
	PrepassSeconds float64
	ApplySeconds   float64
	Fused          bool

	// Pre-pass (directory fix) accounting. FixSeconds and ReaddirSeconds are
	// summed across workers, not wall clock.
	DirsFixed      int
	DirFixErrors   int
	ReaddirErrors  int
	FixSeconds     float64
	ReaddirSeconds float64

	// Interrupted and DuplicateCompletions each mean the counts above describe
	// less work than the tree needed. TotalErrors is the figure the stdout
	// counts block prints, including the walker failure and the duplicate
	// signals that are not in any per-phase counter.
	Interrupted          bool
	DuplicateCompletions int64
	TotalErrors          int64

	// Validate-only counts. Zero on a repair run. UnreadableCount is objects
	// whose stat or ACL read failed, so they were neither matched nor
	// mismatched; it is part of TotalErrors, not added to it.
	IsValidate      bool
	MatchCount      int64
	MismatchCount   int64
	UnreadableCount int64

	// AuditKept counts objects whose existing audit ACEs a DACL reset carried
	// forward (an acl: rule with no sacl: key). It is what the write sent, as
	// the NFS view shows it -- not a read-back, and not SMB descriptor state.
	AuditKept int64

	// EvidenceStopped is true when a failed evidence or error-log write made
	// the run stop scheduling changes. NotAttempted counts the objects the run
	// reached but did not write because of it; the walk also stops, so objects
	// it never reached are in no count at all.
	EvidenceStopped bool
	NotAttempted    int64
	// HandedOff is the Config.Handoff directories the walk reached and
	// pruned, sorted, one entry per prune.
	HandedOff []string
	// Evidence is the closed sink's manifest; nil when the run had no sink.
	Evidence *evidence.Manifest
}

// maxMismatchSamples bounds the mismatches a validate run keeps to print.
const maxMismatchSamples = 10

var errRunFailed = errors.New("permission repair run failed")

// ErrDACLFlattening is returned when an --sacl apply has a DACL-keeping rule
// but not --accept-dacl-flattening.
var ErrDACLFlattening = errors.New("DACL-keeping apply needs --accept-dacl-flattening: FlashArray stores inherited ACEs written back over NFS as explicit")

// ErrHighIDPrincipal is returned when an apply's spec names an id at or above
// 1000000000 (numeric, or a name NSS resolves to one) without --allow-high-ids.
// FlashBlade decodes such ids as 1000000000+RID on write, so the ACE would
// name a different, usually nonexistent, SID (RISKS.md #12, #50).
var ErrHighIDPrincipal = errors.New("spec names an id at or above 1000000000, which FlashBlade stores as a different SID; pass --allow-high-ids only for FlashArray")

// highIDLookup resolves a named principal to its POSIX id for the high-id
// check. It is a variable so tests can script it without the host's NSS.
var highIDLookup = idmap.NumericID

// ErrCheckpointUnflushed reports that the repair itself finished cleanly but the
// checkpoint could not be flushed and closed, so the file on disk does not
// describe the work that was actually done. Resuming from it would skip
// directories that were never completed, or redo ones that were — either way the
// file cannot be trusted, and that is a different outcome from "the repair
// failed". It is exported so automation can distinguish the two with errors.Is
// rather than by matching on stderr text; the command maps it to its own exit
// code.
var ErrCheckpointUnflushed = errors.New("repair succeeded but the checkpoint was not flushed; do not --resume from it")

// ErrEvidenceIncomplete reports that the run's evidence is not a complete
// record of what it did: a write to it failed (and the run stopped making
// changes), or its manifest could not be written.
var ErrEvidenceIncomplete = errors.New("evidence is incomplete")

// ErrTraverseNotPreserved reports that the spec's directory permissions would
// strip execute/traverse from the running identity, which would lock the walk
// out of child directories partway through its own descent. The run refuses
// before anything is modified. Like ErrCheckpointUnflushed it is exported so
// automation can match the outcome with errors.Is; the returned error wraps both
// this sentinel and the underlying apply.CheckTraversePreserved cause, so the
// specific offending rule stays matchable and printable. The operator-facing
// remedy text lives in the command, not here.
var ErrTraverseNotPreserved = errors.New("spec's directory permissions would remove traverse for the running identity")

// closeTransport and closeCheckpoint exist only so tests can observe the two
// close paths below independently. Run constructs both resources itself, and
// there is no portable way to make a real DESTROY_SESSION or a real fsync fail
// on demand, so the alternative to these seams is no coverage of the two
// behaviours that the close paths were split apart to express.
var (
	closeTransport  = func(tr transport.Transport) error { return tr.Close() }
	closeCheckpoint = func(ckpt *checkpoint.Checkpoint) error { return ckpt.Close() }
)

type namedWriter interface {
	Name() string
}

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (w lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.w.Write(p)
}

// Run performs one permission-repair run. The caller is responsible for
// command-line-only validation and for loading Config.Spec.
func Run(ctx context.Context, cfg Config, out io.Writer) (result Result, runErr error) {
	if out == nil {
		out = io.Discard
	}
	errOut := cfg.ErrOut
	if errOut == nil {
		errOut = io.Discard
	}
	// reachedEnd is set once the run has done everything it was going to do,
	// so the evidence can be called complete; any earlier return leaves it false.
	var reachedEnd bool
	if cfg.Evidence != nil {
		// Registered first so it runs last, after the checkpoint close. A
		// repair failure keeps precedence over the evidence verdict, as it does
		// over ErrCheckpointUnflushed.
		defer func() {
			var reasons []string
			switch {
			case result.EvidenceStopped:
				reasons = append(reasons, "run stopped making changes after an evidence or log write failed")
			case result.Interrupted:
				reasons = append(reasons, "run interrupted")
			case !reachedEnd:
				reasons = append(reasons, "run ended before it finished")
			}
			m, err := cfg.Evidence.Close(len(reasons) == 0, reasons...)
			result.Evidence = &m
			fmt.Fprintf(out, "  Evidence:   %s (%s, %d records in %d shards, %d dropped)\n",
				cfg.Evidence.Dir(), m.Status, m.RecordsWritten, len(m.Shards), m.RecordsDropped)
			if err != nil {
				fmt.Fprintf(errOut, "ERROR: evidence: %v\n", err)
				if runErr == nil {
					runErr = fmt.Errorf("%w: %w", ErrEvidenceIncomplete, err)
				}
			}
		}()
	}
	if cfg.Spec == nil {
		return result, errors.New("nil permission spec")
	}
	if ctx == nil {
		return result, errors.New("nil context")
	}

	// The exclude list is compiled before the transport is constructed: a bad
	// pattern is an operator typo and must be refused before a session is
	// established or anything is read.
	effectiveExcludes := spec.MergeExcludes(cfg.Spec.Exclude, cfg.Exclude)
	excludeRoot := cfg.ExcludeRoot
	if excludeRoot == "" {
		excludeRoot = cfg.Root
	}
	excluder, err := spec.NewExcluder(excludeRoot, effectiveExcludes)
	if err != nil {
		fmt.Fprintf(errOut, "ERROR: %v\n", err)
		return result, errRunFailed
	}
	result.Excludes = effectiveExcludes
	handoff, err := newHandoff(cfg)
	if err != nil {
		fmt.Fprintf(errOut, "ERROR: %v\n", err)
		return result, errRunFailed
	}

	// SACL mode is opt-in. Without --sacl, a spec naming sacl: is refused, so
	// audit ACEs are never written by accident, and runPreflight refuses an
	// acl: spec whose target root already carries audit ACEs: FlashBlade
	// returns them in system.nfs4_acl too (#51), so the write would delete them. With --sacl, the
	// SACL guard runs before the transport is constructed, let alone the
	// walk: an NFSv4 rule that sets acl: but names no sacl: key at all would
	// have its write delete the object's existing audit ACEs on FlashArray,
	// silently and at every object the rule matches. sacl: [] says an empty
	// audit ACL is intended, and a rule that sets it is not reported by
	// MissingSACL at all.
	if !cfg.Sacl {
		if rules := cfg.Spec.SaclRules(); len(rules) > 0 {
			fmt.Fprintln(errOut, "ERROR: the following NFSv4 rule(s) set sacl: (audit ACEs):")
			for _, label := range rules {
				fmt.Fprintf(errOut, "  %s\n", label)
			}
			fmt.Fprintln(errOut, "Writing audit ACEs is SACL mode. Pass --sacl to turn it on.")
			return result, errRunFailed
		}
	} else {
		if missing := cfg.Spec.MissingSACL(); len(missing) > 0 {
			fmt.Fprintln(errOut, "ERROR: the following NFSv4 rule(s) set acl: with no sacl: key:")
			for _, label := range missing {
				fmt.Fprintf(errOut, "  %s\n", label)
			}
			fmt.Fprintln(errOut, "On FlashArray, writing the DACL without a SACL deletes the object's existing audit ACEs.")
			fmt.Fprintln(errOut, "Add sacl: [] to that rule to say an empty audit ACL is intended, or run without --sacl if this is not a FlashArray SACL run.")
			return result, errRunFailed
		}
		// A DACL-keeping apply writes each object's DACL back, and FlashArray
		// stores what it gets as explicit ACEs: its NFS view has no inherited
		// marker to send. Only a real apply writes, so a dry run and --validate
		// (whose preflight probes a throwaway file) are not refused.
		if rules := cfg.Spec.KeepDACLRules(); len(rules) > 0 && cfg.Apply && !cfg.DryRun && !cfg.Validate && !cfg.AcceptDACLFlattening {
			fmt.Fprintln(errOut, "ERROR: the following NFSv4 rule(s) keep each object's DACL (sacl: with no acl:):")
			for _, label := range rules {
				fmt.Fprintf(errOut, "  %s\n", label)
			}
			fmt.Fprintln(errOut, "Adding the SACL rewrites the whole ACL, and FlashArray's NFS view does not say which ACEs")
			fmt.Fprintln(errOut, "are inherited. Every inherited ACE comes back as an explicit one, and the DACL is marked")
			fmt.Fprintln(errOut, "protected (D:P). Effective access is kept, but Windows inheritance is not: a later change on a")
			fmt.Fprintln(errOut, "parent folder no longer flows down the way it did.")
			fmt.Fprintln(errOut, "For SMB-written data, add the SACL from the SMB side instead. If flattened DACLs are")
			fmt.Fprintln(errOut, "acceptable (an NFS-written tree, say), pass --accept-dacl-flattening.")
			fmt.Fprintln(errOut, "See RISKS.md #11 and benchmarks/sacl-unmapped-sid-20261020/RESULTS.md.")
			return result, fmt.Errorf("%w: %w", errRunFailed, ErrDACLFlattening)
		}
	}

	// A spec naming an id at or above 1e9 is refused on a real apply: on
	// FlashBlade every such ACE lands on a different SID, with exit 0 (#50
	// lab: all 10 objects). Dry run and --validate write nothing, so they only
	// warn, and --allow-high-ids is the operator saying the target is not FB.
	if high := cfg.Spec.SyntheticRangePrincipals(highIDLookup); len(high) > 0 {
		refuse := cfg.Apply && !cfg.DryRun && !cfg.Validate && !cfg.AllowHighIDs
		switch {
		case cfg.AllowHighIDs:
			// The operator has already said the target is a FlashArray (or a
			// FlashBlade using the array's own 1000000000 + RID form), so the
			// FlashBlade warning would only be noise on the run it was meant for.
			fmt.Fprintf(errOut, "NOTE: --allow-high-ids: %d spec principal(s) at or above 1000000000 are written as given.\n", len(high))
		default:
			if refuse {
				fmt.Fprintln(errOut, "ERROR: the spec names principals with ids at or above 1000000000:")
			} else {
				fmt.Fprintln(errOut, "WARNING: the spec names principals with ids at or above 1000000000:")
			}
			for _, h := range high {
				fmt.Fprintf(errOut, "  %s\n", h)
			}
			fmt.Fprintln(errOut, "FlashBlade reads every id that high as 1000000000 + RID on an NFS write, so these entries")
			fmt.Fprintln(errOut, "would name a different, usually nonexistent, SID as seen from SMB, with nothing reported")
			fmt.Fprintln(errOut, "(RISKS.md #12). This applies to FlashBlade only. For a FlashBlade target, use RFC 2307 ids")
			fmt.Fprintln(errOut, "below 1000000000; for a FlashArray target, pass --allow-high-ids.")
		}
		if refuse {
			fmt.Fprintln(errOut, "Nothing was written. Pass --allow-high-ids only if the target is a FlashArray, or a")
			fmt.Fprintln(errOut, "FlashBlade where each listed id is the array's own 1000000000 + RID form of a domain SID.")
			return result, fmt.Errorf("%w: %w", errRunFailed, ErrHighIDPrincipal)
		}
	}

	// This NOTE is unconditional, printed before anything is touched and on
	// every path that reaches here -- apply, dry run and --validate alike --
	// because it is true regardless of what the preflight below finds: sacl:
	// writes audit ACEs, but an object only gets logged against if the
	// managed directory also has an audit policy turned on, and that is
	// server-side configuration this tool has no way to read over NFS.
	if cfg.Spec.UsesSacl() {
		fmt.Fprintln(errOut, "NOTE: sacl: writes audit ACEs, but logging them still needs an audit policy turned")
		fmt.Fprintln(errOut, "      on for the managed directory -- permissionreset cannot check that over NFS.")
	}

	var writerMu sync.Mutex
	out = lockedWriter{mu: &writerMu, w: out}
	errOut = lockedWriter{mu: &writerMu, w: errOut}
	// Two sinks, one mutex. The error log is bounded by how much went wrong; the
	// audit log has one line per object and is what makes a 100-million-object
	// run produce a multi-gigabyte file, so it is opt-in and separate. The mutex
	// is shared because the caller is allowed to point both at the same file --
	// interleaved writes to one descriptor must still be whole lines.
	//
	// Every write is checked. The first failure sets stopMutations, which every
	// write site consults before changing anything: the walk stops descending
	// and fixing, and the apply workers skip what is left. A change already in
	// flight finishes; its record lands in the manifest as dropped.
	var logMu sync.Mutex
	var stopMutations atomic.Bool
	stop := func(what string, err error) {
		if stopMutations.CompareAndSwap(false, true) {
			fmt.Fprintf(errOut, "ERROR: %s failed: %v; making no further changes\n", what, err)
		}
	}
	writeLog := func(msg string) {
		if msg == "" {
			return
		}
		if cfg.Evidence != nil && !cfg.Evidence.Write(msg) {
			stop("evidence write", cfg.Evidence.Err())
		}
		if cfg.Log == nil {
			return
		}
		logMu.Lock()
		_, err := fmt.Fprintln(cfg.Log, msg)
		logMu.Unlock()
		if err != nil {
			stop("error log write", err)
		}
	}
	writeAudit := func(msg string) {
		if cfg.Evidence == nil || msg == "" {
			return
		}
		if !cfg.Evidence.Write(msg) {
			stop("evidence write", cfg.Evidence.Err())
		}
	}
	// routeLog splits a sink that carries both kinds -- the pre-pass Fix result,
	// which is an ERR line or a per-directory OK/WOULD/FALLBACK line depending on
	// what happened. Only the error form is classified by prefix; everything else
	// is an audit record.
	routeLog := func(msg string) {
		if isErrorLine(msg) {
			writeLog(msg)
			return
		}
		writeAudit(msg)
	}

	var tr transport.Transport
	switch cfg.Transport {
	case "kernel":
		tr, err = transport.NewKernel(cfg.Root)
	case "userspace":
		gateLog := func(msg string) {
			fmt.Fprintln(errOut, msg)
			writeLog(msg)
		}
		tr, err = nfs41.New(ctx, nfs41.Config{
			Server:             cfg.Server,
			Export:             cfg.Export,
			Target:             cfg.Root,
			Connections:        cfg.Connections,
			Slots:              cfg.Slots,
			MaxOpsPerCompound:  cfg.MaxOpsPerCompound,
			RPCTimeout:         cfg.RPCTimeout,
			RetryBudget:        cfg.RetryBudget,
			RetryBaseDelay:     cfg.RetryBaseDelay,
			AllowNonPureServer: cfg.AllowNonPureServer,
			Auth:               cfg.Auth,
			Log:                gateLog,
		})
	default:
		return result, fmt.Errorf("unknown transport %q (want kernel or userspace)", cfg.Transport)
	}
	if err != nil {
		// The command renders the two product-gate sentinels itself so their
		// deliberately opaque wording cannot be changed by an error wrapper.
		if !errors.Is(err, nfs41.ErrNotPureServer) && !errors.Is(err, nfs41.ErrFlashArrayNotSupported) {
			fmt.Fprintf(errOut, "ERROR: %v\n", err)
		}
		rootSquashHint(errOut, cfg)
		return result, err
	}
	// Closing the transport is advisory. On the userspace transport it sends
	// DESTROY_SESSION, and a session the client never destroys expires
	// server-side on its own, so a failed close costs nothing that the server
	// does not clean up by itself: nothing on disk depends on it, and no work
	// the run reported as done becomes untrue. Hence WARNING and not ERROR --
	// an ERROR line printed beside exit 0 is self-contradictory and teaches
	// operators that the prefix means nothing -- and hence no effect on runErr.
	//
	// This deliberately does NOT share a helper with the checkpoint close below.
	// The two were collapsed into one once and it was wrong: see that defer.
	defer func() {
		if err := closeTransport(tr); err != nil {
			fmt.Fprintf(errOut, "WARNING: close transport: %v (the session expires server-side, so a failed DESTROY_SESSION costs nothing)\n", err)
		}
	}()

	workersExplicit := cfg.Workers != 0
	if !workersExplicit {
		cfg.Workers = defaultWorkers(cfg.Transport, transportPlatform(tr))
	}
	if cfg.Workers < 1 {
		fmt.Fprintf(errOut, "ERROR: --workers must be >= 1 (got %d)\n", cfg.Workers)
		return result, errRunFailed
	}
	if cfg.BatchSize < 1 {
		fmt.Fprintf(errOut, "ERROR: --batch-size must be >= 1 (got %d)\n", cfg.BatchSize)
		return result, errRunFailed
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}

	// The reporting metadata is recorded only past the argument checks and the
	// cancellation check, so a run that never started reports a zero Result
	// rather than a run's worth of identity with no counts under it.
	result.Platform = platformLabel(transportPlatform(tr))
	result.FilesystemID, result.FilesystemIDSource = filesystemIdentity(tr, cfg.Transport)
	result.Workers, result.WorkersDefaulted = cfg.Workers, !workersExplicit
	result.Fused = !cfg.Pfind

	if cfg.Resume && cfg.CheckpointPath == "" {
		fmt.Fprintln(errOut, "ERROR: --resume requires --checkpoint")
		return result, errRunFailed
	}
	if cfg.CheckpointPath != "" && cfg.Pfind {
		fmt.Fprintln(errOut, "ERROR: --checkpoint is not supported with --pfind")
		return result, errRunFailed
	}
	// !cfg.Apply is the load-bearing term: the default invocation names neither
	// --apply nor --dry-run, and only becomes a dry run below, well past this
	// guard. Testing cfg.DryRun alone would let the commonest form of a
	// write-nothing run straight through.
	if cfg.CheckpointPath != "" && (cfg.DryRun || cfg.Validate || !cfg.Apply) {
		fmt.Fprintln(errOut, "ERROR: --checkpoint cannot be used with --dry-run or --validate, or without --apply: a run that writes nothing would still record every directory as complete, and a later --resume would skip the whole tree unrepaired")
		return result, errRunFailed
	}

	var ckpt *checkpoint.Checkpoint
	if cfg.CheckpointPath != "" {
		specHash, err := checkpoint.RunHash(cfg.SpecPath, cfg.Root, cfg.Spec.Protocol, cfg.Version, handoff.binding(effectiveExcludes, excludeRoot != cfg.Root, excludeRoot))
		if err != nil {
			fmt.Fprintf(errOut, "ERROR: hash spec file: %v\n", err)
			return result, errRunFailed
		}
		ckpt, err = checkpoint.Open(cfg.CheckpointPath, specHash, cfg.Resume)
		if err != nil {
			fmt.Fprintf(errOut, "ERROR: %v\n", err)
			return result, errRunFailed
		}
		// Closing the checkpoint is not advisory: it is the flush that turns
		// buffered completion records into the file a later --resume reads. If it
		// fails, the run may well have repaired everything correctly while the
		// file on disk claims something else, and resuming from it skips
		// directories that were never finished. That is a durable, silent wrong
		// answer, so it is fatal and carries its own sentinel -- unlike the
		// transport close above, which loses nothing.
		//
		// The guard on runErr is the precedence rule and not defensive noise. A
		// deferred assignment runs after the run's own verdict is known, so
		// without the guard a flush failure would overwrite a real repair failure
		// and downgrade "the repair failed" to "the checkpoint is stale" -- the
		// command maps the sentinel to a different exit code, so automation would
		// read a failed run as a successful one. A repair failure always wins;
		// ErrCheckpointUnflushed means specifically that the repair succeeded.
		defer func() {
			err := closeCheckpoint(ckpt)
			if err == nil {
				return
			}
			fmt.Fprintf(errOut, "ERROR: close checkpoint: %v\n", err)
			if runErr != nil {
				return
			}
			runErr = fmt.Errorf("%w: %w", ErrCheckpointUnflushed, err)
		}()
		if cfg.Resume {
			cfg.Compare = true
			fmt.Fprintf(out, "Resuming from checkpoint: %d directories already completed\n", ckpt.CompletedCount())
		}
	}

	if cfg.Pfind {
		fmt.Fprintln(out, "Using pfind for enumeration (parallel)")
	} else {
		fmt.Fprintln(out, "Using built-in parallel walk for enumeration")
	}
	fmt.Fprintf(out, "Protocol: %s\n", cfg.Spec.Protocol)
	if workersExplicit {
		fmt.Fprintf(out, "Workers: %d\n", cfg.Workers)
	} else {
		fmt.Fprintf(out, "Workers: %d (default for transport=%s, platform=%s)\n",
			cfg.Workers, cfg.Transport, platformLabel(transportPlatform(tr)))
	}
	fmt.Fprintf(out, "Target: %s\n", cfg.Root)
	if cfg.Validate {
		fmt.Fprintln(out, "VALIDATE — checking permissions against spec (read-only)")
	} else if cfg.DryRun {
		fmt.Fprintln(out, "DRY RUN — no changes will be made")
	}
	if cfg.Compare {
		fmt.Fprintln(out, "COMPARE — will skip files whose permissions already match spec")
	}
	if len(effectiveExcludes) > 0 {
		fmt.Fprintf(out, "Excluding: %s\n", strings.Join(effectiveExcludes, " "))
		if cfg.Pfind {
			fmt.Fprintln(out, "NOTE: --pfind still walks excluded subtrees; excluded paths are dropped from its output")
		}
	}

	result.DryRun, result.Compare = cfg.DryRun, cfg.Compare

	if cfg.Validate {
		fmt.Fprintln(out)
		r, err := runValidate(ctx, tr, cfg, result, excluder, handoff, out, errOut, writeLog)
		reachedEnd = true
		return r, err
	}

	if !cfg.Apply && !cfg.DryRun {
		cfg.DryRun = true
		fmt.Fprintln(out, "DRY RUN (pass --apply to make changes)")
	}
	result.DryRun = cfg.DryRun
	// Review item 7: a dry run of a DACL-keeping rule reads nothing, because
	// before Purity//FA 6.12.1 a read without the audit bypass empties an
	// inheriting SACL and a dry run has no preflight to prove the bypass.
	// A dry run reads no NFSv4 ACL at all (PS-02), so --compare cannot skip an
	// object that already matches: every object is counted as applied, and the
	// count is an upper bound, not a prediction.
	if cfg.DryRun && cfg.Compare && cfg.Spec.Protocol == "nfsv4" {
		fmt.Fprintln(errOut, "NOTE: --compare has no effect on an nfsv4 dry run: a dry run reads no ACL, because a")
		fmt.Fprintln(errOut, "      read without the proven audit bypass can empty inherited auditing. Objects that")
		fmt.Fprintln(errOut, "      already match are counted as applied; use --validate to see what would change.")
	}
	if cfg.DryRun && len(cfg.Spec.KeepDACLRules()) > 0 {
		fmt.Fprintln(errOut, "NOTE: dry run does not read objects under a DACL-keeping (sacl:-only) rule: before")
		fmt.Fprintln(errOut, "      Purity//FA 6.12.1 a read without the audit bypass empties inheriting SACLs.")
		fmt.Fprintln(errOut, "      Every such object is reported as WOULD; use --validate to check them.")
	}

	// Verify directory permissions preserve traverse for the running identity.
	// This runs before the identity pre-resolve, and before ProbePreflight, so a
	// spec that would lock the walk out of its own descent is refused while
	// nothing has been modified yet. --validate returns above and never reaches
	// this, which is correct: a read-only comparison cannot lock anyone out.
	if err := apply.CheckTraversePreserved(cfg.Spec); err != nil {
		fmt.Fprintf(errOut, "ERROR: %v\n", err)
		return result, fmt.Errorf("%w: %w", ErrTraverseNotPreserved, err)
	}

	if !cfg.SkipIdentityCheck {
		if errs := apply.PreResolveIdentities(cfg.Spec); len(errs) > 0 {
			if !cfg.LocalIdentityAuthoritative {
				fmt.Fprintln(errOut, "WARNING: some named principals do not resolve on this host:")
				for _, err := range errs {
					fmt.Fprintf(errOut, "  %v\n", err)
				}
				fmt.Fprintln(errOut, "  This host is not the authority for them -- the array resolves the")
				fmt.Fprintln(errOut, "  principal string from the wire -- so the run continues. Check the")
				fmt.Fprintln(errOut, "  spelling if the repair reports permission failures.")
			} else {
				fmt.Fprintln(errOut, "ERROR: identity pre-resolution failed:")
				for _, err := range errs {
					fmt.Fprintf(errOut, "  %v\n", err)
				}
				fmt.Fprintln(errOut, "Fix the identities or use --skip-identity-check with numeric UIDs/GIDs")
				return result, errRunFailed
			}
		}
	}

	// One resolver for the whole run: it memoizes, and the apply workers all
	// share it rather than each rediscovering the same handful of principals.
	resolver := idmap.NewNSS()
	opts := apply.Options{DryRun: cfg.DryRun, Compare: cfg.Compare, SetOwner: cfg.SetOwner, Idmap: resolver, AllowAuditedDACLReset: cfg.AllowAuditedDACLReset}
	fmt.Fprintln(out)

	if !cfg.DryRun {
		if err := runPreflight(tr, cfg, errOut); err != nil {
			return result, err
		}
	}

	st := &stats.Stats{}
	var auditKept atomic.Int64
	started := time.Now()
	// finish assigns fields rather than replacing result: the transport identity
	// and the effective options were resolved above and are still wanted on every
	// early-return path below.
	finish := func(walkErrs *walk.WalkErrors) {
		result.Stats = st.Snapshot()
		result.AuditKept = auditKept.Load()
		result.Elapsed = time.Since(started)
		if walkErrs != nil {
			result.WalkErrors = walkErrs.Count()
		}
	}

	if cfg.Pfind {
		fmt.Fprintln(out, "Pre-pass: fixing directory permissions top-down...")
	} else {
		fmt.Fprintln(out, "Single pass: fixing directories and applying permissions...")
	}
	// countingExclude is the predicate the enumerator that owns the count uses;
	// walk consults it exactly once per candidate path. In the fused shape that
	// is the pre-pass walk. Under --pfind two enumerators run over the same tree
	// -- the fix-only pre-pass and pfind itself -- so only pfind counts, or every
	// excluded directory would be counted twice.
	countingExclude := func(path string) bool {
		if handoff.take(path) {
			writeAudit(fmt.Sprintf("HANDOFF: %s", path))
			return true
		}
		if !excluder.Match(path) {
			return false
		}
		st.IncExcluded()
		writeAudit(fmt.Sprintf("EXCLUDE: %s", path))
		return true
	}
	countingExcludeAncestor := func(path string) bool {
		if !excluder.MatchOrUnder(path) {
			return false
		}
		st.IncExcluded()
		writeAudit(fmt.Sprintf("EXCLUDE: %s", path))
		return true
	}
	popts := walk.PrepassOptions{
		Transport: tr,
		Fix: func(ref transport.Ref) (bool, string, walk.FixResult) {
			out := apply.FixDirPerms(tr, ref, cfg.Spec, opts)
			if out.AuditKept > 0 {
				auditKept.Add(1)
			}
			return out.OK, out.Msg, walk.FixResult{Done: out.RealApply, Applied: out.Applied, LogMsg: out.Msg}
		},
		Log:     routeLog,
		Workers: cfg.Workers,
		Exclude: countingExclude,
		Stop:    stopMutations.Load,
	}
	if cfg.Spec.Protocol == "nfsv4" && !cfg.DryRun && !cfg.Compare && !cfg.SetOwner {
		popts.DirACL = func(path string) []byte {
			perms := cfg.Spec.EffectivePerms(path, true)
			// A rule that keeps auditing must read the directory before it
			// writes, which a write folded into READDIR cannot do.
			if len(perms.ACL) == 0 || perms.PreserveSACL() {
				return nil
			}
			return perms.EncodedACL()
		}
	}
	if cfg.Pfind {
		popts.Exclude = excluder.Match
	}
	if ckpt != nil {
		popts.SkipDir = ckpt.SkipCompleted
		popts.RegisterDir = ckpt.RegisterDir
	}
	if cfg.OneFilesystem {
		rootRef, err := tr.Root()
		if err != nil {
			finish(nil)
			fmt.Fprintf(errOut, "ERROR: resolve target for --one-filesystem: %v\n", err)
			return result, errRunFailed
		}
		rootAttr, err := tr.Stat(rootRef)
		if err != nil {
			finish(nil)
			fmt.Fprintf(errOut, "ERROR: stat target for filesystem ID: %v\n", err)
			return result, errRunFailed
		}
		if rootAttr.FSID == 0 {
			finish(nil)
			fmt.Fprintln(errOut, "ERROR: target reports filesystem ID 0; --one-filesystem cannot be enforced")
			return result, errRunFailed
		}
		popts.RootFSID = rootAttr.FSID
	}

	stopProgress := make(chan struct{})
	var progressWG sync.WaitGroup
	if !cfg.Quiet {
		progressWG.Add(1)
		go func() {
			defer progressWG.Done()
			st.Reporter(errOut, time.Second, stopProgress)
		}()
	}

	entryCh := make(chan walk.Entry, cfg.Workers*100)
	walkErrs := &walk.WalkErrors{}

	tPre := time.Now()
	var (
		pre            walk.PrepassResult
		prepassElapsed time.Duration
		walkErr        error
		producerWG     sync.WaitGroup
	)
	producerWG.Add(1)
	go func() {
		defer producerWG.Done()
		defer close(entryCh)
		if cfg.Pfind {
			pre = walk.Prepass(cfg.Root, nil, walkErrs, popts)
			prepassElapsed = time.Since(tPre)
			fmt.Fprintf(out, "Pre-pass complete: %d fixed, %d errors in %.1fs\n\n", pre.Fixed, pre.Errors, prepassElapsed.Seconds())
			walkErr = walk.Pfind(cfg.Root, entryCh, walkErrs, countingExcludeAncestor)
			return
		}
		pre = walk.Prepass(cfg.Root, entryCh, walkErrs, popts)
	}()

	tMain := time.Now()
	var wg sync.WaitGroup
	sem := make(chan struct{}, cfg.Workers)

	// useACLBatch gates the KeepDACL pre-fetch below the same way runValidate
	// gates its own ACL batch: GetACLBatch only exists for nfsv4, and only a
	// DACL-keeping rule's apply (applyKeepDACL) ever reads the current ACL
	// before writing, so a non-nfsv4 spec has nothing to pre-fetch.
	// A dry run never reads a KeepDACL object (applyKeepDACL returns before
	// its read; see the NOTE in Run), so it has nothing to pre-fetch either.
	useACLBatch := cfg.Spec.Protocol == "nfsv4" && !cfg.DryRun
	// The detailed evidence profile records each object's state before the
	// write. For nfsv4 that is a read the compact profile does not make,
	// batched with the pre-fetch above; it is only handed to the apply for the
	// rules that would have read anyway, so the write itself is unchanged.
	detailedRead := cfg.Evidence != nil && cfg.Evidence.Profile() == evidence.ProfileDetailed &&
		cfg.Spec.Protocol == "nfsv4"
	var notAttempted atomic.Int64

	batch := make([]walk.Entry, 0, cfg.BatchSize)
	processBatch := func(entries []walk.Entry) {
		defer wg.Done()
		defer func() { <-sem }()

		// pending holds the entries that still need the real ProcessPath call
		// below, in original order, after the lstat/symlink/already-applied
		// cases above have been handled inline.
		type pending struct {
			idx int
			e   *walk.Entry
		}
		pendingEntries := make([]pending, 0, len(entries))

		for i := range entries {
			e := &entries[i]
			if !e.Stat() {
				st.IncError()
				writeLog(fmt.Sprintf("ERR: lstat %s failed", e.Path))
				continue
			}
			if e.IsSymlink {
				st.IncSymlinks()
				writeAudit(fmt.Sprintf("SKIP: symlink %s", e.Path))
				if ckpt != nil {
					ckpt.EntryDone(e.DirPath)
				}
				continue
			}
			if e.ACLApplied && e.IsDir {
				st.IncApplied()
				writeAudit(fmt.Sprintf("OK: setxattr nfs4_acl %s (readdir-fold)", e.Path))
				if ckpt != nil {
					ckpt.DirApplyDone(e.Path)
				}
				continue
			}
			if e.IsDir && e.Fix.Done {
				// The prepass's Fix call already ran the real spec apply for this
				// directory (readdir failed, so Fix repaired it before the retry
				// below succeeded) -- reprocessing it here would just repeat the
				// same GETATTR+SETATTR (or chmod) with the same result. The audit
				// line for a real change was already written by Fix's own log
				// route; only the no-op "already correct" case has nothing to show
				// for it yet, so that one is written here.
				if e.Fix.Applied {
					st.IncApplied()
				} else {
					st.IncSkipped()
				}
				if e.Fix.LogMsg == "" {
					writeAudit(fmt.Sprintf("SKIP: %s already correct (pre-pass)", e.Path))
				}
				if ckpt != nil {
					ckpt.DirApplyDone(e.Path)
				}
				continue
			}
			pendingEntries = append(pendingEntries, pending{idx: i, e: e})
		}

		// Pre-fetch ACLs in batch for the entries whose effective rule keeps
		// the object's existing DACL (sacl: with no acl:): applyKeepDACL always
		// has to read the current ACL before it can write one, and batching
		// that read the way runValidate already does for ValidatePath turns N
		// per-object GETATTRs into N/4 COMPOUNDs on the userspace transport. A
		// rule that replaces the DACL outright never reads before writing, so
		// it is left out of the batch -- there is nothing for it to use the
		// read for.
		cachedACLs := make(map[int][]byte, len(pendingEntries))
		applyReads := make(map[int]bool, len(pendingEntries))
		if useACLBatch || detailedRead {
			var refs []transport.Ref
			var refIdx []int
			for _, p := range pendingEntries {
				perms := cfg.Spec.EffectivePerms(p.e.Path, p.e.IsDir)
				reads := useACLBatch && (perms.KeepDACL() || perms.PreserveSACL())
				if reads || detailedRead {
					refs = append(refs, p.e.Ref())
					refIdx = append(refIdx, p.idx)
					applyReads[p.idx] = reads
				}
			}
			if len(refs) > 0 {
				acls, err := tr.GetACLBatch(refs)
				if err != nil {
					// A missing read must never turn into a write: leave
					// cachedACLs empty and let applyKeepDACL fall back to its
					// own per-object GetACL (or fail that object on its own)
					// below, same as if no batch had been attempted.
					writeLog(fmt.Sprintf("ERR: batch GetACL (%d entries): %v; falling back to per-object read", len(refs), err))
				} else {
					for i, idx := range refIdx {
						cachedACLs[idx] = acls[i]
					}
				}
			}
		}

		for _, p := range pendingEntries {
			e := p.e
			if stopMutations.Load() {
				notAttempted.Add(1)
				continue
			}
			o := opts
			acl, haveACL := cachedACLs[p.idx]
			if haveACL && applyReads[p.idx] {
				o.CachedACL = acl
			}
			r := apply.ProcessPath(tr, e.Ref(), e.IsDir, cfg.Spec, o, e.Mode)
			if detailedRead && r.Error == nil && r.LogMsg != "" {
				r.LogMsg += "\t" + beforeState(acl, haveACL)
			}
			if r.AuditKept > 0 {
				auditKept.Add(1)
			}
			if r.Applied {
				st.IncApplied()
			} else if r.Skipped {
				st.IncSkipped()
			}
			if r.Error != nil {
				st.IncError()
				writeLog(fmt.Sprintf("ERR: %v", r.Error))
			} else {
				writeAudit(r.LogMsg)
				if ckpt != nil {
					if e.IsDir {
						ckpt.DirApplyDone(e.Path)
					} else {
						ckpt.EntryDone(e.DirPath)
					}
				}
			}
		}
	}

	interrupted := false
	for entry := range entryCh {
		if ctx.Err() != nil {
			interrupted = true
			// Keep receiving without applying so the producer can finish and Run
			// still owns every goroutine that can use its transport. On the apply
			// path Prepass keeps fixing directory permissions while it drains, so
			// cancellation can still enumerate and write every remaining directory.
			continue
		}
		if stopMutations.Load() {
			// Unlike cancellation, a failed evidence write also stops the walk
			// (popts.Stop), so this drains only what was already queued.
			notAttempted.Add(1)
			continue
		}
		st.IncEnumerated()
		batch = append(batch, entry)
		if len(batch) >= cfg.BatchSize {
			wg.Add(1)
			sem <- struct{}{}
			b := make([]walk.Entry, len(batch))
			copy(b, batch)
			go processBatch(b)
			batch = batch[:0]
		}
	}
	if len(batch) > 0 && !interrupted && !stopMutations.Load() {
		wg.Add(1)
		sem <- struct{}{}
		b := make([]walk.Entry, len(batch))
		copy(b, batch)
		go processBatch(b)
	} else if len(batch) > 0 && stopMutations.Load() {
		notAttempted.Add(int64(len(batch)))
	}

	producerWG.Wait()
	wg.Wait()
	close(stopProgress)
	progressWG.Wait()

	mainElapsed := time.Since(tMain)
	finish(walkErrs)
	applyErrors := result.Stats.Errors
	totalErrors := applyErrors + result.WalkErrors + int64(pre.Errors) + int64(pre.ReaddirErrors)
	result.PrepassSeconds = prepassElapsed.Seconds()
	result.ApplySeconds = mainElapsed.Seconds()
	result.DirsFixed, result.DirFixErrors = pre.Fixed, pre.Errors
	result.ReaddirErrors = pre.ReaddirErrors
	result.FixSeconds, result.ReaddirSeconds = pre.FixTime.Seconds(), pre.ReaddirTime.Seconds()
	result.Interrupted = interrupted
	result.EvidenceStopped = stopMutations.Load()
	result.NotAttempted = notAttempted.Load()
	result.HandedOff = handoff.reached()
	reachedEnd = true

	fmt.Fprintln(out, "\nComplete:")
	fmt.Fprintf(out, "  Enumerated: %d\n", result.Stats.Enumerated)
	fmt.Fprintf(out, "  Applied:    %d\n", result.Stats.Applied)
	fmt.Fprintf(out, "  Skipped:    %d (already correct)\n", result.Stats.Skipped)
	if result.Stats.Symlinks > 0 {
		fmt.Fprintf(out, "  Symlinks:   %d (not followed)\n", result.Stats.Symlinks)
	}
	if result.Stats.Excluded > 0 {
		fmt.Fprintf(out, "  Excluded:   %d (matched an exclude pattern)\n", result.Stats.Excluded)
	}
	fmt.Fprintf(out, "  Dirs fixed: %d\n", pre.Fixed)
	if result.AuditKept > 0 {
		fmt.Fprintf(out, "  Audit kept: %d (existing audit ACEs written back with the new DACL, as NFS shows them; SMB inheritance state not checked)\n", result.AuditKept)
	}
	fmt.Fprintf(out, "  Errors:     %d", totalErrors)
	if totalErrors > 0 {
		fmt.Fprintf(out, " (fix %d, walk %d, apply %d", pre.Errors, result.WalkErrors, applyErrors)
		if pre.ReaddirErrors > 0 {
			fmt.Fprintf(out, ", readdir %d — %d directories skipped due to file descriptor exhaustion, raise ulimit -n",
				pre.ReaddirErrors, pre.ReaddirErrors)
		}
		fmt.Fprint(out, ")")
	}
	fmt.Fprintln(out)
	if cfg.Pfind {
		fmt.Fprintf(out, "  Elapsed:    %.1fs (pre-pass %.1fs, main pass %.1fs)\n",
			result.Elapsed.Seconds(), prepassElapsed.Seconds(), mainElapsed.Seconds())
	} else {
		fmt.Fprintf(out, "  Elapsed:    %.1fs (single fused pass)\n", result.Elapsed.Seconds())
		fmt.Fprintf(out, "  Walk time:  readdir %.1fs, fix %.1fs (summed across %d workers)\n",
			pre.ReaddirTime.Seconds(), pre.FixTime.Seconds(), cfg.Workers)
	}
	if result.Elapsed.Seconds() > 0 {
		fmt.Fprintf(out, "  Rate:       %.0f ops/sec overall\n", float64(result.Stats.Applied)/result.Elapsed.Seconds())
	}
	if cfg.Pfind && mainElapsed.Seconds() > 0 {
		fmt.Fprintf(out, "  Main pass:  %.0f ops/sec\n", float64(result.Stats.Applied)/mainElapsed.Seconds())
	}
	// The write-path report, and the one decision it exists to settle. See
	// lingerverdict.go for why a shallow gather depth is not on its own an
	// argument for making writeLoop wait.
	if cfg.RPCStats {
		if cl, ok := tr.(*nfs41.Client); ok {
			batches, records := cl.WriteStats()
			cpu, cpuKnown := processCPU()
			for _, line := range lingerVerdict(lingerInputs{
				Batches:  batches,
				Records:  records,
				Conns:    cfg.Connections,
				Workers:  cfg.Workers,
				Wall:     result.Elapsed,
				CPU:      cpu,
				CPUKnown: cpuKnown,
				Cores:    runtime.NumCPU(),
			}) {
				fmt.Fprintln(out, line)
			}
		}
	}
	if named, ok := cfg.Log.(namedWriter); ok {
		fmt.Fprintf(out, "  Error log:  %s\n", named.Name())
	}

	if interrupted {
		fmt.Fprintf(errOut, "INTERRUPTED: run did not complete — %d applied before signal\n", result.Stats.Applied)
	}
	if result.EvidenceStopped {
		fmt.Fprintf(errOut, "ERROR: run stopped making changes after an evidence or log write failed — %d applied, "+
			"%d reached but not attempted, the rest of the tree not walked; free space and re-run with --resume\n",
			result.Stats.Applied, result.NotAttempted)
		totalErrors++
	}
	if walkErr != nil {
		fmt.Fprintf(errOut, "ERROR: walker failed: %v\n", walkErr)
		totalErrors++
	}
	if ckpt != nil {
		if duplicates, sample := ckpt.DuplicateCompletions(); duplicates > 0 {
			result.DuplicateCompletions = int64(duplicates)
			fmt.Fprintf(errOut, "ERROR: %d duplicate completion signals (e.g. %s); "+
				"this is a bug in permissionreset, not a problem with the tree. The affected "+
				"directories were deliberately left incomplete, so re-running with "+
				"--resume re-does them; do not trust this run's counts.\n",
				duplicates, sample)
			totalErrors++
		}
	}
	result.TotalErrors = totalErrors
	if totalErrors > 0 || interrupted {
		if result.WalkErrors > 0 {
			fmt.Fprintf(errOut, "WARNING: %d enumeration errors — walk may be incomplete\n", result.WalkErrors)
		}
		if pre.Errors > 0 {
			fmt.Fprintf(errOut, "WARNING: %d directory fix errors — subtrees under unfixed directories were not walked\n", pre.Errors)
		}
		if pre.ReaddirErrors > 0 {
			fmt.Fprintf(errOut, "WARNING: %d directories could not be read (file descriptor exhaustion) — their subtrees were not walked; raise ulimit -n\n", pre.ReaddirErrors)
		}
		if interrupted {
			return result, fmt.Errorf("run interrupted: %w", context.Canceled)
		}
		return result, errRunFailed
	}
	return result, nil
}

const defaultWorkersFallback = 128

type workerDefault struct {
	transport string
	platform  nfs41.Platform
}

// workerDefaults holds concurrency defaults that a measurement justifies. Any
// combination absent from the table falls back to defaultWorkersFallback.
//
// MEASURED on the lab S200 (userspace NFSv4.1 against a FlashBlade), objects/s
// by worker count: 128 -> 54,371; 512 -> 63,128; 1024 -> 64,535 and 68,037;
// 2048 -> 59,092; 4096 -> 54,019. The curve peaks at 1024 and falls off on
// either side, which is worth roughly 17-25% over the historical 128.
//
// FlashArray has no row because FlashArray is not a supported target for the
// userspace transport: an FA runs the kernel path. The client can reach one --
// CREATE_SESSION completes, and the FlashArray rows in RFC-Deviations.md came
// through it -- but only behind the non-Pure server override, and a worker
// default measured on a FlashBlade would not transfer anyway. FA file services
// are active/passive and the array saturates near 2,240 objects/s, two orders
// off the numbers above, so the curve that peaks at 1024 here is a FlashBlade
// curve. When FA is supported, its row is one line and its own measurement.
var workerDefaults = map[workerDefault]int{
	{transport: "userspace", platform: nfs41.PlatformFlashBlade}: 1024,
}

func defaultWorkers(transportName string, platform nfs41.Platform) int {
	if n, ok := workerDefaults[workerDefault{transport: transportName, platform: platform}]; ok {
		return n
	}
	return defaultWorkersFallback
}

func transportPlatform(tr transport.Transport) nfs41.Platform {
	if c, ok := tr.(*nfs41.Client); ok {
		return c.Platform()
	}
	return nfs41.PlatformUnknown
}

// filesystemIdentity reads the filesystem identity of the tree being operated
// on: st_dev on the kernel transport, FATTR4_FSID in userspace. Both come from
// the same transport call, so the only thing that differs is what the number is
// called -- and that label matters, since the two are not comparable.
//
// Which filesystem answered is part of a run's identity: two runs against the
// same path can hit different filesystems across a remount or a nested mount,
// and the counts alone cannot tell them apart.
//
// A failure returns (0, "unknown") rather than an error: this is reporting
// metadata, and no run should fail for want of it.
func filesystemIdentity(tr transport.Transport, transportName string) (uint64, string) {
	root, err := tr.Root()
	if err != nil {
		return 0, "unknown"
	}
	attr, err := tr.Stat(root)
	if err != nil || attr.FSID == 0 {
		return 0, "unknown"
	}
	if transportName == "userspace" {
		return attr.FSID, "fsid"
	}
	return attr.FSID, "st_dev"
}

func platformLabel(p nfs41.Platform) string {
	if p == nfs41.PlatformUnknown {
		return "unknown"
	}
	return string(p)
}

// runValidate takes the partially filled Result from Run -- transport identity
// and effective options -- and adds its own counts to it, so a --validate run
// reports the same identifying facts as a repair run.
//
// Enumeration goes through walk.Prepass with a no-op fix, so it uses the
// transport for readdir — which is what makes --validate work under
// --transport=userspace. The earlier implementation used ParallelWalk/Pfind
// (local filesystem only) and was therefore refused under userspace.
func runValidate(ctx context.Context, tr transport.Transport, cfg Config, base Result, excluder *spec.Excluder, handoff *handoffSet, out, errOut io.Writer, writeLog func(string)) (result Result, runErr error) {
	// Shared across the validate workers for the same reason the apply path
	// shares one: the resolver memoizes, and a spec names a handful of
	// principals however many objects it touches.
	resolver := idmap.NewNSS()

	result = base
	st := &stats.Stats{}
	started := time.Now()
	if err := ctx.Err(); err != nil {
		result.Stats, result.Elapsed = st.Snapshot(), time.Since(started)
		return result, err
	}

	// --validate is read-only over the tree, but a sacl: spec still needs the
	// privilege proven before telling the operator every object matches: a
	// run lacking the audit bypass would otherwise report ErrAuditPrivilege
	// nowhere, since validate never attempts the write a real run would have
	// failed on. The probe itself writes a throwaway object (see
	// apply.ProbePreflight) -- "read-only" describes what happens to cfg.Root,
	// not to the probe target. Keyed on any sacl: key, sacl: [] included: a
	// DACL-keeping sacl: [] rule still reads every object, and on Purity//FA
	// before 6.12.1 that read without the bypass empties an inheriting SACL.
	// Any other nfsv4 spec still reads every object, so it proves the audit
	// bypass alone before the walk; a posix spec reads no ACLs.
	if len(cfg.Spec.SaclRules()) > 0 {
		if err := runPreflight(tr, cfg, errOut); err != nil {
			result.Stats, result.Elapsed = st.Snapshot(), time.Since(started)
			return result, err
		}
	} else if needsAuditBypassProof(cfg) {
		if err := proveAuditBypass(tr, cfg, errOut); err != nil {
			result.Stats, result.Elapsed = st.Snapshot(), time.Since(started)
			return result, err
		}
	}

	entryCh := make(chan walk.Entry, cfg.Workers*100)
	walkErrs := &walk.WalkErrors{}

	countingExclude := func(path string) bool {
		if handoff.take(path) {
			return true
		}
		if !excluder.Match(path) {
			return false
		}
		st.IncExcluded()
		return true
	}
	defer func() { result.HandedOff = handoff.reached() }()

	popts := walk.PrepassOptions{
		Transport: tr,
		Fix:       func(_ transport.Ref) (bool, string, walk.FixResult) { return false, "", walk.FixResult{} },
		Workers:   cfg.Workers,
		Exclude:   countingExclude,
	}
	if cfg.OneFilesystem {
		rootRef, err := tr.Root()
		if err != nil {
			result.Stats, result.Elapsed = st.Snapshot(), time.Since(started)
			fmt.Fprintf(errOut, "ERROR: resolve target for --one-filesystem: %v\n", err)
			return result, errRunFailed
		}
		rootAttr, err := tr.Stat(rootRef)
		if err != nil {
			result.Stats, result.Elapsed = st.Snapshot(), time.Since(started)
			fmt.Fprintf(errOut, "ERROR: stat target for filesystem ID: %v\n", err)
			return result, errRunFailed
		}
		if rootAttr.FSID == 0 {
			result.Stats, result.Elapsed = st.Snapshot(), time.Since(started)
			fmt.Fprintln(errOut, "ERROR: target reports filesystem ID 0; --one-filesystem cannot be enforced")
			return result, errRunFailed
		}
		popts.RootFSID = rootAttr.FSID
	}

	var producerWG sync.WaitGroup
	producerWG.Add(1)
	var prepassResult walk.PrepassResult
	go func() {
		defer producerWG.Done()
		prepassResult = walk.Prepass(cfg.Root, entryCh, walkErrs, popts)
		close(entryCh)
	}()

	stopProgress := make(chan struct{})
	var progressWG sync.WaitGroup
	if !cfg.Quiet {
		progressWG.Add(1)
		go func() {
			defer progressWG.Done()
			st.Reporter(errOut, time.Second, stopProgress)
		}()
	}

	var mismatches sync.Map
	var mismatchCount, matchCount, errCount int64
	var mu sync.Mutex

	var wg sync.WaitGroup
	sem := make(chan struct{}, cfg.Workers)

	batch := make([]walk.Entry, 0, cfg.BatchSize)
	useACLBatch := cfg.Spec.Protocol == "nfsv4"

	processBatch := func(entries []walk.Entry) {
		defer wg.Done()
		defer func() { <-sem }()

		// Filter to statable, non-symlink entries and record their indices.
		type validEntry struct {
			idx int
			e   *walk.Entry
		}
		valid := make([]validEntry, 0, len(entries))
		for i := range entries {
			e := &entries[i]
			if !e.Stat() {
				mu.Lock()
				errCount++
				mu.Unlock()
				writeLog(fmt.Sprintf("ERR: lstat %s failed", e.Path))
				continue
			}
			if e.IsSymlink {
				st.IncSymlinks()
				continue
			}
			valid = append(valid, validEntry{i, e})
		}

		// Pre-fetch ACLs in batch for NFSv4 validation.
		var cachedACLs [][]byte
		if useACLBatch && len(valid) > 0 {
			refs := make([]transport.Ref, len(valid))
			for i, v := range valid {
				refs[i] = v.e.Ref()
			}
			var err error
			cachedACLs, err = tr.GetACLBatch(refs)
			if err != nil {
				mu.Lock()
				errCount += int64(len(valid))
				mu.Unlock()
				writeLog(fmt.Sprintf("ERR: batch GetACL: %v", err))
				return
			}
		}

		for i, v := range valid {
			var acl []byte
			if cachedACLs != nil {
				acl = cachedACLs[i]
			}
			r := apply.ValidatePath(tr, v.e.Ref(), v.e.IsDir, cfg.Spec, v.e.Mode, acl, resolver)
			if r.Error != nil {
				mu.Lock()
				errCount++
				mu.Unlock()
				writeLog(fmt.Sprintf("ERR: %v", r.Error))
			} else if r.Matches {
				mu.Lock()
				matchCount++
				mu.Unlock()
			} else {
				mu.Lock()
				mismatchCount++
				sample := mismatchCount <= maxMismatchSamples
				mu.Unlock()
				// Only the printed sample is kept: a map of every mismatch would
				// grow with the tree.
				if sample {
					mismatches.Store(v.e.Path, r.Detail)
				}
				writeLog(r.Detail)
			}
		}
	}

	interrupted := false
	for entry := range entryCh {
		if ctx.Err() != nil {
			interrupted = true
			// Keep receiving without validating so the producer can finish and Run
			// still owns every goroutine that can use its transport. Unlike the apply
			// path, this producer is read-only while it drains.
			continue
		}
		st.IncEnumerated()
		batch = append(batch, entry)
		if len(batch) >= cfg.BatchSize {
			wg.Add(1)
			sem <- struct{}{}
			b := make([]walk.Entry, len(batch))
			copy(b, batch)
			go processBatch(b)
			batch = batch[:0]
		}
	}
	if len(batch) > 0 && !interrupted {
		wg.Add(1)
		sem <- struct{}{}
		b := make([]walk.Entry, len(batch))
		copy(b, batch)
		go processBatch(b)
	}

	producerWG.Wait()
	wg.Wait()
	close(stopProgress)
	progressWG.Wait()

	result.Stats, result.Elapsed, result.WalkErrors = st.Snapshot(), time.Since(started), walkErrs.Count()
	result.Interrupted = interrupted
	result.IsValidate = true
	result.MatchCount = matchCount
	result.MismatchCount = mismatchCount
	result.UnreadableCount = errCount
	result.ReaddirErrors = prepassResult.ReaddirErrors
	totalErrs := errCount + result.WalkErrors
	result.TotalErrors = totalErrs

	fmt.Fprintln(out, "\nValidation complete:")
	fmt.Fprintf(out, "  Checked:    %d\n", result.Stats.Enumerated)
	fmt.Fprintf(out, "  Match:      %d\n", matchCount)
	fmt.Fprintf(out, "  Mismatch:   %d\n", mismatchCount)
	if result.Stats.Symlinks > 0 {
		fmt.Fprintf(out, "  Symlinks:   %d (not checked)\n", result.Stats.Symlinks)
	}
	if result.Stats.Excluded > 0 {
		fmt.Fprintf(out, "  Excluded:   %d (matched an exclude pattern)\n", result.Stats.Excluded)
	}
	fmt.Fprintf(out, "  Errors:     %d\n", totalErrs)
	fmt.Fprintf(out, "  Elapsed:    %.1fs\n", result.Elapsed.Seconds())
	checked := matchCount + mismatchCount
	if result.Elapsed.Seconds() > 0 && checked > 0 {
		fmt.Fprintf(out, "  Rate:       %.0f checks/sec\n", float64(checked)/result.Elapsed.Seconds())
	}

	if !cfg.Quiet && mismatchCount > 0 {
		fmt.Fprintf(out, "\nFirst mismatches (up to %d):\n", maxMismatchSamples)
		mismatches.Range(func(_, v any) bool {
			fmt.Fprintf(out, "  %s\n", v.(string))
			return true
		})
	}

	if interrupted {
		return result, fmt.Errorf("run interrupted: %w", context.Canceled)
	}
	if mismatchCount > 0 || totalErrs > 0 {
		return result, errRunFailed
	}
	return result, nil
}

// beforeState renders an object's NFSv4 ACL before the write for the detailed
// evidence profile. A state the run did not read says so rather than guessing.
// Other protocols get nothing: their apply line already names the old mode
// ("(was 0600)"), and the walk does not stat every object to know it here.
func beforeState(acl []byte, haveACL bool) string {
	if !haveACL {
		return "before=unread"
	}
	lines, err := nfs4acl.FormatACL(acl)
	if err != nil {
		return "before=unparseable"
	}
	return "before=" + strings.Join(lines, ",")
}
