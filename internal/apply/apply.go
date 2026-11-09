package apply

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/auditproof"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/idmap"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs4acl"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/spec"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

type Result struct {
	Applied bool
	Skipped bool
	Error   error
	LogMsg  string
	// AuditKept is how many existing audit/alarm ACEs a DACL reset carried
	// forward (applyPreserveSACL). Zero for every other apply.
	AuditKept int
}

// Options controls optional apply behavior.
type Options struct {
	DryRun   bool
	Compare  bool           // read current ACL/mode before writing; skip if already correct
	SetOwner bool           // apply owner/group from spec (requires root or CAP_CHOWN)
	Idmap    idmap.Resolver // reconciles numeric and name@domain ACE principals; nil compares strictly

	// CachedACL, when non-nil, is used by applyKeepDACL and applyPreserveSACL
	// instead of calling
	// t.GetACL -- the caller's batch pre-fetch (run.go's processBatch, the way
	// runValidate already does for ValidatePath). Only meaningful for a
	// DACL-keeping rule (sacl: with no acl:): that is the one apply path that
	// must read the object's current ACL before it can write. A caller that
	// could not batch-read this object (or whose rule is not DACL-keeping)
	// leaves this nil, and applyKeepDACL falls back to its own per-object
	// GetACL -- there is no path from a missing or failed read to a write.
	CachedACL []byte

	// AllowAuditedDACLReset is --allow-audited-dacl-reset. Without it a DACL
	// reset (an acl: rule with no sacl: key) refuses any object that already
	// carries audit ACEs (ErrAuditedObject) instead of writing it.
	AllowAuditedDACLReset bool
}

// uidGidCache caches name-to-id lookups so we don't hit nsswitch per file.
var uidGidCache sync.Map

type uidGid struct {
	uid int
	gid int
}

func resolveOwnerGroup(owner, group string) (int, int, error) {
	key := owner + ":" + group
	if cached, ok := uidGidCache.Load(key); ok {
		ug := cached.(uidGid)
		return ug.uid, ug.gid, nil
	}

	uid := -1
	gid := -1

	if owner != "" {
		if n, err := strconv.Atoi(owner); err == nil {
			uid = n
		} else {
			n, err := idmap.LookupUID(owner)
			if err != nil {
				return 0, 0, fmt.Errorf("lookup user %q: %w "+
					"(a numeric uid needs no local directory and is sent to the array as-is)", owner, err)
			}
			uid = n
		}
	}

	if group != "" {
		if n, err := strconv.Atoi(group); err == nil {
			gid = n
		} else {
			n, err := idmap.LookupGID(group)
			if err != nil {
				return 0, 0, fmt.Errorf("lookup group %q: %w "+
					"(a numeric gid needs no local directory and is sent to the array as-is)", group, err)
			}
			gid = n
		}
	}

	uidGidCache.Store(key, uidGid{uid, gid})
	return uid, gid, nil
}

func applyOwnership(t transport.Transport, ref transport.Ref, perms *spec.RulePerms, opts Options) Result {
	path := ref.Path
	if perms.Owner == "" && perms.Group == "" {
		return Result{Skipped: true}
	}

	uid, gid, err := resolveOwnerGroup(perms.Owner, perms.Group)
	if err != nil {
		return Result{Error: fmt.Errorf("resolve owner/group for %s: %w", path, err)}
	}

	if opts.DryRun {
		return Result{
			Applied: true,
			LogMsg:  fmt.Sprintf("WOULD: lchown %s uid=%d gid=%d", path, uid, gid),
		}
	}

	if err := t.Chown(ref, uid, gid); err != nil {
		return Result{Error: fmt.Errorf("lchown %s: %w", path, err)}
	}
	return Result{
		Applied: true,
		LogMsg:  fmt.Sprintf("OK: lchown %s uid=%d gid=%d", path, uid, gid),
	}
}

// ProcessPath applies permissions to the object named by ref. cachedMode is the
// mode from enumeration lstat; pass 0 if unknown (will stat again).
//
// ref is passed through to the transport unchanged, filehandle included. That is
// the point: on the userspace transport the walk already learned each object's
// filehandle from READDIR, so forwarding it here is what keeps Chmod, Chown,
// SetACL and GetACL from re-resolving the path by LOOKUP. On the kernel transport
// ref.FH is nil and every call sees exactly what it saw when this took a string.
//
// ref.Path must always be set: it drives spec matching, log output, and the
// transport's own recovery from a stale filehandle. Nothing here may come to
// depend on ref.FH being present.
func ProcessPath(t transport.Transport, ref transport.Ref, isDir bool, s *spec.Spec, opts Options, cachedMode uint32) Result {
	path := ref.Path
	var r Result
	switch s.Protocol {
	case "posix":
		r = applyPosix(t, ref, isDir, s, opts, cachedMode)
	case "nfsv4":
		r = applyNFSv4(t, ref, isDir, s, opts)
	case "smb":
		r = applySMB(path, isDir, s, opts)
	default:
		return Result{Error: fmt.Errorf("unknown protocol %q", s.Protocol)}
	}

	if r.Error != nil || !opts.SetOwner {
		return r
	}

	perms := s.EffectivePerms(path, isDir)
	if perms.Owner == "" && perms.Group == "" {
		return r
	}

	owr := applyOwnership(t, ref, perms, opts)
	if owr.Error != nil {
		return Result{Error: owr.Error}
	}
	if owr.Applied {
		if r.LogMsg != "" {
			r.LogMsg += "; " + owr.LogMsg
		} else {
			r.LogMsg = owr.LogMsg
		}
		r.Applied = true
	}
	return r
}

func applyPosix(t transport.Transport, ref transport.Ref, isDir bool, s *spec.Spec, opts Options, cachedMode uint32) Result {
	path := ref.Path
	perms := s.EffectivePerms(path, isDir)
	if perms.Mode == "" {
		return Result{Skipped: true}
	}

	target, err := strconv.ParseUint(perms.Mode, 8, 32)
	if err != nil {
		return Result{Error: fmt.Errorf("parse mode %q: %w", perms.Mode, err)}
	}

	current := cachedMode
	if current == 0 {
		attr, err := t.Stat(ref)
		if err != nil {
			// Not wrapped: the transport already names the operation and the
			// path. Wrapping again produced "lstat P: lstat P: ..." and changed
			// log output that this task must leave byte-identical.
			return Result{Error: err}
		}
		current = attr.Mode
	}

	if uint64(current) == target {
		return Result{Skipped: true}
	}

	if opts.DryRun {
		return Result{
			Applied: true,
			LogMsg:  fmt.Sprintf("WOULD: chmod %s %s  (was 0%o)", perms.Mode, path, current),
		}
	}

	if err := t.Chmod(ref, uint32(target)); err != nil {
		return Result{Error: fmt.Errorf("chmod %s %s: %w", perms.Mode, path, err)}
	}
	return Result{
		Applied: true,
		LogMsg:  fmt.Sprintf("OK: chmod %s %s  (was 0%o)", perms.Mode, path, current),
	}
}

func applyNFSv4(t transport.Transport, ref transport.Ref, isDir bool, s *spec.Spec, opts Options) Result {
	path := ref.Path
	perms := s.EffectivePerms(path, isDir)

	if perms.KeepDACL() {
		return applyKeepDACL(t, ref, perms, opts)
	}

	if len(perms.ACL) == 0 {
		return Result{Skipped: true}
	}
	if perms.PreserveSACL() {
		return applyPreserveSACL(t, ref, perms, opts)
	}

	// Encoded when the spec was validated, not here: these bytes are identical
	// for every object the rule matches, and building them per object is pure
	// repetition on the hottest path in the program.
	aclData := perms.EncodedACL()
	if len(aclData) == 0 {
		return Result{Error: fmt.Errorf("encode ACL for %s: spec rule lists %d ACEs but none encoded", path, len(perms.ACL))}
	}

	// A dry run does not read: run.Run proves the audit bypass only before a
	// real apply, and an unproven read can empty inherited auditing (PS-02).
	if opts.Compare && !opts.DryRun {
		// Read through the transport, compare structurally. bytes.Equal is wrong
		// here even though both sides are the same wire format: a server is free
		// to normalise what it stores, and these do -- FlashArray drops the g
		// flag from GROUP@, and an idmapped export renders a numeric principal
		// back as name@domain -- so a byte comparison never matches and every
		// object is rewritten on every run. ACLEqualIdent decodes both sides,
		// compares ACEs field by field, and puts the principal through the
		// resolver so the two forms of one identity are recognised as one
		// identity.
		current, err := t.GetACL(ref)
		if err == nil && nfs4acl.ACLEqualIdent(current, aclData, opts.Idmap) {
			return Result{Skipped: true}
		}
	}

	if opts.DryRun {
		return Result{
			Applied: true,
			LogMsg:  fmt.Sprintf("WOULD: setxattr nfs4_acl %s", path),
		}
	}

	if err := t.SetACL(ref, aclData); err != nil {
		return Result{Error: fmt.Errorf("setxattr %s: %w", path, err)}
	}
	return Result{Applied: true, LogMsg: fmt.Sprintf("OK: setxattr nfs4_acl %s", path)}
}

// ErrNoDACLToKeep reports that a DACL-keeping rule (sacl: with no acl:) matched
// an object whose current ACL carries no ALLOW/DENY entries at all -- an
// all-audit ACL, most likely left by an earlier run against a spec that had
// not yet converged, or a decode failure's worth of nothing useful. There is
// nothing safe to keep: writing the rule's SACL alone would remove every
// grant and denial the object currently has. applyKeepDACL refuses rather than
// do that, and writes nothing.
var ErrNoDACLToKeep = errors.New("object has no ALLOW/DENY entries to keep; refusing to write a SACL-only ACL")

// ErrUnmappedPrincipal reports that the DACL a DACL-keeping rule would write
// back names a principal the array rendered as nobody (nfs4acl.IsUnmappedWho).
// The array has already folded that SID, and any others without an RFC 2307
// id, into one nobody identity on read, so writing those bytes back replaces
// each of them with the array's local nobody SID: on Purity//FA 6.10.6 it does
// so silently, with the NFS view unchanged (benchmarks/sacl-unmapped-sid-20261020).
// applyKeepDACL refuses and writes nothing. There is no override: the fix is
// RFC 2307 ids for those principals, or adding the SACL over SMB instead.
var ErrUnmappedPrincipal = errors.New("DACL names a principal the array shows as nobody (a SID with no RFC 2307 id); writing it back over NFS would replace that SID, so the object was left untouched -- give the principal a uidNumber/gidNumber or add the SACL over SMB")

// ErrSyntheticRangePrincipal reports that the DACL a DACL-keeping rule would
// write back names a numeric principal at or above nfs4acl.SyntheticIDFloor.
// FlashBlade decodes such a number as 1000000000 + RID on write, so the entry
// comes back naming a different, usually nonexistent, SID (#52). FlashArray
// does not, but permissionreset cannot tell the two apart on the kernel transport,
// so the object is refused on both.
var ErrSyntheticRangePrincipal = errors.New("DACL names a principal whose id is at or above 1000000000; FlashBlade decodes such ids as 1000000000+RID on an NFS write, which would replace that SID, so the object was left untouched -- use RFC 2307 ids below 1000000000, or add the SACL over SMB")

// ErrUnpreservableAudit reports that an object's existing audit ACEs name a
// principal an NFS write-back would not preserve -- one the array shows as
// nobody, or an id at or above 1000000000 -- so a DACL reset that keeps them
// would write a different SID into the SACL. The object is left untouched.
var ErrUnpreservableAudit = errors.New("existing audit ACEs name a principal an NFS write-back would change, so the DACL reset that keeps them was not written -- give the principal an RFC 2307 id below 1000000000, or reset this object's SACL explicitly with --sacl")

// ErrAuditedObject reports that a DACL reset met an object that already carries
// audit ACEs and --allow-audited-dacl-reset was not given. FlashArray rewrites
// the security descriptor control flags on any NFS ACL write: the SACL goes
// from auto-inherited to protected (S:AI -> S:P) and the DACL is flattened
// (D:AI -> D:P, RISKS.md #11), even when the bytes written are identical. The
// audit entries themselves survive, but their inheritance does not, so the
// object is not written. Not writing it does not freeze its access: FlashArray
// recomputes an unprotected object's inherited ACEs whenever an ancestor's ACL
// changes, so a refused child still follows its parent's reset.
var ErrAuditedObject = errors.New("object carries audit ACEs, and an NFS ACL write makes FlashArray mark its SACL and DACL protected (S:AI -> S:P, D:AI -> D:P), so the DACL reset was not written -- reset it over SMB, or pass --allow-audited-dacl-reset to accept the header change")

// checkMappedDACL fails with ErrUnmappedPrincipal or ErrSyntheticRangePrincipal,
// naming the who values, when daclRaw carries a principal an NFS write-back
// would not preserve.
func checkMappedDACL(daclRaw []byte) error {
	bad, err := nfs4acl.UnmappedPrincipals(daclRaw)
	if err != nil {
		return fmt.Errorf("decode DACL: %w", err)
	}
	if len(bad) > 0 {
		return fmt.Errorf("%w (who: %s)", ErrUnmappedPrincipal, strings.Join(bad, ", "))
	}
	high, err := nfs4acl.SyntheticRangePrincipals(daclRaw)
	if err != nil {
		return fmt.Errorf("decode DACL: %w", err)
	}
	// FlashBlade shows a principal it has written once as name@domain, so a
	// high id can hide behind a name. Resolve named principals through NSS and
	// apply the same floor to the id they map to.
	aces, _ := nfs4acl.DecodeACL(daclRaw)
	for _, a := range aces {
		if !strings.Contains(a.Who, "@") || strings.HasSuffix(a.Who, "@") {
			continue // numeric (checked above) or a special such as OWNER@
		}
		if id, ok := highIDLookup(a.Who, a.Flags&nfs4acl.FlagGroup != 0); ok && nfs4acl.IsSyntheticRangeWho(id) {
			high = append(high, a.Who+"="+id)
		}
	}
	if len(high) > 0 {
		return fmt.Errorf("%w (who: %s)", ErrSyntheticRangePrincipal, strings.Join(high, ", "))
	}
	return nil
}

// highIDLookup resolves a named principal to its POSIX id. It is a variable so
// tests can script it without the host's NSS.
var highIDLookup = idmap.NumericID

// CheckKeepDACLTarget reads the ACL of root and fails with
// ErrUnmappedPrincipal if its DACL names an unmapped principal. run calls it
// once before the walk, so a tree whose top already shows the problem is
// refused whole instead of producing one error per object.
func CheckKeepDACLTarget(t transport.Transport, root transport.Ref) error {
	raw, err := t.GetACL(root)
	if err != nil {
		return fmt.Errorf("getxattr %s: %w", root.Path, err)
	}
	daclRaw, _, _, err := nfs4acl.SplitACL(raw)
	if err != nil {
		return fmt.Errorf("split ACL for %s: %w", root.Path, err)
	}
	return checkMappedDACL(daclRaw)
}

// ProveAuditBypass proves, entirely on a disposable probe target (never root
// or any other live object), that this identity holds the array's audit
// bypass: it writes a placeholder audit ACE and confirms the read-back
// retains it.
//
// PS-02 (#71): CheckKeepDACLTarget reads root's live ACL, and a DACL reset
// that preserves auditing reads every object's, and on at least one array an unprivileged read has been observed to
// empty inherited auditing -- so reading root to decide whether it is safe to
// touch its auditing can itself destroy the state being protected. Callers
// that are about to read a live object's ACL for a reason that depends on its
// SACL being observed without being disturbed must call ProveAuditBypass
// first and fail closed (never read root) on any error from it, including
// ErrAuditPrivilege and ErrAuditNotRetained -- proving the bypass on a
// disposable target never touches what the run is trying to protect.
//
// This proves write-then-keep privilege, which is what avoids the documented
// unprivileged-write/unprivileged-loss failure; it does not independently
// prove that a privileged *read* never mutates dynamic inheritance on every
// array and firmware revision. See PS-02's acceptance notes.
// The proof itself lives in internal/auditproof, so build-spec capture can
// run it without importing this package.
func ProveAuditBypass(t transport.Transport, ref transport.Ref) error {
	return auditproof.Prove(t, ref)
}

// applyKeepDACL implements the DACL-keeping rule (plan v3 commit 4): the
// object's own ALLOW/DENY entries are kept exactly as read -- copied
// byte-for-byte by nfs4acl.SplitACL, never decoded and re-encoded, so a who
// field FA renders oddly (a numeric principal, GROUP@ with no g flag, a
// non-canonical ordering) round-trips exactly -- and its audit (U/L) entries,
// wherever they were, are replaced with perms.SaclACEs() appended at the tail.
//
// A read error fails the object outright: with nothing known about its
// current DACL there is nothing safe to keep, so this never reaches a write.
// An object with no ALLOW/DENY entries to keep fails with ErrNoDACLToKeep,
// also before any write is attempted.
//
// opts.Compare compares the whole reassembled ACL against what was just read
// with nfs4acl.ACLEqualIdent -- the same structural, identity-aware comparison
// every other NFSv4 compare in this file uses. That comparison is byte-exact
// for the kept DACL region by construction (it is the same bytes on both
// sides) and identity-aware for the SACL tail, so a second run against an
// object this rule already converged is a no-op.
//
// opts.DryRun returns before the read (review item 7), so a dry run never
// touches the object at all.
func applyKeepDACL(t transport.Transport, ref transport.Ref, perms *spec.RulePerms, opts Options) Result {
	path := ref.Path

	// A dry run must not read either. Before Purity//FA 6.12.1 an ACL read by
	// an identity without the audit bypass empties an inheriting SACL, and a
	// dry run has no preflight to prove the bypass (the probe would be a
	// write). So the report is unconditional: it cannot tell a converged
	// object (--compare) or an ErrNoDACLToKeep object from one that would be
	// written. --validate reads, but only after its own preflight.
	if opts.DryRun {
		return Result{
			Applied: true,
			LogMsg:  fmt.Sprintf("WOULD: setxattr nfs4_acl %s (keep DACL, replace SACL; not read on a dry run)", path),
		}
	}

	current := opts.CachedACL
	if current == nil {
		var err error
		current, err = t.GetACL(ref)
		if err != nil {
			return Result{Error: fmt.Errorf("getxattr %s: %w", path, err)}
		}
	}

	daclRaw, daclCount, _, err := nfs4acl.SplitACL(current)
	if err != nil {
		return Result{Error: fmt.Errorf("split ACL for %s: %w", path, err)}
	}
	if daclCount == 0 {
		return Result{Error: fmt.Errorf("%s: %w", path, ErrNoDACLToKeep)}
	}
	if err := checkMappedDACL(daclRaw); err != nil {
		return Result{Error: fmt.Errorf("%s: %w", path, err)}
	}

	want := nfs4acl.JoinACL(daclRaw, perms.SaclACEs())

	if opts.Compare && nfs4acl.ACLEqualIdent(current, want, opts.Idmap) {
		return Result{Skipped: true}
	}

	if err := t.SetACL(ref, want); err != nil {
		return Result{Error: fmt.Errorf("setxattr %s: %w", path, err)}
	}
	return Result{Applied: true, LogMsg: fmt.Sprintf("OK: setxattr nfs4_acl %s (keep DACL, replace SACL)", path)}
}

// applyPreserveSACL implements a DACL reset that keeps auditing (PS-04): an
// acl: rule with no sacl: key replaces the object's ALLOW/DENY entries with
// the spec's and carries the object's existing audit/alarm entries forward,
// byte-for-byte, at the tail. Both FlashArray and FlashBlade return the SACL
// inside system.nfs4_acl, so a blind write of the spec DACL would delete it
// (RISKS.md #10, #51) -- and a clean root says nothing about its descendants,
// so every object is read.
//
// What is kept is the set of audit entries the NFS view shows, not SMB
// inheritance state: an inherited audit ACE written back over NFS may be
// stored as an explicit one. That is the contract; raw SMB descriptor
// fidelity is a separate check (PS-06).
//
// A read or parse failure fails the object with no write. So does an audit
// entry naming a principal the write-back would change (ErrUnpreservableAudit).
// A dry run neither reads nor writes, for the reason applyKeepDACL gives.
func applyPreserveSACL(t transport.Transport, ref transport.Ref, perms *spec.RulePerms, opts Options) Result {
	path := ref.Path
	if opts.DryRun {
		return Result{
			Applied: true,
			LogMsg:  fmt.Sprintf("WOULD: setxattr nfs4_acl %s (replace DACL, keep audit ACEs; not read on a dry run)", path),
		}
	}

	current := opts.CachedACL
	if current == nil {
		var err error
		current, err = t.GetACL(ref)
		if err != nil {
			return Result{Error: fmt.Errorf("getxattr %s (needed to keep its audit ACEs): %w", path, err)}
		}
	}
	_, saclRaw, _, saclCount, err := nfs4acl.SplitRaw(current)
	if err != nil {
		return Result{Error: fmt.Errorf("parse ACL of %s (needed to keep its audit ACEs): %w", path, err)}
	}

	want := perms.EncodedACL()
	if saclCount > 0 {
		if !opts.AllowAuditedDACLReset {
			return Result{Error: fmt.Errorf("%s: %w (%d audit ACEs)", path, ErrAuditedObject, saclCount)}
		}
		if err := checkMappedDACL(saclRaw); err != nil {
			return Result{Error: fmt.Errorf("%s: %w: %v", path, ErrUnpreservableAudit, err)}
		}
		want = nfs4acl.JoinRaw(want, saclRaw)
	}

	if opts.Compare && nfs4acl.ACLEqualIdent(current, want, opts.Idmap) {
		return Result{Skipped: true}
	}
	if err := t.SetACL(ref, want); err != nil {
		return Result{Error: fmt.Errorf("setxattr %s: %w", path, err)}
	}
	if saclCount > 0 {
		return Result{Applied: true, AuditKept: saclCount, LogMsg: fmt.Sprintf("OK: setxattr nfs4_acl %s (replace DACL, kept %d audit ACEs)", path, saclCount)}
	}
	return Result{Applied: true, LogMsg: fmt.Sprintf("OK: setxattr nfs4_acl %s", path)}
}

func applySMB(path string, isDir bool, s *spec.Spec, opts Options) Result {
	perms := s.EffectivePerms(path, isDir)
	if len(perms.DACL) == 0 {
		return Result{Skipped: true}
	}

	daclSpec := strings.Join(perms.DACL, ",")
	unc := fmt.Sprintf("//%s/%s", s.SMB.Server, s.SMB.Share)

	if opts.DryRun {
		return Result{
			Applied: true,
			LogMsg:  fmt.Sprintf("WOULD: smbcacls %s %s --set ...", unc, path),
		}
	}

	args := []string{unc, path, "--set", daclSpec}
	if s.SMB.Credentials != "" {
		args = append(args, "-A", s.SMB.Credentials)
	}

	ctx, cancel := withTimeout(30 * time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "smbcacls", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return Result{Error: fmt.Errorf("smbcacls %s: %s: %w", path, strings.TrimSpace(string(out)), err)}
	}
	return Result{Applied: true, LogMsg: fmt.Sprintf("OK: smbcacls %s", path)}
}

func withTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

// ValidateResult reports whether a path's current permissions match the spec.
type ValidateResult struct {
	Matches bool
	Detail  string // human-readable mismatch description; empty if matches
	Error   error
}

// ValidatePath checks whether the object named by ref currently matches the spec
// without making any changes. As with ProcessPath, ref is handed to the transport
// intact so a filehandle the walk already has is not resolved a second time.
//
// cachedACL, when non-nil, is used instead of calling t.GetACL, allowing the
// caller to pre-fetch ACLs in batch.
func ValidatePath(t transport.Transport, ref transport.Ref, isDir bool, s *spec.Spec, cachedMode uint32, cachedACL []byte, resolver idmap.Resolver) ValidateResult {
	switch s.Protocol {
	case "posix":
		return validatePosix(t, ref, isDir, s, cachedMode)
	case "nfsv4":
		return validateNFSv4(t, ref, isDir, s, cachedACL, resolver)
	default:
		return ValidateResult{Error: fmt.Errorf("validate not supported for protocol %q", s.Protocol)}
	}
}

func validatePosix(t transport.Transport, ref transport.Ref, isDir bool, s *spec.Spec, cachedMode uint32) ValidateResult {
	path := ref.Path
	perms := s.EffectivePerms(path, isDir)
	var mismatches []string

	if perms.Mode != "" {
		target, err := strconv.ParseUint(perms.Mode, 8, 32)
		if err != nil {
			return ValidateResult{Error: fmt.Errorf("parse mode %q: %w", perms.Mode, err)}
		}
		current := cachedMode
		if current == 0 {
			attr, err := t.Stat(ref)
			if err != nil {
				// See applyPosix: the transport already wraps this.
				return ValidateResult{Error: err}
			}
			current = attr.Mode
		}
		if uint64(current) != target {
			mismatches = append(mismatches, fmt.Sprintf("mode=0%o want=%s", current, perms.Mode))
		}
	}

	if ownerMismatch := validateOwnership(path, perms); ownerMismatch != "" {
		mismatches = append(mismatches, ownerMismatch)
	}

	if len(mismatches) == 0 {
		return ValidateResult{Matches: true}
	}
	return ValidateResult{
		Detail: fmt.Sprintf("MISMATCH: %s %s", path, strings.Join(mismatches, ", ")),
	}
}

func validateNFSv4(t transport.Transport, ref transport.Ref, isDir bool, s *spec.Spec, cachedACL []byte, resolver idmap.Resolver) ValidateResult {
	path := ref.Path
	perms := s.EffectivePerms(path, isDir)
	var mismatches []string

	switch {
	case perms.KeepDACL():
		// The spec defines no DACL for this rule, so there is nothing of the
		// spec's to compare the object's ALLOW/DENY entries against -- only
		// the SACL tail the rule actually names is checked, identity-aware,
		// same as every other NFSv4 compare here.
		got := cachedACL
		if got == nil {
			var err error
			got, err = t.GetACL(ref)
			if err != nil {
				return ValidateResult{Error: fmt.Errorf("getxattr %s: %w", path, err)}
			}
		}
		_, _, gotSacl, err := nfs4acl.SplitACL(got)
		if err != nil {
			return ValidateResult{Error: fmt.Errorf("split ACL %s: %w", path, err)}
		}
		wantSacl := perms.SaclACEs()
		if !nfs4acl.ACEsEqualIdent(gotSacl, wantSacl, resolver) {
			mismatches = append(mismatches, describeSaclMismatch(gotSacl, wantSacl))
		}
	default:
		if want := perms.EncodedACL(); len(want) > 0 {
			got := cachedACL
			if got == nil {
				var err error
				got, err = t.GetACL(ref)
				if err != nil {
					return ValidateResult{Error: fmt.Errorf("getxattr %s: %w", path, err)}
				}
			}
			// A rule that keeps auditing says nothing about the SACL, so only
			// the ALLOW/DENY entries are the spec's to check.
			if perms.PreserveSACL() {
				dacl, _, _, _, err := nfs4acl.SplitRaw(got)
				if err != nil {
					return ValidateResult{Error: fmt.Errorf("parse ACL %s: %w", path, err)}
				}
				got = dacl
			}
			if !nfs4acl.ACLEqualIdent(got, want, resolver) {
				mismatches = append(mismatches, describeACLMismatch(got, want, resolver))
			}
		}
	}

	if ownerMismatch := validateOwnership(path, perms); ownerMismatch != "" {
		mismatches = append(mismatches, ownerMismatch)
	}

	if len(mismatches) == 0 {
		return ValidateResult{Matches: true}
	}
	return ValidateResult{
		Detail: fmt.Sprintf("MISMATCH: %s %s", path, strings.Join(mismatches, ", ")),
	}
}

// validateOwnership reports how the object's owner and group differ from the
// spec, or "" when they match.
//
// Uses syscall.Lstat on the path, which reads the client's local view. The
// transport.Attr does not carry UID/GID, so this is the only route available.
// Under --transport=userspace the path still resolves through the kernel mount,
// which is correct for ownership: the kernel NFS client is the authority on
// uid/gid mapping, and the userspace transport has no GETATTR for owner.
// describeACLMismatch names the first ACE that differs. A byte-count alone --
// which is all this reported for its first year -- makes an identity-form
// difference look like a structural one and costs an operator a manual
// nfs4_getfacl to tell them apart.
func describeACLMismatch(got, want []byte, resolver idmap.Resolver) string {
	summary := fmt.Sprintf("acl %d bytes, want %d bytes", len(got), len(want))

	gotACEs, gotErr := nfs4acl.DecodeACL(got)
	wantACEs, wantErr := nfs4acl.DecodeACL(want)
	if gotErr != nil || wantErr != nil {
		return summary
	}
	if len(gotACEs) != len(wantACEs) {
		return fmt.Sprintf("%s (%d ACEs, want %d)", summary, len(gotACEs), len(wantACEs))
	}
	for i := range gotACEs {
		g, w := gotACEs[i], wantACEs[i]
		if g.Type != w.Type || g.Flags != w.Flags || g.Mask != w.Mask {
			return fmt.Sprintf("%s (ACE %d: type/flags/mask 0x%x/0x%x/0x%x, want 0x%x/0x%x/0x%x)",
				summary, i, g.Type, g.Flags, g.Mask, w.Type, w.Flags, w.Mask)
		}
		// Through the resolver, as the comparison was: a who that is only the
		// other form of the same identity is not the difference to report.
		if !nfs4acl.ACEsEqualIdent([]nfs4acl.ACE{g}, []nfs4acl.ACE{w}, resolver) {
			return fmt.Sprintf("%s (ACE %d: who %q, want %q)", summary, i, g.Who, w.Who)
		}
	}
	return summary
}

// describeSaclMismatch is describeACLMismatch for a DACL-keeping rule's
// validate check: it compares two already-decoded ACE slices (the object's
// SACL tail, and the rule's own SaclACEs()) rather than two encoded ACLs,
// since validateNFSv4 never has a "want" ACL to encode for this rule -- the
// spec defines no DACL for it.
func describeSaclMismatch(got, want []nfs4acl.ACE) string {
	if len(got) != len(want) {
		return fmt.Sprintf("sacl %d entries, want %d", len(got), len(want))
	}
	for i := range got {
		g, w := got[i], want[i]
		if g.Type != w.Type || g.Flags != w.Flags || g.Mask != w.Mask {
			return fmt.Sprintf("sacl ACE %d: type/flags/mask 0x%x/0x%x/0x%x, want 0x%x/0x%x/0x%x",
				i, g.Type, g.Flags, g.Mask, w.Type, w.Flags, w.Mask)
		}
		if g.Who != w.Who {
			return fmt.Sprintf("sacl ACE %d: who %q, want %q", i, g.Who, w.Who)
		}
	}
	return "sacl mismatch"
}

func validateOwnership(path string, perms *spec.RulePerms) string {
	if perms.Owner == "" && perms.Group == "" {
		return ""
	}
	wantUID, wantGID, err := resolveOwnerGroup(perms.Owner, perms.Group)
	if err != nil {
		return fmt.Sprintf("owner/group resolve: %v", err)
	}
	var st syscall.Stat_t
	if err := syscall.Lstat(path, &st); err != nil {
		return fmt.Sprintf("lstat: %v", err)
	}
	var parts []string
	if perms.Owner != "" && int(st.Uid) != wantUID {
		parts = append(parts, fmt.Sprintf("uid=%d want=%d", st.Uid, wantUID))
	}
	if perms.Group != "" && int(st.Gid) != wantGID {
		parts = append(parts, fmt.Sprintf("gid=%d want=%d", st.Gid, wantGID))
	}
	return strings.Join(parts, ", ")
}

// CheckTraversePreserved verifies that the spec's directory permissions do not
// remove traverse (execute) access for the running identity. Without traverse,
// the walk cannot enumerate children of directories it has already fixed,
// causing silent incomplete repairs.
func CheckTraversePreserved(s *spec.Spec) error {
	checkPerms := func(label string, perms *spec.RulePerms) error {
		switch s.Protocol {
		case "posix":
			if perms.Mode == "" {
				return nil
			}
			mode, err := strconv.ParseUint(perms.Mode, 8, 32)
			if err != nil {
				return nil
			}
			if mode&0o111 == 0 {
				return fmt.Errorf("%s: directory mode %s removes all execute bits — walk will be locked out of child directories", label, perms.Mode)
			}
			if mode&0o100 == 0 {
				return fmt.Errorf("%s: directory mode %s removes owner execute — walk (running as owner) will be locked out of child directories", label, perms.Mode)
			}
		case "nfsv4":
			if len(perms.ACL) == 0 {
				return nil
			}
			var allowed, denied bool
			for _, line := range perms.ACL {
				ace, err := nfs4acl.ParseACELine(strings.TrimSpace(line))
				if err != nil {
					continue
				}
				if ace.Flags&nfs4acl.FlagInheritOnly != 0 {
					continue
				}
				if ace.Who != "OWNER@" && ace.Who != "EVERYONE@" {
					continue
				}
				if ace.Mask&nfs4acl.MaskExecute == 0 {
					continue
				}
				if ace.Type == nfs4acl.TypeDeny {
					denied = true
				}
				if ace.Type == nfs4acl.TypeAllow {
					allowed = true
				}
			}
			if denied && !allowed {
				return fmt.Errorf("%s: directory ACL denies execute to OWNER@/EVERYONE@ without any ALLOW — walk will be locked out of child directories", label)
			}
			if !allowed && !denied {
				return fmt.Errorf("%s: directory ACL grants no execute to OWNER@ or EVERYONE@ — walk may be locked out of child directories", label)
			}
		}
		return nil
	}

	// Rules are first-match-wins and a matching rule replaces the default, so a
	// perms block is only a lockout risk if a DIRECTORY can actually reach it.
	// An unpatterned rule of type "directory" (or "", which also matches
	// directories) covers every directory: nothing after it — later rules or the
	// default — is ever read for a directory, and judging those as directory
	// modes refuses valid specs (issue #11: default "0644" for files with an
	// unconditional directory rule "0755" is correct and must be accepted). A
	// PATTERNED directory rule covers only what it names, so everything after it
	// stays reachable and must still pass the check.
	for i := range s.Rules {
		r := &s.Rules[i]
		if r.Match.Type == "directory" || r.Match.Type == "" {
			if err := checkPerms(fmt.Sprintf("rule[%d]", i), &r.RulePerms); err != nil {
				return err
			}
			if r.Match.Pattern == "" {
				return nil // every directory matched here; nothing below is reachable by one
			}
		}
	}
	return checkPerms("default (reachable by unmatched directories)", &s.Default)
}

// ErrAuditPrivilege reports that the preflight's audit-ACE write was refused
// by the server: EACCES/EPERM on the kernel transport, NFS4ERR_ACCESS on
// userspace. It means the identity this run will use does not carry the
// array's audit bypass -- plain write access to the object is not enough to
// set a SACL (plan v3's "privilege is required, not just checked").
var ErrAuditPrivilege = auditproof.ErrAuditPrivilege

// ErrAuditNotRetained reports that the preflight's audit-ACE write was
// accepted but the read-back shows no U entries: the array took the write and
// silently dropped the audit ACEs rather than keeping them. This is the
// read-side half of the same 6.10.6 behavior plan v3 describes -- a read
// without the bypass empties the SACL -- so it fires on the read-back here
// exactly as it would on every object a real run touched.
var ErrAuditNotRetained = auditproof.ErrAuditNotRetained

// ProbePreflight verifies the spec can actually be applied, catching identity
// mapping failures, permission errors, missing NFSv4 ACL support, and -- when
// the spec carries any sacl: -- the separate privilege the array requires to
// write and keep audit ACEs.
//
// Applying the real spec is the whole point. A probe that merely proves the tree
// is writable passes on an export with no NFSv4 ACL support, or with idmapd
// misconfigured, or with a spec naming a principal that does not resolve — and
// those are exactly the failures worth finding before touching a million
// objects. ProbeTarget exists so both transports can offer something applyable:
// the kernel a temp file it removes afterwards, the userspace transport a
// disposable directory it creates (Mkdir) and removes (Remove) the same way.
//
// isDir comes from the transport and is not assumed. Spec rules differ for files
// and directories, so hardcoding either one applies the wrong rule set on the
// transport that returns the other. main.go calls this only when --dry-run is
// absent; internal/run also calls it for --validate when the spec uses sacl:.
//
// This supersedes main's path-based ProbePreflight, which created a temp file
// under the target: the userspace transport implements no OPEN, so it cannot
// use that exact mechanism, but it does implement Mkdir/Remove (PS-01, #70),
// so target is a disposable object on both transports now -- never the real
// run root or any other existing object.
//
// Every ACL this probe writes still goes through the same read-orig/restore
// envelope: the target's current ACL is read before anything is written
// (orig), and orig is written back with a deferred SetACL once the probe is
// done, success or failure alike, before the disposable target's own cleanup
// removes it. A failed read of orig means nothing is written at all, since
// there would be nothing to restore. A failed restore does not get swallowed:
// it replaces (or, if the probe also failed, is appended to) the returned
// error, naming the path and warning that its ACL may be altered -- harmless
// in the common case (the object is about to be removed anyway) but still
// surfaced for the rare case where the probe's own cleanup also fails and the
// disposable object outlives the run.
//
// Posix specs are exempt from all of the above: applyPosix chmods, it never
// touches system.nfs4_acl, and there is nothing here to read back or restore.
//
// The sacl: check rides on top of the ordinary apply, inside that same
// read-orig/restore envelope:
//
//   - A spec-DACL rule (acl: with sacl:) already writes its audit ACEs as part
//     of EncodedACL -- same SetACL as the DACL -- so the apply below covers the
//     write by itself. A refusal of that write is reported as ErrAuditPrivilege
//     rather than the generic error below when the matched rule carries sacl:,
//     since it is then the audit bypass that failed, not merely write access.
//   - A DACL-keeping rule (sacl: with no acl:) is applyKeepDACL now (plan v3
//     commit 4): the apply below actually performs the real read-split-join-
//     write, with its own ALLOW/DENY entries kept and the matched rule's
//     sacl: appended at the tail, so this needs no separate write of its own
//     -- the write ProcessPath already made carries the audit ACE. If orig has
//     no ALLOW/DENY entries at all, applyKeepDACL refuses on its own
//     (ErrNoDACLToKeep) before writing anything, and that refusal surfaces
//     here as the generic preflight error, not one of the audit sentinels: it
//     is a data problem with the probe target, not evidence about the
//     privilege.
//   - A spec whose only sacl: is on a directory rule, probed against a file
//     target (or vice versa), hits a different gap: the matched rule carries
//     no sacl: of its own even though the spec plainly uses one, so its
//     ordinary write (spec-DACL) carries no U entry, or applyKeepDACL has no
//     SaclACEs() to append. The second write below borrows another rule's
//     sacl: in that case, built the same way applyKeepDACL would (SplitACL's
//     dacl plus the borrowed sacl:, via JoinACL) but file-shaped (inheritance
//     flags stripped, since the probe target may be a plain file) -- the
//     probe never touches a real object for longer than it takes to restore
//     it, so whose audit ACEs it carries doesn't matter, only whether this
//     identity can write and keep one.
func ProbePreflight(t transport.Transport, ref transport.Ref, s *spec.Spec) (resultErr error) {
	target, isDir, cleanup, err := t.ProbeTarget(ref)
	if err != nil {
		return err
	}
	// Deferred, not called only on the success path: an early return that skips
	// it leaves a probe object behind. Its error is folded into resultErr
	// rather than discarded (PS-01): a disposable probe that failed to remove
	// itself is a real, if minor, failure the operator should see, not a
	// silent leftover.
	defer func() {
		if err := cleanup(); err != nil {
			if resultErr != nil {
				resultErr = fmt.Errorf("%w (also failed to clean up probe: %v)", resultErr, err)
			} else {
				resultErr = fmt.Errorf("preflight: %w", err)
			}
		}
	}()

	if s.Protocol != "nfsv4" {
		// Posix chmods a mode bit; there is no ACL to read back or restore.
		return ProcessPath(t, target, isDir, s, Options{DryRun: false}, 0).Error
	}

	orig, err := t.GetACL(target)
	if err != nil {
		return fmt.Errorf("preflight: read %s's current ACL before probing: %w", target.Path, err)
	}

	// Under a DACL-keeping rule both the probe write and the restore below
	// send orig's DACL back to the array. If it names an unmapped principal
	// that write is itself lossy, so refuse before either happens. On the
	// kernel transport target is a fresh file that inherited the root's ACL,
	// so this also stops a run whose root hands unmapped entries down.
	if len(s.KeepDACLRules()) > 0 {
		if daclRaw, _, _, splitErr := nfs4acl.SplitACL(orig); splitErr == nil {
			if err := checkMappedDACL(daclRaw); err != nil {
				return fmt.Errorf("preflight: %s: %w", target.Path, err)
			}
		}
	}

	// wrote tracks whether a SetACL was actually issued against target, so the
	// deferred restore below runs only when there is something to undo: the
	// no-A/D-entries refusal further down, for instance, must leave target
	// untouched.
	var wrote bool
	defer func() {
		if !wrote {
			return
		}
		if err := t.SetACL(target, orig); err != nil {
			restoreErr := fmt.Errorf("preflight: restore %s's original ACL failed after probing -- its ACL may be altered: %w", target.Path, err)
			if resultErr != nil {
				resultErr = fmt.Errorf("%w (also failed to restore: %v)", resultErr, restoreErr)
			} else {
				resultErr = restoreErr
			}
		}
	}()

	matched := s.EffectivePerms(target.Path, isDir)
	matchedSacl := matched.SaclACEs()

	// Whether ProcessPath is actually going to issue a SetACL, predicted from
	// orig (already read above) so wrote can be set BEFORE the call is made --
	// matching "issued", not merely "succeeded", for the restore above.
	//
	// A spec-DACL rule (acl: set) always attempts one, unconditionally. A
	// DACL-keeping rule (sacl: with no acl:) attempts one only when orig
	// itself has at least one ALLOW/DENY entry to keep -- applyKeepDACL
	// refuses and writes nothing otherwise, and the SplitACL call here is the
	// exact same split that function uses, so the two agree by construction
	// rather than by two independent readings of plan v3.
	attemptsWrite := len(matched.ACL) > 0
	if matched.KeepDACL() {
		if _, daclCount, _, splitErr := nfs4acl.SplitACL(orig); splitErr == nil && daclCount > 0 {
			attemptsWrite = true
		}
	}
	if attemptsWrite {
		wrote = true
	}
	// The probe target is disposable, so the audited-object refusal
	// (ErrAuditedObject) does not apply to it: what it carries is restored and
	// then removed.
	if err := ProcessPath(t, target, isDir, s, Options{AllowAuditedDACLReset: true}, 0).Error; err != nil {
		if len(matchedSacl) > 0 && isAuditAccessDenied(err) {
			return fmt.Errorf("%w: %v", ErrAuditPrivilege, err)
		}
		return err
	}

	// wroteSacl is true exactly when the write above carried a U entry: a
	// spec-DACL rule's EncodedACL already appends its own sacl:, and
	// applyKeepDACL appends the matched rule's SaclACEs() every time it
	// writes at all -- which attemptsWrite already predicted.
	wroteSacl := attemptsWrite && len(matchedSacl) > 0
	saclToVerify := matchedSacl
	if !wroteSacl {
		if len(saclToVerify) == 0 {
			saclToVerify = probeSaclFallback(s)
		}
		if len(saclToVerify) == 0 {
			// No sacl: anywhere in the spec: nothing more to probe.
			return nil
		}
		dacl, daclCount, _, err := nfs4acl.SplitACL(orig)
		if err != nil {
			return fmt.Errorf("preflight: split %s's current ACL: %w", target.Path, err)
		}
		if daclCount == 0 {
			return fmt.Errorf("preflight: %s has no ALLOW/DENY entries to probe the audit-ACE write against; refusing to write a SACL-only ACL", target.Path)
		}
		wrote = true
		if err := t.SetACL(target, buildSaclProbe(dacl, saclToVerify)); err != nil {
			if isAuditAccessDenied(err) {
				return fmt.Errorf("%w: %v", ErrAuditPrivilege, err)
			}
			return fmt.Errorf("preflight: audit ACE probe write: %w", err)
		}
	}

	got, err := t.GetACL(target)
	if err != nil {
		return fmt.Errorf("preflight: audit ACE probe read-back: %w", err)
	}
	aces, err := nfs4acl.DecodeACL(got)
	if err != nil {
		return fmt.Errorf("preflight: audit ACE probe read-back: decode: %w", err)
	}
	if !hasAuditACE(aces) {
		return ErrAuditNotRetained
	}
	return nil
}

// ProbeUnmappedPrincipals reports which named principals of s the array reads
// back as nobody (nfs4acl.IsUnmappedWho). It writes the probe target's own DACL
// plus one read-attributes ALLOW per spec.NamedPrincipals entry, with the
// target's SACL kept at the tail, reads the ACL back, and restores the
// original, inside the same read-orig/restore envelope as ProbePreflight.
//
// This is how Purity//FA treats a principal with no RFC 2307 id: it stores the
// SID, so SMB shows the right account, and renders it as 65534 over NFS (#50,
// benchmarks/dacl-reset-fidelity-20261020/RESULTS-fa.md). The reset is correct,
// so run only warns, but the NFS view can no longer tell such principals apart.
//
// The probe entries are matched to the read-back by position, after the
// target's own entries. If the array returns a different number of ALLOW/DENY
// entries (it merged or dropped some), the principals cannot be told apart, so
// a read-back with more nobody entries than the original is an error rather
// than a guess.
func ProbeUnmappedPrincipals(t transport.Transport, ref transport.Ref, s *spec.Spec) (unmapped []string, resultErr error) {
	named := s.NamedPrincipals()
	if len(named) == 0 {
		return nil, nil
	}
	probe := make([]nfs4acl.ACE, len(named))
	for i, p := range named {
		probe[i] = nfs4acl.ACE{Type: nfs4acl.TypeAllow, Flags: p.Flags, Mask: nfs4acl.MaskReadAttributes, Who: p.Who}
	}

	target, _, cleanup, err := t.ProbeTarget(ref)
	if err != nil {
		return nil, err
	}
	// See ProbePreflight: cleanup's error is folded into resultErr rather than
	// discarded.
	defer func() {
		if err := cleanup(); err != nil {
			if resultErr != nil {
				resultErr = fmt.Errorf("%w (also failed to clean up probe: %v)", resultErr, err)
			} else {
				resultErr = fmt.Errorf("probe unmapped principals: %w", err)
			}
		}
	}()

	orig, err := t.GetACL(target)
	if err != nil {
		return nil, fmt.Errorf("read %s's current ACL: %w", target.Path, err)
	}
	dacl, daclCount, sacl, err := nfs4acl.SplitACL(orig)
	if err != nil {
		return nil, fmt.Errorf("split %s's current ACL: %w", target.Path, err)
	}
	origNobody := countUnmapped(dacl)

	// Registered before the write is issued, as in ProbePreflight: a write that
	// fails may still have changed the object.
	defer func() {
		if err := t.SetACL(target, orig); err != nil {
			restoreErr := fmt.Errorf("restore %s's original ACL failed after probing -- its ACL may be altered: %w", target.Path, err)
			if resultErr != nil {
				resultErr = fmt.Errorf("%w (also failed to restore: %v)", resultErr, restoreErr)
			} else {
				resultErr = restoreErr
			}
		}
	}()
	if err := t.SetACL(target, nfs4acl.JoinACL(nfs4acl.JoinACL(dacl, probe), sacl)); err != nil {
		return nil, fmt.Errorf("probe write naming every spec principal: %w", err)
	}

	got, err := t.GetACL(target)
	if err != nil {
		return nil, fmt.Errorf("probe read-back: %w", err)
	}
	gotDACL, gotCount, _, err := nfs4acl.SplitACL(got)
	if err != nil {
		return nil, fmt.Errorf("probe read-back: %w", err)
	}
	aces, err := nfs4acl.DecodeACL(gotDACL)
	if err != nil {
		return nil, fmt.Errorf("probe read-back: decode: %w", err)
	}
	if gotCount != daclCount+len(probe) {
		if countUnmapped(gotDACL) > origNobody {
			return nil, fmt.Errorf("the array returned %d ALLOW/DENY entries for the %d written, and at least one spec principal reads back as nobody; check the spec's principals from SMB", gotCount, daclCount+len(probe))
		}
		return nil, nil
	}
	for i, a := range aces[daclCount:] {
		if nfs4acl.IsUnmappedWho(a.Who) {
			unmapped = append(unmapped, probe[i].Who)
		}
	}
	return unmapped, nil
}

// countUnmapped is the number of entries in a raw ACL whose who is nobody. A
// malformed ACL counts as none; the callers have already decoded it once.
func countUnmapped(raw []byte) int {
	aces, err := nfs4acl.DecodeACL(raw)
	if err != nil {
		return 0
	}
	n := 0
	for _, a := range aces {
		if nfs4acl.IsUnmappedWho(a.Who) {
			n++
		}
	}
	return n
}

// isAuditAccessDenied reports whether err is the specific "no privilege"
// answer the audit-ACE write can get back on either transport: EACCES/EPERM
// from the kernel's setxattr, or NFS4ERR_ACCESS from the userspace client's
// SETATTR. Any other error (a stale filehandle, a transport fault, ENOSPC...)
// is left for the generic preflight message -- it is not evidence about the
// audit bypass specifically.
func isAuditAccessDenied(err error) bool {
	return auditproof.IsAccessDenied(err)
}

// probeSaclFallback finds a sacl: to probe with when the rule matched against
// the probe target carries none of its own: the spec's only sacl: is on
// directory rules while the probe target is a file (or vice versa), or the
// matched rule sets neither acl: nor sacl:. It is deliberately spec-wide --
// the probe never touches a real object, so which rule's audit ACEs the probe
// text comes from does not matter, only whether writing and keeping a U entry
// succeeds for this identity.
func probeSaclFallback(s *spec.Spec) []nfs4acl.ACE {
	if aces := s.Default.SaclACEs(); len(aces) > 0 {
		return aces
	}
	for i := range s.Rules {
		if aces := s.Rules[i].SaclACEs(); len(aces) > 0 {
			return aces
		}
	}
	// Every sacl: key is sacl: []. Such a rule still needs the bypass (its
	// reads empty inheriting SACLs on Purity//FA before 6.12.1, and its writes
	// cannot remove a SACL without it), so probe with a placeholder audit ACE.
	if len(s.SaclRules()) > 0 {
		return []nfs4acl.ACE{placeholderAuditACE}
	}
	return nil
}

// placeholderAuditACE is the probe's audit ACE for a spec whose only sacl:
// keys are empty. The probe target's original ACL is restored afterwards.
var placeholderAuditACE = auditproof.PlaceholderACE

// buildSaclProbe reassembles dacl -- the ALLOW/DENY region nfs4acl.SplitACL
// returned, header included -- with a file-shaped copy of saclACEs (see
// fileShapedSacl) appended at the tail, ready for SetACL. It is JoinACL plus
// fileShapedSacl: the same raw-byte-preserving reassembly applyKeepDACL uses
// for the real write, kept under its own name because stripping inheritance
// flags is specific to this call site (the probe target may be a plain file
// even when the borrowed sacl: came from a directory rule).
func buildSaclProbe(dacl []byte, saclACEs []nfs4acl.ACE) []byte {
	return nfs4acl.JoinACL(dacl, fileShapedSacl(saclACEs))
}

// fileShapedSacl strips the inheritance flags (f/d/n/i) from a set of audit
// ACEs so they are legal on a plain file. The probe target is whatever
// ProbeTarget hands back -- a plain file on the kernel transport, the export
// root directory on userspace -- and either one accepts an ACE with no
// inheritance flags; only a directory accepts f/d/n, so stripping them is the
// one shape that always applies. The probe is proving the write privilege
// exists, not exercising these ACEs' inheritance semantics.
func fileShapedSacl(aces []nfs4acl.ACE) []nfs4acl.ACE {
	return auditproof.FileShaped(aces)
}

// hasAuditACE reports whether aces contains at least one U (audit) entry.
func hasAuditACE(aces []nfs4acl.ACE) bool {
	return auditproof.HasAuditACE(aces)
}

// PreResolveIdentities validates that all named owner/group principals in the
// spec can be resolved. Returns a list of errors, empty if all resolve.
// Numeric UIDs/GIDs are not checked (they don't need resolution).
func PreResolveIdentities(s *spec.Spec) []error {
	var errs []error
	seen := map[string]bool{}

	check := func(label string, p *spec.RulePerms) {
		if p.Owner != "" && !isNumeric(p.Owner) && !seen["u:"+p.Owner] {
			seen["u:"+p.Owner] = true
			if err := idmap.CanResolveUser(p.Owner); err != nil {
				errs = append(errs, fmt.Errorf("%s: user %q: %w", label, p.Owner, err))
			}
		}
		if p.Group != "" && !isNumeric(p.Group) && !seen["g:"+p.Group] {
			seen["g:"+p.Group] = true
			if err := idmap.CanResolveGroup(p.Group); err != nil {
				errs = append(errs, fmt.Errorf("%s: group %q: %w", label, p.Group, err))
			}
		}
	}

	check("default", &s.Default)
	for i := range s.Rules {
		check(fmt.Sprintf("rule[%d]", i), &s.Rules[i].RulePerms)
	}
	return errs
}

func isNumeric(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

// FixOutcome reports what FixDirPerms did for one directory: whether it is
// now traversable, the message to log, and whether the real spec apply
// already ran (RealApply). A caller that would otherwise reprocess this
// directory through the ordinary apply path (walk's non-pfind Prepass does,
// since the directory's Entry is always also emitted to entryCh) can skip
// that reprocessing when RealApply is true and just count Applied for stats
// -- ProcessPath already ran to completion above, so a second run would only
// be a redundant GETATTR+SETATTR (or chmod) with the same result.
//
// RealApply is false in exactly one case: the posix chmod-755 fallback. That
// write only restores traversability: it is not the spec's real mode, so the
// directory still needs the ordinary apply path to set final permissions.
// It is also false when ProcessPath itself failed outright (OK false).
type FixOutcome struct {
	OK        bool
	Msg       string
	Applied   bool
	RealApply bool
	AuditKept int // Result.AuditKept of the real apply
}

// FixDirPerms fixes a single directory's permissions, returning whether it is
// traversable after.
func FixDirPerms(t transport.Transport, ref transport.Ref, s *spec.Spec, opts Options) FixOutcome {
	path := ref.Path
	r := ProcessPath(t, ref, true, s, opts, 0)
	if r.Error != nil {
		if s.Protocol == "posix" {
			if opts.DryRun {
				return FixOutcome{OK: true, Msg: fmt.Sprintf("[pre-pass] WOULD FALLBACK: chmod 755 %s: %v", path, r.Error)}
			}
			if err := t.Chmod(ref, 0o755); err == nil {
				return FixOutcome{OK: true, Msg: fmt.Sprintf("[pre-pass] FALLBACK: chmod 755 %s: %v", path, r.Error)}
			}
		}
		return FixOutcome{OK: false, Msg: fmt.Sprintf("[pre-pass] ERR: %s: %v", path, r.Error)}
	}
	if r.Applied {
		return FixOutcome{OK: true, Msg: fmt.Sprintf("[pre-pass] %s", r.LogMsg), Applied: true, RealApply: true, AuditKept: r.AuditKept}
	}
	return FixOutcome{OK: true, RealApply: true}
}
