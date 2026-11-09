// Package auditproof proves, on a disposable probe object, that the running
// identity has the array's audit bypass before anything reads a live object's
// NFSv4 ACL (PS-02, #71). On at least one array an unprivileged read has been
// observed to empty inherited auditing, so the proof must come first and must
// never touch a live object.
//
// It depends only on nfs4acl, transport and the XDR status codes, so the
// build-spec capture path (Windows included) can use it without pulling in
// internal/apply or internal/walk.
package auditproof

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41/xdr"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs4acl"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// ErrAuditPrivilege reports that the array refused the probe's audit ACE
// write: the running identity lacks the audit bypass.
var ErrAuditPrivilege = errors.New("preflight: audit (SACL) ACE write was refused -- the running identity lacks the array's audit bypass")

// ErrAuditNotRetained reports that the array accepted the probe's audit ACE
// write but the read-back carries no audit ACEs.
var ErrAuditNotRetained = errors.New("preflight: audit (SACL) ACEs were accepted but the array did not retain them")

// Prober is the part of a transport the proof needs. transport.Kernel and
// nfs41.Client both satisfy it.
type Prober interface {
	ProbeTarget(transport.Ref) (target transport.Ref, isDir bool, cleanup func() error, err error)
	GetACL(transport.Ref) ([]byte, error)
	SetACL(transport.Ref, []byte) error
}

// Proof describes a proof that passed. Its String is the one line callers print
// before the first live ACL read, so an operator or a qualification run can see
// from the output alone that the proof ran, and that it ran first (#31).
type Proof struct {
	Probe string // the disposable probe object; removed before Prove returned
	IsDir bool   // the probe was a directory (userspace) rather than a file (kernel)
}

func (p Proof) String() string {
	kind := "file"
	if p.IsDir {
		kind = "directory"
	}
	return fmt.Sprintf("audit-bypass proof passed: the array kept an audit ACE written to disposable probe %s %s, and the probe was removed", kind, p.Probe)
}

// PlaceholderACE is the probe's audit ACE. The probe object is removed
// afterwards, so the entry never reaches a live object.
var PlaceholderACE = nfs4acl.ACE{
	Type:  nfs4acl.TypeAudit,
	Flags: nfs4acl.FlagSuccessAccess | nfs4acl.FlagFailedAccess,
	Mask:  nfs4acl.MaskReadData,
	Who:   "EVERYONE@",
}

// Prove creates a disposable probe under dir, writes PlaceholderACE to it,
// reads it back and confirms the array kept it. It reads and writes only the
// probe object, which it removes before returning. The probe's own first read
// sees the ACL it inherited from dir; that object is new and disposable, so
// nothing an unprivileged read could empty there is worth keeping.
//
// On success it returns the Proof to report. The returned error wraps
// ErrAuditPrivilege when the write is refused and is ErrAuditNotRetained when
// the read-back has no audit ACE; on any error the Proof is zero.
func Prove(p Prober, dir transport.Ref) (proof Proof, resultErr error) {
	target, isDir, cleanup, err := p.ProbeTarget(dir)
	if err != nil {
		return Proof{}, fmt.Errorf("prove audit bypass: %w", err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			proof = Proof{}
			if resultErr != nil {
				resultErr = fmt.Errorf("%w (also failed to clean up probe: %v)", resultErr, err)
			} else {
				resultErr = fmt.Errorf("prove audit bypass: %w", err)
			}
		}
	}()

	orig, err := p.GetACL(target)
	if err != nil {
		return Proof{}, fmt.Errorf("prove audit bypass: read probe target's ACL: %w", err)
	}
	dacl, daclCount, _, err := nfs4acl.SplitACL(orig)
	if err != nil {
		return Proof{}, fmt.Errorf("prove audit bypass: split probe target's ACL: %w", err)
	}
	if daclCount == 0 {
		return Proof{}, fmt.Errorf("prove audit bypass: disposable probe target %s has no ALLOW/DENY entries to probe against", target.Path)
	}

	if err := p.SetACL(target, nfs4acl.JoinACL(dacl, FileShaped([]nfs4acl.ACE{PlaceholderACE}))); err != nil {
		if IsAccessDenied(err) {
			return Proof{}, fmt.Errorf("%w: %v", ErrAuditPrivilege, err)
		}
		return Proof{}, fmt.Errorf("prove audit bypass: probe write: %w", err)
	}

	got, err := p.GetACL(target)
	if err != nil {
		return Proof{}, fmt.Errorf("prove audit bypass: probe read-back: %w", err)
	}
	aces, err := nfs4acl.DecodeACL(got)
	if err != nil {
		return Proof{}, fmt.Errorf("prove audit bypass: decode probe read-back: %w", err)
	}
	if !HasAuditACE(aces) {
		return Proof{}, ErrAuditNotRetained
	}
	return Proof{Probe: target.Path, IsDir: isDir}, nil
}

// nfsStatuser is implemented by the userspace client's status errors.
type nfsStatuser interface {
	NFSStatus() uint32
}

// IsAccessDenied reports whether err is the specific "no privilege" answer
// to an audit ACE write: EACCES/EPERM from the kernel's setxattr, or
// NFS4ERR_ACCESS from the userspace client's SETATTR. Any other error is not
// evidence about the audit bypass specifically.
func IsAccessDenied(err error) bool {
	if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		return true
	}
	var se nfsStatuser
	if errors.As(err, &se) {
		return se.NFSStatus() == uint32(xdr.NFS4ERR_ACCESS)
	}
	return false
}

// FileShaped strips the inheritance flags (f/d/n/i) from a set of audit ACEs
// so they are legal on a plain file. A probe target may be a file (kernel) or
// a directory (userspace), and both accept an ACE with no inheritance flags.
func FileShaped(aces []nfs4acl.ACE) []nfs4acl.ACE {
	const inheritFlags = nfs4acl.FlagFileInherit | nfs4acl.FlagDirInherit |
		nfs4acl.FlagNoPropInherit | nfs4acl.FlagInheritOnly
	out := make([]nfs4acl.ACE, len(aces))
	for i, a := range aces {
		a.Flags &^= inheritFlags
		out[i] = a
	}
	return out
}

// HasAuditACE reports whether aces contains at least one U (audit) entry.
func HasAuditACE(aces []nfs4acl.ACE) bool {
	for _, a := range aces {
		if a.Type == nfs4acl.TypeAudit {
			return true
		}
	}
	return false
}
