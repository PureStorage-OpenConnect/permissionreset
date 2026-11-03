package speccapture

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41/xdr"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs4acl"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// ReplayVerifier is the write interface used by Verify to confirm that
// captured ACLs survive a SetACL/GetACL round-trip on the target transport.
// The kernel and userspace adapters each implement this with exclusive creates
// and their respective ACL operations.
type ReplayVerifier interface {
	CreateProbeDirectory(parent transport.Ref, name string) (transport.Ref, error)
	CreateProbeFile(parent transport.Ref, name string) (transport.Ref, error)
	SetACL(transport.Ref, []byte) error
	GetACL(transport.Ref) ([]byte, error)
	Remove(parent transport.Ref, name string) error
}

// probeName returns a unique probe name that avoids collisions under the
// scratch directory: .build-spec-probe-<pid>-<8 random hex bytes>-<suffix>
// ErrVerifyAuditPrivilege reports that a probe write carrying the captured
// audit (U) ACEs was refused with EACCES/EPERM/NFS4ERR_ACCESS. That is the
// running identity lacking the array's audit bypass, not an ACL an NFSv4.1
// repair cannot reproduce, so it gets its own message.
var ErrVerifyAuditPrivilege = errors.New("write of the captured audit (U) ACEs was refused -- the running identity lacks the array's audit bypass; " +
	"run --verify-write as root over AUTH_SYS with root squash off, or as an AD identity the array grants the bypass (Domain Admins membership is not enough)")

// isAccessDenied mirrors apply's audit-refusal check (EACCES/EPERM from the
// kernel's setxattr, NFS4ERR_ACCESS from the userspace SETATTR). It is kept
// here because internal/apply does not build on Windows and build-spec does.
func isAccessDenied(err error) bool {
	if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		return true
	}
	var se interface{ NFSStatus() uint32 }
	return errors.As(err, &se) && se.NFSStatus() == uint32(xdr.NFS4ERR_ACCESS)
}

func probeName(suffix string) string {
	var buf [8]byte
	_, _ = rand.Read(buf[:])
	return fmt.Sprintf(".build-spec-probe-%d-%x-%s", os.Getpid(), buf[:], suffix)
}

// Verify replays the captured ACLs through SetACL/GetACL to confirm that the
// server accepts them and that the emitted form is stable. It returns a new
// Result with YAML rebuilt from the stable (possibly canonicalized) form and
// IdentityReport.Verified set to true.
//
// scratch must not equal either exemplar; the function refuses that to prevent
// accidentally overwriting an exemplar's ACL.
func Verify(v ReplayVerifier, scratch, dirExemplar, fileExemplar transport.Ref, in *Result) (ret *Result, retErr error) {
	if scratch.Path == dirExemplar.Path {
		return nil, fmt.Errorf("scratch %q is the same as the directory exemplar; use a different directory", scratch.Path)
	}
	if scratch.Path == fileExemplar.Path {
		return nil, fmt.Errorf("scratch %q is the same as the file exemplar; use a different directory", scratch.Path)
	}

	dirProbeName := probeName("dir")
	fileProbeName := probeName("file")

	type probe struct {
		name    string
		created bool
	}
	probes := []*probe{
		{name: dirProbeName},
		{name: fileProbeName},
	}

	// Deferred cleanup: remove every probe that was created. If any removal
	// fails, override the return error naming the exact remaining paths.
	defer func() {
		var remaining []string
		for _, p := range probes {
			if !p.created {
				continue
			}
			if err := v.Remove(scratch, p.name); err != nil {
				remaining = append(remaining, scratch.Path+"/"+p.name)
			}
		}
		if len(remaining) > 0 {
			cleanupErr := fmt.Errorf("verification cleanup failed; remaining paths: %s", strings.Join(remaining, ", "))
			if retErr != nil {
				retErr = fmt.Errorf("%w; additionally verification cleanup failed; remaining paths: %s", retErr, strings.Join(remaining, ", "))
			} else {
				retErr = cleanupErr
				ret = nil
			}
		}
	}()

	// Create probes.
	dirProbe, err := v.CreateProbeDirectory(scratch, dirProbeName)
	if err != nil {
		return nil, fmt.Errorf("create probe directory under %q: %w", scratch.Path, err)
	}
	probes[0].created = true

	fileProbe, err := v.CreateProbeFile(scratch, fileProbeName)
	if err != nil {
		return nil, fmt.Errorf("create probe file under %q: %w", scratch.Path, err)
	}
	probes[1].created = true

	type exemplarInfo struct {
		label    string
		aces     []string
		hasSACL  bool
		probeRef transport.Ref
	}
	exemplars := []exemplarInfo{
		{label: "directory", aces: append(append([]string(nil), in.DirACEs...), in.DirSACL...), hasSACL: len(in.DirSACL) > 0, probeRef: dirProbe},
		{label: "file", aces: append(append([]string(nil), in.FileACEs...), in.FileSACL...), hasSACL: len(in.FileSACL) > 0, probeRef: fileProbe},
	}

	stableACEs := make([][]string, 2)
	stableRaw := make([][]byte, 2)

	for i, ex := range exemplars {
		// Encode captured ACEs.
		rawCaptured, err := nfs4acl.ParseACLSpec(ex.aces)
		if err != nil {
			return nil, fmt.Errorf("encode %s ACEs for verification: %w", ex.label, err)
		}

		// Pass 1: SetACL, GetACL, FormatACL.
		if err := v.SetACL(ex.probeRef, rawCaptured); err != nil {
			if ex.hasSACL && isAccessDenied(err) {
				return nil, fmt.Errorf("%w: %s exemplar: %v", ErrVerifyAuditPrivilege, ex.label, err)
			}
			return nil, fmt.Errorf(
				"SetACL failed for %s exemplar (ACEs: %v); this ACL cannot be reproduced by an NFSv4.1-only repair workflow: %w",
				ex.label, ex.aces, err)
		}

		readback1, err := v.GetACL(ex.probeRef)
		if err != nil {
			return nil, fmt.Errorf("GetACL readback for %s exemplar failed: %w", ex.label, err)
		}

		readback1ACEs, err := nfs4acl.FormatACL(readback1)
		if err != nil {
			return nil, fmt.Errorf("FormatACL readback for %s exemplar: %w", ex.label, err)
		}

		// If readback differs structurally from what we wrote, rebuild from readback.
		canonicalACEs := readback1ACEs
		if !nfs4acl.ACLEqual(rawCaptured, readback1) {
			// Server canonicalized; use the readback form.
			canonicalACEs = readback1ACEs
		}

		// Pass 2: re-encode the canonical form, SetACL, GetACL.
		rawCanonical, err := nfs4acl.ParseACLSpec(canonicalACEs)
		if err != nil {
			return nil, fmt.Errorf("encode canonicalized %s ACEs: %w", ex.label, err)
		}

		if err := v.SetACL(ex.probeRef, rawCanonical); err != nil {
			if ex.hasSACL && isAccessDenied(err) {
				return nil, fmt.Errorf("%w: %s exemplar, second pass: %v", ErrVerifyAuditPrivilege, ex.label, err)
			}
			return nil, fmt.Errorf(
				"SetACL failed for %s exemplar on second pass (ACEs: %v); this ACL cannot be reproduced by an NFSv4.1-only repair workflow: %w",
				ex.label, canonicalACEs, err)
		}

		readback2, err := v.GetACL(ex.probeRef)
		if err != nil {
			return nil, fmt.Errorf("GetACL second readback for %s exemplar failed: %w", ex.label, err)
		}

		// Second readback must be structurally identical to first.
		if !nfs4acl.ACLEqual(readback1, readback2) {
			return nil, fmt.Errorf(
				"%s ACL not stable after two passes: first readback and second readback differ structurally",
				ex.label)
		}

		stableACEs[i] = canonicalACEs
		stableRaw[i] = readback1
	}

	// Build new Result from stable form, split by type exactly as Capture does.
	result, err := assemble(stableRaw[0], stableACEs[0], stableRaw[1], stableACEs[1], in.opts)
	if err != nil {
		return nil, fmt.Errorf("verified ACLs: %w", err)
	}
	result.addProofNote(in.proofNote)
	// Per exemplar, not in aggregate: a server that kept the directory's U
	// entries but dropped the file's would otherwise verify, and the file rule
	// would become sacl: [] -- a rule that removes auditing from every file.
	for _, c := range []struct {
		label     string
		want, got []string
	}{
		{"directory", in.DirSACL, result.DirSACL},
		{"file", in.FileSACL, result.FileSACL},
	} {
		if len(c.want) != len(c.got) {
			return nil, fmt.Errorf("the server kept %d of the %s exemplar's %d audit (U) ACEs on its probe; "+
				"--verify-write with audit ACEs needs the array's audit bypass", len(c.got), c.label, len(c.want))
		}
	}
	result.Identity = in.Identity
	result.Identity.Verified = true

	return result, nil
}
