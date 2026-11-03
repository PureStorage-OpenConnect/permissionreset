package apply

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41/xdr"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs4acl"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/spec"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// fakeStatusError stands in for *nfs41.StatusError without importing
// internal/nfs41: that package's own test files import internal/apply, so
// this package importing it back -- even from a _test.go -- would be a cycle.
// It carries just enough to satisfy apply.go's nfsStatuser duck-typing.
type fakeStatusError struct{ status uint32 }

func (e *fakeStatusError) Error() string     { return "nfs41: fake status error" }
func (e *fakeStatusError) NFSStatus() uint32 { return e.status }

type setACLCall struct {
	ref transport.Ref
	acl []byte
}

type chmodCall struct {
	ref  transport.Ref
	mode uint32
}

type chownCall struct {
	ref transport.Ref
	uid int
	gid int
}

// recordingTransport records what apply asked for without touching a filesystem.
type recordingTransport struct {
	mu          sync.Mutex
	setACLCalls []setACLCall
	chmodCalls  []chmodCall
	chownCalls  []chownCall
	opOrder     []string // "chmod" or "chown" in call order
	getACL      []byte
	getACLErr   error
	getACLCalls int
	statCalls   []transport.Ref
	attr        transport.Attr
	statErr     error
	cleanupRan  bool
	probeIsDir  bool
	// cleanupErr, when non-nil, is returned by ProbeTarget's cleanup func, so a
	// test can assert it is folded into ProbePreflight/ProbeUnmappedPrincipals's
	// returned error rather than discarded (PS-01).
	cleanupErr error

	// setACLErr, when non-nil, is returned instead of recording the call --
	// used to simulate a privilege refusal on the preflight's audit-ACE
	// write. By default it fires on every call; failSetACLOnAttempt (1-based)
	// narrows that to exactly one call, so an earlier write can still land
	// for real and a later one (such as the restore) can still succeed.
	setACLErr           error
	failSetACLOnAttempt int
	setACLAttempts      int
	// echoACLOnGet makes GetACL return the bytes from the most recent SetACL
	// call instead of the fixed getACL field, so a test can write a probe ACL
	// and then assert on what the read-back actually contains, the way
	// ProbePreflight's retention check does.
	echoACLOnGet bool
}

func (r *recordingTransport) Root() (transport.Ref, error) { return transport.Ref{Path: "/"}, nil }

func (r *recordingTransport) ReadDir(transport.Ref) ([]transport.Dirent, error) { return nil, nil }
func (r *recordingTransport) ReadDirSetACL(ref transport.Ref, acl []byte) ([]transport.Dirent, bool, error) {
	entries, err := r.ReadDir(ref)
	if err != nil {
		return nil, false, err
	}
	if len(acl) > 0 {
		if err := r.SetACL(ref, acl); err != nil {
			return entries, false, nil
		}
		return entries, true, nil
	}
	return entries, false, nil
}

func (r *recordingTransport) SetACL(ref transport.Ref, acl []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.setACLAttempts++
	if r.setACLErr != nil && (r.failSetACLOnAttempt == 0 || r.setACLAttempts == r.failSetACLOnAttempt) {
		return r.setACLErr
	}
	r.setACLCalls = append(r.setACLCalls, setACLCall{ref: ref, acl: append([]byte(nil), acl...)})
	if r.echoACLOnGet {
		r.getACL = r.setACLCalls[len(r.setACLCalls)-1].acl
	}
	return nil
}

func (r *recordingTransport) GetACL(transport.Ref) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.getACLCalls++
	return r.getACL, r.getACLErr
}

func (r *recordingTransport) GetACLBatch(refs []transport.Ref) ([][]byte, error) {
	out := make([][]byte, len(refs))
	for i, ref := range refs {
		acl, err := r.GetACL(ref)
		if err != nil {
			return nil, err
		}
		out[i] = acl
	}
	return out, nil
}

func (r *recordingTransport) Chmod(ref transport.Ref, mode uint32) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.chmodCalls = append(r.chmodCalls, chmodCall{ref: ref, mode: mode})
	r.opOrder = append(r.opOrder, "chmod")
	return nil
}

func (r *recordingTransport) Chown(ref transport.Ref, uid, gid int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.chownCalls = append(r.chownCalls, chownCall{ref: ref, uid: uid, gid: gid})
	r.opOrder = append(r.opOrder, "chown")
	return nil
}
func (r *recordingTransport) Close() error { return nil }

func (r *recordingTransport) Stat(ref transport.Ref) (transport.Attr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.statCalls = append(r.statCalls, ref)
	return r.attr, r.statErr
}

// ProbeTarget hands back a fixed ref and records that cleanup ran, so a test can
// assert preflight both applied the spec and cleaned up after itself.
func (r *recordingTransport) ProbeTarget(transport.Ref) (transport.Ref, bool, func() error, error) {
	return transport.Ref{Path: "/probe-target"}, r.probeIsDir, func() error {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.cleanupRan = true
		return r.cleanupErr
	}, nil
}

func loadSpec(t *testing.T, content string) *spec.Spec {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "spec.yaml")
	os.WriteFile(path, []byte(content), 0644)
	s, err := spec.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestApplyPosixChangesMode(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "test.txt")
	os.WriteFile(f, []byte("x"), 0600)

	s := loadSpec(t, `
protocol: posix
default:
  mode: "0644"
`)
	r := ProcessPath(kernelTransport(t), transport.Ref{Path: f}, false, s, Options{}, 0)
	if !r.Applied {
		t.Fatal("expected Applied=true")
	}
	if r.Error != nil {
		t.Fatal(r.Error)
	}

	info, _ := os.Stat(f)
	got := info.Mode().Perm()
	if got != 0644 {
		t.Errorf("mode = 0%o, want 0644", got)
	}
}

func TestApplyPosixSkipsCorrect(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "test.txt")
	os.WriteFile(f, []byte("x"), 0644)

	s := loadSpec(t, `
protocol: posix
default:
  mode: "0644"
`)
	r := ProcessPath(kernelTransport(t), transport.Ref{Path: f}, false, s, Options{}, 0644)
	if !r.Skipped {
		t.Error("expected Skipped=true for already-correct mode")
	}
}

func TestApplyPosixDryRun(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "test.txt")
	os.WriteFile(f, []byte("x"), 0600)

	s := loadSpec(t, `
protocol: posix
default:
  mode: "0644"
`)
	r := ProcessPath(kernelTransport(t), transport.Ref{Path: f}, false, s, Options{DryRun: true}, 0)
	if !r.Applied {
		t.Fatal("dry-run should report Applied=true")
	}

	info, _ := os.Stat(f)
	if info.Mode().Perm() != 0600 {
		t.Error("dry-run should not change mode")
	}
}

func TestApplyPosixRuleMatch(t *testing.T) {
	dir := t.TempDir()
	sh := filepath.Join(dir, "run.sh")
	txt := filepath.Join(dir, "data.txt")
	os.WriteFile(sh, []byte("x"), 0600)
	os.WriteFile(txt, []byte("x"), 0600)

	s := loadSpec(t, `
protocol: posix
default:
  mode: "0644"
rules:
  - match:
      type: file
      pattern: "*.sh"
    mode: "0755"
`)
	ProcessPath(kernelTransport(t), transport.Ref{Path: sh}, false, s, Options{}, 0)
	ProcessPath(kernelTransport(t), transport.Ref{Path: txt}, false, s, Options{}, 0)

	shInfo, _ := os.Stat(sh)
	txtInfo, _ := os.Stat(txt)
	if shInfo.Mode().Perm() != 0755 {
		t.Errorf("run.sh mode = 0%o, want 0755", shInfo.Mode().Perm())
	}
	if txtInfo.Mode().Perm() != 0644 {
		t.Errorf("data.txt mode = 0%o, want 0644", txtInfo.Mode().Perm())
	}
}

func TestApplyUnknownProtocol(t *testing.T) {
	r := ProcessPath(kernelTransport(t), transport.Ref{Path: "/tmp"}, false, &spec.Spec{Protocol: "ftp"}, Options{}, 0)
	if r.Error == nil {
		t.Error("expected error for unknown protocol")
	}
}

func TestValidatePosixMatch(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "test.txt")
	os.WriteFile(f, []byte("x"), 0644)

	s := loadSpec(t, `
protocol: posix
default:
  mode: "0644"
`)
	r := ValidatePath(kernelTransport(t), transport.Ref{Path: f}, false, s, 0644, nil, nil)
	if !r.Matches {
		t.Errorf("expected match, got: %s", r.Detail)
	}
}

func TestValidatePosixMismatch(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "test.txt")
	os.WriteFile(f, []byte("x"), 0600)

	s := loadSpec(t, `
protocol: posix
default:
  mode: "0644"
`)
	r := ValidatePath(kernelTransport(t), transport.Ref{Path: f}, false, s, 0600, nil, nil)
	if r.Matches {
		t.Error("expected mismatch for 0600 vs 0644")
	}
	if r.Detail == "" {
		t.Error("expected non-empty Detail for mismatch")
	}
}

func TestValidateNoPerms(t *testing.T) {
	s := loadSpec(t, `
protocol: posix
default:
  mode: "0755"
rules:
  - match:
      type: directory
    mode: "0755"
`)
	// File doesn't match any rule and default has a mode, but test a path
	// where the effective perms mode matches — validate should say "matches."
	r := ValidatePath(kernelTransport(t), transport.Ref{Path: "/any"}, false, s, 0755, nil, nil)
	if !r.Matches {
		t.Error("matching mode should report matches")
	}
}

func TestFixDirPermsDryRun(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	os.Mkdir(sub, 0000)

	s := loadSpec(t, `
protocol: posix
default:
  mode: "0755"
rules:
  - match:
      type: directory
    mode: "0755"
`)
	out := FixDirPerms(kernelTransport(t), transport.Ref{Path: sub}, s, Options{DryRun: true})
	if !out.OK {
		t.Error("FixDirPerms dry-run should return ok=true")
	}

	info, _ := os.Stat(sub)
	if info.Mode().Perm() != 0000 {
		t.Errorf("dry-run should not change mode, got 0%o", info.Mode().Perm())
	}
}

func TestApplyNFSv4WritesThroughTheTransport(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "f")
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	rec := &recordingTransport{getACL: plainACL}
	s := &spec.Spec{
		Protocol: "nfsv4",
		Default:  spec.RulePerms{ACL: []string{"A::OWNER@:rwatTnNcCy"}},
	}

	r := ProcessPath(rec, transport.Ref{Path: p}, false, s, Options{DryRun: false}, 0)
	if r.Error != nil {
		t.Fatalf("ProcessPath: %v", r.Error)
	}
	if !r.Applied {
		t.Fatal("Applied = false, want true")
	}
	if len(rec.setACLCalls) != 1 {
		t.Fatalf("SetACL called %d times, want 1", len(rec.setACLCalls))
	}
	if rec.setACLCalls[0].ref.Path != p {
		t.Errorf("SetACL got path %q, want %q", rec.setACLCalls[0].ref.Path, p)
	}

	// The bytes handed to the transport must be exactly what nfs4acl produces.
	want, err := nfs4acl.ParseACLSpec(s.Default.ACL)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rec.setACLCalls[0].acl, want) {
		t.Error("SetACL received bytes that differ from nfs4acl.ParseACLSpec output")
	}
}

func TestApplyPosixChmodsThroughTheTransport(t *testing.T) {
	rec := &recordingTransport{}
	s := &spec.Spec{
		Protocol: "posix",
		Default:  spec.RulePerms{Mode: "750"},
	}
	r := ProcessPath(rec, transport.Ref{Path: "/x/y"}, true, s, Options{DryRun: false}, 0o700)
	if r.Error != nil {
		t.Fatalf("ProcessPath: %v", r.Error)
	}
	if len(rec.chmodCalls) != 1 || rec.chmodCalls[0].mode != 0o750 {
		t.Fatalf("chmod calls = %+v, want one call with mode 0750", rec.chmodCalls)
	}
}

// TestProbePreflightAppliesTheSpec is the regression test for finding 2 of the
// Task 1 review. A preflight that only proves the tree is writable passes on an
// export with no NFSv4 ACL support, or with idmapd misconfigured — which are the
// failures it exists to catch.
func TestProbePreflightAppliesTheSpec(t *testing.T) {
	orig := plainACL
	rec := &recordingTransport{getACL: orig}
	s := &spec.Spec{
		Protocol: "nfsv4",
		Default:  spec.RulePerms{ACL: []string{"A::OWNER@:rwatTnNcCy"}},
	}
	if err := ProbePreflight(rec, transport.Ref{Path: "/tree"}, s); err != nil {
		t.Fatalf("ProbePreflight: %v", err)
	}
	if len(rec.setACLCalls) != 2 {
		t.Fatalf("SetACL called %d times, want 2 — the real spec write, then the restore of the target's original ACL", len(rec.setACLCalls))
	}
	if rec.setACLCalls[0].ref.Path != "/probe-target" {
		t.Errorf("spec applied to %q, want the ProbeTarget result", rec.setACLCalls[0].ref.Path)
	}
	if !bytes.Equal(rec.setACLCalls[1].acl, orig) {
		t.Errorf("restore write = %q, want the target's original ACL %q back", rec.setACLCalls[1].acl, orig)
	}
	if !rec.cleanupRan {
		t.Error("cleanup did not run; a probe file would be left in the customer's tree")
	}
}

// TestProbePreflightPropagatesCleanupFailure pins PS-01's "propagate cleanup
// failures alongside the original error" requirement: a probe that otherwise
// succeeds but fails to remove its disposable target must not have that
// failure silently discarded.
func TestProbePreflightPropagatesCleanupFailure(t *testing.T) {
	orig := plainACL
	cleanupErr := errors.New("remove /probe-target: boom")
	rec := &recordingTransport{getACL: orig, cleanupErr: cleanupErr}
	s := &spec.Spec{
		Protocol: "nfsv4",
		Default:  spec.RulePerms{ACL: []string{"A::OWNER@:rwatTnNcCy"}},
	}
	err := ProbePreflight(rec, transport.Ref{Path: "/tree"}, s)
	if err == nil {
		t.Fatal("ProbePreflight() error = nil, want the cleanup failure surfaced")
	}
	if !strings.Contains(err.Error(), cleanupErr.Error()) {
		t.Fatalf("ProbePreflight() error = %v, want it to mention the cleanup failure %v", err, cleanupErr)
	}
}

// TestProveAuditBypassSucceedsOnDisposableTargetOnly pins PS-02's core
// contract: the probe writes and reads back only the disposable probe target
// -- never a Ref naming anything else -- and never calls CheckKeepDACLTarget's
// own operation (a plain GetACL of a caller-supplied root) itself.
func TestProveAuditBypassSucceedsOnDisposableTargetOnly(t *testing.T) {
	orig, err := nfs4acl.ParseACLSpec([]string{"A::OWNER@:rwaDxtTnNcCoy"})
	if err != nil {
		t.Fatal(err)
	}
	rec := &recordingTransport{getACL: orig, echoACLOnGet: true}
	if err := ProveAuditBypass(rec, transport.Ref{Path: "/tree"}); err != nil {
		t.Fatalf("ProveAuditBypass() error = %v", err)
	}
	if len(rec.setACLCalls) != 1 {
		t.Fatalf("SetACL called %d times, want 1 (the probe write only -- no restore is needed before the disposable target is removed)", len(rec.setACLCalls))
	}
	if rec.setACLCalls[0].ref.Path != "/probe-target" {
		t.Fatalf("SetACL went to %q, want the disposable probe target, not a live object", rec.setACLCalls[0].ref.Path)
	}
	if !rec.cleanupRan {
		t.Error("cleanup did not run; a probe object would be left behind")
	}
}

// TestProveAuditBypassNoAllowDenyEntriesRefuses pins that a disposable probe
// target with nothing to keep refuses rather than writing a SACL-only ACL.
func TestProveAuditBypassNoAllowDenyEntriesRefuses(t *testing.T) {
	auditOnly := nfs4acl.Encode([]nfs4acl.ACE{{Type: nfs4acl.TypeAudit, Who: "EVERYONE@", Mask: nfs4acl.MaskReadData, Flags: nfs4acl.FlagSuccessAccess}})
	rec := &recordingTransport{getACL: auditOnly}
	err := ProveAuditBypass(rec, transport.Ref{Path: "/tree"})
	if err == nil {
		t.Fatal("ProveAuditBypass() error = nil, want a refusal")
	}
	if len(rec.setACLCalls) != 0 {
		t.Fatalf("SetACL called %d times, want 0", len(rec.setACLCalls))
	}
}

// TestProveAuditBypassAccessDeniedGivesErrAuditPrivilege pins that a refused
// probe write is reported as ErrAuditPrivilege, matching ProbePreflight's own
// sentinel, so callers (run.go) can render it identically.
func TestProveAuditBypassAccessDeniedGivesErrAuditPrivilege(t *testing.T) {
	orig, err := nfs4acl.ParseACLSpec([]string{"A::OWNER@:rwaDxtTnNcCoy"})
	if err != nil {
		t.Fatal(err)
	}
	rec := &recordingTransport{getACL: orig, setACLErr: &fakeStatusError{status: uint32(xdr.NFS4ERR_ACCESS)}}
	if err := ProveAuditBypass(rec, transport.Ref{Path: "/tree"}); !errors.Is(err, ErrAuditPrivilege) {
		t.Fatalf("ProveAuditBypass() error = %v, want ErrAuditPrivilege", err)
	}
}

// TestProveAuditBypassReadBackWithoutUGivesErrAuditNotRetained pins that an
// array accepting the write but dropping the audit ACE on read-back is
// ErrAuditNotRetained, not a silent success.
func TestProveAuditBypassReadBackWithoutUGivesErrAuditNotRetained(t *testing.T) {
	daclOnly, err := nfs4acl.ParseACLSpec([]string{"A::OWNER@:rwaDxtTnNcCoy"})
	if err != nil {
		t.Fatal(err)
	}
	rec := &recordingTransport{getACL: daclOnly}
	if err := ProveAuditBypass(rec, transport.Ref{Path: "/tree"}); !errors.Is(err, ErrAuditNotRetained) {
		t.Fatalf("ProveAuditBypass() error = %v, want ErrAuditNotRetained", err)
	}
}

// TestProveAuditBypassPropagatesCleanupFailure matches ProbePreflight's own
// contract: a failed probe cleanup is folded into the returned error.
func TestProveAuditBypassPropagatesCleanupFailure(t *testing.T) {
	orig, err := nfs4acl.ParseACLSpec([]string{"A::OWNER@:rwaDxtTnNcCoy"})
	if err != nil {
		t.Fatal(err)
	}
	cleanupErr := errors.New("remove /probe-target: boom")
	rec := &recordingTransport{getACL: orig, echoACLOnGet: true, cleanupErr: cleanupErr}
	gotErr := ProveAuditBypass(rec, transport.Ref{Path: "/tree"})
	if gotErr == nil || !strings.Contains(gotErr.Error(), cleanupErr.Error()) {
		t.Fatalf("ProveAuditBypass() error = %v, want it to mention the cleanup failure %v", gotErr, cleanupErr)
	}
}

func TestDryRunTouchesNothing(t *testing.T) {
	rec := &recordingTransport{}
	s := &spec.Spec{Protocol: "posix", Default: spec.RulePerms{Mode: "750"}}
	r := ProcessPath(rec, transport.Ref{Path: "/x/y"}, true, s, Options{DryRun: true}, 0o700)
	if !r.Applied {
		t.Fatal("dry run should still report Applied so counts match a real run")
	}
	if len(rec.chmodCalls) != 0 {
		t.Fatal("dry run called Chmod on the transport")
	}
}

// TestProbePreflightHonorsTheProbeIsADirectory is finding C of the Task 2
// review. ProbePreflight used to hardcode isDir=false, which is right for the
// kernel transport's temp file and wrong for the userspace transport, whose
// probe target IS the export root. Applying a spec's file rules to a real
// directory writes the wrong ACL to it, and nothing reverts that write.
func TestProbePreflightHonorsTheProbeIsADirectory(t *testing.T) {
	dirACL := []string{"A:fd:GROUP@:rwaDxtTnNcCy"}
	s := &spec.Spec{
		Protocol: "nfsv4",
		Default:  spec.RulePerms{ACL: []string{"A::OWNER@:rwatTnNcCy"}},
		Rules: []spec.Rule{
			{Match: spec.RuleMatch{Type: "directory"}, RulePerms: spec.RulePerms{ACL: dirACL}},
		},
	}

	wantDir, err := nfs4acl.ParseACLSpec(dirACL)
	if err != nil {
		t.Fatal(err)
	}
	wantFile, err := nfs4acl.ParseACLSpec(s.Default.ACL)
	if err != nil {
		t.Fatal(err)
	}

	orig := plainACL

	// A directory probe, as the userspace transport reports.
	rec := &recordingTransport{probeIsDir: true, getACL: orig}
	if err := ProbePreflight(rec, transport.Ref{Path: "/tree"}, s); err != nil {
		t.Fatalf("ProbePreflight: %v", err)
	}
	if len(rec.setACLCalls) != 2 {
		t.Fatalf("SetACL called %d times, want 2 (the directory rule's write, then the restore)", len(rec.setACLCalls))
	}
	if bytes.Equal(rec.setACLCalls[0].acl, wantFile) {
		t.Error("applied the file rule to a directory probe; isDir was not threaded through")
	}
	if !bytes.Equal(rec.setACLCalls[0].acl, wantDir) {
		t.Error("directory probe did not receive the directory rule's ACL")
	}
	if !bytes.Equal(rec.setACLCalls[1].acl, orig) {
		t.Errorf("restore write = %q, want the target's original ACL %q back", rec.setACLCalls[1].acl, orig)
	}

	// A file probe, as the kernel transport reports.
	recFile := &recordingTransport{probeIsDir: false, getACL: orig}
	if err := ProbePreflight(recFile, transport.Ref{Path: "/tree"}, s); err != nil {
		t.Fatalf("ProbePreflight: %v", err)
	}
	if !bytes.Equal(recFile.setACLCalls[0].acl, wantFile) {
		t.Error("file probe did not receive the default (file) rule's ACL")
	}
	if !bytes.Equal(recFile.setACLCalls[1].acl, orig) {
		t.Errorf("restore write = %q, want the target's original ACL %q back", recFile.setACLCalls[1].acl, orig)
	}
}

// loadNFSv4Spec is loadSpec with protocol: nfsv4 prepended, for the sacl:
// preflight tests below, which all need a spec that went through validate()
// so saclACEs is actually populated (a struct literal never calls it).
// plainACL is a well-formed ACL with no audit ACEs: what a DACL reset that
// keeps auditing must be able to read before it writes.
var plainACL = nfs4acl.Encode([]nfs4acl.ACE{{Type: nfs4acl.TypeAllow, Who: "OWNER@", Mask: nfs4acl.MaskReadData}})

func loadNFSv4Spec(t *testing.T, body string) *spec.Spec {
	t.Helper()
	return loadSpec(t, "protocol: nfsv4\n"+body)
}

// TestProbePreflightEPERMGivesAuditPrivilege covers a spec-DACL rule (acl:
// with sacl: together): the ordinary apply write carries the SACL already, so
// a write refusal on that single SetACL must come back as ErrAuditPrivilege,
// not the generic preflight error.
func TestProbePreflightEPERMGivesAuditPrivilege(t *testing.T) {
	s := loadNFSv4Spec(t, `
default:
  acl:
    - "A::OWNER@:rwaDxtTnNcCoy"
  sacl:
    - "U:SF:EVERYONE@:rwaD"
`)
	orig := plainACL
	rec := &recordingTransport{getACL: orig, setACLErr: fmt.Errorf("setxattr /probe-target: %w", unix.EPERM)}
	err := ProbePreflight(rec, transport.Ref{Path: "/tree"}, s)
	if !errors.Is(err, ErrAuditPrivilege) {
		t.Fatalf("ProbePreflight error = %v, want ErrAuditPrivilege", err)
	}
}

// TestProbePreflightRestoresAfterAuditPrivilegeFailure is the coordinator's
// fix: a probe write that fails is still a write that was issued (the server
// may have state about the attempt even if it refused it), and more
// importantly a later write in the same probe may have already landed before
// this one was attempted. The restore must still run and still put back the
// probe target's original ACL -- verified here with a transport that fails
// only the SECOND SetACL (the audit-ACE fallback write), after the first
// (ordinary DACL) write already landed for real.
func TestProbePreflightRestoresAfterAuditPrivilegeFailure(t *testing.T) {
	s := loadNFSv4Spec(t, `
default:
  acl:
    - "A::OWNER@:rwaDxtTnNcCoy"
  sacl: []
rules:
  - match: {type: directory}
    acl:
      - "A:fd:OWNER@:rwaDxtTnNcCoy"
    sacl:
      - "U:fdSF:EVERYONE@:rwaD"
`)
	orig, err := nfs4acl.ParseACLSpec([]string{"A::OWNER@:rwaDxtTnNcCoy"})
	if err != nil {
		t.Fatal(err)
	}
	rec := &recordingTransport{getACL: orig, failSetACLOnAttempt: 2, setACLErr: fmt.Errorf("setxattr /probe-target: %w", unix.EACCES)}
	gotErr := ProbePreflight(rec, transport.Ref{Path: "/tree"}, s)
	if !errors.Is(gotErr, ErrAuditPrivilege) {
		t.Fatalf("ProbePreflight error = %v, want ErrAuditPrivilege", gotErr)
	}
	if len(rec.setACLCalls) != 2 {
		t.Fatalf("SetACL recorded %d calls, want 2 (the ordinary DACL write, then the restore) -- the audit probe write that failed is not recorded by this fake", len(rec.setACLCalls))
	}
	if !bytes.Equal(rec.setACLCalls[1].acl, orig) {
		t.Errorf("restore write = %q, want the probe target's original ACL %q back even after the audit probe write was refused", rec.setACLCalls[1].acl, orig)
	}
}

// TestProbePreflightRestoresAfterAuditNotRetained is the same requirement for
// the other sentinel: the array accepted the probe write (so it is real, on
// userspace, on a live object) and the preflight still has to put the
// original ACL back even though it is reporting ErrAuditNotRetained.
func TestProbePreflightRestoresAfterAuditNotRetained(t *testing.T) {
	s := loadNFSv4Spec(t, `
default:
  acl:
    - "A::OWNER@:rwaDxtTnNcCoy"
  sacl:
    - "U:SF:EVERYONE@:rwaD"
`)
	daclOnly, err := nfs4acl.ParseACLSpec([]string{"A::OWNER@:rwaDxtTnNcCoy"})
	if err != nil {
		t.Fatal(err)
	}
	rec := &recordingTransport{getACL: daclOnly}
	gotErr := ProbePreflight(rec, transport.Ref{Path: "/tree"}, s)
	if !errors.Is(gotErr, ErrAuditNotRetained) {
		t.Fatalf("ProbePreflight error = %v, want ErrAuditNotRetained", gotErr)
	}
	if len(rec.setACLCalls) != 2 {
		t.Fatalf("SetACL called %d times, want 2 (the ordinary write, then the restore)", len(rec.setACLCalls))
	}
	if !bytes.Equal(rec.setACLCalls[1].acl, daclOnly) {
		t.Errorf("restore write = %q, want the probe target's original ACL %q back", rec.setACLCalls[1].acl, daclOnly)
	}
}

// TestProbePreflightOrigReadErrorWritesNothing is the other half of the
// coordinator's fix: if the target's current ACL cannot even be read, nothing
// is known about what to restore, so nothing is written at all -- not the
// ordinary spec write, not any audit probe write.
func TestProbePreflightOrigReadErrorWritesNothing(t *testing.T) {
	s := loadNFSv4Spec(t, `
default:
  acl:
    - "A::OWNER@:rwaDxtTnNcCoy"
  sacl:
    - "U:SF:EVERYONE@:rwaD"
`)
	rec := &recordingTransport{getACLErr: errors.New("getxattr: boom")}
	err := ProbePreflight(rec, transport.Ref{Path: "/tree"}, s)
	if err == nil {
		t.Fatal("ProbePreflight: want an error when the target's current ACL cannot be read")
	}
	if len(rec.setACLCalls) != 0 {
		t.Fatalf("SetACL called %d times, want 0 -- a failed read of the target's current ACL must leave it untouched", len(rec.setACLCalls))
	}
}

// TestProbePreflightNoAllowDenyEntriesRefuses is the DACL-keeping/fallback
// case where the target's current ACL has no ALLOW/DENY entries at all (an
// all-audit ACL, or a decode failure's worth of nothing useful): there is
// nothing safe to keep, and writing a SACL-only ACL would strip all access
// from a real object. The preflight must refuse rather than do that, and must
// not have written anything first.
func TestProbePreflightNoAllowDenyEntriesRefuses(t *testing.T) {
	s := loadNFSv4Spec(t, `
default:
  sacl:
    - "U:SF:EVERYONE@:rwaD"
`)
	auditOnly := nfs4acl.Encode([]nfs4acl.ACE{{Type: nfs4acl.TypeAudit, Who: "EVERYONE@", Mask: nfs4acl.MaskReadData, Flags: nfs4acl.FlagSuccessAccess}})
	rec := &recordingTransport{getACL: auditOnly}
	err := ProbePreflight(rec, transport.Ref{Path: "/tree"}, s)
	if err == nil {
		t.Fatal("ProbePreflight: want an error when the probe target has no ALLOW/DENY entries to keep")
	}
	if errors.Is(err, ErrAuditPrivilege) || errors.Is(err, ErrAuditNotRetained) {
		t.Fatalf("ProbePreflight error = %v, want a plain refusal, not one of the audit sentinels", err)
	}
	if len(rec.setACLCalls) != 0 {
		t.Fatalf("SetACL called %d times, want 0 -- refusing to write a SACL-only ACL means never calling SetACL at all", len(rec.setACLCalls))
	}
}

// TestProbePreflightAccessDeniedUserspaceGivesAuditPrivilege is the same
// check against the userspace transport's error shape: an *nfs41.StatusError
// carrying NFS4ERR_ACCESS, not an EACCES/EPERM errno.
func TestProbePreflightAccessDeniedUserspaceGivesAuditPrivilege(t *testing.T) {
	s := loadNFSv4Spec(t, `
default:
  acl:
    - "A::OWNER@:rwaDxtTnNcCoy"
  sacl:
    - "U:SF:EVERYONE@:rwaD"
`)
	rec := &recordingTransport{setACLErr: &fakeStatusError{status: uint32(xdr.NFS4ERR_ACCESS)}}
	err := ProbePreflight(rec, transport.Ref{Path: "/tree"}, s)
	if !errors.Is(err, ErrAuditPrivilege) {
		t.Fatalf("ProbePreflight error = %v, want ErrAuditPrivilege", err)
	}
}

// TestProbePreflightReadBackWithoutUGivesAuditNotRetained covers the array
// accepting the write and then handing back an ACL with no U entries: the
// array dropped the audit ACEs rather than keeping them.
func TestProbePreflightReadBackWithoutUGivesAuditNotRetained(t *testing.T) {
	s := loadNFSv4Spec(t, `
default:
  acl:
    - "A::OWNER@:rwaDxtTnNcCoy"
  sacl:
    - "U:SF:EVERYONE@:rwaD"
`)
	daclOnly, err := nfs4acl.ParseACLSpec([]string{"A::OWNER@:rwaDxtTnNcCoy"})
	if err != nil {
		t.Fatal(err)
	}
	rec := &recordingTransport{getACL: daclOnly}
	if err := ProbePreflight(rec, transport.Ref{Path: "/tree"}, s); !errors.Is(err, ErrAuditNotRetained) {
		t.Fatalf("ProbePreflight error = %v, want ErrAuditNotRetained", err)
	}
}

// TestProbePreflightDirectoryOnlySaclStillWritesU is the DACL-keeping and
// "sacl: only on directory rules" case from plan v3 commit 2: the probe
// target (a file, as the kernel transport reports) matches a rule with no
// sacl: of its own, but the spec's directory rule carries one. The preflight
// must still issue a second write carrying a U entry, or the privilege is
// never actually proven.
func TestProbePreflightDirectoryOnlySaclStillWritesU(t *testing.T) {
	s := loadNFSv4Spec(t, `
default:
  acl:
    - "A::OWNER@:rwaDxtTnNcCoy"
  sacl: []
rules:
  - match: {type: directory}
    acl:
      - "A:fd:OWNER@:rwaDxtTnNcCoy"
    sacl:
      - "U:fdSF:EVERYONE@:rwaD"
`)
	orig, err := nfs4acl.ParseACLSpec([]string{"A::OWNER@:rwaDxtTnNcCoy"})
	if err != nil {
		t.Fatal(err)
	}
	rec := &recordingTransport{probeIsDir: false, getACL: orig, echoACLOnGet: true}
	if err := ProbePreflight(rec, transport.Ref{Path: "/tree"}, s); err != nil {
		t.Fatalf("ProbePreflight: %v", err)
	}
	if len(rec.setACLCalls) != 3 {
		t.Fatalf("SetACL called %d times, want 3 (the ordinary DACL write, the audit probe write, then the restore)", len(rec.setACLCalls))
	}
	aces, err := nfs4acl.DecodeACL(rec.setACLCalls[1].acl)
	if err != nil {
		t.Fatal(err)
	}
	if !hasAuditACE(aces) {
		t.Fatal("the second write did not carry a U entry; the audit-ACE privilege was never actually probed")
	}
	for _, a := range aces {
		if a.Type == nfs4acl.TypeAudit && a.Flags&(nfs4acl.FlagFileInherit|nfs4acl.FlagDirInherit|nfs4acl.FlagInheritOnly) != 0 {
			t.Errorf("probe U entry kept an inheritance flag (0x%x); the directory rule's sacl: must be stripped to file shape", a.Flags)
		}
	}
	if !bytes.Equal(rec.setACLCalls[2].acl, orig) {
		t.Errorf("restore write = %q, want the probe target's original ACL %q back", rec.setACLCalls[2].acl, orig)
	}
}

// TestProbePreflightKeepDACLStillWritesU is the DACL-keeping rule itself
// (sacl: with no acl:): ProcessPath has nothing to apply yet (plan v3 commit
// 4), so without the separate probe write here the privilege would never be
// checked at all.
func TestProbePreflightKeepDACLStillWritesU(t *testing.T) {
	s := loadNFSv4Spec(t, `
default:
  sacl:
    - "U:SF:EVERYONE@:rwaD"
`)
	orig, err := nfs4acl.ParseACLSpec([]string{"A::OWNER@:rwaDxtTnNcCoy"})
	if err != nil {
		t.Fatal(err)
	}
	rec := &recordingTransport{getACL: orig, echoACLOnGet: true}
	if err := ProbePreflight(rec, transport.Ref{Path: "/tree"}, s); err != nil {
		t.Fatalf("ProbePreflight: %v", err)
	}
	if len(rec.setACLCalls) != 2 {
		t.Fatalf("SetACL called %d times, want 2 (ProcessPath skips a DACL-keeping rule; the audit probe write, then the restore)", len(rec.setACLCalls))
	}
	aces, err := nfs4acl.DecodeACL(rec.setACLCalls[0].acl)
	if err != nil {
		t.Fatal(err)
	}
	if !hasAuditACE(aces) {
		t.Fatal("the probe write did not carry a U entry")
	}
	if !bytes.Equal(rec.setACLCalls[1].acl, orig) {
		t.Errorf("restore write = %q, want the probe target's original ACL %q back", rec.setACLCalls[1].acl, orig)
	}
}

// TestProbePreflightEmptySaclOnlyStillWritesU: a spec whose only sacl: key is
// sacl: [] still reads every object and still needs the bypass, so the probe
// writes a placeholder U entry rather than returning with nothing proven.
func TestProbePreflightEmptySaclOnlyStillWritesU(t *testing.T) {
	s := loadNFSv4Spec(t, `
default:
  sacl: []
`)
	orig, err := nfs4acl.ParseACLSpec([]string{"A::OWNER@:rwaDxtTnNcCoy"})
	if err != nil {
		t.Fatal(err)
	}
	rec := &recordingTransport{getACL: orig, echoACLOnGet: true}
	if err := ProbePreflight(rec, transport.Ref{Path: "/tree"}, s); err != nil {
		t.Fatalf("ProbePreflight: %v", err)
	}
	if len(rec.setACLCalls) != 3 {
		t.Fatalf("SetACL called %d times, want 3 (the DACL-keeping write, the audit probe write, then the restore)", len(rec.setACLCalls))
	}
	aces, err := nfs4acl.DecodeACL(rec.setACLCalls[1].acl)
	if err != nil {
		t.Fatal(err)
	}
	if !hasAuditACE(aces) {
		t.Fatal("the probe write did not carry a U entry; the bypass was never probed")
	}
	if !bytes.Equal(rec.setACLCalls[2].acl, orig) {
		t.Errorf("restore write = %q, want the probe target's original ACL %q back", rec.setACLCalls[2].acl, orig)
	}
}

// TestProbePreflightNoSaclUnaffected pins the no-sacl: case: a spec with no
// sacl: anywhere must not trigger any audit-specific second write. It still
// gets the universal restore (commit 2's fix for the coordinator-flagged
// userspace mutation): the ordinary spec write, then the target's original
// ACL put back.
func TestProbePreflightNoSaclUnaffected(t *testing.T) {
	orig := plainACL
	rec := &recordingTransport{getACL: orig}
	s := &spec.Spec{
		Protocol: "nfsv4",
		Default:  spec.RulePerms{ACL: []string{"A::OWNER@:rwatTnNcCy"}},
	}
	if err := ProbePreflight(rec, transport.Ref{Path: "/tree"}, s); err != nil {
		t.Fatalf("ProbePreflight: %v", err)
	}
	if len(rec.setACLCalls) != 2 {
		t.Fatalf("SetACL called %d times, want 2 — a spec with no sacl: must not trigger the audit probe, but still gets the ordinary write and its restore", len(rec.setACLCalls))
	}
	if !bytes.Equal(rec.setACLCalls[1].acl, orig) {
		t.Errorf("restore write = %q, want the target's original ACL %q back", rec.setACLCalls[1].acl, orig)
	}
}

// keepDACLSpec is a DACL-keeping spec (sacl: with no acl:): the default rule
// replaces only the object's audit ACEs and leaves whatever ALLOW/DENY entries
// it already has.
const keepDACLSpec = "protocol: nfsv4\ndefault:\n  sacl:\n    - \"U:SF:EVERYONE@:rwaD\"\n"

// TestApplyKeepDACLPreservesDACLByteForByte is plan v3 commit 4's core
// requirement: the object's own ALLOW/DENY entries, including a who field FA
// renders oddly (a numeric principal, GROUP@ with no g flag), come back in the
// write exactly as read.
func TestApplyKeepDACLPreservesDACLByteForByte(t *testing.T) {
	s := loadNFSv4Spec(t, "default:\n  sacl:\n    - \"U:SF:EVERYONE@:rwaD\"\n")

	current := nfs4acl.Encode([]nfs4acl.ACE{
		{Type: nfs4acl.TypeDeny, Who: "9999", Mask: nfs4acl.MaskWriteData},
		{Type: nfs4acl.TypeAllow, Who: "1402", Mask: nfs4acl.MaskReadData | nfs4acl.MaskExecute},
		{Type: nfs4acl.TypeAllow, Who: "GROUP@", Mask: nfs4acl.MaskReadData}, // no g flag, as FA returns it
	})
	rec := &recordingTransport{getACL: current}

	r := ProcessPath(rec, transport.Ref{Path: "/f"}, false, s, Options{DryRun: false}, 0)
	if r.Error != nil {
		t.Fatalf("ProcessPath: %v", r.Error)
	}
	if !r.Applied {
		t.Fatal("Applied = false, want true")
	}
	if len(rec.setACLCalls) != 1 {
		t.Fatalf("SetACL called %d times, want 1", len(rec.setACLCalls))
	}

	daclRaw, daclCount, _, err := nfs4acl.SplitACL(rec.setACLCalls[0].acl)
	if err != nil {
		t.Fatalf("SplitACL(written ACL): %v", err)
	}
	if daclCount != 3 {
		t.Fatalf("written ACL has %d DACL entries, want 3", daclCount)
	}
	wantDaclRaw, _, _, err := nfs4acl.SplitACL(current)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(daclRaw, wantDaclRaw) {
		t.Fatalf("written DACL region = %x, want the object's original DACL bytes %x unchanged", daclRaw, wantDaclRaw)
	}

	aces, err := nfs4acl.DecodeACL(rec.setACLCalls[0].acl)
	if err != nil {
		t.Fatal(err)
	}
	if len(aces) != 4 {
		t.Fatalf("written ACL has %d ACEs, want 4 (3 kept DACL + 1 new SACL)", len(aces))
	}
	last := aces[3]
	if last.Type != nfs4acl.TypeAudit || last.Who != "EVERYONE@" {
		t.Errorf("last ACE = %+v, want the rule's sacl: entry at the tail", last)
	}
}

// TestApplyKeepDACLReplacesStaleAuditEntries covers the object already
// carrying audit ACEs that do not match the spec: they are dropped, wherever
// they were (interleaved, not just at the tail), and replaced with the rule's
// own sacl:.
func TestApplyKeepDACLReplacesStaleAuditEntries(t *testing.T) {
	s := loadNFSv4Spec(t, "default:\n  sacl:\n    - \"U:SF:EVERYONE@:rwaD\"\n")

	current := nfs4acl.Encode([]nfs4acl.ACE{
		{Type: nfs4acl.TypeAudit, Who: "STALEPRINCIPAL@", Flags: nfs4acl.FlagFailedAccess, Mask: nfs4acl.MaskWriteData},
		{Type: nfs4acl.TypeAllow, Who: "OWNER@", Mask: nfs4acl.MaskReadData},
		{Type: nfs4acl.TypeAlarm, Who: "STALEPRINCIPAL@", Flags: nfs4acl.FlagFailedAccess, Mask: nfs4acl.MaskWriteData},
	})
	rec := &recordingTransport{getACL: current}

	r := ProcessPath(rec, transport.Ref{Path: "/f"}, false, s, Options{DryRun: false}, 0)
	if r.Error != nil {
		t.Fatalf("ProcessPath: %v", r.Error)
	}
	aces, err := nfs4acl.DecodeACL(rec.setACLCalls[0].acl)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range aces {
		if a.Who == "STALEPRINCIPAL@" {
			t.Fatalf("stale audit/alarm entry survived in the write: %+v", aces)
		}
	}
	var gotU int
	for _, a := range aces {
		if a.Type == nfs4acl.TypeAudit {
			gotU++
			if a.Who != "EVERYONE@" {
				t.Errorf("U entry who = %q, want EVERYONE@ (the spec's own)", a.Who)
			}
		}
	}
	if gotU != 1 {
		t.Fatalf("write has %d U entries, want exactly 1 (the spec's, replacing the stale one)", gotU)
	}
}

// TestApplyKeepDACLRefusesWithNoAllowDenyEntries is the zero-A/D-entries case:
// writing a SACL-only ACL would strip all access from the object, so the
// object must be failed with a clear error and no SetACL ever issued.
func TestApplyKeepDACLRefusesWithNoAllowDenyEntries(t *testing.T) {
	s := loadSpec(t, keepDACLSpec)
	auditOnly := nfs4acl.Encode([]nfs4acl.ACE{{Type: nfs4acl.TypeAudit, Who: "EVERYONE@", Flags: nfs4acl.FlagSuccessAccess, Mask: nfs4acl.MaskReadData}})
	rec := &recordingTransport{getACL: auditOnly}

	r := ProcessPath(rec, transport.Ref{Path: "/f"}, false, s, Options{DryRun: false}, 0)
	if r.Error == nil {
		t.Fatal("ProcessPath: want an error when the object has no ALLOW/DENY entries to keep")
	}
	if !errors.Is(r.Error, ErrNoDACLToKeep) {
		t.Errorf("ProcessPath error = %v, want it to wrap ErrNoDACLToKeep", r.Error)
	}
	if len(rec.setACLCalls) != 0 {
		t.Fatalf("SetACL called %d times, want 0 -- refusing must not write anything", len(rec.setACLCalls))
	}
}

// TestApplyKeepDACLGetACLErrorMakesNoWrite covers the read side: a failed
// GetACL leaves nothing known about the object's current DACL, so the object
// is failed and SetACL is never called.
func TestApplyKeepDACLGetACLErrorMakesNoWrite(t *testing.T) {
	s := loadSpec(t, keepDACLSpec)
	rec := &recordingTransport{getACLErr: errors.New("getxattr: boom")}

	r := ProcessPath(rec, transport.Ref{Path: "/f"}, false, s, Options{DryRun: false}, 0)
	if r.Error == nil {
		t.Fatal("ProcessPath: want an error when GetACL fails")
	}
	if len(rec.setACLCalls) != 0 {
		t.Fatalf("SetACL called %d times, want 0 -- a failed read must leave the object untouched", len(rec.setACLCalls))
	}
}

// TestApplyKeepDACLUsesCachedACLInsteadOfGetACL proves a caller that already
// read the object's ACL (run.go's batch pre-fetch for KeepDACL entries) can
// hand it to ProcessPath via Options.CachedACL and applyKeepDACL will use it
// instead of calling t.GetACL -- the whole point of the pre-fetch is to turn
// N per-object GETATTRs into a handful of batched ones, which only works if
// the per-object apply does not then issue its own read anyway.
func TestApplyKeepDACLUsesCachedACLInsteadOfGetACL(t *testing.T) {
	s := loadSpec(t, keepDACLSpec)
	cached := nfs4acl.Encode([]nfs4acl.ACE{
		{Type: nfs4acl.TypeAllow, Who: "OWNER@", Mask: nfs4acl.MaskReadData},
	})
	// rec.getACL is left unset (nil) -- if applyKeepDACL ever calls t.GetACL
	// despite the cache, it would see a current ACL with zero DACL entries and
	// fail with ErrNoDACLToKeep, which is how this test would notice.
	rec := &recordingTransport{}

	r := ProcessPath(rec, transport.Ref{Path: "/f"}, false, s, Options{DryRun: false, CachedACL: cached}, 0)
	if r.Error != nil {
		t.Fatalf("ProcessPath: %v, want success using the cached ACL", r.Error)
	}
	if rec.getACLCalls != 0 {
		t.Fatalf("GetACL called %d times, want 0 -- CachedACL should make the per-object read unnecessary", rec.getACLCalls)
	}
	if len(rec.setACLCalls) != 1 {
		t.Fatalf("SetACL called %d times, want 1", len(rec.setACLCalls))
	}
	daclRaw, daclCount, _, err := nfs4acl.SplitACL(rec.setACLCalls[0].acl)
	if err != nil {
		t.Fatal(err)
	}
	if daclCount != 1 {
		t.Fatalf("written ACL has %d DACL entries, want 1 (from the cached ACL, not rec.getACL)", daclCount)
	}
	wantDaclRaw, _, _, err := nfs4acl.SplitACL(cached)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(daclRaw, wantDaclRaw) {
		t.Fatalf("written DACL = %x, want the cached ACL's DACL %x", daclRaw, wantDaclRaw)
	}
}

// TestApplyKeepDACLFallsBackToGetACLWhenCacheAbsent proves the ordinary
// per-object read still runs when Options.CachedACL is nil (the zero value) --
// a caller that could not batch-read this object (GetACLBatch failed, or the
// object was never a batch candidate) must still get a correct apply, never a
// skipped read.
func TestApplyKeepDACLFallsBackToGetACLWhenCacheAbsent(t *testing.T) {
	s := loadSpec(t, keepDACLSpec)
	current := nfs4acl.Encode([]nfs4acl.ACE{
		{Type: nfs4acl.TypeAllow, Who: "OWNER@", Mask: nfs4acl.MaskReadData},
	})
	rec := &recordingTransport{getACL: current}

	r := ProcessPath(rec, transport.Ref{Path: "/f"}, false, s, Options{DryRun: false}, 0)
	if r.Error != nil {
		t.Fatalf("ProcessPath: %v", r.Error)
	}
	if rec.getACLCalls != 1 {
		t.Fatalf("GetACL called %d times, want 1 -- no cache means the real read must still happen", rec.getACLCalls)
	}
}

// TestApplyKeepDACLCompareSkipsSecondRun proves --compare makes the second run
// against an already-converged object a no-op: the first run's own write,
// read back, must compare equal and skip.
func TestApplyKeepDACLCompareSkipsSecondRun(t *testing.T) {
	s := loadSpec(t, keepDACLSpec)
	current := nfs4acl.Encode([]nfs4acl.ACE{{Type: nfs4acl.TypeAllow, Who: "OWNER@", Mask: nfs4acl.MaskReadData}})
	rec := &recordingTransport{getACL: current, echoACLOnGet: true}

	r1 := ProcessPath(rec, transport.Ref{Path: "/f"}, false, s, Options{DryRun: false, Compare: true}, 0)
	if r1.Error != nil {
		t.Fatalf("first ProcessPath: %v", r1.Error)
	}
	if !r1.Applied {
		t.Fatal("first run: Applied = false, want true (object had no matching SACL yet)")
	}
	if len(rec.setACLCalls) != 1 {
		t.Fatalf("after first run, SetACL called %d times, want 1", len(rec.setACLCalls))
	}

	r2 := ProcessPath(rec, transport.Ref{Path: "/f"}, false, s, Options{DryRun: false, Compare: true}, 0)
	if r2.Error != nil {
		t.Fatalf("second ProcessPath: %v", r2.Error)
	}
	if !r2.Skipped {
		t.Fatal("second run: Skipped = false, want true -- the object already matches")
	}
	if len(rec.setACLCalls) != 1 {
		t.Fatalf("after second run, SetACL called %d times, want still 1 (no second write)", len(rec.setACLCalls))
	}
}

// TestApplyKeepDACLDryRunMakesNoWrite proves --dry-run neither reads nor
// writes (review item 7: a read without the audit bypass empties inheriting
// SACLs before Purity//FA 6.12.1, and a dry run has no preflight).
func TestApplyKeepDACLDryRunMakesNoWrite(t *testing.T) {
	s := loadSpec(t, keepDACLSpec)
	current := nfs4acl.Encode([]nfs4acl.ACE{{Type: nfs4acl.TypeAllow, Who: "OWNER@", Mask: nfs4acl.MaskReadData}})
	rec := &recordingTransport{getACL: current}

	r := ProcessPath(rec, transport.Ref{Path: "/f"}, false, s, Options{DryRun: true}, 0)
	if r.Error != nil {
		t.Fatalf("ProcessPath: %v", r.Error)
	}
	if !r.Applied {
		t.Fatal("dry run should still report Applied so counts match a real run")
	}
	if len(rec.setACLCalls) != 0 {
		t.Fatalf("SetACL called %d times, want 0 -- dry run must never write", len(rec.setACLCalls))
	}
	if rec.getACLCalls != 0 {
		t.Fatalf("GetACL called %d times, want 0 -- dry run must not read without a proven bypass", rec.getACLCalls)
	}
}

// TestApplyKeepDACLAppliesToDirectoriesToo proves the dispatch is the same for
// a directory: applyNFSv4 branches on perms.KeepDACL(), not on isDir, so a
// directory-shaped rule (carrying fd on its sacl:) goes through the same
// read-split-join-write path. This is the directory design from plan v3
// commit 4 step 3: KeepDACL directories need no special walk/run-level
// handling because ProcessPath itself is isDir-agnostic here, and run.go's
// DirACL already returns nil for a KeepDACL rule (its acl: is always empty),
// so the fused readdir+SETATTR path never fires for one and every KeepDACL
// directory flows through ProcessPath exactly like a file, exactly once.
func TestApplyKeepDACLAppliesToDirectoriesToo(t *testing.T) {
	s := loadNFSv4Spec(t, `
default:
  sacl: []
rules:
  - match: {type: directory}
    sacl:
      - "U:fdSF:EVERYONE@:rwaD"
`)
	current := nfs4acl.Encode([]nfs4acl.ACE{{Type: nfs4acl.TypeAllow, Flags: nfs4acl.FlagDirInherit, Who: "OWNER@", Mask: nfs4acl.MaskReadData}})
	rec := &recordingTransport{getACL: current}

	r := ProcessPath(rec, transport.Ref{Path: "/dir"}, true, s, Options{DryRun: false}, 0)
	if r.Error != nil {
		t.Fatalf("ProcessPath(isDir=true): %v", r.Error)
	}
	if len(rec.setACLCalls) != 1 {
		t.Fatalf("SetACL called %d times, want 1", len(rec.setACLCalls))
	}
	aces, err := nfs4acl.DecodeACL(rec.setACLCalls[0].acl)
	if err != nil {
		t.Fatal(err)
	}
	if len(aces) != 2 || aces[0].Who != "OWNER@" || aces[1].Who != "EVERYONE@" || aces[1].Flags&nfs4acl.FlagDirInherit == 0 {
		t.Fatalf("written ACEs = %+v, want the kept OWNER@ allow then the directory rule's fd-flagged U entry", aces)
	}
}

// TestValidateKeepDACLComparesOnlySacl proves --validate for a DACL-keeping
// rule checks only the SACL tail: a DACL that would never match any spec (the
// rule defines none) must not be reported as a mismatch, and a SACL that does
// match must report Matches.
func TestValidateKeepDACLComparesOnlySacl(t *testing.T) {
	s := loadNFSv4Spec(t, "default:\n  sacl:\n    - \"U:SF:EVERYONE@:rwaD\"\n")
	current := nfs4acl.Encode([]nfs4acl.ACE{
		{Type: nfs4acl.TypeDeny, Who: "9999", Mask: nfs4acl.MaskWriteData},
		{Type: nfs4acl.TypeAllow, Who: "OWNER@", Mask: nfs4acl.MaskReadData},
		{Type: nfs4acl.TypeAudit, Who: "EVERYONE@", Flags: nfs4acl.FlagSuccessAccess | nfs4acl.FlagFailedAccess,
			Mask: nfs4acl.MaskReadData | nfs4acl.MaskWriteData | nfs4acl.MaskAppendData | nfs4acl.MaskDeleteChild},
	})
	rec := &recordingTransport{getACL: current}

	res := ValidatePath(rec, transport.Ref{Path: "/f"}, false, s, 0, nil, nil)
	if res.Error != nil {
		t.Fatalf("ValidatePath: %v", res.Error)
	}
	if !res.Matches {
		t.Fatalf("Matches = false, want true (SACL matches, DACL is irrelevant): %s", res.Detail)
	}
}

// TestValidateKeepDACLMismatchReportsSaclOnly is the other half: a SACL that
// does not match the spec must be reported, with a message about the sacl,
// not about the DACL the spec never defined.
func TestValidateKeepDACLMismatchReportsSaclOnly(t *testing.T) {
	s := loadNFSv4Spec(t, "default:\n  sacl:\n    - \"U:SF:EVERYONE@:rwaD\"\n")
	current := nfs4acl.Encode([]nfs4acl.ACE{
		{Type: nfs4acl.TypeAllow, Who: "OWNER@", Mask: nfs4acl.MaskReadData},
		{Type: nfs4acl.TypeAudit, Who: "SOMEONEELSE@", Flags: nfs4acl.FlagSuccessAccess, Mask: nfs4acl.MaskReadData},
	})
	rec := &recordingTransport{getACL: current}

	res := ValidatePath(rec, transport.Ref{Path: "/f"}, false, s, 0, nil, nil)
	if res.Error != nil {
		t.Fatalf("ValidatePath: %v", res.Error)
	}
	if res.Matches {
		t.Fatal("Matches = true, want false (the SACL does not match the spec)")
	}
	if !strings.Contains(res.Detail, "sacl") {
		t.Errorf("Detail = %q, want it to mention the sacl mismatch", res.Detail)
	}
}

// TestApplyPosixSurfacesAStatError is finding D of the Task 2 review: the
// unknown-cachedMode fallback stats through the transport, and a swallowed error
// there would leave current at zero, chmod to the spec mode regardless, and
// report success. That is the same class as finding 4 of the Task 1 review.
func TestApplyPosixSurfacesAStatError(t *testing.T) {
	rec := &recordingTransport{statErr: errors.New("boom")}
	s := &spec.Spec{Protocol: "posix", Default: spec.RulePerms{Mode: "750"}}

	// cachedMode 0 means "unknown", which is what Prepass emits for every file,
	// so this is the common path rather than an edge case.
	r := ProcessPath(rec, transport.Ref{Path: "/x/y"}, false, s, Options{DryRun: false}, 0)
	if r.Error == nil {
		t.Fatal("a Stat failure was swallowed; want an error")
	}
	if len(rec.chmodCalls) != 0 {
		t.Errorf("chmod ran despite an unreadable current mode: %+v", rec.chmodCalls)
	}
	if r.Applied {
		t.Error("Applied = true after a failed Stat")
	}
	// Finding B: the transport already wraps with "lstat <path>", so the message
	// must not be doubled.
	if got := r.Error.Error(); strings.Count(got, "lstat") > 1 {
		t.Errorf("error message wraps lstat more than once: %q", got)
	}
}

func TestCheckTraversePreservedPosix(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		wantErr bool
	}{
		{"owner execute", "2775", false},
		{"no execute", "0660", true},
		{"no owner execute", "0670", true},
		{"all execute", "0775", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &spec.Spec{
				Protocol: "posix",
				Default:  spec.RulePerms{Mode: tt.mode},
			}
			err := CheckTraversePreserved(s)
			if (err != nil) != tt.wantErr {
				t.Errorf("mode=%s: err=%v, wantErr=%v", tt.mode, err, tt.wantErr)
			}
		})
	}
}

// Issue #11: the default is the fallback for anything a rule doesn't match,
// files included. It may only be judged as a directory mode when a directory
// can actually reach it under first-match-wins.
func TestCheckTraversePreservedDefaultReachability(t *testing.T) {
	dirRule := func(pattern, mode string) spec.Rule {
		return spec.Rule{
			Match:     spec.RuleMatch{Type: "directory", Pattern: pattern},
			RulePerms: spec.RulePerms{Mode: mode},
		}
	}
	tests := []struct {
		name    string
		s       *spec.Spec
		wantErr bool
	}{
		{
			// natural.yaml from the issue: files 0644 by default, every
			// directory covered by an unconditional rule. No directory ever
			// reads the default — must be accepted.
			"unconditional dir rule shadows file default",
			&spec.Spec{Protocol: "posix",
				Default: spec.RulePerms{Mode: "0644"},
				Rules:   []spec.Rule{dirRule("", "0755")}},
			false,
		},
		{
			// Patterned rule covers only logs*; every other directory falls
			// through to the 0644 default and locks the walk out — refuse.
			"patterned dir rule leaves default reachable",
			&spec.Spec{Protocol: "posix",
				Default: spec.RulePerms{Mode: "0644"},
				Rules:   []spec.Rule{dirRule("logs*", "0755")}},
			true,
		},
		{
			// A directory-capable rule after an unconditional directory rule is
			// just as unreachable as the default — must be accepted.
			"rule after unconditional dir rule is unreachable",
			&spec.Spec{Protocol: "posix",
				Default: spec.RulePerms{Mode: "0755"},
				Rules: []spec.Rule{
					dirRule("", "0755"),
					{Match: spec.RuleMatch{}, RulePerms: spec.RulePerms{Mode: "0644"}},
				}},
			false,
		},
		{
			// The unconditional rule itself still has to be traversable.
			"unconditional dir rule with bad mode still refused",
			&spec.Spec{Protocol: "posix",
				Default: spec.RulePerms{Mode: "0644"},
				Rules:   []spec.Rule{dirRule("", "0660")}},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckTraversePreserved(tt.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("err=%v, wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestCheckTraversePreservedNFSv4(t *testing.T) {
	tests := []struct {
		name    string
		acl     []string
		wantErr bool
	}{
		{
			"owner has execute",
			[]string{"A::OWNER@:rwaDxtTnNcCoy"},
			false,
		},
		{
			"deny execute no allow",
			[]string{"D::OWNER@:x"},
			true,
		},
		{
			"no execute granted at all",
			[]string{"A::OWNER@:rwaTtcCo"},
			true,
		},
		{
			"deny then allow",
			[]string{"D::OWNER@:x", "A::EVERYONE@:rxtcy"},
			false,
		},
		{
			"inherit-only deny is harmless",
			[]string{"D:i:OWNER@:x", "A::OWNER@:rwaDxtTnNcCoy"},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &spec.Spec{
				Protocol: "nfsv4",
				Default:  spec.RulePerms{ACL: tt.acl},
			}
			err := CheckTraversePreserved(s)
			if (err != nil) != tt.wantErr {
				t.Errorf("acl=%v: err=%v, wantErr=%v", tt.acl, err, tt.wantErr)
			}
		})
	}
}

func TestChmodBeforeChownOrdering(t *testing.T) {
	rec := &recordingTransport{attr: transport.Attr{Mode: 0600}}
	s := loadSpec(t, `
protocol: posix
default:
  mode: "0755"
  owner: "0"
  group: "0"
`)
	ref := transport.Ref{Path: "/ordering-test"}
	r := ProcessPath(rec, ref, false, s, Options{SetOwner: true}, 0)
	if r.Error != nil {
		t.Fatal(r.Error)
	}
	if len(rec.opOrder) < 2 {
		t.Fatalf("expected at least 2 ops, got %d: %v", len(rec.opOrder), rec.opOrder)
	}
	if rec.opOrder[0] != "chmod" || rec.opOrder[1] != "chown" {
		t.Errorf("operation order = %v, want [chmod chown]; chown after chmod clears setuid/setgid — a known limitation when --set-owner is combined with setuid modes", rec.opOrder)
	}
}

func TestSetuidBitApplied(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "setuid-test")
	os.WriteFile(f, []byte("x"), 0600)

	s := loadSpec(t, `
protocol: posix
default:
  mode: "4755"
`)
	r := ProcessPath(kernelTransport(t), transport.Ref{Path: f}, false, s, Options{}, 0)
	if r.Error != nil {
		t.Fatal(r.Error)
	}
	info, err := os.Stat(f)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSetuid == 0 {
		t.Errorf("mode = %v, want setuid bit set", info.Mode())
	}
	if info.Mode().Perm() != 0755 {
		t.Errorf("perm bits = 0%o, want 0755", info.Mode().Perm())
	}
}

func TestSetgidBitOnDirectory(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "setgid-dir")
	os.Mkdir(sub, 0700)

	s := loadSpec(t, `
protocol: posix
default:
  mode: "2755"
`)
	r := ProcessPath(kernelTransport(t), transport.Ref{Path: sub}, true, s, Options{}, 0)
	if r.Error != nil {
		t.Fatal(r.Error)
	}
	info, err := os.Stat(sub)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSetgid == 0 {
		t.Errorf("mode = %v, want setgid bit set", info.Mode())
	}
	if info.Mode().Perm() != 0755 {
		t.Errorf("perm bits = 0%o, want 0755", info.Mode().Perm())
	}
}

// A named owner needs a local directory; a numeric one never does, and
// Client.Chown sends decimal owner strings as the NFSv4 numeric-owner fallback.
// The error has to say so, because on a machine with no directory behind
// getpwnam the fix is to change the spec, not to fix the machine.
func TestResolveOwnerGroupErrorPointsAtNumericIDs(t *testing.T) {
	_, _, err := resolveOwnerGroup("definitely-not-a-real-user-9f3a2b", "")
	if err == nil {
		t.Fatal("resolveOwnerGroup resolved a name that cannot exist")
	}
	if !strings.Contains(err.Error(), "numeric") {
		t.Fatalf("error = %q, want it to mention numeric ids", err)
	}
}

func TestResolveOwnerGroupAcceptsNumericIDsWithNoLookup(t *testing.T) {
	uid, gid, err := resolveOwnerGroup("10010", "10000")
	if err != nil {
		t.Fatalf("resolveOwnerGroup: %v", err)
	}
	if uid != 10010 || gid != 10000 {
		t.Fatalf("uid, gid = %d, %d; want 10010, 10000", uid, gid)
	}
}

// faUnmappedDACL is the shape FA 6.10.6 returned for writeback-probe.txt in
// benchmarks/sacl-unmapped-sid-20261020: a group deny and a user allow on two
// different SIDs with no RFC 2307 id, both rendered as 65534, beside mapped
// uids. Writing these bytes back replaced both SIDs with FA's local nobody.
func faUnmappedDACL() []byte {
	return nfs4acl.Encode([]nfs4acl.ACE{
		{Type: nfs4acl.TypeDeny, Who: "65534", Mask: nfs4acl.MaskDeleteChild},
		{Type: nfs4acl.TypeAllow, Who: "65534", Mask: nfs4acl.MaskReadData | nfs4acl.MaskWriteData},
		{Type: nfs4acl.TypeAllow, Who: "1445", Mask: nfs4acl.MaskReadData},
		{Type: nfs4acl.TypeAllow, Who: "1402", Mask: nfs4acl.MaskReadData | nfs4acl.MaskWriteData},
	})
}

// TestApplyKeepDACLRefusesUnmappedPrincipal: a DACL carrying the nobody
// sentinel is never written back, and the error names it.
func TestApplyKeepDACLRefusesUnmappedPrincipal(t *testing.T) {
	s := loadSpec(t, keepDACLSpec)
	rec := &recordingTransport{getACL: faUnmappedDACL()}

	r := ProcessPath(rec, transport.Ref{Path: "/f"}, false, s, Options{DryRun: false}, 0)
	if !errors.Is(r.Error, ErrUnmappedPrincipal) {
		t.Fatalf("ProcessPath error = %v, want ErrUnmappedPrincipal", r.Error)
	}
	if !strings.Contains(r.Error.Error(), "65534") {
		t.Errorf("error %q does not name the unmapped who", r.Error)
	}
	if len(rec.setACLCalls) != 0 {
		t.Fatalf("SetACL called %d times, want 0", len(rec.setACLCalls))
	}
}

// TestApplyKeepDACLRefusesUnmappedEvenWhenConverged: an object that already
// carries the spec's SACL is still reported, not skipped, under --compare, so
// a rerun over a tree an older build already damaged says so.
func TestApplyKeepDACLRefusesUnmappedEvenWhenConverged(t *testing.T) {
	s := loadSpec(t, keepDACLSpec)
	dacl, _, _, err := nfs4acl.SplitACL(faUnmappedDACL())
	if err != nil {
		t.Fatal(err)
	}
	rec := &recordingTransport{getACL: nfs4acl.JoinACL(dacl, s.Default.SaclACEs())}

	r := ProcessPath(rec, transport.Ref{Path: "/f"}, false, s, Options{Compare: true}, 0)
	if !errors.Is(r.Error, ErrUnmappedPrincipal) {
		t.Fatalf("ProcessPath error = %v, want ErrUnmappedPrincipal", r.Error)
	}
	if len(rec.setACLCalls) != 0 {
		t.Fatalf("SetACL called %d times, want 0", len(rec.setACLCalls))
	}
}

// TestApplyKeepDACLRefusesNamedNobody covers the name form an array with
// idmapd configured returns for the same identity.
func TestApplyKeepDACLRefusesNamedNobody(t *testing.T) {
	s := loadSpec(t, keepDACLSpec)
	rec := &recordingTransport{getACL: nfs4acl.Encode([]nfs4acl.ACE{
		{Type: nfs4acl.TypeAllow, Who: "OWNER@", Mask: nfs4acl.MaskReadData},
		{Type: nfs4acl.TypeAllow, Who: "nobody@example.net", Mask: nfs4acl.MaskReadData},
	})}
	r := ProcessPath(rec, transport.Ref{Path: "/f"}, false, s, Options{}, 0)
	if !errors.Is(r.Error, ErrUnmappedPrincipal) || len(rec.setACLCalls) != 0 {
		t.Fatalf("error = %v, SetACL calls = %d; want ErrUnmappedPrincipal and no write", r.Error, len(rec.setACLCalls))
	}
}

// TestProbePreflightRefusesUnmappedBeforeAnyWrite: both the probe write and
// the restore would send the unmapped DACL back, so neither may happen.
func TestProbePreflightRefusesUnmappedBeforeAnyWrite(t *testing.T) {
	s := loadSpec(t, keepDACLSpec)
	rec := &recordingTransport{getACL: faUnmappedDACL()}

	err := ProbePreflight(rec, transport.Ref{Path: "/tree"}, s)
	if !errors.Is(err, ErrUnmappedPrincipal) {
		t.Fatalf("ProbePreflight error = %v, want ErrUnmappedPrincipal", err)
	}
	if len(rec.setACLCalls) != 0 {
		t.Fatalf("SetACL called %d times, want 0 (no probe write, no restore)", len(rec.setACLCalls))
	}
}

// TestProbePreflightUnmappedIgnoredForSpecDACL: an acl: rule replaces the
// DACL with the spec's, so the object's current unmapped entries are not
// written back and the guard does not apply.
func TestProbePreflightUnmappedIgnoredForSpecDACL(t *testing.T) {
	s := loadNFSv4Spec(t, "default:\n  acl:\n    - \"A::OWNER@:rwaDxtTnNcCoy\"\n")
	rec := &recordingTransport{getACL: faUnmappedDACL()}
	if err := ProbePreflight(rec, transport.Ref{Path: "/tree"}, s); errors.Is(err, ErrUnmappedPrincipal) {
		t.Fatalf("ProbePreflight error = %v; the unmapped guard must only apply to DACL-keeping rules", err)
	}
}

func TestCheckKeepDACLTarget(t *testing.T) {
	if err := CheckKeepDACLTarget(&recordingTransport{getACL: faUnmappedDACL()}, transport.Ref{Path: "/tree"}); !errors.Is(err, ErrUnmappedPrincipal) {
		t.Fatalf("unmapped root: error = %v, want ErrUnmappedPrincipal", err)
	}
	mapped := nfs4acl.Encode([]nfs4acl.ACE{{Type: nfs4acl.TypeAllow, Who: "1445", Mask: nfs4acl.MaskReadData}})
	if err := CheckKeepDACLTarget(&recordingTransport{getACL: mapped}, transport.Ref{Path: "/tree"}); err != nil {
		t.Fatalf("mapped root: error = %v, want nil", err)
	}
}

// TestApplyKeepDACLRefusesSyntheticRangePrincipal is #52's shape on FB 4.8.0:
// a real uidNumber >= 1e9 and BUILTIN\Administrators' synthetic id.
func TestApplyKeepDACLRefusesSyntheticRangePrincipal(t *testing.T) {
	s := loadSpec(t, keepDACLSpec)
	rec := &recordingTransport{getACL: nfs4acl.Encode([]nfs4acl.ACE{
		{Type: nfs4acl.TypeAllow, Who: "1402", Mask: nfs4acl.MaskReadData},
		{Type: nfs4acl.TypeAllow, Who: "2000000003", Mask: nfs4acl.MaskReadData},
		{Type: nfs4acl.TypeAllow, Flags: nfs4acl.FlagGroup, Who: "1000000544", Mask: nfs4acl.MaskReadData},
	})}
	r := ProcessPath(rec, transport.Ref{Path: "/f"}, false, s, Options{}, 0)
	if !errors.Is(r.Error, ErrSyntheticRangePrincipal) {
		t.Fatalf("error = %v, want ErrSyntheticRangePrincipal", r.Error)
	}
	if !strings.Contains(r.Error.Error(), "2000000003") || !strings.Contains(r.Error.Error(), "1000000544") {
		t.Errorf("error %q does not name both ids", r.Error)
	}
	if len(rec.setACLCalls) != 0 {
		t.Fatalf("SetACL called %d times, want 0", len(rec.setACLCalls))
	}
}

// TestApplyKeepDACLAllowsIdsBelowSyntheticFloor: fb-mapped2's ids survived.
func TestApplyKeepDACLAllowsIdsBelowSyntheticFloor(t *testing.T) {
	s := loadSpec(t, keepDACLSpec)
	rec := &recordingTransport{getACL: nfs4acl.Encode([]nfs4acl.ACE{
		{Type: nfs4acl.TypeAllow, Who: "1000003", Mask: nfs4acl.MaskReadData},
		{Type: nfs4acl.TypeAllow, Flags: nfs4acl.FlagGroup, Who: "9224117", Mask: nfs4acl.MaskReadData},
		{Type: nfs4acl.TypeAllow, Who: "999999999", Mask: nfs4acl.MaskReadData},
	})}
	r := ProcessPath(rec, transport.Ref{Path: "/f"}, false, s, Options{}, 0)
	if r.Error != nil || len(rec.setACLCalls) != 1 {
		t.Fatalf("error = %v, SetACL calls = %d; want a write", r.Error, len(rec.setACLCalls))
	}
}

// TestApplyKeepDACLRefusesNamedHighID: after one NFS write FB shows a
// principal as name@domain, so the id floor must apply to what the name
// resolves to (fb-mapped1: sacl-map1@example.net is uid 2000000003).
func TestApplyKeepDACLRefusesNamedHighID(t *testing.T) {
	old := highIDLookup
	t.Cleanup(func() { highIDLookup = old })
	highIDLookup = func(who string, isGroup bool) (string, bool) {
		switch who {
		case "sacl-map1@example.net":
			return "2000000003", true
		case "jdoe@example.net":
			return "1402", true
		}
		return "", false
	}
	s := loadSpec(t, keepDACLSpec)
	rec := &recordingTransport{getACL: nfs4acl.Encode([]nfs4acl.ACE{
		{Type: nfs4acl.TypeAllow, Who: "jdoe@example.net", Mask: nfs4acl.MaskReadData},
		{Type: nfs4acl.TypeAllow, Who: "sacl-map1@example.net", Mask: nfs4acl.MaskReadData},
		{Type: nfs4acl.TypeAllow, Who: "OWNER@", Mask: nfs4acl.MaskReadData},
	})}
	r := ProcessPath(rec, transport.Ref{Path: "/f"}, false, s, Options{}, 0)
	if !errors.Is(r.Error, ErrSyntheticRangePrincipal) || !strings.Contains(r.Error.Error(), "sacl-map1@example.net=2000000003") {
		t.Fatalf("error = %v, want ErrSyntheticRangePrincipal naming sacl-map1@example.net=2000000003", r.Error)
	}
	if len(rec.setACLCalls) != 0 {
		t.Fatalf("SetACL called %d times, want 0", len(rec.setACLCalls))
	}
}

// mapResolver resolves the who strings in its table to each other, both ways.
type mapResolver map[string]string

func (m mapResolver) Forms(who string, _ bool) []string {
	if other, ok := m[who]; ok {
		return []string{who, other}
	}
	for k, v := range m {
		if v == who {
			return []string{who, k}
		}
	}
	return []string{who}
}

// FlashBlade returns a spec's numeric id as name@domain. The mismatch report
// must skip that ACE and name the one that really differs, or it sends the
// operator after an identity that is correct (#50 RC regression).
func TestDescribeACLMismatchSkipsOtherFormOfSameIdentity(t *testing.T) {
	want := nfs4acl.Encode([]nfs4acl.ACE{
		{Type: nfs4acl.TypeAllow, Mask: 0x1f01ff, Who: "1402"},
		{Type: nfs4acl.TypeAllow, Mask: 0x1200a9, Who: "1000003"},
	})
	got := nfs4acl.Encode([]nfs4acl.ACE{
		{Type: nfs4acl.TypeAllow, Mask: 0x1f01ff, Who: "jdoe@example.net"},
		{Type: nfs4acl.TypeAllow, Mask: 0x1200a9, Who: "juser@example.net"},
	})
	r := mapResolver{"1402": "jdoe@example.net", "1000003": "sacl-map2@example.net"}
	d := describeACLMismatch(got, want, r)
	if !strings.Contains(d, `ACE 1: who "juser@example.net", want "1000003"`) {
		t.Errorf("describeACLMismatch = %q, want it to name ACE 1", d)
	}
}

// TestDryRunCompareDoesNotReadTheObject: a dry run has no audit-bypass proof,
// and an unproven read can empty inherited auditing (PS-02), so --compare on a
// dry run must not read the object before its blind write would be decided.
func TestDryRunCompareDoesNotReadTheObject(t *testing.T) {
	s := loadSpec(t, "protocol: nfsv4\ndefault:\n  acl:\n    - \"A::OWNER@:rwaDxtTnNcCoy\"\n  sacl:\n    - \"U:SF:EVERYONE@:rwaD\"\n")
	rt := &recordingTransport{}
	r := ProcessPath(rt, transport.Ref{Path: "/tree/f"}, false, s, Options{DryRun: true, Compare: true}, 0644)
	if r.Error != nil {
		t.Fatalf("ProcessPath error = %v", r.Error)
	}
	if rt.getACLCalls != 0 || len(rt.setACLCalls) != 0 {
		t.Fatalf("dry run with --compare: %d GetACL, %d SetACL calls, want 0 and 0", rt.getACLCalls, len(rt.setACLCalls))
	}
}
