package speccapture_test

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs4acl"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/speccapture"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// fakeVerifier is a scripted ReplayVerifier for testing Verify logic without
// any real filesystem or network. Each SetACL/GetACL can be injected per call
// ordinal or per-path.
type fakeVerifier struct {
	// setACLReturns maps probe path to error to return from SetACL.
	setACLReturns map[string]error

	// getACLReturns maps probe path to (raw ACL, error) to return from GetACL.
	// When the path is absent, GetACL returns whatever was last set via SetACL.
	getACLReturns map[string]getACLResult

	// stored tracks the last ACL written to each path.
	stored map[string][]byte

	// removeErr maps probe name to error for Remove.
	removeErr map[string]error

	// createDirErr / createFileErr inject creation failures.
	createDirErr  error
	createFileErr error

	// created tracks probe names for cleanup assertions.
	created []string
	removed []string
}

type getACLResult struct {
	raw []byte
	err error
}

func newFakeVerifier() *fakeVerifier {
	return &fakeVerifier{
		setACLReturns: map[string]error{},
		getACLReturns: map[string]getACLResult{},
		stored:        map[string][]byte{},
		removeErr:     map[string]error{},
	}
}

func (f *fakeVerifier) CreateProbeDirectory(parent transport.Ref, name string) (transport.Ref, error) {
	if f.createDirErr != nil {
		return transport.Ref{}, f.createDirErr
	}
	ref := transport.Ref{Path: parent.Path + "/" + name}
	f.created = append(f.created, name)
	return ref, nil
}

func (f *fakeVerifier) CreateProbeFile(parent transport.Ref, name string) (transport.Ref, error) {
	if f.createFileErr != nil {
		return transport.Ref{}, f.createFileErr
	}
	ref := transport.Ref{Path: parent.Path + "/" + name}
	f.created = append(f.created, name)
	return ref, nil
}

func (f *fakeVerifier) SetACL(ref transport.Ref, acl []byte) error {
	if err, ok := f.setACLReturns[ref.Path]; ok {
		return err
	}
	f.stored[ref.Path] = append([]byte(nil), acl...)
	return nil
}

func (f *fakeVerifier) GetACL(ref transport.Ref) ([]byte, error) {
	if r, ok := f.getACLReturns[ref.Path]; ok {
		return r.raw, r.err
	}
	raw, ok := f.stored[ref.Path]
	if !ok {
		return nil, fmt.Errorf("no ACL stored for %q", ref.Path)
	}
	return append([]byte(nil), raw...), nil
}

func (f *fakeVerifier) Remove(parent transport.Ref, name string) error {
	f.removed = append(f.removed, name)
	if err, ok := f.removeErr[name]; ok {
		return err
	}
	return nil
}

// ---------- helpers ----------------------------------------------------------

func captureResult(t *testing.T, dirACEs, fileACEs []string) *speccapture.Result {
	t.Helper()
	r, dir, file := simpleReader(dirACEs, fileACEs, t)
	res, err := captureUnproven(r, dir, file)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	return res
}

var (
	scratch      = transport.Ref{Path: "/scratch"}
	dirExemplar  = transport.Ref{Path: "/vol/dir"}
	fileExemplar = transport.Ref{Path: "/vol/file.txt"}
)

// ---------- success: stable first pass ---------------------------------------

func TestVerifyStableFirstPass(t *testing.T) {
	in := captureResult(t, goldenDirACEs, goldenFileACEs)
	fv := newFakeVerifier()

	out, err := speccapture.Verify(fv, scratch, dirExemplar, fileExemplar, in)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !out.Identity.Verified {
		t.Error("Verified should be true after successful verification")
	}
	if len(out.DirACEs) != len(in.DirACEs) {
		t.Errorf("DirACEs count = %d, want %d", len(out.DirACEs), len(in.DirACEs))
	}
	if len(out.FileACEs) != len(in.FileACEs) {
		t.Errorf("FileACEs count = %d, want %d", len(out.FileACEs), len(in.FileACEs))
	}
	if len(out.YAML) == 0 {
		t.Error("YAML is empty")
	}
	// Cleanup ran.
	if len(fv.removed) != 2 {
		t.Errorf("removed %d probes, want 2", len(fv.removed))
	}
}

// ---------- canonicalized first readback, then stable second -----------------

func TestVerifyCanonicalizedReadback(t *testing.T) {
	dirACEs := []string{"A:fd:alice@EXAMPLE.COM:rwaDxtTcCoy"}
	fileACEs := []string{"A::alice@EXAMPLE.COM:rwaTcCoy"}
	in := captureResult(t, dirACEs, fileACEs)
	fv := newFakeVerifier()

	// Simulate server canonicalizing alice@EXAMPLE.COM → alice@example.com on
	// first readback. The domain change means ACLEqual returns false,
	// triggering the rebuild path.
	canonDirACEs := []string{"A:fd:alice@example.com:rwaDxtTcCoy"}
	canonFileACEs := []string{"A::alice@example.com:rwaTcCoy"}
	canonDirRaw := mustEncode(t, canonDirACEs)
	canonFileRaw := mustEncode(t, canonFileACEs)

	// Override GetACL: first call for each probe returns the canonicalized form.
	// The fakeVerifier stores whatever SetACL writes, so the second SetACL
	// writes the canonical raw, and the second GetACL returns that same stored
	// value — structurally identical to the first readback.
	//
	// We intercept by path prefix: after CreateProbeDirectory/File the paths
	// will be /scratch/.build-spec-probe-*-dir and -file. We can't know the
	// exact names, so we use a custom fakeVerifier that overrides the first
	// GetACL per object.

	// Use a wrapping verifier that intercepts the first GetACL per probe.
	wrapper := &canonicalizingVerifier{
		inner:       fv,
		canonDir:    canonDirRaw,
		canonFile:   canonFileRaw,
		getACLCalls: map[string]int{},
	}

	out, err := speccapture.Verify(wrapper, scratch, dirExemplar, fileExemplar, in)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !out.Identity.Verified {
		t.Error("Verified should be true")
	}
	// Output should use the canonical (lowercased) form.
	for _, ace := range out.DirACEs {
		if strings.Contains(ace, "EXAMPLE.COM") {
			t.Errorf("DirACE %q still has uppercase domain", ace)
		}
	}
	for _, ace := range out.FileACEs {
		if strings.Contains(ace, "EXAMPLE.COM") {
			t.Errorf("FileACE %q still has uppercase domain", ace)
		}
	}
}

// canonicalizingVerifier wraps a fakeVerifier and returns a canonicalized ACL
// on the first GetACL call for each probe, then delegates to the inner
// verifier for subsequent calls.
type canonicalizingVerifier struct {
	inner         *fakeVerifier
	canonDir      []byte
	canonFile     []byte
	getACLCalls   map[string]int
	dirProbePath  string
	fileProbePath string
}

func (c *canonicalizingVerifier) CreateProbeDirectory(parent transport.Ref, name string) (transport.Ref, error) {
	ref, err := c.inner.CreateProbeDirectory(parent, name)
	if err == nil {
		c.dirProbePath = ref.Path
	}
	return ref, err
}

func (c *canonicalizingVerifier) CreateProbeFile(parent transport.Ref, name string) (transport.Ref, error) {
	ref, err := c.inner.CreateProbeFile(parent, name)
	if err == nil {
		c.fileProbePath = ref.Path
	}
	return ref, err
}

func (c *canonicalizingVerifier) SetACL(ref transport.Ref, acl []byte) error {
	return c.inner.SetACL(ref, acl)
}

func (c *canonicalizingVerifier) GetACL(ref transport.Ref) ([]byte, error) {
	c.getACLCalls[ref.Path]++
	if c.getACLCalls[ref.Path] == 1 {
		// First readback: return canonicalized form.
		if ref.Path == c.dirProbePath {
			return append([]byte(nil), c.canonDir...), nil
		}
		if ref.Path == c.fileProbePath {
			return append([]byte(nil), c.canonFile...), nil
		}
	}
	return c.inner.GetACL(ref)
}

func (c *canonicalizingVerifier) Remove(parent transport.Ref, name string) error {
	return c.inner.Remove(parent, name)
}

// ---------- continued normalization fails (not stable) -----------------------

func TestVerifyNotStableAfterTwoPasses(t *testing.T) {
	in := captureResult(t, goldenDirACEs, goldenFileACEs)

	// Build a verifier where GetACL returns a different value every time,
	// so the second readback never matches the first.
	fv := &unstableVerifier{
		fakeVerifier: newFakeVerifier(),
		callCount:    map[string]int{},
	}

	_, err := speccapture.Verify(fv, scratch, dirExemplar, fileExemplar, in)
	if err == nil {
		t.Fatal("expected error for unstable ACL, got nil")
	}
	if !strings.Contains(err.Error(), "not stable after two passes") {
		t.Errorf("error %q does not mention stability failure", err.Error())
	}
}

// unstableVerifier returns a different ACL on every GetACL call.
type unstableVerifier struct {
	*fakeVerifier
	callCount map[string]int
}

func (u *unstableVerifier) GetACL(ref transport.Ref) ([]byte, error) {
	u.callCount[ref.Path]++
	n := u.callCount[ref.Path]
	// Return different ACLs on successive calls by appending a unique ACE.
	base := []nfs4acl.ACE{
		{Type: nfs4acl.TypeAllow, Flags: 0, Mask: nfs4acl.MaskReadData, Who: "OWNER@"},
	}
	// Add n extra ACEs to make each readback structurally different.
	for i := 0; i < n; i++ {
		base = append(base, nfs4acl.ACE{
			Type: nfs4acl.TypeAllow, Flags: 0, Mask: nfs4acl.MaskReadData,
			Who: fmt.Sprintf("extra%d@example.com", i),
		})
	}
	return nfs4acl.Encode(base), nil
}

// ---------- SetACL rejection -------------------------------------------------

func TestVerifySetACLRejection(t *testing.T) {
	in := captureResult(t, goldenDirACEs, goldenFileACEs)
	fv := &setACLRejectVerifier{
		fakeVerifier: newFakeVerifier(),
		rejectCount:  0,
	}

	_, err := speccapture.Verify(fv, scratch, dirExemplar, fileExemplar, in)
	if err == nil {
		t.Fatal("expected error when SetACL is rejected, got nil")
	}
	// Error must name the exemplar type and include ACE list.
	if !strings.Contains(err.Error(), "directory") && !strings.Contains(err.Error(), "file") {
		t.Errorf("error %q does not identify the exemplar", err.Error())
	}
	if !strings.Contains(err.Error(), "NFSv4.1-only repair workflow") {
		t.Errorf("error %q does not explain the ACL is not reproducible", err.Error())
	}
	// Must include ACE strings.
	if !strings.Contains(err.Error(), "OWNER@") {
		t.Errorf("error %q does not include ACE list", err.Error())
	}
}

// TestVerifyAuditWriteRefusedNamesTheBypass: a probe write that carries the
// captured U ACEs and comes back EACCES is the missing audit bypass, and must
// say so instead of calling the ACL unreproducible.
func TestVerifyAuditWriteRefusedNamesTheBypass(t *testing.T) {
	in := captureResult(t, goldenDirACEs, goldenFileACEs)
	in.DirSACL = []string{"U:fdSF:EVERYONE@:r"}
	fv := &errnoRejectVerifier{fakeVerifier: newFakeVerifier(), err: syscall.EACCES}

	_, err := speccapture.Verify(fv, scratch, dirExemplar, fileExemplar, in)
	if !errors.Is(err, speccapture.ErrVerifyAuditPrivilege) {
		t.Fatalf("err = %v, want ErrVerifyAuditPrivilege", err)
	}
	if !strings.Contains(err.Error(), "directory exemplar") || strings.Contains(err.Error(), "NFSv4.1-only repair workflow") {
		t.Errorf("error %q should name the exemplar and not claim the ACL is unreproducible", err.Error())
	}
}

// TestVerifyAccessDeniedWithoutSACLStaysGeneric: EACCES on an exemplar with
// no audit ACEs says nothing about the bypass.
func TestVerifyAccessDeniedWithoutSACLStaysGeneric(t *testing.T) {
	in := captureResult(t, goldenDirACEs, goldenFileACEs)
	fv := &errnoRejectVerifier{fakeVerifier: newFakeVerifier(), err: syscall.EACCES}

	_, err := speccapture.Verify(fv, scratch, dirExemplar, fileExemplar, in)
	if err == nil || errors.Is(err, speccapture.ErrVerifyAuditPrivilege) {
		t.Fatalf("err = %v, want the generic SetACL error", err)
	}
}

type errnoRejectVerifier struct {
	*fakeVerifier
	err error
}

func (e *errnoRejectVerifier) SetACL(ref transport.Ref, acl []byte) error {
	return fmt.Errorf("setxattr %s: %w", ref.Path, e.err)
}

type setACLRejectVerifier struct {
	*fakeVerifier
	rejectCount int
}

func (s *setACLRejectVerifier) SetACL(ref transport.Ref, acl []byte) error {
	s.rejectCount++
	return errors.New("NFS4ERR_ATTRNOTSUPP: server rejected ACL")
}

// ---------- GetACL readback failure ------------------------------------------

func TestVerifyGetACLReadbackFailure(t *testing.T) {
	in := captureResult(t, goldenDirACEs, goldenFileACEs)
	fv := &getACLFailVerifier{
		fakeVerifier: newFakeVerifier(),
	}

	_, err := speccapture.Verify(fv, scratch, dirExemplar, fileExemplar, in)
	if err == nil {
		t.Fatal("expected error when GetACL fails, got nil")
	}
	if !strings.Contains(err.Error(), "readback") {
		t.Errorf("error %q does not mention readback", err.Error())
	}
}

type getACLFailVerifier struct {
	*fakeVerifier
}

func (g *getACLFailVerifier) SetACL(ref transport.Ref, acl []byte) error {
	return nil // SetACL succeeds
}

func (g *getACLFailVerifier) GetACL(ref transport.Ref) ([]byte, error) {
	return nil, errors.New("I/O error reading ACL")
}

// ---------- cleanup failure names paths --------------------------------------

func TestVerifyCleanupFailure(t *testing.T) {
	in := captureResult(t, goldenDirACEs, goldenFileACEs)
	fv := newFakeVerifier()

	// Make all Remove calls fail.
	fv.removeErr["*"] = errors.New("EBUSY")

	// We need a verifier that fails Remove for any name.
	wrapper := &removeFailVerifier{fakeVerifier: fv}

	_, err := speccapture.Verify(wrapper, scratch, dirExemplar, fileExemplar, in)
	if err == nil {
		t.Fatal("expected error when cleanup fails, got nil")
	}
	if !strings.Contains(err.Error(), "cleanup failed") {
		t.Errorf("error %q does not mention cleanup failure", err.Error())
	}
	if !strings.Contains(err.Error(), "remaining paths") {
		t.Errorf("error %q does not list remaining paths", err.Error())
	}
	// Paths should include the scratch directory prefix.
	if !strings.Contains(err.Error(), "/scratch/") {
		t.Errorf("error %q does not include scratch path", err.Error())
	}
}

type removeFailVerifier struct {
	*fakeVerifier
}

func (r *removeFailVerifier) Remove(parent transport.Ref, name string) error {
	r.fakeVerifier.removed = append(r.fakeVerifier.removed, name)
	return errors.New("EBUSY")
}

// ---------- cleanup runs on every created path (even after error) ------------

func TestVerifyCleanupRunsOnEveryPath(t *testing.T) {
	in := captureResult(t, goldenDirACEs, goldenFileACEs)
	fv := newFakeVerifier()

	// Verify succeeds — check that both probes are removed.
	_, err := speccapture.Verify(fv, scratch, dirExemplar, fileExemplar, in)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(fv.created) != 2 {
		t.Fatalf("created %d probes, want 2", len(fv.created))
	}
	if len(fv.removed) != 2 {
		t.Errorf("removed %d probes, want 2", len(fv.removed))
	}
	// The removed names should match the created names (order may differ).
	createdSet := map[string]bool{}
	for _, n := range fv.created {
		createdSet[n] = true
	}
	for _, n := range fv.removed {
		if !createdSet[n] {
			t.Errorf("removed probe %q was not in created set", n)
		}
	}
}

// ---------- scratch == exemplar refused --------------------------------------

func TestVerifyScratchEqualsDirExemplar(t *testing.T) {
	in := captureResult(t, goldenDirACEs, goldenFileACEs)
	fv := newFakeVerifier()

	same := transport.Ref{Path: "/vol/dir"}
	_, err := speccapture.Verify(fv, same, same, fileExemplar, in)
	if err == nil {
		t.Fatal("expected error when scratch == dir exemplar, got nil")
	}
	if !strings.Contains(err.Error(), "same as the directory exemplar") {
		t.Errorf("error %q does not identify the problem", err.Error())
	}
}

func TestVerifyScratchEqualsFileExemplar(t *testing.T) {
	in := captureResult(t, goldenDirACEs, goldenFileACEs)
	fv := newFakeVerifier()

	same := transport.Ref{Path: "/vol/file.txt"}
	_, err := speccapture.Verify(fv, same, dirExemplar, same, in)
	if err == nil {
		t.Fatal("expected error when scratch == file exemplar, got nil")
	}
	if !strings.Contains(err.Error(), "same as the file exemplar") {
		t.Errorf("error %q does not identify the problem", err.Error())
	}
}

// ---------- probes are unique siblings under scratch -------------------------

func TestVerifyProbesAreUniqueSiblings(t *testing.T) {
	in := captureResult(t, goldenDirACEs, goldenFileACEs)
	fv := newFakeVerifier()

	_, err := speccapture.Verify(fv, scratch, dirExemplar, fileExemplar, in)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(fv.created) != 2 {
		t.Fatalf("created %d probes, want 2", len(fv.created))
	}
	// Names must be different.
	if fv.created[0] == fv.created[1] {
		t.Error("both probes have the same name")
	}
	// Names must start with .build-spec-probe-.
	for _, name := range fv.created {
		if !strings.HasPrefix(name, ".build-spec-probe-") {
			t.Errorf("probe name %q does not start with expected prefix", name)
		}
	}
	// One should end with -dir and the other with -file.
	hasDirSuffix := strings.HasSuffix(fv.created[0], "-dir") || strings.HasSuffix(fv.created[1], "-dir")
	hasFileSuffix := strings.HasSuffix(fv.created[0], "-file") || strings.HasSuffix(fv.created[1], "-file")
	if !hasDirSuffix || !hasFileSuffix {
		t.Errorf("probe names %v missing -dir/-file suffixes", fv.created)
	}
}
