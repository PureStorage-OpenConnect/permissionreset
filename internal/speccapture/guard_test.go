package speccapture_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/auditproof"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs4acl"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/speccapture"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// captureUnproven is the tests' Capture for behavior that does not depend on
// the read-safety guard: it accepts the unproven read explicitly.
func captureUnproven(r speccapture.Reader, dir, file transport.Ref) (*speccapture.Result, error) {
	return speccapture.CaptureWithOptions(r, dir, file, speccapture.Options{AcceptUnprovenRead: true})
}

// proberReader is a fakeReader that can also create a disposable probe, and
// records every ACL call in order.
type proberReader struct {
	*fakeReader
	calls     []string
	probeErr  error
	setErr    error
	dropAudit bool
	probeACL  []byte
}

func (p *proberReader) ProbeTarget(dir transport.Ref) (transport.Ref, bool, func() error, error) {
	p.calls = append(p.calls, "ProbeTarget:"+dir.Path)
	if p.probeErr != nil {
		return transport.Ref{}, false, nil, p.probeErr
	}
	p.probeACL = nfs4acl.Encode([]nfs4acl.ACE{{Type: nfs4acl.TypeAllow, Who: "OWNER@", Mask: nfs4acl.MaskReadData}})
	return transport.Ref{Path: dir.Path + "/.probe"}, false, func() error {
		p.calls = append(p.calls, "cleanup")
		return nil
	}, nil
}

func (p *proberReader) GetACL(ref transport.Ref) ([]byte, error) {
	p.calls = append(p.calls, "GetACL:"+ref.Path)
	if strings.HasSuffix(ref.Path, "/.probe") {
		return p.probeACL, nil
	}
	return p.fakeReader.GetACL(ref)
}

func (p *proberReader) SetACL(ref transport.Ref, acl []byte) error {
	p.calls = append(p.calls, "SetACL:"+ref.Path)
	if p.setErr != nil {
		return p.setErr
	}
	if p.dropAudit {
		dacl, _, _, _ := nfs4acl.SplitACL(acl)
		acl = dacl
	}
	p.probeACL = acl
	return nil
}

var _ auditproof.Prober = (*proberReader)(nil)

func newProber(t *testing.T) (*proberReader, transport.Ref, transport.Ref) {
	r, dir, file := simpleReader(goldenDirACEs, goldenFileACEs, t)
	r.attrs["/vol/scratch"] = transport.Attr{Kind: transport.KindDirectory, IsDir: true}
	return &proberReader{fakeReader: r}, dir, file
}

// exemplarReads counts GetACL calls on the two exemplars.
func exemplarReads(calls []string) int {
	n := 0
	for _, c := range calls {
		if c == "GetACL:/vol/dir" || c == "GetACL:/vol/file.txt" {
			n++
		}
	}
	return n
}

// TestCaptureRefusesAnUnprovenReadByDefault: with neither a probe directory
// nor an explicit acceptance, capture reads no exemplar ACL at all.
func TestCaptureRefusesAnUnprovenReadByDefault(t *testing.T) {
	p, dir, file := newProber(t)
	_, err := speccapture.CaptureWithOptions(p, dir, file, speccapture.Options{})
	if !errors.Is(err, speccapture.ErrUnprovenRead) {
		t.Fatalf("err = %v, want ErrUnprovenRead", err)
	}
	if exemplarReads(p.calls) != 0 || len(p.calls) != 0 {
		t.Fatalf("calls = %v, want none", p.calls)
	}
	if _, err := speccapture.Capture(p, dir, file); !errors.Is(err, speccapture.ErrUnprovenRead) {
		t.Fatalf("Capture err = %v, want ErrUnprovenRead", err)
	}
}

// TestCaptureProvesTheBypassBeforeReadingExemplars pins the order: probe
// created, written, read back and removed before either exemplar is read.
func TestCaptureProvesTheBypassBeforeReadingExemplars(t *testing.T) {
	p, dir, file := newProber(t)
	onProof := func(pr auditproof.Proof) { p.calls = append(p.calls, "OnProof:"+pr.Probe) }
	res, err := speccapture.CaptureWithOptions(p, dir, file, speccapture.Options{ProbeDir: "/vol/scratch", OnProof: onProof})
	if err != nil {
		t.Fatalf("err = %v; calls = %v", err, p.calls)
	}
	cleanupIdx, proofIdx, firstRead := -1, -1, -1
	for i, c := range p.calls {
		if c == "cleanup" && cleanupIdx == -1 {
			cleanupIdx = i
		}
		if c == "OnProof:/vol/scratch/.probe" && proofIdx == -1 {
			proofIdx = i
		}
		if (c == "GetACL:/vol/dir" || c == "GetACL:/vol/file.txt") && firstRead == -1 {
			firstRead = i
		}
	}
	if p.calls[0] != "ProbeTarget:/vol/scratch" || cleanupIdx == -1 || firstRead < cleanupIdx {
		t.Fatalf("exemplar read before the proof finished; calls = %v", p.calls)
	}
	// #31: the proof is reported after the probe is gone and before either
	// exemplar is read, so the caller's output shows the order.
	if proofIdx == -1 || proofIdx < cleanupIdx || proofIdx > firstRead {
		t.Fatalf("OnProof not called between the probe cleanup and the first exemplar read; calls = %v", p.calls)
	}
	for _, n := range res.Notes {
		if strings.Contains(n, "no audit-bypass proof") {
			t.Errorf("proven capture carries the unproven-read note: %q", n)
		}
	}
}

// TestCaptureFailsClosedWhenTheProofFails: a refused, failed or unretained
// probe stops the capture before any exemplar read.
func TestCaptureFailsClosedWhenTheProofFails(t *testing.T) {
	cases := []struct {
		name string
		set  func(*proberReader)
		want error
	}{
		{"probe create fails", func(p *proberReader) { p.probeErr = errors.New("create denied") }, nil},
		{"audit write refused", func(p *proberReader) { p.setErr = &nfsErr{} }, auditproof.ErrAuditPrivilege},
		{"audit not retained", func(p *proberReader) { p.dropAudit = true }, auditproof.ErrAuditNotRetained},
	}
	for _, c := range cases {
		p, dir, file := newProber(t)
		c.set(p)
		_, err := speccapture.CaptureWithOptions(p, dir, file, speccapture.Options{ProbeDir: "/vol/scratch", AcceptUnprovenRead: true})
		if err == nil {
			t.Fatalf("%s: err = nil, want a refusal", c.name)
		}
		if c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
		if exemplarReads(p.calls) != 0 {
			t.Errorf("%s: exemplars read after a failed proof; calls = %v", c.name, p.calls)
		}
	}
}

// nfsErr is an NFS4ERR_ACCESS status, as the userspace client returns it.
type nfsErr struct{}

func (*nfsErr) Error() string     { return "NFS4ERR_ACCESS" }
func (*nfsErr) NFSStatus() uint32 { return 13 }

// TestCaptureProbeDirNeedsAProber: a reader that cannot create a probe is an
// error, not a silent unproven read.
func TestCaptureProbeDirNeedsAProber(t *testing.T) {
	r, dir, file := simpleReader(goldenDirACEs, goldenFileACEs, t)
	if _, err := speccapture.CaptureWithOptions(r, dir, file, speccapture.Options{ProbeDir: "/vol/scratch"}); err == nil {
		t.Fatal("err = nil, want a refusal")
	}
}

// TestCaptureAcceptedUnprovenReadSaysSo: the operator who accepts the risk
// gets a note naming it, first among the notes.
func TestCaptureAcceptedUnprovenReadSaysSo(t *testing.T) {
	r, dir, file := simpleReader(goldenDirACEs, goldenFileACEs, t)
	res, err := captureUnproven(r, dir, file)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Notes) == 0 || !strings.Contains(res.Notes[0], "no audit-bypass proof") {
		t.Fatalf("notes = %q, want the unproven-read note first", res.Notes)
	}
}
