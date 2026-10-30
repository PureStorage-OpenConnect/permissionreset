package apply

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs4acl"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/spec"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// nobodyTransport stores what is written and, on read-back, shows every who in
// unmapped as 65534, the way Purity//FA renders a principal with no RFC 2307 id
// (#50, fa-reset-c4). merge drops the first entry of every write (one of the
// target's own, so the probe entries survive), standing in for an array that
// folds entries together.
type nobodyTransport struct {
	*recordingTransport
	unmapped map[string]bool
	merge    bool
	stored   []byte
}

func (n *nobodyTransport) SetACL(ref transport.Ref, acl []byte) error {
	if err := n.recordingTransport.SetACL(ref, acl); err != nil {
		return err
	}
	aces, err := nfs4acl.DecodeACL(acl)
	if err != nil {
		return err
	}
	for i := range aces {
		if n.unmapped[aces[i].Who] {
			aces[i].Who = "65534"
		}
	}
	if n.merge && len(aces) > 1 {
		aces = aces[1:]
	}
	n.stored = nfs4acl.Encode(aces)
	return nil
}

func (n *nobodyTransport) GetACL(ref transport.Ref) ([]byte, error) {
	if n.stored != nil {
		return n.stored, nil
	}
	return n.recordingTransport.GetACL(ref)
}

var probeOrig = nfs4acl.Encode([]nfs4acl.ACE{
	{Type: nfs4acl.TypeAllow, Mask: 0x1f01ff, Who: "OWNER@"},
	{Type: nfs4acl.TypeAllow, Mask: 0x1200a9, Who: "1402"},
})

func unmappedSpec() *spec.Spec {
	return &spec.Spec{
		Protocol: "nfsv4",
		Default:  spec.RulePerms{ACL: []string{"A::OWNER@:rwatTnNcCy", "A::1402:rxtncy"}},
		Rules: []spec.Rule{{
			Match: spec.RuleMatch{Type: "directory"},
			RulePerms: spec.RulePerms{ACL: []string{
				"D:fdg:sacl-nomap-grp@example.net:dD",
				"A:fd:sacl-nomap1@example.net:rxtncy",
				"A:fdg:sacl-nomap-grp@example.net:rwadxtTnNcy",
				"A::EVERYONE@:rxtncy",
			}},
		}},
	}
}

func TestProbeUnmappedPrincipalsNamesTheNobodyEntries(t *testing.T) {
	n := &nobodyTransport{
		recordingTransport: &recordingTransport{getACL: probeOrig},
		unmapped:           map[string]bool{"sacl-nomap1@example.net": true, "sacl-nomap-grp@example.net": true},
	}
	got, err := ProbeUnmappedPrincipals(n, transport.Ref{Path: "/tree"}, unmappedSpec())
	if err != nil {
		t.Fatalf("ProbeUnmappedPrincipals: %v", err)
	}
	// 1402 is mapped; the deny and allow on the group are one principal.
	want := []string{"sacl-nomap-grp@example.net", "sacl-nomap1@example.net"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("unmapped = %q, want %q", got, want)
	}
	calls := n.setACLCalls
	if len(calls) != 2 {
		t.Fatalf("SetACL called %d times, want 2: the probe write, then the restore", len(calls))
	}
	if !bytes.Equal(calls[1].acl, probeOrig) {
		t.Error("the restore did not write the target's original ACL back")
	}
	if !n.cleanupRan {
		t.Error("cleanup did not run; a probe file would be left in the customer's tree")
	}
}

func TestProbeUnmappedPrincipalsAllMapped(t *testing.T) {
	n := &nobodyTransport{recordingTransport: &recordingTransport{getACL: probeOrig}}
	got, err := ProbeUnmappedPrincipals(n, transport.Ref{Path: "/tree"}, unmappedSpec())
	if err != nil || len(got) != 0 {
		t.Fatalf("got %q, %v; want no principals and no error", got, err)
	}
}

// The target's existing nobody entries are its own, not the spec's: only the
// probe entries after them are attributed.
func TestProbeUnmappedPrincipalsIgnoresTheTargetsOwnNobody(t *testing.T) {
	orig := nfs4acl.Encode([]nfs4acl.ACE{
		{Type: nfs4acl.TypeAllow, Mask: 0x1f01ff, Who: "OWNER@"},
		{Type: nfs4acl.TypeAllow, Mask: 0x1200a9, Who: "65534"},
	})
	n := &nobodyTransport{recordingTransport: &recordingTransport{getACL: orig}}
	got, err := ProbeUnmappedPrincipals(n, transport.Ref{Path: "/tree"}, unmappedSpec())
	if err != nil || len(got) != 0 {
		t.Fatalf("got %q, %v; want no principals and no error", got, err)
	}
}

func TestProbeUnmappedPrincipalsKeepsTheTargetsSACL(t *testing.T) {
	audit := nfs4acl.ACE{Type: nfs4acl.TypeAudit, Flags: nfs4acl.FlagSuccessAccess, Mask: nfs4acl.MaskReadData, Who: "EVERYONE@"}
	orig := nfs4acl.Encode([]nfs4acl.ACE{{Type: nfs4acl.TypeAllow, Mask: 0x1f01ff, Who: "OWNER@"}, audit})
	n := &nobodyTransport{recordingTransport: &recordingTransport{getACL: orig}}
	if _, err := ProbeUnmappedPrincipals(n, transport.Ref{Path: "/tree"}, unmappedSpec()); err != nil {
		t.Fatalf("ProbeUnmappedPrincipals: %v", err)
	}
	aces, err := nfs4acl.DecodeACL(n.setACLCalls[0].acl)
	if err != nil {
		t.Fatal(err)
	}
	if last := aces[len(aces)-1]; last != audit {
		t.Errorf("probe write ends with %+v, want the target's audit ACE kept at the tail", last)
	}
}

func TestProbeUnmappedPrincipalsMergedReadBack(t *testing.T) {
	n := &nobodyTransport{
		recordingTransport: &recordingTransport{getACL: probeOrig},
		unmapped:           map[string]bool{"sacl-nomap1@example.net": true},
		merge:              true,
	}
	_, err := ProbeUnmappedPrincipals(n, transport.Ref{Path: "/tree"}, unmappedSpec())
	if err == nil || !strings.Contains(err.Error(), "reads back as nobody") {
		t.Fatalf("err = %v, want the cannot-attribute error", err)
	}

	// The same merge with nothing unmapped is no finding at all.
	n = &nobodyTransport{recordingTransport: &recordingTransport{getACL: probeOrig}, merge: true}
	if got, err := ProbeUnmappedPrincipals(n, transport.Ref{Path: "/tree"}, unmappedSpec()); err != nil || len(got) != 0 {
		t.Fatalf("got %q, %v; want no principals and no error", got, err)
	}
}

func TestProbeUnmappedPrincipalsWriteRefusedStillRestores(t *testing.T) {
	refused := errors.New("invalid argument")
	rec := &recordingTransport{getACL: probeOrig, setACLErr: refused, failSetACLOnAttempt: 1}
	_, err := ProbeUnmappedPrincipals(rec, transport.Ref{Path: "/tree"}, unmappedSpec())
	if !errors.Is(err, refused) {
		t.Fatalf("err = %v, want the refused write", err)
	}
	if len(rec.setACLCalls) != 1 || !bytes.Equal(rec.setACLCalls[0].acl, probeOrig) {
		t.Error("a refused probe write was not followed by a restore of the original ACL")
	}
}

func TestProbeUnmappedPrincipalsNoNamedPrincipalsTouchesNothing(t *testing.T) {
	rec := &recordingTransport{getACL: probeOrig}
	s := &spec.Spec{Protocol: "nfsv4", Default: spec.RulePerms{ACL: []string{"A::OWNER@:rwatTnNcCy", "A::EVERYONE@:rxtncy"}}}
	if got, err := ProbeUnmappedPrincipals(rec, transport.Ref{Path: "/tree"}, s); err != nil || len(got) != 0 {
		t.Fatalf("got %q, %v; want nothing", got, err)
	}
	if len(rec.setACLCalls) != 0 || rec.getACLCalls != 0 {
		t.Error("a spec with only specials still probed the target")
	}
}
