package apply

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs4acl"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// treeTransport holds one ACL per path, the way an array does. Nothing in the
// apply path takes a platform, so one fixture stands for FlashArray and
// FlashBlade alike: both return the SACL inside system.nfs4_acl.
type treeTransport struct {
	transport.Transport
	mu    sync.Mutex
	acls  map[string][]byte
	reads int
	sets  int
}

func (t *treeTransport) GetACL(ref transport.Ref) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.reads++
	acl, ok := t.acls[ref.Path]
	if !ok {
		return nil, errors.New("no such object")
	}
	return acl, nil
}

func (t *treeTransport) SetACL(ref transport.Ref, acl []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sets++
	t.acls[ref.Path] = append([]byte(nil), acl...)
	return nil
}

const preserveSpec = "default:\n  acl:\n    - \"A::OWNER@:rwaDxtTnNcCoy\"\n"

var (
	allowEveryone = nfs4acl.ACE{Type: nfs4acl.TypeAllow, Who: "EVERYONE@", Mask: nfs4acl.MaskReadData}
	auditDir      = nfs4acl.ACE{Type: nfs4acl.TypeAudit, Flags: nfs4acl.FlagSuccessAccess | nfs4acl.FlagFailedAccess | nfs4acl.FlagFileInherit | nfs4acl.FlagDirInherit, Who: "EVERYONE@", Mask: nfs4acl.MaskReadData}
	auditFile     = nfs4acl.ACE{Type: nfs4acl.TypeAudit, Flags: nfs4acl.FlagFailedAccess, Who: "1402", Mask: nfs4acl.MaskWriteData}
)

func saclOf(t *testing.T, acl []byte) []byte {
	t.Helper()
	_, sacl, _, _, err := nfs4acl.SplitRaw(acl)
	if err != nil {
		t.Fatal(err)
	}
	return sacl
}

// TestPreserveSACLCleanRootAuditedDescendants is the PS-04 fixture: a root
// with no audit ACEs says nothing about what lies under it, so every
// descendant's auditing survives the DACL reset, byte for byte.
func TestPreserveSACLCleanRootAuditedDescendants(t *testing.T) {
	s := loadNFSv4Spec(t, preserveSpec)
	before := map[string][]byte{
		"/t":     nfs4acl.Encode([]nfs4acl.ACE{allowEveryone}),
		"/t/d":   nfs4acl.Encode([]nfs4acl.ACE{auditDir, allowEveryone}), // audit first: order on input is not order on output
		"/t/d/f": nfs4acl.Encode([]nfs4acl.ACE{allowEveryone, auditFile, auditDir}),
		"/t/g":   nfs4acl.Encode([]nfs4acl.ACE{allowEveryone}),
	}
	tr := &treeTransport{acls: map[string][]byte{}}
	for p, a := range before {
		tr.acls[p] = a
	}
	isDir := map[string]bool{"/t": true, "/t/d": true, "/t/g": true}
	kept := 0
	for p := range before {
		r := ProcessPath(tr, transport.Ref{Path: p}, isDir[p], s, Options{AllowAuditedDACLReset: true}, 0)
		if r.Error != nil {
			t.Fatalf("%s: %v", p, r.Error)
		}
		kept += r.AuditKept
	}
	for p, orig := range before {
		got := tr.acls[p]
		dacl, sacl, _, _, err := nfs4acl.SplitRaw(got)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(dacl, s.Default.EncodedACL()) {
			t.Errorf("%s: DACL is not the spec's", p)
		}
		if !bytes.Equal(sacl, saclOf(t, orig)) {
			t.Errorf("%s: audit ACEs changed:\n got %x\nwant %x", p, sacl, saclOf(t, orig))
		}
	}
	if kept != 3 {
		t.Errorf("AuditKept summed to %d, want 3", kept)
	}

	// --compare on the converged tree reads and writes nothing new.
	sets := tr.sets
	for p := range before {
		if r := ProcessPath(tr, transport.Ref{Path: p}, isDir[p], s, Options{Compare: true, AllowAuditedDACLReset: true}, 0); !r.Skipped || r.Error != nil {
			t.Errorf("%s: second pass = %+v, want skipped", p, r)
		}
	}
	if tr.sets != sets {
		t.Errorf("second pass wrote %d times, want 0", tr.sets-sets)
	}
}

// The three sacl: forms: absent keeps, entries replace, [] clears.
func TestSaclKeyForms(t *testing.T) {
	orig := nfs4acl.Encode([]nfs4acl.ACE{allowEveryone, auditFile})
	for _, tc := range []struct {
		name, body string
		want       []nfs4acl.ACE // audit ACEs after
	}{
		{"absent", preserveSpec, []nfs4acl.ACE{auditFile}},
		{"empty", preserveSpec + "  sacl: []\n", nil},
		{"nonempty", preserveSpec + "  sacl:\n    - \"U:SF:EVERYONE@:rwaD\"\n", []nfs4acl.ACE{{Type: nfs4acl.TypeAudit, Flags: nfs4acl.FlagSuccessAccess | nfs4acl.FlagFailedAccess, Who: "EVERYONE@", Mask: nfs4acl.MaskReadData | nfs4acl.MaskWriteData | nfs4acl.MaskAppendData | nfs4acl.MaskDeleteChild}}},
	} {
		tr := &treeTransport{acls: map[string][]byte{"/f": orig}}
		if r := ProcessPath(tr, transport.Ref{Path: "/f"}, false, loadNFSv4Spec(t, tc.body), Options{AllowAuditedDACLReset: true}, 0); r.Error != nil {
			t.Fatalf("%s: %v", tc.name, r.Error)
		}
		_, _, got, err := nfs4acl.SplitACL(tr.acls["/f"])
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(tc.want) || (len(got) > 0 && !nfs4acl.ACEsEqualIdent(got, tc.want, nil)) {
			t.Errorf("%s: audit ACEs = %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

// Mixed rules: each object follows its own rule's sacl: form.
func TestPreserveSACLMixedRules(t *testing.T) {
	s := loadNFSv4Spec(t, preserveSpec+"rules:\n  - match:\n      pattern: \"*.log\"\n    acl:\n      - \"A::OWNER@:rwaDxtTnNcCoy\"\n    sacl: []\n")
	orig := nfs4acl.Encode([]nfs4acl.ACE{allowEveryone, auditFile})
	tr := &treeTransport{acls: map[string][]byte{"/a.txt": orig, "/b.log": orig}}
	for _, p := range []string{"/a.txt", "/b.log"} {
		if r := ProcessPath(tr, transport.Ref{Path: p}, false, s, Options{AllowAuditedDACLReset: true}, 0); r.Error != nil {
			t.Fatalf("%s: %v", p, r.Error)
		}
	}
	if has, _ := nfs4acl.HasAudit(tr.acls["/a.txt"]); !has {
		t.Error("/a.txt (no sacl: key) lost its audit ACEs")
	}
	if has, _ := nfs4acl.HasAudit(tr.acls["/b.log"]); has {
		t.Error("/b.log (sacl: []) kept its audit ACEs")
	}
}

// No read, no write: an unreadable or unparseable ACL is never overwritten.
func TestPreserveSACLFailsClosed(t *testing.T) {
	s := loadNFSv4Spec(t, preserveSpec)
	good := nfs4acl.Encode([]nfs4acl.ACE{allowEveryone, auditFile})
	for name, tr := range map[string]*recordingTransport{
		"read error": {getACLErr: errors.New("EACCES")},
		"truncated":  {getACL: good[:len(good)-3]},
		"trailing":   {getACL: append(append([]byte(nil), good...), 0, 0, 0, 0)},
		"nobody":     {getACL: nfs4acl.Encode([]nfs4acl.ACE{allowEveryone, {Type: nfs4acl.TypeAudit, Flags: nfs4acl.FlagFailedAccess, Who: "65534", Mask: nfs4acl.MaskReadData}})},
		"high id":    {getACL: nfs4acl.Encode([]nfs4acl.ACE{allowEveryone, {Type: nfs4acl.TypeAudit, Flags: nfs4acl.FlagFailedAccess, Who: "2000000003", Mask: nfs4acl.MaskReadData}})},
	} {
		r := ProcessPath(tr, transport.Ref{Path: "/f"}, false, s, Options{AllowAuditedDACLReset: true}, 0)
		if r.Error == nil || len(tr.setACLCalls) != 0 {
			t.Errorf("%s: error = %v, writes = %d; want an error and no write", name, r.Error, len(tr.setACLCalls))
		}
		if (name == "nobody" || name == "high id") && !errors.Is(r.Error, ErrUnpreservableAudit) {
			t.Errorf("%s: error = %v, want ErrUnpreservableAudit", name, r.Error)
		}
	}
}

// A batch read is used instead of a second per-object read, and a dry run
// reads nothing at all.
func TestPreserveSACLCachedReadAndDryRun(t *testing.T) {
	s := loadNFSv4Spec(t, preserveSpec)
	orig := nfs4acl.Encode([]nfs4acl.ACE{allowEveryone, auditFile})
	rec := &recordingTransport{}
	r := ProcessPath(rec, transport.Ref{Path: "/f"}, false, s, Options{CachedACL: orig, AllowAuditedDACLReset: true}, 0)
	if r.Error != nil || rec.getACLCalls != 0 || len(rec.setACLCalls) != 1 || r.AuditKept != 1 {
		t.Fatalf("cached: %+v, reads %d, writes %d", r, rec.getACLCalls, len(rec.setACLCalls))
	}
	if has, _ := nfs4acl.HasAudit(rec.setACLCalls[0].acl); !has {
		t.Error("cached: the write dropped the audit ACE")
	}

	rec = &recordingTransport{getACL: orig}
	if r := ProcessPath(rec, transport.Ref{Path: "/f"}, false, s, Options{DryRun: true}, 0); !r.Applied || rec.getACLCalls != 0 || len(rec.setACLCalls) != 0 {
		t.Fatalf("dry run: %+v, reads %d, writes %d", r, rec.getACLCalls, len(rec.setACLCalls))
	}
}

// --validate checks only the DACL of a rule that keeps auditing.
func TestValidatePreserveSACLIgnoresAudit(t *testing.T) {
	s := loadNFSv4Spec(t, preserveSpec)
	withAudit := nfs4acl.JoinRaw(s.Default.EncodedACL(), saclOf(t, nfs4acl.Encode([]nfs4acl.ACE{auditFile})))
	if r := ValidatePath(&recordingTransport{}, transport.Ref{Path: "/f"}, false, s, 0, withAudit, nil); !r.Matches || r.Error != nil {
		t.Errorf("spec DACL + audit: %+v, want a match", r)
	}
	wrong := nfs4acl.Encode([]nfs4acl.ACE{allowEveryone, auditFile})
	if r := ValidatePath(&recordingTransport{}, transport.Ref{Path: "/f"}, false, s, 0, wrong, nil); r.Matches {
		t.Error("wrong DACL + audit matched")
	}
}

// Without --allow-audited-dacl-reset a DACL reset refuses an object that
// carries audit ACEs and writes nothing (FA marks the SACL and DACL protected
// on any NFS ACL write). An object with no audit ACEs is still written.
func TestPreserveSACLRefusesAuditedObject(t *testing.T) {
	s := loadNFSv4Spec(t, preserveSpec)
	rec := &recordingTransport{getACL: nfs4acl.Encode([]nfs4acl.ACE{allowEveryone, auditFile})}
	r := ProcessPath(rec, transport.Ref{Path: "/f"}, false, s, Options{}, 0)
	if !errors.Is(r.Error, ErrAuditedObject) || len(rec.setACLCalls) != 0 {
		t.Fatalf("audited: error = %v, writes = %d; want ErrAuditedObject and no write", r.Error, len(rec.setACLCalls))
	}
	if !strings.HasPrefix(r.Error.Error(), "/f: ") {
		t.Errorf("audited: error = %q, want it to name the object so the log and evidence can attribute it", r.Error)
	}

	rec = &recordingTransport{getACL: nfs4acl.Encode([]nfs4acl.ACE{allowEveryone})}
	if r := ProcessPath(rec, transport.Ref{Path: "/f"}, false, s, Options{}, 0); r.Error != nil || len(rec.setACLCalls) != 1 {
		t.Fatalf("unaudited: error = %v, writes = %d; want one write", r.Error, len(rec.setACLCalls))
	}
}
