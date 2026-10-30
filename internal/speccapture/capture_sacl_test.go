package speccapture_test

import (
	"strings"
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs4acl"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/spec"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/speccapture"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

var (
	auditDirACEs  = []string{"A:fd:OWNER@:rwaDxtTcCoy", "A:fdg:GROUP@:rxtncy", "U:fdSF:EVERYONE@:rwadxTNcCoy"}
	auditFileACEs = []string{"A::OWNER@:rwaTcCoy", "U:SF:EVERYONE@:rwadxTNcCoy"}
)

func parseYAML(t *testing.T, y []byte) *spec.Spec {
	t.Helper()
	s, err := spec.Parse(y, "<test>")
	if err != nil {
		t.Fatalf("spec.Parse: %v\n%s", err, y)
	}
	return s
}

func hasNote(res *speccapture.Result, sub string) bool {
	for _, n := range res.Notes {
		if strings.Contains(n, sub) {
			return true
		}
	}
	return false
}

// No audit ACEs: the spec is the DACL spec build-spec has always written, with
// no sacl: key, so it runs without permissionreset --sacl.
func TestCaptureNoAuditKeepsDACLSpec(t *testing.T) {
	for _, withDACL := range []bool{false, true} {
		r, dir, file := simpleReader(goldenDirACEs, goldenFileACEs, t)
		res, err := speccapture.CaptureWithOptions(r, dir, file, speccapture.Options{WithDACL: withDACL})
		if err != nil {
			t.Fatalf("Capture: %v", err)
		}
		if strings.Contains(string(res.YAML), "sacl") {
			t.Errorf("withDACL=%v: YAML has a sacl key:\n%s", withDACL, res.YAML)
		}
		if res.HasSACL() || res.KeepsDACL {
			t.Errorf("withDACL=%v: HasSACL=%v KeepsDACL=%v, want false", withDACL, res.HasSACL(), res.KeepsDACL)
		}
		if got := parseYAML(t, res.YAML).MissingSACL(); len(got) != 2 {
			t.Errorf("withDACL=%v: MissingSACL = %v, want both rules", withDACL, got)
		}
		if !hasNote(res, "no audit (U) ACEs were read") {
			t.Errorf("withDACL=%v: missing the no-audit note: %q", withDACL, res.Notes)
		}
		if hasNote(res, "--with-dacl has no effect") != withDACL {
			t.Errorf("withDACL=%v: notes %q", withDACL, res.Notes)
		}
	}
	// The default entry point is byte-identical to the explicit default.
	r, dir, file := simpleReader(goldenDirACEs, goldenFileACEs, t)
	a, _ := speccapture.Capture(r, dir, file)
	b, _ := speccapture.CaptureWithOptions(r, dir, file, speccapture.Options{})
	if string(a.YAML) != string(b.YAML) {
		t.Error("Capture and CaptureWithOptions(Options{}) differ")
	}
}

// Audit ACEs, default: DACL-keeping rules with the U lines in sacl: and no acl:.
func TestCaptureAuditDefaultKeepsDACL(t *testing.T) {
	r, dir, file := simpleReader(auditDirACEs, auditFileACEs, t)
	res, err := speccapture.Capture(r, dir, file)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if !res.KeepsDACL {
		t.Fatal("KeepsDACL = false, want true")
	}
	if strings.Contains(string(res.YAML), "    acl:") {
		t.Errorf("DACL-keeping YAML has acl:\n%s", res.YAML)
	}
	s := parseYAML(t, res.YAML)
	for i, rule := range s.Rules {
		if !rule.KeepDACL() {
			t.Errorf("rule[%d] KeepDACL = false", i)
		}
	}
	if got := *s.Rules[0].Sacl; len(got) != 1 || got[0] != "U:fdSF:EVERYONE@:rwaNxTdcCoy" {
		t.Errorf("dir sacl = %q", got)
	}
	if got := *s.Rules[1].Sacl; len(got) != 1 || got[0] != "U:SF:EVERYONE@:rwaNxTdcCoy" {
		t.Errorf("file sacl = %q", got)
	}
	// DirACEs/FileACEs hold the DACL only.
	if len(res.DirACEs) != 2 || len(res.FileACEs) != 1 {
		t.Errorf("DACL split: dir %q file %q", res.DirACEs, res.FileACEs)
	}
	if !hasNote(res, "keeps each object's own DACL") || !hasNote(res, "audit bypass") {
		t.Errorf("notes %q", res.Notes)
	}
}

// Audit ACEs on one exemplar only: the other rule gets sacl: [], because that
// exemplar says objects of its type carry no audit ACEs.
func TestCaptureAuditOneExemplarEmitsEmptySACL(t *testing.T) {
	r, dir, file := simpleReader(auditDirACEs, goldenFileACEs, t)
	res, err := speccapture.Capture(r, dir, file)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if !strings.Contains(string(res.YAML), "    sacl: []\n") {
		t.Errorf("want sacl: [] for the file rule:\n%s", res.YAML)
	}
	s := parseYAML(t, res.YAML)
	if !s.Rules[1].SaclSet() || len(*s.Rules[1].Sacl) != 0 {
		t.Errorf("file rule sacl = %v", s.Rules[1].Sacl)
	}
	if !hasNote(res, "the file rule is sacl: []") || hasNote(res, "the directory rule is sacl: []") {
		t.Errorf("notes %q, want the file rule's sacl: [] named and only that", res.Notes)
	}
}

// --with-dacl: acl: and sacl: together; the guard has nothing to report.
func TestCaptureAuditWithDACL(t *testing.T) {
	r, dir, file := simpleReader(auditDirACEs, auditFileACEs, t)
	res, err := speccapture.CaptureWithOptions(r, dir, file, speccapture.Options{WithDACL: true})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if res.KeepsDACL {
		t.Error("KeepsDACL = true under --with-dacl")
	}
	s := parseYAML(t, res.YAML)
	if got := s.MissingSACL(); len(got) != 0 {
		t.Errorf("MissingSACL = %v", got)
	}
	if len(s.Rules[0].ACL) != 2 || len(*s.Rules[0].Sacl) != 1 {
		t.Errorf("dir rule acl %q sacl %q", s.Rules[0].ACL, *s.Rules[0].Sacl)
	}
	if !hasNote(res, "replaces every object's DACL") {
		t.Errorf("notes %q", res.Notes)
	}
}

// Alarm (L) ACEs are dropped with a note; they never reach the spec.
func TestCaptureDropsAlarmACEs(t *testing.T) {
	r, dir, file := simpleReader(goldenDirACEs, goldenFileACEs, t)
	r.acls["/vol/file.txt"] = nfs4acl.Encode([]nfs4acl.ACE{
		{Type: nfs4acl.TypeAllow, Mask: nfs4acl.MaskReadData, Who: "OWNER@"},
		{Type: nfs4acl.TypeAlarm, Flags: nfs4acl.FlagFailedAccess, Mask: nfs4acl.MaskReadData, Who: "EVERYONE@"},
	})
	res, err := speccapture.Capture(r, dir, file)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if strings.Contains(string(res.YAML), "L:") {
		t.Errorf("alarm ACE reached the YAML:\n%s", res.YAML)
	}
	if !hasNote(res, "dropped 1 alarm (L) ACE") {
		t.Errorf("notes %q", res.Notes)
	}
}

// Verify keeps the capture's shape: a DACL-keeping capture verifies to a
// DACL-keeping spec, with the full ACL (DACL and SACL) replayed on the probes.
func TestVerifyAuditKeepsShape(t *testing.T) {
	r, dir, file := simpleReader(auditDirACEs, auditFileACEs, t)
	in, err := speccapture.Capture(r, dir, file)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	fv := newFakeVerifier()
	out, err := speccapture.Verify(fv, scratch, dirExemplar, fileExemplar, in)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if string(out.YAML) != string(in.YAML) {
		t.Errorf("verified YAML differs:\n%s\nvs\n%s", out.YAML, in.YAML)
	}
	if !out.Identity.Verified || !out.KeepsDACL {
		t.Errorf("Verified=%v KeepsDACL=%v", out.Identity.Verified, out.KeepsDACL)
	}
	for path, raw := range fv.stored {
		aces, _ := nfs4acl.DecodeACL(raw)
		if aces[len(aces)-1].Type != nfs4acl.TypeAudit {
			t.Errorf("probe %s was written without its SACL", path)
		}
	}
}

// auditDroppingVerifier stands in for an array that silently drops U ACEs, as
// FlashArray does for a writer without the audit bypass.
type auditDroppingVerifier struct{ *fakeVerifier }

func (a auditDroppingVerifier) SetACL(ref transport.Ref, raw []byte) error {
	aces, err := nfs4acl.DecodeACL(raw)
	if err != nil {
		return err
	}
	var kept []nfs4acl.ACE
	for _, ace := range aces {
		if ace.Type != nfs4acl.TypeAudit {
			kept = append(kept, ace)
		}
	}
	return a.fakeVerifier.SetACL(ref, nfs4acl.Encode(kept))
}

// fileAuditDroppingVerifier keeps the directory probe's U entries and drops
// the file probe's: verification must fail rather than emit sacl: [] for files.
type fileAuditDroppingVerifier struct{ *fakeVerifier }

func (a fileAuditDroppingVerifier) SetACL(ref transport.Ref, raw []byte) error {
	if strings.HasSuffix(ref.Path, "-dir") {
		return a.fakeVerifier.SetACL(ref, raw)
	}
	return auditDroppingVerifier(a).SetACL(ref, raw)
}

func TestVerifyAuditPartlyDroppedByServer(t *testing.T) {
	r, dir, file := simpleReader(auditDirACEs, auditFileACEs, t)
	in, err := speccapture.Capture(r, dir, file)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	_, err = speccapture.Verify(fileAuditDroppingVerifier{newFakeVerifier()}, scratch, dirExemplar, fileExemplar, in)
	if err == nil || !strings.Contains(err.Error(), "file exemplar") {
		t.Fatalf("err = %v, want a refusal naming the file exemplar", err)
	}
}

func TestVerifyAuditDroppedByServer(t *testing.T) {
	r, dir, file := simpleReader(auditDirACEs, auditFileACEs, t)
	in, err := speccapture.Capture(r, dir, file)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	_, err = speccapture.Verify(auditDroppingVerifier{newFakeVerifier()}, scratch, dirExemplar, fileExemplar, in)
	if err == nil || !strings.Contains(err.Error(), "audit bypass") {
		t.Fatalf("err = %v, want the audit-bypass refusal", err)
	}
}
