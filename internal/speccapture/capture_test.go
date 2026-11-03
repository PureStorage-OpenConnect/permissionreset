package speccapture_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs4acl"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/spec"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/speccapture"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// fakeReader implements speccapture.Reader without any real filesystem access.
type fakeReader struct {
	attrs   map[string]transport.Attr
	acls    map[string][]byte
	statErr map[string]error
	aclErr  map[string]error
}

func (f *fakeReader) Stat(ref transport.Ref) (transport.Attr, error) {
	if err := f.statErr[ref.Path]; err != nil {
		return transport.Attr{}, err
	}
	a, ok := f.attrs[ref.Path]
	if !ok {
		return transport.Attr{}, fmt.Errorf("no attr for %q", ref.Path)
	}
	return a, nil
}

func (f *fakeReader) GetACL(ref transport.Ref) ([]byte, error) {
	if err := f.aclErr[ref.Path]; err != nil {
		return nil, f.aclErr[ref.Path]
	}
	b, ok := f.acls[ref.Path]
	if !ok {
		return nil, fmt.Errorf("no ACL for %q", ref.Path)
	}
	return b, nil
}

func mkRef(path string) transport.Ref { return transport.Ref{Path: path} }

func mustEncode(t *testing.T, aces []string) []byte {
	t.Helper()
	raw, err := nfs4acl.ParseACLSpec(aces)
	if err != nil {
		t.Fatalf("ParseACLSpec: %v", err)
	}
	return raw
}

// encodeRetentionACL builds a raw ACL with a MaskWriteRetention bit that
// FormatACL cannot express, so Capture must fail.
func encodeRetentionACL() []byte {
	return nfs4acl.Encode([]nfs4acl.ACE{
		{Type: nfs4acl.TypeAllow, Flags: 0, Mask: nfs4acl.MaskWriteRetention, Who: "OWNER@"},
	})
}

// mustFileACL returns encoded bytes for a minimal valid file ACL.
func mustFileACL() []byte {
	raw, err := nfs4acl.ParseACLSpec([]string{"A::OWNER@:rwaTcCoy"})
	if err != nil {
		panic(fmt.Sprintf("mustFileACL: %v", err))
	}
	return raw
}

// simpleReader builds a fakeReader for the common dir+file happy-path.
func simpleReader(dirACEs, fileACEs []string, t *testing.T) (*fakeReader, transport.Ref, transport.Ref) {
	t.Helper()
	dir := mkRef("/vol/dir")
	file := mkRef("/vol/file.txt")
	return &fakeReader{
		attrs: map[string]transport.Attr{
			"/vol/dir":      {Kind: transport.KindDirectory, IsDir: true},
			"/vol/file.txt": {Kind: transport.KindRegular},
		},
		acls: map[string][]byte{
			"/vol/dir":      mustEncode(t, dirACEs),
			"/vol/file.txt": mustEncode(t, fileACEs),
		},
		statErr: map[string]error{},
		aclErr:  map[string]error{},
	}, dir, file
}

// ---- success case and golden checks ----------------------------------------

var (
	goldenDirACEs  = []string{"A:fd:OWNER@:rwaDxtTcCoy", "A:fdg:GROUP@:rxtncy"}
	goldenFileACEs = []string{"A::OWNER@:rwaTcCoy", "A:g:GROUP@:rncy"}
)

func TestCaptureSuccess(t *testing.T) {
	r, dir, file := simpleReader(goldenDirACEs, goldenFileACEs, t)
	res, err := captureUnproven(r, dir, file)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if len(res.DirACEs) != 2 {
		t.Errorf("DirACEs count = %d, want 2", len(res.DirACEs))
	}
	if len(res.FileACEs) != 2 {
		t.Errorf("FileACEs count = %d, want 2", len(res.FileACEs))
	}

	// YAML must contain the protocol and both rule type markers.
	yaml := string(res.YAML)
	for _, want := range []string{
		"protocol: nfsv4",
		"type: directory",
		"type: file",
		"default: {}",
	} {
		if !strings.Contains(yaml, want) {
			t.Errorf("YAML missing %q", want)
		}
	}
	// ACE strings must appear quoted.
	for _, ace := range append(res.DirACEs, res.FileACEs...) {
		quoted := fmt.Sprintf("%q", ace)
		if !strings.Contains(yaml, quoted) {
			t.Errorf("YAML missing ACE %s", quoted)
		}
	}
}

func TestCaptureGoldenReloadsViaSpecParse(t *testing.T) {
	r, dir, file := simpleReader(goldenDirACEs, goldenFileACEs, t)
	res, err := captureUnproven(r, dir, file)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	s, err := spec.Parse(res.YAML, "<test-golden>")
	if err != nil {
		t.Fatalf("spec.Parse on generated YAML: %v", err)
	}
	if s.Protocol != "nfsv4" {
		t.Errorf("Protocol = %q, want nfsv4", s.Protocol)
	}
	if len(s.Rules) != 2 {
		t.Errorf("len(Rules) = %d, want 2", len(s.Rules))
	}
	// Directory rule is first.
	if s.Rules[0].Match.Type != "directory" {
		t.Errorf("Rules[0].Match.Type = %q, want directory", s.Rules[0].Match.Type)
	}
	if s.Rules[1].Match.Type != "file" {
		t.Errorf("Rules[1].Match.Type = %q, want file", s.Rules[1].Match.Type)
	}
	if len(s.Rules[0].ACL) != 2 {
		t.Errorf("dir rule ACL len = %d, want 2", len(s.Rules[0].ACL))
	}
	if len(s.Rules[1].ACL) != 2 {
		t.Errorf("file rule ACL len = %d, want 2", len(s.Rules[1].ACL))
	}
}

func TestCaptureDenyBeforeAllowPreserved(t *testing.T) {
	// Deny ACE before allow ACE -- capture must not reorder.
	dirACEs := []string{
		"D::EVERYONE@:w",
		"A::OWNER@:rwaTcCoy",
	}
	fileACEs := []string{"A::OWNER@:rwaTcCoy"}
	r, dir, file := simpleReader(dirACEs, fileACEs, t)
	res, err := captureUnproven(r, dir, file)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if len(res.DirACEs) < 2 {
		t.Fatalf("DirACEs too short: %v", res.DirACEs)
	}
	if !strings.HasPrefix(res.DirACEs[0], "D:") {
		t.Errorf("DirACEs[0] = %q, want deny (D:...) first", res.DirACEs[0])
	}
	if !strings.HasPrefix(res.DirACEs[1], "A:") {
		t.Errorf("DirACEs[1] = %q, want allow (A:...) second", res.DirACEs[1])
	}
}

// ---- rejection cases -------------------------------------------------------

func TestCaptureReversedArgs(t *testing.T) {
	// Swap dir and file arguments.
	r := &fakeReader{
		attrs: map[string]transport.Attr{
			"/vol/dir":  {Kind: transport.KindDirectory, IsDir: true},
			"/vol/file": {Kind: transport.KindRegular},
		},
		acls:    map[string][]byte{},
		statErr: map[string]error{},
		aclErr:  map[string]error{},
	}
	_, err := captureUnproven(r, mkRef("/vol/file"), mkRef("/vol/dir"))
	if err == nil {
		t.Fatal("expected error for reversed arguments, got nil")
	}
	if !strings.Contains(err.Error(), "reversed") {
		t.Errorf("error %q does not mention 'reversed'", err.Error())
	}
}

func TestCaptureTwoDirectories(t *testing.T) {
	r := &fakeReader{
		attrs: map[string]transport.Attr{
			"/a": {Kind: transport.KindDirectory, IsDir: true},
			"/b": {Kind: transport.KindDirectory, IsDir: true},
		},
		acls:    map[string][]byte{},
		statErr: map[string]error{},
		aclErr:  map[string]error{},
	}
	_, err := captureUnproven(r, mkRef("/a"), mkRef("/b"))
	if err == nil {
		t.Fatal("expected error for two-directory input, got nil")
	}
	if !strings.Contains(err.Error(), "directory") {
		t.Errorf("error %q does not mention 'directory'", err.Error())
	}
}

func TestCaptureTwoFiles(t *testing.T) {
	r := &fakeReader{
		attrs: map[string]transport.Attr{
			"/a": {Kind: transport.KindRegular},
			"/b": {Kind: transport.KindRegular},
		},
		acls:    map[string][]byte{},
		statErr: map[string]error{},
		aclErr:  map[string]error{},
	}
	_, err := captureUnproven(r, mkRef("/a"), mkRef("/b"))
	if err == nil {
		t.Fatal("expected error for two-file input, got nil")
	}
}

func TestCaptureSymlinkAsFile(t *testing.T) {
	r := &fakeReader{
		attrs: map[string]transport.Attr{
			"/d": {Kind: transport.KindDirectory, IsDir: true},
			"/l": {Kind: transport.KindSymlink, IsSymlink: true},
		},
		acls:    map[string][]byte{},
		statErr: map[string]error{},
		aclErr:  map[string]error{},
	}
	_, err := captureUnproven(r, mkRef("/d"), mkRef("/l"))
	if err == nil {
		t.Fatal("expected error for symlink file exemplar, got nil")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error %q does not mention 'symlink'", err.Error())
	}
}

func TestCaptureStatError(t *testing.T) {
	r := &fakeReader{
		attrs:   map[string]transport.Attr{},
		acls:    map[string][]byte{},
		statErr: map[string]error{"/d": fmt.Errorf("stat failed")},
		aclErr:  map[string]error{},
	}
	_, err := captureUnproven(r, mkRef("/d"), mkRef("/f"))
	if err == nil {
		t.Fatal("expected error when Stat fails, got nil")
	}
}

func TestCaptureUnsupportedMaskBit(t *testing.T) {
	// Build a raw ACL with a retention mask bit that FormatACL cannot express.
	retRaw := encodeRetentionACL()
	r := &fakeReader{
		attrs: map[string]transport.Attr{
			"/d": {Kind: transport.KindDirectory, IsDir: true},
			"/f": {Kind: transport.KindRegular},
		},
		acls: map[string][]byte{
			"/d": retRaw,
			"/f": mustFileACL(),
		},
		statErr: map[string]error{},
		aclErr:  map[string]error{},
	}
	_, err := captureUnproven(r, mkRef("/d"), mkRef("/f"))
	if err == nil {
		t.Fatal("expected error for unsupported mask bit, got nil")
	}
	// Error must name the exemplar (directory) and contain ACE index info.
	if !strings.Contains(err.Error(), "directory") {
		t.Errorf("error %q does not name the directory exemplar", err.Error())
	}
}

// ---- identity classification -----------------------------------------------

func TestIdentitySpecialCounting(t *testing.T) {
	// OWNER@, GROUP@, EVERYONE@ are all special.
	dirACEs := []string{
		"A::OWNER@:rwaTcCoy",
		"A:g:GROUP@:rxtncy",
		"A::EVERYONE@:rncy",
	}
	fileACEs := []string{"A::OWNER@:rwaTcCoy"}
	r, dir, file := simpleReader(dirACEs, fileACEs, t)
	res, err := captureUnproven(r, dir, file)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	// OWNER@, GROUP@, EVERYONE@ on the dir; the file's OWNER@ is the same principal.
	if res.Identity.Special != 3 {
		t.Errorf("Special = %d, want 3", res.Identity.Special)
	}
	if res.Identity.Named != 0 {
		t.Errorf("Named = %d, want 0", res.Identity.Named)
	}
	if res.Identity.NumericUser != 0 {
		t.Errorf("NumericUser = %d, want 0", res.Identity.NumericUser)
	}
	if res.Identity.NumericGroup != 0 {
		t.Errorf("NumericGroup = %d, want 0", res.Identity.NumericGroup)
	}
	if res.Identity.Verified {
		t.Error("Verified = true, want false from Capture")
	}
}

func TestIdentityNamedPrincipal(t *testing.T) {
	dirACEs := []string{"A::alice@example.com:rwaTcCoy"}
	fileACEs := []string{"A::bob@example.com:rncy"}
	r, dir, file := simpleReader(dirACEs, fileACEs, t)
	res, err := captureUnproven(r, dir, file)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if res.Identity.Named != 2 {
		t.Errorf("Named = %d, want 2", res.Identity.Named)
	}
	if res.Identity.Special != 0 {
		t.Errorf("Special = %d, want 0", res.Identity.Special)
	}
}

func TestIdentityNumericGFlagDistinguishesUserGroup(t *testing.T) {
	// "10010" without g flag = numeric user; "10020" with g flag = numeric group.
	// g flag is never inferred from the who value alone.
	dirACEs := []string{
		"A::10010:rwaTcCoy", // numeric user (no g flag)
		"A:g:10020:rxtncy",  // numeric group (g flag set)
		"A::10030:rncy",     // numeric user
	}
	fileACEs := []string{"A:g:10040:rncy"} // numeric group
	r, dir, file := simpleReader(dirACEs, fileACEs, t)
	res, err := captureUnproven(r, dir, file)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if res.Identity.NumericUser != 2 {
		t.Errorf("NumericUser = %d, want 2", res.Identity.NumericUser)
	}
	if res.Identity.NumericGroup != 2 {
		t.Errorf("NumericGroup = %d, want 2", res.Identity.NumericGroup)
	}
}

func TestIdentityVerifiedFalseFromCapture(t *testing.T) {
	r, dir, file := simpleReader(goldenDirACEs, goldenFileACEs, t)
	res, err := captureUnproven(r, dir, file)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if res.Identity.Verified {
		t.Error("Verified must be false from Capture; only a verifier sets it true")
	}
}

// TestIdentityDistinctPrincipals is the FlashBlade capture that read as 5 numeric
// users, 2 numeric groups and 2 specials: the summary counted ACEs, not
// principals, and counted the audit ACEs with the DACL.
func TestIdentityDistinctPrincipals(t *testing.T) {
	dirACEs := []string{
		"A:fdg:9224117:rwanNxtTdcy",
		"A:fd:1000003:rnxtcy",
		"A:fd:1402:rwanNxDtTdcCoy",
		"A:fd:1445:rnxtcy",
		"U:fdSF:EVERYONE@:rwanNxDtTdcCoy",
	}
	fileACEs := []string{
		"A:g:9224117:rntcy",
		"A::1000003:rwanNxtTdcy",
		"A::1402:rwanNxDtTdcCoy",
		"A:g:1402:rntcy", // same id with the g flag: a different principal
		"U:SF:EVERYONE@:rwanNxDtTdcCoy",
		"L:SF:EVERYONE@:rwanNxDtTdcCoy", // alarm: dropped from the spec, not counted
	}
	r, dir, file := simpleReader(dirACEs, fileACEs, t)
	res, err := captureUnproven(r, dir, file)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	id := res.Identity
	if id.Special != 0 || id.Named != 0 || id.NumericUser != 3 || id.NumericGroup != 2 {
		t.Errorf("DACL counts = %d/%d/%d/%d, want 0/0/3/2", id.Special, id.Named, id.NumericUser, id.NumericGroup)
	}
	if want := (speccapture.KindCounts{Special: 1}); id.SACL != want {
		t.Errorf("SACL counts = %+v, want %+v", id.SACL, want)
	}
	want := []struct {
		who         string
		group       bool
		kind, where string
	}{
		{"9224117", true, speccapture.KindNumericGroup, "directory DACL, file DACL"},
		{"1000003", false, speccapture.KindNumericUser, "directory DACL, file DACL"},
		{"1402", false, speccapture.KindNumericUser, "directory DACL, file DACL"},
		{"1445", false, speccapture.KindNumericUser, "directory DACL"},
		{"EVERYONE@", false, speccapture.KindSpecial, "directory SACL, file SACL"},
		{"1402", true, speccapture.KindNumericGroup, "file DACL"},
	}
	if len(id.Principals) != len(want) {
		t.Fatalf("%d principals, want %d: %+v", len(id.Principals), len(want), id.Principals)
	}
	for i, w := range want {
		p := id.Principals[i]
		if p.Who != w.who || p.Group != w.group || p.Kind != w.kind || p.Where() != w.where {
			t.Errorf("principal %d = %s group=%v %s (%s), want %s group=%v %s (%s)", i, p.Who, p.Group, p.Kind, p.Where(), w.who, w.group, w.kind, w.where)
		}
	}
	s := id.String()
	for _, line := range []string{
		"  DACL: special 0, named 0, numeric user 3, numeric group 2\n",
		"  SACL: special 1, named 0, numeric user 0, numeric group 0\n",
		"    g:9224117  numeric group  directory DACL, file DACL\n",
		"    EVERYONE@  special        directory SACL, file SACL\n",
	} {
		if !strings.Contains(s, line) {
			t.Errorf("String() missing %q:\n%s", line, s)
		}
	}
}

func TestIdentityReportString(t *testing.T) {
	rep := speccapture.IdentityReport{Special: 2, Named: 1, NumericUser: 0, NumericGroup: 1, Verified: false}
	s := rep.String()
	if !strings.Contains(s, "write verification: not performed") {
		t.Errorf("String() missing 'write verification: not performed': %q", s)
	}

	rep.Verified = true
	s = rep.String()
	if !strings.Contains(s, "write verification: passed") {
		t.Errorf("String() missing 'write verification: passed': %q", s)
	}
}

// TestCaptureYAMLDeterministic verifies two captures of identical input produce
// byte-identical output (LF newlines, stable field order, quoted strings).
func TestCaptureYAMLDeterministic(t *testing.T) {
	r1, dir1, file1 := simpleReader(goldenDirACEs, goldenFileACEs, t)
	r2, dir2, file2 := simpleReader(goldenDirACEs, goldenFileACEs, t)
	res1, err := captureUnproven(r1, dir1, file1)
	if err != nil {
		t.Fatalf("first Capture: %v", err)
	}
	res2, err := captureUnproven(r2, dir2, file2)
	if err != nil {
		t.Fatalf("second Capture: %v", err)
	}
	if string(res1.YAML) != string(res2.YAML) {
		t.Errorf("YAML not deterministic:\nfirst:\n%s\nsecond:\n%s", res1.YAML, res2.YAML)
	}
	// LF-only newlines (no CRLF).
	if strings.Contains(string(res1.YAML), "\r\n") {
		t.Error("YAML contains CRLF newlines; must use LF only")
	}
	// Exactly one trailing newline.
	y := string(res1.YAML)
	if !strings.HasSuffix(y, "\n") {
		t.Error("YAML does not end with newline")
	}
	if strings.HasSuffix(y, "\n\n") {
		t.Error("YAML ends with more than one trailing newline")
	}
}
