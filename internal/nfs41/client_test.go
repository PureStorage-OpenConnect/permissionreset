package nfs41

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41/xdr"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs4acl"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// newTestClient builds a Client against the fake and fails the test if it cannot.
// Config fields the caller left zero get test-appropriate defaults: one
// connection, the fake's slot grant, and short timeouts, so a hung test fails in
// seconds rather than at the go test deadline.
//
// It sets AllowNonPureServer, because the fake's default max file size is not a
// Pure value and the gate would otherwise refuse every client in the suite. The
// gate is exercised deliberately in Task 11 through newTestClientErr instead.
func newTestClient(t *testing.T, srv *fakeServer, cfg Config) *Client {
	t.Helper()
	cfg.AllowNonPureServer = true
	cl, err := newTestClientErr(t, srv, cfg)
	if err != nil {
		t.Fatalf("newTestClient: %v", err)
	}
	t.Cleanup(func() { cl.Close() })
	return cl
}

// newTestClientErr is the same but returns the error, for the gate tests in
// Task 11 whose whole subject is the refusal. It does NOT set
// AllowNonPureServer: those tests choose the server's reported size explicitly.
func newTestClientErr(t *testing.T, srv *fakeServer, cfg Config) (*Client, error) {
	t.Helper()
	if cfg.Connections == 0 {
		cfg.Connections = 1
	}
	if cfg.RPCTimeout == 0 {
		cfg.RPCTimeout = 5 * time.Second
	}
	if cfg.RetryBaseDelay == 0 {
		cfg.RetryBaseDelay = time.Millisecond
	}
	if cfg.MaxOpsPerCompound == 0 {
		cfg.MaxOpsPerCompound = 16
	}
	return newClientWithDialer(context.Background(), cfg, srv.Dialer())
}

func TestGateAcceptsAKnownPureMaxFileSize(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46))
	defer srv.Close()
	cl, err := newTestClientErr(t, srv, Config{Connections: 1})
	if err != nil {
		t.Fatalf("a server reporting 64 TiB must be accepted: %v", err)
	}
	// The accepted gate is also the platform signal callers tune themselves on,
	// so nothing else has to ask the server what it is.
	if got := cl.Platform(); got != PlatformFlashBlade {
		t.Errorf("Platform() = %q, want %q", got, PlatformFlashBlade)
	}
	cl.Close()
}

func TestGateRefusesAnUnknownMaxFileSize(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<41)) // 2 TiB, a generic Linux server
	defer srv.Close()

	_, err := newTestClientErr(t, srv, Config{Connections: 16})
	if err == nil {
		t.Fatal("want a refusal, got nil")
	}
	if !errors.Is(err, ErrNotPureServer) {
		t.Fatalf("err = %v, want ErrNotPureServer", err)
	}
}

// TestRefusalDisclosesNothing is a security property, not a formatting nit. An
// error naming the expected value is a working instruction for defeating the
// gate.
func TestRefusalDisclosesNothing(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<41))
	defer srv.Close()
	_, err := newTestClientErr(t, srv, Config{Connections: 1})
	if err == nil {
		t.Fatal("want a refusal")
	}
	msg := err.Error()
	want := "--transport=userspace requires a FlashBlade; refusing to continue"
	if !strings.Contains(msg, want) {
		t.Fatalf("message = %q, want it to contain %q", msg, want)
	}
	for _, leak := range []string{"70368744177664", "2199023255552", "max file size", "maxfilesize", "expected"} {
		if strings.Contains(strings.ToLower(msg), strings.ToLower(leak)) {
			t.Errorf("refusal message leaks %q: %q", leak, msg)
		}
	}
}

// TestGateRunsBeforeThePoolIsBuilt is the property that makes this safe to ship.
// A non-Pure server must see one connection and a handful of cheap metadata ops,
// which is strictly gentler than what a single mount would have done.
func TestGateRunsBeforeThePoolIsBuilt(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<41))
	defer srv.Close()
	_, _ = newTestClientErr(t, srv, Config{Connections: 64})
	if n := srv.ConnectionCount(); n != 1 {
		t.Fatalf("a refused server saw %d connections, want exactly 1", n)
	}
}

func TestUnsafeOverrideAllowsANonPureServer(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<41))
	defer srv.Close()
	var logged []string
	cl, err := newTestClientErr(t, srv, Config{
		Connections:        2,
		AllowNonPureServer: true,
		Log:                func(s string) { logged = append(logged, s) },
	})
	if err != nil {
		t.Fatalf("the override must permit a non-Pure server: %v", err)
	}
	defer cl.Close()

	joined := strings.Join(logged, "\n")
	if !strings.Contains(joined, "WARNING") {
		t.Error("the override must warn prominently on every run")
	}
	if !strings.Contains(joined, "2199023255552") {
		t.Error("the warning must name the detected max file size; that is the point of taking the override")
	}
}

// TestObservedValueGoesToTheLogNotTheError keeps the diagnosability the opaque
// refusal trades away, without putting it where an attacker reads it.
func TestObservedValueGoesToTheLogNotTheError(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<41))
	defer srv.Close()
	var logged []string
	_, err := newTestClientErr(t, srv, Config{Connections: 1, Log: func(s string) { logged = append(logged, s) }})
	if err == nil {
		t.Fatal("want a refusal")
	}
	if !strings.Contains(strings.Join(logged, "\n"), "2199023255552") {
		t.Error("the observed value must reach the log so a support engineer can diagnose a firmware bump")
	}
}

func TestRootResolvesTheExportPath(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46))
	srv.AddTree(map[string][]fakeEntry{
		"/":             {{Name: "exports", FH: "e", IsDir: true}},
		"/exports":      {{Name: "data", FH: "d", IsDir: true}},
		"/exports/data": {},
	})
	defer srv.Close()

	cl, err := newTestClientErr(t, srv, Config{Connections: 1, Export: "/exports/data"})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()

	r, err := cl.Root()
	if err != nil {
		t.Fatal(err)
	}
	if string(r.FH) != "d" {
		t.Fatalf("Root().FH = %q, want the filehandle of /exports/data", r.FH)
	}
	if r.Path != "/exports/data" {
		t.Fatalf("Root().Path = %q", r.Path)
	}
}

// TestSetACLRoundTrip is the phase 1 spike, end to end.
func TestSetACLRoundTrip(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46))
	srv.AddTree(map[string][]fakeEntry{"/": {{Name: "f", FH: "f"}}})
	defer srv.Close()

	cl, err := newTestClientErr(t, srv, Config{Connections: 1, Export: "/"})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()

	want, err := nfs4acl.ParseACLSpec([]string{"A::OWNER@:rwatTnNcCy"})
	if err != nil {
		t.Fatal(err)
	}
	ref := transport.Ref{Path: "/f", FH: []byte("f")}
	if err := cl.SetACL(ref, want); err != nil {
		t.Fatal(err)
	}
	if got := srv.ACLFor("f"); !bytes.Equal(got, want) {
		t.Fatalf("server stored %x, want %x — both transports must write identical ACE bytes", got, want)
	}
}

func TestServerIdentityIsRecorded(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46), withImplID("purestorage.com", "Purity//FB"))
	defer srv.Close()
	cl, _ := newTestClientErr(t, srv, Config{Connections: 1})
	defer cl.Close()
	id := cl.ServerIdentity()
	if id.ImplName != "Purity//FB" {
		t.Errorf("ImplName = %q, want it recorded whether or not it is used as a signal", id.ImplName)
	}
}

// TestRetryBudgetIsExhausted proves there is no unbounded loop. A server stuck
// returning DELAY must eventually fail the object rather than spin forever.
func TestRetryBudgetIsExhausted(t *testing.T) {
	srv := startFakeServer(t)
	defer srv.Close()
	// The tree is not decoration. Without it PUTFH answers NFS4ERR_STALE for an
	// unknown filehandle, the COMPOUND ends at that operation, and SETATTR is
	// never decoded — so CallCount(opSETATTR) would be 0 no matter how the retry
	// budget behaves, and this test would be asserting nothing about its subject.
	srv.AddTree(map[string][]fakeEntry{"/": {{Name: "f", FH: "f"}}})
	srv.InjectN(opSETATTR, NFS4ERR_DELAY, 100)

	cl := newTestClient(t, srv, Config{RetryBudget: 3, RetryBaseDelay: time.Millisecond})
	defer cl.Close()

	err := cl.SetACL(transport.Ref{Path: "/f", FH: []byte("f")}, []byte{0, 0, 0, 0})
	if err == nil {
		t.Fatal("want an error after the retry budget is exhausted, got nil")
	}
	if srv.CallCount(opSETATTR) != 3 {
		t.Fatalf("SETATTR attempted %d times, want exactly the budget of 3", srv.CallCount(opSETATTR))
	}
}

// TestStaleFilehandleRecoversByPath is what Ref.Path is for. The filehandle is
// dead but the path is still valid, so recovery is a LOOKUP from root.
func TestStaleFilehandleRecoversByPath(t *testing.T) {
	srv := startFakeServer(t)
	defer srv.Close()
	srv.AddTree(map[string][]fakeEntry{"/": {{Name: "f", FH: "f-new"}}})
	srv.InjectOnce(opSETATTR, NFS4ERR_STALE)

	cl := newTestClient(t, srv, Config{RetryBudget: 3, RetryBaseDelay: time.Millisecond})
	defer cl.Close()

	if err := cl.SetACL(transport.Ref{Path: "/f", FH: []byte("f-old")}, []byte{0, 0, 0, 0}); err != nil {
		t.Fatalf("SetACL should have recovered by looking the path up again: %v", err)
	}
	if srv.LookupCount("f") == 0 {
		t.Error("no LOOKUP was issued; recovery must re-resolve the path, not retry the dead filehandle")
	}
}

func TestReadDirReturnsFilehandlesAndModes(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46))
	srv.AddTree(map[string][]fakeEntry{
		"/": {
			{Name: "b.txt", FH: "fb", Mode: 0o644, FSID: 7},
			{Name: "a.dir", FH: "fa", Mode: 0o755, FSID: 7, IsDir: true},
			{Name: "c.lnk", FH: "fc", IsSymlink: true, FSID: 7},
		},
	})
	defer srv.Close()

	cl, _ := newTestClientErr(t, srv, Config{Connections: 1, Export: "/"})
	defer cl.Close()

	root, _ := cl.Root()
	ents, err := cl.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 3 {
		t.Fatalf("got %d entries, want 3", len(ents))
	}
	// Sorted by name, matching os.ReadDir, so log and checkpoint output does not
	// depend on which transport produced it.
	if ents[0].Name != "a.dir" || ents[1].Name != "b.txt" || ents[2].Name != "c.lnk" {
		t.Fatalf("entries are not sorted by name: %v %v %v", ents[0].Name, ents[1].Name, ents[2].Name)
	}
	if string(ents[1].Ref.FH) != "fb" {
		t.Errorf("b.txt FH = %q; READDIR must return it so steady state issues no LOOKUP", ents[1].Ref.FH)
	}
	if ents[1].Mode != 0o644 {
		t.Errorf("b.txt Mode = 0%o, want 0644", ents[1].Mode)
	}
	if !ents[0].IsDir {
		t.Error("a.dir: IsDir = false")
	}
	if !ents[2].IsSymlink || ents[2].IsDir {
		t.Error("c.lnk must be tagged a symlink and never a directory")
	}
	if ents[0].FSID != 7 {
		t.Errorf("FSID = %d, want 7", ents[0].FSID)
	}
	if srv.LookupCount("b.txt") != 0 {
		t.Error("a LOOKUP was issued for an entry READDIR already described")
	}
}

func TestReadDirSetACLFoldsSetAttrIntoReadDir(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46))
	srv.AddTree(map[string][]fakeEntry{
		"/": {
			{Name: "a.txt", FH: "fa", Mode: 0o644, FSID: 7},
			{Name: "sub", FH: "fs", Mode: 0o755, FSID: 7, IsDir: true},
		},
	})
	defer srv.Close()

	cl, _ := newTestClientErr(t, srv, Config{Connections: 1, Export: "/"})
	defer cl.Close()

	root, _ := cl.Root()
	acl := nfs4acl.Encode([]nfs4acl.ACE{
		{Type: nfs4acl.TypeAllow, Who: "EVERYONE@", Mask: nfs4acl.MaskReadData | nfs4acl.MaskExecute},
	})

	ents, applied, err := cl.ReadDirSetACL(root, acl)
	if err != nil {
		t.Fatal(err)
	}
	if !applied {
		t.Error("ACL should have been applied by the folded SETATTR")
	}
	if len(ents) != 2 {
		t.Fatalf("got %d entries, want 2", len(ents))
	}
	if ents[0].Name != "a.txt" || ents[1].Name != "sub" {
		t.Fatalf("entries not sorted: %v %v", ents[0].Name, ents[1].Name)
	}

	stored := srv.ACLFor("/")
	if stored == nil {
		t.Fatal("fake server has no ACL stored — SETATTR was not executed")
	}
	if !bytes.Equal(stored, acl) {
		t.Errorf("stored ACL %x differs from sent %x", stored, acl)
	}
}

func TestReadDirSetACLNilACLSkipsSetAttr(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46))
	srv.AddTree(map[string][]fakeEntry{
		"/": {{Name: "f", FH: "h", Mode: 0o644}},
	})
	defer srv.Close()

	cl, _ := newTestClientErr(t, srv, Config{Connections: 1, Export: "/"})
	defer cl.Close()

	root, _ := cl.Root()
	ents, applied, err := cl.ReadDirSetACL(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if applied {
		t.Error("ACL should not be applied when acl is nil")
	}
	if len(ents) != 1 {
		t.Fatalf("got %d entries, want 1", len(ents))
	}
}

func TestReadDirSetACLMultiPageAppliesOnce(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46))
	entries := make([]fakeEntry, 200)
	for i := range entries {
		entries[i] = fakeEntry{Name: fmt.Sprintf("f%03d", i), FH: fmt.Sprintf("h%03d", i), Mode: 0o644}
	}
	srv.AddTree(map[string][]fakeEntry{"/": entries})
	srv.SetReaddirPageSize(80)
	defer srv.Close()

	cl, _ := newTestClientErr(t, srv, Config{Connections: 1, Export: "/"})
	defer cl.Close()

	root, _ := cl.Root()
	acl := nfs4acl.Encode([]nfs4acl.ACE{
		{Type: nfs4acl.TypeAllow, Who: "EVERYONE@", Mask: nfs4acl.MaskReadData},
	})

	ents, applied, err := cl.ReadDirSetACL(root, acl)
	if err != nil {
		t.Fatal(err)
	}
	if !applied {
		t.Error("ACL should have been applied on the first page")
	}
	if len(ents) != 200 {
		t.Fatalf("got %d entries, want 200", len(ents))
	}
}

func TestReadDirFollowsTheCookieChain(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46))
	// 250 entries with the fake capped at 100 per reply forces three round trips.
	entries := make([]fakeEntry, 250)
	for i := range entries {
		entries[i] = fakeEntry{Name: fmt.Sprintf("f%03d", i), FH: fmt.Sprintf("h%03d", i), Mode: 0o644}
	}
	srv.AddTree(map[string][]fakeEntry{"/": entries})
	srv.SetReaddirPageSize(100)
	defer srv.Close()

	cl, _ := newTestClientErr(t, srv, Config{Connections: 1, Export: "/"})
	defer cl.Close()
	root, _ := cl.Root()
	got, err := cl.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 250 {
		t.Fatalf("got %d entries, want 250 — the cookie chain was not followed to the end", len(got))
	}
}

func TestReadDirGrowsTheBufferOnTOOSMALL(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46))
	srv.AddTree(map[string][]fakeEntry{"/": {{Name: "f", FH: "h", Mode: 0o644}}})
	srv.InjectOnce(opREADDIR, NFS4ERR_TOOSMALL)
	defer srv.Close()

	cl, _ := newTestClientErr(t, srv, Config{Connections: 1, Export: "/", RetryBudget: 3})
	defer cl.Close()
	root, _ := cl.Root()
	got, err := cl.ReadDir(root)
	if err != nil {
		t.Fatalf("TOOSMALL must grow the buffer and retry the same cookie: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
}

func TestReadDirRestartsWhenTheVerifierChanges(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46))
	entries := make([]fakeEntry, 150)
	for i := range entries {
		entries[i] = fakeEntry{Name: fmt.Sprintf("f%03d", i), FH: fmt.Sprintf("h%03d", i)}
	}
	srv.AddTree(map[string][]fakeEntry{"/": entries})
	srv.SetReaddirPageSize(100)
	srv.ChangeVerifierAfter(1) // the directory changes mid-enumeration
	defer srv.Close()

	cl, _ := newTestClientErr(t, srv, Config{Connections: 1, Export: "/", RetryBudget: 3})
	defer cl.Close()
	root, _ := cl.Root()
	got, err := cl.ReadDir(root)
	if err != nil {
		t.Fatalf("a changed verifier must restart the directory from cookie 0: %v", err)
	}
	if len(got) != 150 {
		t.Fatalf("got %d entries after the restart, want 150", len(got))
	}
	// A restart that does not clear what it already collected duplicates entries.
	seen := map[string]bool{}
	for _, e := range got {
		if seen[e.Name] {
			t.Fatalf("duplicate entry %q: the restart did not discard the partial listing", e.Name)
		}
		seen[e.Name] = true
	}
}

func TestReadDirNeverReportsASymlinkAsADirectory(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46))
	srv.AddTree(map[string][]fakeEntry{
		"/": {{Name: "link", FH: "link-fh", IsDir: true, IsSymlink: true}},
	})
	defer srv.Close()

	cl, _ := newTestClientErr(t, srv, Config{Connections: 1, Export: "/"})
	defer cl.Close()
	root, _ := cl.Root()
	got, err := cl.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	// IsDir and IsSymlink are deliberately not mutually exclusive at the
	// transport boundary. NF4LNK must win so a server reporting both can never
	// induce the walk to descend through a link; this must not be simplified into
	// a plain symlink test, which would leave that ordering untested.
	if !got[0].IsSymlink {
		t.Error("link: IsSymlink = false")
	}
	if got[0].IsDir {
		t.Error("link: IsDir = true; a symlink must never be reported as a directory")
	}
}

// TestReadDirLeavesAttrsUnknownWhenTheServerOmitsMode is the test that was
// missing when this transport landed: every other ReadDir test runs against a
// fake that answers the full attribute request, so a ReadDir that assigned
// AttrsKnown = true unconditionally passed all of them.
//
// RFC 8881 section 18.23.3 lets a READDIR reply carry a subset of
// rd_attr_request. AttrsKnown must therefore be derived from what came back,
// never from what was asked for. False is always safe: the walk falls back to
// Stat. A wrong true is not, because Mode is then zero and the walk reads that
// as mode 0000 on a real object.
func TestReadDirLeavesAttrsUnknownWhenTheServerOmitsMode(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46))
	srv.AddTree(map[string][]fakeEntry{
		"/": {{Name: "f.txt", FH: "fh-f", Mode: 0o644, FSID: 7}},
	})
	srv.OmitReaddirAttrs(fattr4Mode)
	defer srv.Close()

	cl := newTestClient(t, srv, Config{Connections: 1, Export: "/"})
	root, err := cl.Root()
	if err != nil {
		t.Fatal(err)
	}
	got, err := cl.ReadDir(root)
	if err != nil {
		t.Fatalf("a reply without FATTR4_MODE is legal and must not fail enumeration: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	if got[0].AttrsKnown {
		t.Error("AttrsKnown = true after the server omitted FATTR4_MODE; the walk would trust a zero mode")
	}
	if got[0].Mode != 0 || got[0].FSID != 0 {
		t.Errorf("Mode = 0%o, FSID = %d; both must stay zero when AttrsKnown is false", got[0].Mode, got[0].FSID)
	}
	// The filehandle and the type are not optional: ReadDir errors out without
	// them, so they must still be present and correct here.
	if string(got[0].Ref.FH) != "fh-f" {
		t.Errorf("Ref.FH = %q, want %q", got[0].Ref.FH, "fh-f")
	}
	// AttrsKnown false means "not asked", never "lookup failed", so the
	// fallback has to work. This is what makes false the safe answer.
	attr, err := cl.Stat(got[0].Ref)
	if err != nil {
		t.Fatalf("Stat must succeed on the entry ReadDir could not fully describe: %v", err)
	}
	if attr.Mode != 0o644 {
		t.Errorf("Stat Mode = 0%o, want 0644", attr.Mode)
	}
	if attr.Kind != transport.KindRegular {
		t.Errorf("Stat Kind = %d, want KindRegular (%d)", attr.Kind, transport.KindRegular)
	}
}

// TestReadDirLeavesAttrsUnknownWhenTheServerOmitsFSID is the same property for
// the other half of the pair. Both are needed: AttrsKnown covers Mode and FSID
// together, so a condition testing only one of the two bits still lets the
// other be trusted when it is absent.
func TestReadDirLeavesAttrsUnknownWhenTheServerOmitsFSID(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46))
	srv.AddTree(map[string][]fakeEntry{
		"/": {{Name: "f.txt", FH: "fh-f", Mode: 0o644, FSID: 7}},
	})
	srv.OmitReaddirAttrs(fattr4FSID)
	defer srv.Close()

	cl := newTestClient(t, srv, Config{Connections: 1, Export: "/"})
	root, err := cl.Root()
	if err != nil {
		t.Fatal(err)
	}
	got, err := cl.ReadDir(root)
	if err != nil {
		t.Fatalf("a reply without FATTR4_FSID is legal and must not fail enumeration: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	if got[0].AttrsKnown {
		t.Error("AttrsKnown = true after the server omitted FATTR4_FSID; --one-filesystem would read a zero FSID as a different filesystem")
	}
	if got[0].Mode != 0 || got[0].FSID != 0 {
		t.Errorf("Mode = 0%o, FSID = %d; both must stay zero when AttrsKnown is false", got[0].Mode, got[0].FSID)
	}
}

// TestReadDirReportsAttrsKnownWhenBothArrive is the positive half of the pair.
// Without it, the two tests above are satisfied by a ReadDir that hardcodes
// AttrsKnown = false, which is safe but silently reintroduces one stat per
// object — the cost this transport exists to remove.
func TestReadDirReportsAttrsKnownWhenBothArrive(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46))
	srv.AddTree(map[string][]fakeEntry{
		"/": {{Name: "f.txt", FH: "fh-f", Mode: 0o640, FSID: 9}},
	})
	defer srv.Close()

	cl := newTestClient(t, srv, Config{Connections: 1, Export: "/"})
	root, err := cl.Root()
	if err != nil {
		t.Fatal(err)
	}
	got, err := cl.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	if !got[0].AttrsKnown {
		t.Fatal("AttrsKnown = false although the server returned both FATTR4_MODE and FATTR4_FSID; the walk would stat every object")
	}
	if got[0].Mode != 0o640 {
		t.Errorf("Mode = 0%o, want 0640", got[0].Mode)
	}
	if got[0].FSID != 9 {
		t.Errorf("FSID = %d, want 9", got[0].FSID)
	}
}

// TestReadDirSkipsDotAndDotDot is not cosmetic. path.Join(parent, "..") yields
// the PARENT with IsDir true, and walk.go gates its descent on IsDir alone, so a
// single such entry is either unbounded recursion or a subtree re-walked from a
// shallower point. Only this transport is exposed: os.ReadDir never returns them,
// so the kernel path is structurally immune and no shared test can catch it.
func TestReadDirSkipsDotAndDotDot(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46))
	srv.AddTree(map[string][]fakeEntry{
		"/":    {{Name: "sub", IsDir: true}},
		"/sub": {{Name: ".", IsDir: true}, {Name: "..", IsDir: true}, {Name: "real.txt", FH: "freal", Mode: 0o644}},
	})
	defer srv.Close()

	cl, err := newTestClientErr(t, srv, Config{Connections: 1, Export: "/", Target: "/sub", AllowNonPureServer: true})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()

	root, err := cl.Root()
	if err != nil {
		t.Fatal(err)
	}
	got, err := cl.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range got {
		if e.Name == "." || e.Name == ".." {
			t.Errorf("ReadDir returned %q; the walk would descend it as a directory", e.Name)
		}
	}
	if len(got) != 1 || got[0].Name != "real.txt" {
		names := make([]string, len(got))
		for i, e := range got {
			names[i] = e.Name
		}
		t.Fatalf("entries = %v, want exactly [real.txt]", names)
	}
}

// TestReadDirMakesProgressThroughAPageOfOnlyDotEntries pins the reason the skip
// counts raw entries separately. A non-EOF page the server did advance through
// must not be mistaken for an empty reply just because everything in it was
// filtered out.
func TestReadDirMakesProgressThroughAPageOfOnlyDotEntries(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46))
	srv.AddTree(map[string][]fakeEntry{
		"/":    {{Name: "sub", IsDir: true}},
		"/sub": {{Name: ".", IsDir: true}, {Name: "..", IsDir: true}, {Name: "real.txt", FH: "freal", Mode: 0o644}},
	})
	srv.SetReaddirPageSize(2) // the first page is "." and ".." and nothing else
	defer srv.Close()

	cl, err := newTestClientErr(t, srv, Config{Connections: 1, Export: "/", Target: "/sub", AllowNonPureServer: true})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	root, err := cl.Root()
	if err != nil {
		t.Fatal(err)
	}
	got, err := cl.ReadDir(root)
	if err != nil {
		t.Fatalf("a page holding only . and .. is progress, not an empty reply: %v", err)
	}
	if len(got) != 1 || got[0].Name != "real.txt" {
		t.Fatalf("got %d entries, want exactly [real.txt]", len(got))
	}
}

// TestReadDirLeavesHeadroomForCompoundOverhead is the whole finding: rd_maxcount
// bounds READDIR4resok, ca_maxresponsesize bounds the entire reply, and growing
// the former to the latter asks for a reply that legitimately exceeds it once
// SEQUENCE and PUTFH are counted. A strict server answers NFS4ERR_REP_TOO_BIG.
func TestReadDirLeavesHeadroomForCompoundOverhead(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46), withMaxChannelSizes(0, 96<<10))
	srv.AddTree(map[string][]fakeEntry{"/": {{Name: "f", FH: "h", Mode: 0o644}}})
	srv.InjectOnce(opREADDIR, NFS4ERR_TOOSMALL) // force one growth step, up to the cap
	defer srv.Close()

	cl, _ := newTestClientErr(t, srv, Config{Connections: 1, Export: "/", RetryBudget: 3, AllowNonPureServer: true})
	defer cl.Close()
	root, _ := cl.Root()
	if _, err := cl.ReadDir(root); err != nil {
		t.Fatal(err)
	}

	maxResponse := cl.pool[0].session.ChannelAttrs().MaxResponseSize
	counts := srv.ReaddirMaxcounts()
	if len(counts) == 0 {
		t.Fatal("the fake recorded no READDIR")
	}
	for _, c := range counts {
		if c > maxResponse-readdirCompoundOverhead {
			t.Errorf("rd_maxcount %d exceeds ca_maxresponsesize %d less the %d bytes of SEQUENCE, PUTFH and framing overhead the same reply must also carry",
				c, maxResponse, readdirCompoundOverhead)
		}
	}
	if got, want := counts[len(counts)-1], maxResponse-readdirCompoundOverhead; got != want {
		t.Errorf("rd_maxcount grew to %d, want exactly %d: the cap must be ca_maxresponsesize (%d) minus the compound overhead, not ca_maxresponsesize itself",
			got, want, maxResponse)
	}
}

// TestReadDirShrinksOnRepTooBig covers a server that accounts the reply against
// ca_maxresponsesize more strictly than the headroom above allows for. Shrinking
// is the only response that converges; without it the directory fails.
func TestReadDirShrinksOnRepTooBig(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46), withMaxChannelSizes(0, 96<<10))
	srv.AddTree(map[string][]fakeEntry{"/": {{Name: "f", FH: "h", Mode: 0o644}}})
	srv.InjectOnce(opREADDIR, NFS4ERR_REP_TOO_BIG)
	defer srv.Close()

	cl, _ := newTestClientErr(t, srv, Config{Connections: 1, Export: "/", RetryBudget: 3, AllowNonPureServer: true})
	defer cl.Close()
	root, _ := cl.Root()
	got, err := cl.ReadDir(root)
	if err != nil {
		t.Fatalf("NFS4ERR_REP_TOO_BIG must shrink rd_maxcount and retry the same cookie, not fail the directory: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}

	counts := srv.ReaddirMaxcounts()
	if len(counts) != 1 {
		t.Fatalf("the fake answered %d READDIRs, want 1 (the injected one never reaches it)", len(counts))
	}
	if want := uint32(64<<10) / 2; counts[0] != want {
		t.Errorf("rd_maxcount after REP_TOO_BIG = %d, want %d: the retry must ask for a smaller reply than the one that was refused", counts[0], want)
	}
}

// TestServerAddressDefaultsTheNFSPort covers the promise --server has always made
// in its own help text. A bare IP is the first thing an operator types.
func TestServerAddressDefaultsTheNFSPort(t *testing.T) {
	for _, tc := range []struct {
		in, want, why string
	}{
		{"192.0.2.50", "192.0.2.50:2049", "a bare IPv4 address must get the default NFS port"},
		{"192.0.2.50:2049", "192.0.2.50:2049", "an explicit default port must survive unchanged"},
		{"192.0.2.50:20049", "192.0.2.50:20049", "a non-default explicit port must be preserved"},
		{"fb-mgmt.example.com", "fb-mgmt.example.com:2049", "a bare hostname must get the default port"},
		{"::1", "[::1]:2049", "a bare IPv6 literal is all colons and must not be read as host:port; JoinHostPort supplies the brackets"},
		{"2001:db8::1", "[2001:db8::1]:2049", "a bare IPv6 literal must be bracketed, not concatenated"},
		{"[::1]:2049", "[::1]:2049", "a bracketed IPv6 address with a port must survive unchanged"},
		{"[::1]", "[::1]:2049", "a bracketed IPv6 address with no port must not acquire a second pair of brackets"},
		{"192.0.2.50:", "192.0.2.50:2049", "an empty port is a missing port"},
	} {
		got, err := normalizeServerAddress(tc.in)
		if err != nil {
			t.Errorf("normalizeServerAddress(%q) = %v; %s", tc.in, err, tc.why)
			continue
		}
		if got != tc.want {
			t.Errorf("normalizeServerAddress(%q) = %q, want %q: %s", tc.in, got, tc.want, tc.why)
		}
	}
}

func TestServerAddressRejectsAnEmptyHost(t *testing.T) {
	for _, in := range []string{":2049", ":"} {
		if got, err := normalizeServerAddress(in); err == nil {
			t.Errorf("normalizeServerAddress(%q) = %q, want an error: a port with no host names no server", in, got)
		}
	}
}

func TestNormalizeConfigDefaultsTheServerPort(t *testing.T) {
	cfg, err := normalizeConfig(Config{Server: "192.0.2.50", Export: "/e"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server != "192.0.2.50:2049" {
		t.Errorf("cfg.Server = %q, want %q", cfg.Server, "192.0.2.50:2049")
	}

	// An empty Server is legitimate here and nowhere else: every test in this
	// file reaches newClientWithDialer with an injected dialer and no address.
	cfg, err = normalizeConfig(Config{Export: "/e"})
	if err != nil {
		t.Fatalf("an injected dialer needs no address: %v", err)
	}
	if cfg.Server != "" {
		t.Errorf("cfg.Server = %q, want it left empty", cfg.Server)
	}
}

// TestNewDialsTheDefaultedPort is the one that would have caught the original
// defect. The dialer captures the address before normalizeConfig runs, so
// normalizing only cfg.Server would leave a bare host failing at net.Dial with
// "missing port in address" -- which is exactly what it did.
func TestNewDialsTheDefaultedPort(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// 127.0.0.1:2049 is either refused or answered by something that is not a
	// FlashBlade. Either way the assertion holds: what must never come back is a
	// complaint about the address itself.
	_, err := New(ctx, Config{Server: "127.0.0.1", Export: "/e", RPCTimeout: 2 * time.Second})
	if err == nil {
		t.Skip("something is listening on 127.0.0.1:2049 and completed a session; nothing to assert")
	}
	for _, addressComplaint := range []string{"missing port in address", "too many colons"} {
		if strings.Contains(err.Error(), addressComplaint) {
			t.Fatalf("New(%q) failed with %v: the default port never reached the dialer", "127.0.0.1", err)
		}
	}
}

// TestReadDirTerminatesWhenNoReplySizeSatisfiesTheServer is the pair-termination
// property that neither TOOSMALL nor REP_TOO_BIG has on its own. Each arm's hard
// exit is a boundary of the legal range -- TOOSMALL fails only AT the cap,
// REP_TOO_BIG only AT the floor -- so a server that refuses one way below some
// crossover and the other way above it keeps rd_maxcount oscillating strictly
// between the two boundaries and neither exit is ever reached. That is not a slow
// enumeration, it is a walk worker spinning READDIRs on one directory forever with
// no error and no timeout.
//
// The window here is deliberately inverted: nothing at all satisfies a server that
// wants more than 60000 bytes' worth of room and refuses to send more than 40000.
func TestReadDirTerminatesWhenNoReplySizeSatisfiesTheServer(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46), withMaxChannelSizes(0, 96<<10))
	srv.AddTree(map[string][]fakeEntry{"/": {{Name: "f", FH: "h", Mode: 0o644}}})
	srv.SetReaddirSizeWindow(60000, 40000)
	defer srv.Close()

	cl, _ := newTestClientErr(t, srv, Config{Connections: 1, Export: "/", RetryBudget: 3, AllowNonPureServer: true})
	defer cl.Close()
	root, _ := cl.Root()

	type result struct {
		ents []transport.Dirent
		err  error
	}
	done := make(chan result, 1)
	go func() {
		ents, err := cl.ReadDir(root)
		done <- result{ents, err}
	}()

	select {
	case got := <-done:
		if got.err == nil {
			t.Fatalf("ReadDir succeeded with %d entries; no rd_maxcount satisfies this server", len(got.ents))
		}
		// The message has to say that BOTH refusals were seen. "TOOSMALL at the
		// largest reply allowed" would be a lie here: the largest allowed reply was
		// never tried, REP_TOO_BIG took it off the table.
		for _, want := range []string{"NFS4ERR_TOOSMALL", "NFS4ERR_REP_TOO_BIG"} {
			if !strings.Contains(got.err.Error(), want) {
				t.Errorf("error does not name %s, so it does not say why there is nothing left to try: %v", want, got.err)
			}
		}
		if n := len(srv.ReaddirMaxcounts()); n > 8 {
			t.Errorf("the fake answered %d READDIRs before ReadDir gave up, want a handful: the resize must converge, not walk the whole range", n)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ReadDir did not terminate: NFS4ERR_TOOSMALL grew rd_maxcount back to a size NFS4ERR_REP_TOO_BIG had already refused, and the two recoveries cycled without bound")
	}
}

// TestRootPathIsTheTargetVerbatim pins walk.Prepass's precondition for picking up
// the root filehandle. Prepass does
//
//	if r, err := o.Transport.Root(); err == nil && r.Path == root { rootRef = r }
//
// so the optimization is lost SILENTLY -- no error, just a LOOKUP per root and a
// nil FH threaded onward -- if the client's stored root path is not byte-identical
// to the string main.go handed in. That string is filepath.Clean's output and this
// is path.Clean's, which agree on every absolute slash-separated path, so the only
// way they can part company is a future change on one side. This covers the branch
// the existing Root test does not: a target strictly below the export, which is
// the ordinary shape of a permissionreset run.
func TestRootPathIsTheTargetVerbatim(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46))
	srv.AddTree(map[string][]fakeEntry{
		"/":                 {{Name: "exports", IsDir: true}},
		"/exports":          {{Name: "data", FH: "d", IsDir: true}},
		"/exports/data":     {{Name: "sub", FH: "s", IsDir: true}},
		"/exports/data/sub": {},
	})
	defer srv.Close()

	const target = "/exports/data/sub"
	cl, err := newTestClientErr(t, srv, Config{Connections: 1, Export: "/exports/data", Target: target})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()

	r, err := cl.Root()
	if err != nil {
		t.Fatal(err)
	}
	if r.Path != target {
		t.Errorf("Root().Path = %q, want %q byte for byte: walk.Prepass compares it against the target string the CLI passed and silently drops the root filehandle when they differ", r.Path, target)
	}
	if len(r.FH) == 0 {
		t.Error("Root().FH is empty, so there is no root filehandle for the walk to pick up")
	}
}

// TestTargetBelowTheExportResolvesAgainstTheExportRoot is the regression test
// for Defect 1. Before the fix, --transport=userspace could not address ANY path
// below the export root: resolvePath sent PUTROOTFH plus one LOOKUP per
// component, and a FlashBlade refuses the LOOKUP that follows the
// pseudo-filesystem crossing inside one COMPOUND. Every subtree target — the
// tool's normal case — died at startup with NFS4ERR_NOENT.
//
// The fake now models that refusal by default, so this test fails against the
// old resolvePath. It is a whole-client test rather than a unit test of
// resolvePath because the bug was in which filehandle the resolution STARTED
// from, and only Init knows the export root.
func TestTargetBelowTheExportResolvesAgainstTheExportRoot(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46))
	srv.AddTree(map[string][]fakeEntry{
		"/":                    {{Name: "fs", FH: "fs", IsDir: true}},
		"/fs":                  {{Name: "team", FH: "team", IsDir: true}},
		"/fs/team":             {{Name: "project", FH: "proj", IsDir: true}},
		"/fs/team/project":     {{Name: "deep", FH: "deep", IsDir: true}},
		"/fs/team/project/dee": {},
	})
	defer srv.Close()

	cl, err := newTestClientErr(t, srv, Config{
		Connections: 1, Export: "/fs", Target: "/fs/team/project",
	})
	if err != nil {
		t.Fatalf("a target below the export root must resolve: %v", err)
	}
	defer cl.Close()

	r, err := cl.Root()
	if err != nil {
		t.Fatal(err)
	}
	if string(r.FH) != "proj" {
		t.Fatalf("Root().FH = %q, want %q — the target must resolve to its own "+
			"filehandle, not the export root's", r.FH, "proj")
	}
	if r.Path != "/fs/team/project" {
		t.Fatalf("Root().Path = %q, want the target path verbatim", r.Path)
	}
}

// TestResolvingWithinTheExportTakesOneRoundTrip pins the cost of the fix. The
// export root's filehandle is already held after Init, so a target three
// components below it must be one COMPOUND, not three. Without this a future
// change could "fix" the crossing by walking component-by-component everywhere,
// which is correct and pays a round trip per directory level on every stale
// filehandle recovery.
func TestResolvingWithinTheExportTakesOneRoundTrip(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46))
	srv.AddTree(map[string][]fakeEntry{
		"/":         {{Name: "fs", FH: "fs", IsDir: true}},
		"/fs":       {{Name: "a", FH: "a", IsDir: true}},
		"/fs/a":     {{Name: "b", FH: "b", IsDir: true}},
		"/fs/a/b":   {{Name: "c", FH: "c", IsDir: true}},
		"/fs/a/b/c": {},
	})
	defer srv.Close()

	cl, err := newTestClientErr(t, srv, Config{Connections: 1, Export: "/fs"})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()

	before := srv.CallCount(uint32(xdr.OP_PUTFH))
	if _, err := cl.resolvePath(context.Background(), "/fs/a/b/c"); err != nil {
		t.Fatalf("resolve a path three levels below the export: %v", err)
	}
	if got := srv.CallCount(uint32(xdr.OP_PUTFH)) - before; got != 1 {
		t.Errorf("PUTFH operations = %d, want 1 — resolving within the export must "+
			"chain LOOKUPs in a single COMPOUND from the export root", got)
	}
	if got := srv.CallCount(uint32(xdr.OP_PUTROOTFH)); got != 1 {
		t.Errorf("PUTROOTFH operations = %d, want 1 (the export resolution at Init "+
			"only) — resolving within the export must not return to the pseudo-root", got)
	}
}

// ---------------------------------------------------------------------------
// The FlashArray refusal
// ---------------------------------------------------------------------------

const faImplName = "PureStorage FlashArray 6.10.6 202604291817+1e21401674a1-610jackfruit"

// TestGateRefusesAFlashArrayReportingAFlashBladeSize is the whole reason the
// impl_id check exists, so it is written as the exact hazard rather than as a
// generic refusal test.
//
// FA File raised its max file size at 6.6.10. An FA on an earlier release reports
// the same value a FlashBlade reports, so a size-only gate ADMITS it -- and then
// labels it PlatformFlashBlade, which is what feeds a FlashBlade-measured worker
// default to an array that saturates two orders lower. The size here is
// deliberately the accepted one: a refusal driven by the size would prove nothing.
func TestGateRefusesAFlashArrayReportingAFlashBladeSize(t *testing.T) {
	srv := startFakeServer(t,
		withMaxFileSize(1<<46),
		withImplID("purestorage.com", faImplName))
	defer srv.Close()

	cl, err := newTestClientErr(t, srv, Config{Connections: 1})
	if err == nil {
		cl.Close()
		t.Fatal("a FlashArray must be refused even when its max file size is one this gate accepts")
	}
	if !errors.Is(err, ErrFlashArrayNotSupported) {
		t.Fatalf("err = %v, want ErrFlashArrayNotSupported", err)
	}
	// A FlashArray IS a Pure array. Reporting "requires a FlashBlade" against one
	// sends the reader looking for a cabling or DNS mistake.
	if errors.Is(err, ErrNotPureServer) {
		t.Error("the FlashArray refusal must not also satisfy ErrNotPureServer")
	}
}

// TestFlashArrayRefusalDisclosesNothing holds the same security property as
// TestRefusalDisclosesNothing on the new path: neither the observed nor the
// expected max file size may appear.
func TestFlashArrayRefusalDisclosesNothing(t *testing.T) {
	srv := startFakeServer(t,
		withMaxFileSize(1<<46),
		withImplID("purestorage.com", faImplName))
	defer srv.Close()

	_, err := newTestClientErr(t, srv, Config{Connections: 1})
	if err == nil {
		t.Fatal("want a refusal")
	}
	msg := strings.ToLower(err.Error())
	for _, leak := range []string{"70368744177664", "1099511627776", "max file size", "maxfilesize"} {
		if strings.Contains(msg, strings.ToLower(leak)) {
			t.Errorf("refusal leaks %q: %q", leak, err.Error())
		}
	}
}

// TestFlashArrayUnderTheOverrideIsLabelledFlashArray covers the path the
// FlashArray protocol probes run on. The override lets the client through, but the
// platform it reports must be the truth: workerDefaults keys on exactly this
// value, so a FlashArray labelled flashblade would silently draw 1024 workers.
func TestFlashArrayUnderTheOverrideIsLabelledFlashArray(t *testing.T) {
	srv := startFakeServer(t,
		withMaxFileSize(1<<46),
		withImplID("purestorage.com", faImplName))
	defer srv.Close()

	cl, err := newTestClientErr(t, srv, Config{Connections: 1, AllowNonPureServer: true})
	if err != nil {
		t.Fatalf("the override must still admit a FlashArray: %v", err)
	}
	defer cl.Close()

	if got := cl.Platform(); got != PlatformFlashArray {
		t.Errorf("Platform() = %q, want %q: the accepted max file size must not relabel an array impl_id already identified", got, PlatformFlashArray)
	}
}

// TestAFlashBladeStillReportsFlashBlade guards the regression the guard above
// could introduce. FlashBlade supplies no impl_id at all, so the size table
// remains its only signal and must still name it.
func TestAFlashBladeStillReportsFlashBlade(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46))
	defer srv.Close()

	cl, err := newTestClientErr(t, srv, Config{Connections: 1})
	if err != nil {
		t.Fatalf("a FlashBlade must still be accepted: %v", err)
	}
	defer cl.Close()

	if got := cl.Platform(); got != PlatformFlashBlade {
		t.Errorf("Platform() = %q, want %q", got, PlatformFlashBlade)
	}
}

// TestANonPureImplIDStillFailsOnSize checks the ordering does not swallow the
// original gate: a server that names itself something else is judged on its size
// exactly as before.
func TestANonPureImplIDStillFailsOnSize(t *testing.T) {
	srv := startFakeServer(t,
		withMaxFileSize(1<<41),
		withImplID("example.com", "SomeOtherNFSServer 1.0"))
	defer srv.Close()

	_, err := newTestClientErr(t, srv, Config{Connections: 1})
	if !errors.Is(err, ErrNotPureServer) {
		t.Fatalf("err = %v, want ErrNotPureServer", err)
	}
}

// TestThePureDomainAloneDoesNotMeanFlashArray pins the detector to the product
// name rather than the domain.
//
// FlashBlade supplies no impl_id today, but if a future release starts to, it will
// almost certainly carry the same "purestorage.com" domain a FlashArray carries --
// the domain names the vendor, not the product. A gate keyed on the domain would
// then refuse every FlashBlade, which is the one platform this transport supports.
func TestThePureDomainAloneDoesNotMeanFlashArray(t *testing.T) {
	srv := startFakeServer(t,
		withMaxFileSize(1<<46),
		withImplID("purestorage.com", "PureStorage FlashBlade 4.8.0"))
	defer srv.Close()

	cl, err := newTestClientErr(t, srv, Config{Connections: 1})
	if err != nil {
		t.Fatalf("a FlashBlade naming itself in impl_id must still be accepted: %v", err)
	}
	defer cl.Close()

	if got := cl.Platform(); got != PlatformFlashBlade {
		t.Errorf("Platform() = %q, want %q", got, PlatformFlashBlade)
	}
}

func makeNumberedEntries(n int) []fakeEntry {
	entries := make([]fakeEntry, n)
	for i := range entries {
		entries[i] = fakeEntry{Name: fmt.Sprintf("f%03d", i), FH: fmt.Sprintf("h%03d", i), Mode: 0o644}
	}
	return entries
}

func TestReadDirLimitedBelowOnePage(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46))
	srv.AddTree(map[string][]fakeEntry{"/": makeNumberedEntries(10)})
	defer srv.Close()

	cl, _ := newTestClientErr(t, srv, Config{Connections: 1, Export: "/"})
	defer cl.Close()
	root, _ := cl.Root()

	got, truncated, err := cl.ReadDirLimited(root, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d entries, want 3", len(got))
	}
	if !truncated {
		t.Error("truncated = false, want true")
	}
	if got[0].Name != "f000" || got[1].Name != "f001" || got[2].Name != "f002" {
		t.Fatalf("entries not sorted by name: %v %v %v", got[0].Name, got[1].Name, got[2].Name)
	}
}

func TestReadDirLimitedLargerThanDir(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46))
	srv.AddTree(map[string][]fakeEntry{"/": makeNumberedEntries(10)})
	defer srv.Close()

	cl, _ := newTestClientErr(t, srv, Config{Connections: 1, Export: "/"})
	defer cl.Close()
	root, _ := cl.Root()

	got, truncated, err := cl.ReadDirLimited(root, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 10 {
		t.Fatalf("got %d entries, want 10", len(got))
	}
	if truncated {
		t.Error("truncated = true, want false")
	}
}

func TestReadDirLimitedExact(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46))
	srv.AddTree(map[string][]fakeEntry{"/": makeNumberedEntries(10)})
	defer srv.Close()

	cl, _ := newTestClientErr(t, srv, Config{Connections: 1, Export: "/"})
	defer cl.Close()
	root, _ := cl.Root()

	got, truncated, err := cl.ReadDirLimited(root, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 10 {
		t.Fatalf("got %d entries, want 10", len(got))
	}
	if truncated {
		t.Error("truncated = true, want false: the directory has exactly limit entries")
	}
}

func TestReadDirLimitedZeroEqualsReadDir(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46))
	srv.AddTree(map[string][]fakeEntry{"/": makeNumberedEntries(10)})
	defer srv.Close()

	cl, _ := newTestClientErr(t, srv, Config{Connections: 1, Export: "/"})
	defer cl.Close()
	root, _ := cl.Root()

	want, err := cl.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	got, truncated, err := cl.ReadDirLimited(root, 0)
	if err != nil {
		t.Fatal(err)
	}
	if truncated {
		t.Error("truncated = true, want false for limit <= 0")
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Name != want[i].Name {
			t.Fatalf("entry %d: got %q, want %q", i, got[i].Name, want[i].Name)
		}
	}
}

// TestReadDirLimitedAcrossPages forces the fake server's per-reply page size
// down to 4 so a limit of 6 lands mid-second-page: the first page yields 4
// entries, the second contributes 2 more before the cap stops appending, and
// the second page still has unconsumed entries and is not eof.
func TestReadDirLimitedAcrossPages(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46))
	srv.AddTree(map[string][]fakeEntry{"/": makeNumberedEntries(10)})
	srv.SetReaddirPageSize(4)
	defer srv.Close()

	cl, _ := newTestClientErr(t, srv, Config{Connections: 1, Export: "/"})
	defer cl.Close()
	root, _ := cl.Root()

	got, truncated, err := cl.ReadDirLimited(root, 6)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 6 {
		t.Fatalf("got %d entries, want 6", len(got))
	}
	if !truncated {
		t.Error("truncated = false, want true")
	}
	for i, ent := range got {
		want := fmt.Sprintf("f%03d", i)
		if ent.Name != want {
			t.Fatalf("entry %d: got %q, want %q", i, ent.Name, want)
		}
	}
}
