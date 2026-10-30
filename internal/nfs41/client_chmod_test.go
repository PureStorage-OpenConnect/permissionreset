package nfs41

import (
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// TestChmodUsesTheSuppliedFilehandle pins the plan's operation table for Chmod:
// "one COMPOUND: PUTFH + SETATTR(FATTR4_MODE)". An earlier revision resolved the
// path with PUTROOTFH + LOOKUP* + GETFH first, on the stated grounds that this
// reproduced the kernel's follow-symlink chmod. It does not: NFSv4 LOOKUP does
// not follow symbolic links, so the chain returned the same filehandle ref.FH
// already carried and cost one LOOKUP per path component on every object.
//
// LookupCount is the load-bearing assertion. Checking only that the mode landed
// would pass either way.
func TestChmodUsesTheSuppliedFilehandle(t *testing.T) {
	srv := startFakeServer(t)
	defer srv.Close()
	srv.AddTree(map[string][]fakeEntry{
		"/":        {{Name: "dir", FH: "dir-fh", IsDir: true}},
		"/dir":     {{Name: "sub", FH: "sub-fh", IsDir: true}},
		"/dir/sub": {{Name: "f", FH: "f-fh", Mode: 0o600}},
	})

	cl := newTestClient(t, srv, Config{})
	ref := transport.Ref{Path: "/dir/sub/f", FH: []byte("f-fh")}

	before := srv.LookupCount("f")
	if err := cl.Chmod(ref, 0o644); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	if got := srv.LookupCount("f") - before; got != 0 {
		t.Errorf("Chmod issued %d LOOKUP(f); want 0 — a supplied filehandle must be used directly", got)
	}
	for _, component := range []string{"dir", "sub"} {
		if n := srv.LookupCount(component); n != 0 {
			t.Errorf("Chmod issued %d LOOKUP(%s); want 0 — no root-anchored resolve per object", n, component)
		}
	}

	attr, err := cl.Stat(ref)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if attr.Mode != 0o644 {
		t.Errorf("mode = 0%o, want 0644", attr.Mode)
	}
}
