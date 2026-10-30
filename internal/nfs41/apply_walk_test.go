package nfs41

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/apply"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/spec"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/walk"
)

// TestWalkThenApplyIssuesNoLookups is the assertion Task 12b exists for.
//
// READDIR asks for FATTR4_FILEHANDLE, so every child's filehandle arrives with
// the listing. Before this task apply reconstructed transport.Ref from the path
// alone and threw that filehandle away, so each object was resolved again by
// PUTROOTFH + LOOKUP* + GETFH on its first touch. The run still produced the
// right answer, which is why the defect survived being written into the plan —
// only a round-trip count can see it.
//
// This drives the real chain: walk.Prepass over the userspace client, then
// apply.ProcessPath on each streamed entry through Entry.Ref(), which is exactly
// what cmd/permissionreset does. srv.LookupCount must be zero for every name in the
// tree, and the SETATTR count proves the ACLs really were written rather than
// the walk having quietly found nothing.
func TestWalkThenApplyIssuesNoLookups(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46))
	defer srv.Close()
	srv.AddTree(map[string][]fakeEntry{
		"/":        {{Name: "dir", FH: "dir-fh", Mode: 0o755, FSID: 7, IsDir: true}},
		"/dir":     {{Name: "sub", FH: "sub-fh", Mode: 0o755, FSID: 7, IsDir: true}},
		"/dir/sub": {{Name: "f", FH: "f-fh", Mode: 0o644, FSID: 7}},
	})

	cl, err := newTestClientErr(t, srv, Config{Connections: 1, Export: "/"})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer cl.Close()

	s := &spec.Spec{
		Protocol: "nfsv4",
		Default:  spec.RulePerms{ACL: []string{"A::OWNER@:rwatTnNcCy"}},
	}
	opts := apply.Options{}

	setattrBefore := srv.CallCount(opSETATTR)

	entries := make(chan walk.Entry, 64)
	var (
		mu      sync.Mutex
		applied []string
		errs    []error
	)
	var consumer sync.WaitGroup
	consumer.Add(1)
	go func() {
		defer consumer.Done()
		for e := range entries {
			r := apply.ProcessPath(cl, e.Ref(), e.IsDir, s, opts, e.Mode)
			mu.Lock()
			if r.Error != nil {
				errs = append(errs, r.Error)
			} else if r.Applied {
				applied = append(applied, e.Path)
			}
			mu.Unlock()
		}
	}()

	walkErrs := &walk.WalkErrors{}
	res := walk.Prepass("/", entries, walkErrs, walk.PrepassOptions{
		Transport: cl,
		Fix: func(ref transport.Ref) (bool, string, walk.FixResult) {
			out := apply.FixDirPerms(cl, ref, s, opts)
			return out.OK, out.Msg, walk.FixResult{Done: out.RealApply, Applied: out.Applied, LogMsg: out.Msg}
		},
		Workers: 4,
	})
	close(entries)
	consumer.Wait()

	if len(errs) != 0 {
		t.Fatalf("apply errors: %v", errs)
	}
	if res.Errors != 0 || walkErrs.Count() != 0 {
		t.Fatalf("walk reported %d fix errors and %d walk errors, want none", res.Errors, walkErrs.Count())
	}

	// Three directories and one file. If this drops, the walk stopped early and
	// the LOOKUP assertion below would be vacuously true.
	if len(applied) != 4 {
		t.Fatalf("applied to %d objects (%v), want 4", len(applied), applied)
	}
	if got := srv.CallCount(opSETATTR) - setattrBefore; got != 4 {
		t.Fatalf("SETATTR issued %d times, want 4 (one ACL write per object)", got)
	}

	for _, name := range []string{"dir", "sub", "f"} {
		if n := srv.LookupCount(name); n != 0 {
			t.Errorf("LOOKUP %q issued %d times, want 0: the filehandle READDIR returned was dropped instead of being carried into apply", name, n)
		}
	}

	// Task 12b step 2. fhCache is no longer a whole-tree index, and this is what
	// says so: a completed walk-and-apply over four objects must leave behind
	// only the export root resolved at Init. Seeding it from READDIR, or storing
	// a caller-supplied Ref.FH on the way past, would put an entry here per
	// object -- the ~200 MB at 1.1M objects the struct comment used to describe.
	cl.cacheMu.RLock()
	cached := make([]string, 0, len(cl.fhCache))
	for k := range cl.fhCache {
		cached = append(cached, k)
	}
	cl.cacheMu.RUnlock()
	sort.Strings(cached)
	if len(cached) != 1 || cached[0] != "/" {
		t.Errorf("fhCache holds %v, want only the export root; steady state must not populate it", cached)
	}
}

// TestApplyAddressesTheHandleNotThePath pins the semantic change Task 12b makes
// to the userspace transport, which no test in the task's own commit observes.
//
// Before 12b, apply handed the transport a path and no filehandle, so every
// operation re-resolved the path at the moment it ran: the object written to was
// whatever occupied that path then. After 12b the walk's filehandle is forwarded,
// and filehandleForRef prefers it over resolving, so the object written to is the
// one that occupied the path at ENUMERATION time. On a quiescent tree the two are
// the same object and the change is purely a round-trip saving, which is how the
// commit message describes it. On a tree being modified under the run they are
// not: a rename between READDIR and apply leaves the filehandle valid, so the
// spec matched against the old path is written to an object that has moved, and
// the log line names the path the object no longer has.
//
// This test is not an argument for reverting -- addressing the enumerated object
// is what removes the LOOKUP, and it is the more defensible of the two semantics
// besides. It exists so the divergence is a decision on the record rather than a
// side effect, and so a later change back to path-resolution is caught here.
func TestApplyAddressesTheHandleNotThePath(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46))
	defer srv.Close()
	srv.AddTree(map[string][]fakeEntry{
		"/": {{Name: "f", FH: "f-fh", Mode: 0o644, FSID: 7}},
	})

	cl, err := newTestClientErr(t, srv, Config{Connections: 1, Export: "/"})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer cl.Close()

	s := &spec.Spec{
		Protocol: "nfsv4",
		Default:  spec.RulePerms{ACL: []string{"A::OWNER@:rwatTnNcCy"}},
	}

	// "/moved" is a path the server cannot resolve: LOOKUP of that name returns
	// NFS4ERR_NOENT. The filehandle, however, is live -- exactly the state a
	// rename between READDIR and apply produces.
	const gonePath = "/moved"

	// With the filehandle, the write lands on the enumerated object and no LOOKUP
	// of the vanished name is ever attempted.
	r := apply.ProcessPath(cl, transport.Ref{Path: gonePath, FH: []byte("f-fh")}, false, s, apply.Options{}, 0)
	if r.Error != nil {
		t.Fatalf("apply with a live filehandle and a dead path failed: %v; the transport resolved the path instead of using Ref.FH", r.Error)
	}
	if !r.Applied {
		t.Fatal("apply with a live filehandle reported nothing applied")
	}
	if !strings.Contains(r.LogMsg, gonePath) {
		t.Errorf("log message %q does not name the ref path; the log records the path, not the object actually written", r.LogMsg)
	}
	if n := srv.LookupCount("moved"); n != 0 {
		t.Errorf("LOOKUP %q issued %d times, want 0: Ref.FH must win over resolving the path", "moved", n)
	}
	if got := srv.ACLFor("f-fh"); len(got) == 0 {
		t.Error("no ACL was written to f-fh; the filehandle in Ref did not reach SETATTR")
	}

	// The same call without the filehandle is the pre-12b behaviour, and it is
	// the contrast that gives the assertion above its meaning: a path-only Ref
	// fails, because there is nothing at that path any more.
	r = apply.ProcessPath(cl, transport.Ref{Path: gonePath}, false, s, apply.Options{}, 0)
	if r.Error == nil {
		t.Fatal("apply with a path-only Ref succeeded against a path the server cannot resolve; the two addressing modes are supposed to differ here")
	}
	if n := srv.LookupCount("moved"); n == 0 {
		t.Error("a path-only Ref issued no LOOKUP, so it did not resolve the path at all")
	}
}

// TestFilehandleCacheBoundKeepsTheRootsAndNeverGrows pins Task 12b Step 2's
// bound, which the task's own tests do not reach: they assert the cache stays at
// one entry in steady state, and say nothing about what happens when the
// fault path fills it.
//
// Two properties matter and neither is self-evident from the code. First the
// bound holds: fhCacheMax entries is the ceiling, and overflow drops the map
// rather than growing it, so a mass-re-export storm cannot rebuild the O(tree)
// index the task removed. Second the drop keeps the export and target roots.
// Every other entry can be reconstructed by its caller, which still holds the
// filehandle in its own Ref -- the roots cannot, because Root and ProbeTarget
// read them through currentRef, and c.root/c.exportRoot hold only the handle
// negotiated at Init. Dropping a root's post-recovery handle un-recovers it for
// the rest of the run.
func TestFilehandleCacheBoundKeepsTheRootsAndNeverGrows(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1<<46))
	defer srv.Close()
	srv.AddTree(map[string][]fakeEntry{
		"/":    {{Name: "dir", FH: "dir-fh", Mode: 0o755, FSID: 7, IsDir: true}},
		"/dir": {{Name: "f", FH: "f-fh", Mode: 0o644, FSID: 7}},
	})

	// Distinct export and target so both root entries are exercised.
	cl, err := newTestClientErr(t, srv, Config{Connections: 1, Export: "/", Target: "/dir"})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer cl.Close()

	exportFH, ok := cl.cachedFilehandle("/")
	if !ok {
		t.Fatal("the export root is not cached after Init; the rest of this test would be vacuous")
	}
	targetFH, ok := cl.cachedFilehandle("/dir")
	if !ok {
		t.Fatal("the target root is not cached after Init")
	}

	// Overflow the cache from the one path that populates it, twice over, so the
	// drop is exercised more than once.
	const overflow = 2*fhCacheMax + 7
	for i := 0; i < overflow; i++ {
		cl.cacheFilehandle(fmt.Sprintf("/storm/%d", i), []byte(fmt.Sprintf("h%d", i)))
		cl.cacheMu.RLock()
		size := len(cl.fhCache)
		cl.cacheMu.RUnlock()
		if size > fhCacheMax {
			t.Fatalf("fhCache holds %d entries after %d inserts, above the bound of %d: the cache can still become a whole-tree index", size, i+1, fhCacheMax)
		}
	}

	cl.cacheMu.RLock()
	size := len(cl.fhCache)
	cl.cacheMu.RUnlock()
	if size >= overflow {
		t.Fatalf("fhCache holds %d entries for %d inserts; nothing was ever dropped", size, overflow)
	}

	// The roots survived every drop, with the handles Init resolved.
	got, ok := cl.cachedFilehandle("/")
	if !ok {
		t.Error("the export root was dropped from fhCache; Root and ProbeTarget now fall back to the handle negotiated at Init and a stale-filehandle recovery on the root is lost for the rest of the run")
	} else if !bytes.Equal(got, exportFH) {
		t.Errorf("export root filehandle changed across the drop: got %x, want %x", got, exportFH)
	}
	got, ok = cl.cachedFilehandle("/dir")
	if !ok {
		t.Error("the target root was dropped from fhCache")
	} else if !bytes.Equal(got, targetFH) {
		t.Errorf("target root filehandle changed across the drop: got %x, want %x", got, targetFH)
	}

	// A retained entry still maps to the handle it was stored with. A drop may
	// only ever cause a miss; returning another object's filehandle would write
	// a permission to the wrong object.
	last := fmt.Sprintf("/storm/%d", overflow-1)
	got, ok = cl.cachedFilehandle(last)
	if !ok {
		t.Fatalf("the most recent insert %q is not in the cache", last)
	}
	if want := fmt.Sprintf("h%d", overflow-1); string(got) != want {
		t.Errorf("cached filehandle for %q is %q, want %q: the cache returned another object's handle", last, got, want)
	}
}
