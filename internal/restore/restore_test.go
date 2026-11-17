package restore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/apply"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/auditproof"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/checkpoint"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs4acl"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/spec"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// aclFS is a kernel transport over a tmpdir tree whose ACLs live in a map,
// since tmpfs has no system.nfs4_acl. Every ACL call is recorded in order.
type aclFS struct {
	*transport.Kernel
	mu      sync.Mutex
	acls    map[string][]byte
	calls   []string // "get PATH" / "set PATH"
	failSet map[string]error
	failGet map[string]error
	// File ids are scripted, since the two tmpdir trees really are different
	// files. By default an object's id is a hash of its path relative to the
	// root, the same on both sides; direntIno and statIno override it.
	root      string
	direntIno map[string]uint64
	statIno   map[string]uint64
}

func (f *aclFS) defaultIno(p string) uint64 {
	rel, _ := filepath.Rel(f.root, p)
	h := fnv.New64a()
	h.Write([]byte(rel))
	return h.Sum64() | 1
}

func (f *aclFS) ReadDirIno(r transport.Ref) ([]transport.Dirent, error) {
	ents, err := f.Kernel.ReadDir(r)
	for i := range ents {
		ents[i].Ino = f.defaultIno(ents[i].Ref.Path)
		if v, ok := f.direntIno[ents[i].Ref.Path]; ok {
			ents[i].Ino = v
		}
	}
	return ents, err
}

func (f *aclFS) Stat(r transport.Ref) (transport.Attr, error) {
	a, err := f.Kernel.Stat(r)
	a.Ino = f.defaultIno(r.Path)
	if v, ok := f.statIno[r.Path]; ok {
		a.Ino = v
	}
	return a, err
}

func newACLFS(t *testing.T, root string) *aclFS {
	t.Helper()
	k, err := transport.NewKernel(root)
	if err != nil {
		t.Fatal(err)
	}
	return &aclFS{Kernel: k, acls: map[string][]byte{}, failSet: map[string]error{}, failGet: map[string]error{},
		root: root, direntIno: map[string]uint64{}, statIno: map[string]uint64{}}
}

func (f *aclFS) GetACL(r transport.Ref) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "get "+r.Path)
	if err := f.failGet[r.Path]; err != nil {
		return nil, err
	}
	a, ok := f.acls[r.Path]
	if !ok {
		return nil, errors.New("no ACL scripted for " + r.Path)
	}
	return append([]byte(nil), a...), nil
}

func (f *aclFS) SetACL(r transport.Ref, b []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "set "+r.Path)
	if err := f.failSet[r.Path]; err != nil {
		return err
	}
	f.acls[r.Path] = append([]byte(nil), b...)
	return nil
}

func (f *aclFS) sets() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		if strings.HasPrefix(c, "set ") {
			out = append(out, strings.TrimPrefix(c, "set "))
		}
	}
	return out
}

func (f *aclFS) gets() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, "get ") {
			n++
		}
	}
	return n
}

func acl(aces ...nfs4acl.ACE) []byte { return nfs4acl.Encode(aces) }

func allow(who string, mask uint32) nfs4acl.ACE {
	return nfs4acl.ACE{Type: nfs4acl.TypeAllow, Mask: mask, Who: who}
}

func audit(who string) nfs4acl.ACE {
	return nfs4acl.ACE{Type: nfs4acl.TypeAudit, Flags: nfs4acl.FlagSuccessAccess, Mask: nfs4acl.MaskReadData, Who: who}
}

var (
	// The issue's case: a file ACE carrying ACE4_DELETE_CHILD (0x40), which
	// the nfs4_setfacl loop dropped.
	refFileACL  = acl(allow("OWNER@", nfs4acl.MaskReadData|nfs4acl.MaskWriteData|nfs4acl.MaskDeleteChild), allow("1001", nfs4acl.MaskReadData))
	liveFileACL = acl(allow("OWNER@", nfs4acl.MaskReadData|nfs4acl.MaskWriteData), allow("1001", nfs4acl.MaskReadData))
	refDirACL   = acl(allow("OWNER@", nfs4acl.MaskReadData|nfs4acl.MaskExecute|nfs4acl.MaskDeleteChild))
	liveDirACL  = acl(allow("OWNER@", nfs4acl.MaskReadData|nfs4acl.MaskExecute))
)

type fixture struct {
	t         *testing.T
	refRoot   string
	liveRoot  string
	ref, live *aclFS
}

func newFixture(t *testing.T) *fixture {
	base := t.TempDir()
	fx := &fixture{t: t, refRoot: filepath.Join(base, "ref"), liveRoot: filepath.Join(base, "live")}
	for _, d := range []string{fx.refRoot, fx.liveRoot} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	fx.ref, fx.live = newACLFS(t, fx.refRoot), newACLFS(t, fx.liveRoot)
	fx.ref.acls[fx.refRoot], fx.live.acls[fx.liveRoot] = refDirACL, liveDirACL
	return fx
}

// dir creates rel as a directory on the given sides, with the default ACLs.
func (fx *fixture) dir(rel string, onRef, onLive bool) {
	fx.t.Helper()
	if onRef {
		mustMkdir(fx.t, filepath.Join(fx.refRoot, rel))
		fx.ref.acls[filepath.Join(fx.refRoot, rel)] = refDirACL
	}
	if onLive {
		mustMkdir(fx.t, filepath.Join(fx.liveRoot, rel))
		fx.live.acls[filepath.Join(fx.liveRoot, rel)] = liveDirACL
	}
}

func (fx *fixture) file(rel string, onRef, onLive bool) {
	fx.t.Helper()
	if onRef {
		mustWrite(fx.t, filepath.Join(fx.refRoot, rel))
		fx.ref.acls[filepath.Join(fx.refRoot, rel)] = refFileACL
	}
	if onLive {
		mustWrite(fx.t, filepath.Join(fx.liveRoot, rel))
		fx.live.acls[filepath.Join(fx.liveRoot, rel)] = liveFileACL
	}
}

func (fx *fixture) config(mode Mode) Config {
	return Config{
		Reference: fx.refRoot, Target: fx.liveRoot, Ref: fx.ref, Live: fx.live, Mode: mode, Workers: 4,
		ReplacedCheck: true,
		Prove:         func() (auditproof.Proof, error) { return auditproof.Proof{Probe: "probe"}, nil },
	}
}

func (fx *fixture) run(cfg Config) Result {
	fx.t.Helper()
	var out, errOut bytes.Buffer
	res, err := Run(context.Background(), cfg, &out, &errOut)
	if err != nil {
		fx.t.Fatalf("Run: %v\nstdout:\n%s\nstderr:\n%s", err, out.String(), errOut.String())
	}
	return res
}

func (fx *fixture) refPath(rel string) string  { return filepath.Join(fx.refRoot, rel) }
func (fx *fixture) livePath(rel string) string { return filepath.Join(fx.liveRoot, rel) }

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.Mkdir(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, p string) {
	t.Helper()
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreWritesReferenceBytesIncludingDeleteChild(t *testing.T) {
	fx := newFixture(t)
	fx.file("a.txt", true, true)
	fx.dir("d", true, true)
	fx.file("d/b.txt", true, true)

	res := fx.run(fx.config(Apply))
	if !res.OK() {
		t.Fatalf("not OK: %+v", res.Counts)
	}
	for _, rel := range []string{"a.txt", "d/b.txt"} {
		if got := fx.live.acls[fx.livePath(rel)]; !bytes.Equal(got, refFileACL) {
			t.Errorf("%s: live ACL not the reference bytes", rel)
		}
	}
	for _, rel := range []string{"", "d"} {
		if got := fx.live.acls[fx.livePath(rel)]; !bytes.Equal(got, refDirACL) {
			t.Errorf("dir %q: live ACL not the reference bytes", rel)
		}
	}
	if res.Counts.Restored != 4 || res.Counts.Compared != 4 {
		t.Errorf("counts = %+v, want 4 restored of 4 compared", res.Counts)
	}
	if !strings.Contains(res.Proof, "audit-bypass") {
		t.Errorf("proof not reported: %q", res.Proof)
	}
}

func TestRestoreSkipsByteIdenticalPairs(t *testing.T) {
	fx := newFixture(t)
	fx.file("a.txt", true, true)
	fx.live.acls[fx.livePath("a.txt")] = refFileACL
	fx.live.acls[fx.liveRoot] = refDirACL

	res := fx.run(fx.config(Apply))
	if res.Counts.Same != 2 || res.Counts.Restored != 0 {
		t.Errorf("counts = %+v, want 2 same, 0 restored", res.Counts)
	}
	if s := fx.live.sets(); len(s) != 0 {
		t.Errorf("wrote %v, want no writes", s)
	}
}

func TestRestorePairingRows(t *testing.T) {
	fx := newFixture(t)
	fx.file("deleted.txt", true, false)
	fx.dir("deleteddir", true, false)
	fx.file("deleteddir/x", true, false)
	fx.file("created.txt", false, true)
	// was a file, now a symlink; was a symlink, now a file
	fx.file("nowlink", true, false)
	if err := os.Symlink("created.txt", fx.livePath("nowlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("deleted.txt", fx.refPath("waslink")); err != nil {
		t.Fatal(err)
	}
	fx.file("waslink", false, true)
	// file -> dir and dir -> file
	fx.file("f2d", true, false)
	fx.dir("f2d", false, true)
	fx.file("f2d/inner", false, true)
	fx.dir("d2f", true, false)
	fx.file("d2f/inner", true, false)
	fx.file("d2f", false, true)
	fx.dir("skipme", true, true)
	fx.file("skipme/x", true, true)

	ex, err := spec.NewExcluder(fx.liveRoot, []string{"skipme"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := fx.config(Apply)
	cfg.Excluder = ex
	res := fx.run(cfg)

	c := res.Counts
	want := Counts{Compared: 1, Restored: 1, DeletedSince: 2, CreatedSince: 1, Symlink: 2, TypeChanged: 2, Excluded: 1}
	if c != want {
		t.Errorf("counts =\n %+v\nwant\n %+v", c, want)
	}
	// Only the root was compared and written; nothing under a skip was read.
	if s := fx.live.sets(); len(s) != 1 || s[0] != fx.liveRoot {
		t.Errorf("writes = %v, want only the root", s)
	}
	for _, c := range fx.live.calls {
		if strings.Contains(c, "f2d/inner") || strings.Contains(c, "skipme") {
			t.Errorf("touched %s", c)
		}
	}
}

func TestRestoreWritesDirectoriesAfterTheirSubtreeAndRootLast(t *testing.T) {
	fx := newFixture(t)
	fx.dir("a", true, true)
	fx.dir("a/b", true, true)
	fx.file("a/b/f1", true, true)
	fx.file("a/f2", true, true)
	fx.dir("c", true, true)
	fx.file("c/f3", true, true)
	fx.file("top", true, true)

	fx.run(fx.config(Apply))
	sets := fx.live.sets()
	pos := map[string]int{}
	for i, p := range sets {
		pos[p] = i
	}
	before := func(child, parent string) {
		if pos[fx.livePath(child)] >= pos[fx.livePath(parent)] {
			t.Errorf("%s written at %d, not before its parent %s at %d (order %v)", child, pos[fx.livePath(child)], parent, pos[fx.livePath(parent)], sets)
		}
	}
	before("a/b/f1", "a/b")
	before("a/b", "a")
	before("a/f2", "a")
	before("c/f3", "c")
	if sets[len(sets)-1] != fx.liveRoot {
		t.Errorf("root not written last: %v", sets)
	}
	if len(sets) != 8 {
		t.Errorf("%d writes, want 8", len(sets))
	}
}

func TestRestoreProvesTheBypassBeforeAnyRead(t *testing.T) {
	fx := newFixture(t)
	fx.file("a.txt", true, true)
	cfg := fx.config(Apply)
	cfg.Prove = func() (auditproof.Proof, error) { return auditproof.Proof{}, auditproof.ErrAuditPrivilege }

	var out, errOut bytes.Buffer
	_, err := Run(context.Background(), cfg, &out, &errOut)
	if !errors.Is(err, auditproof.ErrAuditPrivilege) {
		t.Fatalf("err = %v, want ErrAuditPrivilege", err)
	}
	if fx.ref.gets() != 0 || fx.live.gets() != 0 {
		t.Errorf("read before the proof: ref %d, live %d", fx.ref.gets(), fx.live.gets())
	}
}

func TestRestoreGuards(t *testing.T) {
	cases := []struct {
		name     string
		ref      []byte
		live     []byte
		mutate   func(*Config)
		refused  string // refusedBy key; "" means restored
		sameSkip bool
	}{
		{name: "unmapped principal", ref: acl(allow("OWNER@", 1), allow("65534", 1)), live: liveFileACL, refused: "unmapped_principal"},
		{name: "synthetic range id", ref: acl(allow("OWNER@", 1), allow("1000000123", 1)), live: liveFileACL, refused: "synthetic_range_principal"},
		{name: "unpreservable audit", ref: acl(allow("OWNER@", 1), audit("65534")), live: liveFileACL,
			mutate: func(c *Config) { c.AllowAuditedDACLReset = true }, refused: "unpreservable_audit"},
		{name: "audit vanished", ref: liveFileACL, live: acl(allow("OWNER@", 1), audit("EVERYONE@")),
			mutate: func(c *Config) { c.AllowAuditedDACLReset = true }, refused: "audit_vanished"},
		{name: "audit vanished allowed", ref: liveFileACL, live: acl(allow("OWNER@", 1), audit("EVERYONE@")),
			mutate: func(c *Config) { c.AllowAuditedDACLReset, c.AllowAuditRemoval = true, true }},
		{name: "audited without flag", ref: acl(allow("OWNER@", 1), audit("EVERYONE@")), live: liveFileACL, refused: "audited_object"},
		{name: "audited with flag", ref: acl(allow("OWNER@", 1), audit("EVERYONE@")), live: liveFileACL,
			mutate: func(c *Config) { c.AllowAuditedDACLReset = true }},
		{name: "unparseable reference", ref: []byte{0, 0, 0, 9}, live: liveFileACL, refused: "unparseable_acl"},
		// A pair that already matches is left alone, whatever it names.
		{name: "same bytes naming nobody", ref: acl(allow("65534", 1)), live: acl(allow("65534", 1)), sameSkip: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t)
			fx.file("f", true, true)
			fx.ref.acls[fx.refPath("f")], fx.live.acls[fx.livePath("f")] = tc.ref, tc.live
			fx.live.acls[fx.liveRoot] = refDirACL // root already matches
			cfg := fx.config(Apply)
			if tc.mutate != nil {
				tc.mutate(&cfg)
			}
			res := fx.run(cfg)
			wrote := len(fx.live.sets()) > 0
			switch {
			case tc.sameSkip:
				if wrote || res.Counts.Same != 2 || res.Counts.Refused != 0 {
					t.Errorf("counts %+v wrote %v, want same and untouched", res.Counts, wrote)
				}
			case tc.refused != "":
				if wrote || res.RefusedBy[tc.refused] != 1 {
					t.Errorf("refusedBy %v wrote %v, want one %s and no write", res.RefusedBy, wrote, tc.refused)
				}
				if res.OK() {
					t.Error("a refusal must fail the run")
				}
			default:
				if !wrote || res.Counts.Restored != 1 || !bytes.Equal(fx.live.acls[fx.livePath("f")], tc.ref) {
					t.Errorf("counts %+v, want restored to the reference bytes", res.Counts)
				}
			}
		})
	}
}

func TestRestoreValidateComparesWithoutWriting(t *testing.T) {
	fx := newFixture(t)
	fx.file("a.txt", true, true)
	fx.file("b.txt", true, true)
	fx.live.acls[fx.livePath("b.txt")] = refFileACL

	var log bytes.Buffer
	cfg := fx.config(Validate)
	cfg.Log = &log
	res := fx.run(cfg)
	if s := fx.live.sets(); len(s) != 0 {
		t.Fatalf("validate wrote %v", s)
	}
	if res.Counts.Mismatch != 2 || res.Counts.Same != 1 || res.OK() {
		t.Errorf("counts = %+v ok=%v, want 2 mismatches (a.txt, root), 1 same, not OK", res.Counts, res.OK())
	}
	// The decoded diff shows the dropped DELETE_CHILD bit.
	if !strings.Contains(log.String(), "0x0/0x0/0x3, want 0x0/0x0/0x43") {
		t.Errorf("mismatch report does not show the masks:\n%s", log.String())
	}
}

func TestRestoreDryRunReadsNoACL(t *testing.T) {
	fx := newFixture(t)
	fx.file("a.txt", true, true)
	fx.file("gone", true, false)
	res := fx.run(fx.config(DryRun))
	if fx.live.gets() != 0 || len(fx.live.sets()) != 0 || fx.ref.gets() != 0 {
		t.Errorf("dry run read or wrote an ACL: live %v, ref %v", fx.live.calls, fx.ref.calls)
	}
	if res.Counts.Would != 2 || res.Counts.DeletedSince != 1 {
		t.Errorf("counts = %+v, want 2 would, 1 deleted-since", res.Counts)
	}
}

func TestRestoreWritableReferenceMattersOnlyUnderApply(t *testing.T) {
	for _, mode := range []Mode{DryRun, Validate} {
		fx := newFixture(t)
		fx.file("a.txt", true, true)
		cfg := fx.config(mode)
		cfg.ReferenceWritable = true
		if res := fx.run(cfg); res.Counts.Errors() != 0 {
			t.Errorf("%s with a writable reference: %+v", mode, res.Counts)
		}
	}
}

func TestRestoreRefusesAWritableReferenceUnderApply(t *testing.T) {
	fx := newFixture(t)
	fx.file("a.txt", true, true)
	cfg := fx.config(Apply)
	cfg.ReferenceWritable = true
	var out, errOut bytes.Buffer
	if _, err := Run(context.Background(), cfg, &out, &errOut); !errors.Is(err, ErrWritableReference) {
		t.Fatalf("err = %v, want ErrWritableReference", err)
	}
	if fx.live.gets() != 0 || fx.ref.gets() != 0 {
		t.Error("read before refusing")
	}
	cfg.AllowWritableReference = true
	if res := fx.run(cfg); res.Counts.Restored != 2 {
		t.Errorf("with the flag: %+v", res.Counts)
	}
}

func TestRestoreResumeRedoesOnlyIncompleteSubtrees(t *testing.T) {
	fx := newFixture(t)
	fx.dir("good", true, true)
	fx.file("good/f", true, true)
	fx.dir("bad", true, true)
	fx.file("bad/f", true, true)
	fx.file("bad/g", true, true)
	fx.live.failSet[fx.livePath("bad/f")] = errors.New("EIO")

	ckptPath := filepath.Join(t.TempDir(), "restore.ckpt")
	hash := checkpoint.RestoreHash(fx.refRoot, fx.liveRoot, "test", nil)
	open := func(resume bool) *checkpoint.Checkpoint {
		c, err := checkpoint.Open(ckptPath, hash, resume)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	cfg := fx.config(Apply)
	cfg.Checkpoint = open(false)
	res := fx.run(cfg)
	cfg.Checkpoint.Close()
	if res.Counts.WriteErrors != 1 || res.OK() {
		t.Fatalf("first run: %+v", res.Counts)
	}

	delete(fx.live.failSet, fx.livePath("bad/f"))
	fx.live.calls = nil
	cfg.Checkpoint = open(true)
	res = fx.run(cfg)
	cfg.Checkpoint.Close()
	if !res.OK() || res.Counts.Resumed != 1 {
		t.Fatalf("resume: %+v", res.Counts)
	}
	for _, c := range fx.live.calls {
		if strings.Contains(c, "/good") {
			t.Errorf("resume touched the completed subtree: %s", c)
		}
	}
	// The first run already restored bad/g, bad and the root (a directory is
	// written once its children are handled, failed or not), so only bad/f is
	// written; the rest compare same.
	if s := fx.live.sets(); len(s) != 1 || s[0] != fx.livePath("bad/f") {
		t.Errorf("resume writes = %v, want only bad/f", s)
	}
	if res.Counts.Same != 3 {
		t.Errorf("resume same = %d, want 3 (bad/g, bad, root)", res.Counts.Same)
	}

	cfg.Checkpoint = open(true)
	res = fx.run(cfg)
	cfg.Checkpoint.Close()
	if res.Counts.Resumed != 1 || res.Counts.Compared != 0 {
		t.Errorf("a resume of a complete tree did work: %+v", res.Counts)
	}
}

func TestRestoreListingFailureLeavesTheDirectoryUnwritten(t *testing.T) {
	fx := newFixture(t)
	fx.dir("locked", true, true)
	fx.file("locked/f", true, true)
	if err := os.Chmod(fx.livePath("locked"), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(fx.livePath("locked"), 0o755) })
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode-0 directory")
	}
	res := fx.run(fx.config(Apply))
	if res.Counts.ListErrors != 1 {
		t.Fatalf("counts %+v, want one list error", res.Counts)
	}
	for _, s := range fx.live.sets() {
		if strings.Contains(s, "locked") {
			t.Errorf("wrote %s under a directory that could not be listed", s)
		}
	}
	// The root is still restored.
	if !bytes.Equal(fx.live.acls[fx.liveRoot], refDirACL) {
		t.Error("root not restored")
	}
}

func TestCheckRestorableCountsAudit(t *testing.T) {
	n, err := apply.CheckRestorable(acl(allow("OWNER@", 1), audit("EVERYONE@"), audit("OWNER@")))
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestRestoreSkipsObjectsRecreatedSinceTheReference(t *testing.T) {
	fx := newFixture(t)
	fx.file("kept", true, true)
	fx.file("recreated", true, true)
	fx.dir("newdir", true, true)
	fx.file("newdir/inner", true, true)
	fx.file("readdir-only", true, true)
	for _, rel := range []string{"recreated", "newdir"} {
		fx.live.direntIno[fx.livePath(rel)] = 7
		fx.live.statIno[fx.livePath(rel)] = 7
	}
	// READDIR disagrees but lstat agrees: not a replacement.
	fx.live.direntIno[fx.livePath("readdir-only")] = 9

	res := fx.run(fx.config(Apply))
	if res.Counts.ReplacedSince != 2 || res.Counts.Restored != 3 || !res.OK() {
		t.Fatalf("counts = %+v, want 2 replaced; kept, readdir-only and root restored", res.Counts)
	}
	for _, s := range fx.live.sets() {
		if strings.Contains(s, "recreated") || strings.Contains(s, "newdir") {
			t.Errorf("wrote replaced object %s", s)
		}
	}
	for _, c := range fx.live.calls {
		if strings.Contains(c, "newdir/inner") {
			t.Errorf("descended into a replaced directory: %s", c)
		}
	}
}

func TestRestoreReplacedCheckOffWritesRecreatedObjects(t *testing.T) {
	fx := newFixture(t)
	fx.file("recreated", true, true)
	fx.live.direntIno[fx.livePath("recreated")] = 7
	fx.live.statIno[fx.livePath("recreated")] = 7
	cfg := fx.config(Apply)
	cfg.ReplacedCheck = false
	if res := fx.run(cfg); res.Counts.ReplacedSince != 0 || res.Counts.Restored != 2 {
		t.Errorf("counts = %+v", res.Counts)
	}
}

func TestRestoreReplacedSkipsCompleteInTheCheckpoint(t *testing.T) {
	fx := newFixture(t)
	fx.dir("d", true, true)
	fx.file("d/recreated", true, true)
	fx.live.direntIno[fx.livePath("d/recreated")] = 7
	fx.live.statIno[fx.livePath("d/recreated")] = 7
	ckptPath := filepath.Join(t.TempDir(), "c.ckpt")
	hash := checkpoint.RestoreHash(fx.refRoot, fx.liveRoot, "test", nil)
	c, err := checkpoint.Open(ckptPath, hash, false)
	if err != nil {
		t.Fatal(err)
	}
	cfg := fx.config(Apply)
	cfg.Checkpoint = c
	fx.run(cfg)
	c.Close()
	c, _ = checkpoint.Open(ckptPath, hash, true)
	defer c.Close()
	if !c.DirCompleted(fx.liveRoot) {
		t.Error("a replaced-since skip kept the tree from completing")
	}
}

func TestRestoreReplacedSincePathsReachStderrOrTheLog(t *testing.T) {
	fx := newFixture(t)
	fx.file("recreated", true, true)
	fx.file("gone", true, false) // deleted since: an expected skip
	fx.live.direntIno[fx.livePath("recreated")] = 7
	fx.live.statIno[fx.livePath("recreated")] = 7
	want := "SKIP: replaced-since " + fx.livePath("recreated")

	// No --log: the path is on stderr; the expected skip is not.
	var out, errOut bytes.Buffer
	if _, err := Run(context.Background(), fx.config(Apply), &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errOut.String(), want) {
		t.Errorf("stderr does not name the replaced path:\n%s", errOut.String())
	}
	if strings.Contains(errOut.String(), "gone") {
		t.Errorf("an expected skip reached stderr:\n%s", errOut.String())
	}

	// --log: the path is in the log, and not on stderr.
	var log bytes.Buffer
	cfg := fx.config(Validate)
	cfg.Log = &log
	out.Reset()
	errOut.Reset()
	if _, err := Run(context.Background(), cfg, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log.String(), want) || strings.Contains(errOut.String(), want) {
		t.Errorf("with --log, want the path in the log only\nlog:\n%s\nstderr:\n%s", log.String(), errOut.String())
	}
}

func TestRestoreReplacedSinceStderrIsCappedApartFromErrors(t *testing.T) {
	fx := newFixture(t)
	n := errOutLimit + 5
	for i := 0; i < n; i++ {
		rel := fmt.Sprintf("r%02d", i)
		fx.file(rel, true, true)
		fx.live.direntIno[fx.livePath(rel)] = 7
		fx.live.statIno[fx.livePath(rel)] = 7
	}
	var out, errOut bytes.Buffer
	res, err := Run(context.Background(), fx.config(Apply), &out, &errOut)
	if err != nil {
		t.Fatal(err)
	}
	if res.Counts.ReplacedSince != int64(n) {
		t.Fatalf("counts = %+v, want %d replaced", res.Counts, n)
	}
	if got := strings.Count(errOut.String(), "SKIP: replaced-since "); got != errOutLimit {
		t.Errorf("%d replaced-since lines on stderr, want %d", got, errOutLimit)
	}
	if !strings.Contains(errOut.String(), "... 5 more replaced-since paths not shown") {
		t.Errorf("no suppression line:\n%s", errOut.String())
	}
	if strings.Contains(errOut.String(), "more errors not shown") {
		t.Errorf("replaced-since lines used the error budget:\n%s", errOut.String())
	}
}
