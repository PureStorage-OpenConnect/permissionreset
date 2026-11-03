package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/platform"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/session"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/speccapture"
)

// fakeRuntime is a runtimeSeam for tests, recording emitted events and
// scripting dialog results.
type fakeRuntime struct {
	events   []string
	savePath string
	saveErr  error
	dirPath  string
	dirErr   error
	filePath string
	fileErr  error
}

func (f *fakeRuntime) EventsEmit(ctx context.Context, name string, data ...interface{}) {
	f.events = append(f.events, name)
}

func (f *fakeRuntime) SaveFileDialog(ctx context.Context, options wailsruntime.SaveDialogOptions) (string, error) {
	return f.savePath, f.saveErr
}

func (f *fakeRuntime) OpenDirectoryDialog(ctx context.Context, options wailsruntime.OpenDialogOptions) (string, error) {
	return f.dirPath, f.dirErr
}

func (f *fakeRuntime) OpenFileDialog(ctx context.Context, options wailsruntime.OpenDialogOptions) (string, error) {
	return f.filePath, f.fileErr
}

// fakeSess is a sess for tests.
type fakeSess struct {
	root       string
	transport  session.Transport
	entries    []session.Entry
	truncated  bool
	listErr    error
	captureRes *speccapture.Result
	captureErr error
	verifyRes  *speccapture.Result
	verifyErr  error
	gotOpts    speccapture.Options
	expired    bool
	closed     bool
}

func (f *fakeSess) Root() string                 { return f.root }
func (f *fakeSess) Transport() session.Transport { return f.transport }
func (f *fakeSess) ListDir(p string, limit int) ([]session.Entry, bool, error) {
	return f.entries, f.truncated, f.listErr
}
func (f *fakeSess) Exports(ctx context.Context) ([]string, bool, error) { return nil, false, nil }
func (f *fakeSess) Capture(dir, file string, opts speccapture.Options) (*speccapture.Result, error) {
	f.gotOpts = opts
	return f.captureRes, f.captureErr
}
func (f *fakeSess) Verify(scratch, dir, file string, opts speccapture.Options) (*speccapture.Result, error) {
	f.gotOpts = opts
	return f.verifyRes, f.verifyErr
}
func (f *fakeSess) Expired() bool { return f.expired }
func (f *fakeSess) Close() error  { f.closed = true; return nil }

func newTestApp(rt *fakeRuntime) *App {
	return &App{rt: rt, ctx: context.Background()}
}

func TestCapabilities(t *testing.T) {
	orig := caps
	origVersion := version
	defer func() { caps = orig; version = origVersion }()

	caps = platform.Capabilities{OS: "linux", KernelTransport: true, CredentialFromProcess: true}
	version = "1.2.3"

	a := newTestApp(&fakeRuntime{})
	got := a.Capabilities()
	if got.OS != "linux" || !got.KernelTransport || !got.CredentialFromProcess || got.Version != "1.2.3" {
		t.Fatalf("unexpected capabilities: %+v", got)
	}
}

func withFakeConnect(t *testing.T, fake *fakeSess) {
	t.Helper()
	origConnect := connect
	connect = func(ctx context.Context, req session.ConnectRequest, idle time.Duration, now func() time.Time) (sess, error) {
		fake.transport = req.Transport
		return fake, nil
	}
	t.Cleanup(func() { connect = origConnect })
}

func TestConnectBuildsNilAuthWhenNothingTypedAndCredentialFromProcess(t *testing.T) {
	origCaps := caps
	defer func() { caps = origCaps }()
	caps = platform.Capabilities{CredentialFromProcess: true}

	fake := &fakeSess{root: "/export"}
	origConnect := connect
	var gotAuth *nfs41.AuthSys
	connect = func(ctx context.Context, req session.ConnectRequest, idle time.Duration, now func() time.Time) (sess, error) {
		gotAuth = req.Auth
		return fake, nil
	}
	defer func() { connect = origConnect }()

	a := newTestApp(&fakeRuntime{})
	res, err := a.Connect(ConnectRequest{Transport: "userspace", Server: "s", Export: "e", AuthUid: -1, AuthGid: -1})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if gotAuth != nil {
		t.Fatalf("expected nil Auth, got %+v", gotAuth)
	}
	if res.Root != "/export" {
		t.Fatalf("unexpected root: %q", res.Root)
	}
}

func TestConnectRefusesMissingUidGidWhenNoProcessCredential(t *testing.T) {
	origCaps := caps
	defer func() { caps = origCaps }()
	caps = platform.Capabilities{CredentialFromProcess: false}

	a := newTestApp(&fakeRuntime{})
	_, err := a.Connect(ConnectRequest{Transport: "userspace", Server: "s", Export: "e", AuthUid: -1, AuthGid: -1})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := err.Error(); got == "" {
		t.Fatalf("expected non-empty error message")
	}
}

func TestConnectClosesPreviousSession(t *testing.T) {
	origCaps := caps
	defer func() { caps = origCaps }()
	caps = platform.Capabilities{CredentialFromProcess: true}

	prev := &fakeSess{root: "/old"}
	next := &fakeSess{root: "/new"}
	origConnect := connect
	first := true
	connect = func(ctx context.Context, req session.ConnectRequest, idle time.Duration, now func() time.Time) (sess, error) {
		if first {
			first = false
			return prev, nil
		}
		return next, nil
	}
	defer func() { connect = origConnect }()

	a := newTestApp(&fakeRuntime{})
	if _, err := a.Connect(ConnectRequest{Transport: "userspace", Server: "s", Export: "e", AuthUid: -1, AuthGid: -1}); err != nil {
		t.Fatalf("first connect: %v", err)
	}
	if _, err := a.Connect(ConnectRequest{Transport: "userspace", Server: "s", Export: "e", AuthUid: -1, AuthGid: -1}); err != nil {
		t.Fatalf("second connect: %v", err)
	}
	if !prev.closed {
		t.Fatal("expected previous session to be closed")
	}
}

func TestListDirMapsEntriesAndPassesLimit(t *testing.T) {
	fake := &fakeSess{
		entries: []session.Entry{
			{Name: "a", IsDir: true},
			{Name: "b.txt", IsSymlink: true},
		},
		truncated: true,
	}
	a := newTestApp(&fakeRuntime{})
	a.sess = fake

	res, err := a.ListDir("/x", 10)
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	if !res.Truncated {
		t.Fatal("expected truncated true")
	}
	if len(res.Entries) != 2 || res.Entries[0].Name != "a" || !res.Entries[0].IsDir {
		t.Fatalf("unexpected entries: %+v", res.Entries)
	}
	if !res.Entries[1].IsSymlink {
		t.Fatalf("expected entry 1 symlink")
	}
}

func TestCaptureMapsResult(t *testing.T) {
	fake := &fakeSess{
		captureRes: &speccapture.Result{
			DirACEs:  []string{"d1"},
			FileACEs: []string{"f1"},
			YAML:     []byte("rules: []\n"),
			Identity: speccapture.IdentityReport{
				Special: 1, Named: 2, NumericUser: 3, NumericGroup: 4,
				SACL: speccapture.KindCounts{Special: 1},
				Principals: []speccapture.Principal{
					{Who: "9224117", Group: true, Kind: speccapture.KindNumericGroup, DirDACL: true, FileDACL: true},
					{Who: "EVERYONE@", Kind: speccapture.KindSpecial, DirSACL: true},
				},
			},
		},
	}
	a := newTestApp(&fakeRuntime{})
	a.sess = fake

	res, err := a.Capture("/d", "/f", false, true)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if res.Yaml != "rules: []\n" || len(res.DirAces) != 1 || len(res.FileAces) != 1 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if res.Identity.Special != 1 || res.Identity.Named != 2 || res.Identity.NumericUser != 3 || res.Identity.NumericGroup != 4 {
		t.Fatalf("unexpected identity: %+v", res.Identity)
	}
	if res.Identity.Sacl.Special != 1 || len(res.Identity.Principals) != 2 {
		t.Fatalf("SACL counts or principals not mapped: %+v", res.Identity)
	}
	if p := res.Identity.Principals[0]; p.Who != "9224117" || !p.Group || p.Kind != "numeric group" || p.Where != "directory DACL, file DACL" {
		t.Fatalf("principal 0 = %+v", p)
	}
}

func TestListDirSessionLostEmitsAndNilsSession(t *testing.T) {
	fake := &fakeSess{listErr: session.ErrSessionLost}
	rt := &fakeRuntime{}
	a := newTestApp(rt)
	a.sess = fake

	_, err := a.ListDir("/x", 10)
	if !errors.Is(err, session.ErrSessionLost) {
		t.Fatalf("expected ErrSessionLost, got %v", err)
	}
	if a.sess != nil {
		t.Fatal("expected session to be nilled")
	}
	found := false
	for _, e := range rt.events {
		if e == "session:lost" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected session:lost event, got %v", rt.events)
	}
}

func TestSaveSpecRefusesExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "spec.yaml")
	if err := os.WriteFile(path, []byte("existing"), 0644); err != nil {
		t.Fatal(err)
	}
	rt := &fakeRuntime{savePath: path}
	a := newTestApp(rt)

	_, err := a.SaveSpec("new content", "spec.yaml")
	if err == nil {
		t.Fatal("expected error for existing file")
	}
}

func TestSaveSpecWritesNewFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "spec.yaml")
	rt := &fakeRuntime{savePath: path}
	a := newTestApp(rt)

	res, err := a.SaveSpec("content", "spec.yaml")
	if err != nil {
		t.Fatalf("SaveSpec: %v", err)
	}
	if res.Path != path {
		t.Fatalf("unexpected path: %q", res.Path)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0644 {
		t.Fatalf("unexpected mode: %v", info.Mode())
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "content" {
		t.Fatalf("unexpected content: %q", got)
	}
}

func TestSaveSpecCancelledReturnsEmptyPathWithoutWriting(t *testing.T) {
	rt := &fakeRuntime{savePath: ""}
	a := newTestApp(rt)

	res, err := a.SaveSpec("content", "spec.yaml")
	if err != nil {
		t.Fatalf("SaveSpec: %v", err)
	}
	if res.Path != "" {
		t.Fatalf("expected empty path, got %q", res.Path)
	}
}

func TestChooseScratchRefusedOnUserspace(t *testing.T) {
	fake := &fakeSess{transport: session.Userspace}
	a := newTestApp(&fakeRuntime{})
	a.sess = fake

	_, err := a.ChooseScratch()
	if err == nil {
		t.Fatal("expected error on userspace transport")
	}
}

func TestIdleTickerEmitsSessionLost(t *testing.T) {
	fake := &fakeSess{expired: true}
	rt := &fakeRuntime{}
	a := newTestApp(rt)
	a.sess = fake

	a.tick()

	if a.sess != nil {
		t.Fatal("expected session to be nilled after idle tick")
	}
	if !fake.closed {
		t.Fatal("expected session to be closed")
	}
	found := false
	for _, e := range rt.events {
		if e == "session:lost" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected session:lost event, got %v", rt.events)
	}
}

func TestCaptureSaclAndWithDACL(t *testing.T) {
	fake := &fakeSess{
		captureRes: &speccapture.Result{
			DirSACL:   []string{"U:fdS:EVERYONE@:wadD"},
			KeepsDACL: true,
			YAML:      []byte("rules: []\n"),
		},
		verifyRes: &speccapture.Result{YAML: []byte("rules: []\n")},
	}
	a := newTestApp(&fakeRuntime{})
	a.sess = fake

	res, err := a.Capture("/d", "/f", false, true)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if !res.HasSacl || !res.KeepsDacl || len(res.DirSacl) != 1 {
		t.Fatalf("SACL fields not mapped: %+v", res)
	}
	if fake.gotOpts.WithDACL {
		t.Fatal("Capture(withDACL=false) passed WithDACL=true")
	}
	if _, err := a.Capture("/d", "/f", true, true); err != nil || !fake.gotOpts.WithDACL {
		t.Fatalf("Capture(withDACL=true): err=%v WithDACL=%v", err, fake.gotOpts.WithDACL)
	}
	if _, err := a.Verify("/s", "/d", "/f", true); err != nil || !fake.gotOpts.WithDACL {
		t.Fatalf("Verify(withDACL=true): err=%v WithDACL=%v", err, fake.gotOpts.WithDACL)
	}
	if fake.gotOpts.AcceptUnprovenRead {
		t.Fatal("Verify passed AcceptUnprovenRead=true; its scratch folder proves the bypass instead")
	}
	if _, err := a.Capture("/d", "/f", false, false); err != nil || fake.gotOpts.AcceptUnprovenRead {
		t.Fatalf("Capture(acceptUnprovenRead=false): err=%v AcceptUnprovenRead=%v", err, fake.gotOpts.AcceptUnprovenRead)
	}
	if _, err := a.Capture("/d", "/f", false, true); err != nil || !fake.gotOpts.AcceptUnprovenRead {
		t.Fatalf("Capture(acceptUnprovenRead=true): err=%v AcceptUnprovenRead=%v", err, fake.gotOpts.AcceptUnprovenRead)
	}
}

// The GUI's plan is the CLI's: the same bytes as build-spec --sacl-plan's
// golden file, apart from the source path it records.
func TestSaclPlanMatchesCLIGolden(t *testing.T) {
	path := filepath.Join("..", "..", "cmd", "build_spec", "testdata", "saclplan.yaml")
	a := newTestApp(&fakeRuntime{filePath: path})

	res, err := a.SaclPlan()
	if err != nil {
		t.Fatalf("SaclPlan: %v", err)
	}
	want, err := os.ReadFile(filepath.Join("..", "..", "cmd", "build_spec", "testdata", "saclplan.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	src, _ := json.Marshal(path)
	got := strings.Replace(res.JSON, `"source": `+string(src), `"source": "testdata/saclplan.yaml"`, 1)
	if w := strings.ReplaceAll(string(want), "\r\n", "\n"); got != w {
		t.Errorf("plan differs from the CLI golden file:\n--- got\n%s\n--- want\n%s", got, w)
	}
	if res.SpecPath != path || res.Rules != 4 {
		t.Errorf("SpecPath=%q Rules=%d", res.SpecPath, res.Rules)
	}
	if strings.Join(res.Refused, ",") != "rule[2],rule[3]" {
		t.Errorf("Refused = %v, want [rule[2] rule[3]]", res.Refused)
	}
}

func TestSaclPlanCancelledAndInvalid(t *testing.T) {
	a := newTestApp(&fakeRuntime{})
	if res, err := a.SaclPlan(); err != nil || res.SpecPath != "" {
		t.Fatalf("cancelled: res=%+v err=%v", res, err)
	}
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("protocol: nfsv4\nrules: [\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a = newTestApp(&fakeRuntime{filePath: bad})
	if _, err := a.SaclPlan(); err == nil {
		t.Fatal("expected an error for an invalid spec")
	}
}

func TestSavePlanRefusesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	a := newTestApp(&fakeRuntime{savePath: path})
	if _, err := a.SavePlan("{}\n", "plan.json"); err == nil {
		t.Fatal("expected refusal to overwrite")
	}
	if b, _ := os.ReadFile(path); string(b) != "old" {
		t.Fatalf("existing file changed: %q", b)
	}
}
