package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs4acl"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/speccapture"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// fakeBackend implements the session package's backend interface without any
// real filesystem or network access.
type fakeBackend struct {
	attrs map[string]transport.Attr
	acls  map[string][]byte

	readDirErr error
	entries    []transport.Dirent
	truncated  bool

	closeCalls int32
	lastLimit  int

	mu       sync.Mutex
	inFlight int32
	maxConc  int32
}

func (f *fakeBackend) enterConc() func() {
	n := atomic.AddInt32(&f.inFlight, 1)
	f.mu.Lock()
	if n > f.maxConc {
		f.maxConc = n
	}
	f.mu.Unlock()
	return func() { atomic.AddInt32(&f.inFlight, -1) }
}

func (f *fakeBackend) Stat(ref transport.Ref) (transport.Attr, error) {
	a, ok := f.attrs[ref.Path]
	if !ok {
		return transport.Attr{}, fmt.Errorf("no attr for %q", ref.Path)
	}
	return a, nil
}

func (f *fakeBackend) GetACL(ref transport.Ref) ([]byte, error) {
	b, ok := f.acls[ref.Path]
	if !ok {
		return nil, fmt.Errorf("no ACL for %q", ref.Path)
	}
	return b, nil
}

func (f *fakeBackend) ReadDirLimited(ref transport.Ref, limit int) ([]transport.Dirent, bool, error) {
	defer f.enterConc()()
	// Small sleep so concurrent callers overlap if they were not serialized.
	time.Sleep(time.Millisecond)
	if f.readDirErr != nil {
		return nil, false, f.readDirErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	entries := f.entries
	truncated := f.truncated
	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
		truncated = true
	}
	f.lastLimit = limit
	return entries, truncated, nil
}

func (f *fakeBackend) Verifier() speccapture.ReplayVerifier { return nil }

func (f *fakeBackend) Close() error {
	atomic.AddInt32(&f.closeCalls, 1)
	return nil
}

var _ backend = (*fakeBackend)(nil)

func mustEncodeACL(aces []string) []byte {
	raw, err := nfs4acl.ParseACLSpec(aces)
	if err != nil {
		panic(fmt.Sprintf("ParseACLSpec: %v", err))
	}
	return raw
}

func newFakeSessionBackend(root string) *fakeBackend {
	dir := root + "/dir"
	file := root + "/file.txt"
	return &fakeBackend{
		attrs: map[string]transport.Attr{
			dir:  {Kind: transport.KindDirectory, IsDir: true},
			file: {Kind: transport.KindRegular},
		},
		acls: map[string][]byte{
			dir:  mustEncodeACL([]string{"A:fd:OWNER@:rwaDxtTcCoy"}),
			file: mustEncodeACL([]string{"A::OWNER@:rwaTcCoy"}),
		},
	}
}

func withFakeBackend(t *testing.T, b *fakeBackend, root string, transportKind Transport) {
	t.Helper()
	saved := newBackend
	newBackend = func(ctx context.Context, req ConnectRequest) (backend, string, error) {
		return b, root, nil
	}
	t.Cleanup(func() { newBackend = saved })
	_ = transportKind
}

func connectFake(t *testing.T, b *fakeBackend, root string, transportKind Transport, idle time.Duration, now func() time.Time) *Session {
	t.Helper()
	withFakeBackend(t, b, root, transportKind)
	req := ConnectRequest{Transport: transportKind}
	switch transportKind {
	case Userspace:
		req.Server = "192.0.2.1"
		req.Export = root
	case Kernel:
		req.MountPath = root
	}
	s, err := Connect(context.Background(), req, idle, now)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	return s
}

func TestConnectUserspaceRequiresServerAndExport(t *testing.T) {
	if _, err := Connect(context.Background(), ConnectRequest{Transport: Userspace, Export: "/x"}, 0, nil); err == nil {
		t.Fatal("expected error for empty Server")
	}
	if _, err := Connect(context.Background(), ConnectRequest{Transport: Userspace, Server: "h"}, 0, nil); err == nil {
		t.Fatal("expected error for empty Export")
	}
}

func TestConnectKernelRequiresMountPath(t *testing.T) {
	if _, err := Connect(context.Background(), ConnectRequest{Transport: Kernel}, 0, nil); err == nil {
		t.Fatal("expected error for empty MountPath")
	}
}

func TestListDirDefaultLimit(t *testing.T) {
	b := newFakeSessionBackend("/vol")
	b.entries = make([]transport.Dirent, 10)
	s := connectFake(t, b, "/vol", Kernel, 0, nil)
	if _, _, err := s.ListDir("/vol", 0); err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	if b.lastLimit != defaultListLimit {
		t.Fatalf("lastLimit = %d, want %d", b.lastLimit, defaultListLimit)
	}
}

func TestListDirClampsLimit(t *testing.T) {
	b := newFakeSessionBackend("/vol")
	s := connectFake(t, b, "/vol", Kernel, 0, nil)
	if _, _, err := s.ListDir("/vol", 7000); err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	if b.lastLimit != maxListLimit {
		t.Fatalf("lastLimit = %d, want %d", b.lastLimit, maxListLimit)
	}
}

func TestListDirTruncatedPassthrough(t *testing.T) {
	b := newFakeSessionBackend("/vol")
	b.entries = []transport.Dirent{{Name: "a"}, {Name: "b"}, {Name: "c"}}
	b.truncated = true
	s := connectFake(t, b, "/vol", Kernel, 0, nil)
	entries, truncated, err := s.ListDir("/vol", 2)
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	if !truncated {
		t.Fatal("expected truncated = true")
	}
	if len(entries) != 2 || entries[0].Name != "a" || entries[1].Name != "b" {
		t.Fatalf("unexpected entries: %+v", entries)
	}
}

func TestListDirPathOutsideRootRejected(t *testing.T) {
	b := newFakeSessionBackend("/vol")
	s := connectFake(t, b, "/vol", Kernel, 0, nil)
	if _, _, err := s.ListDir("/other", 0); err == nil {
		t.Fatal("expected rejection of path outside root")
	}
}

func TestListDirRootAllowed(t *testing.T) {
	b := newFakeSessionBackend("/vol")
	s := connectFake(t, b, "/vol", Kernel, 0, nil)
	if _, _, err := s.ListDir("/vol", 0); err != nil {
		t.Fatalf("ListDir at root: %v", err)
	}
}

func TestCaptureRootRejectedAsExemplar(t *testing.T) {
	b := newFakeSessionBackend("/vol")
	s := connectFake(t, b, "/vol", Kernel, 0, nil)
	if _, err := s.Capture("/vol", "/vol/file.txt", speccapture.Options{AcceptUnprovenRead: true}); err == nil {
		t.Fatal("expected root rejected as exemplar")
	}
}

func TestCapturePassthrough(t *testing.T) {
	b := newFakeSessionBackend("/vol")
	s := connectFake(t, b, "/vol", Kernel, 0, nil)
	res, err := s.Capture("/vol/dir", "/vol/file.txt", speccapture.Options{AcceptUnprovenRead: true})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if len(res.DirACEs) == 0 || len(res.FileACEs) == 0 {
		t.Fatalf("unexpected result: %+v", res)
	}
}

// The capture options reach speccapture: with an audit ACE on the exemplars, the
// default keeps each object's DACL and WithDACL writes it as acl: too.
func TestCaptureOptionsPassthrough(t *testing.T) {
	b := newFakeSessionBackend("/vol")
	b.acls["/vol/dir"] = mustEncodeACL([]string{"A:fd:OWNER@:rwaDxtTcCoy", "U:fdS:EVERYONE@:wadD"})
	s := connectFake(t, b, "/vol", Kernel, 0, nil)
	for _, withDACL := range []bool{false, true} {
		res, err := s.Capture("/vol/dir", "/vol/file.txt", speccapture.Options{AcceptUnprovenRead: true, WithDACL: withDACL})
		if err != nil {
			t.Fatalf("withDACL=%v: Capture: %v", withDACL, err)
		}
		if !res.HasSACL() || res.KeepsDACL == withDACL {
			t.Errorf("withDACL=%v: HasSACL=%v KeepsDACL=%v", withDACL, res.HasSACL(), res.KeepsDACL)
		}
	}
}

func TestCaptureArgumentOrderErrorNotSessionLost(t *testing.T) {
	b := newFakeSessionBackend("/vol")
	s := connectFake(t, b, "/vol", Kernel, 0, nil)
	_, err := s.Capture("/vol/file.txt", "/vol/dir", speccapture.Options{AcceptUnprovenRead: true})
	if err == nil {
		t.Fatal("expected reversed-argument error")
	}
	if errors.Is(err, ErrSessionLost) {
		t.Fatalf("argument-order error misclassified as ErrSessionLost: %v", err)
	}
}

func TestCaptureOutsideRootRejected(t *testing.T) {
	b := newFakeSessionBackend("/vol")
	s := connectFake(t, b, "/vol", Kernel, 0, nil)
	if _, err := s.Capture("/other/dir", "/vol/file.txt", speccapture.Options{AcceptUnprovenRead: true}); err == nil {
		t.Fatal("expected rejection")
	}
}

func TestVerifyOutsideRootRejected(t *testing.T) {
	b := newFakeSessionBackend("/vol")
	s := connectFake(t, b, "/vol", Kernel, 0, nil)
	if _, err := s.Verify("/other/scratch", "/vol/dir", "/vol/file.txt", speccapture.Options{AcceptUnprovenRead: true}); err == nil {
		t.Fatal("expected rejection")
	}
}

func TestReadDirEOFClassifiedAsSessionLost(t *testing.T) {
	b := newFakeSessionBackend("/vol")
	b.readDirErr = io.EOF
	s := connectFake(t, b, "/vol", Kernel, 0, nil)
	_, _, err := s.ListDir("/vol", 0)
	if !errors.Is(err, ErrSessionLost) {
		t.Fatalf("err = %v, want ErrSessionLost", err)
	}
}

func TestIdleExpiry(t *testing.T) {
	b := newFakeSessionBackend("/vol")
	cur := time.Unix(0, 0)
	clock := func() time.Time { return cur }
	s := connectFake(t, b, "/vol", Kernel, 10*time.Second, clock)
	cur = cur.Add(11 * time.Second)
	if !s.Expired() {
		t.Fatal("expected session expired")
	}
	if _, _, err := s.ListDir("/vol", 0); !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
}

func TestConcurrentListDirSerializes(t *testing.T) {
	b := newFakeSessionBackend("/vol")
	s := connectFake(t, b, "/vol", Kernel, 0, nil)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := s.ListDir("/vol", 0); err != nil {
				t.Errorf("ListDir: %v", err)
			}
		}()
	}
	wg.Wait()
	if b.maxConc != 1 {
		t.Fatalf("max concurrency = %d, want 1", b.maxConc)
	}
}

func TestExportsKernelUnsupported(t *testing.T) {
	b := newFakeSessionBackend("/vol")
	s := connectFake(t, b, "/vol", Kernel, 0, nil)
	names, supported, err := s.Exports(context.Background())
	if err != nil {
		t.Fatalf("Exports: %v", err)
	}
	if supported || names != nil {
		t.Fatalf("Exports = %v, %v, want nil, false", names, supported)
	}
}

func TestExportsUserspaceDelegatesToDiscover(t *testing.T) {
	b := newFakeSessionBackend("/vol")
	s := connectFake(t, b, "/vol", Userspace, 0, nil)
	savedDiscover := discover
	discover = func(ctx context.Context, cfg nfs41.Config) ([]string, error) {
		return []string{"/b", "/a"}, nil
	}
	t.Cleanup(func() { discover = savedDiscover })
	names, supported, err := s.Exports(context.Background())
	if err != nil {
		t.Fatalf("Exports: %v", err)
	}
	if !supported {
		t.Fatal("expected supported = true")
	}
	if len(names) != 2 || names[0] != "/a" || names[1] != "/b" {
		t.Fatalf("names = %v, want sorted [/a /b]", names)
	}
}

func TestExportsUnsupportedError(t *testing.T) {
	b := newFakeSessionBackend("/vol")
	s := connectFake(t, b, "/vol", Userspace, 0, nil)
	savedDiscover := discover
	discover = func(ctx context.Context, cfg nfs41.Config) ([]string, error) {
		return nil, nfs41.ErrDiscoveryUnsupported
	}
	t.Cleanup(func() { discover = savedDiscover })
	names, supported, err := s.Exports(context.Background())
	if err != nil {
		t.Fatalf("Exports: %v", err)
	}
	if supported || names != nil {
		t.Fatalf("Exports = %v, %v, want nil, false", names, supported)
	}
}

func TestCloseTwice(t *testing.T) {
	b := newFakeSessionBackend("/vol")
	s := connectFake(t, b, "/vol", Kernel, 0, nil)
	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if b.closeCalls != 1 {
		t.Fatalf("backend Close called %d times, want 1", b.closeCalls)
	}
}

// TestVerifyProvesTheBypassInScratch: Verify uses its scratch folder as the
// probe directory, so a backend that cannot create a probe is refused before
// the exemplars are read, even without an explicit ProbeDir.
func TestVerifyProvesTheBypassInScratch(t *testing.T) {
	b := newFakeSessionBackend("/vol")
	s := connectFake(t, b, "/vol", Kernel, 0, nil)
	_, err := s.Verify("/vol/scratch", "/vol/dir", "/vol/file.txt", speccapture.Options{})
	if err == nil || !strings.Contains(err.Error(), `probe directory "/vol/scratch"`) {
		t.Fatalf("Verify err = %v, want the scratch folder used as the probe directory", err)
	}
}

// TestCaptureRefusesAnUnprovenRead: a plain Capture with neither a probe
// directory nor an accepted risk is refused.
func TestCaptureRefusesAnUnprovenRead(t *testing.T) {
	b := newFakeSessionBackend("/vol")
	s := connectFake(t, b, "/vol", Kernel, 0, nil)
	if _, err := s.Capture("/vol/dir", "/vol/file.txt", speccapture.Options{}); !errors.Is(err, speccapture.ErrUnprovenRead) {
		t.Fatalf("Capture err = %v, want ErrUnprovenRead", err)
	}
}
