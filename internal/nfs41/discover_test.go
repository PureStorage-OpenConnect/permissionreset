package nfs41

import (
	"context"
	"errors"
	"testing"
	"time"
)

func discoverTestConfig(srv *fakeServer) Config {
	return Config{
		Server:         srv.ln.Addr().String(),
		RPCTimeout:     5 * time.Second,
		RetryBaseDelay: time.Millisecond,
	}
}

func TestDiscoverExportsListsDirectories(t *testing.T) {
	srv := startFakeServer(t)
	srv.AddTree(map[string][]fakeEntry{
		"/": {
			{Name: "bbb", FH: "bbb-fh", IsDir: true},
			{Name: "aaa", FH: "aaa-fh", IsDir: true},
			{Name: "notadir", FH: "notadir-fh"},
		},
	})

	got, err := DiscoverExports(context.Background(), discoverTestConfig(srv))
	if err != nil {
		t.Fatalf("DiscoverExports: %v", err)
	}
	want := []string{"/aaa", "/bbb"}
	if len(got) != len(want) {
		t.Fatalf("DiscoverExports = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("DiscoverExports = %v, want %v", got, want)
		}
	}
}

func TestDiscoverExportsEmptyIsUnsupported(t *testing.T) {
	srv := startFakeServer(t)
	srv.AddTree(map[string][]fakeEntry{
		"/": {},
	})

	_, err := DiscoverExports(context.Background(), discoverTestConfig(srv))
	if !errors.Is(err, ErrDiscoveryUnsupported) {
		t.Fatalf("DiscoverExports error = %v, want ErrDiscoveryUnsupported", err)
	}
}

func TestDiscoverExportsNotSuppIsUnsupported(t *testing.T) {
	srv := startFakeServer(t)
	srv.AddTree(map[string][]fakeEntry{
		"/": {{Name: "fs", FH: "fs-fh", IsDir: true}},
	})
	srv.InjectOnce(opREADDIR, NFS4ERR_NOTSUPP)

	_, err := DiscoverExports(context.Background(), discoverTestConfig(srv))
	if !errors.Is(err, ErrDiscoveryUnsupported) {
		t.Fatalf("DiscoverExports error = %v, want ErrDiscoveryUnsupported", err)
	}
}

func TestDiscoverExportsIgnoresGate(t *testing.T) {
	srv := startFakeServer(t, withMaxFileSize(1))
	srv.AddTree(map[string][]fakeEntry{
		"/": {{Name: "fs", FH: "fs-fh", IsDir: true}},
	})

	got, err := DiscoverExports(context.Background(), discoverTestConfig(srv))
	if err != nil {
		t.Fatalf("DiscoverExports: %v", err)
	}
	want := []string{"/fs"}
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("DiscoverExports = %v, want %v", got, want)
	}
}
