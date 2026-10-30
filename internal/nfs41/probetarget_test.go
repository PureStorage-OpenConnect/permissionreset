package nfs41

import (
	"errors"
	"fmt"
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// TestProbeTargetWithSucceedsOnFirstTry pins the common case: resolve the
// directory, mkdir a disposable child on the first attempt, and hand back a
// cleanup that removes exactly that child.
func TestProbeTargetWithSucceedsOnFirstTry(t *testing.T) {
	var mkdirCalls, removeCalls int
	target, isDir, cleanup, err := probeTargetWith(
		func() (transport.Ref, error) { return transport.Ref{Path: "/root"}, nil },
		func(dirRef transport.Ref, name string) (transport.Ref, error) {
			mkdirCalls++
			return transport.Ref{Path: dirRef.Path + "/" + name}, nil
		},
		func(dirRef transport.Ref, name string) error {
			removeCalls++
			return nil
		},
		func() string { return "probe-1" },
	)
	if err != nil {
		t.Fatalf("probeTargetWith() error = %v", err)
	}
	if !isDir {
		t.Fatalf("isDir = false, want true (a disposable directory)")
	}
	if target.Path != "/root/probe-1" {
		t.Fatalf("target.Path = %q, want /root/probe-1", target.Path)
	}
	if mkdirCalls != 1 {
		t.Fatalf("mkdirCalls = %d, want 1", mkdirCalls)
	}
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup() error = %v", err)
	}
	if removeCalls != 1 {
		t.Fatalf("removeCalls = %d, want 1", removeCalls)
	}
}

// TestProbeTargetWithPathResolutionFailure pins that a failure to resolve the
// requested directory fails outright -- it must never fall back to the export
// root or any other live object.
func TestProbeTargetWithPathResolutionFailure(t *testing.T) {
	resolveErr := errors.New("resolve boom")
	_, _, cleanup, err := probeTargetWith(
		func() (transport.Ref, error) { return transport.Ref{}, resolveErr },
		func(transport.Ref, string) (transport.Ref, error) {
			t.Fatal("mkdir must not be called when path resolution fails")
			return transport.Ref{}, nil
		},
		func(transport.Ref, string) error { return nil },
		func() string { return "probe" },
	)
	if cleanup != nil {
		t.Fatal("cleanup != nil, want nil on failure")
	}
	if !errors.Is(err, resolveErr) {
		t.Fatalf("err = %v, want it to wrap %v", err, resolveErr)
	}
}

// TestProbeTargetWithCollisionRetries pins that a name collision (NFS4ERR_EXIST)
// retries with a fresh name rather than failing or falling back to a live
// object.
func TestProbeTargetWithCollisionRetries(t *testing.T) {
	names := []string{"a", "b", "c"}
	var i int
	nextName := func() string {
		n := names[i]
		i++
		return n
	}
	var mkdirNames []string
	_, _, cleanup, err := probeTargetWith(
		func() (transport.Ref, error) { return transport.Ref{Path: "/root"}, nil },
		func(dirRef transport.Ref, name string) (transport.Ref, error) {
			mkdirNames = append(mkdirNames, name)
			if name != "c" {
				return transport.Ref{}, &StatusError{Op: "create", Path: name, Status: NFS4ERR_EXIST}
			}
			return transport.Ref{Path: dirRef.Path + "/" + name}, nil
		},
		func(transport.Ref, string) error { return nil },
		nextName,
	)
	if err != nil {
		t.Fatalf("probeTargetWith() error = %v", err)
	}
	if cleanup == nil {
		t.Fatal("cleanup = nil, want a cleanup func after eventual success")
	}
	want := []string{"a", "b", "c"}
	if fmt.Sprint(mkdirNames) != fmt.Sprint(want) {
		t.Fatalf("mkdir attempted names = %v, want %v", mkdirNames, want)
	}
}

// TestProbeTargetWithCollisionExhaustion pins that persistent collisions fail
// closed after a bounded number of attempts instead of looping forever or
// falling back to a live object.
func TestProbeTargetWithCollisionExhaustion(t *testing.T) {
	var attempts int
	_, _, cleanup, err := probeTargetWith(
		func() (transport.Ref, error) { return transport.Ref{Path: "/root"}, nil },
		func(transport.Ref, string) (transport.Ref, error) {
			attempts++
			return transport.Ref{}, &StatusError{Op: "create", Status: NFS4ERR_EXIST}
		},
		func(transport.Ref, string) error { return nil },
		func() string { return "same-name" },
	)
	if err == nil {
		t.Fatal("probeTargetWith() error = nil, want a collision-exhaustion error")
	}
	if cleanup != nil {
		t.Fatal("cleanup != nil, want nil on failure")
	}
	if attempts == 0 {
		t.Fatal("attempts = 0, want at least one mkdir attempt")
	}
}

// TestProbeTargetWithCreateDenialNeverFallsBackToALiveObject pins the central
// PS-01 requirement: any create failure that is not a name collision fails the
// probe outright, with an actionable explanation, and never substitutes a live
// object (the export root or the requested directory itself) as the probe
// target.
func TestProbeTargetWithCreateDenialNeverFallsBackToALiveObject(t *testing.T) {
	denyErr := &StatusError{Op: "create", Status: NFS4ERR_ACCESS}
	target, _, cleanup, err := probeTargetWith(
		func() (transport.Ref, error) { return transport.Ref{Path: "/root"}, nil },
		func(transport.Ref, string) (transport.Ref, error) { return transport.Ref{}, denyErr },
		func(transport.Ref, string) error { return nil },
		func() string { return "probe" },
	)
	if err == nil {
		t.Fatal("probeTargetWith() error = nil, want a create-denial error")
	}
	if cleanup != nil {
		t.Fatal("cleanup != nil, want nil on failure")
	}
	if target.Path == "/root" {
		t.Fatalf("target = %+v, fell back to the live root directory", target)
	}
}

// TestProbeTargetWithCancellation pins that a context-cancellation error from
// mkdir is treated like any other non-collision failure: fail closed, no live
// fallback.
func TestProbeTargetWithCancellation(t *testing.T) {
	cancelErr := errors.New("context canceled")
	_, _, cleanup, err := probeTargetWith(
		func() (transport.Ref, error) { return transport.Ref{Path: "/root"}, nil },
		func(transport.Ref, string) (transport.Ref, error) { return transport.Ref{}, cancelErr },
		func(transport.Ref, string) error { return nil },
		func() string { return "probe" },
	)
	if !errors.Is(err, cancelErr) {
		t.Fatalf("err = %v, want it to wrap %v", err, cancelErr)
	}
	if cleanup != nil {
		t.Fatal("cleanup != nil, want nil on failure")
	}
}

// TestProbeTargetWithCleanupFailurePropagates pins that a failed removal of
// the disposable probe surfaces to the caller through the cleanup func's
// return value, rather than being silently discarded (PS-01: "propagate
// cleanup failures alongside the original error").
func TestProbeTargetWithCleanupFailurePropagates(t *testing.T) {
	removeErr := errors.New("remove boom")
	_, _, cleanup, err := probeTargetWith(
		func() (transport.Ref, error) { return transport.Ref{Path: "/root"}, nil },
		func(dirRef transport.Ref, name string) (transport.Ref, error) {
			return transport.Ref{Path: dirRef.Path + "/" + name}, nil
		},
		func(transport.Ref, string) error { return removeErr },
		func() string { return "probe" },
	)
	if err != nil {
		t.Fatalf("probeTargetWith() error = %v, want nil (create succeeded)", err)
	}
	cerr := cleanup()
	if !errors.Is(cerr, removeErr) {
		t.Fatalf("cleanup() error = %v, want it to wrap %v", cerr, removeErr)
	}
}

// TestProbeNameIsCollisionSafe pins that probeName generates distinct,
// recognizable names across calls -- the collision-retry loop depends on this.
func TestProbeNameIsCollisionSafe(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		n := probeName()
		if seen[n] {
			t.Fatalf("probeName() produced a duplicate: %q", n)
		}
		seen[n] = true
		if len(n) == 0 {
			t.Fatal("probeName() returned an empty string")
		}
	}
}
