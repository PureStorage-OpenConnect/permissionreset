package treegen

import (
	"errors"
	"strings"
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// fakeDirLister is the smallest thing that answers the two calls the emptiness
// precheck makes. The nfs41 package's fake server lives in a _test.go file in
// package nfs41, so it cannot be imported here; an interface seam is both what
// makes this testable at all and a smaller surface than the whole client.
type fakeDirLister struct {
	// dirs maps an export-relative directory path ("" is the export root) to
	// the names it holds. A name absent from dirs is a file.
	dirs map[string][]string
	err  error

	// errOn fails READDIR on one specific directory, which is how a transport
	// failure partway down a path presents. A single err field cannot express
	// it: it fails Root() first and the walk never starts.
	errOn map[string]error

	readDirs []string // every path READDIR was called on, in order
}

func (f *fakeDirLister) Root() (transport.Ref, error) {
	if f.err != nil {
		return transport.Ref{}, f.err
	}
	return transport.Ref{Path: ""}, nil
}

func (f *fakeDirLister) ReadDir(ref transport.Ref) ([]transport.Dirent, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.readDirs = append(f.readDirs, ref.Path)
	if err, ok := f.errOn[ref.Path]; ok {
		return nil, err
	}
	names, ok := f.dirs[ref.Path]
	if !ok {
		return nil, errors.New("NFS4ERR_NOENT: " + ref.Path)
	}
	var out []transport.Dirent
	for _, n := range names {
		child := n
		if ref.Path != "" {
			child = ref.Path + "/" + n
		}
		_, isDir := f.dirs[child]
		out = append(out, transport.Dirent{Name: n, Ref: transport.Ref{Path: child}, IsDir: isDir})
	}
	return out, nil
}

// Generating a million-object tree into a directory that already holds one
// interleaves two trees and leaves neither usable. On the userspace path there
// is no local view of the target, so this guard goes over the wire or it does
// not exist -- and before this it did not exist, because the os.ReadDir
// precheck sits after the userspace branch has already returned.
func TestUserspaceTargetIsEmptyRefusesPopulatedTarget(t *testing.T) {
	c := &fakeDirLister{dirs: map[string][]string{
		"":            {"tree"},
		"tree":        {"already-here.txt"},
		"tree/nested": {},
	}}
	empty, err := userspaceTargetIsEmpty(c, "tree")
	if err != nil {
		t.Fatalf("userspaceTargetIsEmpty: %v", err)
	}
	if empty {
		t.Fatal("a target holding a file was reported empty")
	}
}

func TestUserspaceTargetIsEmptyAcceptsEmptyTarget(t *testing.T) {
	c := &fakeDirLister{dirs: map[string][]string{"": {"tree"}, "tree": {}}}
	empty, err := userspaceTargetIsEmpty(c, "tree")
	if err != nil {
		t.Fatalf("userspaceTargetIsEmpty: %v", err)
	}
	if !empty {
		t.Fatal("an empty target was reported non-empty")
	}
}

// A target that does not exist is empty for this purpose: the fan-out creates
// it. The local precheck this replaces behaved the same way -- it ignored its
// error and refused only on a successful read of a populated directory -- so
// refusing here would break every first run.
func TestUserspaceTargetIsEmptyTreatsAMissingTargetAsEmpty(t *testing.T) {
	c := &fakeDirLister{dirs: map[string][]string{"": {"something-else"}}}
	empty, err := userspaceTargetIsEmpty(c, "tree")
	if err != nil {
		t.Fatalf("userspaceTargetIsEmpty: %v", err)
	}
	if !empty {
		t.Fatal("a target that does not exist yet was reported non-empty")
	}
}

// A nested target is walked component by component, and a missing component
// anywhere along the way is still "does not exist yet".
func TestUserspaceTargetIsEmptyWalksNestedTargets(t *testing.T) {
	c := &fakeDirLister{dirs: map[string][]string{
		"":            {"a"},
		"a":           {"b"},
		"a/b":         {"c"},
		"a/b/c":       {"file.txt"},
		"a/b/c/other": {},
	}}
	empty, err := userspaceTargetIsEmpty(c, "a/b/c")
	if err != nil {
		t.Fatalf("userspaceTargetIsEmpty: %v", err)
	}
	if empty {
		t.Fatal("a nested target holding a file was reported empty")
	}

	if empty, err = userspaceTargetIsEmpty(c, "a/b/missing/deep"); err != nil {
		t.Fatalf("userspaceTargetIsEmpty: %v", err)
	} else if !empty {
		t.Fatal("a nested target whose parent does not exist was reported non-empty")
	}
}

// The export root itself is a legal target: --export /fb-perms with the
// tree at the top of it means an empty export-relative path, and Trim must not
// turn that into a lookup for a directory named "".
func TestUserspaceTargetIsEmptyHandlesTheExportRoot(t *testing.T) {
	for _, target := range []string{"", "/", "."} {
		c := &fakeDirLister{dirs: map[string][]string{"": {}}}
		empty, err := userspaceTargetIsEmpty(c, target)
		if err != nil {
			t.Fatalf("target %q: %v", target, err)
		}
		if !empty {
			t.Fatalf("target %q: an empty export root was reported non-empty", target)
		}
		for _, p := range c.readDirs {
			if p != "" {
				t.Fatalf("target %q: READDIR on %q; the export root should be read directly", target, p)
			}
		}
	}
}

// A transport failure is not emptiness. Reporting "empty" on a broken
// connection would let the fan-out proceed into a directory nobody could read,
// which is the exact case the guard exists to prevent.
func TestUserspaceTargetIsEmptyPropagatesTransportFailure(t *testing.T) {
	c := &fakeDirLister{err: errors.New("connection reset")}
	empty, err := userspaceTargetIsEmpty(c, "tree")
	if err == nil {
		t.Fatal("a transport failure was reported as a clean answer")
	}
	if empty {
		t.Fatal("a transport failure was reported as empty")
	}
	if !strings.Contains(err.Error(), "connection reset") {
		t.Fatalf("error = %q, want the underlying failure named", err)
	}
}

// A READDIR failure on an intermediate component must not read as "the target
// does not exist yet". It did: lookupChild returned the same false for "not
// found" and "the call failed", and userspaceTargetIsEmpty took that as
// permission to fan a million objects into a directory it never managed to
// look at.
func TestUserspaceTargetIsEmptyPropagatesAnIntermediateReadDirFailure(t *testing.T) {
	f := &fakeDirLister{
		dirs: map[string][]string{
			"":    {"a"},
			"a":   {"b"},
			"a/b": {"a-million-objects-already-here"},
		},
		errOn: map[string]error{"a": errors.New("NFS4ERR_ACCESS")},
	}

	empty, err := userspaceTargetIsEmpty(f, "a/b")
	if err == nil {
		t.Fatalf("error = nil (empty = %v); a populated target was reported on a READDIR that failed", empty)
	}
	if !strings.Contains(err.Error(), "NFS4ERR_ACCESS") {
		t.Fatalf("error = %v, want the transport failure preserved", err)
	}
}
