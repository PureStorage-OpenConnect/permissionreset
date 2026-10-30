package treegen

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs4acl"
)

// A target on a filesystem with no NFSv4 ACL (a tmpdir) is created and left
// alone: the ACL read fails with "no such attribute", and that is not an error.
func TestEnsureSafetyRootCreatesTargetWithoutACLSupport(t *testing.T) {
	target := filepath.Join(t.TempDir(), "a", "b")
	if err := ensureSafetyRoot(target, "jdoe@example.net"); err != nil {
		t.Fatalf("ensureSafetyRoot: %v", err)
	}
	if fi, err := os.Stat(target); err != nil || !fi.IsDir() {
		t.Fatalf("target not created as a directory: %v", err)
	}
}

func safetyACE(t *testing.T, who string) nfs4acl.ACE {
	t.Helper()
	aces, err := parseACEs([]string{ace("A", "fd", who, MaskFull)})
	if err != nil {
		t.Fatal(err)
	}
	return aces[0]
}

// The safety ACE goes first, and the ACEs already there follow it unchanged,
// inherited flag included.
func TestWithSafetyACEPrependsAndKeepsExisting(t *testing.T) {
	other := nfs4acl.ACE{
		Type:  nfs4acl.TypeAllow,
		Flags: nfs4acl.FlagFileInherit | nfs4acl.FlagDirInherit | nfs4acl.FlagGroup | nfs4acl.FlagInherited,
		Mask:  nfs4acl.MaskReadData,
		Who:   "1000000513",
	}
	safety := safetyACE(t, "jdoe@example.net")

	got, changed := withSafetyACE([]nfs4acl.ACE{other}, safety)
	if !changed {
		t.Fatal("changed = false, want true")
	}
	if len(got) != 2 || got[0] != safety || got[1] != other {
		t.Fatalf("got %+v, want [safety other]", got)
	}
}

// A rerun against the same target must not stack a second copy.
func TestWithSafetyACEIsIdempotent(t *testing.T) {
	safety := safetyACE(t, "jdoe@example.net")
	first, _ := withSafetyACE(nil, safety)

	dup := safety
	dup.Who = "JDOE@example.net"
	got, changed := withSafetyACE(first, dup)
	if changed || len(got) != 1 {
		t.Fatalf("changed=%v len=%d, want false and 1", changed, len(got))
	}
}

// An ACE for the same principal with different flags is not the safety ACE: a
// non-inheritable owner ACE does not give the seed directory its access.
func TestWithSafetyACENonInheritableDoesNotCount(t *testing.T) {
	safety := safetyACE(t, "jdoe@example.net")
	plain := safety
	plain.Flags = 0

	got, changed := withSafetyACE([]nfs4acl.ACE{plain}, safety)
	if !changed || len(got) != 2 {
		t.Fatalf("changed=%v len=%d, want true and 2", changed, len(got))
	}
}
