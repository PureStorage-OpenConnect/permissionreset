package treegen

import (
	"bytes"
	"strings"
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs4acl"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/transport"
)

// fakePathClient records what resolveOrCreatePath and ensureSafetyACE send.
type fakePathClient struct {
	mkdirACL map[string][]byte
	acl      map[string][]byte // GetACL/SetACL store, by Ref.Path
	setCalls int
}

func (f *fakePathClient) Root() (transport.Ref, error) { return transport.Ref{Path: "/"}, nil }

func (f *fakePathClient) ReadDir(transport.Ref) ([]transport.Dirent, error) { return nil, nil }

func (f *fakePathClient) Mkdir(dir transport.Ref, name string, acl []byte, mode uint32) (transport.Ref, error) {
	f.mkdirACL[name] = acl
	return transport.Ref{Path: dir.Path + "/" + name}, nil
}

func (f *fakePathClient) GetACL(ref transport.Ref) ([]byte, error) { return f.acl[ref.Path], nil }

func (f *fakePathClient) SetACL(ref transport.Ref, acl []byte) error {
	f.setCalls++
	f.acl[ref.Path] = acl
	return nil
}

func newFakePathClient() *fakePathClient {
	return &fakePathClient{mkdirACL: map[string][]byte{}, acl: map[string][]byte{}}
}

// Every directory the chain creates gets the ACL at creation, so the next Mkdir
// inside it is not denied. Without it, the first Mkdir under a root that only
// passes down another principal's ACE made a mode-000 directory.
func TestResolveOrCreatePathSetsACLOnEveryCreatedDir(t *testing.T) {
	c := newFakePathClient()
	acl := []byte{1, 2, 3, 4}
	if _, err := resolveOrCreatePath(c, transport.Ref{Path: ""}, "a/b", acl); err != nil {
		t.Fatalf("resolveOrCreatePath: %v", err)
	}
	for _, name := range []string{"a", "b"} {
		if !bytes.Equal(c.mkdirACL[name], acl) {
			t.Fatalf("Mkdir %s acl = %v, want %v", name, c.mkdirACL[name], acl)
		}
	}
}

// A target that already exists is not created, so its ACL has to be fixed in
// place; and a second pass must find the ACE and leave it alone.
func TestEnsureSafetyACEPrependsOnceToExistingTarget(t *testing.T) {
	c := newFakePathClient()
	ref := transport.Ref{Path: "/t"}
	other := nfs4acl.ACE{Type: nfs4acl.TypeAllow, Flags: nfs4acl.FlagDirInherit | nfs4acl.FlagGroup, Mask: nfs4acl.MaskReadData, Who: "1000000513"}
	c.acl["/t"] = nfs4acl.Encode([]nfs4acl.ACE{other})
	safety := safetyACE(t, "jdoe@example.net")

	if err := ensureSafetyACE(c, ref, safety); err != nil {
		t.Fatalf("first ensureSafetyACE: %v", err)
	}
	got, err := nfs4acl.DecodeACL(c.acl["/t"])
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != safety || got[1] != other {
		t.Fatalf("ACL = %+v, want [safety other]", got)
	}

	if err := ensureSafetyACE(c, ref, safety); err != nil {
		t.Fatalf("second ensureSafetyACE: %v", err)
	}
	if c.setCalls != 1 {
		t.Fatalf("SetACL called %d times, want 1: a rerun must not rewrite the ACL", c.setCalls)
	}
}

// The mount-translated target must be relative to the export. A path that
// repeats the export's name is created one level too deep on the server.
func TestResolveExportRelTargetDropsTheExportName(t *testing.T) {
	const table = "s200-datavip0:/fs01 /mnt/fb/c09-33/fs01 nfs4 rw,vers=4.1 0 0\n"
	rel, _, err := resolveExportRelTarget("/mnt/fb/c09-33/fs01/xlarge_userspace", "/fs01", strings.NewReader(table))
	if err != nil {
		t.Fatal(err)
	}
	if rel != "xlarge_userspace" {
		t.Fatalf("rel = %q, want %q", rel, "xlarge_userspace")
	}
}

// A sibling directory whose name merely starts with the export's name, and an
// export of "/", both have to come out as plain components.
func TestResolveExportRelTargetIsComponentAware(t *testing.T) {
	cases := []struct{ table, target, export, want string }{
		{"h:/fs /mnt/fs nfs4 rw 0 0\n", "/mnt/fs/fs-old/x", "/fs", "fs-old/x"},
		{"h:/ /mnt/root nfs4 rw 0 0\n", "/mnt/root/x/y", "/", "x/y"},
	}
	for _, c := range cases {
		rel, _, err := resolveExportRelTarget(c.target, c.export, strings.NewReader(c.table))
		if err != nil {
			t.Fatalf("%s: %v", c.target, err)
		}
		if rel != c.want {
			t.Fatalf("%s on export %s: rel = %q, want %q", c.target, c.export, rel, c.want)
		}
	}
}
