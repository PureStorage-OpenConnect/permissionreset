package tuning

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestResolveMountUsesLongestContainingNFSMount(t *testing.T) {
	mounts := strings.NewReader(
		"192.0.2.1:/pool /mnt/fb nfs4 rw 0 0\n" +
			"192.0.2.2:/other /mnt/fb/team nfs4 rw,vers=4.1 0 0\n")
	got, err := ResolveMount("/mnt/fb/team/tree", mounts)
	if err != nil {
		t.Fatal(err)
	}
	if got.MountPoint != "/mnt/fb/team" || got.Server != "192.0.2.2" || got.Export != "/other" {
		t.Fatalf("ResolveMount() = %+v", got)
	}
	serverPath, err := ServerPath("/mnt/fb/team/tree", got)
	if err != nil {
		t.Fatal(err)
	}
	if serverPath != "/other/tree" {
		t.Fatalf("ServerPath() = %q", serverPath)
	}
}

func TestResolveMountReturnsNoMountSentinel(t *testing.T) {
	_, err := ResolveMount("/local/tree", strings.NewReader("/dev/sda1 /local ext4 rw 0 0\n"))
	if !errors.Is(err, ErrNoMountForTarget) {
		t.Fatalf("ResolveMount() error = %v, want ErrNoMountForTarget", err)
	}
}

func TestResolveMountUsesLastEntryWhenMountPointsTie(t *testing.T) {
	mounts := strings.NewReader(
		"old:/a /mnt/x nfs4 rw 0 0\n" +
			"new:/b /mnt/x nfs4 rw 0 0\n")
	got, err := ResolveMount("/mnt/x/tree", mounts)
	if err != nil {
		t.Fatal(err)
	}
	if got.Server != "new" || got.Export != "/b" {
		t.Fatalf("ResolveMount() = %+v, want last mount entry new:/b", got)
	}
}

func TestMatchExportRejectsANameMismatch(t *testing.T) {
	m := Mount{Server: "192.0.2.50", Export: "/fb-perms"}
	if err := MatchExport(m, "192.0.2.51", "/fb-perms"); err == nil {
		t.Fatal("MatchExport() error = nil")
	}
}

func TestMatchExportRejectsEmptyIdentityFields(t *testing.T) {
	tests := []struct {
		name   string
		mount  Mount
		server string
		export string
	}{
		{name: "empty requested server", mount: Mount{Server: "s", Export: "/e"}, export: "/e"},
		{name: "empty requested export", mount: Mount{Server: "s", Export: "/e"}, server: "s"},
		{name: "empty mount export", mount: Mount{Server: "s"}, server: "s", export: "/e"},
		{name: "empty mount server", mount: Mount{Export: "/e"}, server: "s", export: "/e"},
		{name: "all empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := MatchExport(tt.mount, tt.server, tt.export); err == nil {
				t.Fatal("MatchExport() error = nil")
			}
		})
	}
}

func TestMatchExportAcceptsDefaultPortAndCleanedExport(t *testing.T) {
	m := Mount{Server: "[2001:db8::1]:2049", Export: "/data/./team"}
	if err := MatchExport(m, "[2001:db8::1]", "/data/team/"); err != nil {
		t.Fatal(err)
	}
}

func TestResolveMountRejectsRelativeTarget(t *testing.T) {
	if _, err := ResolveMount("relative/path", failingReader{t}); err == nil {
		t.Fatal("ResolveMount() error = nil for a relative target")
	}
}

func TestServerPathAtMountPointReturnsExportRoot(t *testing.T) {
	mount := Mount{MountPoint: "/mnt/data", Export: "/export"}
	got, err := ServerPath("/mnt/data", mount)
	if err != nil {
		t.Fatal(err)
	}
	if got != "/export" {
		t.Fatalf("ServerPath() = %q, want export root", got)
	}
}

func TestServerPathRejectsPathOutsideMount(t *testing.T) {
	mount := Mount{MountPoint: "/mnt/data", Export: "/data"}
	if _, err := ServerPath("/mnt/data2/file", mount); err == nil {
		t.Fatal("ServerPath() error = nil for path outside mount")
	}
}

func TestResolveMountHandlesProcMountForms(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		mounts     string
		wantSource string
		wantPoint  string
		wantType   string
		wantServer string
		wantExport string
		wantErr    bool
	}{
		{
			name:       "component boundary excludes a prefix sibling",
			target:     "/mnt/data2/tree",
			mounts:     "wrong:/data /mnt/data nfs4 rw 0 0\nright:/ /mnt nfs rw 0 0\n",
			wantSource: "right:/",
			wantPoint:  "/mnt",
			wantType:   "nfs",
			wantServer: "right",
			wantExport: "/",
		},
		{
			name:       "escaped spaces and backslashes",
			target:     `/mnt/client data/share\name/tree`,
			mounts:     `server:/export\040data/share\134name /mnt/client\040data/share\134name nfs4 rw 0 0` + "\n",
			wantSource: `server:/export data/share\name`,
			wantPoint:  `/mnt/client data/share\name`,
			wantType:   "nfs4",
			wantServer: "server",
			wantExport: `/export data/share\name`,
		},
		{
			name:       "non NFS mount ignored",
			target:     "/mnt/data/tree",
			mounts:     "/dev/sda1 /mnt/data ext4 rw 0 0\nserver:/ /mnt nfs4 rw 0 0\n",
			wantSource: "server:/",
			wantPoint:  "/mnt",
			wantType:   "nfs4",
			wantServer: "server",
			wantExport: "/",
		},
		{
			name:       "host source",
			target:     "/mnt/data",
			mounts:     "host:/export /mnt/data nfs4 rw 0 0\n",
			wantSource: "host:/export",
			wantPoint:  "/mnt/data",
			wantType:   "nfs4",
			wantServer: "host",
			wantExport: "/export",
		},
		{
			name:       "bracketed IPv6 source",
			target:     "/mnt/data/tree",
			mounts:     "[2001:db8::1]:/export /mnt/data nfs4 rw 0 0\n",
			wantSource: "[2001:db8::1]:/export",
			wantPoint:  "/mnt/data",
			wantType:   "nfs4",
			wantServer: "[2001:db8::1]",
			wantExport: "/export",
		},
		{
			name:    "source lacks export",
			target:  "/mnt/data/tree",
			mounts:  "server /mnt/data nfs4 rw 0 0\n",
			wantErr: true,
		},
		{
			name:    "truncated octal escape",
			target:  "/mnt/data/tree",
			mounts:  "server:/data\\04 /mnt/data nfs4 rw 0 0\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveMount(tt.target, strings.NewReader(tt.mounts))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ResolveMount() = %+v, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Source != tt.wantSource || got.MountPoint != tt.wantPoint || got.FSType != tt.wantType ||
				got.Server != tt.wantServer || got.Export != tt.wantExport {
				t.Fatalf("ResolveMount() = %+v", got)
			}
		})
	}
}

type failingReader struct{ t *testing.T }

func (r failingReader) Read([]byte) (int, error) {
	r.t.Fatal("mounts read on the userspace path")
	return 0, nil
}

func TestKernelKeyUsesResolvedMountIdentity(t *testing.T) {
	mounts := strings.NewReader("192.0.2.1:/data /mnt/data nfs4 rw 0 0\n")
	got, err := KernelKey([]string{"host-b", "host-a"}, "/mnt/data/tree", mounts)
	if err != nil {
		t.Fatal(err)
	}
	want, err := NewKey([]string{"host-a", "host-b"}, "192.0.2.1", "/data", "kernel")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(want) {
		t.Fatalf("KernelKey() = %+v, want %+v", got, want)
	}
	if got.String() != "host-a,host-b@192.0.2.1:/data/kernel" {
		t.Fatalf("Key.String() = %q", got.String())
	}
}

func TestUserspaceKeyConsultsNoMounts(t *testing.T) {
	_ = failingReader{t} // not passed anywhere: UserspaceKey takes no reader by design
	got, err := UserspaceKey([]string{"host-a"}, "192.0.2.1", "/data/")
	if err != nil {
		t.Fatal(err)
	}
	want, err := NewKey([]string{"host-a"}, "192.0.2.1", "/data", "userspace")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(want) {
		t.Fatalf("key = %+v, want %+v", got, want)
	}
}

func TestNewKeyAcceptsOnlySupportedTransports(t *testing.T) {
	for _, transport := range []string{"kernel", "userspace"} {
		t.Run(transport, func(t *testing.T) {
			if _, err := NewKey([]string{"host-a"}, "192.0.2.1", "/data", transport); err != nil {
				t.Fatalf("NewKey() rejected supported transport %q: %v", transport, err)
			}
		})
	}
	if _, err := NewKey([]string{"host-a"}, "192.0.2.1", "/data", "kernal"); err == nil {
		t.Fatal("NewKey() error = nil for unsupported transport typo")
	}
}

func TestNewKeyCanonicalizesClientOrder(t *testing.T) {
	clients := []string{"host-b", "host-a", "host-a"}
	before := append([]string(nil), clients...)
	a, err := NewKey(clients, "192.0.2.1", "/data", "userspace")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewKey([]string{"host-a", "host-b"}, "192.0.2.1", "/data", "userspace")
	if err != nil {
		t.Fatal(err)
	}
	if !a.Equal(b) {
		t.Fatalf("%v != %v: order or duplicates leaked into identity", a, b)
	}
	if got := len(a.Clients); got != 2 {
		t.Fatalf("clients = %d, want 2 after dedupe", got)
	}
	if !reflect.DeepEqual(clients, before) {
		t.Fatalf("NewKey() mutated caller slice: got %v, want %v", clients, before)
	}
}

func TestNewKeyRejectsAnEmptyClientList(t *testing.T) {
	if _, err := NewKey(nil, "192.0.2.1", "/data", "userspace"); err == nil {
		t.Fatal("NewKey() error = nil for an empty client list")
	}
}

func TestNewKeyRejectsClientNamesThatMakeStringAmbiguous(t *testing.T) {
	for _, client := range []string{"host-a,host-b", "host-a@lab"} {
		t.Run(client, func(t *testing.T) {
			if _, err := NewKey([]string{client}, "192.0.2.1", "/data", "userspace"); err == nil {
				t.Fatalf("NewKey() error = nil for client %q", client)
			}
		})
	}
}

func TestLookupRequiresExactClientSetNotMembership(t *testing.T) {
	cluster := Entry{Clients: []string{"host-a", "host-b", "host-c", "host-d"},
		Server: "192.0.2.1", Export: "/data", Transport: "userspace",
		Params: Params{Connections: 32}}
	file := File{Version: Version, Tunings: []Entry{cluster}}

	solo, err := NewKey([]string{"host-a"}, "192.0.2.1", "/data", "userspace")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := file.Lookup(solo); ok {
		t.Fatal("Lookup() matched a 4-client entry for a solo run: those params were " +
			"measured with three other hosts sharing the array")
	}
	if _, ok := file.Lookup(cluster.Key()); !ok {
		t.Fatal("Lookup() missed the exact client set")
	}
}

func TestInvalidEntryKeyMatchesNothing(t *testing.T) {
	invalid := Entry{Clients: []string{""}, Server: "s", Export: "/e", Transport: "kernel"}
	file := File{Version: Version, Tunings: []Entry{invalid}}
	if _, ok := file.Lookup(Key{}); ok {
		t.Fatal("Lookup() matched a partially-invalid entry's zero key")
	}
}

func TestEqualRejectsInvalidKeys(t *testing.T) {
	if (Key{}).Equal(Key{}) {
		t.Fatal("two invalid zero keys compared equal")
	}
	valid, err := NewKey([]string{"host-a", "host-b"}, "s", "/e", "kernel")
	if err != nil {
		t.Fatal(err)
	}
	if valid.Equal(Key{}) || (Key{}).Equal(valid) {
		t.Fatal("a valid and invalid key compared equal")
	}
	for name, invalid := range map[string]Key{
		"empty client":          {Clients: []string{""}, Server: "s", Export: "/e", Transport: "kernel"},
		"unsorted clients":      {Clients: []string{"host-b", "host-a"}, Server: "s", Export: "/e", Transport: "kernel"},
		"duplicate clients":     {Clients: []string{"host-a", "host-a"}, Server: "s", Export: "/e", Transport: "kernel"},
		"unclean export":        {Clients: []string{"host-a", "host-b"}, Server: "s", Export: "/e/", Transport: "kernel"},
		"unsupported transport": {Clients: []string{"host-a", "host-b"}, Server: "s", Export: "/e", Transport: "kernal"},
	} {
		t.Run(name, func(t *testing.T) {
			if invalid.Equal(invalid) {
				t.Fatalf("invalid key compared equal: %+v", invalid)
			}
		})
	}
}
