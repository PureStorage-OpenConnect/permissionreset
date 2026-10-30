package tuning

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestValidateParamsRequiresUserspaceConnections(t *testing.T) {
	params := Params{Connections: 0, Workers: 128, BatchSize: 50}
	if err := ValidateParams(params, "userspace", nil, 1024); err == nil || !strings.Contains(err.Error(), "connections absent or zero") {
		t.Fatalf("ValidateParams() error = %v, want missing connections", err)
	}
	if err := ValidateParams(params, "kernel", nil, 1024); err != nil {
		t.Fatalf("kernel's inapplicable zero connections was rejected: %v", err)
	}
}

func TestSaveLoadAndReplaceOneKeyInPlace(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	first := Entry{Clients: []string{"host-a"}, Server: "192.0.2.1", Export: "/data", Transport: "userspace",
		Params: Params{Connections: 16, Slots: 8, Workers: 1024, BatchSize: 50}}
	second := Entry{Clients: []string{"host-b"}, Server: "192.0.2.2", Export: "/data", Transport: "kernel"}
	file := File{Version: Version, Tunings: []Entry{first, second}}
	if err := Save(path, file); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	first.Params.Connections = 32
	loaded.Upsert(first)
	if len(loaded.Tunings) != 2 {
		t.Fatalf("entries = %d, want 2", len(loaded.Tunings))
	}
	if loaded.Tunings[0].Params.Connections != 32 {
		t.Fatalf("replacement moved or failed: %+v", loaded.Tunings)
	}
	// Entry now contains slices, so == does not compile. reflect.DeepEqual is the check.
	if !reflect.DeepEqual(loaded.Tunings[1], second) {
		t.Fatalf("unrelated entry changed: %+v", loaded.Tunings[1])
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0644 {
		t.Fatalf("mode = %04o, want 0644", got)
	}
}

func TestUpsertCopiesEntrySlices(t *testing.T) {
	clients := []string{"host-a"}
	perClient := []ClientMeasurement{{Client: "host-a", Bound: true}}
	entry := Entry{Clients: clients, Server: "s", Export: "/e", Transport: "kernel",
		Measured: Measured{PerClient: perClient}}
	var file File
	file.Upsert(entry) // append path

	clients[0] = "host-z"
	perClient[0].Client = "host-z"
	if got := file.Tunings[0]; got.Clients[0] != "host-a" || got.Measured.PerClient[0].Client != "host-a" {
		t.Fatalf("Upsert() append retained caller slices: %+v", got)
	}

	clients = []string{"host-a"}
	perClient = []ClientMeasurement{{Client: "host-a", Bound: false}}
	entry.Clients = clients
	entry.Measured.PerClient = perClient
	file.Upsert(entry) // replace path
	clients[0] = "host-z"
	perClient[0].Client = "host-z"
	if got := file.Tunings[0]; got.Clients[0] != "host-a" || got.Measured.PerClient[0].Client != "host-a" {
		t.Fatalf("Upsert() replace retained caller slices: %+v", got)
	}
}

func TestLookupReturnsCopiedEntrySlices(t *testing.T) {
	entry := Entry{Clients: []string{"host-a"}, Server: "s", Export: "/e", Transport: "kernel",
		Measured: Measured{PerClient: []ClientMeasurement{{Client: "host-a", Bound: true}}}}
	file := File{Tunings: []Entry{entry}}
	got, ok := file.Lookup(entry.Key())
	if !ok {
		t.Fatal("Lookup() missed entry")
	}

	got.Clients[0] = "host-z"
	got.Measured.PerClient[0].Client = "host-z"
	stored := file.Tunings[0]
	if stored.Clients[0] != "host-a" || stored.Measured.PerClient[0].Client != "host-a" {
		t.Fatalf("Lookup() exposed stored slices: %+v", stored)
	}
}

func TestUpsertInvalidKeysNeverReplaceEntries(t *testing.T) {
	invalid := Entry{Clients: []string{""}, Server: "s", Export: "/e", Transport: "kernel"}
	valid := Entry{Clients: []string{"host-a"}, Server: "s", Export: "/e", Transport: "kernel"}

	t.Run("invalid incoming key", func(t *testing.T) {
		file := File{Tunings: []Entry{invalid}}
		file.Upsert(invalid)
		if len(file.Tunings) != 2 {
			t.Fatalf("entries = %d, want invalid incoming entry appended", len(file.Tunings))
		}
	})

	t.Run("invalid stored key", func(t *testing.T) {
		file := File{Tunings: []Entry{invalid}}
		file.Upsert(valid)
		if len(file.Tunings) != 2 || !reflect.DeepEqual(file.Tunings[0], invalid) {
			t.Fatalf("tunings = %+v, want invalid stored entry untouched", file.Tunings)
		}
	})
}

func TestUpsertAppendsNewKey(t *testing.T) {
	first := Entry{Clients: []string{"host-a"}, Server: "s", Export: "/e", Transport: "kernel"}
	second := Entry{Clients: []string{"host-b"}, Server: "s", Export: "/e", Transport: "kernel"}
	file := File{Version: Version, Tunings: []Entry{first}}
	file.Upsert(second)
	if len(file.Tunings) != 2 || !reflect.DeepEqual(file.Tunings[1], second) {
		t.Fatalf("tunings = %+v, want appended second entry", file.Tunings)
	}
}

func TestPathForExecutableUsesExecutableDirectory(t *testing.T) {
	got := PathForExecutable(filepath.Join("/opt", "permissionreset", "bin", "permissionreset"))
	want := filepath.Join("/opt", "permissionreset", "bin", FileName)
	if got != want {
		t.Fatalf("PathForExecutable() = %q, want %q", got, want)
	}
}

func TestDefaultPathUsesRunningExecutableDirectory(t *testing.T) {
	got, err := DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if want := PathForExecutable(executable); got != want {
		t.Fatalf("DefaultPath() = %q, want %q", got, want)
	}
}

func TestSaveCanonicalizesEntryIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	originalClients := []string{"host-b", "host-a", "host-a"}
	file := File{Version: Version, Tunings: []Entry{{
		Clients: originalClients, Server: "s", Export: "/e/", Transport: "kernel",
	}}}
	if err := Save(path, file); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(file.Tunings[0].Clients, originalClients) || file.Tunings[0].Export != "/e/" {
		t.Fatalf("Save() mutated caller file: %+v", file.Tunings[0])
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "clients:\n        - host-a\n        - host-b\n      server: s\n      export: /e\n"
	if !strings.Contains(string(body), want) {
		t.Fatalf("Save() wrote noncanonical identity:\n%s", body)
	}
}

func TestLoadCanonicalizesClients(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	body := "version: 1\ntunings:\n  - clients: [host-b, host-a, host-a]\n    server: s\n    export: /e/\n    transport: kernel\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"host-a", "host-b"}
	if !reflect.DeepEqual(file.Tunings[0].Clients, want) {
		t.Fatalf("clients = %v, want %v", file.Tunings[0].Clients, want)
	}
	key, err := NewKey(want, "s", "/e", "kernel")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := file.Lookup(key); !ok {
		t.Fatal("Lookup() missed clients loaded in a different order")
	}
}

func TestNilPerClientIsOmittedAndRoundTripsNil(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	file := File{Version: Version, Tunings: []Entry{{
		Clients: []string{"host-a"}, Server: "s", Export: "/e", Transport: "kernel",
	}}}
	if err := Save(path, file); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "per_client:") {
		t.Fatalf("nil PerClient was emitted:\n%s", body)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Tunings[0].Measured.PerClient != nil {
		t.Fatalf("PerClient = %#v, want nil", loaded.Tunings[0].Measured.PerClient)
	}
}

func TestSaveRejectsDuplicateCanonicalKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	file := File{Version: Version, Tunings: []Entry{
		{Clients: []string{"host-b", "host-a"}, Server: "s", Export: "/e/", Transport: "kernel"},
		{Clients: []string{"host-a", "host-b", "host-a"}, Server: "s", Export: "/e", Transport: "kernel"},
	}}
	if err := Save(path, file); err == nil {
		t.Fatal("Save() error = nil for duplicate canonical keys")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("destination exists after validation failure: %v", err)
	}
}

func TestSaveFailureLeavesExistingDestinationIntact(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses parent directory write permissions")
	}
	parent := t.TempDir()
	path := filepath.Join(parent, FileName)
	old := []byte("existing tuning content\n")
	if err := os.WriteFile(path, old, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0755) })

	file := File{Version: Version, Tunings: []Entry{{
		Clients: []string{"host-a"}, Server: "s", Export: "/e", Transport: "kernel",
	}}}
	if err := Save(path, file); err == nil {
		t.Fatal("Save() error = nil in unwritable parent directory")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, old) {
		t.Fatalf("destination changed after failed Save(): got %q, want %q", got, old)
	}
}

func TestSaveRemovesTemporaryFileWhenRenameFails(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, FileName)
	if err := os.Mkdir(path, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "keep"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	file := File{Version: Version, Tunings: []Entry{{
		Clients: []string{"host-a"}, Server: "s", Export: "/e", Transport: "kernel",
	}}}
	if err := Save(path, file); err == nil {
		t.Fatal("Save() error = nil when destination is a non-empty directory")
	}
	leftovers, err := filepath.Glob(filepath.Join(parent, "."+FileName+"-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("temporary tuning files left behind: %v", leftovers)
	}
}

func TestLoadAcceptsRegularFileAndSymlinkToRegularFile(t *testing.T) {
	body := []byte("version: 1\ntunings: []\n")
	regular := filepath.Join(t.TempDir(), "regular.yaml")
	if err := os.WriteFile(regular, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(regular); err != nil {
		t.Fatalf("Load(regular) error = %v", err)
	}

	link := filepath.Join(t.TempDir(), FileName)
	if err := os.Symlink(regular, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := Load(link); err != nil {
		t.Fatalf("Load(symlink to regular) error = %v", err)
	}
}

func TestLoadRejectsDanglingSymlinkAndNonRegularFiles(t *testing.T) {
	t.Run("dangling symlink", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), FileName)
		if err := os.Symlink(filepath.Join(t.TempDir(), "missing"), path); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "inspect tuning file target") {
			t.Fatalf("Load() error = %v, want dangling-target inspection error", err)
		} else if errors.Is(err, os.ErrNotExist) {
			t.Fatalf("dangling symlink error still classifies as absent: %v", err)
		}
	})

	t.Run("directory", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), FileName)
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("Load() error = %v, want non-regular-file error", err)
		}
	})

	t.Run("fifo does not block", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), FileName)
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Skipf("FIFO unavailable: %v", err)
		}
		done := make(chan error, 1)
		go func() {
			_, err := Load(path)
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "not a regular file") {
				t.Fatalf("Load() error = %v, want non-regular-file error", err)
			}
		case <-time.After(time.Second):
			t.Fatal("Load() blocked opening a FIFO")
		}
	})
}

func TestLoadRejectsDuplicateCanonicalKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	body := "version: 1\ntunings:\n" +
		"  - clients: [host-b, host-a]\n    server: s\n    export: /e/\n    transport: kernel\n" +
		"  - clients: [host-a, host-b, host-a]\n    server: s\n    export: /e\n    transport: kernel\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load() error = nil for duplicate canonical keys")
	}
}

func TestLoadRejectsNonIntegerParameterScalars(t *testing.T) {
	for _, field := range []string{"connections", "slots", "workers", "batch_size", "max_ops_per_compound"} {
		t.Run(field, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), FileName)
			body := "version: 1\ntunings:\n" +
				"  - clients: [host-a]\n    server: s\n    export: /e\n    transport: kernel\n" +
				"    params:\n      " + field + ": 32.5\n"
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "must be a plain base-10 integer") {
				t.Fatalf("Load() error = %v, want integer-scalar rejection", err)
			}
		})
	}
}

// TestLoadRejectsLiteralsThatChangeValue covers the forms YAML resolves as !!int
// while reading them as a different number than the digits written, plus the
// forms that are not integers at all. A tag comparison accepts the first group,
// which is what made "workers: 0100" load and then announce workers=64.
func TestLoadRejectsLiteralsThatChangeValue(t *testing.T) {
	for name, literal := range map[string]string{
		"zero padded octal":   "0100",
		"leading zero":        "007",
		"hexadecimal":         "0x20",
		"octal prefix":        "0o17",
		"underscore grouping": "1_000",
		"explicit sign":       "+32",
		"double quoted":       `"32"`,
		"single quoted":       "'32'",
		"float":               "32.0",
		"exponent":            "1e3",
		"boolean":             "true",
		"null":                "null",
		"absent value":        "",
		"sequence":            "[1, 2]",
		"mapping":             "{a: 1}",
		"overflow":            "99999999999999999999",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), FileName)
			body := "version: 1\ntunings:\n" +
				"  - clients: [host-a]\n    server: s\n    export: /e\n    transport: kernel\n" +
				"    params:\n      workers: " + literal + "\n"
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if err == nil {
				t.Fatalf("Load() accepted workers: %s", literal)
			}
			if !strings.Contains(err.Error(), "tuning param workers") {
				t.Fatalf("Load() error = %v, want a message naming the parameter", err)
			}
			assertMessageIsComplete(t, err)
		})
	}
}

// TestLoadRejectsAliasParamLegibly pins the message shape for an alias, whose
// node carries no tag: reporting the tag rendered a sentence ending in "got ".
func TestLoadRejectsAliasParamLegibly(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	body := "version: 1\ntunings:\n" +
		"  - clients: [host-a]\n    server: &anchored s\n    export: /e\n    transport: kernel\n" +
		"    params:\n      workers: *anchored\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() accepted an alias parameter")
	}
	if !strings.Contains(err.Error(), "a YAML alias") {
		t.Fatalf("Load() error = %v, want a message naming the alias", err)
	}
	assertMessageIsComplete(t, err)
}

// assertMessageIsComplete rejects a message that trails off after "got",
// which is what a node with no tag produced when the tag was the message.
func assertMessageIsComplete(t *testing.T, err error) {
	t.Helper()
	message := err.Error()
	if strings.HasSuffix(message, "got") || strings.HasSuffix(message, "got ") {
		t.Fatalf("Load() error = %q, want text after \"got\"", message)
	}
}

// TestLoadAcceptsPlainAndTaggedDecimalIntegers keeps the strict check from
// rejecting what the sweeper writes and what a person reasonably hand-writes.
func TestLoadAcceptsPlainAndTaggedDecimalIntegers(t *testing.T) {
	for name, params := range map[string]string{
		"block plain":  "\n      connections: 32\n      workers: 1024\n      batch_size: 50\n",
		"flow mapping": " {connections: 32, workers: 1024, batch_size: 50}\n",
		"explicit tag": "\n      connections: !!int 32\n      workers: 1024\n      batch_size: 50\n",
		"anchored":     "\n      connections: &c 32\n      workers: 1024\n      batch_size: 50\n",
		"negative":     "\n      connections: -1\n      workers: 1024\n      batch_size: 50\n",
		"zero":         "\n      connections: 0\n      workers: 1024\n      batch_size: 50\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), FileName)
			body := "version: 1\ntunings:\n" +
				"  - clients: [host-a]\n    server: s\n    export: /e\n    transport: kernel\n" +
				"    params:" + params
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			file, err := Load(path)
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			got := file.Tunings[0].Params
			if got.Workers != 1024 || got.BatchSize != 50 {
				t.Fatalf("params = %+v", got)
			}
			if name == "negative" {
				// Range rejection belongs to the command, not the loader.
				if got.Connections != -1 {
					t.Fatalf("connections = %d, want -1 passed through", got.Connections)
				}
				return
			}
			if name == "zero" {
				if got.Connections != 0 {
					t.Fatalf("connections = %d, want 0", got.Connections)
				}
				return
			}
			if got.Connections != 32 {
				t.Fatalf("connections = %d, want 32", got.Connections)
			}
		})
	}
}

func TestLoadRejectsMalformedAndUnsupportedFiles(t *testing.T) {
	for name, body := range map[string]string{
		"malformed":         "version: [",
		"unsupported":       "version: 2\ntunings: []\n",
		"unknown field":     "version: 1\nunknown: true\ntunings: []\n",
		"empty clients":     "version: 1\ntunings:\n  - clients: []\n    server: s\n    export: /e\n    transport: kernel\n",
		"empty client name": "version: 1\ntunings:\n  - clients: ['']\n    server: s\n    export: /e\n    transport: kernel\n",
		"empty server":      "version: 1\ntunings:\n  - clients: [host-a]\n    server: ''\n    export: /e\n    transport: kernel\n",
		"empty export":      "version: 1\ntunings:\n  - clients: [host-a]\n    server: s\n    export: ''\n    transport: kernel\n",
		"empty transport":   "version: 1\ntunings:\n  - clients: [host-a]\n    server: s\n    export: /e\n    transport: ''\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), FileName)
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("Load() error = nil")
			}
		})
	}
}
