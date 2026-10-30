package main

// Platform-gate and flag-surface tests for generate-tree.
//
// These drive run() in-process, which is what makes the capability seam
// testable: cmdflagstest.With swaps `caps` so one Linux test binary exercises
// the darwin branch of every gate. main_test.go's tests build and exec the real
// binary instead, and cannot do that -- a subprocess gets the host's true
// capabilities. Both styles are wanted; they are in separate files because they
// need different imports and answer different questions.

import (
	"bytes"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/cmdflags/cmdflagstest"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/platform"
)

// The matrix row the spec always promised and no task delivered. A default
// macOS run must refuse at startup, naming the transport that works -- not
// build a million-file tree and then fail per object on a missing xattr.
func TestGenerateTreeRefusesKernelTransportWithoutIt(t *testing.T) {
	cmdflagstest.With(t, &caps, platform.Darwin())

	var out, errOut bytes.Buffer
	code := run([]string{"--transport", "kernel", "/tmp/tree"}, &out, &errOut)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr = %q", code, errOut.String())
	}
	got := errOut.String()
	if !strings.Contains(got, "system.nfs4_acl") {
		t.Fatalf("error = %q, want it to name the missing capability", got)
	}
	if !strings.Contains(got, "--transport=userspace") {
		t.Fatalf("error = %q, want it to name the transport that does work here", got)
	}
	if strings.Contains(got, "requires Linux") {
		t.Fatalf("error = %q; name the capability, not an OS", got)
	}
}

// The default must not BE kernel where kernel cannot work. Without this the
// gate only helps operators who type the flag, and the common invocation --
// no --transport at all -- still walks into setxattr.
func TestGenerateTreeDefaultsToUserspaceWithoutKernelTransport(t *testing.T) {
	cmdflagstest.With(t, &caps, platform.Darwin())

	if got := defaultGenTreeTransport(); got != "userspace" {
		t.Fatalf("default transport = %q on darwin, want userspace", got)
	}
}

func TestGenerateTreeDefaultsToKernelWithIt(t *testing.T) {
	cmdflagstest.With(t, &caps, platform.Linux())

	if got := defaultGenTreeTransport(); got != "kernel" {
		t.Fatalf("default transport = %q on linux, want kernel", got)
	}
}

// A macOS run that names no transport must not be refused: the default moved
// to the value that works. This is the invocation the gate exists for, and
// testing only the typed flag would miss it entirely.
func TestGenerateTreeDefaultRunIsNotRefusedOnDarwin(t *testing.T) {
	cmdflagstest.With(t, &caps, platform.Darwin())

	// Real arguments, not --help: --help returns from fs.Parse before the gate
	// is consulted at all, so it would pass whatever the default became.
	var out, errOut bytes.Buffer
	run([]string{"--principals", minimalPrincipals(t), "--server", "s", "--export", "/e", "--dry-run", "/bigdata"}, &out, &errOut)
	if got := errOut.String(); strings.Contains(got, "is unavailable on this build") {
		t.Fatalf("a darwin run with no --transport was refused: %q", got)
	}
}

// --transport=userspace is the value that works on macOS, so the flag stays
// visible and the value is accepted.
func TestGenerateTreeAcceptsUserspaceOnDarwin(t *testing.T) {
	cmdflagstest.With(t, &caps, platform.Darwin())

	var out, errOut bytes.Buffer
	run([]string{"--transport", "userspace", "--principals", minimalPrincipals(t),
		"--server", "s", "--export", "/e", "--dry-run", "/bigdata"}, &out, &errOut)
	if got := errOut.String(); strings.Contains(got, "is unavailable on this build") {
		t.Fatalf("--transport=userspace was refused on darwin: %q", got)
	}

	// Separately: the flag stays in --help, because its working value is the
	// one this platform needs.
	var helpOut, helpErr bytes.Buffer
	run([]string{"--help"}, &helpOut, &helpErr)
	if help := helpOut.String() + helpErr.String(); !strings.Contains(help, "-transport") {
		t.Error("-transport is hidden; userspace works here and must be discoverable")
	}
}

// The credential flags reach this binary too. Without them a macOS
// generate-tree creates every object as uid 501 with no way to say otherwise.
func TestGenerateTreeRegistersAuthFlags(t *testing.T) {
	cmdflagstest.With(t, &caps, platform.Darwin())

	var out, errOut bytes.Buffer
	run([]string{"--help"}, &out, &errOut)
	help := out.String() + errOut.String()
	for _, name := range []string{"-auth-uid", "-auth-gid", "-auth-gids", "-auth-hostname"} {
		if !strings.Contains(help, name) {
			t.Errorf("%s missing from generate-tree --help", name)
		}
	}
}

// An unknown flag is exit 2 and a usage dump, not a panic -- the seam has to
// behave like a command, not like a function that happens to take args.
func TestGenerateTreeRejectsUnknownFlag(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"--nope"}, &out, &errOut); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

// The seam must not write to the real stdout/stderr, or a test cannot see what
// the command said. Every diagnostic below goes through the injected writers.
func TestGenerateTreeUsageErrorsGoToTheInjectedWriter(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no target", []string{}, "TARGET"},
		{"missing principals", []string{"/tmp/tree"}, "--principals is required"},
		{"two targets", []string{"/tmp/a", "/tmp/b"}, "TARGET"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := run(tc.args, &out, &errOut); code != 1 {
				t.Fatalf("exit code = %d, want 1", code)
			}
			if got := out.String() + errOut.String(); !strings.Contains(got, tc.want) {
				t.Fatalf("output = %q, want it to mention %q", got, tc.want)
			}
		})
	}
}

// --server and --export are required on the userspace transport, and on macOS
// that is the only transport, so this is the first thing a Mac operator will
// hit. It must be a clean refusal rather than a connect to "".
func TestGenerateTreeRequiresServerAndExportOnUserspace(t *testing.T) {
	cmdflagstest.With(t, &caps, platform.Darwin())

	var out, errOut bytes.Buffer
	code := run([]string{"--principals", minimalPrincipals(t), "--transport", "userspace", "/tmp/tree"}, &out, &errOut)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if got := errOut.String(); !strings.Contains(got, "--server") || !strings.Contains(got, "--export") {
		t.Fatalf("error = %q, want both --server and --export named", got)
	}
}

// Every flag this command registers is classified. Per-flag assertions naming
// -transport by hand cannot see a mount-dependent flag someone adds later, and
// on macOS the compiler will not catch it either. generate-tree is the binary
// where an ungated mount-dependent flag costs the most: it creates objects
// rather than fixing them.
func TestEveryGenerateTreeFlagIsClassified(t *testing.T) {
	// portable: works identically on every platform this version ships.
	portable := map[string]bool{
		"principals": true, "scale": true, "workers": true, "beastmode": true,
		"seed": true, "acls-only": true, "no-acls": true, "dry-run": true,
		"safety-principal": true, "files-per-subtree": true, "copies": true,
		"seed-files": true, "max-depth": true, "server": true, "export": true,
		"connections": true, "manifest": true,
		// The AUTH_SYS flags are ungated on purpose: they are how you present a
		// different identity on any platform, without sudo -u.
		"auth-uid": true, "auth-gid": true, "auth-gids": true, "auth-hostname": true,
		// transport is value-gated, not presence-gated: the flag is portable,
		// one of its values is not. TestGenerateTreeRefusesKernelTransportWithoutIt
		// covers it.
		"transport": true,
	}
	// gated: refused outright where the capability is absent. generate-tree has
	// none today -- every flag it registers either works everywhere or is
	// value-gated.
	gated := map[string]bool{}

	fs, _ := registerGenTreeFlags(flag.NewFlagSet("classify", flag.ContinueOnError), io.Discard)
	fs.VisitAll(func(f *flag.Flag) {
		if portable[f.Name] == gated[f.Name] { // in neither, or in both
			t.Errorf("flag -%s is unclassified: add it to `portable` if it works on every "+
				"platform, or gate it and add it to `gated`. On macOS the compiler will not "+
				"catch a mount-dependent flag; this test is what does.", f.Name)
		}
	})

	// VisitAll above catches an UNCLASSIFIED flag, never a MISCLASSIFIED one: a
	// gated flag listed in `portable` passes it and still refuses on macOS. Ask
	// the gate what it actually refuses. Registration runs under absent
	// capabilities because Gate records a flag only when its capability is gone.
	cmdflagstest.With(t, &caps, platform.Darwin())

	_, f := registerGenTreeFlags(flag.NewFlagSet("gatecheck", flag.ContinueOnError), io.Discard)
	actual := map[string]bool{}
	for _, name := range f.gate.GatedNames() {
		actual[name] = true
		if !gated[name] {
			t.Errorf("flag -%s is gated by the Gate but listed as portable; a macOS operator "+
				"is refused a flag this test certified as working everywhere", name)
		}
	}
	for name := range gated {
		if !actual[name] {
			t.Errorf("flag -%s is listed in `gated` but the Gate does not refuse it; the "+
				"classification is documentation, not a constraint", name)
		}
	}
}

// --acls-only and --no-acls both run through the kernel code paths whatever
// --transport says: a local setxattr of system.nfs4_acl, and a fan-out that
// copies through a mount. On the platform that has to use the userspace
// transport neither exists, so silently honouring the flag builds the tree in
// the wrong place or dies at the first xattr. cmdflags.Gate cannot see this --
// both flags are portable in themselves; it is the combination that is not.
func TestGenerateTreeRefusesKernelOnlyModesOnUserspace(t *testing.T) {
	cmdflagstest.With(t, &caps, platform.Darwin())

	for _, mode := range []string{"--acls-only", "--no-acls"} {
		t.Run(mode, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := run([]string{"--principals", minimalPrincipals(t), "--transport", "userspace",
				"--server", "s", "--export", "/e", mode, "/bigdata"}, &out, &errOut)
			if code != 1 {
				t.Fatalf("exit code = %d, want 1", code)
			}
			if got := errOut.String(); !strings.Contains(got, mode) || !strings.Contains(got, "userspace") {
				t.Fatalf("error = %q, want %s named alongside the transport", got, mode)
			}
		})
	}
}

// A dry run prints its plan and returns before it would connect, so it must not
// demand a server. On macOS the default transport is userspace, which makes
// this the plainest "what would this do" invocation on the platform.
func TestGenerateTreeDryRunNeedsNoServerOnUserspace(t *testing.T) {
	cmdflagstest.With(t, &caps, platform.Darwin())

	var out, errOut bytes.Buffer
	code := run([]string{"--principals", minimalPrincipals(t), "--dry-run", t.TempDir()}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %s", code, errOut.String())
	}
}

// The ordering regression that made five subprocess tests fail on macOS: a
// transport-dependent check placed ahead of the roster and the scale answers
// every mistake with a transport complaint, because on macOS the default
// transport is userspace and those invocations name no --server.
//
// This has to be an in-process test under injected caps. CI's whole macOS story
// is cross-compilation and go vet -- a darwin binary is type-checked there and
// never executed -- so the subprocess tests in main_test.go cannot protect this
// on the platform where it breaks, and go vet cannot see argument ordering.
func TestGenerateTreeDiagnosesTheOperatorsMistakeNotTheTransport(t *testing.T) {
	cmdflagstest.With(t, &caps, platform.Darwin())

	cases := []struct {
		name string
		args func(t *testing.T) []string
		want string
	}{
		{
			name: "unknown scale",
			args: func(t *testing.T) []string {
				return []string{"--principals", minimalPrincipals(t), "--scale", "bogus", "/bigdata"}
			},
			want: "unknown scale",
		},
		{
			name: "unreadable principals",
			args: func(t *testing.T) []string {
				return []string{"--principals", "/no/such/file.json", "/bigdata"}
			},
			want: "reading principals",
		},
		{
			name: "malformed principals",
			args: func(t *testing.T) []string {
				bad := filepath.Join(t.TempDir(), "bad.json")
				if err := os.WriteFile(bad, []byte("not json"), 0o600); err != nil {
					t.Fatal(err)
				}
				return []string{"--principals", bad, "/bigdata"}
			},
			want: "parsing principals",
		},
		{
			name: "empty roster",
			args: func(t *testing.T) []string {
				empty := filepath.Join(t.TempDir(), "empty.json")
				if err := os.WriteFile(empty, []byte(`{"domain":"","roles":{}}`), 0o600); err != nil {
					t.Fatal(err)
				}
				return []string{"--principals", empty, "/bigdata"}
			},
			want: "must have",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := run(tc.args(t), &out, &errOut); code != 1 {
				t.Fatalf("exit code = %d, want 1", code)
			}
			if got := errOut.String(); !strings.Contains(got, tc.want) {
				t.Fatalf("error = %q, want %q", got, tc.want)
			}
		})
	}
}
