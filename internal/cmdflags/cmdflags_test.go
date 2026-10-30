package cmdflags

import (
	"bytes"
	"flag"
	"slices"
	"strings"
	"testing"

	"github.com/PureStorage-OpenConnect/permissionreset/internal/nfs41"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/platform"
	"github.com/PureStorage-OpenConnect/permissionreset/internal/tuning"
)

func darwinGate() *Gate { return &Gate{OS: "darwin", Arch: "arm64"} }

// A gated flag must still be registered -- that is the whole point of the
// register-and-reject design -- but must carry an empty usage string, which is
// how each command's custom fs.Usage (cmd/permissionreset/main.go:149,
// cmd/sweep/main.go:187) keeps a flag out of --help.
func TestGateHidesUnsupportedFlag(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	g := darwinGate()
	g.Bool(fs, Pfind(platform.Darwin()), "pfind", false, "enumerate with pfind")

	f := fs.Lookup("pfind")
	if f == nil {
		t.Fatal("gated flag was not registered; an unknown-flag error is the wrong diagnosis")
	}
	if f.Usage != "" {
		t.Fatalf("gated flag usage = %q, want empty so fs.Usage skips it", f.Usage)
	}
}

func TestGateKeepsSupportedFlagVisible(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	g := &Gate{OS: "linux", Arch: "amd64"}
	g.Bool(fs, Pfind(platform.Linux()), "pfind", false, "enumerate with pfind")

	if got := fs.Lookup("pfind").Usage; got != "enumerate with pfind" {
		t.Fatalf("supported flag usage = %q, want it intact", got)
	}
	if len(g.gated) != 0 {
		t.Fatalf("supported flag was recorded as gated: %v", g.gated)
	}
}

// The refusal names the CAPABILITY and what would restore it, not an operating
// system. "requires Linux" is wrong the first time a capability is false on a
// Linux build, and it never says what is actually missing.
func TestGateRejectsExplicitUseAndNamesTheCapability(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(new(bytes.Buffer))
	g := darwinGate()
	g.Bool(fs, Pfind(platform.Darwin()), "pfind", false, "enumerate with pfind")

	if err := fs.Parse([]string{"-pfind"}); err != nil {
		t.Fatalf("parse: %v", err)
	}

	var errOut bytes.Buffer
	if !g.Reject(tuning.Explicit(fs), nil, &errOut) {
		t.Fatal("Reject returned false for a flag the operator typed")
	}
	got := errOut.String()
	for _, want := range []string{"--pfind", "darwin/arm64", "RapidFile pfind"} {
		if !strings.Contains(got, want) {
			t.Errorf("error = %q, want it to mention %q", got, want)
		}
	}
	if strings.Contains(got, "requires Linux") {
		t.Errorf("error = %q, still blames an operating system rather than naming the capability", got)
	}
}

// Every gated flag the operator typed is reported, not just the first. Somebody
// porting a Linux command line usually has more than one, and one error
// round-trip per flag is a bad trade for four lines of code.
func TestGateRejectsReportsEveryTypedGatedFlag(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(new(bytes.Buffer))
	g := darwinGate()
	g.Bool(fs, Pfind(platform.Darwin()), "pfind", false, "enumerate with pfind")
	g.Bool(fs, Pfind(platform.Darwin()), "no-pfind", false, "deprecated")

	if err := fs.Parse([]string{"-pfind", "-no-pfind"}); err != nil {
		t.Fatalf("parse: %v", err)
	}

	var errOut bytes.Buffer
	if !g.Reject(tuning.Explicit(fs), nil, &errOut) {
		t.Fatal("Reject returned false")
	}
	got := errOut.String()
	if !strings.Contains(got, "--pfind") || !strings.Contains(got, "--no-pfind") {
		t.Fatalf("error = %q, want both gated flags named", got)
	}
}

// A gated flag sitting at its default is silent. tuning.Explicit reports typed
// flags, not set flags, which is what makes this precise: nothing rejects a
// command line that never mentioned the flag.
func TestGateIgnoresUntypedGatedFlag(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	g := darwinGate()
	g.Bool(fs, Pfind(platform.Darwin()), "pfind", false, "enumerate with pfind")
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}

	var errOut bytes.Buffer
	if g.Reject(tuning.Explicit(fs), nil, &errOut) {
		t.Fatalf("Reject fired on an untyped flag: %q", errOut.String())
	}
}

// --transport is the case a presence gate gets WRONG. userspace is the value
// that works where the kernel transport does not, and it is the value the
// shipped docs teach, so the flag stays registered, stays in --help, and keeps
// its usage string. Only the value "kernel" is refused.
func TestGateValueRefusesOnlyTheUnsupportedValue(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(new(bytes.Buffer))
	g := darwinGate()
	transport := fs.String("transport", "userspace", "filesystem transport: kernel or userspace")
	g.Value("transport", "kernel", KernelTransport(platform.Darwin()))

	if err := fs.Parse([]string{"-transport", "userspace"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if fs.Lookup("transport").Usage == "" {
		t.Fatal("a value-gated flag lost its usage string; it must stay in --help")
	}

	var errOut bytes.Buffer
	if g.Reject(tuning.Explicit(fs), map[string]string{"transport": *transport}, &errOut) {
		t.Fatalf("Reject refused --transport=userspace: %q", errOut.String())
	}
}

func TestGateValueRefusesTheKernelTransport(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(new(bytes.Buffer))
	g := darwinGate()
	transport := fs.String("transport", "userspace", "filesystem transport: kernel or userspace")
	g.Value("transport", "kernel", KernelTransport(platform.Darwin()))

	if err := fs.Parse([]string{"-transport", "kernel"}); err != nil {
		t.Fatalf("parse: %v", err)
	}

	var errOut bytes.Buffer
	if !g.Reject(tuning.Explicit(fs), map[string]string{"transport": *transport}, &errOut) {
		t.Fatal("Reject accepted --transport=kernel on a build with no kernel transport")
	}
	got := errOut.String()
	for _, want := range []string{"--transport=kernel", "darwin/arm64", "system.nfs4_acl", "--transport=userspace"} {
		if !strings.Contains(got, want) {
			t.Errorf("error = %q, want it to mention %q", got, want)
		}
	}
}

// A value gate fires on the value, not on whether the flag was typed: a build
// whose DEFAULT is the unsupported value would otherwise sail through. No such
// build exists in this version (defaultTransport moves the default), but the
// gate must not depend on that staying true.
func TestGateValueFiresOnAnUntypedUnsupportedDefault(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	g := darwinGate()
	transport := fs.String("transport", "kernel", "filesystem transport")
	g.Value("transport", "kernel", KernelTransport(platform.Darwin()))
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}

	var errOut bytes.Buffer
	if !g.Reject(tuning.Explicit(fs), map[string]string{"transport": *transport}, &errOut) {
		t.Fatal("Reject accepted an unsupported value that arrived as the default")
	}
}

func TestGateStringFlag(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(new(bytes.Buffer))
	g := darwinGate()
	v := g.String(fs, Pfind(platform.Darwin()), "pfind-path", "/usr/bin/pfind", "pfind binary")

	if fs.Lookup("pfind-path").Usage != "" {
		t.Fatal("gated string flag kept its usage string")
	}
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if *v != "/usr/bin/pfind" {
		t.Fatalf("default = %q, want the default to survive gating", *v)
	}
}

// withProcessCredential fixes both halves of "what the running process is".
// Stubbing the notes too is not incidental: the real ProcessCredentialNotes
// reads os.Getgroups, so leaving it live would make every warning assertion
// below depend on how many groups the account running the suite happens to be
// in. withProcessNotes overrides it where the notes are the subject.
func withProcessCredential(t *testing.T, a nfs41.AuthSys) {
	t.Helper()
	prev := CurrentAuthSys
	CurrentAuthSys = func() nfs41.AuthSys { return a }
	t.Cleanup(func() { CurrentAuthSys = prev })
	withProcessNotes(t, nil)
}

func withProcessNotes(t *testing.T, notes []string) {
	t.Helper()
	prev := ProcessCredentialNotes
	ProcessCredentialNotes = func() []string { return notes }
	t.Cleanup(func() { ProcessCredentialNotes = prev })
}

func directoryCredential() nfs41.AuthSys {
	return nfs41.AuthSys{Machine: "lab01", UID: 10010, GID: 10000, AuxGIDs: []uint32{10020}}
}

func macCredential() nfs41.AuthSys {
	return nfs41.AuthSys{Machine: "mba", UID: 501, GID: 20, AuxGIDs: []uint32{12, 61}}
}

func authFlags(t *testing.T, args ...string) (*AuthFlags, map[string]bool) {
	t.Helper()
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(new(bytes.Buffer))
	a := RegisterAuth(fs, func(s string) string { return s })
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse: %v", err)
	}
	return a, tuning.Explicit(fs)
}

// Nothing typed means nil: nfs41 builds the process credential itself, exactly
// as it always has.
func TestAuthResolveDefaultsToProcess(t *testing.T) {
	withProcessCredential(t, directoryCredential())
	a, explicit := authFlags(t)
	got, warnings, err := a.Resolve(explicit, "userspace")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != nil {
		t.Fatalf("auth = %+v, want nil so nfs41 builds the process credential itself", got)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none for a directory-range process uid", warnings)
	}
}

// THE test this task exists for. The default, process-derived credential on a
// Mac is uid 501, and the design's behavior matrix promises a warning for
// exactly that case. The previous revision returned before ever looking.
func TestAuthResolveWarnsOnALocalProcessUIDWithNothingTyped(t *testing.T) {
	withProcessCredential(t, macCredential())
	a, explicit := authFlags(t)
	got, warnings, err := a.Resolve(explicit, "userspace")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != nil {
		t.Fatalf("auth = %+v, want nil: warning about a credential does not mean overriding it", got)
	}
	if len(warnings) == 0 || !strings.Contains(warnings[0], "501") {
		t.Fatalf("warnings = %v, want one naming the process uid 501", warnings)
	}
	if !strings.Contains(warnings[0], "--auth-uid") {
		t.Fatalf("warnings = %v, want the fix named", warnings)
	}
}

// AUTH_SYS is what the USERSPACE transport puts on the wire. A kernel run
// authenticates through the mount and never sends this credential, so warning
// about it there is noise.
func TestAuthResolveIsSilentOnTheKernelTransport(t *testing.T) {
	withProcessCredential(t, macCredential())
	a, explicit := authFlags(t)
	_, warnings, err := a.Resolve(explicit, "kernel")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none: the kernel transport sends no AUTH_SYS", warnings)
	}
}

// uid 0 says NOTHING at startup. Root squash is real, but so is a Linux
// operator running the userspace transport under sudo against an export that
// does not squash -- a configuration that worked for months without comment,
// and one this warning would have started nagging on every run. The fact moved
// to run.rootSquashHint, which prints it as an explanation of a failure that
// actually happened. Warning fatigue is the failure mode being avoided: this is
// the only warning channel the credential path has.
func TestAuthResolveIsSilentForRootAtStartup(t *testing.T) {
	withProcessCredential(t, nfs41.AuthSys{Machine: "lab01", UID: 0, GID: 0})
	a, explicit := authFlags(t)
	_, warnings, err := a.Resolve(explicit, "userspace")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none: uid 0 is explained on failure, not warned about "+
			"before one", warnings)
	}
}

// uid 0 must not fall through to the local-account arm either. It is below the
// ceiling, and "0 looks like a local account rather than a directory one" is
// both wrong and a different fix from the one root needs.
func TestAuthResolveDoesNotCallRootALocalAccount(t *testing.T) {
	withProcessCredential(t, nfs41.AuthSys{Machine: "lab01", UID: 0, GID: 0})
	a, explicit := authFlags(t)
	_, warnings, err := a.Resolve(explicit, "userspace")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	for _, w := range warnings {
		if strings.Contains(w, "local account") {
			t.Fatalf("warning = %q, want uid 0 excluded from the local-account arm", w)
		}
	}
}

// The AUTH_SYS wire format holds 16 auxiliary gids. Truncating is correct;
// doing it silently means an account in more groups presents an identity
// missing the rest, preflight passes on the primary identity, and the objects
// guarded by a dropped group fail hours later with nothing connecting the two.
func TestAuthResolveReportsTruncatedGroupList(t *testing.T) {
	withProcessCredential(t, macCredential())
	withProcessNotes(t, []string{"WARNING: this account is in 20 groups but AUTH_SYS carries only 16"})

	a, explicit := authFlags(t)
	_, warnings, err := a.Resolve(explicit, "userspace")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !slices.ContainsFunc(warnings, func(w string) bool { return strings.Contains(w, "20 groups") }) {
		t.Fatalf("warnings = %v, want the truncation reported", warnings)
	}
}

// An explicit --auth-gids replaces the process list outright, so what the
// process happened to carry is no longer a fact about the credential going on
// the wire. An over-long explicit list is refused at encode, not truncated.
func TestAuthResolveSuppressesTruncationNoteWhenGIDsAreTyped(t *testing.T) {
	withProcessCredential(t, macCredential())
	withProcessNotes(t, []string{"WARNING: this account is in 20 groups but AUTH_SYS carries only 16"})

	a, explicit := authFlags(t, "-auth-gids", "10020,10021")
	_, warnings, err := a.Resolve(explicit, "userspace")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	for _, w := range warnings {
		if strings.Contains(w, "20 groups") {
			t.Fatalf("warning = %q, want it suppressed: the typed list replaced the process one", w)
		}
	}
}

// The kernel transport sends no AUTH_SYS at all, so the process group list is
// not a fact about it.
func TestAuthResolveSuppressesTruncationNoteOnKernel(t *testing.T) {
	withProcessCredential(t, macCredential())
	withProcessNotes(t, []string{"WARNING: this account is in 20 groups but AUTH_SYS carries only 16"})

	a, explicit := authFlags(t)
	_, warnings, err := a.Resolve(explicit, "kernel")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none: the kernel transport sends no AUTH_SYS", warnings)
	}
}

func TestAuthResolveExplicitOverrides(t *testing.T) {
	withProcessCredential(t, macCredential())
	a, explicit := authFlags(t,
		"-auth-uid", "10010", "-auth-gid", "10000",
		"-auth-gids", "10020,10021", "-auth-hostname", "lab-client")
	got, _, err := a.Resolve(explicit, "userspace")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got == nil {
		t.Fatal("auth = nil, want an explicit credential")
	}
	if got.UID != 10010 || got.GID != 10000 || got.Machine != "lab-client" {
		t.Fatalf("auth = %+v, want uid 10010 gid 10000 machine lab-client", got)
	}
	if len(got.AuxGIDs) != 2 || got.AuxGIDs[0] != 10020 || got.AuxGIDs[1] != 10021 {
		t.Fatalf("aux gids = %v, want [10020 10021]", got.AuxGIDs)
	}
}

// A partial override still has to produce a whole credential: the fields the
// operator did not name come from the process, so --auth-uid alone does not
// silently blank the gid and the group list.
func TestAuthResolvePartialOverrideFillsFromProcess(t *testing.T) {
	proc := directoryCredential()
	withProcessCredential(t, proc)
	a, explicit := authFlags(t, "-auth-uid", "10011")
	got, _, err := a.Resolve(explicit, "userspace")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got == nil {
		t.Fatal("auth = nil, want a credential")
	}
	if got.UID != 10011 {
		t.Fatalf("uid = %d, want the override 10011", got.UID)
	}
	if got.GID != proc.GID {
		t.Fatalf("gid = %d, want the process gid %d", got.GID, proc.GID)
	}
	if got.Machine != proc.Machine {
		t.Fatalf("machine = %q, want the process hostname %q", got.Machine, proc.Machine)
	}
}

func TestAuthResolveRejectsBadGIDList(t *testing.T) {
	withProcessCredential(t, directoryCredential())
	a, explicit := authFlags(t, "-auth-gids", "10020,notanumber")
	if _, _, err := a.Resolve(explicit, "userspace"); err == nil {
		t.Fatal("Resolve accepted a non-numeric gid")
	}
}

func TestAuthResolveRejectsNegativeUID(t *testing.T) {
	withProcessCredential(t, directoryCredential())
	a, explicit := authFlags(t, "-auth-uid", "-1")
	if _, _, err := a.Resolve(explicit, "userspace"); err == nil {
		t.Fatal("Resolve accepted a negative uid")
	}
}

// A typed low uid warns too. The operator chose it, but "I chose it" and "I
// chose it correctly" are different claims, and this is the cheap one to check.
func TestAuthResolveWarnsOnATypedLocalUID(t *testing.T) {
	withProcessCredential(t, directoryCredential())
	a, explicit := authFlags(t, "-auth-uid", "501")
	_, warnings, err := a.Resolve(explicit, "userspace")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(warnings) == 0 || !strings.Contains(warnings[0], "501") {
		t.Fatalf("warnings = %v, want one naming the suspicious uid", warnings)
	}
}

func TestAuthResolveDoesNotWarnOnADirectoryUID(t *testing.T) {
	withProcessCredential(t, macCredential())
	a, explicit := authFlags(t, "-auth-uid", "10010")
	_, warnings, err := a.Resolve(explicit, "userspace")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none for a directory-range uid", warnings)
	}
}

// withNoProcessCredential simulates a platform where CredentialFromProcess is
// false (Windows). It restores the previous value on test cleanup.
func withNoProcessCredential(t *testing.T) {
	t.Helper()
	prev := credentialFromProcess
	credentialFromProcess = false
	t.Cleanup(func() { credentialFromProcess = prev })
}

// TestAuthResolveRequiresBothFlagsWhenNoProcessCredential exercises the gate
// that fires when credentialFromProcess is false. On real Windows the constant
// is false; here we simulate it with the injectable var.
func TestAuthResolveRequiresBothFlagsWhenNoProcessCredential(t *testing.T) {
	withNoProcessCredential(t)
	withProcessCredential(t, directoryCredential())

	// No explicit flags at all: must error.
	a, explicit := authFlags(t)
	if _, _, err := a.Resolve(explicit, "userspace"); err == nil {
		t.Fatal("Resolve accepted userspace with no explicit creds when CredentialFromProcess is false")
	}

	// auth-uid only, no auth-gid: must error.
	a, explicit = authFlags(t, "-auth-uid", "10010")
	if _, _, err := a.Resolve(explicit, "userspace"); err == nil {
		t.Fatal("Resolve accepted userspace with auth-uid but no auth-gid when CredentialFromProcess is false")
	}

	// auth-gid only, no auth-uid: must error.
	a, explicit = authFlags(t, "-auth-gid", "10000")
	if _, _, err := a.Resolve(explicit, "userspace"); err == nil {
		t.Fatal("Resolve accepted userspace with auth-gid but no auth-uid when CredentialFromProcess is false")
	}

	// Both explicit: must succeed.
	a, explicit = authFlags(t, "-auth-uid", "10010", "-auth-gid", "10000")
	if _, _, err := a.Resolve(explicit, "userspace"); err != nil {
		t.Fatalf("Resolve rejected explicit uid+gid when CredentialFromProcess is false: %v", err)
	}

	// Kernel transport with no flags: no requirement even without process creds.
	a, explicit = authFlags(t)
	if _, _, err := a.Resolve(explicit, "kernel"); err != nil {
		t.Fatalf("Resolve rejected empty creds for kernel transport: %v", err)
	}
}
